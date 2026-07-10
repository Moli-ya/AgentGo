import { existsSync } from 'node:fs'
import { platform } from 'node:os'
import { join } from 'node:path'
import { chromium, type Browser, type BrowserContext } from 'playwright-core'

export interface BrowserExecutionGuard {
  authorize(input: { policyDecisionId: string; baseUrl: string }): Promise<void>
}

export interface BrowserFormField {
  name: string
  type: string
  required: boolean
}

export interface BrowserFormSummary {
  action: string
  method: string
  fields: BrowserFormField[]
}

export interface BrowserExecutionRequest {
  requestId: string
  policyDecisionId: string
  baseUrl: string
  html: string
  action: 'inspect-dom' | 'verify-xss' | 'capture-evidence'
  marker?: string
  contentSecurityPolicy?: string
  timeoutMs: number
  maxDomBytes?: number
}

export interface BrowserExecutionResult {
  requestId: string
  status: 'succeeded' | 'failed' | 'cancelled'
  finalUrl: string
  pageTitle?: string
  links: string[]
  forms: BrowserFormSummary[]
  domSnapshot?: string
  markerExecuted?: boolean
  screenshot?: Uint8Array
  networkRequestsBlocked: number
  durationMs: number
  errorCode?:
    | 'authorization-denied'
    | 'browser-unavailable'
    | 'timeout'
    | 'render-error'
    | 'cancelled'
  errorMessage?: string
}

export interface BrowserRunnerOptions {
  executablePath?: string
  headless?: boolean
}

type BrowserExecutionAbortCode = 'cancelled' | 'timeout'

interface ActiveBrowserExecution {
  browser?: Browser
  closePromise?: Promise<void>
  controller: AbortController
}

class BrowserExecutionAbortError extends Error {
  constructor(readonly code: BrowserExecutionAbortCode) {
    super(
      code === 'timeout'
        ? 'Browser execution exceeded its overall timeout.'
        : 'Browser execution was cancelled.'
    )
    this.name = 'BrowserExecutionAbortError'
  }
}

const browserCloseGraceMs = 1_000

const windowsBrowserCandidates = [
  join(process.env['PROGRAMFILES(X86)'] ?? '', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  join(process.env.PROGRAMFILES ?? '', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  join(process.env.PROGRAMFILES ?? '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
  join(process.env.LOCALAPPDATA ?? '', 'Google', 'Chrome', 'Application', 'chrome.exe')
]

export function findSystemBrowserExecutable(): string | undefined {
  if (platform() !== 'win32') return undefined
  return windowsBrowserCandidates.find((candidate) => candidate && existsSync(candidate))
}

function escapeHtmlAttribute(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function withDocumentPolicies(
  html: string,
  baseUrl: string,
  contentSecurityPolicy?: string
): string {
  const base = `<base href="${escapeHtmlAttribute(baseUrl)}">`
  const csp = contentSecurityPolicy
    ? `<meta http-equiv="Content-Security-Policy" content="${escapeHtmlAttribute(contentSecurityPolicy)}">`
    : ''
  const policies = `${base}${csp}`
  const headMatch = /<head(?:\s[^>]*)?>/i.exec(html)
  if (headMatch?.index !== undefined) {
    const insertAt = headMatch.index + headMatch[0].length
    return `${html.slice(0, insertAt)}${policies}${html.slice(insertAt)}`
  }
  return `<!doctype html><html><head>${policies}</head><body>${html}</body></html>`
}

export function buildInertXssMarkerPayload(marker: string): string {
  if (!/^agx_[a-f0-9]{16,64}$/.test(marker)) {
    throw new Error('XSS marker must be an AgentGo random hexadecimal marker.')
  }
  return `"><svg data-agentgo-marker="${marker}" onload="document.documentElement.setAttribute('data-agentgo-xss','${marker}')"></svg>`
}

function getAbortCode(error: unknown): BrowserExecutionAbortCode | undefined {
  return error instanceof BrowserExecutionAbortError ? error.code : undefined
}

async function raceWithAbort<T>(
  operation: Promise<T>,
  signal: AbortSignal
): Promise<T> {
  if (signal.aborted) {
    throw signal.reason
  }

  let onAbort: (() => void) | undefined
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(signal.reason)
    signal.addEventListener('abort', onAbort, { once: true })
  })

  try {
    return await Promise.race([operation, aborted])
  } finally {
    if (onAbort) signal.removeEventListener('abort', onAbort)
  }
}

async function closeBrowserWithinGrace(browser: Browser): Promise<void> {
  let graceTimer: ReturnType<typeof setTimeout> | undefined
  try {
    await Promise.race([
      browser.close().catch(() => undefined),
      new Promise<void>((resolve) => {
        graceTimer = setTimeout(resolve, browserCloseGraceMs)
      })
    ])
  } finally {
    if (graceTimer) clearTimeout(graceTimer)
  }
}

export class PlaywrightBrowserRunner {
  private readonly active = new Map<string, ActiveBrowserExecution>()

  constructor(
    private readonly guard: BrowserExecutionGuard,
    private readonly options: BrowserRunnerOptions = {}
  ) {}

  async execute(input: BrowserExecutionRequest): Promise<BrowserExecutionResult> {
    const startedAt = Date.now()
    if (this.active.has(input.requestId)) {
      throw new Error(`Browser request ${input.requestId} is already running.`)
    }

    const deadlineAt = startedAt + input.timeoutMs
    const execution: ActiveBrowserExecution = {
      controller: new AbortController()
    }
    this.active.set(input.requestId, execution)
    const timeout = setTimeout(() => {
      execution.controller.abort(new BrowserExecutionAbortError('timeout'))
      void this.closeExecution(execution)
    }, input.timeoutMs)

    const remainingMs = (): number => {
      const remaining = deadlineAt - Date.now()
      if (remaining <= 0) {
        throw new BrowserExecutionAbortError('timeout')
      }
      return remaining
    }

    try {
      await raceWithAbort(
        this.guard.authorize({
          policyDecisionId: input.policyDecisionId,
          baseUrl: input.baseUrl
        }),
        execution.controller.signal
      )
    } catch (error) {
      const abortCode = getAbortCode(error)
      clearTimeout(timeout)
      if (this.active.get(input.requestId) === execution) {
        this.active.delete(input.requestId)
      }
      return this.failure(
        input,
        startedAt,
        abortCode ?? 'authorization-denied',
        error
      )
    }

    let browser: Browser | undefined
    let context: BrowserContext | undefined
    let blockedRequests = 0
    try {
      const executablePath = this.options.executablePath ?? findSystemBrowserExecutable()
      if (!executablePath) {
        return this.failure(
          input,
          startedAt,
          'browser-unavailable',
          new Error('No supported Edge or Chrome executable was found.')
        )
      }

      const launchPromise = chromium.launch({
        executablePath,
        headless: this.options.headless ?? true,
        args: [
          '--disable-background-networking',
          '--disable-component-update',
          '--disable-default-apps',
          '--disable-extensions',
          '--disable-sync',
          '--no-first-run'
        ],
        timeout: remainingMs()
      })
      try {
        browser = await raceWithAbort(launchPromise, execution.controller.signal)
      } catch (error) {
        void launchPromise
          .then((lateBrowser) => closeBrowserWithinGrace(lateBrowser))
          .catch(() => undefined)
        throw error
      }
      execution.browser = browser
      context = await raceWithAbort(browser.newContext({
        acceptDownloads: false,
        bypassCSP: false,
        ignoreHTTPSErrors: false,
        javaScriptEnabled: true,
        serviceWorkers: 'block'
      }), execution.controller.signal)
      await raceWithAbort(
        context.route('**/*', async (route) => {
          blockedRequests += 1
          await route.abort('blockedbyclient')
        }),
        execution.controller.signal
      )
      const page = await raceWithAbort(
        context.newPage(),
        execution.controller.signal
      )
      page.setDefaultTimeout(remainingMs())
      page.on('dialog', (dialog) => void dialog.dismiss().catch(() => undefined))
      page.on('popup', (popup) => void popup.close().catch(() => undefined))

      await raceWithAbort(
        page.setContent(
          withDocumentPolicies(input.html, input.baseUrl, input.contentSecurityPolicy),
          { waitUntil: 'domcontentloaded', timeout: remainingMs() }
        ),
        execution.controller.signal
      )
      await raceWithAbort(page.waitForTimeout(50), execution.controller.signal)

      const summary = await raceWithAbort(
        page.evaluate(({ marker, maxDomBytes }) => {
          const links = [...document.querySelectorAll<HTMLAnchorElement>('a[href]')]
            .map((anchor) => anchor.href)
            .filter((value, index, values) => values.indexOf(value) === index)
            .slice(0, 500)
          const forms = [...document.forms].slice(0, 100).map((form) => ({
            action: form.action || document.baseURI,
            method: (form.method || 'GET').toUpperCase(),
            fields: [...form.elements]
              .filter(
                (element): element is HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement =>
                  element instanceof HTMLInputElement ||
                  element instanceof HTMLSelectElement ||
                  element instanceof HTMLTextAreaElement
              )
              .map((element) => ({
                name: element.name,
                type: element instanceof HTMLInputElement ? element.type : element.tagName.toLowerCase(),
                required: element.required
              }))
              .filter((field) => Boolean(field.name))
          }))
          const dom = document.documentElement.outerHTML
          return {
            title: document.title,
            links,
            forms,
            domSnapshot: dom.slice(0, maxDomBytes),
            markerExecuted: marker
              ? document.documentElement.getAttribute('data-agentgo-xss') === marker
              : undefined
          }
        }, {
          marker: input.marker,
          maxDomBytes: input.maxDomBytes ?? 1024 * 1024
        }),
        execution.controller.signal
      )

      const screenshot =
        input.action === 'capture-evidence' || input.action === 'verify-xss'
          ? await raceWithAbort(
              page.screenshot({
                type: 'png',
                fullPage: true,
                animations: 'disabled',
                timeout: remainingMs()
              }),
              execution.controller.signal
            )
          : undefined

      return {
        requestId: input.requestId,
        status: 'succeeded',
        finalUrl: input.baseUrl,
        pageTitle: summary.title,
        links: summary.links,
        forms: summary.forms,
        domSnapshot: summary.domSnapshot,
        ...(summary.markerExecuted !== undefined
          ? { markerExecuted: summary.markerExecuted }
          : {}),
        ...(screenshot ? { screenshot } : {}),
        networkRequestsBlocked: blockedRequests,
        durationMs: Date.now() - startedAt
      }
    } catch (error) {
      const abortCode = getAbortCode(error)
      const timeout =
        abortCode === 'timeout' ||
        (error instanceof Error && /timeout|timed out/i.test(error.message))
      return this.failure(
        input,
        startedAt,
        abortCode === 'cancelled' ? 'cancelled' : timeout ? 'timeout' : 'render-error',
        error,
        blockedRequests
      )
    } finally {
      clearTimeout(timeout)
      if (this.active.get(input.requestId) === execution) {
        this.active.delete(input.requestId)
      }
      await this.closeExecution(execution)
    }
  }

  async cancel(requestId: string): Promise<void> {
    const execution = this.active.get(requestId)
    if (!execution) return
    execution.controller.abort(new BrowserExecutionAbortError('cancelled'))
    await this.closeExecution(execution)
  }

  private closeExecution(execution: ActiveBrowserExecution): Promise<void> {
    if (!execution.browser) return Promise.resolve()
    execution.closePromise ??= closeBrowserWithinGrace(execution.browser)
    return execution.closePromise
  }

  private failure(
    input: BrowserExecutionRequest,
    startedAt: number,
    errorCode: NonNullable<BrowserExecutionResult['errorCode']>,
    error: unknown,
    blockedRequests = 0
  ): BrowserExecutionResult {
    return {
      requestId: input.requestId,
      status: errorCode === 'cancelled' ? 'cancelled' : 'failed',
      finalUrl: input.baseUrl,
      links: [],
      forms: [],
      networkRequestsBlocked: blockedRequests,
      durationMs: Date.now() - startedAt,
      errorCode,
      errorMessage: error instanceof Error ? error.message : 'Browser execution failed.'
    }
  }
}

export type BrowserRunner = Pick<PlaywrightBrowserRunner, 'execute' | 'cancel'>
