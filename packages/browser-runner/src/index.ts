import { Buffer } from 'node:buffer'
import { existsSync } from 'node:fs'
import { platform } from 'node:os'
import { join } from 'node:path'
import { chromium, type Browser, type BrowserContext } from 'playwright-core'

export { buildInertXssMarkerPayload } from '@agentgo/domain'

export interface BrowserFormField {
  readonly name: string
  readonly type: string
  readonly required: boolean
}

export interface BrowserFormSummary {
  readonly action: string
  readonly method: string
  readonly fields: readonly BrowserFormField[]
}

export interface BrowserExecutionRequest {
  readonly requestId: string
  readonly baseUrl: string
  readonly html: string
  readonly action: 'inspect-dom' | 'verify-xss' | 'capture-evidence'
  readonly marker?: string
  readonly contentSecurityPolicy?: string
  readonly timeoutMs: number
  readonly maxDomBytes?: number
  readonly signal?: AbortSignal
}

export interface BrowserExecutionResult {
  readonly requestId: string
  readonly status: 'succeeded' | 'failed' | 'cancelled'
  readonly finalUrl: string
  readonly pageTitle?: string
  readonly links: readonly string[]
  readonly forms: readonly BrowserFormSummary[]
  readonly domSnapshot?: string
  readonly markerExecuted?: boolean
  readonly screenshot?: Uint8Array
  readonly networkRequestsBlocked: number
  readonly resultBytes: number
  readonly durationMs: number
  readonly errorCode?:
    | 'browser-unavailable'
    | 'timeout'
    | 'render-error'
    | 'result-too-large'
    | 'cancelled'
    | 'dispatch-mark-failed'
    | 'response-start-mark-failed'
    | 'runner-output-invalid'
  readonly errorMessage?: string
}

export interface BrowserRunnerOptions {
  executablePath?: string
  headless?: boolean
}

type BrowserExecutionErrorCode = NonNullable<BrowserExecutionResult['errorCode']>

const safeBrowserErrorMessages: Record<BrowserExecutionErrorCode, string> = {
  'browser-unavailable': 'No supported offline browser executable is available.',
  timeout: 'The offline browser execution timed out.',
  'render-error': 'The offline browser could not render the supplied document.',
  'result-too-large': 'The offline browser result exceeded its byte budget.',
  cancelled: 'The offline browser execution was cancelled.',
  'dispatch-mark-failed': 'The offline browser dispatch could not be persisted.',
  'response-start-mark-failed': 'The offline browser response could not be persisted.',
  'runner-output-invalid': 'The offline browser runner returned an invalid result.'
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

  constructor(private readonly options: BrowserRunnerOptions = {}) {}

  async execute(input: BrowserExecutionRequest): Promise<BrowserExecutionResult> {
    const startedAt = Date.now()
    const maxResultBytes = input.maxDomBytes ?? 1024 * 1024
    if (!Number.isSafeInteger(maxResultBytes) || maxResultBytes <= 0) {
      return this.failure(
        input,
        startedAt,
        'render-error',
        new Error('Browser result byte budget must be a positive safe integer.')
      )
    }
    if (this.active.has(input.requestId)) {
      throw new Error(`Browser request ${input.requestId} is already running.`)
    }

    const deadlineAt = startedAt + input.timeoutMs
    const execution: ActiveBrowserExecution = {
      controller: new AbortController()
    }
    this.active.set(input.requestId, execution)
    const onExternalAbort = (): void => {
      execution.controller.abort(new BrowserExecutionAbortError('cancelled'))
      void this.closeExecution(execution)
    }
    input.signal?.addEventListener('abort', onExternalAbort, { once: true })
    if (input.signal?.aborted) onExternalAbort()
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

    let browser: Browser | undefined
    let context: BrowserContext | undefined
    let blockedRequests = 0
    try {
      if (execution.controller.signal.aborted) {
        throw execution.controller.signal.reason
      }
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
        offline: true,
        acceptDownloads: false,
        bypassCSP: false,
        ignoreHTTPSErrors: false,
        javaScriptEnabled: true,
        serviceWorkers: 'block',
        viewport: { width: 1280, height: 720 }
      }), execution.controller.signal)
      await raceWithAbort(
        context.route('**/*', async (route) => {
          blockedRequests += 1
          await route.abort('blockedbyclient')
        }),
        execution.controller.signal
      )
      await raceWithAbort(
        context.routeWebSocket('**/*', async (webSocket) => {
          blockedRequests += 1
          await webSocket.close({
            code: 1008,
            reason: 'AgentGo offline browser execution'
          })
        }),
        execution.controller.signal
      )
      await raceWithAbort(
        context.addInitScript(() => {
          const replace = (
            target: object,
            property: string,
            value: unknown
          ): void => {
            try {
              Object.defineProperty(target, property, {
                configurable: false,
                enumerable: false,
                writable: false,
                value
              })
            } catch {
              // The browser's offline mode and routing remain the primary controls.
            }
          }
          for (const constructorName of [
            'WebSocket',
            'EventSource',
            'WebTransport',
            'RTCPeerConnection',
            'webkitRTCPeerConnection'
          ]) {
            replace(globalThis, constructorName, undefined)
          }
          replace(Navigator.prototype, 'sendBeacon', () => false)
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
        page.evaluate(({ marker, maxResultBytes }) => {
          const links = [...document.querySelectorAll<HTMLAnchorElement>('a[href]')]
            .map((anchor) => anchor.href.slice(0, 2_048))
            .filter((value, index, values) => values.indexOf(value) === index)
            .slice(0, 100)
          const forms = [...document.forms].slice(0, 50).map((form) => ({
            action: (form.action || document.baseURI).slice(0, 2_048),
            method: (form.method || 'GET').toUpperCase().slice(0, 32),
            fields: [...form.elements]
              .slice(0, 50)
              .filter(
                (element): element is HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement =>
                  element instanceof HTMLInputElement ||
                  element instanceof HTMLSelectElement ||
                  element instanceof HTMLTextAreaElement
              )
              .map((element) => ({
                name: element.name.slice(0, 256),
                type: (
                  element instanceof HTMLInputElement ? element.type : element.tagName.toLowerCase()
                ).slice(0, 64),
                required: element.required
              }))
              .filter((field) => Boolean(field.name))
          }))
          const dom = document.documentElement.outerHTML
          const encodedDom = new TextEncoder().encode(
            dom.slice(0, maxResultBytes)
          )
          let domEnd = Math.min(encodedDom.byteLength, maxResultBytes)
          const decoder = new TextDecoder('utf-8', { fatal: true })
          let domSnapshot = ''
          while (domEnd > 0) {
            try {
              domSnapshot = decoder.decode(encodedDom.subarray(0, domEnd))
              break
            } catch {
              domEnd -= 1
            }
          }
          return {
            title: document.title.slice(0, 1_024),
            links,
            forms,
            domSnapshot,
            markerExecuted: marker
              ? document.documentElement.getAttribute('data-agentgo-xss') === marker
              : undefined
          }
        }, {
          marker: input.marker,
          maxResultBytes
        }),
        execution.controller.signal
      )

      const metadataBytes = Buffer.byteLength(
        JSON.stringify({
          title: summary.title,
          links: summary.links,
          forms: summary.forms,
          markerExecuted: summary.markerExecuted
        }),
        'utf8'
      )
      const domSnapshotBytes = Buffer.byteLength(summary.domSnapshot, 'utf8')
      const resultBytesWithoutScreenshot = metadataBytes + domSnapshotBytes
      if (resultBytesWithoutScreenshot > maxResultBytes) {
        return this.failure(
          input,
          startedAt,
          'result-too-large',
          undefined,
          blockedRequests,
          resultBytesWithoutScreenshot
        )
      }

      const screenshotBuffer =
        input.action === 'capture-evidence' || input.action === 'verify-xss'
          ? await raceWithAbort(
              page.screenshot({
                type: 'png',
                fullPage: false,
                animations: 'disabled',
                timeout: remainingMs()
              }),
              execution.controller.signal
            )
          : undefined
      const screenshot =
        screenshotBuffer === undefined
          ? undefined
          : Uint8Array.from(screenshotBuffer)

      if (resultBytesWithoutScreenshot + (screenshot?.byteLength ?? 0) > maxResultBytes) {
        return this.failure(
          input,
          startedAt,
          'result-too-large',
          undefined,
          blockedRequests,
          resultBytesWithoutScreenshot + (screenshot?.byteLength ?? 0)
        )
      }

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
        resultBytes: resultBytesWithoutScreenshot + (screenshot?.byteLength ?? 0),
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
      input.signal?.removeEventListener('abort', onExternalAbort)
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
    _error: unknown,
    blockedRequests = 0,
    resultBytes = 0
  ): BrowserExecutionResult {
    return {
      requestId: input.requestId,
      status: errorCode === 'cancelled' ? 'cancelled' : 'failed',
      finalUrl: input.baseUrl,
      links: [],
      forms: [],
      networkRequestsBlocked: blockedRequests,
      resultBytes,
      durationMs: Date.now() - startedAt,
      errorCode,
      errorMessage: safeBrowserErrorMessages[errorCode]
    }
  }
}

export type BrowserRunner = Pick<PlaywrightBrowserRunner, 'execute' | 'cancel'>
export { PlaywrightBrokeredBrowserRecon } from './brokered-browser-recon'
export type {
  BrokeredReconDecision,
  BrokeredReconFulfillment,
  BrokeredReconNetworkBroker,
  BrokeredReconNetworkRequest,
  BrokeredReconRequest,
  BrokeredReconResult
} from './brokered-browser-recon'
