import { Buffer } from 'node:buffer'
import { existsSync } from 'node:fs'
import { platform } from 'node:os'
import { join } from 'node:path'
import { chromium, type Browser, type BrowserContext } from 'playwright-core'

export interface BrokeredReconRequest {
  readonly requestId: string
  readonly startUrl: string
  readonly timeoutMs: number
  readonly signal?: AbortSignal
}

export interface BrokeredReconNetworkRequest {
  readonly url: string
  readonly method: string
  readonly resourceType: string
  readonly headers: Readonly<Record<string, string>>
  readonly postData?: string
  readonly isNavigation: boolean
  readonly frameUrl?: string
  readonly pageUrl?: string
}

export interface BrokeredReconFulfillment {
  readonly status: number
  readonly headers: Readonly<Record<string, string>>
  readonly body: Uint8Array
}

export interface BrokeredReconDecision {
  readonly action: 'fulfill' | 'abort'
  readonly fulfillment?: BrokeredReconFulfillment
}

export interface BrokeredReconNetworkBroker {
  handle(request: BrokeredReconNetworkRequest): Promise<BrokeredReconDecision>
}

export interface BrokeredReconResult {
  readonly requestId: string
  readonly status: 'succeeded' | 'failed' | 'cancelled'
  readonly finalUrl: string
  readonly pageTitle?: string
  readonly blockedTransports: number
  readonly durationMs: number
  readonly errorCode?: 'browser-unavailable' | 'timeout' | 'render-error' | 'cancelled'
}

const windowsBrowserCandidates = [
  join(process.env['PROGRAMFILES(X86)'] ?? '', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  join(process.env.PROGRAMFILES ?? '', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  join(process.env.PROGRAMFILES ?? '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
  join(process.env.LOCALAPPDATA ?? '', 'Google', 'Chrome', 'Application', 'chrome.exe')
]

function executablePath(): string | undefined {
  if (platform() !== 'win32') return undefined
  return windowsBrowserCandidates.find((candidate) => candidate && existsSync(candidate))
}

export class PlaywrightBrokeredBrowserRecon {
  async execute(
    input: BrokeredReconRequest,
    broker: BrokeredReconNetworkBroker
  ): Promise<BrokeredReconResult> {
    const startedAt = Date.now()
    const executable = executablePath()
    if (!executable) {
      return {
        requestId: input.requestId,
        status: 'failed',
        finalUrl: input.startUrl,
        blockedTransports: 0,
        durationMs: Date.now() - startedAt,
        errorCode: 'browser-unavailable'
      }
    }

    let browser: Browser | undefined
    let blockedTransports = 0
    try {
      browser = await chromium.launch({
        executablePath: executable,
        headless: true,
        args: [
          '--disable-background-networking',
          '--disable-component-update',
          '--disable-default-apps',
          '--disable-extensions',
          '--disable-sync',
          '--no-first-run',
          '--disable-quic',
          '--disable-webrtc',
          '--dns-prefetch-disable',
          '--disable-features=NetworkPrediction,SpeculativeLaunch,DnsOverHttps'
        ]
      })
      const context: BrowserContext = await browser.newContext({
        offline: true,
        acceptDownloads: false,
        bypassCSP: false,
        ignoreHTTPSErrors: false,
        javaScriptEnabled: true,
        serviceWorkers: 'block',
        viewport: { width: 1280, height: 720 }
      })
      await context.route('**/*', async (route) => {
        const request = route.request()
        const postData = request.postData() ?? undefined
        const frameUrl = request.frame().url()
        const decision = await broker.handle({
          url: request.url(),
          method: request.method().toUpperCase(),
          resourceType: request.resourceType(),
          headers: request.headers(),
          ...(postData ? { postData } : {}),
          isNavigation: request.isNavigationRequest(),
          ...(frameUrl ? { frameUrl } : {}),
          pageUrl: input.startUrl
        })
        if (decision.action === 'fulfill' && decision.fulfillment) {
          const headers = Object.fromEntries(
            Object.entries(decision.fulfillment.headers).filter(
              ([name]) => name.toLowerCase() !== 'set-cookie'
            )
          )
          await route.fulfill({
            status: decision.fulfillment.status,
            headers,
            body: Buffer.from(decision.fulfillment.body)
          })
          return
        }
        blockedTransports += 1
        await route.abort('blockedbyclient')
      })
      await context.routeWebSocket('**/*', async (webSocket) => {
        blockedTransports += 1
        await webSocket.close({
          code: 1008,
          reason: 'AgentGo mediated browser recon'
        })
      })
      await context.addInitScript(() => {
        const replace = (target: object, property: string, value: unknown): void => {
          try {
            Object.defineProperty(target, property, {
              configurable: false,
              enumerable: false,
              writable: false,
              value
            })
          } catch {
            // Offline routing remains the primary control.
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
      })
      const page = await context.newPage()
      page.setDefaultTimeout(input.timeoutMs)
      page.on('dialog', (dialog) => void dialog.dismiss().catch(() => undefined))
      page.on('popup', (popup) => {
        blockedTransports += 1
        void popup.close().catch(() => undefined)
      })
      if (input.signal?.aborted) {
        return {
          requestId: input.requestId,
          status: 'cancelled',
          finalUrl: input.startUrl,
          blockedTransports,
          durationMs: Date.now() - startedAt,
          errorCode: 'cancelled'
        }
      }
      await page.goto(input.startUrl, {
        waitUntil: 'domcontentloaded',
        timeout: input.timeoutMs
      })
      await page.waitForTimeout(50)
      const title = await page.title()
      return {
        requestId: input.requestId,
        status: 'succeeded',
        finalUrl: page.url() || input.startUrl,
        pageTitle: title.slice(0, 1_024),
        blockedTransports,
        durationMs: Date.now() - startedAt
      }
    } catch (error) {
      const cancelled = input.signal?.aborted
      const timeout =
        error instanceof Error && /timeout|timed out/i.test(error.message)
      return {
        requestId: input.requestId,
        status: cancelled ? 'cancelled' : 'failed',
        finalUrl: input.startUrl,
        blockedTransports,
        durationMs: Date.now() - startedAt,
        errorCode: cancelled ? 'cancelled' : timeout ? 'timeout' : 'render-error'
      }
    } finally {
      await browser?.close().catch(() => undefined)
    }
  }
}
