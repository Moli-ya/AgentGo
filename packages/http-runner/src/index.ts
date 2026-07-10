import { createHash } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { Agent, request, type Dispatcher } from 'undici'

export interface ResolvedAddress {
  address: string
  family: 4 | 6
}

export interface HttpExecutionAuthorizationInput {
  policyDecisionId: string
  url: string
  method: string
  redirectFrom?: string
  addresses: ResolvedAddress[]
}

export interface HttpExecutionGuard {
  authorize(input: HttpExecutionAuthorizationInput): Promise<void>
}

export interface HostnameResolver {
  resolve(hostname: string): Promise<ResolvedAddress[]>
}

export interface HttpExecutionRequest {
  requestId: string
  policyDecisionId: string
  targetUrl: string
  method: string
  headers?: Record<string, string>
  body?: string | Uint8Array
  timeoutMs: number
  maxResponseBytes?: number
  maxRedirects?: number
}

export interface HttpRedirectRecord {
  from: string
  to: string
  statusCode: number
}

export interface HttpExecutionResult {
  requestId: string
  status: 'succeeded' | 'failed' | 'cancelled'
  finalUrl: string
  method: string
  statusCode?: number
  requestHeaders: Record<string, string>
  responseHeaders: Record<string, string>
  responseBody?: Uint8Array
  requestBodySha256?: string
  responseBodySha256?: string
  responseBytes: number
  durationMs: number
  redirectChain: HttpRedirectRecord[]
  resolvedAddresses: string[]
  errorCode?:
    | 'authorization-denied'
    | 'dns-failed'
    | 'timeout'
    | 'response-too-large'
    | 'network-error'
    | 'cancelled'
  errorMessage?: string
}

const sensitiveHeaderNames = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  'x-api-key',
  'x-auth-token',
  'set-cookie'
])

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function redactHeaders(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name.toLowerCase(),
      sensitiveHeaderNames.has(name.toLowerCase()) ? '[REDACTED]' : value
    ])
  )
}

function normalizeResponseHeaders(
  headers: Record<string, string | string[] | undefined>
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter((entry): entry is [string, string | string[]] => entry[1] !== undefined)
      .map(([name, value]) => [
        name.toLowerCase(),
        sensitiveHeaderNames.has(name.toLowerCase())
          ? '[REDACTED]'
          : Array.isArray(value)
            ? value.join(', ')
            : value
      ])
  )
}

function locationHeader(
  headers: Record<string, string | string[] | undefined>
): string | undefined {
  const value = headers.location
  return Array.isArray(value) ? value[0] : value
}

function isRedirect(statusCode: number): boolean {
  return [301, 302, 303, 307, 308].includes(statusCode)
}

function redirectMethod(statusCode: number, currentMethod: string): string {
  if (statusCode === 303) return 'GET'
  if ([301, 302].includes(statusCode) && currentMethod === 'POST') return 'GET'
  return currentMethod
}

function removeCrossOriginCredentials(
  headers: Record<string, string>,
  from: URL,
  to: URL
): Record<string, string> {
  if (from.origin === to.origin) return headers
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !['authorization', 'cookie', 'proxy-authorization'].includes(name.toLowerCase())
    )
  )
}

const defaultResolver: HostnameResolver = {
  resolve: async (hostname) => {
    const literalVersion = isIP(hostname)
    if (literalVersion === 4 || literalVersion === 6) {
      return [{ address: hostname, family: literalVersion }]
    }
    const addresses = await lookup(hostname, { all: true, verbatim: true })
    return addresses.map((address) => ({
      address: address.address,
      family: address.family as 4 | 6
    }))
  }
}

class ResponseTooLargeError extends Error {}

export class UndiciHttpRunner {
  private readonly active = new Map<string, AbortController>()

  constructor(
    private readonly guard: HttpExecutionGuard,
    private readonly resolver: HostnameResolver = defaultResolver
  ) {}

  async execute(input: HttpExecutionRequest): Promise<HttpExecutionResult> {
    if (this.active.has(input.requestId)) {
      throw new Error(`HTTP request ${input.requestId} is already running.`)
    }

    const controller = new AbortController()
    this.active.set(input.requestId, controller)
    const startedAt = Date.now()
    const redirects: HttpRedirectRecord[] = []
    const allResolvedAddresses = new Set<string>()
    const maxRedirects = input.maxRedirects ?? 5
    const maxResponseBytes = input.maxResponseBytes ?? 5 * 1024 * 1024
    let currentUrl = new URL(input.targetUrl)
    let currentMethod = input.method.toUpperCase()
    let currentHeaders = { ...(input.headers ?? {}) }
    let currentBody = input.body
    let lastStatusCode: number | undefined
    let lastResponseHeaders: Record<string, string> = {}

    try {
      for (let redirectIndex = 0; redirectIndex <= maxRedirects; redirectIndex += 1) {
        let addresses: ResolvedAddress[]
        try {
          addresses = await this.resolver.resolve(currentUrl.hostname)
        } catch (error) {
          return this.failureResult({
            input,
            startedAt,
            finalUrl: currentUrl.toString(),
            method: currentMethod,
            requestHeaders: currentHeaders,
            redirects,
            addresses: allResolvedAddresses,
            errorCode: 'dns-failed',
            error
          })
        }

        try {
          await this.guard.authorize({
            policyDecisionId: input.policyDecisionId,
            url: currentUrl.toString(),
            method: currentMethod,
            ...(redirects.at(-1)?.from ? { redirectFrom: redirects.at(-1)!.from } : {}),
            addresses
          })
        } catch (error) {
          return this.failureResult({
            input,
            startedAt,
            finalUrl: currentUrl.toString(),
            method: currentMethod,
            requestHeaders: currentHeaders,
            redirects,
            addresses: allResolvedAddresses,
            errorCode: 'authorization-denied',
            error
          })
        }
        addresses.forEach((item) => allResolvedAddresses.add(item.address))

        const dispatcher = this.createPinnedDispatcher(addresses)
        try {
          const response = await request(currentUrl, {
            method: currentMethod as Dispatcher.HttpMethod,
            headers: currentHeaders,
            body: ['GET', 'HEAD'].includes(currentMethod) ? undefined : currentBody,
            dispatcher,
            headersTimeout: input.timeoutMs,
            bodyTimeout: input.timeoutMs,
            signal: controller.signal
          })
          lastStatusCode = response.statusCode
          lastResponseHeaders = normalizeResponseHeaders(response.headers)
          const location = locationHeader(response.headers)

          if (isRedirect(response.statusCode) && location) {
            for await (const _chunk of response.body) {
              // Drain the small redirect body so the socket can close cleanly.
            }
            if (redirectIndex >= maxRedirects) {
              throw new Error(`Redirect budget of ${maxRedirects} exhausted.`)
            }
            const nextUrl = new URL(location, currentUrl)
            redirects.push({
              from: currentUrl.toString(),
              to: nextUrl.toString(),
              statusCode: response.statusCode
            })
            const nextMethod = redirectMethod(response.statusCode, currentMethod)
            currentHeaders = removeCrossOriginCredentials(currentHeaders, currentUrl, nextUrl)
            if (nextMethod === 'GET') {
              currentBody = undefined
              currentHeaders = Object.fromEntries(
                Object.entries(currentHeaders).filter(
                  ([name]) => !['content-length', 'content-type'].includes(name.toLowerCase())
                )
              )
            }
            currentMethod = nextMethod
            currentUrl = nextUrl
            continue
          }

          const chunks: Uint8Array[] = []
          let totalBytes = 0
          for await (const chunk of response.body) {
            const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
            totalBytes += bytes.byteLength
            if (totalBytes > maxResponseBytes) {
              response.body.destroy()
              throw new ResponseTooLargeError(
                `Response exceeded ${maxResponseBytes} bytes.`
              )
            }
            chunks.push(bytes)
          }
          const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))
          return {
            requestId: input.requestId,
            status: 'succeeded',
            finalUrl: currentUrl.toString(),
            method: currentMethod,
            statusCode: response.statusCode,
            requestHeaders: redactHeaders(currentHeaders),
            responseHeaders: lastResponseHeaders,
            responseBody: body,
            ...(input.body !== undefined ? { requestBodySha256: sha256(input.body) } : {}),
            responseBodySha256: sha256(body),
            responseBytes: body.byteLength,
            durationMs: Date.now() - startedAt,
            redirectChain: redirects,
            resolvedAddresses: [...allResolvedAddresses]
          }
        } finally {
          await dispatcher.close()
        }
      }

      throw new Error('HTTP redirect loop ended unexpectedly.')
    } catch (error) {
      const aborted = controller.signal.aborted
      const timeout =
        error instanceof Error &&
        /headers timeout|body timeout|timed out|timeout/i.test(error.message)
      const responseTooLarge = error instanceof ResponseTooLargeError
      return {
        requestId: input.requestId,
        status: aborted ? 'cancelled' : 'failed',
        finalUrl: currentUrl.toString(),
        method: currentMethod,
        ...(lastStatusCode !== undefined ? { statusCode: lastStatusCode } : {}),
        requestHeaders: redactHeaders(currentHeaders),
        responseHeaders: lastResponseHeaders,
        ...(input.body !== undefined ? { requestBodySha256: sha256(input.body) } : {}),
        responseBytes: 0,
        durationMs: Date.now() - startedAt,
        redirectChain: redirects,
        resolvedAddresses: [...allResolvedAddresses],
        errorCode: aborted
          ? 'cancelled'
          : responseTooLarge
            ? 'response-too-large'
            : timeout
              ? 'timeout'
              : 'network-error',
        errorMessage: error instanceof Error ? error.message : 'HTTP execution failed.'
      }
    } finally {
      this.active.delete(input.requestId)
    }
  }

  async cancel(requestId: string): Promise<void> {
    this.active.get(requestId)?.abort()
  }

  private createPinnedDispatcher(addresses: ResolvedAddress[]): Agent {
    const selected = addresses[0]
    if (!selected) throw new Error('No resolved address available for connection.')
    return new Agent({
      connect: {
        lookup: (_hostname, options, callback) => {
          if (options.all) {
            callback(
              null,
              addresses.map((item) => ({
                address: item.address,
                family: item.family
              }))
            )
            return
          }
          callback(null, selected.address, selected.family)
        }
      }
    })
  }

  private failureResult(input: {
    input: HttpExecutionRequest
    startedAt: number
    finalUrl: string
    method: string
    requestHeaders: Record<string, string>
    redirects: HttpRedirectRecord[]
    addresses: Set<string>
    errorCode: HttpExecutionResult['errorCode']
    error: unknown
  }): HttpExecutionResult {
    return {
      requestId: input.input.requestId,
      status: 'failed',
      finalUrl: input.finalUrl,
      method: input.method,
      requestHeaders: redactHeaders(input.requestHeaders),
      responseHeaders: {},
      ...(input.input.body !== undefined
        ? { requestBodySha256: sha256(input.input.body) }
        : {}),
      responseBytes: 0,
      durationMs: Date.now() - input.startedAt,
      redirectChain: input.redirects,
      resolvedAddresses: [...input.addresses],
      errorCode: input.errorCode,
      errorMessage:
        input.error instanceof Error ? input.error.message : 'HTTP execution failed.'
    }
  }
}

export type HttpRunner = Pick<UndiciHttpRunner, 'execute' | 'cancel'>
