import { createHash } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib'
import { Agent, request, type Dispatcher } from 'undici'

export interface ResolvedAddress {
  readonly address: string
  readonly family: 4 | 6
}

export interface HttpWireHeader {
  readonly name: string
  readonly value: string
}

export interface HttpExactWireRequest {
  readonly method: string
  readonly url: string
  /**
   * Canonical, authorization-bound headers. Their sorted order is part of the
   * wire HMAC, but not a promise about HTTP/1 serialization order: the pinned
   * transport owns `host`/`connection` and may serialize `content-length` in
   * its framing section after the application headers.
   */
  readonly headers: readonly HttpWireHeader[]
  readonly bodyBytes?: readonly number[]
}

export interface HttpExecutionLimits {
  readonly timeoutMs: number
  readonly maxResponseBytes: number
}

export interface HttpExecutionClaimInput {
  readonly leaseId: string
  readonly wire: HttpExactWireRequest
  readonly limits: HttpExecutionLimits
}

export interface HttpExecutionGuard<ClaimToken extends object = object> {
  /** Atomically consumes the lease and returns an opaque, in-memory token. */
  claim(input: HttpExecutionClaimInput): Promise<ClaimToken>
  /**
   * Revalidates and binds the post-claim DNS result before dispatch. DNS is
   * intentionally deferred until after the single-use lease is consumed.
   */
  validateResolvedAddresses(
    claimToken: ClaimToken,
    addresses: readonly ResolvedAddress[]
  ): Promise<void>
  /** Persists the claimed-to-dispatched transition before any network send. */
  markDispatched(claimToken: ClaimToken): Promise<void>
  /** Persists that response headers arrived before body consumption starts. */
  markResponseStarted(claimToken: ClaimToken): Promise<void>
}

export interface HostnameResolver {
  resolve(hostname: string): Promise<ResolvedAddress[]>
}

export interface HttpExecutionRequest {
  readonly requestId: string
  readonly leaseId: string
  readonly wire: HttpExactWireRequest
  readonly timeoutMs: number
  readonly maxResponseBytes?: number
  readonly maxHeaderBytes?: number
  readonly maxDecompressedBytes?: number
  readonly maxCompressionRatio?: number
  readonly slowReadTimeoutMs?: number
  readonly signal?: AbortSignal
  /**
   * Private sink for raw Set-Cookie values. Values flow only to this
   * callback; they are never added to the result, logs, or evidence. The
   * runner does not interpret them — the owning session vault does.
   */
  readonly setCookieSink?: (
    cookies: readonly string[],
    requestUrl: string
  ) => void
}

export interface HttpExecutionResult<ClaimToken extends object = object> {
  readonly requestId: string
  readonly status: 'succeeded' | 'failed' | 'cancelled'
  readonly finalUrl: string
  readonly method: string
  readonly statusCode?: number
  readonly redirectLocation?: string
  readonly requestHeaders: readonly HttpWireHeader[]
  readonly responseHeaders: Record<string, string>
  readonly responseBody?: Uint8Array
  readonly requestBodySha256?: string
  readonly responseBodySha256?: string
  readonly responseBytes: number
  readonly durationMs: number
  readonly resolvedAddresses: readonly string[]
  /**
   * Ephemeral and opaque. Return this exact token to the lease owner for
   * conditional finalization; never log, serialize, persist, or add it to evidence.
   */
  readonly claimToken?: ClaimToken
  readonly errorCode?:
    | 'invalid-wire'
    | 'dns-failed'
    | 'claim-rejected'
    | 'address-rejected'
    | 'dispatch-mark-failed'
    | 'response-start-mark-failed'
    | 'timeout'
    | 'response-too-large'
    | 'response-header-too-large'
    | 'response-decompressed-too-large'
    | 'response-compression-bomb'
    | 'response-decompression-failed'
    | 'response-slow-read'
    | 'network-error'
    | 'cancelled'
    | 'runner-output-invalid'
  readonly errorMessage?: string
}

const exposedResponseHeaderNames = new Set([
  'content-security-policy',
  'content-type'
])
const httpMethodPattern = /^[!#$%&'*+.^_`|~0-9A-Z-]+$/u
const httpFieldNamePattern = /^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u
const printableHeaderValuePattern = /^[\x20-\x7e]*$/u
const defaultMaxResponseBytes = 5 * 1024 * 1024
const defaultMaxHeaderBytes = 64 * 1024
const defaultMaxCompressionRatio = 100
const defaultSlowReadTimeoutMs = 10_000

/**
 * These are the only fields that the pinned HTTP/1 transport may add to the
 * authorization-bound header set. Their values are derived from the canonical
 * URL and connection state, never accepted from a caller.
 */
export const HTTP_TRANSPORT_DERIVED_HEADER_NAMES = Object.freeze([
  'connection',
  'host'
] as const)

const transportDerivedHeaderNames = new Set<string>(
  HTTP_TRANSPORT_DERIVED_HEADER_NAMES
)
const unsupportedTransportControlHeaderNames = new Set([
  ...transportDerivedHeaderNames,
  'expect',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
])

type HttpExecutionErrorCode = NonNullable<HttpExecutionResult['errorCode']>

const safeErrorMessages: Record<HttpExecutionErrorCode, string> = {
  'invalid-wire': 'The HTTP execution request is not canonical.',
  'dns-failed': 'The target hostname could not be resolved safely.',
  'claim-rejected': 'The execution lease could not be claimed.',
  'address-rejected': 'The resolved target addresses were rejected.',
  'dispatch-mark-failed': 'The execution dispatch could not be persisted.',
  'response-start-mark-failed': 'The response-start transition could not be persisted.',
  timeout: 'The HTTP execution timed out.',
  'response-too-large': 'The HTTP response exceeded the configured byte limit.',
  'response-header-too-large':
    'The HTTP response headers exceeded the configured byte limit.',
  'response-decompressed-too-large':
    'The HTTP response exceeded the decompressed byte limit.',
  'response-compression-bomb':
    'The HTTP response exceeded the compression ratio limit.',
  'response-decompression-failed':
    'The HTTP response body could not be decompressed.',
  'response-slow-read': 'The HTTP response body read timed out between chunks.',
  'network-error': 'The HTTP execution failed.',
  cancelled: 'The HTTP execution was cancelled.',
  'runner-output-invalid': 'The HTTP runner returned an invalid result.'
}

class HttpRunnerStageError extends Error {
  constructor(readonly code: HttpExecutionErrorCode) {
    super(safeErrorMessages[code])
    this.name = 'HttpRunnerStageError'
  }
}

const dispatcherCloseGraceMs = 1_000

function attachClaimToken<ClaimToken extends object>(
  result: HttpExecutionResult<ClaimToken>,
  claimToken: ClaimToken
): HttpExecutionResult<ClaimToken> {
  Object.defineProperty(result, 'claimToken', {
    value: claimToken,
    enumerable: false,
    configurable: false,
    writable: false
  })
  return result
}

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function headerByteLength(
  headers: Record<string, string | string[] | undefined>
): number {
  let total = 0
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue
    const values = Array.isArray(value) ? value : [value]
    for (const item of values) {
      total +=
        Buffer.byteLength(name, 'latin1') +
        Buffer.byteLength(item, 'latin1') +
        4
    }
  }
  return total
}

function declaredContentLength(
  headers: Record<string, string | string[] | undefined>
): number | undefined {
  const raw = headers['content-length']
  const value = Array.isArray(raw) ? raw[0] : raw
  if (value === undefined) return undefined
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined
}

function compressedContentEncoding(
  headers: Record<string, string | string[] | undefined>
): 'gzip' | 'deflate' | 'br' | undefined {
  const raw = headers['content-encoding']
  const value = (Array.isArray(raw) ? raw[0] : raw)?.toLowerCase() ?? ''
  if (/(?:^|,)\s*gzip\s*(?:$|,)/.test(value)) return 'gzip'
  if (/(?:^|,)\s*deflate\s*(?:$|,)/.test(value)) return 'deflate'
  if (/(?:^|,)\s*br\s*(?:$|,)/.test(value)) return 'br'
  return undefined
}

function decompressBounded(
  encoding: 'gzip' | 'deflate' | 'br',
  raw: Buffer,
  maxDecompressedBytes: number
): Uint8Array {
  try {
    const options = { maxOutputLength: maxDecompressedBytes }
    if (encoding === 'gzip') return new Uint8Array(gunzipSync(raw, options))
    if (encoding === 'deflate') return new Uint8Array(inflateSync(raw, options))
    return new Uint8Array(brotliDecompressSync(raw, options))
  } catch (error) {
    if (
      error instanceof RangeError ||
      (error instanceof Error && /exceeded/i.test(error.message))
    ) {
      throw new HttpRunnerStageError('response-decompressed-too-large')
    }
    // Corrupt or otherwise undecodable payloads are not compression bombs;
    // only the post-decompression ratio check may raise that code.
    throw new HttpRunnerStageError('response-decompression-failed')
  }
}

function redactRequestHeaders(
  headers: readonly HttpWireHeader[]
): readonly HttpWireHeader[] {
  return Object.freeze(
    headers.map((header) =>
      Object.freeze({
        name: header.name.toLowerCase(),
        value: '[REDACTED]'
      })
    )
  )
}

function normalizeResponseHeaders(
  headers: Record<string, string | string[] | undefined>
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter(
        (entry): entry is [string, string | string[]] =>
          entry[1] !== undefined &&
          exposedResponseHeaderNames.has(entry[0].toLowerCase())
      )
      .map(([name, value]) => [
        name.toLowerCase(),
        Array.isArray(value)
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

function snapshotExactDataObject(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = []
): Readonly<Record<string, unknown>> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return undefined
  }
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      return undefined
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const keys = Reflect.ownKeys(descriptors)
    const allowedKeys = new Set([...requiredKeys, ...optionalKeys])
    if (
      keys.some(
        (key) => typeof key !== 'string' || !allowedKeys.has(key)
      ) ||
      requiredKeys.some((key) => !Object.hasOwn(descriptors, key))
    ) {
      return undefined
    }
    const snapshot: Record<string, unknown> = Object.create(null)
    for (const key of keys) {
      if (typeof key !== 'string') return undefined
      const descriptor = descriptors[key]
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        return undefined
      }
      snapshot[key] = descriptor.value
    }
    return Object.freeze(snapshot)
  } catch {
    return undefined
  }
}

function snapshotExactArray(value: unknown): readonly unknown[] | undefined {
  if (!Array.isArray(value)) return undefined
  try {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      return undefined
    }
    const descriptors = Object.getOwnPropertyDescriptors(
      value
    ) as unknown as Record<PropertyKey, PropertyDescriptor>
    const lengthDescriptor = descriptors['length']
    if (
      !lengthDescriptor ||
      !Object.hasOwn(lengthDescriptor, 'value') ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0
    ) {
      return undefined
    }
    const length = lengthDescriptor.value as number
    const keys = Reflect.ownKeys(descriptors)
    if (
      keys.length !== length + 1 ||
      keys.some(
        (key) =>
          key !== 'length' &&
          (typeof key !== 'string' ||
            !/^(?:0|[1-9][0-9]*)$/u.test(key) ||
            Number(key) >= length)
      )
    ) {
      return undefined
    }
    const snapshot: unknown[] = []
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)]
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        return undefined
      }
      snapshot.push(descriptor.value)
    }
    return Object.freeze(snapshot)
  } catch {
    return undefined
  }
}

function snapshotExecutionRequest(
  input: HttpExecutionRequest
):
  | Readonly<{
      requestId: string
      leaseId: string
      wire: HttpExactWireRequest
      timeoutMs: number
      maxResponseBytes?: number
      maxHeaderBytes?: number
      maxDecompressedBytes?: number
      maxCompressionRatio?: number
      slowReadTimeoutMs?: number
      signal?: AbortSignal
      setCookieSink?: (cookies: readonly string[], requestUrl: string) => void
    }>
  | undefined {
  const candidate = snapshotExactDataObject(
    input,
    ['requestId', 'leaseId', 'wire', 'timeoutMs'],
    [
      'maxResponseBytes',
      'maxHeaderBytes',
      'maxDecompressedBytes',
      'maxCompressionRatio',
      'slowReadTimeoutMs',
      'signal',
      'setCookieSink'
    ]
  )
  if (
    !candidate ||
    typeof candidate.requestId !== 'string' ||
    candidate.requestId.length === 0 ||
    typeof candidate.leaseId !== 'string' ||
    candidate.leaseId.length === 0 ||
    !candidate.wire ||
    typeof candidate.wire !== 'object' ||
    !Number.isSafeInteger(candidate.timeoutMs) ||
    (candidate.signal !== undefined &&
      !(candidate.signal instanceof AbortSignal)) ||
    (candidate.setCookieSink !== undefined &&
      typeof candidate.setCookieSink !== 'function')
  ) {
    return undefined
  }
  return Object.freeze({
    requestId: candidate.requestId,
    leaseId: candidate.leaseId,
    wire: candidate.wire as HttpExactWireRequest,
    timeoutMs: candidate.timeoutMs as number,
    ...(candidate.maxResponseBytes !== undefined
      ? { maxResponseBytes: candidate.maxResponseBytes as number }
      : {}),
    ...(candidate.maxHeaderBytes !== undefined
      ? { maxHeaderBytes: candidate.maxHeaderBytes as number }
      : {}),
    ...(candidate.maxDecompressedBytes !== undefined
      ? { maxDecompressedBytes: candidate.maxDecompressedBytes as number }
      : {}),
    ...(candidate.maxCompressionRatio !== undefined
      ? { maxCompressionRatio: candidate.maxCompressionRatio as number }
      : {}),
    ...(candidate.slowReadTimeoutMs !== undefined
      ? { slowReadTimeoutMs: candidate.slowReadTimeoutMs as number }
      : {}),
    ...(candidate.signal !== undefined
      ? { signal: candidate.signal as AbortSignal }
      : {}),
    ...(candidate.setCookieSink !== undefined
      ? {
          setCookieSink: candidate.setCookieSink as (
            cookies: readonly string[],
            requestUrl: string
          ) => void
        }
      : {})
  })
}

function snapshotWire(input: HttpExactWireRequest): {
  readonly wire: HttpExactWireRequest
  readonly url: URL
  readonly bodyBytes?: Uint8Array
  readonly undiciHeaders: string[]
} {
  const candidate = snapshotExactDataObject(
    input,
    ['method', 'url', 'headers'],
    ['bodyBytes']
  )
  const inputHeaders = snapshotExactArray(candidate?.headers)
  if (
    !candidate ||
    typeof candidate.method !== 'string' ||
    candidate.method !== candidate.method.toUpperCase() ||
    !httpMethodPattern.test(candidate.method) ||
    typeof candidate.url !== 'string' ||
    !inputHeaders
  ) {
    throw new HttpRunnerStageError('invalid-wire')
  }
  const method = candidate.method
  const wireUrl = candidate.url

  let url: URL
  try {
    url = new URL(wireUrl)
  } catch {
    throw new HttpRunnerStageError('invalid-wire')
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.hash !== '' ||
    url.toString() !== wireUrl
  ) {
    throw new HttpRunnerStageError('invalid-wire')
  }

  let previousName: string | undefined
  let contentLength: string | undefined
  const headers = inputHeaders.map((rawHeader) => {
    const header = snapshotExactDataObject(rawHeader, ['name', 'value'])
    if (
      !header ||
      typeof header.name !== 'string' ||
      typeof header.value !== 'string' ||
      !httpFieldNamePattern.test(header.name) ||
      !printableHeaderValuePattern.test(header.value) ||
      header.value !== header.value.trim() ||
      unsupportedTransportControlHeaderNames.has(header.name) ||
      (previousName !== undefined && previousName >= header.name)
    ) {
      throw new HttpRunnerStageError('invalid-wire')
    }
    previousName = header.name
    if (header.name === 'content-length') {
      contentLength = header.value
    }
    return Object.freeze({ name: header.name, value: header.value })
  })

  let bodyBytes: Uint8Array | undefined
  let frozenBodyBytes: readonly number[] | undefined
  if (candidate.bodyBytes !== undefined) {
    const inputBodyBytes = snapshotExactArray(candidate.bodyBytes)
    if (!inputBodyBytes) {
      throw new HttpRunnerStageError('invalid-wire')
    }
    const copied = inputBodyBytes.map((byte) => {
      if (
        typeof byte !== 'number' ||
        !Number.isInteger(byte) ||
        byte < 0 ||
        byte > 255
      ) {
        throw new HttpRunnerStageError('invalid-wire')
      }
      return byte
    })
    frozenBodyBytes = Object.freeze(copied)
    bodyBytes = Uint8Array.from(copied)
  }
  if (bodyBytes !== undefined && ['GET', 'HEAD'].includes(method)) {
    throw new HttpRunnerStageError('invalid-wire')
  }
  if (
    (bodyBytes === undefined && contentLength !== undefined) ||
    (bodyBytes !== undefined && contentLength !== String(bodyBytes.byteLength))
  ) {
    throw new HttpRunnerStageError('invalid-wire')
  }

  const wire = Object.freeze({
    method,
    url: wireUrl,
    headers: Object.freeze(headers),
    ...(frozenBodyBytes !== undefined ? { bodyBytes: frozenBodyBytes } : {})
  })
  return Object.freeze({
    wire,
    url,
    ...(bodyBytes !== undefined ? { bodyBytes } : {}),
    undiciHeaders: headers.flatMap((header) => [header.name, header.value])
  })
}

function summarizeInvalidWire(input: unknown): {
  readonly method: string
  readonly url: string
  readonly headers: readonly HttpWireHeader[]
} {
  if (!input || typeof input !== 'object') {
    return { method: '', url: '', headers: [] }
  }
  const candidate = snapshotExactDataObject(
    input,
    [],
    ['method', 'url', 'headers', 'bodyBytes']
  )
  const candidateHeaders = snapshotExactArray(candidate?.headers)
  const headers = candidateHeaders
    ? candidateHeaders.flatMap((rawHeader) => {
        const header = snapshotExactDataObject(rawHeader, ['name', 'value'])
        return header &&
          typeof header.name === 'string' &&
          typeof header.value === 'string'
          ? [{ name: header.name, value: header.value }]
          : []
      })
    : []
  return {
    method: typeof candidate?.method === 'string' ? candidate.method : '',
    url: typeof candidate?.url === 'string' ? candidate.url : '',
    headers: redactRequestHeaders(headers)
  }
}

function isTimeoutError(error: unknown): boolean {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = (error as { code?: unknown }).code
    if (
      code === 'UND_ERR_CONNECT_TIMEOUT' ||
      code === 'UND_ERR_HEADERS_TIMEOUT' ||
      code === 'UND_ERR_BODY_TIMEOUT'
    ) {
      return true
    }
  }
  return error instanceof Error && /timed out|timeout/iu.test(error.message)
}

async function raceWithAbort<T>(
  operation: Promise<T>,
  signal: AbortSignal
): Promise<T> {
  if (signal.aborted) throw signal.reason
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

function resolutionHostname(url: URL): string {
  return url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname
}

function snapshotAddresses(addresses: ResolvedAddress[]): readonly ResolvedAddress[] {
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new HttpRunnerStageError('dns-failed')
  }
  return Object.freeze(
    addresses.map((item) => {
      if (
        !item ||
        typeof item.address !== 'string' ||
        (item.family !== 4 && item.family !== 6) ||
        isIP(item.address) !== item.family
      ) {
        throw new HttpRunnerStageError('dns-failed')
      }
      return Object.freeze({ address: item.address, family: item.family })
    })
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

export class UndiciHttpRunner<ClaimToken extends object = object> {
  private readonly active = new Map<string, AbortController>()

  constructor(
    private readonly guard: HttpExecutionGuard<ClaimToken>,
    private readonly resolver: HostnameResolver = defaultResolver
  ) {}

  async execute(
    input: HttpExecutionRequest
  ): Promise<HttpExecutionResult<ClaimToken>> {
    const startedAt = Date.now()
    const executionRequest = snapshotExecutionRequest(input)
    if (!executionRequest) {
      return {
        requestId: '',
        status: 'failed',
        finalUrl: '',
        method: '',
        requestHeaders: Object.freeze([]),
        responseHeaders: {},
        responseBytes: 0,
        durationMs: Date.now() - startedAt,
        resolvedAddresses: Object.freeze([]),
        errorCode: 'invalid-wire',
        errorMessage: safeErrorMessages['invalid-wire']
      }
    }
    if (this.active.has(executionRequest.requestId)) {
      throw new Error(
        `HTTP request ${executionRequest.requestId} is already running.`
      )
    }

    const controller = new AbortController()
    this.active.set(executionRequest.requestId, controller)
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined
    let deadlineAt = startedAt
    let prepared: ReturnType<typeof snapshotWire> | undefined
    let addresses: readonly ResolvedAddress[] = []
    let dispatcher: Agent | undefined
    let statusCode: number | undefined
    let redirectLocation: string | undefined
    let responseHeaders: Record<string, string> = {}
    let responseBytes = 0
    let claimToken: ClaimToken | undefined
    let claimed = false
    let completedNormally = false
    let externalCancellationRequested =
      executionRequest.signal?.aborted ?? false
    const onExternalAbort = (): void => {
      externalCancellationRequested = true
      if (claimed && !controller.signal.aborted) {
        controller.abort(new HttpRunnerStageError('cancelled'))
      }
    }
    executionRequest.signal?.addEventListener('abort', onExternalAbort, {
      once: true
    })

    const remainingMs = (): number => {
      this.throwIfCancelled(controller.signal)
      const remaining = deadlineAt - Date.now()
      if (remaining <= 0) {
        const timeout = new HttpRunnerStageError('timeout')
        controller.abort(timeout)
        throw timeout
      }
      return remaining
    }

    try {
      if (
        executionRequest.timeoutMs <= 0 ||
        (executionRequest.maxResponseBytes !== undefined &&
          (!Number.isSafeInteger(executionRequest.maxResponseBytes) ||
            executionRequest.maxResponseBytes < 0)) ||
        (executionRequest.maxHeaderBytes !== undefined &&
          (!Number.isSafeInteger(executionRequest.maxHeaderBytes) ||
            executionRequest.maxHeaderBytes < 0)) ||
        (executionRequest.maxDecompressedBytes !== undefined &&
          (!Number.isSafeInteger(executionRequest.maxDecompressedBytes) ||
            executionRequest.maxDecompressedBytes < 0)) ||
        (executionRequest.maxCompressionRatio !== undefined &&
          (!Number.isFinite(executionRequest.maxCompressionRatio) ||
            executionRequest.maxCompressionRatio < 1)) ||
        (executionRequest.slowReadTimeoutMs !== undefined &&
          (!Number.isSafeInteger(executionRequest.slowReadTimeoutMs) ||
            executionRequest.slowReadTimeoutMs <= 0))
      ) {
        throw new HttpRunnerStageError('invalid-wire')
      }
      deadlineAt = startedAt + executionRequest.timeoutMs
      deadlineTimer = setTimeout(() => {
        controller.abort(new HttpRunnerStageError('timeout'))
      }, remainingMs())
      prepared = snapshotWire(executionRequest.wire)
      const maxResponseBytes =
        executionRequest.maxResponseBytes ?? defaultMaxResponseBytes
      const maxHeaderBytes =
        executionRequest.maxHeaderBytes ?? defaultMaxHeaderBytes
      const maxDecompressedBytes =
        executionRequest.maxDecompressedBytes ?? maxResponseBytes
      const maxCompressionRatio =
        executionRequest.maxCompressionRatio ?? defaultMaxCompressionRatio
      const slowReadTimeoutMs = Math.min(
        executionRequest.slowReadTimeoutMs ?? defaultSlowReadTimeoutMs,
        executionRequest.timeoutMs
      )

      try {
        claimToken = await this.guard.claim(
          Object.freeze({
            leaseId: executionRequest.leaseId,
            wire: prepared.wire,
            limits: Object.freeze({
              timeoutMs: executionRequest.timeoutMs,
              maxResponseBytes
            })
          })
        )
        claimed = true
      } catch {
        throw new HttpRunnerStageError('claim-rejected')
      }
      if (externalCancellationRequested && !controller.signal.aborted) {
        controller.abort(new HttpRunnerStageError('cancelled'))
      }
      this.throwIfCancelled(controller.signal)

      let resolved: ResolvedAddress[]
      try {
        resolved = await raceWithAbort(
          this.resolver.resolve(resolutionHostname(prepared.url)),
          controller.signal
        )
      } catch {
        this.throwIfCancelled(controller.signal)
        throw new HttpRunnerStageError('dns-failed')
      }
      addresses = snapshotAddresses(resolved)
      try {
        await this.guard.validateResolvedAddresses(
          claimToken as ClaimToken,
          addresses
        )
      } catch {
        throw new HttpRunnerStageError('address-rejected')
      }
      dispatcher = this.createPinnedDispatcher(addresses, remainingMs())
      this.throwIfCancelled(controller.signal)

      try {
        await this.guard.markDispatched(claimToken as ClaimToken)
      } catch {
        throw new HttpRunnerStageError('dispatch-mark-failed')
      }
      this.throwIfCancelled(controller.signal)

      const response = await request(prepared.url, {
        method: prepared.wire.method as Dispatcher.HttpMethod,
        headers: prepared.undiciHeaders,
        body: prepared.bodyBytes,
        dispatcher,
        headersTimeout: remainingMs(),
        bodyTimeout: remainingMs(),
        signal: controller.signal
      })
      statusCode = response.statusCode
      responseHeaders = normalizeResponseHeaders(response.headers)
      if (executionRequest.setCookieSink) {
        const setCookieValues = response.headers['set-cookie']
        const cookies = Array.isArray(setCookieValues)
          ? setCookieValues.filter((value) => typeof value === 'string')
          : typeof setCookieValues === 'string'
            ? [setCookieValues]
            : []
        if (cookies.length > 0) {
          try {
            executionRequest.setCookieSink(Object.freeze([...cookies]), prepared!.wire.url)
          } catch {
            // A vault-side rejection must not fail the authorized request.
          }
        }
      }
      const location = locationHeader(response.headers)
      if (response.statusCode >= 300 && response.statusCode < 400 && location) {
        redirectLocation = location
      }
      try {
        await this.guard.markResponseStarted(claimToken as ClaimToken)
      } catch {
        this.abortResponseBody(response.body)
        throw new HttpRunnerStageError('response-start-mark-failed')
      }
      this.throwIfCancelled(controller.signal)

      if (headerByteLength(response.headers) > maxHeaderBytes) {
        this.abortResponseBody(response.body)
        throw new HttpRunnerStageError('response-header-too-large')
      }
      const contentEncoding = compressedContentEncoding(response.headers)
      const declaredLength = declaredContentLength(response.headers)
      if (declaredLength !== undefined && declaredLength > maxResponseBytes) {
        this.abortResponseBody(response.body)
        throw new HttpRunnerStageError('response-too-large')
      }

      const chunks: Uint8Array[] = []
      const bodyIterator = response.body[Symbol.asyncIterator]()
      while (true) {
        let timedOut = false
        let timeoutTimer: ReturnType<typeof setTimeout> | undefined
        const timeout = new Promise<never>((_resolve, reject) => {
          timeoutTimer = setTimeout(() => {
            timedOut = true
            this.abortResponseBody(response.body)
            reject(new HttpRunnerStageError('response-slow-read'))
          }, slowReadTimeoutMs)
        })
        let next: IteratorResult<unknown>
        try {
          next = await Promise.race([bodyIterator.next(), timeout])
        } catch (error) {
          if (timedOut || (error instanceof HttpRunnerStageError && error.code === 'response-slow-read')) {
            throw new HttpRunnerStageError('response-slow-read')
          }
          throw error
        } finally {
          if (timeoutTimer) clearTimeout(timeoutTimer)
        }
        if (next.done) break
        const chunk = next.value
        const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk as ArrayBufferLike)
        responseBytes += bytes.byteLength
        if (responseBytes > maxResponseBytes) {
          this.abortResponseBody(response.body)
          throw new HttpRunnerStageError('response-too-large')
        }
        chunks.push(bytes)
      }
      this.throwIfCancelled(controller.signal)
      const rawBody = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))
      let responseBody: Uint8Array = new Uint8Array(rawBody)
      if (contentEncoding) {
        responseBody = decompressBounded(
          contentEncoding,
          rawBody,
          maxDecompressedBytes
        )
        if (rawBody.byteLength > 0 &&
          responseBody.byteLength > rawBody.byteLength * maxCompressionRatio
        ) {
          throw new HttpRunnerStageError('response-compression-bomb')
        }
      } else if (responseBody.byteLength > maxDecompressedBytes) {
        throw new HttpRunnerStageError('response-decompressed-too-large')
      }
      const result: HttpExecutionResult<ClaimToken> = {
        requestId: executionRequest.requestId,
        status: 'succeeded',
        finalUrl: prepared.wire.url,
        method: prepared.wire.method,
        statusCode: response.statusCode,
        ...(redirectLocation !== undefined ? { redirectLocation } : {}),
        requestHeaders: redactRequestHeaders(prepared.wire.headers),
        responseHeaders,
        responseBody,
        ...(prepared.bodyBytes !== undefined
          ? { requestBodySha256: sha256(prepared.bodyBytes) }
          : {}),
        responseBodySha256: sha256(responseBody),
        responseBytes: responseBody.byteLength,
        durationMs: Date.now() - startedAt,
        resolvedAddresses: addresses.map((item) => item.address)
      }
      completedNormally = true
      return attachClaimToken(result, claimToken as ClaimToken)
    } catch (error) {
      const abortReason = controller.signal.reason
      const errorCode: HttpExecutionErrorCode =
        abortReason instanceof HttpRunnerStageError
          ? abortReason.code
          : controller.signal.aborted
            ? 'cancelled'
            : error instanceof HttpRunnerStageError
          ? error.code
          : isTimeoutError(error)
            ? 'timeout'
            : 'network-error'
      const invalidSummary = summarizeInvalidWire(executionRequest.wire)
      const result: HttpExecutionResult<ClaimToken> = {
        requestId: executionRequest.requestId,
        status: errorCode === 'cancelled' ? 'cancelled' : 'failed',
        finalUrl: prepared?.wire.url ?? invalidSummary.url,
        method: prepared?.wire.method ?? invalidSummary.method,
        ...(statusCode !== undefined ? { statusCode } : {}),
        ...(redirectLocation !== undefined ? { redirectLocation } : {}),
        requestHeaders:
          prepared !== undefined
            ? redactRequestHeaders(prepared.wire.headers)
            : invalidSummary.headers,
        responseHeaders,
        ...(prepared?.bodyBytes !== undefined
          ? { requestBodySha256: sha256(prepared.bodyBytes) }
          : {}),
        responseBytes,
        durationMs: Date.now() - startedAt,
        resolvedAddresses: addresses.map((item) => item.address),
        errorCode,
        errorMessage: safeErrorMessages[errorCode]
      }
      return claimed
        ? attachClaimToken(result, claimToken as ClaimToken)
        : result
    } finally {
      executionRequest.signal?.removeEventListener('abort', onExternalAbort)
      if (deadlineTimer) clearTimeout(deadlineTimer)
      if (dispatcher) {
        if (!completedNormally || controller.signal.aborted) {
          void dispatcher
            .destroy(new Error('AgentGo HTTP execution ended before clean completion.'))
            .catch(() => undefined)
        } else {
          const closeResult = dispatcher.close().then(
            () => true,
            () => false
          )
          let graceTimer: ReturnType<typeof setTimeout> | undefined
          const closed = await Promise.race([
            closeResult,
            new Promise<false>((resolve) => {
              graceTimer = setTimeout(
                () => resolve(false),
                dispatcherCloseGraceMs
              )
            })
          ])
          if (graceTimer) clearTimeout(graceTimer)
          if (!closed) {
            void dispatcher
              .destroy(new Error('AgentGo HTTP dispatcher close exceeded its grace period.'))
              .catch(() => undefined)
          }
        }
      }
      this.active.delete(executionRequest.requestId)
    }
  }

  async cancel(requestId: string): Promise<void> {
    this.active
      .get(requestId)
      ?.abort(new HttpRunnerStageError('cancelled'))
  }

  private throwIfCancelled(signal: AbortSignal): void {
    if (!signal.aborted) return
    if (signal.reason instanceof HttpRunnerStageError) {
      throw signal.reason
    }
    throw new HttpRunnerStageError('cancelled')
  }

  private abortResponseBody(
    body: Dispatcher.ResponseData['body']
  ): void {
    // Undici emits UND_ERR_ABORTED asynchronously when an unread body is
    // destroyed. Install the handler first so a deliberate fail-closed abort
    // cannot escape as an uncaught exception after execute() has returned.
    body.once('error', () => undefined)
    body.destroy()
  }

  private createPinnedDispatcher(
    addresses: readonly ResolvedAddress[],
    timeoutMs: number
  ): Agent {
    const selected = addresses[0]
    if (!selected) throw new HttpRunnerStageError('dns-failed')
    return new Agent({
      connect: {
        timeout: timeoutMs,
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
}

export type HttpRunner<ClaimToken extends object = object> = Pick<
  UndiciHttpRunner<ClaimToken>,
  'execute' | 'cancel'
>
