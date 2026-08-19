import { createHash } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
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
  readonly signal?: AbortSignal
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
      signal?: AbortSignal
    }>
  | undefined {
  const candidate = snapshotExactDataObject(
    input,
    ['requestId', 'leaseId', 'wire', 'timeoutMs'],
    ['maxResponseBytes', 'signal']
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
      !(candidate.signal instanceof AbortSignal))
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
    ...(candidate.signal !== undefined
      ? { signal: candidate.signal as AbortSignal }
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
            executionRequest.maxResponseBytes < 0))
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

      const chunks: Uint8Array[] = []
      for await (const chunk of response.body) {
        const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
        responseBytes += bytes.byteLength
        if (responseBytes > maxResponseBytes) {
          this.abortResponseBody(response.body)
          throw new HttpRunnerStageError('response-too-large')
        }
        chunks.push(bytes)
      }
      this.throwIfCancelled(controller.signal)
      const responseBody = Uint8Array.from(
        Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))
      )
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
