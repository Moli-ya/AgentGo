import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import { canonicalJson } from '@agentgo/domain'
import { z } from 'zod'
import type { MaterializedWireRequest } from './request-compiler'

const sha256Pattern = /^[0-9a-f]{64}$/u
const maxValidationNodes = 20_000
const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype
) as object
const typedArrayByteLengthGetter =
  Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    'byteLength'
  )?.get
const forbiddenByteArrayOwnProperties = Object.freeze([
  'buffer',
  'byteLength',
  'byteOffset',
  'constructor',
  'length',
  'set',
  'slice',
  'subarray'
])
const allowedResponseHeaderNames = new Set([
  'content-security-policy',
  'content-type'
])

const httpErrorMessages = Object.freeze({
  'invalid-wire': 'The HTTP execution request is not canonical.',
  'dns-failed': 'The target hostname could not be resolved safely.',
  'claim-rejected': 'The execution lease could not be claimed.',
  'address-rejected': 'The resolved target addresses were rejected.',
  'dispatch-mark-failed': 'The execution dispatch could not be persisted.',
  'response-start-mark-failed':
    'The response-start transition could not be persisted.',
  timeout: 'The HTTP execution timed out.',
  'response-too-large':
    'The HTTP response exceeded the configured byte limit.',
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
  cancelled: 'The HTTP execution was cancelled.'
} as const)

const browserErrorMessages = Object.freeze({
  'browser-unavailable':
    'No supported offline browser executable is available.',
  timeout: 'The offline browser execution timed out.',
  'render-error':
    'The offline browser could not render the supplied document.',
  'result-too-large':
    'The offline browser result exceeded its byte budget.',
  cancelled: 'The offline browser execution was cancelled.'
} as const)

const HttpHeaderSchema = z
  .object({
    name: z.string().min(1).max(128),
    value: z.string().max(8_192)
  })
  .strict()

const HttpRunnerResultSchema = z
  .object({
    requestId: z.string().min(1).max(512),
    status: z.enum(['succeeded', 'failed', 'cancelled']),
    finalUrl: z.string().min(1).max(16_384),
    method: z.string().min(1).max(64),
    statusCode: z.number().int().min(100).max(599).optional(),
    redirectLocation: z.string().min(1).max(16_384).optional(),
    requestHeaders: z.array(HttpHeaderSchema).max(512),
    responseHeaders: z.record(
      z.string().min(1).max(128),
      z.string().max(8_192)
    ),
    responseBody: z.instanceof(Uint8Array).optional(),
    requestBodySha256: z.string().regex(sha256Pattern).optional(),
    responseBodySha256: z.string().regex(sha256Pattern).optional(),
    responseBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    durationMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    resolvedAddresses: z.array(z.string().min(2).max(64)).max(64),
    errorCode: z.enum([
      'invalid-wire',
      'dns-failed',
      'claim-rejected',
      'address-rejected',
      'dispatch-mark-failed',
      'response-start-mark-failed',
      'timeout',
      'response-too-large',
      'response-header-too-large',
      'response-decompressed-too-large',
      'response-compression-bomb',
      'response-decompression-failed',
      'response-slow-read',
      'network-error',
      'cancelled'
    ]).optional(),
    errorMessage: z.string().min(1).max(256).optional()
  })
  .strict()

const BrowserFormFieldSchema = z
  .object({
    name: z.string().min(1).max(256),
    type: z.string().min(1).max(64),
    required: z.boolean()
  })
  .strict()

const BrowserFormSchema = z
  .object({
    action: z.string().min(1).max(2_048),
    method: z.string().min(1).max(32),
    fields: z.array(BrowserFormFieldSchema).max(50)
  })
  .strict()

const BrowserRunnerResultSchema = z
  .object({
    requestId: z.string().min(1).max(512),
    status: z.enum(['succeeded', 'failed', 'cancelled']),
    finalUrl: z.string().min(1).max(16_384),
    pageTitle: z.string().max(1_024).optional(),
    links: z.array(z.string().min(1).max(2_048)).max(100),
    forms: z.array(BrowserFormSchema).max(50),
    domSnapshot: z.string().optional(),
    markerExecuted: z.boolean().optional(),
    screenshot: z.instanceof(Uint8Array).optional(),
    networkRequestsBlocked: z.number().int().nonnegative().max(1_000_000),
    resultBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    durationMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    errorCode: z.enum([
      'browser-unavailable',
      'timeout',
      'render-error',
      'result-too-large',
      'cancelled'
    ]).optional(),
    errorMessage: z.string().min(1).max(256).optional()
  })
  .strict()

type ParsedHttpRunnerResult = z.infer<typeof HttpRunnerResultSchema>
type ParsedBrowserRunnerResult = z.infer<typeof BrowserRunnerResultSchema>

export type ValidatedHttpRunnerResult<ClaimToken extends object> = Readonly<
  Omit<
    ParsedHttpRunnerResult,
    'requestHeaders' | 'responseHeaders' | 'responseBody' | 'resolvedAddresses'
  > & {
    readonly requestHeaders: readonly Readonly<{
      name: string
      value: string
    }>[]
    readonly responseHeaders: Readonly<Record<string, string>>
    readonly responseBody?: Uint8Array
    readonly resolvedAddresses: readonly string[]
    readonly claimToken?: ClaimToken
  }
>

export type ValidatedBrowserRunnerResult = Readonly<
  Omit<ParsedBrowserRunnerResult, 'links' | 'forms' | 'screenshot'> & {
    readonly links: readonly string[]
    readonly forms: readonly Readonly<
      Omit<ParsedBrowserRunnerResult['forms'][number], 'fields'> & {
        readonly fields: readonly Readonly<
          ParsedBrowserRunnerResult['forms'][number]['fields'][number]
        >[]
      }
    >[]
    readonly screenshot?: Uint8Array
  }
>

export interface HttpRunnerValidationExpectation {
  readonly requestId: string
  readonly wire: MaterializedWireRequest
  readonly timeoutMs: number
  readonly maxResponseBytes: number
}

export interface BrowserRunnerValidationExpectation {
  readonly request: Readonly<{
    requestId: string
    baseUrl: string
    action: 'inspect-dom' | 'verify-xss' | 'capture-evidence'
    marker?: string
    timeoutMs: number
  }>
  readonly maxResultBytes: number
}

export class RunnerOutputValidationError extends Error {
  constructor() {
    super('Execution runner output failed closed validation.')
    this.name = 'RunnerOutputValidationError'
  }
}

const invalidHttpClaimTokens =
  new WeakMap<RunnerOutputValidationError, object>()

export function claimTokenFromRunnerOutputError<
  ClaimToken extends object
>(error: unknown): ClaimToken | undefined {
  return error instanceof RunnerOutputValidationError
    ? invalidHttpClaimTokens.get(error) as ClaimToken | undefined
    : undefined
}

function fail(): never {
  throw new RunnerOutputValidationError()
}

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function nativeByteLength(value: Uint8Array): number {
  if (
    typedArrayByteLengthGetter === undefined ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0 ||
    forbiddenByteArrayOwnProperties.some((property) =>
      Object.prototype.hasOwnProperty.call(value, property)
    )
  ) {
    fail()
  }
  try {
    const byteLength = Reflect.apply(
      typedArrayByteLengthGetter,
      value,
      []
    ) as unknown
    if (
      typeof byteLength !== 'number' ||
      !Number.isSafeInteger(byteLength) ||
      byteLength < 0
    ) {
      fail()
    }
    return byteLength
  } catch {
    fail()
  }
}

function snapshotBytes(
  value: Uint8Array<ArrayBufferLike>
): Uint8Array<ArrayBuffer> {
  const byteLength = nativeByteLength(value)
  const snapshot = new Uint8Array(new ArrayBuffer(byteLength))
  try {
    Uint8Array.prototype.set.call(snapshot, value)
  } catch {
    fail()
  }
  return snapshot
}

function assertDataGraph(value: unknown): void {
  let visited = 0
  const seen = new Set<object>()
  const visit = (candidate: unknown, depth: number): void => {
    if (
      candidate === null ||
      (typeof candidate !== 'object' && typeof candidate !== 'function')
    ) {
      return
    }
    if (candidate instanceof Uint8Array) {
      nativeByteLength(candidate)
      return
    }
    if (depth > 8 || visited >= maxValidationNodes) fail()
    const object = candidate as object
    if (seen.has(object)) fail()
    seen.add(object)
    visited += 1
    if (Array.isArray(object)) {
      const keys = Reflect.ownKeys(object)
      if (
        object.length > maxValidationNodes ||
        keys.length !== object.length + 1 ||
        keys.at(-1) !== 'length'
      ) {
        fail()
      }
      for (let index = 0; index < object.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(
          object,
          String(index)
        )
        if (
          !descriptor ||
          !Object.prototype.hasOwnProperty.call(descriptor, 'value')
        ) fail()
        visit(descriptor.value, depth + 1)
      }
      return
    }
    const prototype = Object.getPrototypeOf(object)
    if (prototype !== Object.prototype && prototype !== null) fail()
    for (const key of Reflect.ownKeys(object)) {
      if (typeof key !== 'string') fail()
      const descriptor = Object.getOwnPropertyDescriptor(object, key)
      if (
        !descriptor ||
        !Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ) fail()
      if (!descriptor.enumerable) {
        if (key === 'claimToken') continue
        fail()
      }
      visit(descriptor.value, depth + 1)
    }
  }
  visit(value, 0)
}

function extractClaimToken(value: unknown): object | undefined {
  if (
    value === null ||
    (typeof value !== 'object' && typeof value !== 'function')
  ) {
    return undefined
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'claimToken')
  if (!descriptor) return undefined
  if (
    descriptor.enumerable ||
    descriptor.configurable ||
    descriptor.writable ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
    descriptor.value === null ||
    (typeof descriptor.value !== 'object' &&
      typeof descriptor.value !== 'function')
  ) {
    fail()
  }
  return descriptor.value as object
}

function attachClaimToken<TResult extends object>(
  result: TResult,
  claimToken: object | undefined
): TResult {
  if (claimToken !== undefined) {
    Object.defineProperty(result, 'claimToken', {
      value: claimToken,
      enumerable: false,
      configurable: false,
      writable: false
    })
  }
  return Object.freeze(result)
}

function expectedRedactedHeaders(
  wire: MaterializedWireRequest
): readonly Readonly<{ name: string; value: string }>[] {
  return wire.headers.map(({ name }) => ({
    name: name.toLowerCase(),
    value: '[REDACTED]'
  }))
}

function assertHttpResultInvariants(
  result: z.infer<typeof HttpRunnerResultSchema>,
  claimToken: object | undefined,
  expected: HttpRunnerValidationExpectation
): void {
  if (
    result.requestId !== expected.requestId ||
    result.finalUrl !== expected.wire.url ||
    result.method !== expected.wire.method ||
    result.durationMs > expected.timeoutMs + 2_000 ||
    canonicalJson(result.requestHeaders) !==
      canonicalJson(expectedRedactedHeaders(expected.wire)) ||
    Object.keys(result.responseHeaders).some(
      (name) =>
        name !== name.toLowerCase() ||
        !allowedResponseHeaderNames.has(name)
    )
  ) {
    fail()
  }
  const uniqueAddresses = new Set(result.resolvedAddresses)
  if (
    uniqueAddresses.size !== result.resolvedAddresses.length ||
    result.resolvedAddresses.some((address) => isIP(address) === 0)
  ) {
    fail()
  }
  const requestBody = expected.wire.bodyBytes
  if (
    requestBody === undefined
      ? result.requestBodySha256 !== undefined
      : result.requestBodySha256 !== sha256(Uint8Array.from(requestBody))
  ) {
    fail()
  }
  if (
    result.responseBody !== undefined &&
    result.responseBody.byteLength > expected.maxResponseBytes
  ) {
    fail()
  }
  if (result.responseBody !== undefined) {
    if (
      result.responseBytes !== result.responseBody.byteLength ||
      result.responseBodySha256 !== sha256(result.responseBody)
    ) {
      fail()
    }
  } else if (result.responseBodySha256 !== undefined) {
    fail()
  }
  if (
    result.redirectLocation !== undefined &&
    (result.statusCode === undefined ||
      result.statusCode < 300 ||
      result.statusCode >= 400)
  ) {
    fail()
  }
  if (result.status === 'succeeded') {
    if (
      claimToken === undefined ||
      result.errorCode !== undefined ||
      result.errorMessage !== undefined ||
      result.statusCode === undefined ||
      result.responseBody === undefined ||
      result.responseBytes > expected.maxResponseBytes
    ) {
      fail()
    }
    return
  }
  if (
    result.errorCode === undefined ||
    result.errorMessage !== httpErrorMessages[result.errorCode] ||
    result.responseBody !== undefined ||
    (result.status === 'cancelled') !== (result.errorCode === 'cancelled')
  ) {
    fail()
  }
  if (claimToken === undefined) {
    if (
      result.errorCode !== 'claim-rejected' ||
      result.statusCode !== undefined ||
      result.responseBytes !== 0 ||
      result.resolvedAddresses.length !== 0
    ) {
      fail()
    }
  } else if (result.errorCode === 'claim-rejected') {
    fail()
  }
}

export function validateHttpRunnerOutput<ClaimToken extends object>(
  value: unknown,
  expected: HttpRunnerValidationExpectation
): ValidatedHttpRunnerResult<ClaimToken> {
  let claimToken: object | undefined
  try {
    claimToken = extractClaimToken(value)
    assertDataGraph(value)
    const parsed = HttpRunnerResultSchema.safeParse(value)
    if (!parsed.success) fail()
    const data: ParsedHttpRunnerResult = {
      ...parsed.data,
      ...(parsed.data.responseBody !== undefined
        ? { responseBody: snapshotBytes(parsed.data.responseBody) }
        : {})
    }
    assertHttpResultInvariants(data, claimToken, expected)
    const result: ValidatedHttpRunnerResult<ClaimToken> = {
      ...data,
      requestHeaders: Object.freeze(
        data.requestHeaders.map((header) => Object.freeze({ ...header }))
      ),
      responseHeaders: Object.freeze({ ...data.responseHeaders }),
      ...(data.responseBody !== undefined
        ? { responseBody: data.responseBody }
        : {}),
      resolvedAddresses: Object.freeze([...data.resolvedAddresses])
    }
    return attachClaimToken(
      result,
      claimToken
    ) as ValidatedHttpRunnerResult<ClaimToken>
  } catch {
    const error = new RunnerOutputValidationError()
    if (claimToken !== undefined) {
      invalidHttpClaimTokens.set(error, claimToken)
    }
    throw error
  }
}

function browserMetadataBytes(
  result: z.infer<typeof BrowserRunnerResultSchema>
): number {
  return Buffer.byteLength(
    JSON.stringify({
      title: result.pageTitle,
      links: result.links,
      forms: result.forms,
      markerExecuted: result.markerExecuted
    }),
    'utf8'
  )
}

function assertBrowserResultInvariants(
  result: z.infer<typeof BrowserRunnerResultSchema>,
  expected: BrowserRunnerValidationExpectation
): void {
  const request = expected.request
  if (
    result.requestId !== request.requestId ||
    result.finalUrl !== request.baseUrl ||
    result.durationMs > request.timeoutMs + 2_000
  ) {
    fail()
  }
  if (result.status === 'succeeded') {
    if ((result.domSnapshot?.length ?? 0) > expected.maxResultBytes) fail()
    if ((result.screenshot?.byteLength ?? 0) > expected.maxResultBytes) fail()
    const calculatedBytes =
      browserMetadataBytes(result) +
      Buffer.byteLength(result.domSnapshot ?? '', 'utf8') +
      (result.screenshot?.byteLength ?? 0)
    if (
      result.errorCode !== undefined ||
      result.errorMessage !== undefined ||
      result.pageTitle === undefined ||
      result.domSnapshot === undefined ||
      result.resultBytes !== calculatedBytes ||
      result.resultBytes > expected.maxResultBytes ||
      (request.marker === undefined) !==
        (result.markerExecuted === undefined) ||
      (request.action === 'inspect-dom'
        ? result.screenshot !== undefined
        : result.screenshot === undefined)
    ) {
      fail()
    }
    return
  }
  if (
    result.errorCode === undefined ||
    result.errorMessage !== browserErrorMessages[result.errorCode] ||
    result.pageTitle !== undefined ||
    result.domSnapshot !== undefined ||
    result.markerExecuted !== undefined ||
    result.screenshot !== undefined ||
    result.links.length !== 0 ||
    result.forms.length !== 0 ||
    (result.status === 'cancelled') !== (result.errorCode === 'cancelled') ||
    (result.errorCode === 'result-too-large'
      ? result.resultBytes <= expected.maxResultBytes
      : result.resultBytes !== 0)
  ) {
    fail()
  }
}

export function validateBrowserRunnerOutput(
  value: unknown,
  expected: BrowserRunnerValidationExpectation
): ValidatedBrowserRunnerResult {
  assertDataGraph(value)
  if (extractClaimToken(value) !== undefined) fail()
  const parsed = BrowserRunnerResultSchema.safeParse(value)
  if (!parsed.success) fail()
  const data: ParsedBrowserRunnerResult = {
    ...parsed.data,
    ...(parsed.data.screenshot !== undefined
      ? { screenshot: snapshotBytes(parsed.data.screenshot) }
      : {})
  }
  assertBrowserResultInvariants(data, expected)
  return Object.freeze({
    ...data,
    links: Object.freeze([...data.links]),
    forms: Object.freeze(
      data.forms.map((form) =>
        Object.freeze({
          ...form,
          fields: Object.freeze(
            form.fields.map((field) => Object.freeze({ ...field }))
          )
        })
      )
    ),
    ...(data.screenshot !== undefined
      ? { screenshot: data.screenshot }
      : {})
  })
}
