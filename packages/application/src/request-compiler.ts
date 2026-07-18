import { createHmac } from 'node:crypto'
import {
  CapabilityIdSchema,
  DefinitionIdSchema,
  FormValueSourceSchema,
  IdentityRefSchema,
  InventoryEndpointRecordSchema,
  MutationGeneratorMetadataSchema,
  ModuleVersionSchema,
  RequestBodyTemplateSchema,
  RequestMutationTargetSchema,
  RequestVariantRecordSchema,
  RESOLVED_INTENT_HASH_DOMAIN,
  SessionGenerationRefSchema,
  SystemIssuedOpaqueIdSchema,
  TEMPLATE_INTENT_HASH_DOMAIN,
  TestObjectRefSchema,
  WIRE_REQUEST_HMAC_DOMAIN,
  type CapabilityId,
  type FormValueSource,
  type IdentityRef,
  type InventoryEndpointRecord,
  type InventoryValueType,
  type JsonValueSource,
  type JsonValueTemplate,
  type MutationGeneratorMetadata,
  type RequestBodyTemplate,
  type RequestMutationTarget,
  type RequestVariantRecord,
  type ResolvedIntentHash,
  type SessionGenerationRef,
  type SystemIssuedOpaqueId,
  type TemplateIntentHash,
  type TestObjectRef,
  type WireRequestHmac
} from '@agentgo/contracts'
import {
  canonicalJson,
  canonicalizeAllowedHeaderDescriptors,
  canonicalizeInventoryBodyShape,
  canonicalizeInventoryUrl,
  canonicalizeSelectorRefs,
  compareText,
  deepFreeze,
  sha256Text,
  stableInventoryHash
} from '@agentgo/domain'

const HTTP_FIELD_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u
const CANONICAL_MEDIA_TYPE_PATTERN =
  /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u
const CANONICAL_APPLICATION_JSON_PATTERN =
  /^application\/[a-z0-9!#$&^_.+-]+\+json$/u
const COOKIE_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/u
const COOKIE_VALUE_PATTERN = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/u
const PERCENT_ESCAPE_PATTERN = /%(?![0-9A-Fa-f]{2})/u
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/u
const MAX_TEMPLATE_ENTRIES = 4_096
const MAX_JSON_NODES = 4_096
const MAX_JSON_DEPTH = 64
const MAX_TEMPLATE_NODES = 20_000
const MAX_TEMPLATE_BYTES = 1_048_576
const MAX_INPUT_SNAPSHOT_NODES = 100_000
const MAX_INPUT_SNAPSHOT_BYTES = 4_194_304
const MAX_BODY_BYTES = 1_048_576
const MAX_RESOLVED_VALUE_BYTES = 262_144
const MAX_TOTAL_RESOLVED_BYTES = 2_359_296
const MAX_URL_BYTES = 16_384
const MAX_HEADER_BLOCK_BYTES = 65_536
const MAX_WIRE_BYTES = 1_146_880
const MIN_HMAC_KEY_BYTES = 32
const MAX_HMAC_KEY_BYTES = 4_096
const RESOLVED_VALUE_COMMITMENT_DOMAIN =
  'agentgo.resolved-value-commitment.v1' as const

const RESERVED_TRANSPORT_HEADERS = new Set([
  'connection',
  'content-length',
  'content-type',
  'host',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
])
const READ_ONLY_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const TEST_OBJECT_WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH'])

export type JsonScalar = string | number | boolean | null
export interface ResolvedJsonArray
  extends ReadonlyArray<ResolvedJsonValue> {}
export interface ResolvedJsonObject {
  readonly [key: string]: ResolvedJsonValue
}
export type ResolvedJsonValue =
  | JsonScalar
  | ResolvedJsonArray
  | ResolvedJsonObject

function isResolvedJsonArray(
  value: ResolvedJsonValue
): value is ResolvedJsonArray {
  return Array.isArray(value)
}

export interface NamedRequestValueTemplate {
  readonly name: string
  readonly value: FormValueSource
}

/**
 * Runtime values are explicit slots. The reviewed inventory stays value-free,
 * while secret material can only enter through a resolver-backed opaque ref.
 */
export interface ProbeRequestTemplate {
  readonly url: Readonly<{
    readonly origin: FormValueSource
    readonly pathSegments: readonly Readonly<{
      readonly selectorName?: string
      readonly value: FormValueSource
    }>[]
  }>
  readonly query: readonly NamedRequestValueTemplate[]
  readonly headers: readonly NamedRequestValueTemplate[]
  readonly cookies: readonly NamedRequestValueTemplate[]
  readonly body: RequestBodyTemplate
}

export interface MutationGeneratorRef {
  readonly generatorId: string
  readonly version: string
}

export interface MutationGeneratorInput {
  readonly target: RequestMutationTarget
  readonly bodyEncoding: RequestVariantRecord['codec']
  readonly originalValue: ResolvedJsonValue | undefined
}

export interface MutationGenerator {
  readonly metadata: MutationGeneratorMetadata
  generate(input: MutationGeneratorInput): unknown
}

export interface DynamicValueResolverInput {
  readonly slotId: string
  readonly identityRef?: IdentityRef
  readonly sessionRef?: SessionGenerationRef
  readonly testObjectRef?: TestObjectRef
}

export interface DynamicValueResolver {
  readonly resolverId: string
  readonly version: string
  resolve(input: DynamicValueResolverInput): unknown
}

export interface SecretRefResolverInput {
  readonly secretRef: SystemIssuedOpaqueId
  readonly generation: number
  readonly identityRef?: IdentityRef
  readonly sessionRef?: SessionGenerationRef
}

export interface SecretRefResolver {
  readonly resolverId: string
  readonly version: string
  resolve(input: SecretRefResolverInput): unknown
}

export interface RequestHashKeyRef {
  readonly keyRef: SystemIssuedOpaqueId
  readonly keyVersion: number
}

/** The compiler uses and zeroes an ephemeral copy of provider-owned key bytes. */
export interface RequestHashKeyProvider {
  resolveKey(input: RequestHashKeyRef): Uint8Array
}

export interface ProbeRequestCompilerDependencies {
  readonly mutationGenerators: readonly MutationGenerator[]
  readonly dynamicValueResolvers: readonly DynamicValueResolver[]
  readonly secretRefResolvers: readonly SecretRefResolver[]
  readonly knownCapabilityIds: readonly CapabilityId[]
  readonly hashKeyProvider: RequestHashKeyProvider
}

export interface ProbeRequestCompilerInput {
  readonly scanId: string
  readonly endpoint: InventoryEndpointRecord
  readonly requestVariant: RequestVariantRecord
  readonly requestTemplate: ProbeRequestTemplate
  readonly mutationTarget: RequestMutationTarget
  readonly mutationGenerator: MutationGeneratorRef
  readonly enabledCapabilityIds: readonly CapabilityId[]
  readonly hashKey: RequestHashKeyRef
  readonly ownerRef?: SystemIssuedOpaqueId
  readonly scopeSnapshotId?: SystemIssuedOpaqueId
  readonly identityRef?: IdentityRef
  readonly sessionRef?: SessionGenerationRef
  readonly testObjectRef?: TestObjectRef
}

export type ProbeRequestCompileErrorCode =
  | 'invalid-input'
  | 'inventory-binding-rejected'
  | 'variant-not-executable'
  | 'unsupported-transport'
  | 'unsupported-codec'
  | 'unsupported-selector'
  | 'template-mismatch'
  | 'invalid-canonical-input'
  | 'unknown-capability'
  | 'capability-rejected'
  | 'unknown-generator'
  | 'generator-rejected'
  | 'unknown-resolver'
  | 'resolver-rejected'
  | 'opaque-ref-rejected'
  | 'hash-key-rejected'
  | 'request-budget-rejected'

const SAFE_ERROR_MESSAGES: Record<ProbeRequestCompileErrorCode, string> = {
  'invalid-input': 'The request compiler input is invalid.',
  'inventory-binding-rejected': 'The reviewed inventory binding is invalid.',
  'variant-not-executable': 'The request variant is not executable.',
  'unsupported-transport': 'The request transport is not supported by this compiler.',
  'unsupported-codec': 'The request body codec is not supported by this compiler.',
  'unsupported-selector': 'The mutation selector is not supported by this compiler.',
  'template-mismatch': 'The request template does not match the reviewed variant.',
  'invalid-canonical-input': 'A request value cannot be canonicalized safely.',
  'unknown-capability': 'A request capability is not registered.',
  'capability-rejected': 'The registered capabilities do not authorize this compiler input.',
  'unknown-generator': 'The mutation generator is not registered.',
  'generator-rejected': 'The mutation generator output is invalid.',
  'unknown-resolver': 'A request value resolver is not registered.',
  'resolver-rejected': 'A request value resolver returned an invalid value.',
  'opaque-ref-rejected': 'An opaque request reference is invalid or inactive.',
  'hash-key-rejected': 'The request hash key is unavailable or invalid.',
  'request-budget-rejected': 'The compiled request exceeds a deterministic byte budget.'
}

export class ProbeRequestCompileError extends Error {
  readonly code: ProbeRequestCompileErrorCode

  constructor(code: ProbeRequestCompileErrorCode) {
    super(SAFE_ERROR_MESSAGES[code])
    this.name = 'ProbeRequestCompileError'
    this.code = code
  }
}

export interface MaterializedWireRequest {
  readonly method: string
  readonly url: string
  readonly headers: readonly Readonly<{ name: string; value: string }>[]
  readonly bodyBytes?: readonly number[]
}

/**
 * Exact request material is deliberately non-enumerable. `JSON.stringify`
 * emits only a fixed marker, keeping resolver output out of logs/snapshots.
 */
export class CompiledWireRequest {
  readonly #method: string
  readonly #url: string
  readonly #headers: readonly Readonly<{ name: string; value: string }>[]
  readonly #bodyBytes: readonly number[] | undefined

  constructor(input: MaterializedWireRequest) {
    this.#method = input.method
    this.#url = input.url
    this.#headers = Object.freeze(
      input.headers.map((header) => Object.freeze({ ...header }))
    )
    this.#bodyBytes = input.bodyBytes
      ? Object.freeze([...input.bodyBytes])
      : undefined
    Object.freeze(this)
  }

  get method(): string {
    return this.#method
  }

  get url(): string {
    return this.#url
  }

  get headers(): readonly Readonly<{ name: string; value: string }>[] {
    return this.#headers
  }

  get bodyBytes(): readonly number[] | undefined {
    return this.#bodyBytes
  }

  materialize(): MaterializedWireRequest {
    return Object.freeze({
      method: this.#method,
      url: this.#url,
      headers: this.#headers,
      ...(this.#bodyBytes
        ? { bodyBytes: Object.freeze([...this.#bodyBytes]) }
        : {})
    })
  }

  toJSON(): Readonly<{ redacted: true; kind: 'ephemeral-wire-request' }> {
    return Object.freeze({ redacted: true, kind: 'ephemeral-wire-request' })
  }
}

export interface CompiledProbeRequest {
  readonly request: CompiledWireRequest
  readonly templateIntentHash: TemplateIntentHash
  readonly resolvedIntentHash: ResolvedIntentHash
  readonly wireRequestHmac: WireRequestHmac
}

interface ResolvedNamedValue {
  readonly name: string
  readonly value: string
  readonly descriptor: unknown
  readonly commitment: string
}

interface ResolutionContext {
  readonly input: ProbeRequestCompilerInput
  readonly commitmentKey: Uint8Array
  readonly resolvedEntries: Array<Readonly<Record<string, unknown>>>
  resolvedBytes: number
}

function fail(code: ProbeRequestCompileErrorCode): never {
  throw new ProbeRequestCompileError(code)
}

function registryKey(id: string, version: string): string {
  return `${id}\u0000${version}`
}

function assertValidUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail('invalid-canonical-input')
      }
      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail('invalid-canonical-input')
    }
  }
  if (value !== value.normalize('NFC')) fail('invalid-canonical-input')
}

function utf8(value: string): Uint8Array {
  assertValidUnicode(value)
  return Buffer.from(value, 'utf8')
}

function canonicalValueBytes(value: ResolvedJsonValue): Uint8Array {
  return utf8(canonicalJson(value))
}

function updateFrame(
  hmac: ReturnType<typeof createHmac>,
  label: string,
  value: Uint8Array
): void {
  const labelBytes = Buffer.from(label, 'utf8')
  const lengths = Buffer.allocUnsafe(8)
  lengths.writeUInt32BE(labelBytes.byteLength, 0)
  lengths.writeUInt32BE(value.byteLength, 4)
  hmac.update(lengths)
  hmac.update(labelBytes)
  hmac.update(value)
}

function hmacCommitment(
  key: Uint8Array,
  path: string,
  value: ResolvedJsonValue
): string {
  const hmac = createHmac('sha256', key)
  updateFrame(hmac, 'domain', utf8(RESOLVED_VALUE_COMMITMENT_DOMAIN))
  updateFrame(hmac, 'path', utf8(path))
  updateFrame(hmac, 'value', canonicalValueBytes(value))
  return hmac.digest('hex')
}

function budgetedCommitment(
  context: ResolutionContext,
  path: string,
  value: ResolvedJsonValue,
  failureCode: 'invalid-canonical-input' | 'resolver-rejected' | 'generator-rejected'
): string {
  const valueBytes = canonicalValueBytes(value).byteLength
  if (
    valueBytes > MAX_RESOLVED_VALUE_BYTES ||
    context.resolvedBytes + valueBytes > MAX_TOTAL_RESOLVED_BYTES
  ) {
    fail(failureCode)
  }
  context.resolvedBytes += valueBytes
  return hmacCommitment(context.commitmentKey, path, value)
}

function valueSourceDescriptor(source: FormValueSource | JsonValueSource): unknown {
  switch (source.kind) {
    case 'literal':
      return {
        kind: source.kind,
        sensitivity: source.sensitivity,
        value: source.value
      }
    case 'dynamic':
      return {
        kind: source.kind,
        slotId: source.slotId,
        resolver: source.resolver
      }
    case 'secret-ref':
      return {
        kind: source.kind,
        secretRef: source.secretRef,
        generation: source.generation,
        resolver: source.resolver
      }
  }
}

function valueSourceBudgetFailure(
  source: FormValueSource | JsonValueSource
): 'invalid-canonical-input' | 'resolver-rejected' {
  return source.kind === 'literal'
    ? 'invalid-canonical-input'
    : 'resolver-rejected'
}

function jsonTemplateDescriptor(value: JsonValueTemplate): unknown {
  if (value.kind === 'array') {
    return {
      kind: 'array',
      items: value.items.map(jsonTemplateDescriptor)
    }
  }
  if (value.kind === 'object') {
    return {
      kind: 'object',
      entries: value.entries
        .map((entry) => ({
          key: entry.key,
          value: jsonTemplateDescriptor(entry.value)
        }))
        .sort((left, right) => compareText(left.key, right.key))
    }
  }
  return valueSourceDescriptor(value)
}

function requestTemplateDescriptor(template: ProbeRequestTemplate): unknown {
  return {
    url: {
      origin: valueSourceDescriptor(template.url.origin),
      pathSegments: template.url.pathSegments.map((segment) => ({
        selectorName: segment.selectorName ?? null,
        value: valueSourceDescriptor(segment.value)
      }))
    },
    query: template.query.map((entry) => ({
      name: entry.name,
      value: valueSourceDescriptor(entry.value)
    })),
    headers: [...template.headers]
      .map((entry) => ({
        name: entry.name,
        value: valueSourceDescriptor(entry.value)
      }))
      .sort((left, right) => compareText(left.name, right.name)),
    cookies: template.cookies.map((entry) => ({
      name: entry.name,
      value: valueSourceDescriptor(entry.value)
    })),
    body:
      template.body.encoding === 'json'
        ? {
            encoding: 'json',
            value: jsonTemplateDescriptor(template.body.value)
          }
        : template.body.encoding === 'form'
          ? {
              encoding: 'form',
              entries: template.body.entries.map((entry) => ({
                name: entry.name,
                value: valueSourceDescriptor(entry.value)
              }))
            }
          : { encoding: 'none' }
  }
}

function safeStringValue(value: unknown, source: 'resolver' | 'generator'): string {
  if (typeof value !== 'string') {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  try {
    assertValidUnicode(value)
  } catch {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  if (Buffer.byteLength(value, 'utf8') > MAX_RESOLVED_VALUE_BYTES) {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  return value
}

function sanitizeJsonValue(
  value: unknown,
  state: { nodes: number; bytes: number; ancestors: Set<object> },
  source: 'resolver' | 'generator',
  depth = 0
): ResolvedJsonValue {
  try {
    return sanitizeJsonValueInternal(value, state, source, depth)
  } catch (error) {
    if (error instanceof ProbeRequestCompileError) throw error
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
}

function sanitizeJsonValueInternal(
  value: unknown,
  state: { nodes: number; bytes: number; ancestors: Set<object> },
  source: 'resolver' | 'generator',
  depth: number
): ResolvedJsonValue {
  if (depth > MAX_JSON_DEPTH) {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  state.nodes += 1
  state.bytes += 2
  if (state.nodes > MAX_JSON_NODES) {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  if (state.bytes > MAX_RESOLVED_VALUE_BYTES) {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  if (
    value === null ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value
  }
  if (typeof value === 'string') {
    const stringValue = safeStringValue(value, source)
    state.bytes += Buffer.byteLength(stringValue, 'utf8')
    if (state.bytes > MAX_RESOLVED_VALUE_BYTES) {
      fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
    }
    return stringValue
  }
  if (Array.isArray(value)) {
    if (state.ancestors.has(value)) {
      fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
    }
    state.ancestors.add(value)
    try {
      const keys = Reflect.ownKeys(value)
      if (keys.some((key) => typeof key !== 'string')) {
        fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
      }
      const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, 'length')
      const length = lengthDescriptor?.value
      if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) {
        fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
      }
      const allowedKeys = new Set(['length'])
      const output: ResolvedJsonValue[] = []
      for (let index = 0; index < length; index += 1) {
        const key = String(index)
        allowedKeys.add(key)
        const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
        if (!descriptor || !('value' in descriptor)) {
          fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
        }
        output.push(
          sanitizeJsonValueInternal(descriptor.value, state, source, depth + 1)
        )
      }
      if (keys.some((key) => !allowedKeys.has(key as string))) {
        fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
      }
      return Object.freeze(output)
    } finally {
      state.ancestors.delete(value)
    }
  }
  if (typeof value !== 'object' || value === null) {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  if (state.ancestors.has(value)) {
    fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
  }
  state.ancestors.add(value)
  const result = Object.create(null) as Record<string, ResolvedJsonValue>
  try {
    const keys = Reflect.ownKeys(value)
    if (keys.some((key) => typeof key !== 'string')) {
      fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
    }
    for (const key of (keys as string[]).sort(compareText)) {
      state.bytes += Buffer.byteLength(key, 'utf8') + 4
      if (state.bytes > MAX_RESOLVED_VALUE_BYTES) {
        fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
      }
      try {
        assertValidUnicode(key)
      } catch {
        fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
      }
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
        fail(source === 'resolver' ? 'resolver-rejected' : 'generator-rejected')
      }
      Object.defineProperty(result, key, {
        configurable: false,
        enumerable: true,
        writable: false,
        value: sanitizeJsonValueInternal(
          descriptor.value,
          state,
          source,
          depth + 1
        )
      })
    }
  } finally {
    state.ancestors.delete(value)
  }
  return Object.freeze(result)
}

function encodeRfc3986Component(value: string): string {
  assertValidUnicode(value)
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  )
}

function encodeFormComponent(value: string): string {
  assertValidUnicode(value)
  return encodeURIComponent(value)
    .replace(/[!'()~]/gu, (character) =>
      `%${character.charCodeAt(0).toString(16).toUpperCase()}`
    )
    .replace(/%20/gu, '+')
}

function assertSlotName(value: string): void {
  assertValidUnicode(value)
  if (value.length === 0 || value !== value.trim() || CONTROL_PATTERN.test(value)) {
    fail('invalid-canonical-input')
  }
}

function assertHeaderName(value: string): void {
  if (!HTTP_FIELD_NAME_PATTERN.test(value)) fail('invalid-canonical-input')
}

function assertHeaderValue(value: string): void {
  assertValidUnicode(value)
  if (value !== value.trim() || /[^\x20-\x7e]/u.test(value)) {
    fail('invalid-canonical-input')
  }
}

function isCanonicalReviewedContentType(
  value: string,
  codec: RequestVariantRecord['codec']
): boolean {
  if (
    value !== value.toLowerCase() ||
    !CANONICAL_MEDIA_TYPE_PATTERN.test(value) ||
    CONTROL_PATTERN.test(value)
  ) {
    return false
  }
  if (codec === 'form') return value === 'application/x-www-form-urlencoded'
  if (codec === 'json') {
    return value === 'application/json' ||
      CANONICAL_APPLICATION_JSON_PATTERN.test(value)
  }
  return false
}

function assertCookieName(value: string): void {
  if (!COOKIE_NAME_PATTERN.test(value)) fail('invalid-canonical-input')
}

function assertCookieValue(value: string): void {
  if (!COOKIE_VALUE_PATTERN.test(value)) fail('invalid-canonical-input')
}

function assertTemplateBudget(value: unknown): void {
  const pending: unknown[] = [value]
  const visited = new Set<object>()
  let nodes = 0
  let bytes = 0
  while (pending.length > 0) {
    const current = pending.pop()
    nodes += 1
    if (nodes > MAX_TEMPLATE_NODES) fail('invalid-input')
    if (typeof current === 'string') {
      try {
        assertValidUnicode(current)
        bytes += Buffer.byteLength(current, 'utf8')
      } catch {
        fail('invalid-input')
      }
    } else if (typeof current === 'object' && current !== null) {
      if (visited.has(current)) fail('invalid-input')
      visited.add(current)
      if (!Array.isArray(current)) {
        const prototype = Object.getPrototypeOf(current)
        if (prototype !== Object.prototype && prototype !== null) {
          fail('invalid-input')
        }
      }
      const descriptors = Object.getOwnPropertyDescriptors(current)
      for (const [key, descriptor] of Object.entries(descriptors)) {
        if ('get' in descriptor || 'set' in descriptor) fail('invalid-input')
        bytes += Buffer.byteLength(key, 'utf8')
        pending.push(descriptor.value)
      }
    } else if (
      current !== undefined &&
      current !== null &&
      typeof current !== 'number' &&
      typeof current !== 'boolean'
    ) {
      fail('invalid-input')
    }
    if (bytes > MAX_TEMPLATE_BYTES) fail('invalid-input')
  }
}

function capturePlainInput(
  value: unknown,
  state: { nodes: number; bytes: number; ancestors: Set<object> } = {
    nodes: 0,
    bytes: 0,
    ancestors: new Set()
  },
  depth = 0
): unknown {
  if (depth > 128) fail('invalid-input')
  state.nodes += 1
  if (state.nodes > MAX_INPUT_SNAPSHOT_NODES) fail('invalid-input')
  if (typeof value === 'string') {
    state.bytes += Buffer.byteLength(value, 'utf8')
    if (state.bytes > MAX_INPUT_SNAPSHOT_BYTES) fail('invalid-input')
    return value
  }
  if (
    value === null ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value
  }
  if (typeof value !== 'object' || value === null) fail('invalid-input')
  if (state.ancestors.has(value)) fail('invalid-input')
  state.ancestors.add(value)
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null && !Array.isArray(value)) {
      fail('invalid-input')
    }
    const keys = Reflect.ownKeys(value)
    if (keys.some((key) => typeof key !== 'string')) fail('invalid-input')
    if (Array.isArray(value)) {
      const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, 'length')
      const length = lengthDescriptor?.value
      if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) {
        fail('invalid-input')
      }
      const allowed = new Set(['length'])
      const output: unknown[] = []
      for (let index = 0; index < length; index += 1) {
        const key = String(index)
        allowed.add(key)
        const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
        if (!descriptor || !('value' in descriptor)) fail('invalid-input')
        output.push(capturePlainInput(descriptor.value, state, depth + 1))
      }
      if (keys.some((key) => !allowed.has(key as string))) fail('invalid-input')
      return output
    }
    const output = Object.create(null) as Record<string, unknown>
    for (const key of keys as string[]) {
      state.bytes += Buffer.byteLength(key, 'utf8')
      if (state.bytes > MAX_INPUT_SNAPSHOT_BYTES) fail('invalid-input')
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
        fail('invalid-input')
      }
      Object.defineProperty(output, key, {
        configurable: true,
        enumerable: true,
        writable: true,
        value: capturePlainInput(descriptor.value, state, depth + 1)
      })
    }
    return output
  } finally {
    state.ancestors.delete(value)
  }
}

function selectorMatches(
  target: RequestMutationTarget,
  variant: RequestVariantRecord
): boolean {
  return variant.selectors.some((selector) => {
    if (selector.kind !== target.kind) return false
    switch (target.kind) {
      case 'query':
      case 'header':
      case 'cookie':
      case 'form':
        return 'name' in selector && selector.name === target.name
      case 'path':
        return selector.kind === 'path' && selector.name === target.selectorName
      case 'json-pointer':
        return selector.kind === 'json-pointer' && selector.pointer === target.pointer
    }
  })
}

function mutateRepeated<T extends Readonly<{ name: string; value: string }>>(
  entries: readonly T[],
  target: Extract<RequestMutationTarget, { kind: 'query' | 'form' | 'cookie' }>,
  replacement: string
): readonly Readonly<{ name: string; value: string }>[] {
  const matchingIndexes = entries.flatMap((entry, index) =>
    entry.name === target.name ? [index] : []
  )
  const requestedMissing =
    matchingIndexes.length === 0 ||
    (typeof target.occurrence === 'number' &&
      target.occurrence === matchingIndexes.length)
  const requestedGap =
    typeof target.occurrence === 'number' &&
    target.occurrence > matchingIndexes.length
  if (requestedGap) fail('template-mismatch')
  if (requestedMissing) {
    if (target.onMissing === 'reject') fail('template-mismatch')
    return Object.freeze([
      ...entries.map((entry) => Object.freeze({ ...entry })),
      Object.freeze({ name: target.name, value: replacement })
    ])
  }
  const selected =
    target.occurrence === 'all'
      ? new Set(matchingIndexes)
      : new Set([matchingIndexes[target.occurrence]])
  return Object.freeze(
    entries.map((entry, index) =>
      Object.freeze({
        name: entry.name,
        value: selected.has(index) ? replacement : entry.value
      })
    )
  )
}

function canonicalOrigin(value: string): string {
  assertValidUnicode(value)
  if (
    PERCENT_ESCAPE_PATTERN.test(value) ||
    value.includes('\\') ||
    CONTROL_PATTERN.test(value) ||
    !/^https?:\/\/[^/?#]+$/u.test(value)
  ) {
    fail('invalid-canonical-input')
  }
  let url: URL
  try {
    url = new URL(`${value}/`)
  } catch {
    fail('invalid-canonical-input')
  }
  if (
    (url.protocol !== 'http:' && url.protocol !== 'https:') ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname !== '/'
  ) {
    fail('invalid-canonical-input')
  }
  if (url.origin !== value) fail('invalid-canonical-input')
  return url.origin
}

function compilePath(
  origin: string,
  pathSegments: readonly string[],
  target: RequestMutationTarget,
  replacement: unknown
): string {
  const segments = [...pathSegments]
  for (const segment of segments) {
    assertValidUnicode(segment)
    if (
      segment === '.' ||
      segment === '..' ||
      segment.includes('/') ||
      segment.includes('\\')
    ) {
      fail('invalid-canonical-input')
    }
  }
  if (target.kind === 'path') {
    if (target.segmentIndex >= segments.length) fail('template-mismatch')
    const value = safeStringValue(replacement, 'generator')
    if (
      value === '.' ||
      value === '..' ||
      value.includes('/') ||
      value.includes('\\')
    ) {
      fail('generator-rejected')
    }
    segments[target.segmentIndex] = value
  }
  return buildExactUrl(origin, segments)
}

function buildExactUrl(origin: string, pathSegments: readonly string[]): string {
  const normalizedOrigin = canonicalOrigin(origin)
  let totalBytes = Buffer.byteLength(normalizedOrigin, 'utf8') + 1
  if (totalBytes > MAX_URL_BYTES) fail('request-budget-rejected')
  const encodedSegments: string[] = []
  for (const segment of pathSegments) {
    assertValidUnicode(segment)
    if (
      segment === '.' ||
      segment === '..' ||
      segment.includes('/') ||
      segment.includes('\\')
    ) {
      fail('invalid-canonical-input')
    }
    const encoded = encodeRfc3986Component(segment)
    totalBytes += Buffer.byteLength(encoded, 'ascii')
    if (encodedSegments.length > 0) totalBytes += 1
    if (totalBytes > MAX_URL_BYTES) fail('request-budget-rejected')
    encodedSegments.push(encoded)
  }
  return `${normalizedOrigin}/${encodedSegments.join('/')}`
}

function parseJsonPointer(pointer: string): readonly string[] {
  if (pointer === '') return Object.freeze([])
  if (!pointer.startsWith('/')) fail('invalid-canonical-input')
  return Object.freeze(
    pointer.slice(1).split('/').map((token) => {
      if (/~(?![01])/u.test(token)) fail('invalid-canonical-input')
      const decoded = token.replace(/~1/gu, '/').replace(/~0/gu, '~')
      assertValidUnicode(decoded)
      return decoded
    })
  )
}

function pointerToken(value: string): string {
  return value.replace(/~/gu, '~0').replace(/\//gu, '~1')
}

function inferredTemplateValueType(
  value: JsonValueTemplate
): InventoryValueType | undefined {
  if (value.kind === 'object') return 'object'
  if (value.kind === 'array') return 'array'
  if (value.kind !== 'literal') return undefined
  if (value.value === null) return 'null'
  if (typeof value.value === 'string') return 'string'
  if (typeof value.value === 'boolean') return 'boolean'
  return Number.isInteger(value.value) ? 'integer' : 'number'
}

function resolvedValueMatchesType(
  value: ResolvedJsonValue,
  expected: InventoryValueType
): boolean {
  switch (expected) {
    case 'unknown':
      return true
    case 'null':
      return value === null
    case 'string':
      return typeof value === 'string'
    case 'number':
      return typeof value === 'number' && Number.isFinite(value)
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value)
    case 'boolean':
      return typeof value === 'boolean'
    case 'array':
      return isResolvedJsonArray(value)
    case 'object':
      return value !== null && typeof value === 'object' && !isResolvedJsonArray(value)
    case 'none':
    case 'binary':
      return false
  }
}

function readResolvedJsonPointer(
  root: ResolvedJsonValue,
  pointer: string
): ResolvedJsonValue {
  let current = root
  for (const token of parseJsonPointer(pointer)) {
    if (isResolvedJsonArray(current)) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) fail('template-mismatch')
      const index = Number(token)
      if (!Number.isSafeInteger(index) || index >= current.length) {
        fail('template-mismatch')
      }
      current = current[index] as ResolvedJsonValue
    } else if (
      current !== null &&
      typeof current === 'object' &&
      Object.prototype.hasOwnProperty.call(current, token)
    ) {
      current = current[token] as ResolvedJsonValue
    } else {
      fail('template-mismatch')
    }
  }
  return current
}

function findResolvedJsonPointer(
  root: ResolvedJsonValue,
  pointer: string
): Readonly<{ found: true; value: ResolvedJsonValue }> | Readonly<{ found: false }> {
  let current = root
  for (const token of parseJsonPointer(pointer)) {
    if (isResolvedJsonArray(current)) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) return { found: false }
      const index = Number(token)
      if (!Number.isSafeInteger(index) || index >= current.length) {
        return { found: false }
      }
      current = current[index] as ResolvedJsonValue
    } else if (
      current !== null &&
      typeof current === 'object' &&
      Object.prototype.hasOwnProperty.call(current, token)
    ) {
      current = current[token] as ResolvedJsonValue
    } else {
      return { found: false }
    }
  }
  return { found: true, value: current }
}

function validateJsonTemplateShape(
  template: JsonValueTemplate,
  variant: RequestVariantRecord
): void {
  const rootType = inferredTemplateValueType(template)
  if (
    rootType !== undefined &&
    variant.bodyShape.rootType !== 'unknown' &&
    rootType !== variant.bodyShape.rootType &&
    !(rootType === 'integer' && variant.bodyShape.rootType === 'number')
  ) {
    fail('template-mismatch')
  }
  const nodes = new Map<
    string,
    Readonly<{ type: InventoryValueType | undefined; leaf: boolean }>
  >()
  const pending: Array<Readonly<{ path: string; value: JsonValueTemplate }>> = [
    { path: '', value: template }
  ]
  while (pending.length > 0) {
    const current = pending.pop()
    if (!current) continue
    if (nodes.has(current.path)) fail('template-mismatch')
    const isEmptyContainer =
      current.value.kind === 'array'
        ? current.value.items.length === 0
        : current.value.kind === 'object'
          ? current.value.entries.length === 0
          : false
    const leaf =
      current.value.kind !== 'array' && current.value.kind !== 'object' ||
      isEmptyContainer
    nodes.set(
      current.path,
      Object.freeze({ type: inferredTemplateValueType(current.value), leaf })
    )
    if (current.value.kind === 'array') {
      for (let index = current.value.items.length - 1; index >= 0; index -= 1) {
        const child = current.value.items[index]
        if (child) pending.push({ path: `${current.path}/${index}`, value: child })
      }
    } else if (current.value.kind === 'object') {
      for (const entry of current.value.entries) {
        pending.push({
          path: `${current.path}/${pointerToken(entry.key)}`,
          value: entry.value
        })
      }
    }
  }

  const fields = new Map(
    variant.bodyShape.fields.map((field) => [field.path, field])
  )
  for (const [path, node] of nodes) {
    if (path === '' || !node.leaf) continue
    if (!fields.has(path)) fail('template-mismatch')
  }
  for (const field of variant.bodyShape.fields) {
    parseJsonPointer(field.path)
    const node = nodes.get(field.path)
    if (!node) {
      if (field.required) fail('template-mismatch')
      continue
    }
    if (
      node.type !== undefined &&
      node.type !== field.valueType &&
      !(node.type === 'integer' && field.valueType === 'number')
    ) {
      fail('template-mismatch')
    }
  }
}

function validateFormTemplateShape(
  template: Extract<RequestBodyTemplate, { encoding: 'form' }>,
  variant: RequestVariantRecord
): void {
  if (variant.bodyShape.rootType !== 'object') fail('template-mismatch')
  const formSelectors = variant.selectors.filter(
    (selector) => selector.kind === 'form'
  )
  const selectorByPath = new Map(
    formSelectors.map((selector) => [
      `/${pointerToken(selector.name)}`,
      selector
    ])
  )
  if (selectorByPath.size !== variant.bodyShape.fields.length) {
    fail('template-mismatch')
  }
  for (const field of variant.bodyShape.fields) {
    const selector = selectorByPath.get(field.path)
    if (
      !selector ||
      selector.valueType !== field.valueType ||
      selector.required !== field.required
    ) {
      fail('template-mismatch')
    }
  }
  const present = new Set(template.entries.map((entry) => entry.name))
  if (
    formSelectors.some(
      (selector) => selector.required && !present.has(selector.name)
    )
  ) {
    fail('template-mismatch')
  }
}

function validateResolvedJsonShape(
  value: ResolvedJsonValue,
  variant: RequestVariantRecord,
  failureCode: 'resolver-rejected' | 'generator-rejected'
): void {
  if (!resolvedValueMatchesType(value, variant.bodyShape.rootType)) {
    fail(failureCode)
  }
  const allowedPaths = new Set<string>([''])
  for (const field of variant.bodyShape.fields) {
    const tokens = parseJsonPointer(field.path)
    let path = ''
    for (const token of tokens) {
      path = `${path}/${pointerToken(token)}`
      allowedPaths.add(path)
    }
  }
  const pending: Array<Readonly<{ path: string; value: ResolvedJsonValue }>> = [
    { path: '', value }
  ]
  while (pending.length > 0) {
    const current = pending.pop()
    if (!current) continue
    if (!allowedPaths.has(current.path)) fail(failureCode)
    if (isResolvedJsonArray(current.value)) {
      for (let index = 0; index < current.value.length; index += 1) {
        pending.push({
          path: `${current.path}/${index}`,
          value: current.value[index] as ResolvedJsonValue
        })
      }
    } else if (current.value !== null && typeof current.value === 'object') {
      for (const key of Object.keys(current.value)) {
        pending.push({
          path: `${current.path}/${pointerToken(key)}`,
          value: current.value[key] as ResolvedJsonValue
        })
      }
    }
  }
  for (const field of variant.bodyShape.fields) {
    const resolved = findResolvedJsonPointer(value, field.path)
    if (!resolved.found) {
      if (field.required) fail(failureCode)
      continue
    }
    if (!resolvedValueMatchesType(resolved.value, field.valueType)) {
      fail(failureCode)
    }
  }
}

function replaceJsonPointer(
  root: ResolvedJsonValue,
  pointer: string,
  replacement: ResolvedJsonValue
): ResolvedJsonValue {
  const tokens = parseJsonPointer(pointer)
  if (tokens.length === 0) return replacement

  const replaceAt = (
    current: ResolvedJsonValue,
    depth: number
  ): ResolvedJsonValue => {
    const token = tokens[depth]
    if (token === undefined) return replacement
    if (isResolvedJsonArray(current)) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) fail('template-mismatch')
      const index = Number(token)
      if (!Number.isSafeInteger(index) || index >= current.length) {
        fail('template-mismatch')
      }
      return Object.freeze(
        current.map((entry, entryIndex) =>
          entryIndex === index ? replaceAt(entry, depth + 1) : entry
        )
      )
    }
    if (current === null || typeof current !== 'object') fail('template-mismatch')
    if (!Object.prototype.hasOwnProperty.call(current, token)) {
      fail('template-mismatch')
    }
    const output = Object.create(null) as Record<string, ResolvedJsonValue>
    for (const key of Object.keys(current).sort(compareText)) {
      Object.defineProperty(output, key, {
        configurable: false,
        enumerable: true,
        writable: false,
        value:
          key === token
            ? replaceAt(current[key] as ResolvedJsonValue, depth + 1)
            : (current[key] as ResolvedJsonValue)
      })
    }
    return Object.freeze(output)
  }

  return replaceAt(root, 0)
}

export class ProbeRequestCompiler {
  readonly #generators = new Map<string, MutationGenerator>()
  readonly #dynamicResolvers = new Map<string, DynamicValueResolver>()
  readonly #secretResolvers = new Map<string, SecretRefResolver>()
  readonly #knownCapabilities: ReadonlySet<string>
  readonly #resolveHashKey: RequestHashKeyProvider['resolveKey']

  constructor(dependencies: ProbeRequestCompilerDependencies) {
    const knownCapabilities = new Set<string>()
    for (const capabilityId of dependencies.knownCapabilityIds) {
      if (!CapabilityIdSchema.safeParse(capabilityId).success || knownCapabilities.has(capabilityId)) {
        fail('unknown-capability')
      }
      knownCapabilities.add(capabilityId)
    }
    this.#knownCapabilities = knownCapabilities
    this.#resolveHashKey = dependencies.hashKeyProvider.resolveKey.bind(
      dependencies.hashKeyProvider
    )

    for (const generator of dependencies.mutationGenerators) {
      const parsed = MutationGeneratorMetadataSchema.safeParse(generator.metadata)
      if (!parsed.success) fail('unknown-generator')
      const key = registryKey(parsed.data.generatorId, parsed.data.version)
      if (this.#generators.has(key)) fail('unknown-generator')
      this.#generators.set(key, {
        metadata: parsed.data,
        generate: generator.generate.bind(generator)
      })
    }
    for (const resolver of dependencies.dynamicValueResolvers) {
      if (
        !DefinitionIdSchema.safeParse(resolver.resolverId).success ||
        !ModuleVersionSchema.safeParse(resolver.version).success
      ) {
        fail('unknown-resolver')
      }
      const key = registryKey(resolver.resolverId, resolver.version)
      if (this.#dynamicResolvers.has(key)) fail('unknown-resolver')
      this.#dynamicResolvers.set(key, {
        resolverId: resolver.resolverId,
        version: resolver.version,
        resolve: resolver.resolve.bind(resolver)
      })
    }
    for (const resolver of dependencies.secretRefResolvers) {
      if (
        !DefinitionIdSchema.safeParse(resolver.resolverId).success ||
        !ModuleVersionSchema.safeParse(resolver.version).success
      ) {
        fail('unknown-resolver')
      }
      const key = registryKey(resolver.resolverId, resolver.version)
      if (this.#secretResolvers.has(key)) fail('unknown-resolver')
      this.#secretResolvers.set(key, {
        resolverId: resolver.resolverId,
        version: resolver.version,
        resolve: resolver.resolve.bind(resolver)
      })
    }
  }

  compile(input: ProbeRequestCompilerInput): CompiledProbeRequest {
    let captured: ProbeRequestCompilerInput
    try {
      captured = capturePlainInput(input) as ProbeRequestCompilerInput
    } catch (error) {
      if (error instanceof ProbeRequestCompileError) throw error
      fail('invalid-input')
    }
    const capturedTargetKind = (
      captured.mutationTarget as { kind?: unknown } | undefined
    )?.kind
    if (
      typeof capturedTargetKind === 'string' &&
      !['query', 'path', 'header', 'cookie', 'form', 'json-pointer'].includes(
        capturedTargetKind
      )
    ) {
      fail('unsupported-selector')
    }
    let snapshot: ProbeRequestCompilerInput
    try {
      snapshot = this.#snapshotInput(captured)
    } catch (error) {
      if (error instanceof ProbeRequestCompileError) throw error
      fail('invalid-input')
    }
    this.#validateInventory(snapshot)
    this.#validateOpaqueRefs(snapshot)
    this.#validateTemplate(snapshot)

    if (!snapshot.hashKey ||
      !SystemIssuedOpaqueIdSchema.safeParse(snapshot.hashKey.keyRef).success ||
      !Number.isInteger(snapshot.hashKey.keyVersion) ||
      snapshot.hashKey.keyVersion < 0) {
      fail('hash-key-rejected')
    }
    const generator = this.#requireGenerator(snapshot)
    this.#validateCapabilities(snapshot, generator.metadata)

    let key: Uint8Array
    try {
      const provided = this.#resolveHashKey(snapshot.hashKey)
      if (!(provided instanceof Uint8Array)) fail('hash-key-rejected')
      key = Uint8Array.from(provided)
    } catch (error) {
      if (error instanceof ProbeRequestCompileError) throw error
      fail('hash-key-rejected')
    }
    if (key.byteLength < MIN_HMAC_KEY_BYTES || key.byteLength > MAX_HMAC_KEY_BYTES) {
      key.fill(0)
      fail('hash-key-rejected')
    }

    try {
      return this.#compileWithKey(snapshot, generator, key)
    } finally {
      key.fill(0)
    }
  }

  #snapshotInput(input: ProbeRequestCompilerInput): ProbeRequestCompilerInput {
    const allowedInputKeys = new Set([
      'enabledCapabilityIds',
      'endpoint',
      'hashKey',
      'identityRef',
      'mutationGenerator',
      'mutationTarget',
      'ownerRef',
      'requestTemplate',
      'requestVariant',
      'scanId',
      'scopeSnapshotId',
      'sessionRef',
      'testObjectRef'
    ])
    if (Object.keys(input).some((key) => !allowedInputKeys.has(key))) {
      fail('invalid-input')
    }
    if (
      !input.mutationGenerator ||
      canonicalJson(Object.keys(input.mutationGenerator).sort(compareText)) !==
        canonicalJson(['generatorId', 'version']) ||
      !input.hashKey ||
      canonicalJson(Object.keys(input.hashKey).sort(compareText)) !==
        canonicalJson(['keyRef', 'keyVersion'])
    ) {
      fail('invalid-input')
    }
    const requestTemplate: ProbeRequestTemplate = {
      ...input.requestTemplate,
      url: {
        ...input.requestTemplate.url,
        origin: FormValueSourceSchema.parse(input.requestTemplate.url.origin),
        pathSegments: Object.freeze(
          input.requestTemplate.url.pathSegments.map((segment) =>
            Object.freeze({
              ...segment,
              ...(segment.selectorName !== undefined
                ? { selectorName: segment.selectorName }
                : {}),
              value: FormValueSourceSchema.parse(segment.value)
            })
          )
        )
      },
      query: Object.freeze(
        input.requestTemplate.query.map((entry) =>
          Object.freeze({
            ...entry,
            name: entry.name,
            value: FormValueSourceSchema.parse(entry.value)
          })
        )
      ),
      headers: Object.freeze(
        input.requestTemplate.headers.map((entry) =>
          Object.freeze({
            ...entry,
            name: entry.name,
            value: FormValueSourceSchema.parse(entry.value)
          })
        )
      ),
      cookies: Object.freeze(
        input.requestTemplate.cookies.map((entry) =>
          Object.freeze({
            ...entry,
            name: entry.name,
            value: FormValueSourceSchema.parse(entry.value)
          })
        )
      ),
      body: RequestBodyTemplateSchema.parse(input.requestTemplate.body)
    }
    return deepFreeze({
      scanId: input.scanId,
      endpoint: InventoryEndpointRecordSchema.parse(input.endpoint),
      requestVariant: RequestVariantRecordSchema.parse(input.requestVariant),
      requestTemplate,
      mutationTarget: RequestMutationTargetSchema.parse(input.mutationTarget),
      mutationGenerator: {
        generatorId: input.mutationGenerator.generatorId,
        version: input.mutationGenerator.version
      },
      enabledCapabilityIds: [...input.enabledCapabilityIds],
      hashKey: { ...input.hashKey },
      ...(input.ownerRef !== undefined ? { ownerRef: input.ownerRef } : {}),
      ...(input.scopeSnapshotId !== undefined
        ? { scopeSnapshotId: input.scopeSnapshotId }
        : {}),
      ...(input.identityRef !== undefined
        ? { identityRef: IdentityRefSchema.parse(input.identityRef) }
        : {}),
      ...(input.sessionRef !== undefined
        ? { sessionRef: SessionGenerationRefSchema.parse(input.sessionRef) }
        : {}),
      ...(input.testObjectRef !== undefined
        ? { testObjectRef: TestObjectRefSchema.parse(input.testObjectRef) }
        : {})
    }) as ProbeRequestCompilerInput
  }

  #validateInventory(input: ProbeRequestCompilerInput): void {
    const targetKind = (input.mutationTarget as { kind?: unknown } | undefined)?.kind
    if (
      typeof targetKind === 'string' &&
      !['query', 'path', 'header', 'cookie', 'form', 'json-pointer'].includes(
        targetKind
      )
    ) {
      fail('unsupported-selector')
    }
    if (
      !InventoryEndpointRecordSchema.safeParse(input.endpoint).success ||
      !RequestVariantRecordSchema.safeParse(input.requestVariant).success ||
      !RequestMutationTargetSchema.safeParse(input.mutationTarget).success
    ) {
      fail('invalid-input')
    }
    const endpoint = input.endpoint
    const variant = input.requestVariant
    if (
      endpoint.scanId !== input.scanId ||
      variant.scanId !== input.scanId ||
      variant.endpointId !== endpoint.id
    ) {
      fail('inventory-binding-rejected')
    }
    if (
      endpoint.lifecycleStatus !== 'active' ||
      variant.lifecycleStatus !== 'active' ||
      variant.reviewStatus !== 'reviewed' ||
      (variant.executionClass !== 'active-l1' &&
        variant.executionClass !== 'active-l2')
    ) {
      fail('variant-not-executable')
    }
    if (
      (!READ_ONLY_HTTP_METHODS.has(endpoint.method) &&
        !TEST_OBJECT_WRITE_METHODS.has(endpoint.method)) ||
      (TEST_OBJECT_WRITE_METHODS.has(endpoint.method) &&
        variant.executionClass !== 'active-l2')
    ) {
      fail('variant-not-executable')
    }
    if (variant.transport !== 'standard-http') fail('unsupported-transport')
    if (variant.codec !== 'none' && variant.codec !== 'form' && variant.codec !== 'json') {
      fail('unsupported-codec')
    }
    if (!selectorMatches(input.mutationTarget, variant)) {
      const supported = new Set([
        'query',
        'path',
        'header',
        'cookie',
        'form',
        'json-pointer'
      ])
      fail(
        supported.has(input.mutationTarget.kind)
          ? 'template-mismatch'
          : 'unsupported-selector'
      )
    }
    if (
      input.mutationTarget.kind === 'form' && variant.codec !== 'form' ||
      input.mutationTarget.kind === 'json-pointer' && variant.codec !== 'json'
    ) {
      fail('template-mismatch')
    }

    const expectedStructureHash = stableInventoryHash({
      contentType: variant.contentType ?? null,
      bodyShape: canonicalizeInventoryBodyShape(variant.bodyShape),
      codec: variant.codec,
      transport: variant.transport,
      allowedHeaders: canonicalizeAllowedHeaderDescriptors(variant.allowedHeaders),
      templateVersion: variant.templateVersion,
      requiredCapabilityIds: [...variant.requiredCapabilityIds].sort(compareText),
      selectors: canonicalizeSelectorRefs(variant.selectors)
    })
    if (expectedStructureHash !== variant.structureHash) {
      fail('inventory-binding-rejected')
    }
  }

  #validateOpaqueRefs(input: ProbeRequestCompilerInput): void {
    if (
      (input.ownerRef !== undefined &&
        !SystemIssuedOpaqueIdSchema.safeParse(input.ownerRef).success) ||
      (input.scopeSnapshotId !== undefined &&
        !SystemIssuedOpaqueIdSchema.safeParse(input.scopeSnapshotId).success) ||
      (input.identityRef && !IdentityRefSchema.safeParse(input.identityRef).success) ||
      (input.sessionRef &&
        !SessionGenerationRefSchema.safeParse(input.sessionRef).success) ||
      (input.testObjectRef &&
        !TestObjectRefSchema.safeParse(input.testObjectRef).success)
    ) {
      fail('opaque-ref-rejected')
    }
    if (
      input.identityRef?.statusSummary !== undefined &&
      input.identityRef.statusSummary !== 'active'
    ) {
      fail('opaque-ref-rejected')
    }
    if (
      input.sessionRef?.statusSummary !== undefined &&
      input.sessionRef.statusSummary !== 'active'
    ) {
      fail('opaque-ref-rejected')
    }
    if (
      input.testObjectRef?.statusSummary !== undefined &&
      input.testObjectRef.statusSummary !== 'ready' &&
      input.testObjectRef.statusSummary !== 'in-use'
    ) {
      fail('opaque-ref-rejected')
    }
    const refs = [input.identityRef, input.sessionRef, input.testObjectRef].filter(
      (value): value is IdentityRef | SessionGenerationRef | TestObjectRef =>
        value !== undefined
    )
    if (
      refs.length > 0 &&
      (!input.ownerRef || !input.scopeSnapshotId ||
        refs.some(
          (ref) =>
            ref.ownerRef !== input.ownerRef ||
            ref.scopeSnapshotId !== input.scopeSnapshotId
        ))
    ) {
      fail('opaque-ref-rejected')
    }
  }

  #requireGenerator(input: ProbeRequestCompilerInput): MutationGenerator {
    const generator = this.#generators.get(
      registryKey(
        input.mutationGenerator.generatorId,
        input.mutationGenerator.version
      )
    )
    if (!generator) fail('unknown-generator')
    if (
      !generator.metadata.supportedSelectorKinds.includes(input.mutationTarget.kind) ||
      !generator.metadata.supportedBodyEncodings.includes(input.requestVariant.codec)
    ) {
      fail('generator-rejected')
    }
    if (
      generator.metadata.safety.mayExecuteInTargetContext ||
      generator.metadata.safety.networkTarget === 'controlled-oob' ||
      (generator.metadata.safety.sideEffect === 'reversible' &&
        input.requestVariant.executionClass !== 'active-l2') ||
      (generator.metadata.safety.dataAccess === 'authorized-target-data' &&
        input.requestVariant.executionClass !== 'active-l2') ||
      (generator.metadata.safety.dataAccess === 'test-object-only' &&
        !input.testObjectRef)
    ) {
      fail('generator-rejected')
    }
    if (
      input.requestVariant.executionClass === 'active-l1' &&
      (generator.metadata.safety.sideEffect !== 'none' ||
        (generator.metadata.safety.dataAccess !== 'none' &&
          generator.metadata.safety.dataAccess !== 'input-only') ||
        (generator.metadata.safety.networkTarget !== 'none' &&
          generator.metadata.safety.networkTarget !== 'request-target'))
    ) {
      fail('generator-rejected')
    }
    if (
      generator.metadata.safety.sideEffect === 'destructive' ||
      generator.metadata.safety.sideEffect === 'unknown' ||
      generator.metadata.safety.dataAccess === 'arbitrary' ||
      generator.metadata.safety.dataAccess === 'unknown' ||
      generator.metadata.safety.networkTarget === 'arbitrary' ||
      generator.metadata.safety.networkTarget === 'unknown'
    ) {
      fail('generator-rejected')
    }
    return generator
  }

  #validateCapabilities(
    input: ProbeRequestCompilerInput,
    metadata: MutationGeneratorMetadata
  ): void {
    const enabled = new Set<string>()
    for (const capabilityId of input.enabledCapabilityIds) {
      if (
        !CapabilityIdSchema.safeParse(capabilityId).success ||
        !this.#knownCapabilities.has(capabilityId)
      ) {
        fail('unknown-capability')
      }
      if (enabled.has(capabilityId)) fail('capability-rejected')
      enabled.add(capabilityId)
    }
    const referenced = [
      ...input.requestVariant.requiredCapabilityIds,
      ...metadata.requiredCapabilityIds,
      ...metadata.forbiddenCapabilityIds
    ]
    if (referenced.some((id) => !this.#knownCapabilities.has(id))) {
      fail('unknown-capability')
    }
    if (
      [...input.requestVariant.requiredCapabilityIds, ...metadata.requiredCapabilityIds]
        .some((id) => !enabled.has(id)) ||
      metadata.forbiddenCapabilityIds.some((id) => enabled.has(id))
    ) {
      fail('capability-rejected')
    }
  }

  #validateTemplate(input: ProbeRequestCompilerInput): void {
    const template = input.requestTemplate
    if (!template || typeof template !== 'object') fail('invalid-input')
    assertTemplateBudget(template)
    const templateKeys = Object.keys(template).sort(compareText)
    if (
      canonicalJson(templateKeys) !==
      canonicalJson(['body', 'cookies', 'headers', 'query', 'url'])
    ) {
      fail('invalid-input')
    }
    if (
      !template.url ||
      typeof template.url !== 'object' ||
      Array.isArray(template.url) ||
      canonicalJson(Object.keys(template.url).sort(compareText)) !==
        canonicalJson(['origin', 'pathSegments']) ||
      !FormValueSourceSchema.safeParse(template.url.origin).success ||
      !Array.isArray(template.url.pathSegments) ||
      template.url.pathSegments.length > MAX_TEMPLATE_ENTRIES ||
      template.url.pathSegments.some(
        (segment) =>
          !segment ||
          typeof segment !== 'object' ||
          Array.isArray(segment) ||
          Object.keys(segment).some(
            (key) => key !== 'selectorName' && key !== 'value'
          ) ||
          !Object.prototype.hasOwnProperty.call(segment, 'value') ||
          (segment.selectorName !== undefined &&
            typeof segment.selectorName !== 'string') ||
          !FormValueSourceSchema.safeParse(segment.value).success
      )
    ) {
      fail('invalid-input')
    }
    const pathSelectors = new Map(
      input.requestVariant.selectors
        .filter((selector) => selector.kind === 'path')
        .map((selector) => [selector.name, selector])
    )
    const boundPathSelectors = new Set<string>()
    for (const segment of template.url.pathSegments) {
      if (segment.selectorName === undefined) continue
      assertSlotName(segment.selectorName)
      if (
        !pathSelectors.has(segment.selectorName) ||
        boundPathSelectors.has(segment.selectorName)
      ) {
        fail('template-mismatch')
      }
      boundPathSelectors.add(segment.selectorName)
    }
    if (
      [...pathSelectors.values()].some(
        (selector) => selector.required && !boundPathSelectors.has(selector.name)
      )
    ) {
      fail('template-mismatch')
    }
    if (input.mutationTarget.kind === 'path') {
      const segment = template.url.pathSegments[input.mutationTarget.segmentIndex]
      if (!segment || segment.selectorName !== input.mutationTarget.selectorName) {
        fail('template-mismatch')
      }
    }
    if (!RequestBodyTemplateSchema.safeParse(template.body).success) {
      fail('invalid-input')
    }
    if (template.body.encoding !== input.requestVariant.codec) {
      fail('template-mismatch')
    }
    for (const entries of [template.query, template.headers, template.cookies]) {
      if (!Array.isArray(entries) || entries.length > MAX_TEMPLATE_ENTRIES) {
        fail('invalid-input')
      }
      for (const entry of entries) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
            canonicalJson(Object.keys(entry).sort(compareText)) !==
              canonicalJson(['name', 'value']) ||
            typeof entry.name !== 'string' ||
            !FormValueSourceSchema.safeParse(entry.value).success) {
          fail('invalid-input')
        }
      }
    }
    for (const entry of template.query) assertSlotName(entry.name)
    for (const entry of template.cookies) assertCookieName(entry.name)
    const headerNames = new Set<string>()
    for (const entry of template.headers) {
      assertHeaderName(entry.name)
      if (headerNames.has(entry.name) || RESERVED_TRANSPORT_HEADERS.has(entry.name) ||
          entry.name === 'cookie') {
        fail('template-mismatch')
      }
      headerNames.add(entry.name)
    }

    const querySelectors = new Set(
      input.requestVariant.selectors
        .filter((selector) => selector.kind === 'query')
        .map((selector) => selector.name)
    )
    const cookieSelectors = new Set(
      input.requestVariant.selectors
        .filter((selector) => selector.kind === 'cookie')
        .map((selector) => selector.name)
    )
    const formSelectors = new Set(
      input.requestVariant.selectors
        .filter((selector) => selector.kind === 'form')
        .map((selector) => selector.name)
    )
    if (
      template.query.some((entry) => !querySelectors.has(entry.name)) ||
      template.cookies.some((entry) => !cookieSelectors.has(entry.name)) ||
      (template.body.encoding === 'form' &&
        template.body.entries.some((entry) => !formSelectors.has(entry.name)))
    ) {
      fail('template-mismatch')
    }
    for (const selector of input.requestVariant.selectors) {
      if (!selector.required) continue
      if (
        selector.kind === 'query' &&
          !template.query.some((entry) => entry.name === selector.name) ||
        selector.kind === 'cookie' &&
          !template.cookies.some((entry) => entry.name === selector.name) ||
        selector.kind === 'form' &&
          (template.body.encoding !== 'form' ||
            !template.body.entries.some((entry) => entry.name === selector.name))
      ) {
        fail('template-mismatch')
      }
    }

    const allowedHeaders = new Map(
      input.requestVariant.allowedHeaders.map((header) => [header.name, header])
    )
    for (const selector of input.requestVariant.selectors) {
      if (selector.kind !== 'header') continue
      const allowed = allowedHeaders.get(selector.name)
      if (
        !allowed ||
        allowed.valueType !== selector.valueType ||
        allowed.required !== selector.required ||
        (selector.required && !headerNames.has(selector.name))
      ) {
        fail('template-mismatch')
      }
    }
    if (template.headers.some((entry) => !allowedHeaders.has(entry.name))) {
      fail('template-mismatch')
    }
    for (const header of input.requestVariant.allowedHeaders) {
      if (
        header.required &&
        (header.name === 'content-type' || header.name === 'content-length') &&
        template.body.encoding === 'none'
      ) {
        fail('template-mismatch')
      }
      if (
        header.required &&
        header.name === 'cookie' &&
        template.cookies.length === 0
      ) {
        fail('template-mismatch')
      }
      if (
        header.required &&
        RESERVED_TRANSPORT_HEADERS.has(header.name) &&
        header.name !== 'content-type' &&
        header.name !== 'content-length'
      ) {
        fail('template-mismatch')
      }
      if (
        header.required &&
        !RESERVED_TRANSPORT_HEADERS.has(header.name) &&
        header.name !== 'cookie' &&
        !headerNames.has(header.name)
      ) {
        fail('template-mismatch')
      }
    }
    if (
      input.requestVariant.contentType !== undefined &&
      (template.body.encoding === 'none' ||
        !isCanonicalReviewedContentType(
          input.requestVariant.contentType,
          input.requestVariant.codec
        ))
    ) {
      fail('template-mismatch')
    }
    if (template.body.encoding === 'form') {
      validateFormTemplateShape(template.body, input.requestVariant)
    } else if (template.body.encoding === 'json') {
      validateJsonTemplateShape(template.body.value, input.requestVariant)
    }
  }

  #compileWithKey(
    input: ProbeRequestCompilerInput,
    generator: MutationGenerator,
    key: Uint8Array
  ): CompiledProbeRequest {
    const resolvedEntries: Array<Readonly<Record<string, unknown>>> = []
    const context: ResolutionContext = {
      input,
      commitmentKey: key,
      resolvedEntries,
      resolvedBytes: 0
    }
    const resolvedUrl = this.#resolveUrl(input.requestTemplate.url, context)
    const query = this.#resolveNamedValues(input.requestTemplate.query, 'query', context)
    const headers = this.#resolveNamedValues(
      [...input.requestTemplate.headers].sort((left, right) =>
        compareText(left.name, right.name)
      ),
      'header',
      context
    )
    const cookies = this.#resolveNamedValues(input.requestTemplate.cookies, 'cookie', context)
    const body = this.#resolveBody(input.requestTemplate.body, context)
    const unmutatedUrl = buildExactUrl(
      resolvedUrl.origin,
      resolvedUrl.pathSegments
    )
    let canonicalIdentity: string
    try {
      canonicalIdentity = canonicalizeInventoryUrl(unmutatedUrl)
    } catch {
      fail('inventory-binding-rejected')
    }
    if (canonicalIdentity !== input.endpoint.canonicalRoute) {
      fail('inventory-binding-rejected')
    }

    const originalValue = this.#selectedOriginalValue(
      input.mutationTarget,
      resolvedUrl.pathSegments,
      query,
      headers,
      cookies,
      body
    )
    let generated: unknown
    try {
      generated = generator.generate(
        deepFreeze({
          target: input.mutationTarget,
          bodyEncoding: input.requestVariant.codec,
          originalValue
        })
      )
    } catch {
      fail('generator-rejected')
    }
    const generatedValue = sanitizeJsonValue(
      generated,
      { nodes: 0, bytes: 0, ancestors: new Set() },
      'generator'
    )
    if (canonicalValueBytes(generatedValue).byteLength > generator.metadata.maxOutputBytes) {
      fail('generator-rejected')
    }
    resolvedEntries.push(
      Object.freeze({
        path: 'mutation-output',
        descriptor: { kind: 'generator-output' },
        commitment: budgetedCommitment(
          context,
          'mutation-output',
          generatedValue,
          'generator-rejected'
        )
      })
    )

    let finalQuery: readonly Readonly<{ name: string; value: string }>[] = query
    let finalHeaders: readonly Readonly<{ name: string; value: string }>[] = headers
    let finalCookies: readonly Readonly<{ name: string; value: string }>[] = cookies
    let finalBody:
      | undefined
      | Readonly<{
          encoding: 'form'
          entries: readonly Readonly<{ name: string; value: string }>[]
        }>
      | Readonly<{ encoding: 'json'; value: ResolvedJsonValue }> = body
    if (input.mutationTarget.kind === 'query') {
      finalQuery = mutateRepeated(
        query,
        input.mutationTarget,
        safeStringValue(generatedValue, 'generator')
      )
    } else if (input.mutationTarget.kind === 'header') {
      const targetName = input.mutationTarget.name
      const replacement = safeStringValue(generatedValue, 'generator')
      try {
        assertHeaderValue(replacement)
      } catch {
        fail('generator-rejected')
      }
      finalHeaders = Object.freeze(
        headers.map((entry) =>
          entry.name === targetName
            ? Object.freeze({ ...entry, value: replacement })
            : entry
        )
      )
      if (!finalHeaders.some((entry) => entry.name === targetName)) {
        fail('template-mismatch')
      }
    } else if (input.mutationTarget.kind === 'cookie') {
      const replacement = safeStringValue(generatedValue, 'generator')
      if (!COOKIE_VALUE_PATTERN.test(replacement)) fail('generator-rejected')
      finalCookies = mutateRepeated(cookies, input.mutationTarget, replacement)
    } else if (input.mutationTarget.kind === 'form') {
      if (!body || body.encoding !== 'form') fail('template-mismatch')
      finalBody = {
        encoding: 'form',
        entries: mutateRepeated(
          body.entries,
          input.mutationTarget,
          safeStringValue(generatedValue, 'generator')
        )
      }
    } else if (input.mutationTarget.kind === 'json-pointer') {
      if (!body || body.encoding !== 'json') fail('template-mismatch')
      finalBody = {
        encoding: 'json',
        value: replaceJsonPointer(body.value, input.mutationTarget.pointer, generatedValue)
      }
    }
    if (finalBody?.encoding === 'json') {
      validateResolvedJsonShape(
        finalBody.value,
        input.requestVariant,
        'generator-rejected'
      )
    }

    const url = this.#buildUrl(
      compilePath(
        resolvedUrl.origin,
        resolvedUrl.pathSegments,
        input.mutationTarget,
        generatedValue
      ),
      finalQuery
    )
    const bodyBytes = this.#encodeBody(finalBody)
    const wireHeaders = this.#buildHeaders(
      finalHeaders,
      finalCookies,
      finalBody,
      bodyBytes,
      input.requestVariant.contentType
    )
    this.#assertWireBudget(
      input.endpoint.method,
      url,
      wireHeaders,
      bodyBytes
    )

    const templateIntentHash: TemplateIntentHash = Object.freeze({
      domain: TEMPLATE_INTENT_HASH_DOMAIN,
      algorithm: 'sha256',
      digest: sha256Text(
        canonicalJson({
          domain: TEMPLATE_INTENT_HASH_DOMAIN,
          scanId: input.scanId,
          endpoint: {
            id: input.endpoint.id,
            method: input.endpoint.method,
            canonicalRoute: input.endpoint.canonicalRoute,
            lifecycleStatus: input.endpoint.lifecycleStatus
          },
          requestVariant: {
            id: input.requestVariant.id,
            endpointId: input.requestVariant.endpointId,
            templateVersion: input.requestVariant.templateVersion,
            structureHash: input.requestVariant.structureHash,
            reviewStatus: input.requestVariant.reviewStatus,
            reviewedBy: input.requestVariant.reviewedBy ?? null,
            reviewedAt: input.requestVariant.reviewedAt ?? null,
            executionClass: input.requestVariant.executionClass,
            lifecycleStatus: input.requestVariant.lifecycleStatus,
            retiredAt: input.requestVariant.retiredAt ?? null
          },
          enabledCapabilityIds: [...input.enabledCapabilityIds].sort(compareText),
          mutationTarget: input.mutationTarget,
          mutationGenerator: generator.metadata,
          requestTemplate: requestTemplateDescriptor(input.requestTemplate)
        })
      )
    })
    const resolvedIntentHash: ResolvedIntentHash = Object.freeze({
      domain: RESOLVED_INTENT_HASH_DOMAIN,
      algorithm: 'sha256',
      commitmentKeyRef: input.hashKey.keyRef,
      commitmentKeyVersion: input.hashKey.keyVersion,
      digest: sha256Text(
        canonicalJson({
          domain: RESOLVED_INTENT_HASH_DOMAIN,
          templateIntentDigest: templateIntentHash.digest,
          commitmentKeyRef: input.hashKey.keyRef,
          commitmentKeyVersion: input.hashKey.keyVersion,
          ownerRef: input.ownerRef ?? null,
          scopeSnapshotId: input.scopeSnapshotId ?? null,
          identityRef: input.identityRef ?? null,
          sessionRef: input.sessionRef ?? null,
          testObjectRef: input.testObjectRef ?? null,
          resolvedEntries
        })
      )
    })
    const wireRequestHmac = this.#wireHmac(
      input,
      key,
      resolvedIntentHash,
      input.endpoint.method,
      url,
      wireHeaders,
      bodyBytes
    )
    const request = new CompiledWireRequest({
      method: input.endpoint.method,
      url,
      headers: wireHeaders,
      ...(bodyBytes ? { bodyBytes: Object.freeze([...bodyBytes]) } : {})
    })
    return Object.freeze({
      request,
      templateIntentHash,
      resolvedIntentHash,
      wireRequestHmac
    })
  }

  #resolveNamedValues(
    entries: readonly NamedRequestValueTemplate[],
    location: 'query' | 'header' | 'cookie',
    context: ResolutionContext
  ): readonly ResolvedNamedValue[] {
    return Object.freeze(
      entries.map((entry, index) => {
        const path = `${location}/${index}`
        const value = safeStringValue(
          this.#resolveValueSource(entry.value, path, context),
          'resolver'
        )
        if (location === 'header') assertHeaderValue(value)
        if (location === 'cookie') assertCookieValue(value)
        const descriptor = valueSourceDescriptor(entry.value)
        const commitment = budgetedCommitment(
          context,
          path,
          value,
          valueSourceBudgetFailure(entry.value)
        )
        context.resolvedEntries.push(
          Object.freeze({ path, descriptor, commitment })
        )
        return Object.freeze({ name: entry.name, value, descriptor, commitment })
      })
    )
  }

  #resolveUrl(
    template: ProbeRequestTemplate['url'],
    context: ResolutionContext
  ): Readonly<{ origin: string; pathSegments: readonly string[] }> {
    const origin = safeStringValue(
      this.#resolveValueSource(template.origin, 'url/origin', context),
      'resolver'
    )
    canonicalOrigin(origin)
    const originDescriptor = valueSourceDescriptor(template.origin)
    context.resolvedEntries.push(
      Object.freeze({
        path: 'url/origin',
        descriptor: originDescriptor,
        commitment: budgetedCommitment(
          context,
          'url/origin',
          origin,
          valueSourceBudgetFailure(template.origin)
        )
      })
    )
    const pathSegments = template.pathSegments.map((segment, index) => {
      const path = `url/path/${index}`
      const value = safeStringValue(
        this.#resolveValueSource(segment.value, path, context),
        'resolver'
      )
      if (
        value === '.' ||
        value === '..' ||
        value.includes('/') ||
        value.includes('\\')
      ) {
        fail('invalid-canonical-input')
      }
      const descriptor = {
        selectorName: segment.selectorName ?? null,
        value: valueSourceDescriptor(segment.value)
      }
      context.resolvedEntries.push(
        Object.freeze({
          path,
          descriptor,
          commitment: budgetedCommitment(
            context,
            path,
            value,
            valueSourceBudgetFailure(segment.value)
          )
        })
      )
      return value
    })
    return Object.freeze({ origin, pathSegments: Object.freeze(pathSegments) })
  }

  #resolveBody(
    template: RequestBodyTemplate,
    context: ResolutionContext
  ):
    | undefined
    | Readonly<{
        encoding: 'form'
        entries: readonly ResolvedNamedValue[]
      }>
    | Readonly<{ encoding: 'json'; value: ResolvedJsonValue }> {
    if (template.encoding === 'none') return undefined
    if (template.encoding === 'form') {
      return Object.freeze({
        encoding: 'form' as const,
        entries: Object.freeze(
          template.entries.map((entry, index) => {
            const path = `body/form/${index}`
            const value = safeStringValue(
              this.#resolveValueSource(entry.value, path, context),
              'resolver'
            )
            const descriptor = valueSourceDescriptor(entry.value)
            const commitment = budgetedCommitment(
              context,
              path,
              value,
              valueSourceBudgetFailure(entry.value)
            )
            context.resolvedEntries.push(
              Object.freeze({ path, descriptor, commitment })
            )
            return Object.freeze({ name: entry.name, value, descriptor, commitment })
          })
        )
      })
    }
    const value = this.#resolveJsonTemplate(template.value, 'body/json', context)
    validateResolvedJsonShape(
      value,
      context.input.requestVariant,
      'resolver-rejected'
    )
    return Object.freeze({ encoding: 'json' as const, value })
  }

  #resolveJsonTemplate(
    template: JsonValueTemplate,
    path: string,
    context: ResolutionContext
  ): ResolvedJsonValue {
    if (template.kind === 'array') {
      return Object.freeze(
        template.items.map((entry, index) =>
          this.#resolveJsonTemplate(entry, `${path}/${index}`, context)
        )
      )
    }
    if (template.kind === 'object') {
      const output = Object.create(null) as Record<string, ResolvedJsonValue>
      for (const entry of [...template.entries].sort((left, right) =>
        compareText(left.key, right.key)
      )) {
        Object.defineProperty(output, entry.key, {
          configurable: false,
          enumerable: true,
          writable: false,
          value: this.#resolveJsonTemplate(
            entry.value,
            `${path}/${entry.key.replace(/~/gu, '~0').replace(/\//gu, '~1')}`,
            context
          )
        })
      }
      return Object.freeze(output)
    }
    const value = sanitizeJsonValue(
      this.#resolveValueSource(template, path, context),
      { nodes: 0, bytes: 0, ancestors: new Set() },
      'resolver'
    )
    const descriptor = valueSourceDescriptor(template)
    const commitment = budgetedCommitment(
      context,
      path,
      value,
      valueSourceBudgetFailure(template)
    )
    context.resolvedEntries.push(Object.freeze({ path, descriptor, commitment }))
    return value
  }

  #resolveValueSource(
    source: FormValueSource | JsonValueSource,
    _path: string,
    context: ResolutionContext
  ): unknown {
    if (source.kind === 'literal') return source.value
    if (source.kind === 'dynamic') {
      const resolver = this.#dynamicResolvers.get(
        registryKey(source.resolver.resolverId, source.resolver.version)
      )
      if (!resolver) fail('unknown-resolver')
      try {
        return resolver.resolve({
          slotId: source.slotId,
          ...(context.input.identityRef
            ? { identityRef: context.input.identityRef }
            : {}),
          ...(context.input.sessionRef
            ? { sessionRef: context.input.sessionRef }
            : {}),
          ...(context.input.testObjectRef
            ? { testObjectRef: context.input.testObjectRef }
            : {})
        })
      } catch {
        fail('resolver-rejected')
      }
    }
    const resolver = this.#secretResolvers.get(
      registryKey(source.resolver.resolverId, source.resolver.version)
    )
    if (!resolver) fail('unknown-resolver')
    try {
      return resolver.resolve({
        secretRef: source.secretRef,
        generation: source.generation,
        ...(context.input.identityRef
          ? { identityRef: context.input.identityRef }
          : {}),
        ...(context.input.sessionRef
          ? { sessionRef: context.input.sessionRef }
          : {})
      })
    } catch {
      fail('resolver-rejected')
    }
  }

  #selectedOriginalValue(
    target: RequestMutationTarget,
    pathSegments: readonly string[],
    query: readonly ResolvedNamedValue[],
    headers: readonly ResolvedNamedValue[],
    cookies: readonly ResolvedNamedValue[],
    body:
      | undefined
      | Readonly<{ encoding: 'form'; entries: readonly ResolvedNamedValue[] }>
      | Readonly<{ encoding: 'json'; value: ResolvedJsonValue }>
  ): ResolvedJsonValue | undefined {
    if (target.kind === 'path') {
      if (target.segmentIndex >= pathSegments.length) fail('template-mismatch')
      return pathSegments[target.segmentIndex] ?? ''
    }
    if (target.kind === 'header') {
      return headers.find((entry) => entry.name === target.name)?.value
    }
    if (target.kind === 'json-pointer') {
      if (!body || body.encoding !== 'json') fail('template-mismatch')
      return readResolvedJsonPointer(body.value, target.pointer)
    }
    const entries =
      target.kind === 'query'
        ? query
        : target.kind === 'cookie'
          ? cookies
          : body?.encoding === 'form'
            ? body.entries
            : []
    const matches = entries.filter((entry) => entry.name === target.name)
    if (target.occurrence === 'all') {
      return Object.freeze(matches.map((entry) => entry.value))
    }
    return matches[target.occurrence]?.value
  }

  #buildUrl(
    route: string,
    query: readonly Readonly<{ name: string; value: string }>[]
  ): string {
    if (query.length === 0) return route
    let totalBytes = Buffer.byteLength(route, 'utf8') + 1
    const pairs: string[] = []
    for (const entry of query) {
      const pair = `${encodeFormComponent(entry.name)}=${encodeFormComponent(entry.value)}`
      totalBytes += Buffer.byteLength(pair, 'ascii')
      if (pairs.length > 0) totalBytes += 1
      if (totalBytes > MAX_URL_BYTES) fail('request-budget-rejected')
      pairs.push(pair)
    }
    return `${route}?${pairs.join('&')}`
  }

  #encodeBody(
    body:
      | undefined
      | Readonly<{
          encoding: 'form'
          entries: readonly Readonly<{ name: string; value: string }>[]
        }>
      | Readonly<{ encoding: 'json'; value: ResolvedJsonValue }>
  ): Uint8Array | undefined {
    if (!body) return undefined
    let text: string
    if (body.encoding === 'form') {
      let totalBytes = 0
      const pairs: string[] = []
      for (const entry of body.entries) {
        const pair = `${encodeFormComponent(entry.name)}=${encodeFormComponent(entry.value)}`
        totalBytes += Buffer.byteLength(pair, 'ascii')
        if (pairs.length > 0) totalBytes += 1
        if (totalBytes > MAX_BODY_BYTES) fail('request-budget-rejected')
        pairs.push(pair)
      }
      text = pairs.join('&')
    } else {
      text = canonicalJson(body.value)
    }
    const bytes = utf8(text)
    if (bytes.byteLength > MAX_BODY_BYTES) fail('request-budget-rejected')
    return bytes
  }

  #buildHeaders(
    headers: readonly Readonly<{ name: string; value: string }>[],
    cookies: readonly Readonly<{ name: string; value: string }>[],
    body:
      | undefined
      | Readonly<{ encoding: 'form'; entries: readonly unknown[] }>
      | Readonly<{ encoding: 'json'; value: ResolvedJsonValue }>,
    bodyBytes: Uint8Array | undefined,
    reviewedContentType: string | undefined
  ): readonly Readonly<{ name: string; value: string }>[] {
    const output = headers.map((entry) => ({ name: entry.name, value: entry.value }))
    if (cookies.length > 0) {
      let cookieBytes = 0
      const pairs: string[] = []
      for (const entry of cookies) {
        const pair = `${entry.name}=${entry.value}`
        cookieBytes += Buffer.byteLength(pair, 'ascii')
        if (pairs.length > 0) cookieBytes += 2
        if (cookieBytes > MAX_HEADER_BLOCK_BYTES) fail('request-budget-rejected')
        pairs.push(pair)
      }
      output.push({
        name: 'cookie',
        value: pairs.join('; ')
      })
    }
    if (body) {
      output.push({
        name: 'content-type',
        value:
          body.encoding === 'form'
            ? `${reviewedContentType ?? 'application/x-www-form-urlencoded'}; charset=utf-8`
            : `${reviewedContentType ?? 'application/json'}; charset=utf-8`
      })
      output.push({ name: 'content-length', value: String(bodyBytes?.byteLength ?? 0) })
    }
    let headerBytes = 0
    const sorted = output.sort((left, right) => compareText(left.name, right.name))
    for (const header of sorted) {
      assertHeaderName(header.name)
      assertHeaderValue(header.value)
      headerBytes +=
        Buffer.byteLength(header.name, 'ascii') +
        2 +
        Buffer.byteLength(header.value, 'ascii') +
        2
      if (headerBytes > MAX_HEADER_BLOCK_BYTES) fail('request-budget-rejected')
    }
    return Object.freeze(sorted.map((entry) => Object.freeze(entry)))
  }

  #assertWireBudget(
    method: string,
    url: string,
    headers: readonly Readonly<{ name: string; value: string }>[],
    bodyBytes: Uint8Array | undefined
  ): void {
    let totalBytes = Buffer.byteLength(method, 'ascii') + Buffer.byteLength(url, 'utf8')
    for (const header of headers) {
      totalBytes +=
        Buffer.byteLength(header.name, 'ascii') +
        Buffer.byteLength(header.value, 'ascii') +
        4
    }
    totalBytes += bodyBytes?.byteLength ?? 0
    if (totalBytes > MAX_WIRE_BYTES) fail('request-budget-rejected')
  }

  #wireHmac(
    input: ProbeRequestCompilerInput,
    key: Uint8Array,
    resolved: ResolvedIntentHash,
    method: string,
    url: string,
    headers: readonly Readonly<{ name: string; value: string }>[],
    bodyBytes: Uint8Array | undefined
  ): WireRequestHmac {
    const hmac = createHmac('sha256', key)
    updateFrame(hmac, 'domain', utf8(WIRE_REQUEST_HMAC_DOMAIN))
    updateFrame(hmac, 'resolved-intent', utf8(resolved.digest))
    updateFrame(hmac, 'method', utf8(method))
    updateFrame(hmac, 'url', utf8(url))
    for (const header of headers) {
      updateFrame(hmac, `header-name`, utf8(header.name))
      updateFrame(hmac, `header-value`, utf8(header.value))
    }
    updateFrame(hmac, 'body-present', utf8(bodyBytes ? '1' : '0'))
    updateFrame(hmac, 'body', bodyBytes ?? new Uint8Array())
    return Object.freeze({
      domain: WIRE_REQUEST_HMAC_DOMAIN,
      algorithm: 'hmac-sha256',
      keyRef: input.hashKey.keyRef,
      keyVersion: input.hashKey.keyVersion,
      digest: hmac.digest('hex')
    })
  }
}
