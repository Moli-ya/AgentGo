import { createHash, createHmac, type Hmac } from 'node:crypto'
import {
  EVIDENCE_SOURCE_HASH_DOMAIN,
  EvidenceArtifactDraftSchema,
  EvidenceCaptureContextSchema,
  EvidenceCaptureDecisionSchema,
  EvidenceCaptureResultSchema,
  OOB_TOKEN_COMMITMENT_DOMAIN,
  OobCaptureMetadataSchema,
  OobTokenCommitmentSchema,
  PROTECTED_EVIDENCE_ARTIFACT_SCHEMA_VERSION,
  type EvidenceArtifactDraft,
  type EvidenceCaptureContext,
  type EvidenceCaptureDecision,
  type EvidenceCaptureReason,
  type EvidenceHashOnlyReason,
  type EvidenceCaptureResult,
  type EvidenceSourceHash,
  type OobCaptureMetadata,
  type OobTokenCommitment
} from '@agentgo/contracts'
import {
  INVENTORY_REDACTION_MARKER,
  canonicalJson,
  compareText,
  deepFreeze,
  redactInventoryText,
  sha256Text
} from '@agentgo/domain'
import {
  snapshotSecureBytes,
  zeroizeSecureBytes
} from './secure-byte-snapshot'

const SENSITIVE_JSON_FIELD_PATTERN =
  /(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[-_.]?key|credential|csrf|xsrf|session)/iu

export type EvidenceCapturePolicyErrorCode =
  | 'invalid-context'
  | 'invalid-decision'
  | 'decision-context-mismatch'
  | 'decision-outside-window'
  | 'invalid-source-input'
  | 'invalid-oob-commitment'

const POLICY_ERROR_MESSAGES: Readonly<
  Record<EvidenceCapturePolicyErrorCode, string>
> = Object.freeze({
  'invalid-context': 'Evidence capture context is invalid.',
  'invalid-decision': 'Evidence capture decision is invalid.',
  'decision-context-mismatch':
    'Evidence capture decision is not bound to this context.',
  'decision-outside-window':
    'Evidence capture occurred outside the authorized window.',
  'invalid-source-input': 'Evidence capture source input is invalid.',
  'invalid-oob-commitment': 'OOB token commitment failed validation.'
})

export class EvidenceCapturePolicyError extends Error {
  constructor(readonly code: EvidenceCapturePolicyErrorCode) {
    super(POLICY_ERROR_MESSAGES[code])
    this.name = 'EvidenceCapturePolicyError'
  }
}

export interface OobCommitmentKeyProvider {
  /**
   * Implementations must be synchronous, in-memory, side-effect-free key
   * lookups. The policy uses and clears its own copy of the returned bytes.
   */
  resolveKey(input: Readonly<{
    keyRef: string
    keyVersion: number
  }>): Uint8Array
}

export interface EvidenceByteCaptureInput {
  readonly kind: 'bytes'
  readonly context: EvidenceCaptureContext
  readonly decision: EvidenceCaptureDecision
  readonly content: Uint8Array
  readonly completeness: 'complete' | 'prefix'
  readonly knownTotalBytes?: number
}

export interface EvidenceOobCaptureInput {
  readonly kind: 'oob'
  readonly context: EvidenceCaptureContext
  readonly decision: EvidenceCaptureDecision
  readonly token: string
  readonly metadata: OobCaptureMetadata
}

export type EvidenceCaptureInput =
  | EvidenceByteCaptureInput
  | EvidenceOobCaptureInput

const MAX_CAPTURE_SOURCE_BYTES = 16_777_216
const MAX_OOB_TOKEN_BYTES = 16_384
const MIN_OOB_HMAC_KEY_BYTES = 32
const MAX_OOB_HMAC_KEY_BYTES = 64

interface PlainSnapshotLimits {
  readonly maxDepth: number
  readonly maxNodes: number
  readonly maxUtf8Bytes: number
  readonly maxArrayLength: number
  readonly maxObjectKeys: number
}

const CONTEXT_SNAPSHOT_LIMITS: PlainSnapshotLimits = Object.freeze({
  maxDepth: 4,
  maxNodes: 64,
  maxUtf8Bytes: 32_768,
  maxArrayLength: 16,
  maxObjectKeys: 32
})

const DECISION_SNAPSHOT_LIMITS: PlainSnapshotLimits = Object.freeze({
  maxDepth: 4,
  maxNodes: 512,
  maxUtf8Bytes: 1_048_576,
  maxArrayLength: 256,
  maxObjectKeys: 64
})

const METADATA_SNAPSHOT_LIMITS: PlainSnapshotLimits = Object.freeze({
  maxDepth: 2,
  maxNodes: 32,
  maxUtf8Bytes: 8_192,
  maxArrayLength: 8,
  maxObjectKeys: 16
})

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return false
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) return false
      index += 1
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false
    }
  }
  return true
}

function snapshotOwnData(
  value: unknown,
  allowedKeys: ReadonlySet<string>,
  requiredKeys: readonly string[]
): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw new EvidenceCapturePolicyError('invalid-source-input')
    }
    const output: Record<string, unknown> = Object.create(null)
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || !allowedKeys.has(key)) {
        throw new EvidenceCapturePolicyError('invalid-source-input')
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ) {
        throw new EvidenceCapturePolicyError('invalid-source-input')
      }
      output[key] = descriptor.value
    }
    for (const key of requiredKeys) {
      if (!Object.prototype.hasOwnProperty.call(output, key)) {
        throw new EvidenceCapturePolicyError('invalid-source-input')
      }
    }
    return Object.freeze(output)
  } catch (error) {
    if (error instanceof EvidenceCapturePolicyError) throw error
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
}

function assertSnapshotShape(
  snapshot: Readonly<Record<string, unknown>>,
  allowedKeys: ReadonlySet<string>,
  requiredKeys: readonly string[]
): void {
  for (const key of Object.keys(snapshot)) {
    if (!allowedKeys.has(key)) {
      throw new EvidenceCapturePolicyError('invalid-source-input')
    }
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(snapshot, key)) {
      throw new EvidenceCapturePolicyError('invalid-source-input')
    }
  }
}

function snapshotByteContent(value: unknown): Uint8Array {
  try {
    return snapshotSecureBytes(value, {
      maximumBytes: MAX_CAPTURE_SOURCE_BYTES
    })
  } catch (error) {
    if (error instanceof EvidenceCapturePolicyError) throw error
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
}

function snapshotBoundedPlainData(
  value: unknown,
  limits: PlainSnapshotLimits,
  errorCode: EvidenceCapturePolicyErrorCode
): unknown {
  const budget = {
    remainingNodes: limits.maxNodes,
    remainingUtf8Bytes: limits.maxUtf8Bytes
  }

  const reject = (): never => {
    throw new EvidenceCapturePolicyError(errorCode)
  }

  const consumeText = (text: string): string => {
    if (text.length > budget.remainingUtf8Bytes) reject()
    const byteLength = Buffer.byteLength(text, 'utf8')
    if (byteLength > budget.remainingUtf8Bytes) reject()
    budget.remainingUtf8Bytes -= byteLength
    return text
  }

  const visit = (entry: unknown, depth: number): unknown => {
    if (depth > limits.maxDepth || budget.remainingNodes <= 0) reject()
    budget.remainingNodes -= 1

    if (entry === null || entry === undefined) return entry
    if (typeof entry === 'string') return consumeText(entry)
    if (typeof entry === 'boolean' || typeof entry === 'number') return entry
    if (typeof entry !== 'object') reject()

    const prototype = Object.getPrototypeOf(entry)
    if (Array.isArray(entry)) {
      if (prototype !== Array.prototype) reject()
      const lengthDescriptor = Object.getOwnPropertyDescriptor(entry, 'length')
      if (
        lengthDescriptor === undefined ||
        !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value') ||
        !Number.isInteger(lengthDescriptor.value) ||
        (lengthDescriptor.value as number) < 0 ||
        (lengthDescriptor.value as number) > limits.maxArrayLength
      ) {
        reject()
      }
      const length = (lengthDescriptor as PropertyDescriptor).value as number
      const keys = Reflect.ownKeys(entry)
      if (keys.length !== length + 1) reject()
      const keySet = new Set<PropertyKey>(keys)
      if (!keySet.has('length')) reject()
      const output: unknown[] = new Array(length)
      for (let index = 0; index < length; index += 1) {
        const key = String(index)
        if (!keySet.has(key)) reject()
        const descriptor = Object.getOwnPropertyDescriptor(entry, key)
        if (
          descriptor === undefined ||
          !descriptor.enumerable ||
          !Object.prototype.hasOwnProperty.call(descriptor, 'value')
        ) {
          reject()
        }
        output[index] = visit(
          (descriptor as PropertyDescriptor).value,
          depth + 1
        )
      }
      return Object.freeze(output)
    }

    if (prototype !== Object.prototype && prototype !== null) reject()
    const keys = Reflect.ownKeys(entry)
    if (keys.length > limits.maxObjectKeys) reject()
    const output: Record<string, unknown> = Object.create(null)
    for (const key of keys) {
      if (typeof key !== 'string') {
        throw new EvidenceCapturePolicyError(errorCode)
      }
      const textKey = key
      consumeText(textKey)
      const descriptor = Object.getOwnPropertyDescriptor(entry, key)
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ) {
        reject()
      }
      output[textKey] = visit(
        (descriptor as PropertyDescriptor).value,
        depth + 1
      )
    }
    return Object.freeze(output)
  }

  try {
    return visit(value, 0)
  } catch (error) {
    if (error instanceof EvidenceCapturePolicyError) throw error
    throw new EvidenceCapturePolicyError(errorCode)
  }
}

function parseContext(value: unknown): EvidenceCaptureContext {
  try {
    const snapshot = snapshotBoundedPlainData(
      value,
      CONTEXT_SNAPSHOT_LIMITS,
      'invalid-context'
    )
    const parsed = EvidenceCaptureContextSchema.safeParse(snapshot)
    if (!parsed.success) throw new EvidenceCapturePolicyError('invalid-context')
    return parsed.data
  } catch (error) {
    if (error instanceof EvidenceCapturePolicyError) throw error
    throw new EvidenceCapturePolicyError('invalid-context')
  }
}

function parseDecision(value: unknown): EvidenceCaptureDecision {
  try {
    const snapshot = snapshotBoundedPlainData(
      value,
      DECISION_SNAPSHOT_LIMITS,
      'invalid-decision'
    )
    const parsed = EvidenceCaptureDecisionSchema.safeParse(snapshot)
    if (!parsed.success) throw new EvidenceCapturePolicyError('invalid-decision')
    return parsed.data
  } catch (error) {
    if (error instanceof EvidenceCapturePolicyError) throw error
    throw new EvidenceCapturePolicyError('invalid-decision')
  }
}

function assertDecisionBinding(
  context: EvidenceCaptureContext,
  decision: EvidenceCaptureDecision
): void {
  if (
    context.scanId !== decision.scanId ||
    context.policyDecisionId !== decision.policyDecisionId ||
    context.techniqueId !== decision.techniqueId ||
    context.techniqueVersion !== decision.techniqueVersion ||
    context.stepId !== decision.stepId ||
    context.executionState !== decision.executionState ||
    context.source !== decision.source ||
    context.role !== decision.role
  ) {
    throw new EvidenceCapturePolicyError('decision-context-mismatch')
  }

  const occurredAt = Date.parse(context.occurredAt)
  if (
    occurredAt < Date.parse(decision.validFrom) ||
    occurredAt > Date.parse(decision.validUntil)
  ) {
    throw new EvidenceCapturePolicyError('decision-outside-window')
  }

  // Technique and step IDs are constrained by strict stable-ID schemas and
  // bound to the sealed execution definition. Applying the generic
  // entropy-based preview redactor to them rejects legitimate IDs such as
  // `sqli.boolean-differential`. Authority labels and unstructured JSON
  // pointers retain the secret-fragment gate.
  for (const value of [
    decision.capturePolicyId,
    context.role,
    ...decision.jsonPointers
  ]) {
    if (redactInventoryText(value, 2_048) !== value) {
      throw new EvidenceCapturePolicyError('invalid-decision')
    }
  }
}

function sha256Bytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function byteContentDescriptor(
  context: EvidenceCaptureContext
): Readonly<{
  mediaType: string
  charset: 'utf-8' | 'non-utf-8' | 'unknown' | 'not-applicable'
  contentEncoding: 'identity' | 'compressed' | 'unknown'
  declaredSizeBytes?: number
}> {
  if (context.source === 'oob-event') {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  return 'content' in context ? context.content : context.response
}

function byteSourceHash(
  input: EvidenceByteCaptureInput,
  context: EvidenceCaptureContext
): EvidenceSourceHash {
  if (context.source === 'oob-event') {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  if (!Number.isInteger(input.knownTotalBytes) && input.knownTotalBytes !== undefined) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  if (
    input.knownTotalBytes !== undefined &&
    (input.knownTotalBytes < 0 ||
      input.knownTotalBytes < input.content.byteLength ||
      (input.completeness === 'prefix' &&
        input.knownTotalBytes === input.content.byteLength))
  ) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  if (
    input.completeness === 'complete' &&
    input.knownTotalBytes !== undefined &&
    input.knownTotalBytes !== input.content.byteLength
  ) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }

  const descriptor = byteContentDescriptor(context)
  if (
    descriptor.declaredSizeBytes !== undefined &&
    (descriptor.declaredSizeBytes < input.content.byteLength ||
      (input.completeness === 'complete' &&
        descriptor.declaredSizeBytes !== input.content.byteLength) ||
      (input.knownTotalBytes !== undefined &&
        descriptor.declaredSizeBytes !== input.knownTotalBytes))
  ) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  const declaredTotal =
    input.knownTotalBytes ?? descriptor.declaredSizeBytes
  const knownTotalBytes =
    input.completeness === 'complete'
      ? input.content.byteLength
      : declaredTotal !== undefined && declaredTotal > input.content.byteLength
        ? declaredTotal
        : undefined

  return deepFreeze({
    domain: EVIDENCE_SOURCE_HASH_DOMAIN,
    algorithm: 'sha256',
    digest: sha256Bytes(input.content),
    basis: 'source-bytes',
    coverage: input.completeness === 'complete' ? 'complete' : 'partial',
    hashedBytes: input.content.byteLength,
    ...(knownTotalBytes !== undefined ? { knownTotalBytes } : {})
  })
}

function selectedOobMetadata(
  metadata: OobCaptureMetadata,
  decision: EvidenceCaptureDecision
): OobCaptureMetadata {
  const bounded = snapshotBoundedPlainData(
    metadata,
    METADATA_SNAPSHOT_LIMITS,
    'invalid-source-input'
  )
  const parsed = OobCaptureMetadataSchema.safeParse(bounded)
  if (!parsed.success) throw new EvidenceCapturePolicyError('invalid-source-input')
  const source = parsed.data as Readonly<Record<string, unknown>>
  const output: Record<string, unknown> = Object.create(null)
  for (const field of [...decision.oobMetadataFields].sort(compareText)) {
    const value = source[field]
    if (value === undefined) continue
    output[field] =
      field === 'receivedAt' && typeof value === 'string'
        ? new Date(value).toISOString()
        : typeof value === 'string'
        ? redactInventoryText(value, 500)
        : value
  }
  const selected = OobCaptureMetadataSchema.safeParse(output)
  if (!selected.success) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  return deepFreeze(selected.data)
}

function oobMetadataHash(
  metadata: OobCaptureMetadata
): EvidenceSourceHash {
  const encoded = canonicalJson(metadata)
  return deepFreeze({
    domain: EVIDENCE_SOURCE_HASH_DOMAIN,
    algorithm: 'sha256',
    digest: sha256Text(encoded),
    basis: 'selected-oob-metadata',
    coverage: 'partial',
    hashedBytes: Buffer.byteLength(encoded, 'utf8')
  })
}

function decodeUtf8(content: Uint8Array): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(content)
  } catch {
    return undefined
  }
}

function decodeJsonPointer(pointer: string): readonly string[] {
  return pointer
    .slice(1)
    .split('/')
    .map((token) => token.replace(/~1/gu, '/').replace(/~0/gu, '~'))
}

function resolveJsonPointer(
  root: unknown,
  pointer: string
): Readonly<{ found: boolean; value?: unknown; sensitive: boolean }> {
  let current = root
  let sensitive = false
  for (const token of decodeJsonPointer(pointer)) {
    sensitive ||= SENSITIVE_JSON_FIELD_PATTERN.test(token)
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9]\d*)$/u.test(token)) return { found: false, sensitive }
      const index = Number(token)
      if (!Number.isSafeInteger(index) || index >= current.length) {
        return { found: false, sensitive }
      }
      current = current[index]
      continue
    }
    if (
      typeof current !== 'object' ||
      current === null ||
      !Object.prototype.hasOwnProperty.call(current, token)
    ) {
      return { found: false, sensitive }
    }
    current = (current as Record<string, unknown>)[token]
  }
  return { found: true, value: current, sensitive }
}

function safeJsonSelectionValue(
  value: unknown,
  sensitive: boolean
): unknown {
  if (sensitive) return INVENTORY_REDACTION_MARKER
  if (typeof value === 'string') return INVENTORY_REDACTION_MARKER
  if (value === null || typeof value === 'boolean') {
    return value
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : INVENTORY_REDACTION_MARKER
  }
  return INVENTORY_REDACTION_MARKER
}

function artifactDraft(input: Readonly<{
  type: Exclude<
    EvidenceArtifactDraft['type'],
    'evidence-capture-protected-original'
  >
  payload: unknown
  context: EvidenceCaptureContext
  decision: EvidenceCaptureDecision
  sourceHash: EvidenceSourceHash
}>): EvidenceArtifactDraft {
  const parsed = EvidenceArtifactDraftSchema.safeParse({
    type: input.type,
    mimeType: 'application/json',
    payload: input.payload,
    role: input.context.role,
    source: input.context.source,
    captureDecisionId: input.decision.id,
    capturePolicyId: input.decision.capturePolicyId,
    capturePolicyVersion: input.decision.capturePolicyVersion,
    redactionState: 'redacted',
    sourceHash: input.sourceHash
  })
  if (!parsed.success) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  return deepFreeze(parsed.data)
}

function protectedOriginalArtifactDraft(input: Readonly<{
  context: EvidenceCaptureContext
  decision: EvidenceCaptureDecision
  sourceHash: EvidenceSourceHash
  originalMimeType: string
  plaintextSize: number
}>): EvidenceArtifactDraft {
  const protectionPlan = input.decision.protectedOriginalPlan
  if (protectionPlan === undefined) {
    throw new EvidenceCapturePolicyError('invalid-decision')
  }
  const retentionUntil = new Date(
    Date.parse(input.context.occurredAt) +
      protectionPlan.retentionSeconds * 1_000
  ).toISOString()
  const parsed = EvidenceArtifactDraftSchema.safeParse({
    type: 'evidence-capture-protected-original',
    mimeType: 'application/vnd.agentgo.protected-evidence',
    source: input.context.source,
    role: input.context.role,
    captureDecisionId: input.decision.id,
    capturePolicyId: input.decision.capturePolicyId,
    capturePolicyVersion: input.decision.capturePolicyVersion,
    redactionState: 'original',
    scanId: input.context.scanId,
    policyDecisionId: input.context.policyDecisionId,
    techniqueId: input.context.techniqueId,
    techniqueVersion: input.context.techniqueVersion,
    stepId: input.context.stepId,
    sourceHash: input.sourceHash,
    payload: {
      schemaVersion: PROTECTED_EVIDENCE_ARTIFACT_SCHEMA_VERSION,
      kind: 'protected-original-persistence-plan',
      originalMimeType: input.originalMimeType,
      plaintextSize: input.plaintextSize,
      retentionUntil,
      protectionPlan,
      sourceHash: input.sourceHash,
      captureContext: input.context,
      captureDecision: input.decision
    }
  })
  if (!parsed.success) {
    throw new EvidenceCapturePolicyError('invalid-source-input')
  }
  return deepFreeze(parsed.data)
}

function result(input: Readonly<{
  state: EvidenceCaptureResult['state']
  reason: EvidenceCaptureReason
  context: EvidenceCaptureContext
  decision: EvidenceCaptureDecision
  sourceHash: EvidenceSourceHash
  tokenCommitment?: OobTokenCommitment
  artifact?: EvidenceArtifactDraft
}>): EvidenceCaptureResult {
  const parsed = EvidenceCaptureResultSchema.safeParse({
    state: input.state,
    reason: input.reason,
    role: input.context.role,
    source: input.context.source,
    captureDecisionId: input.decision.id,
    capturePolicyId: input.decision.capturePolicyId,
    capturePolicyVersion: input.decision.capturePolicyVersion,
    sourceHash: input.sourceHash,
    ...(input.tokenCommitment
      ? { tokenCommitment: input.tokenCommitment }
      : {}),
    artifacts: input.artifact ? [input.artifact] : []
  })
  if (!parsed.success) throw new EvidenceCapturePolicyError('invalid-source-input')
  return deepFreeze(parsed.data)
}

function hashOnlyResult(input: Readonly<{
  reason: EvidenceHashOnlyReason
  context: EvidenceCaptureContext
  decision: EvidenceCaptureDecision
  sourceHash: EvidenceSourceHash
  tokenCommitment?: OobTokenCommitment
}>): EvidenceCaptureResult {
  const payload = deepFreeze({
    schemaVersion: 'evidence-capture-artifact.v1',
    kind: 'hash-only',
    reason: input.reason,
    sourceHash: input.sourceHash,
    ...(input.tokenCommitment
      ? { tokenCommitment: input.tokenCommitment }
      : {})
  })
  return result({
    state: 'hash-only',
    reason: input.reason,
    context: input.context,
    decision: input.decision,
    sourceHash: input.sourceHash,
    ...(input.tokenCommitment
      ? { tokenCommitment: input.tokenCommitment }
      : {}),
    artifact: artifactDraft({
      type: 'evidence-capture-hash-only',
      payload,
      context: input.context,
      decision: input.decision,
      sourceHash: input.sourceHash
    })
  })
}

function isJsonMediaType(mediaType: string): boolean {
  return mediaType === 'application/json' || mediaType.endsWith('+json')
}

function isXmlMediaType(mediaType: string): boolean {
  return (
    mediaType === 'application/xml' ||
    mediaType === 'text/xml' ||
    mediaType.endsWith('+xml')
  )
}

function updateLengthFramed(
  hmac: Hmac,
  label: string,
  value: Uint8Array
): void {
  const labelBytes = Buffer.from(label, 'utf8')
  const labelLength = Buffer.alloc(4)
  const valueLength = Buffer.alloc(4)
  labelLength.writeUInt32BE(labelBytes.byteLength)
  valueLength.writeUInt32BE(value.byteLength)
  hmac.update(labelLength)
  hmac.update(labelBytes)
  hmac.update(valueLength)
  hmac.update(value)
}

function commitOobToken(input: Readonly<{
  token: string
  decision: EvidenceCaptureDecision
  selectedMetadata: OobCaptureMetadata
  sourceHash: EvidenceSourceHash
  keyProvider: OobCommitmentKeyProvider
}>): OobTokenCommitment {
  const keyRef = input.decision.oobCommitmentKeyRef
  const keyVersion = input.decision.oobCommitmentKeyVersion
  if (keyRef === undefined || keyVersion === undefined) {
    throw new EvidenceCapturePolicyError('invalid-oob-commitment')
  }

  let keyBytes: Uint8Array<ArrayBuffer> | undefined
  let tokenBytes: Buffer | undefined
  try {
    keyBytes = snapshotSecureBytes(
      input.keyProvider.resolveKey({ keyRef, keyVersion }),
      {
        minimumBytes: MIN_OOB_HMAC_KEY_BYTES,
        maximumBytes: MAX_OOB_HMAC_KEY_BYTES
      }
    )
    tokenBytes = Buffer.from(input.token, 'utf8')
    const hmac = createHmac('sha256', keyBytes)
    updateLengthFramed(
      hmac,
      'domain',
      Buffer.from(OOB_TOKEN_COMMITMENT_DOMAIN, 'utf8')
    )
    updateLengthFramed(hmac, 'key-ref', Buffer.from(keyRef, 'utf8'))
    updateLengthFramed(
      hmac,
      'key-version',
      Buffer.from(String(keyVersion), 'utf8')
    )
    updateLengthFramed(
      hmac,
      'capture-decision-id',
      Buffer.from(input.decision.id, 'utf8')
    )
    updateLengthFramed(
      hmac,
      'capture-policy-id',
      Buffer.from(input.decision.capturePolicyId, 'utf8')
    )
    updateLengthFramed(
      hmac,
      'capture-policy-version',
      Buffer.from(input.decision.capturePolicyVersion, 'utf8')
    )
    updateLengthFramed(
      hmac,
      'selected-metadata',
      Buffer.from(canonicalJson(input.selectedMetadata), 'utf8')
    )
    updateLengthFramed(
      hmac,
      'source-hash',
      Buffer.from(canonicalJson(input.sourceHash), 'utf8')
    )
    updateLengthFramed(hmac, 'token', tokenBytes)
    const commitment = OobTokenCommitmentSchema.safeParse({
      domain: OOB_TOKEN_COMMITMENT_DOMAIN,
      algorithm: 'hmac-sha256',
      keyRef,
      keyVersion,
      captureDecisionId: input.decision.id,
      capturePolicyId: input.decision.capturePolicyId,
      capturePolicyVersion: input.decision.capturePolicyVersion,
      selectedMetadata: input.selectedMetadata,
      sourceHash: input.sourceHash,
      digest: hmac.digest('hex')
    })
    if (!commitment.success) {
      throw new EvidenceCapturePolicyError('invalid-oob-commitment')
    }
    return deepFreeze(commitment.data)
  } catch (error) {
    if (error instanceof EvidenceCapturePolicyError) throw error
    throw new EvidenceCapturePolicyError('invalid-oob-commitment')
  } finally {
    if (keyBytes) zeroizeSecureBytes(keyBytes)
    tokenBytes?.fill(0)
  }
}

export class EvidenceCapturePolicy {
  constructor(private readonly oobKeyProvider?: OobCommitmentKeyProvider) {}

  capture(input: EvidenceCaptureInput): EvidenceCaptureResult {
    try {
      const initial = snapshotOwnData(
        input,
        new Set([
          'kind',
          'context',
          'decision',
          'content',
          'completeness',
          'knownTotalBytes',
          'token',
          'metadata'
        ]),
        ['kind', 'context', 'decision']
      )
      if (initial.kind === 'bytes') {
        assertSnapshotShape(
          initial,
          new Set([
            'kind',
            'context',
            'decision',
            'content',
            'completeness',
            'knownTotalBytes'
          ]),
          ['kind', 'context', 'decision', 'content', 'completeness']
        )
        if (
          initial.completeness !== 'complete' &&
          initial.completeness !== 'prefix'
        ) {
          throw new EvidenceCapturePolicyError('invalid-source-input')
        }
        const context = parseContext(initial.context)
        const decision = parseDecision(initial.decision)
        assertDecisionBinding(context, decision)
        if (context.source === 'oob-event') {
          throw new EvidenceCapturePolicyError('invalid-source-input')
        }
        const content = snapshotByteContent(initial.content)
        try {
          return this.captureBytes(
            {
              kind: 'bytes',
              context,
              decision,
              content,
              completeness: initial.completeness,
              ...(Object.prototype.hasOwnProperty.call(
                initial,
                'knownTotalBytes'
              )
                ? { knownTotalBytes: initial.knownTotalBytes as number }
                : {})
            },
            context,
            decision
          )
        } finally {
          zeroizeSecureBytes(content)
        }
      }
      if (initial.kind === 'oob') {
        assertSnapshotShape(
          initial,
          new Set(['kind', 'context', 'decision', 'token', 'metadata']),
          ['kind', 'context', 'decision', 'token', 'metadata']
        )
        const context = parseContext(initial.context)
        const decision = parseDecision(initial.decision)
        assertDecisionBinding(context, decision)
        if (context.source !== 'oob-event') {
          throw new EvidenceCapturePolicyError('invalid-source-input')
        }
        return this.captureOob(
          {
            kind: 'oob',
            context,
            decision,
            token: initial.token as string,
            metadata: initial.metadata as OobCaptureMetadata
          },
          context,
          decision
        )
      }
      throw new EvidenceCapturePolicyError('invalid-source-input')
    } catch (error) {
      if (error instanceof EvidenceCapturePolicyError) throw error
      throw new EvidenceCapturePolicyError('invalid-source-input')
    }
  }

  private captureBytes(
    input: EvidenceByteCaptureInput,
    context: EvidenceCaptureContext,
    decision: EvidenceCaptureDecision
  ): EvidenceCaptureResult {
    const sourceHash = byteSourceHash(input, context)

    if (decision.action === 'discard') {
      return result({
        state: 'discarded',
        reason: 'decision-discard',
        context,
        decision,
        sourceHash
      })
    }
    if (decision.action === 'hash-only') {
      return hashOnlyResult({
        reason: 'decision-hash-only',
        context,
        decision,
        sourceHash
      })
    }
    if (input.completeness !== 'complete') {
      return hashOnlyResult({
        reason: 'partial-source',
        context,
        decision,
        sourceHash
      })
    }
    if (input.content.byteLength > decision.maxSourceBytes) {
      return hashOnlyResult({
        reason: 'oversize-source',
        context,
        decision,
        sourceHash
      })
    }
    if (input.content.byteLength === 0) {
      return hashOnlyResult({
        reason: 'empty-source',
        context,
        decision,
        sourceHash
      })
    }
    if (decision.action === 'protected-original') {
      const descriptor = byteContentDescriptor(context)
      const artifact = protectedOriginalArtifactDraft({
        context,
        decision,
        sourceHash,
        originalMimeType: descriptor.mediaType,
        plaintextSize: input.content.byteLength
      })
      return result({
        state: 'captured',
        reason: 'protected-original-authorized',
        context,
        decision,
        sourceHash,
        artifact
      })
    }
    const descriptor = byteContentDescriptor(context)
    if (descriptor.contentEncoding !== 'identity') {
      return hashOnlyResult({
        reason: 'compressed-source',
        context,
        decision,
        sourceHash
      })
    }
    if (context.source === 'browser-screenshot') {
      return hashOnlyResult({
        reason: 'binary-source',
        context,
        decision,
        sourceHash
      })
    }
    if (isXmlMediaType(descriptor.mediaType)) {
      return hashOnlyResult({
        reason: 'xml-source',
        context,
        decision,
        sourceHash
      })
    }
    if (
      descriptor.charset !== 'utf-8' ||
      (!descriptor.mediaType.startsWith('text/') &&
        !isJsonMediaType(descriptor.mediaType))
    ) {
      return hashOnlyResult({
        reason:
          descriptor.charset === 'non-utf-8' ||
          descriptor.charset === 'unknown'
            ? 'non-utf8-source'
            : 'binary-source',
        context,
        decision,
        sourceHash
      })
    }

    const decoded = decodeUtf8(input.content)
    if (decoded === undefined) {
      return hashOnlyResult({
        reason: 'non-utf8-source',
        context,
        decision,
        sourceHash
      })
    }
    if (isJsonMediaType(descriptor.mediaType)) {
      return this.captureJson(decoded, context, decision, sourceHash)
    }
    return hashOnlyResult({
      reason: 'unstructured-text-source',
      context,
      decision,
      sourceHash
    })
  }

  private captureJson(
    decoded: string,
    context: EvidenceCaptureContext,
    decision: EvidenceCaptureDecision,
    sourceHash: EvidenceSourceHash
  ): EvidenceCaptureResult {
    let parsed: unknown
    try {
      parsed = JSON.parse(decoded) as unknown
    } catch {
      return hashOnlyResult({
        reason: 'json-parse-failed',
        context,
        decision,
        sourceHash
      })
    }
    if (decision.jsonPointers.length === 0) {
      return hashOnlyResult({
        reason: 'json-selection-failed',
        context,
        decision,
        sourceHash
      })
    }

    const selections: Array<Readonly<{ pointer: string; value: unknown }>> = []
    for (const pointer of [...decision.jsonPointers].sort(compareText)) {
      const selected = resolveJsonPointer(parsed, pointer)
      if (!selected.found) {
        return hashOnlyResult({
          reason: 'json-selection-failed',
          context,
          decision,
          sourceHash
        })
      }
      selections.push(
        deepFreeze({
          pointer,
          value: safeJsonSelectionValue(
            selected.value,
            selected.sensitive
          )
        })
      )
    }

    const encodedSelections = canonicalJson(selections)
    if (Buffer.byteLength(encodedSelections, 'utf8') > decision.maxExcerptBytes) {
      return hashOnlyResult({
        reason: 'json-selection-failed',
        context,
        decision,
        sourceHash
      })
    }
    const payload = deepFreeze({
      schemaVersion: 'evidence-capture-artifact.v1',
      kind: 'allowlisted-json-selection',
      selections,
      sourceHash
    })
    const artifact = artifactDraft({
      type: 'evidence-capture-json-selection',
      payload,
      context,
      decision,
      sourceHash
    })
    return result({
      state: 'captured',
      reason: 'allowlisted-json-selection',
      context,
      decision,
      sourceHash,
      artifact
    })
  }

  private captureOob(
    input: EvidenceOobCaptureInput,
    context: EvidenceCaptureContext,
    decision: EvidenceCaptureDecision
  ): EvidenceCaptureResult {
    if (
      typeof input.token !== 'string' ||
      input.token.length === 0 ||
      !isWellFormedUnicode(input.token) ||
      input.token !== input.token.normalize('NFC') ||
      Buffer.byteLength(input.token, 'utf8') > MAX_OOB_TOKEN_BYTES
    ) {
      throw new EvidenceCapturePolicyError('invalid-source-input')
    }
    const metadata = selectedOobMetadata(input.metadata, decision)
    const sourceHash = oobMetadataHash(metadata)

    if (decision.action === 'discard') {
      return result({
        state: 'discarded',
        reason: 'decision-discard',
        context,
        decision,
        sourceHash
      })
    }
    if (!this.oobKeyProvider) {
      return result({
        state: 'unsupported',
        reason: 'oob-commitment-unavailable',
        context,
        decision,
        sourceHash
      })
    }

    if (decision.oobCommitmentKeyRef === input.token) {
      throw new EvidenceCapturePolicyError('invalid-oob-commitment')
    }
    const tokenCommitment = commitOobToken({
      token: input.token,
      decision,
      selectedMetadata: metadata,
      sourceHash,
      keyProvider: this.oobKeyProvider
    })

    if (decision.action === 'hash-only') {
      return hashOnlyResult({
        reason: 'decision-hash-only',
        context,
        decision,
        sourceHash,
        tokenCommitment
      })
    }

    const payload = deepFreeze({
      schemaVersion: 'evidence-capture-artifact.v1',
      kind: 'allowlisted-oob-metadata',
      metadata,
      tokenCommitment,
      sourceHash
    })
    const artifact = artifactDraft({
      type: 'evidence-capture-oob-metadata',
      payload,
      context,
      decision,
      sourceHash
    })
    return result({
      state: 'captured',
      reason: 'allowlisted-oob-metadata',
      context,
      decision,
      sourceHash,
      tokenCommitment,
      artifact
    })
  }
}
