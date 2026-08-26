import { randomUUID } from 'node:crypto'
import {
  DefinitionIdSchema,
  EvidenceCaptureDecisionSchema,
  ExecutionAdapterKindSchema,
  ExecutionCapabilityIdsSchema,
  ExecutionCaptureDecisionSetSchema,
  ExecutionCredentialRefSchema,
  ExecutionGrantBudgetSchema,
  ExecutionPlanVersionSchema,
  ExecutionPurposeSchema,
  ExecutionRetryClassSchema,
  IdentityRefSchema,
  ResolvedIntentHashSchema,
  ScanModuleSnapshotRecordSchema,
  SessionGenerationRefSchema,
  SystemIssuedOpaqueIdSchema,
  TemplateIntentHashSchema,
  TestObjectRefSchema,
  VulnerabilityFamilyIdSchema,
  WireRequestHmacSchema,
  type CapabilityId,
  type EvidenceCaptureDecision,
  type EvidenceCaptureExecutionState,
  type ExecutionCaptureDecisionSet,
  type ExecutionCredentialRef,
  type ExecutionAdapterKind,
  type ExecutionGrant,
  type ExecutionLease,
  type ExecutionPurpose,
  type ExecutionRetryClass,
  type IdentityRef,
  type ResolvedIntentHash,
  type ScanModuleSnapshotRecord,
  type SessionGenerationRef,
  type TemplateIntentHash,
  type TestObjectRef,
  type VulnerabilityFamilyId,
  type WireRequestHmac
} from '@agentgo/contracts'
import { canonicalJson, compareText, sha256Text } from '@agentgo/domain'
import {
  executionGrantIntegrityBindingForGrant,
  verifyExecutionGrantIntegrity,
  type AgentGoRepository,
  type ExecutionGrantIntegrityKey,
  type IssueExecutionGrantInput
} from '@agentgo/db'
import { evaluateProbe } from '@agentgo/security-policy'
import type { EphemeralRequestHashKeyProvider } from './request-hash-key-provider'
import {
  CompiledWireRequest,
  createWireRequestAuthorizationContext,
  parseWireRequestAuthorizationContext,
  verifyWireRequestHmac,
  type CompiledProbeRequest,
  type MaterializedWireRequest,
  type WireRequestAuthorizationContextInput
} from './request-compiler'
import {
  snapshotSecureBytes,
  zeroizeSecureBytes
} from './secure-byte-snapshot'

type ScanRow = NonNullable<
  Awaited<ReturnType<AgentGoRepository['getScanRow']>>
>
type ExecutionDecisionContext = NonNullable<
  Awaited<ReturnType<AgentGoRepository['getExecutionDecision']>>
>
type ExecutionGrantDraft = IssueExecutionGrantInput['grant']
type SupportedExecutionAdapter = Extract<
  ExecutionAdapterKind,
  'http' | 'browser-offline'
>

export interface ExecutionAuthorityLimits {
  readonly timeoutMs: number
  readonly maxResponseBytes: number
  readonly maxRedirects: number
}

export interface IssueRootExecutionInput {
  readonly scanId: string
  readonly familyId: VulnerabilityFamilyId
  readonly policyDecisionId: string
  readonly stepId: string
  readonly compiled: CompiledProbeRequest
  readonly capabilityIds: readonly CapabilityId[]
  readonly ownerRef: string
  readonly identityRef?: IdentityRef
  readonly credentialRef: ExecutionCredentialRef | null
  readonly sessionRef?: SessionGenerationRef
  readonly testObjectRef?: TestObjectRef
  readonly purpose: ExecutionPurpose
  readonly adapterKind: SupportedExecutionAdapter
  readonly retryClass: ExecutionRetryClass
  readonly limits: ExecutionAuthorityLimits
  readonly grantValidUntil: string
  readonly leaseExpiresAt: string
}

export interface IssueRedirectChildExecutionInput {
  readonly parentGrantId: string
  readonly parentLeaseId: string
  readonly policyDecisionId: string
  readonly stepId: string
  readonly compiled: CompiledProbeRequest
  readonly credentialRef: ExecutionCredentialRef | null
  readonly limits: ExecutionAuthorityLimits
  readonly grantValidUntil: string
  readonly leaseExpiresAt: string
}

type NormalEvidenceCaptureExecutionState = Exclude<
  EvidenceCaptureExecutionState,
  'interrupted'
>
type EvidenceCaptureDecisionsByState = Readonly<
  Record<NormalEvidenceCaptureExecutionState, EvidenceCaptureDecision>
>
type InterruptionCaptureDecision = Readonly<{
  interrupted: EvidenceCaptureDecision
}>

export type ExecutionEvidenceCaptureDecisionSet =
  | Readonly<{
      'execution-interruption-summary': InterruptionCaptureDecision
      'http-request-summary': EvidenceCaptureDecisionsByState
      'http-response-summary': EvidenceCaptureDecisionsByState
    }>
  | Readonly<{
      'execution-interruption-summary': InterruptionCaptureDecision
      'browser-request-summary': EvidenceCaptureDecisionsByState
      'browser-result-summary': EvidenceCaptureDecisionsByState
    }>

export interface IssuedExecutionAuthority {
  readonly grant: ExecutionGrant
  readonly lease: ExecutionLease
  readonly evidenceCaptureDecisions: ExecutionEvidenceCaptureDecisionSet
}

interface PreparedCompilation {
  readonly wire: MaterializedWireRequest
  readonly requestBytes: number
  readonly templateIntentHash: TemplateIntentHash
  readonly resolvedIntentHash: ResolvedIntentHash
  readonly wireRequestHmac: WireRequestHmac
  readonly enabledCapabilityIds: readonly CapabilityId[]
}

interface LoadedIssuanceContext {
  readonly scan: ScanRow
  readonly decision: ExecutionDecisionContext
  readonly snapshots: readonly ScanModuleSnapshotRecord[]
}

interface PreparedRootRefs {
  readonly ownerRef: string
  readonly identityRef?: IdentityRef
  readonly credentialRef: ExecutionCredentialRef | null
  readonly sessionRef?: SessionGenerationRef
  readonly testObjectRef?: TestObjectRef
}

function hasExactDataKeys(
  value: object,
  expected: readonly string[]
): boolean {
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    return false
  }
  const keys = Reflect.ownKeys(value)
  if (keys.some((key) => typeof key !== 'string')) {
    return false
  }
  const stringKeys = keys as string[]
  if (
    canonicalJson([...stringKeys].sort(compareText)) !==
    canonicalJson(expected)
  ) {
    return false
  }
  return stringKeys.every((key) => {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
    return Boolean(descriptor?.enumerable && descriptor && 'value' in descriptor)
  })
}

function snapshotCompiledWire(
  compiled: CompiledProbeRequest
): MaterializedWireRequest {
  let raw: MaterializedWireRequest
  if (
    !compiled ||
    typeof compiled !== 'object' ||
    Array.isArray(compiled) ||
    (Object.getPrototypeOf(compiled) !== Object.prototype &&
      Object.getPrototypeOf(compiled) !== null)
  ) {
    throw new Error('Compiled execution container is invalid.')
  }
  const requestDescriptor = Reflect.getOwnPropertyDescriptor(
    compiled,
    'request'
  )
  if (
    !requestDescriptor ||
    !requestDescriptor.enumerable ||
    !Object.prototype.hasOwnProperty.call(requestDescriptor, 'value') ||
    !(requestDescriptor.value instanceof CompiledWireRequest)
  ) {
    throw new Error('Compiled execution request is not an exact compiler value.')
  }
  compiled = Object.freeze({
    request: requestDescriptor.value
  }) as CompiledProbeRequest
  try {
    raw = compiled.request.materialize()
  } catch {
    throw new Error('Compiled execution wire is unavailable.')
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Compiled execution wire is invalid.')
  }
  const bodyPresent = Object.prototype.hasOwnProperty.call(raw, 'bodyBytes')
  if (
    !hasExactDataKeys(
      raw,
      bodyPresent
        ? ['bodyBytes', 'headers', 'method', 'url']
        : ['headers', 'method', 'url']
    ) ||
    typeof raw.method !== 'string' ||
    typeof raw.url !== 'string' ||
    !Array.isArray(raw.headers)
  ) {
    throw new Error('Compiled execution wire is invalid.')
  }
  let previousName: string | undefined
  const headers = raw.headers.map((header) => {
    if (
      !header ||
      typeof header !== 'object' ||
      Array.isArray(header) ||
      !hasExactDataKeys(header, ['name', 'value']) ||
      typeof header.name !== 'string' ||
      typeof header.value !== 'string' ||
      (previousName !== undefined && previousName > header.name)
    ) {
      throw new Error('Compiled execution headers are not canonical.')
    }
    previousName = header.name
    return Object.freeze({ name: header.name, value: header.value })
  })
  let bodyBytes: readonly number[] | undefined
  if (bodyPresent) {
    if (
      !Array.isArray(raw.bodyBytes) ||
      raw.bodyBytes.some(
        (byte) => !Number.isInteger(byte) || byte < 0 || byte > 255
      )
    ) {
      throw new Error('Compiled execution body is invalid.')
    }
    bodyBytes = Object.freeze([...raw.bodyBytes])
  }
  return Object.freeze({
    method: raw.method,
    url: raw.url,
    headers: Object.freeze(headers),
    ...(bodyBytes !== undefined ? { bodyBytes } : {})
  })
}

function exactWireByteLength(wire: MaterializedWireRequest): number {
  return (
    Buffer.byteLength(wire.method, 'utf8') +
    Buffer.byteLength(wire.url, 'utf8') +
    wire.headers.reduce(
      (total, header) =>
        total +
        Buffer.byteLength(header.name, 'ascii') +
        Buffer.byteLength(header.value, 'ascii') +
        4,
      0
    ) +
    (wire.bodyBytes?.length ?? 0)
  )
}

function snapshotCompiledContainer(
  compiled: CompiledProbeRequest
): CompiledProbeRequest {
  if (
    !compiled ||
    typeof compiled !== 'object' ||
    Array.isArray(compiled) ||
    !hasExactDataKeys(compiled, [
      'authorizationContext',
      'enabledCapabilityIds',
      'request',
      'resolvedIntentHash',
      'templateIntentHash',
      'wireRequestHmac'
    ])
  ) {
    throw new Error('Compiled execution container is not an exact data object.')
  }
  const dataValue = (key: string): unknown => {
    const descriptor = Reflect.getOwnPropertyDescriptor(compiled, key)
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    ) {
      throw new Error('Compiled execution container changed during capture.')
    }
    return descriptor.value
  }
  const request = dataValue('request')
  if (!(request instanceof CompiledWireRequest)) {
    throw new Error('Compiled execution request is not an exact compiler value.')
  }
  return Object.freeze({
    request,
    templateIntentHash: dataValue('templateIntentHash'),
    resolvedIntentHash: dataValue('resolvedIntentHash'),
    authorizationContext: dataValue('authorizationContext'),
    wireRequestHmac: dataValue('wireRequestHmac'),
    enabledCapabilityIds: dataValue('enabledCapabilityIds')
  }) as CompiledProbeRequest
}

function parseCanonicalIso(value: string, field: string): number {
  const timestamp = Date.parse(value)
  if (
    !Number.isFinite(timestamp) ||
    new Date(timestamp).toISOString() !== value
  ) {
    throw new Error(field + ' must be a canonical ISO timestamp.')
  }
  return timestamp
}

function executionOrigin(value: string): string {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('Execution redirect origin is invalid.')
  }
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    parsed.username !== '' ||
    parsed.password !== ''
  ) {
    throw new Error('Execution redirect origin is invalid.')
  }
  return parsed.origin
}

function parseClock(now: number): number {
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new Error('Execution authority clock is invalid.')
  }
  return now
}

function prepareBudget(
  limits: ExecutionAuthorityLimits,
  requestBytes: number
): ExecutionGrantDraft['budget'] {
  return ExecutionGrantBudgetSchema.parse({
    requestUnits: 1,
    requestBytes,
    timeoutMs: limits.timeoutMs,
    maxResponseBytes: limits.maxResponseBytes,
    maxRedirects: limits.maxRedirects
  })
}

function prepareCompilation(
  compiled: CompiledProbeRequest,
  keyProvider: EphemeralRequestHashKeyProvider,
  trustedAuthorization: Omit<
    WireRequestAuthorizationContextInput,
    'templateIntentHash'
  >
): PreparedCompilation {
  compiled = snapshotCompiledContainer(compiled)
  const wire = snapshotCompiledWire(compiled)
  const templateIntentHash = TemplateIntentHashSchema.parse(
    compiled.templateIntentHash
  )
  const resolvedIntentHash = ResolvedIntentHashSchema.parse(
    compiled.resolvedIntentHash
  )
  const wireRequestHmac = WireRequestHmacSchema.parse(
    compiled.wireRequestHmac
  )
  const enabledCapabilityIds = ExecutionCapabilityIdsSchema.parse(
    compiled.enabledCapabilityIds
  )
  const authorizationContext = createWireRequestAuthorizationContext({
    templateIntentHash,
    ...trustedAuthorization
  })
  let exposedAuthorizationContext
  try {
    exposedAuthorizationContext = parseWireRequestAuthorizationContext(
      compiled.authorizationContext
    )
  } catch {
    throw new Error('Compiled execution authorization context is invalid.')
  }
  if (
    canonicalJson(exposedAuthorizationContext) !==
      canonicalJson(authorizationContext) ||
    canonicalJson(enabledCapabilityIds) !==
      canonicalJson(authorizationContext.enabledCapabilityIds)
  ) {
    throw new Error('Compiled execution authorization context differs from trusted issuance input.')
  }
  if (
    resolvedIntentHash.commitmentKeyRef !== keyProvider.reference.keyRef ||
    resolvedIntentHash.commitmentKeyVersion !==
      keyProvider.reference.keyVersion ||
    wireRequestHmac.keyRef !== keyProvider.reference.keyRef ||
    wireRequestHmac.keyVersion !== keyProvider.reference.keyVersion ||
    !verifyWireRequestHmac(
      {
        hashKey: keyProvider.reference,
        resolvedIntentHash,
        authorizationContext,
        request: wire
      },
      wireRequestHmac,
      keyProvider
    )
  ) {
    throw new Error('Compiled execution proof verification failed.')
  }
  return Object.freeze({
    wire,
    requestBytes: exactWireByteLength(wire),
    templateIntentHash,
    resolvedIntentHash,
    wireRequestHmac,
    enabledCapabilityIds
  })
}

function prepareRootRefs(input: IssueRootExecutionInput): PreparedRootRefs {
  return Object.freeze({
    ownerRef: SystemIssuedOpaqueIdSchema.parse(input.ownerRef),
    credentialRef: ExecutionCredentialRefSchema.nullable().parse(input.credentialRef),
    ...(input.identityRef
      ? { identityRef: IdentityRefSchema.parse(input.identityRef) }
      : {}),
    ...(input.sessionRef
      ? { sessionRef: SessionGenerationRefSchema.parse(input.sessionRef) }
      : {}),
    ...(input.testObjectRef
      ? { testObjectRef: TestObjectRefSchema.parse(input.testObjectRef) }
      : {})
  })
}

function derivePlan(scan: ScanRow): {
  readonly planId: string
  readonly planVersion: string
  readonly planHash: string
} {
  const planId = SystemIssuedOpaqueIdSchema.parse(scan.id)
  const planVersion = ExecutionPlanVersionSchema.parse(scan.planJson.version)
  const planHash = sha256Text(canonicalJson(scan.planJson))
  return Object.freeze({ planId, planVersion, planHash })
}

const EXECUTION_SUMMARY_CAPTURE_POLICY_ID =
  'evidence-summary-v1' as const
const EXECUTION_SUMMARY_CAPTURE_POLICY_VERSION = '1.0.0' as const
const EXECUTION_SUMMARY_MAX_SOURCE_BYTES = 65_536
const EXECUTION_SUMMARY_MAX_EXCERPT_BYTES = 32

type ExecutionSummarySource =
  | 'http-request-summary'
  | 'http-response-summary'
  | 'browser-request-summary'
  | 'browser-result-summary'
  | 'execution-interruption-summary'

function createEvidenceCaptureDecisionSet(
  grant: ExecutionGrantDraft
): ExecutionEvidenceCaptureDecisionSet {
  const issuedIds = new Set<string>()
  const issueId = (): string => {
    const id = SystemIssuedOpaqueIdSchema.parse(randomUUID())
    if (issuedIds.has(id)) {
      throw new Error('Evidence capture decision IDs are not unique.')
    }
    issuedIds.add(id)
    return id
  }
  const decision = (
    source: ExecutionSummarySource,
    role: 'request-summary' | 'response-summary' | 'result-summary' | 'interruption-summary',
    executionState: EvidenceCaptureExecutionState
  ): EvidenceCaptureDecision =>
    EvidenceCaptureDecisionSchema.parse({
      id: issueId(),
      scanId: grant.scanId,
      policyDecisionId: grant.policyDecisionId,
      capturePolicyId: EXECUTION_SUMMARY_CAPTURE_POLICY_ID,
      capturePolicyVersion: EXECUTION_SUMMARY_CAPTURE_POLICY_VERSION,
      techniqueId: grant.techniqueId,
      techniqueVersion: grant.techniqueVersion,
      stepId: grant.stepId,
      executionState,
      source,
      role,
      action: 'hash-only',
      validFrom: grant.validFrom,
      validUntil: grant.validUntil,
      maxSourceBytes: EXECUTION_SUMMARY_MAX_SOURCE_BYTES,
      maxExcerptBytes: EXECUTION_SUMMARY_MAX_EXCERPT_BYTES,
      jsonPointers: [],
      oobMetadataFields: []
    })
  const decisionsByState = (
    source: ExecutionSummarySource,
    role: 'request-summary' | 'response-summary' | 'result-summary'
  ): EvidenceCaptureDecisionsByState =>
    Object.freeze({
      succeeded: decision(source, role, 'succeeded'),
      failed: decision(source, role, 'failed'),
      cancelled: decision(source, role, 'cancelled'),
      'timed-out': decision(source, role, 'timed-out')
    })
  const interruptionDecision = Object.freeze({
    interrupted: decision(
      'execution-interruption-summary',
      'interruption-summary',
      'interrupted'
    )
  })


  if (grant.adapterKind === 'http') {
    return Object.freeze({
      'execution-interruption-summary': interruptionDecision,
      'http-request-summary': decisionsByState(
        'http-request-summary',
        'request-summary'
      ),
      'http-response-summary': decisionsByState(
        'http-response-summary',
        'response-summary'
      )
    })
  }
  if (grant.adapterKind === 'browser-offline') {
    return Object.freeze({
      'execution-interruption-summary': interruptionDecision,
      'browser-request-summary': decisionsByState(
        'browser-request-summary',
        'request-summary'
      ),
      'browser-result-summary': decisionsByState(
        'browser-result-summary',
        'result-summary'
      )
    })
  }
  throw new Error('Evidence capture decisions require a supported adapter.')

}
function toExecutionCaptureDecisionSet(
  input: ExecutionEvidenceCaptureDecisionSet
): ExecutionCaptureDecisionSet {
  const decisions = Object.values(input)
    .flatMap((decisionsByState) => Object.values(decisionsByState))
    .sort(
      (left, right) =>
        compareText(left.source, right.source) ||
        compareText(left.executionState, right.executionState)
    )
  return ExecutionCaptureDecisionSetSchema.parse({
    schemaVersion: 'execution-capture-decision-set.v1',
    decisions
  })
}

function assertAdapterCapability(
  adapterKind: SupportedExecutionAdapter,
  capabilityIds: readonly CapabilityId[]
): void {
  const requiredCapability =
    adapterKind === 'http'
      ? 'http.reviewed-read'
      : 'browser.offline-replay'
  if (!capabilityIds.includes(requiredCapability)) {
    throw new Error(
      'Execution adapter is missing its mandatory capability binding.'
    )
  }
}

function assertModuleMatchesGrant(
  snapshot: ScanModuleSnapshotRecord,
  grant: ExecutionGrant
): void {
  if (
    snapshot.id !== grant.moduleSnapshotId ||
    snapshot.scanId !== grant.scanId ||
    snapshot.snapshotHash !== grant.moduleSnapshotHash ||
    snapshot.moduleId !== grant.moduleId ||
    snapshot.moduleVersion !== grant.moduleVersion ||
    snapshot.techniqueId !== grant.techniqueId ||
    snapshot.techniqueVersion !== grant.techniqueVersion
  ) {
    throw new Error('Parent execution module snapshot is no longer exact.')
  }
  const available = new Set(
    snapshot.capabilityDescriptors.map((descriptor) => descriptor.id)
  )
  if (grant.capabilityIds.some((capabilityId) => !available.has(capabilityId))) {
    throw new Error('Parent execution capabilities left the sealed snapshot.')
  }
}

export class ExecutionAuthority {
  readonly #repository: AgentGoRepository
  readonly #keyProvider: EphemeralRequestHashKeyProvider
  readonly #clock: () => number

  constructor(
    repository: AgentGoRepository,
    keyProvider: EphemeralRequestHashKeyProvider,
    clock: () => number = Date.now
  ) {
    this.#repository = repository
    this.#keyProvider = keyProvider
    this.#clock = clock
  }

  async issue(
    input: IssueRootExecutionInput
  ): Promise<IssuedExecutionAuthority> {
    const scanId = SystemIssuedOpaqueIdSchema.parse(input.scanId)
    const familyId = VulnerabilityFamilyIdSchema.parse(input.familyId)
    const policyDecisionId = SystemIssuedOpaqueIdSchema.parse(
      input.policyDecisionId
    )
    const stepId = DefinitionIdSchema.parse(input.stepId)
    const capabilityIds = ExecutionCapabilityIdsSchema.parse(
      [...input.capabilityIds].sort(compareText)
    )
    const purpose = ExecutionPurposeSchema.parse(input.purpose)
    const adapterKind = ExecutionAdapterKindSchema.parse(input.adapterKind)
    if (adapterKind !== 'http' && adapterKind !== 'browser-offline') {
      throw new Error('Execution adapter is not supported by execution authority.')
    }
    assertAdapterCapability(adapterKind, capabilityIds)
    const retryClass = ExecutionRetryClassSchema.parse(input.retryClass)
    if (retryClass === 'deterministic-readonly' && purpose !== 'read') {
      throw new Error('Deterministic execution retries require read purpose.')
    }
    const refs = prepareRootRefs(input)
    const grantValidUntil = parseCanonicalIso(
      input.grantValidUntil,
      'Grant validUntil'
    )
    const leaseExpiresAt = parseCanonicalIso(
      input.leaseExpiresAt,
      'Lease expiresAt'
    )
    const now = parseClock(this.#clock())
    if (
      grantValidUntil <= now ||
      leaseExpiresAt <= now ||
      leaseExpiresAt > grantValidUntil
    ) {
      throw new Error('Execution lease validity must be contained by its grant.')
    }

    const loaded = await this.#loadContext(scanId, policyDecisionId)
    const compilation = prepareCompilation(
      input.compiled,
      this.#keyProvider,
      {
        enabledCapabilityIds: capabilityIds,
        ownerRef: loaded.decision.targetId,
        scopeSnapshotId: loaded.decision.scope.id,
        ...(refs.identityRef ? { identityRef: refs.identityRef } : {}),
        ...(refs.credentialRef
          ? { credentialRef: refs.credentialRef }
          : {}),
        ...(refs.sessionRef ? { sessionRef: refs.sessionRef } : {}),
        ...(refs.testObjectRef
          ? { testObjectRef: refs.testObjectRef }
          : {}),
        executionBinding: {
          stepId,
          purpose,
          adapterKind
        }
      }
    )
    const budget = prepareBudget(input.limits, compilation.requestBytes)
    this.#validateCommonContext({
      loaded,
      compilation,
      adapterKind,
      budget,
      grantValidUntil,
      now
    })
    if (!loaded.scan.configJson.families.includes(familyId)) {
      throw new Error('Execution family is outside the frozen scan configuration.')
    }
    const moduleSnapshot = this.#selectModuleSnapshot(
      loaded.snapshots,
      scanId,
      familyId,
      capabilityIds
    )
    await this.#validateOpaqueRefs(loaded, refs)
    const plan = derivePlan(loaded.scan)
    const grant: ExecutionGrantDraft = {
      scanId,
      scopeSnapshotId: loaded.decision.scope.id,
      scopeSnapshotHash: loaded.decision.scope.snapshotHash,
      moduleSnapshotId: moduleSnapshot.id,
      moduleSnapshotHash: moduleSnapshot.snapshotHash,
      moduleId: moduleSnapshot.moduleId,
      moduleVersion: moduleSnapshot.moduleVersion,
      techniqueId: moduleSnapshot.techniqueId,
      techniqueVersion: moduleSnapshot.techniqueVersion,
      ...plan,
      stepId,
      templateIntentHash: compilation.templateIntentHash,
      resolvedIntentHash: compilation.resolvedIntentHash,
      wireRequestHmac: compilation.wireRequestHmac,
      capabilityIds,
      ownerRef: refs.ownerRef,
      ...(refs.identityRef ? { identityRef: refs.identityRef } : {}),
      credentialRef: refs.credentialRef,
      ...(refs.sessionRef ? { sessionRef: refs.sessionRef } : {}),
      ...(refs.testObjectRef ? { testObjectRef: refs.testObjectRef } : {}),
      budget,
      purpose,
      adapterKind,
      retryClass,
      policyDecisionId,
      redirectHop: 0,
      validFrom: new Date(now).toISOString(),
      validUntil: input.grantValidUntil
    }
    const evidenceCaptureDecisions = createEvidenceCaptureDecisionSet(grant)
    return this.#persistGrant({
      grant,
      leaseExpiresAt: input.leaseExpiresAt,
      evidenceCaptureDecisions
    })
  }

  async issueRedirectChild(
    input: IssueRedirectChildExecutionInput
  ): Promise<IssuedExecutionAuthority> {
    const parentGrantId = SystemIssuedOpaqueIdSchema.parse(input.parentGrantId)
    const parentLeaseId = SystemIssuedOpaqueIdSchema.parse(input.parentLeaseId)
    const policyDecisionId = SystemIssuedOpaqueIdSchema.parse(
      input.policyDecisionId
    )
    const credentialRef = ExecutionCredentialRefSchema.nullable().parse(
      input.credentialRef
    )
    const stepId = DefinitionIdSchema.parse(input.stepId)
    const grantValidUntil = parseCanonicalIso(
      input.grantValidUntil,
      'Grant validUntil'
    )
    const leaseExpiresAt = parseCanonicalIso(
      input.leaseExpiresAt,
      'Lease expiresAt'
    )
    const now = parseClock(this.#clock())
    if (
      grantValidUntil <= now ||
      leaseExpiresAt <= now ||
      leaseExpiresAt > grantValidUntil
    ) {
      throw new Error('Execution lease validity must be contained by its grant.')
    }

    const [parentGrant, parentLease] = await Promise.all([
      this.#repository.getExecutionGrant(parentGrantId),
      this.#repository.getExecutionLease(parentLeaseId)
    ])
    const parentDecision = parentGrant
      ? await this.#repository.getExecutionDecision(
          parentGrant.policyDecisionId
        )
      : undefined
    if (
      !parentGrant ||
      !parentLease ||
      !parentDecision ||
      parentLease.grantId !== parentGrant.id ||
      parentLease.state !== 'completed' ||
      parentDecision.scanId !== parentGrant.scanId ||
      parentDecision.proposal.scanId !== parentGrant.scanId ||
      parentDecision.decision.id !== parentGrant.policyDecisionId ||
      canonicalJson(parentDecision.decision.authorizedWireRequestHmac) !==
        canonicalJson(parentGrant.wireRequestHmac)
    ) {
      throw new Error('Redirect child requires a completed parent grant lease.')
    }
    if (parentGrant.adapterKind !== 'http') {
      throw new Error('Redirect child grants are restricted to HTTP execution.')
    }
    if (
      credentialRef !== null &&
      parentGrant.credentialRef === null
    ) {
      throw new Error('Redirect child cannot upgrade or replace credentials.')
    }
    if (stepId !== parentGrant.stepId) {
      throw new Error('Redirect child must preserve its parent execution step.')
    }
    if (
      policyDecisionId === parentGrant.policyDecisionId ||
      Date.parse(parentGrant.validFrom) > now ||
      Date.parse(parentGrant.validUntil) <= now ||
      grantValidUntil > Date.parse(parentGrant.validUntil)
    ) {
      throw new Error('Redirect child cannot reuse or outlive its parent grant.')
    }
    const loaded = await this.#loadContext(
      parentGrant.scanId,
      policyDecisionId
    )
    const compilation = prepareCompilation(
      input.compiled,
      this.#keyProvider,
      {
        enabledCapabilityIds: parentGrant.capabilityIds,
        ownerRef: loaded.decision.targetId,
        scopeSnapshotId: loaded.decision.scope.id,
        ...(parentGrant.identityRef
          ? { identityRef: parentGrant.identityRef }
          : {}),
        ...(credentialRef
          ? { credentialRef }
          : {}),
        ...(parentGrant.sessionRef
          ? { sessionRef: parentGrant.sessionRef }
          : {}),
        ...(parentGrant.testObjectRef
          ? { testObjectRef: parentGrant.testObjectRef }
          : {}),
        executionBinding: {
          stepId: parentGrant.stepId,
          purpose: parentGrant.purpose,
          adapterKind: parentGrant.adapterKind
        }
      }
    )
    const sameOrigin =
      executionOrigin(parentDecision.proposal.action.targetUrl) ===
      executionOrigin(compilation.wire.url)
    const sameCredential =
      canonicalJson(credentialRef) ===
      canonicalJson(parentGrant.credentialRef)
    if (
      (sameOrigin && !sameCredential) ||
      (!sameOrigin && credentialRef !== null)
    ) {
      throw new Error(
        sameOrigin
          ? 'Same-origin redirect children must preserve credential generation.'
          : 'Cross-origin redirect children must omit credentials.'
      )
    }
    const budget = prepareBudget(input.limits, compilation.requestBytes)
    const redirectHop = parentGrant.redirectHop + 1
    if (
      redirectHop > 10 ||
      redirectHop > parentGrant.budget.maxRedirects ||
      redirectHop > budget.maxRedirects ||
      budget.timeoutMs > parentGrant.budget.timeoutMs ||
      budget.maxResponseBytes > parentGrant.budget.maxResponseBytes ||
      budget.maxRedirects > parentGrant.budget.maxRedirects
    ) {
      throw new Error('Redirect child execution limits exceed its parent grant.')
    }

    this.#validateCommonContext({
      loaded,
      compilation,
      adapterKind: parentGrant.adapterKind,
      budget,
      grantValidUntil,
      now
    })
    const moduleSnapshot = loaded.snapshots.find(
      (snapshot) => snapshot.id === parentGrant.moduleSnapshotId
    )
    if (!moduleSnapshot) {
      throw new Error('Redirect parent module snapshot is missing.')
    }
    assertModuleMatchesGrant(moduleSnapshot, parentGrant)
    if (!loaded.scan.configJson.families.includes(moduleSnapshot.familyId)) {
      throw new Error('Redirect parent family left the frozen scan configuration.')
    }
    const plan = derivePlan(loaded.scan)
    if (
      plan.planId !== parentGrant.planId ||
      plan.planVersion !== parentGrant.planVersion ||
      plan.planHash !== parentGrant.planHash ||
      loaded.decision.scope.id !== parentGrant.scopeSnapshotId ||
      loaded.decision.scope.snapshotHash !== parentGrant.scopeSnapshotHash
    ) {
      throw new Error('Redirect child plan or scope differs from its parent.')
    }
    if (!parentGrant.ownerRef) {
      throw new Error('Redirect parent grant has no immutable owner binding.')
    }
    const refs: PreparedRootRefs = Object.freeze({
      ownerRef: parentGrant.ownerRef,
      ...(parentGrant.identityRef
        ? { identityRef: parentGrant.identityRef }
        : {}),
      credentialRef,
      ...(parentGrant.sessionRef
        ? { sessionRef: parentGrant.sessionRef }
        : {}),
      ...(parentGrant.testObjectRef
        ? { testObjectRef: parentGrant.testObjectRef }
        : {})
    })
    await this.#validateOpaqueRefs(loaded, refs)

    const grant: ExecutionGrantDraft = {
      scanId: parentGrant.scanId,
      scopeSnapshotId: parentGrant.scopeSnapshotId,
      scopeSnapshotHash: parentGrant.scopeSnapshotHash,
      moduleSnapshotId: parentGrant.moduleSnapshotId,
      moduleSnapshotHash: parentGrant.moduleSnapshotHash,
      moduleId: parentGrant.moduleId,
      moduleVersion: parentGrant.moduleVersion,
      techniqueId: parentGrant.techniqueId,
      techniqueVersion: parentGrant.techniqueVersion,
      planId: parentGrant.planId,
      planVersion: parentGrant.planVersion,
      planHash: parentGrant.planHash,
      stepId: parentGrant.stepId,
      templateIntentHash: compilation.templateIntentHash,
      resolvedIntentHash: compilation.resolvedIntentHash,
      wireRequestHmac: compilation.wireRequestHmac,
      capabilityIds: parentGrant.capabilityIds,
      ownerRef: refs.ownerRef,
      ...(parentGrant.identityRef
        ? { identityRef: parentGrant.identityRef }
        : {}),
      credentialRef,
      ...(parentGrant.sessionRef
        ? { sessionRef: parentGrant.sessionRef }
        : {}),
      ...(parentGrant.testObjectRef
        ? { testObjectRef: parentGrant.testObjectRef }
        : {}),
      budget,
      purpose: parentGrant.purpose,
      adapterKind: parentGrant.adapterKind,
      retryClass: parentGrant.retryClass,
      policyDecisionId,
      ...(parentGrant.approvalBundleRef
        ? { approvalBundleRef: parentGrant.approvalBundleRef }
        : {}),
      parentGrantId: parentGrant.id,
      redirectHop,
      validFrom: new Date(now).toISOString(),
      validUntil: input.grantValidUntil
    }
    const evidenceCaptureDecisions = createEvidenceCaptureDecisionSet(grant)
    return this.#persistGrant(
      {
        grant,
        leaseExpiresAt: input.leaseExpiresAt,
        parentLeaseId: parentLease.id,
        evidenceCaptureDecisions
      },
      parentGrant
    )
  }

  async #loadContext(
    scanId: string,
    policyDecisionId: string
  ): Promise<LoadedIssuanceContext> {
    const [scan, decision, snapshots] = await Promise.all([
      this.#repository.getScanRow(scanId),
      this.#repository.getExecutionDecision(policyDecisionId),
      this.#repository.listScanModuleSnapshots(scanId)
    ])
    if (!scan || !decision) {
      throw new Error('Execution issuance context is missing.')
    }
    if (decision.decision.id !== policyDecisionId) {
      throw new Error('Execution policy decision lookup is not exact.')
    }
    return Object.freeze({
      scan,
      decision,
      snapshots: Object.freeze(
        snapshots.map((snapshot) =>
          ScanModuleSnapshotRecordSchema.parse(snapshot)
        )
      )
    })
  }

  #validateCommonContext(input: {
    readonly loaded: LoadedIssuanceContext
    readonly compilation: PreparedCompilation
    readonly adapterKind: ExecutionAdapterKind
    readonly budget: ExecutionGrantDraft['budget']
    readonly grantValidUntil: number
    readonly now: number
  }): void {
    const { scan, decision } = input.loaded
    const decisionValidUntil = decision.decision.validUntil
      ? Date.parse(decision.decision.validUntil)
      : Number.NaN
    if (
      scan.id !== decision.scanId ||
      decision.proposal.scanId !== scan.id ||
      decision.decision.proposalId !== decision.proposal.id ||
      scan.scopeSnapshotId !== decision.scope.id ||
      decision.decision.scopeSnapshotId !== decision.scope.id ||
      decision.proposal.action.scopeSnapshotId !== decision.scope.id ||
      scan.targetId !== decision.targetId ||
      decision.scope.targetId !== decision.targetId ||
      scan.status !== 'running' ||
      decision.scanStatus !== 'running' ||
      !scan.moduleSnapshotsSealed ||
      canonicalJson(scan.budgetJson) !== canonicalJson(decision.scanBudget) ||
      scan.requestCount !== decision.requestCount ||
      scan.requestCount + 1 > scan.budgetJson.maxRequests ||
      !decision.decision.allowed ||
      decision.decision.requiresApproval ||
      !Number.isFinite(decisionValidUntil) ||
      decisionValidUntil <= input.now ||
      input.grantValidUntil > decisionValidUntil ||
      decision.decision.authorizedWireRequestHmac === undefined ||
      canonicalJson(decision.decision.authorizedWireRequestHmac) !==
        canonicalJson(input.compilation.wireRequestHmac) ||
      input.budget.timeoutMs > decision.proposal.action.timeoutMs
    ) {
      throw new Error('Execution policy or scan binding is not issuable.')
    }
    const scopeValidFrom = decision.scope.validFrom
      ? Date.parse(decision.scope.validFrom)
      : Number.NEGATIVE_INFINITY
    const scopeValidUntil = decision.scope.validUntil
      ? Date.parse(decision.scope.validUntil)
      : Number.POSITIVE_INFINITY
    if (
      !Number.isFinite(scopeValidFrom) &&
      scopeValidFrom !== Number.NEGATIVE_INFINITY
    ) {
      throw new Error('Execution scope start is invalid.')
    }
    if (
      !Number.isFinite(scopeValidUntil) &&
      scopeValidUntil !== Number.POSITIVE_INFINITY
    ) {
      throw new Error('Execution scope expiry is invalid.')
    }
    if (
      scopeValidFrom > input.now ||
      scopeValidUntil <= input.now ||
      input.grantValidUntil > scopeValidUntil
    ) {
      throw new Error('Execution grant validity exceeds its frozen scope.')
    }
    if (input.adapterKind === 'http') {
      if (
        decision.proposal.action.kind !== 'http-request' ||
        input.compilation.wire.method !==
          decision.proposal.action.method.toUpperCase()
      ) {
        throw new Error('HTTP execution differs from its policy proposal.')
      }
    } else if (input.adapterKind === 'browser-offline') {
      if (
        decision.proposal.action.kind !== 'browser-action' ||
        input.compilation.wire.method !== 'BROWSER-OFFLINE'
      ) {
        throw new Error('Offline browser execution differs from its policy proposal.')
      }
    } else {
      throw new Error('Execution adapter is unsupported by the authority.')
    }
    const revalidation = evaluateProbe(
      {
        ...decision.proposal.action,
        targetUrl: input.compilation.wire.url,
        method:
          input.adapterKind === 'http'
            ? input.compilation.wire.method
            : decision.proposal.action.method,
        scopeSnapshotId: decision.scope.id
      },
      decision.scope
    )
    if (!revalidation.allowed) {
      throw new Error(
        'Execution policy revalidation failed: ' +
          revalidation.reasons.join('; ')
      )
    }
  }

  #selectModuleSnapshot(
    snapshots: readonly ScanModuleSnapshotRecord[],
    scanId: string,
    familyId: VulnerabilityFamilyId,
    capabilityIds: readonly CapabilityId[]
  ): ScanModuleSnapshotRecord {
    const matches = snapshots.filter((snapshot) => {
      if (snapshot.scanId !== scanId || snapshot.familyId !== familyId) {
        return false
      }
      const available = new Set(
        snapshot.capabilityDescriptors.map((descriptor) => descriptor.id)
      )
      if (available.size !== snapshot.capabilityDescriptors.length) {
        return false
      }
      return capabilityIds.every((capabilityId) => available.has(capabilityId))
    })
    if (matches.length !== 1) {
      throw new Error(
        'Execution family and capabilities must select exactly one sealed module snapshot.'
      )
    }
    return matches[0]!
  }

  async #validateOpaqueRefs(
    loaded: LoadedIssuanceContext,
    refs: PreparedRootRefs
  ): Promise<void> {
    const { scan, decision } = loaded
    if (refs.ownerRef !== decision.targetId) {
      throw new Error('Execution owner does not match the frozen target.')
    }
    const opaqueRefs = [
      refs.identityRef,
      refs.sessionRef,
      refs.testObjectRef
    ].filter(
      (
        value
      ): value is IdentityRef | SessionGenerationRef | TestObjectRef =>
        value !== undefined
    )
    if (
      opaqueRefs.some(
        (ref) =>
          ref.ownerRef !== refs.ownerRef ||
          ref.scopeSnapshotId !== decision.scope.id
      )
    ) {
      throw new Error('Execution opaque refs differ from owner or scope.')
    }
    const actionIdentityId = decision.proposal.action.identityId
    if (refs.credentialRef !== null && !refs.identityRef) {
      throw new Error(
        'Execution credential metadata requires an authoritative identity.'
      )
    }

    if (actionIdentityId !== refs.identityRef?.id) {
      throw new Error('Execution identity differs from the policy proposal.')
    }
    if (refs.sessionRef && refs.sessionRef.statusSummary !== 'active') {
      throw new Error('Execution session reference is not active.')
    }
    if (
      refs.testObjectRef &&
      refs.testObjectRef.statusSummary !== 'ready' &&
      refs.testObjectRef.statusSummary !== 'in-use'
    ) {
      throw new Error('Execution test-object reference is not usable.')
    }
    if (!refs.identityRef) return
    const identity = await this.#repository.getIdentity(refs.identityRef.id)
    if (
      !identity ||
      identity.targetId !== decision.targetId ||
      !identity.isTestIdentity ||
      !scan.configJson.identityIds.includes(identity.id) ||
      !decision.scope.allowedIdentityIds.includes(identity.id) ||
      refs.identityRef.statusSummary !== 'active' ||
      refs.identityRef.version !== Date.parse(identity.updatedAt)
      ||
      (refs.credentialRef !== null &&
        (identity.credentialId !== refs.credentialRef.id ||
          identity.authType === 'none'))
    ) {
      throw new Error('Execution identity is no longer an authorized test identity.')
    }
  }

  async #persistGrant(
    input: {
      readonly grant: ExecutionGrantDraft
      readonly leaseExpiresAt: string
      readonly parentLeaseId?: string
      readonly evidenceCaptureDecisions: ExecutionEvidenceCaptureDecisionSet
    },
    parentGrant?: ExecutionGrant
  ): Promise<IssuedExecutionAuthority> {
    const reference = this.#keyProvider.reference
    if (
      input.grant.wireRequestHmac.keyRef !== reference.keyRef ||
      input.grant.wireRequestHmac.keyVersion !== reference.keyVersion
    ) {
      throw new Error('Execution grant key generation is unavailable.')
    }
    let keyMaterial: Uint8Array<ArrayBuffer>
    try {
      keyMaterial = snapshotSecureBytes(
        this.#keyProvider.resolveKey(reference),
        {
          minimumBytes: 32,
          maximumBytes: 4_096
        }
      )
    } catch {
      throw new Error('Execution grant integrity key is invalid.')
    }
    const integrityKey: ExecutionGrantIntegrityKey = {
      keyRef: reference.keyRef,
      keyVersion: reference.keyVersion,
      keyMaterial
    }
    try {
      if (
        parentGrant &&
        !verifyExecutionGrantIntegrity(
          executionGrantIntegrityBindingForGrant(parentGrant),
          parentGrant.integrityHmac,
          integrityKey
        )
      ) {
        throw new Error('Redirect parent grant integrity verification failed.')
      }
      const issued = await this.#repository.issueExecutionGrant({
        grant: input.grant,
        captureDecisionSet: toExecutionCaptureDecisionSet(input.evidenceCaptureDecisions),
        integrityKey,
        leaseExpiresAt: input.leaseExpiresAt,
        ...(input.parentLeaseId
          ? { parentLeaseId: input.parentLeaseId }
          : {})
      })
      return Object.freeze({
        ...issued,
        evidenceCaptureDecisions: input.evidenceCaptureDecisions
      })
    } finally {
      zeroizeSecureBytes(keyMaterial)
    }
  }
}
