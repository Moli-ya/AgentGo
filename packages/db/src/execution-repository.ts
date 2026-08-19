import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from 'node:crypto'
import {
  and,
  asc,
  desc,
  eq,
  inArray,
  isNull,
  lte,
  or
} from 'drizzle-orm'
import {
  ExecutionClaimBindingSchema,
  ExecutionCaptureDecisionSetHashSchema,
  ExecutionCaptureDecisionSetSchema,
  ExecutionGrantIntegrityBindingSchema,
  ExecutionGrantIntegrityHmacSchema,
  ExecutionGrantSchema,
  ExecutionEvidenceRefsSchema,
  ExecutionLeaseOutcomeSummarySchema,
  ExecutionLeaseSchema,
  SystemIssuedOpaqueIdSchema,
  type ExecutionClaimBinding,
  type ExecutionCaptureDecisionSet,
  type ExecutionCaptureDecisionSetHash,
  type EvidenceCaptureDecision,
  type ExecutionGrant,
  type ExecutionGrantIntegrityBinding,
  type ExecutionGrantIntegrityHmac,
  type ExecutionLease,
  type ExecutionLeaseDeliveryState,
  type ExecutionLeaseOutcomeSummary,
  type ExecutionLeaseTerminalReason
} from '@agentgo/contracts'
import { canonicalJson } from '@agentgo/domain'
import type { AgentGoDatabase } from './database'
import { isEvidenceItemReferenced } from './evidence-reference-guard'
import {
  evidenceItems,
  executionCaptureDecisions,
  executionGrants,
  executionLeaseEvidence,
  executionLeases,
  identities,
  interactions,
  policyDecisions,
  probeProposals,
  scanModuleSnapshots,
  scanIdentities,
  scans,
  targetScopes,
  targets,
  toolCalls
} from './schema'

type ExecutionGrantRow = typeof executionGrants.$inferSelect
type ExecutionLeaseRow = typeof executionLeases.$inferSelect

export type ExecutionGrantDraft = Omit<
  ExecutionGrantIntegrityBinding,
  'schemaVersion' | 'id' | 'issuedAt' | 'captureDecisionSetHash'
>

export interface ExecutionGrantIntegrityKey {
  readonly keyRef: string
  readonly keyVersion: number
  /** Main-process key material. Never persist, log, or expose it to Renderer. */
  readonly keyMaterial: Uint8Array
}

export interface IssueExecutionGrantInput {
  grant: ExecutionGrantDraft
  captureDecisionSet: ExecutionCaptureDecisionSet
  integrityKey: ExecutionGrantIntegrityKey
  leaseExpiresAt: string
  parentLeaseId?: string
}

export interface ClaimedExecutionLease {
  lease: ExecutionLease
  /**
   * Ephemeral claim capability. It must not be persisted, logged, or sent
   * across the Renderer/Preload boundary.
   */
  claimToken: string
}

export interface FinalizeExecutionLeaseInput {
  leaseId: string
  claimToken: string
  state: 'completed' | 'failed'
  terminalReason: ExecutionLeaseTerminalReason
  deliveryState: ExecutionLeaseDeliveryState
  outcomeSummary: ExecutionLeaseOutcomeSummary
  evidenceRefs: readonly string[]
}

export interface ExecutionLeaseEvidenceLink {
  leaseId: string
  evidenceId: string
  captureDecisionId: string
  role: string
  ordinal: number
}

export interface RecoverInterruptedExecutionLeaseInput {
  leaseId: string
  evidenceId?: string
  /**
   * An interruption artifact that was saved but could not be bound may be
   * discarded in the same transaction that terminalizes the claimed lease.
   */
  discardUnboundEvidenceId?: string
}

export interface RecoverInterruptedExecutionLeaseWithEvidenceInput
  extends RecoverInterruptedExecutionLeaseInput {
  evidenceId: string
  discardUnboundEvidenceId?: never
}

export interface RecoverInterruptedExecutionLeaseWithCleanupInput
  extends RecoverInterruptedExecutionLeaseInput {
  /**
   * The caller must opt in only when it can attempt file deletion for every
   * path returned in `discardedEvidence`. Otherwise metadata is preserved so
   * a content file never becomes an unreachable orphan.
   */
  discardUnboundStagedEvidence: boolean
}

export interface InterruptedExecutionRecoveryContext {
  lease: ExecutionLease
  grant: ExecutionGrant
  captureDecision: EvidenceCaptureDecision
}

export interface InterruptedExecutionScanRecoveryContext {
  lease: ExecutionLease
  grant: ExecutionGrant
  interruptionEvidenceId?: string
}

export interface DiscardedExecutionEvidence {
  readonly id: string
  readonly filePath: string
  readonly sha256: string
}

export interface InterruptedExecutionRecoveryResult {
  readonly lease: ExecutionLease
  readonly discardedEvidence: readonly DiscardedExecutionEvidence[]
}

export interface RecordExecutionInteractionAuditInput {
  leaseId: string
  claimToken: string
  interaction: {
    id?: string
    scanId: string
    endpointId?: string
    identityId?: string
    policyDecisionId: string
    requestRef: string
    responseRef: string
    requestSummary: Record<string, unknown>
    responseSummary: Record<string, unknown>
    statusCode?: number
    durationMs?: number
    stateBeforeHash?: string
    stateAfterHash?: string
  }
  evidenceLinks: readonly [
    ExecutionLeaseEvidenceLink,
    ExecutionLeaseEvidenceLink
  ]
}

function toIso(value: number): string {
  return new Date(value).toISOString()
}

function sha256Text(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function parseIntegrityKey(
  key: ExecutionGrantIntegrityKey
): ExecutionGrantIntegrityKey {
  if (key.keyMaterial.byteLength < 32) {
    throw new TypeError('Execution grant integrity keys must contain at least 256 bits.')
  }
  return {
    keyRef: SystemIssuedOpaqueIdSchema.parse(key.keyRef),
    keyVersion: (() => {
      if (!Number.isInteger(key.keyVersion) || key.keyVersion < 0) {
        throw new TypeError('Execution grant integrity key version is invalid.')
      }
      return key.keyVersion
    })(),
    keyMaterial: key.keyMaterial
  }
}

export function hashExecutionCaptureDecisionSet(
  input: ExecutionCaptureDecisionSet
): ExecutionCaptureDecisionSetHash {
  const decisionSet = ExecutionCaptureDecisionSetSchema.parse(input)
  return ExecutionCaptureDecisionSetHashSchema.parse({
    domain: 'agentgo.execution-capture-decision-set.v1',
    algorithm: 'sha256',
    digest: sha256Text(canonicalJson(decisionSet))
  })
}

function assertCaptureDecisionSetBinding(
  input: ExecutionCaptureDecisionSet,
  grant: ExecutionGrantDraft | ExecutionGrant
): ExecutionCaptureDecisionSet {
  const decisionSet = ExecutionCaptureDecisionSetSchema.parse(input)
  const sourceRoles =
    grant.adapterKind === 'http'
      ? new Map([
          ['http-request-summary', 'request-summary'],
          ['http-response-summary', 'response-summary'],
          ['execution-interruption-summary', 'interruption-summary']
        ])
      : grant.adapterKind === 'browser-offline'
        ? new Map([
            ['browser-request-summary', 'request-summary'],
            ['browser-result-summary', 'result-summary'],
            ['execution-interruption-summary', 'interruption-summary']
          ])
        : undefined
  if (!sourceRoles) {
    throw new Error('Execution capture decisions require a supported adapter.')
  }
  const seen = new Set<string>()
  for (const decision of decisionSet.decisions) {
    const expectedRole = sourceRoles.get(decision.source)
    const bindingKey = `${decision.source}\u0000${decision.executionState}`
    if (
      expectedRole === undefined ||
      decision.role !== expectedRole ||
      decision.action !== 'hash-only' ||
      decision.scanId !== grant.scanId ||
      decision.policyDecisionId !== grant.policyDecisionId ||
      decision.techniqueId !== grant.techniqueId ||
      decision.techniqueVersion !== grant.techniqueVersion ||
      decision.stepId !== grant.stepId ||
      decision.validFrom !== grant.validFrom ||
      decision.validUntil !== grant.validUntil ||
      decision.jsonPointers.length !== 0 ||
      decision.oobMetadataFields.length !== 0 ||
      decision.oobCommitmentKeyRef !== undefined ||
      decision.oobCommitmentKeyVersion !== undefined ||
      (decision.source === 'execution-interruption-summary'
        ? decision.executionState !== 'interrupted'
        : decision.executionState === 'interrupted')
    ) {
      throw new Error(
        'Execution capture decision set does not match its immutable grant.'
      )
    }
    seen.add(bindingKey)
  }
  const states = ['cancelled', 'failed', 'succeeded', 'timed-out'] as const
  for (
    const source of [...sourceRoles.keys()].filter(
      (value) => value !== 'execution-interruption-summary'
    )
  ) {
    for (const state of states) {
      if (!seen.has(`${source}\u0000${state}`)) {
        throw new Error(
          'Execution capture decision set is incomplete for its adapter.'
        )
      }
    }
  }
  if (
    !seen.has('execution-interruption-summary\u0000interrupted')
  ) {
    throw new Error(
      'Execution capture decision set lacks crash-interruption authority.'
    )
  }
  return decisionSet
}

export function verifyExecutionCaptureDecisionSetHash(
  input: ExecutionCaptureDecisionSet,
  proofInput: ExecutionCaptureDecisionSetHash
): boolean {
  const proof = ExecutionCaptureDecisionSetHashSchema.parse(proofInput)
  const expected = hashExecutionCaptureDecisionSet(input)
  const actualDigest = Buffer.from(proof.digest, 'hex')
  const expectedDigest = Buffer.from(expected.digest, 'hex')
  return (
    proof.domain === expected.domain &&
    proof.algorithm === expected.algorithm &&
    actualDigest.byteLength === expectedDigest.byteLength &&
    timingSafeEqual(actualDigest, expectedDigest)
  )
}

function calculateExecutionGrantIntegrityDigest(
  binding: ExecutionGrantIntegrityBinding,
  key: ExecutionGrantIntegrityKey
): Buffer {
  return createHmac('sha256', key.keyMaterial)
    .update(canonicalJson(binding), 'utf8')
    .digest()
}

export function signExecutionGrantIntegrity(
  bindingInput: ExecutionGrantIntegrityBinding,
  keyInput: ExecutionGrantIntegrityKey
): ExecutionGrantIntegrityHmac {
  const binding = ExecutionGrantIntegrityBindingSchema.parse(bindingInput)
  const key = parseIntegrityKey(keyInput)
  return ExecutionGrantIntegrityHmacSchema.parse({
    domain: 'agentgo.execution-grant.v1',
    algorithm: 'hmac-sha256',
    keyRef: key.keyRef,
    keyVersion: key.keyVersion,
    digest: calculateExecutionGrantIntegrityDigest(binding, key).toString('hex')
  })
}

export function verifyExecutionGrantIntegrity(
  bindingInput: ExecutionGrantIntegrityBinding,
  proofInput: ExecutionGrantIntegrityHmac,
  keyInput: ExecutionGrantIntegrityKey
): boolean {
  const binding = ExecutionGrantIntegrityBindingSchema.parse(bindingInput)
  const proof = ExecutionGrantIntegrityHmacSchema.parse(proofInput)
  const key = parseIntegrityKey(keyInput)
  if (proof.keyRef !== key.keyRef || proof.keyVersion !== key.keyVersion) {
    return false
  }
  const actual = Buffer.from(proof.digest, 'hex')
  const expected = calculateExecutionGrantIntegrityDigest(binding, key)
  return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected)
}

export function executionGrantIntegrityBindingForGrant(
  grant: ExecutionGrant
): ExecutionGrantIntegrityBinding {
  const { integrityHmac: _integrityHmac, ...binding } = grant
  return ExecutionGrantIntegrityBindingSchema.parse(binding)
}

function mapExecutionGrant(row: ExecutionGrantRow): ExecutionGrant {
  return ExecutionGrantSchema.parse({
    schemaVersion: row.schemaVersion,
    id: row.id,
    scanId: row.scanId,
    scopeSnapshotId: row.scopeSnapshotId,
    scopeSnapshotHash: row.scopeSnapshotHash,
    moduleSnapshotId: row.moduleSnapshotId,
    moduleSnapshotHash: row.moduleSnapshotHash,
    moduleId: row.moduleId,
    moduleVersion: row.moduleVersion,
    techniqueId: row.techniqueId,
    techniqueVersion: row.techniqueVersion,
    planId: row.planId,
    planVersion: row.planVersion,
    planHash: row.planHash,
    stepId: row.stepId,
    templateIntentHash: row.templateIntentHash,
    resolvedIntentHash: row.resolvedIntentHash,
    wireRequestHmac: row.wireRequestHmac,
    captureDecisionSetHash: row.captureDecisionSetHash,
    integrityHmac: row.integrityHmac,
    capabilityIds: row.capabilityIds,
    ...(row.ownerRef ? { ownerRef: row.ownerRef } : {}),
    ...(row.identityRef ? { identityRef: row.identityRef } : {}),
    credentialRef: row.credentialRef,
    ...(row.sessionRef ? { sessionRef: row.sessionRef } : {}),
    ...(row.testObjectRef ? { testObjectRef: row.testObjectRef } : {}),
    budget: row.budget,
    purpose: row.purpose,
    adapterKind: row.adapterKind,
    retryClass: row.retryClass,
    policyDecisionId: row.policyDecisionId,
    ...(row.approvalBundleRef
      ? { approvalBundleRef: row.approvalBundleRef }
      : {}),
    ...(row.parentGrantId ? { parentGrantId: row.parentGrantId } : {}),
    redirectHop: row.redirectHop,
    validFrom: toIso(row.validFrom),
    validUntil: toIso(row.validUntil),
    issuedAt: toIso(row.issuedAt)
  })
}

function mapExecutionLease(row: ExecutionLeaseRow): ExecutionLease {
  return ExecutionLeaseSchema.parse({
    schemaVersion: row.schemaVersion,
    id: row.id,
    grantId: row.grantId,
    ...(row.parentLeaseId ? { parentLeaseId: row.parentLeaseId } : {}),
    attempt: row.attempt,
    state: row.state,
    issuedAt: toIso(row.issuedAt),
    expiresAt: toIso(row.expiresAt),
    ...(row.claimedAt !== null ? { claimedAt: toIso(row.claimedAt) } : {}),
    ...(row.claimedBy ? { claimedBy: row.claimedBy } : {}),
    ...(row.claimTokenHash
      ? { claimTokenHash: row.claimTokenHash }
      : {}),
    deliveryState: row.deliveryState,
    ...(row.terminalAt !== null ? { terminalAt: toIso(row.terminalAt) } : {}),
    ...(row.terminalReason
      ? { terminalReason: row.terminalReason }
      : {}),
    ...(row.outcomeSummary
      ? { outcomeSummary: row.outcomeSummary }
      : {}),
    evidenceRefs: row.evidenceRefs
  })
}

export function executionClaimBindingForGrant(
  grant: ExecutionGrant
): ExecutionClaimBinding {
  return ExecutionClaimBindingSchema.parse({
    grantId: grant.id,
    scanId: grant.scanId,
    scopeSnapshotId: grant.scopeSnapshotId,
    scopeSnapshotHash: grant.scopeSnapshotHash,
    moduleSnapshotId: grant.moduleSnapshotId,
    moduleSnapshotHash: grant.moduleSnapshotHash,
    moduleId: grant.moduleId,
    moduleVersion: grant.moduleVersion,
    techniqueId: grant.techniqueId,
    techniqueVersion: grant.techniqueVersion,
    planId: grant.planId,
    planVersion: grant.planVersion,
    planHash: grant.planHash,
    stepId: grant.stepId,
    templateIntentHash: grant.templateIntentHash,
    resolvedIntentHash: grant.resolvedIntentHash,
    wireRequestHmac: grant.wireRequestHmac,
    captureDecisionSetHash: grant.captureDecisionSetHash,
    capabilityIds: grant.capabilityIds,
    ...(grant.ownerRef ? { ownerRef: grant.ownerRef } : {}),
    ...(grant.identityRef ? { identityRef: grant.identityRef } : {}),
    credentialRef: grant.credentialRef,
    ...(grant.sessionRef ? { sessionRef: grant.sessionRef } : {}),
    ...(grant.testObjectRef ? { testObjectRef: grant.testObjectRef } : {}),
    budget: grant.budget,
    purpose: grant.purpose,
    adapterKind: grant.adapterKind,
    retryClass: grant.retryClass,
    policyDecisionId: grant.policyDecisionId,
    ...(grant.approvalBundleRef
      ? { approvalBundleRef: grant.approvalBundleRef }
      : {}),
    ...(grant.parentGrantId ? { parentGrantId: grant.parentGrantId } : {}),
    redirectHop: grant.redirectHop,
    validFrom: grant.validFrom,
    validUntil: grant.validUntil,
    issuedAt: grant.issuedAt,
    integrityHmac: grant.integrityHmac
  })
}

function assertExactClaimBinding(
  actual: ExecutionClaimBinding,
  grant: ExecutionGrant
): void {
  const expected = executionClaimBindingForGrant(grant)
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error('Execution lease claim binding does not match its immutable grant.')
  }
}

function requirePlanVersion(plan: Record<string, unknown>): string {
  const version = plan.version
  if (typeof version !== 'string') {
    throw new Error('Execution grant scan plan has no exact persisted version.')
  }
  return version
}

function validateGrantRetryClass(grant: ExecutionGrant): void {
  if (
    grant.retryClass === 'deterministic-readonly' &&
    grant.purpose !== 'read'
  ) {
    throw new Error(
      'Only read-purpose execution grants may declare deterministic retry safety.'
    )
  }
}

export class ExecutionLeaseRepository {
  constructor(private readonly database: AgentGoDatabase) {}

  async getExecutionGrant(id: string): Promise<ExecutionGrant | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(executionGrants)
      .where(eq(executionGrants.id, id))
      .limit(1)
    return row ? mapExecutionGrant(row) : undefined
  }

  async getExecutionLease(id: string): Promise<ExecutionLease | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(executionLeases)
      .where(eq(executionLeases.id, id))
      .limit(1)
    return row ? mapExecutionLease(row) : undefined
  }

  async getExecutionCaptureDecisionSet(
    grantId: string
  ): Promise<ExecutionCaptureDecisionSet | undefined> {
    const parsedGrantId = SystemIssuedOpaqueIdSchema.parse(grantId)
    const rows = await this.database.orm
      .select({ decision: executionCaptureDecisions.decision })
      .from(executionCaptureDecisions)
      .where(eq(executionCaptureDecisions.grantId, parsedGrantId))
      .orderBy(
        asc(executionCaptureDecisions.source),
        asc(executionCaptureDecisions.executionState)
      )
    if (rows.length === 0) return undefined
    return ExecutionCaptureDecisionSetSchema.parse({
      schemaVersion: 'execution-capture-decision-set.v1',
      decisions: rows.map(({ decision }) => decision)
    })
  }

  async getExecutionGrantForLease(
    leaseId: string
  ): Promise<ExecutionGrant | undefined> {
    const [row] = await this.database.orm
      .select({ grant: executionGrants })
      .from(executionLeases)
      .innerJoin(
        executionGrants,
        eq(executionLeases.grantId, executionGrants.id)
      )
      .where(eq(executionLeases.id, leaseId))
      .limit(1)
    return row ? mapExecutionGrant(row.grant) : undefined
  }

  issueExecutionGrant(
    input: IssueExecutionGrantInput
  ): Promise<{ grant: ExecutionGrant; lease: ExecutionLease }> {
    const now = Date.now()
    const issuedAt = toIso(now)
    const captureDecisionSet = assertCaptureDecisionSetBinding(
      input.captureDecisionSet,
      input.grant
    )
    const integrityBinding = ExecutionGrantIntegrityBindingSchema.parse({
      ...input.grant,
      captureDecisionSetHash: hashExecutionCaptureDecisionSet(
        captureDecisionSet
      ),
      schemaVersion: 'execution-grant.v1',
      id: randomUUID(),
      issuedAt
    })
    const grant = ExecutionGrantSchema.parse({
      ...integrityBinding,
      integrityHmac: signExecutionGrantIntegrity(
        integrityBinding,
        input.integrityKey
      )
    })
    validateGrantRetryClass(grant)
    const leaseExpiresAt = Date.parse(input.leaseExpiresAt)
    if (
      !Number.isFinite(leaseExpiresAt) ||
      leaseExpiresAt <= now ||
      leaseExpiresAt > Date.parse(grant.validUntil)
    ) {
      throw new Error(
        'Execution lease validity must be positive and contained by its grant.'
      )
    }
    const lease = ExecutionLeaseSchema.parse({
      schemaVersion: 'execution-lease.v1',
      id: randomUUID(),
      grantId: grant.id,
      ...(input.parentLeaseId
        ? { parentLeaseId: input.parentLeaseId }
        : {}),
      attempt: 1,
      state: 'issued',
      issuedAt,
      expiresAt: toIso(leaseExpiresAt),
      deliveryState: 'not-dispatched',
      evidenceRefs: []
    })
    const captureDecisionRows: Array<
      typeof executionCaptureDecisions.$inferInsert
    > = captureDecisionSet.decisions.map((decision) => ({
      id: decision.id,
      grantId: grant.id,
      scanId: decision.scanId,
      policyDecisionId: decision.policyDecisionId,
      capturePolicyId: decision.capturePolicyId,
      capturePolicyVersion: decision.capturePolicyVersion,
      techniqueId: decision.techniqueId,
      techniqueVersion: decision.techniqueVersion,
      stepId: decision.stepId,
      executionState: decision.executionState,
      source: decision.source,
      role: decision.role,
      action: decision.action,
      validFrom: Date.parse(decision.validFrom),
      validUntil: Date.parse(decision.validUntil),
      maxSourceBytes: decision.maxSourceBytes,
      maxExcerptBytes: decision.maxExcerptBytes,
      jsonPointers: [...decision.jsonPointers],
      oobMetadataFields: [...decision.oobMetadataFields],
      oobCommitmentKeyRef: decision.oobCommitmentKeyRef ?? null,
      oobCommitmentKeyVersion: decision.oobCommitmentKeyVersion ?? null,
      decision
    }))

    return this.database.orm.transaction(
      async (transaction) => {
        const [context] = await transaction
          .select({
            scan: scans,
            targetId: targets.id,
            scope: targetScopes,
            module: scanModuleSnapshots,
            decision: policyDecisions,
            proposal: probeProposals
          })
          .from(scans)
          .innerJoin(targets, eq(scans.targetId, targets.id))
          .innerJoin(
            targetScopes,
            and(
              eq(scans.scopeSnapshotId, targetScopes.id),
              eq(targetScopes.targetId, targets.id)
            )
          )
          .innerJoin(
            scanModuleSnapshots,
            and(
              eq(scanModuleSnapshots.id, grant.moduleSnapshotId),
              eq(scanModuleSnapshots.scanId, scans.id)
            )
          )
          .innerJoin(
            policyDecisions,
            eq(policyDecisions.id, grant.policyDecisionId)
          )
          .innerJoin(
            probeProposals,
            and(
              eq(policyDecisions.proposalId, probeProposals.id),
              eq(probeProposals.scanId, scans.id)
            )
          )
          .where(eq(scans.id, grant.scanId))
          .limit(1)
        if (!context) {
          throw new Error(
            'Execution grant references do not resolve to one scan binding.'
          )
        }
        if (
          context.scan.status !== 'running' ||
          !context.scan.moduleSnapshotsSealed ||
          !context.scan.configJson.families.includes(
            context.module.familyId
          ) ||
          context.scan.requestCount + grant.budget.requestUnits >
            context.scan.budgetJson.maxRequests ||
          context.scope.id !== grant.scopeSnapshotId ||
          context.scope.snapshotHash !== grant.scopeSnapshotHash ||
          context.module.snapshotHash !== grant.moduleSnapshotHash ||
          context.module.moduleId !== grant.moduleId ||
          context.module.moduleVersion !== grant.moduleVersion ||
          context.module.techniqueId !== grant.techniqueId ||
          context.module.techniqueVersion !== grant.techniqueVersion
        ) {
          throw new Error(
            'Execution grant scope or module snapshot binding is invalid.'
          )
        }
        if (
          grant.sessionRef !== undefined ||
          grant.testObjectRef !== undefined
        ) {
          throw new Error(
            'Execution session and test-object refs require authoritative services.'
          )
        }
        if (
          (context.proposal.identityId ?? null) !==
          (grant.identityRef?.id ?? null)
        ) {
          throw new Error(
            'Execution grant identity differs from its policy proposal.'
          )
        }
        if (grant.identityRef) {
          const [identity] = await transaction
            .select({ identity: identities })
            .from(identities)
            .innerJoin(
              scanIdentities,
              and(
                eq(scanIdentities.identityId, identities.id),
                eq(scanIdentities.scanId, grant.scanId)
              )
            )
            .where(eq(identities.id, grant.identityRef.id))
            .limit(1)
          if (
            !identity ||
            identity.identity.targetId !== context.targetId ||
            !identity.identity.isTestIdentity ||
            identity.identity.updatedAt !== grant.identityRef.version ||
            grant.ownerRef !== context.targetId ||
            grant.identityRef.ownerRef !== context.targetId ||
            grant.identityRef.scopeSnapshotId !== grant.scopeSnapshotId ||
            grant.identityRef.statusSummary !== 'active' ||
            !context.scan.configJson.identityIds.includes(
              identity.identity.id
            ) ||
            (grant.credentialRef === null
              ? identity.identity.credentialId !== null &&
                grant.parentGrantId === undefined
              : identity.identity.credentialId !==
                grant.credentialRef.id) ||
            !context.scope.allowedIdentityIds.includes(identity.identity.id)
          ) {
            throw new Error(
              'Execution identity is not an authorized current test identity.'
            )
          }
        }
        if (
          grant.planId !== context.scan.id ||
          grant.planVersion !== requirePlanVersion(context.scan.planJson) ||
          grant.planHash !==
            sha256Text(canonicalJson(context.scan.planJson))
        ) {
          throw new Error(
            'Execution grant plan binding does not match the persisted scan plan.'
          )
        }
        const availableCapabilities = new Set(
          context.module.capabilityDescriptors.map(({ id }) => id)
        )
        if (
          grant.capabilityIds.some(
            (capabilityId) => !availableCapabilities.has(capabilityId)
          )
        ) {
          throw new Error(
            'Execution grant requests a capability outside its module snapshot.'
          )
        }
        if (
          !context.decision.allowed ||
          context.decision.requiresApproval ||
          context.decision.scopeSnapshotId !== grant.scopeSnapshotId ||
          context.decision.validUntil === null ||
          context.decision.validUntil <= now ||
          Date.parse(grant.validUntil) > context.decision.validUntil ||
          context.decision.authorizedWireRequestHmac === null ||
          canonicalJson(context.decision.authorizedWireRequestHmac) !==
            canonicalJson(grant.wireRequestHmac)
        ) {
          throw new Error(
            'Execution grant requires an allowed, unexpired, non-approval policy decision.'
          )
        }
        if (
          (context.scope.validFrom !== null &&
            context.scope.validFrom > now) ||
          (context.scope.validUntil !== null &&
            Date.parse(grant.validUntil) > context.scope.validUntil)
        ) {
          throw new Error(
            'Execution grant validity exceeds its immutable scope snapshot.'
          )
        }
        if (grant.redirectHop > grant.budget.maxRedirects) {
          throw new Error(
            'Execution grant redirect hop exceeds its immutable redirect budget.'
          )
        }
        if (grant.parentGrantId) {
          const [parent] = await transaction
            .select()
            .from(executionGrants)
            .where(eq(executionGrants.id, grant.parentGrantId))
            .limit(1)
          if (
            !parent ||
            parent.scanId !== grant.scanId ||
            parent.redirectHop + 1 !== grant.redirectHop ||
            parent.scopeSnapshotId !== grant.scopeSnapshotId ||
            parent.scopeSnapshotHash !== grant.scopeSnapshotHash ||
            parent.moduleSnapshotId !== grant.moduleSnapshotId ||
            parent.moduleSnapshotHash !== grant.moduleSnapshotHash ||
            parent.moduleId !== grant.moduleId ||
            parent.moduleVersion !== grant.moduleVersion ||
            parent.techniqueId !== grant.techniqueId ||
            parent.techniqueVersion !== grant.techniqueVersion ||
            parent.planId !== grant.planId ||
            parent.planVersion !== grant.planVersion ||
            parent.planHash !== grant.planHash ||
            parent.stepId !== grant.stepId ||
            canonicalJson(parent.capabilityIds) !==
              canonicalJson(grant.capabilityIds) ||
            parent.ownerRef !== (grant.ownerRef ?? null) ||
            canonicalJson(parent.identityRef) !==
              canonicalJson(grant.identityRef ?? null) ||
            (grant.credentialRef !== null &&
              canonicalJson(parent.credentialRef) !==
                canonicalJson(grant.credentialRef)) ||
            canonicalJson(parent.sessionRef) !==
              canonicalJson(grant.sessionRef ?? null) ||
            canonicalJson(parent.testObjectRef) !==
              canonicalJson(grant.testObjectRef ?? null) ||
            parent.purpose !== grant.purpose ||
            parent.adapterKind !== grant.adapterKind ||
            parent.adapterKind !== 'http' ||
            grant.adapterKind !== 'http' ||
            parent.retryClass !== grant.retryClass ||
            parent.approvalBundleRef !== (grant.approvalBundleRef ?? null) ||
            Date.parse(grant.validUntil) > parent.validUntil ||
            grant.budget.timeoutMs > parent.budget.timeoutMs ||
            grant.budget.maxResponseBytes > parent.budget.maxResponseBytes ||
            grant.budget.maxRedirects > parent.budget.maxRedirects ||
            !input.parentLeaseId
          ) {
            throw new Error(
              'Redirect execution grants require the immediately preceding grant and lease.'
            )
          }
          const [parentLease] = await transaction
            .select()
            .from(executionLeases)
            .where(eq(executionLeases.id, input.parentLeaseId))
            .limit(1)
          if (
            !parentLease ||
            parentLease.grantId !== parent.id ||
            parentLease.state !== 'completed'
          ) {
            throw new Error(
              'Redirect execution grants require a completed parent lease.'
            )
          }
        } else if (input.parentLeaseId) {
          throw new Error(
            'Root execution grants cannot bind an unrelated parent lease.'
          )
        }

        const grantRow: typeof executionGrants.$inferInsert = {
          schemaVersion: grant.schemaVersion,
          id: grant.id,
          scanId: grant.scanId,
          scopeSnapshotId: grant.scopeSnapshotId,
          scopeSnapshotHash: grant.scopeSnapshotHash,
          moduleSnapshotId: grant.moduleSnapshotId,
          moduleSnapshotHash: grant.moduleSnapshotHash,
          moduleId: grant.moduleId,
          moduleVersion: grant.moduleVersion,
          techniqueId: grant.techniqueId,
          techniqueVersion: grant.techniqueVersion,
          planId: grant.planId,
          planVersion: grant.planVersion,
          planHash: grant.planHash,
          stepId: grant.stepId,
          templateIntentHash: grant.templateIntentHash,
          resolvedIntentHash: grant.resolvedIntentHash,
          wireRequestHmac: grant.wireRequestHmac,
          captureDecisionSetHash: grant.captureDecisionSetHash,
          integrityHmac: grant.integrityHmac,
          capabilityIds: [...grant.capabilityIds],
          ownerRef: grant.ownerRef ?? null,
          identityRef: grant.identityRef ?? null,
          credentialRef: grant.credentialRef,
          sessionRef: grant.sessionRef ?? null,
          testObjectRef: grant.testObjectRef ?? null,
          budget: grant.budget,
          purpose: grant.purpose,
          adapterKind: grant.adapterKind,
          retryClass: grant.retryClass,
          policyDecisionId: grant.policyDecisionId,
          approvalBundleRef: grant.approvalBundleRef ?? null,
          parentGrantId: grant.parentGrantId ?? null,
          redirectHop: grant.redirectHop,
          validFrom: Date.parse(grant.validFrom),
          validUntil: Date.parse(grant.validUntil),
          issuedAt: now
        }
        const leaseRow: typeof executionLeases.$inferInsert = {
          schemaVersion: lease.schemaVersion,
          id: lease.id,
          grantId: lease.grantId,
          parentLeaseId: lease.parentLeaseId ?? null,
          attempt: lease.attempt,
          state: lease.state,
          issuedAt: now,
          expiresAt: leaseExpiresAt,
          claimedAt: null,
          claimedBy: null,
          claimTokenHash: null,
          deliveryState: lease.deliveryState,
          terminalAt: null,
          terminalReason: null,
          outcomeSummary: null,
          evidenceRefs: []
        }
        await transaction.insert(executionGrants).values(grantRow)
        await transaction
          .insert(executionCaptureDecisions)
          .values(captureDecisionRows)
        await transaction.insert(executionLeases).values(leaseRow)
        return { grant, lease }
      },
      { behavior: 'immediate' }
    )
  }

  async claimExecutionLease(input: {
    leaseId: string
    runnerInstanceId: string
    binding: ExecutionClaimBinding
    integrityKey: ExecutionGrantIntegrityKey
  }): Promise<ClaimedExecutionLease> {
    const binding = ExecutionClaimBindingSchema.parse(input.binding)
    const runnerInstanceId = SystemIssuedOpaqueIdSchema.parse(
      input.runnerInstanceId
    )
    const lease = await this.getExecutionLease(input.leaseId)
    const grant = lease
      ? await this.getExecutionGrant(lease.grantId)
      : undefined
    if (!lease || !grant || lease.id !== input.leaseId) {
      throw new Error('Execution lease claim was rejected.')
    }
    const captureDecisionSet = await this.getExecutionCaptureDecisionSet(
      grant.id
    )
    if (
      !captureDecisionSet ||
      !verifyExecutionCaptureDecisionSetHash(
        assertCaptureDecisionSetBinding(captureDecisionSet, grant),
        grant.captureDecisionSetHash
      )
    ) {
      throw new Error('Execution capture decision set verification failed.')
    }
    assertExactClaimBinding(binding, grant)
    if (
      !verifyExecutionGrantIntegrity(
        executionGrantIntegrityBindingForGrant(grant),
        grant.integrityHmac,
        input.integrityKey
      )
    ) {
      throw new Error('Execution grant integrity verification failed.')
    }

    const now = Date.now()
    const claimToken = randomBytes(32).toString('base64url')
    const claimTokenHash = sha256Text(claimToken)
    const native = this.database.native
    let transactionStarted = false
    try {
      native.exec('BEGIN IMMEDIATE')
      transactionStarted = true
      const claimed = native
        .prepare(
          `UPDATE execution_leases
           SET state = 'claimed',
               claimed_at = ?,
               claimed_by = ?,
               claim_token_hash = ?
           WHERE id = ?
             AND state = 'issued'
             AND issued_at <= ?
             AND expires_at > ?
             AND EXISTS (
               SELECT 1
               FROM execution_grants AS grant_row
               INNER JOIN scans AS scan_row
                 ON scan_row.id = grant_row.scan_id
               INNER JOIN targets AS target_row
                 ON target_row.id = scan_row.target_id
               INNER JOIN target_scopes AS scope_row
                 ON scope_row.id = grant_row.scope_snapshot_id
                AND scope_row.target_id = target_row.id
               INNER JOIN scan_module_snapshots AS module_row
                 ON module_row.id = grant_row.module_snapshot_id
                AND module_row.scan_id = scan_row.id
               INNER JOIN policy_decisions AS decision_row
                 ON decision_row.id = grant_row.policy_decision_id
               INNER JOIN probe_proposals AS proposal_row
                 ON proposal_row.id = decision_row.proposal_id
                AND proposal_row.scan_id = scan_row.id
               WHERE grant_row.id = execution_leases.grant_id
                 AND grant_row.id = ?
                 AND grant_row.scan_id = ?
                 AND grant_row.scope_snapshot_id = ?
                 AND grant_row.module_snapshot_id = ?
                 AND grant_row.plan_id = ?
                 AND grant_row.step_id = ?
                 AND json_extract(
                   grant_row.template_intent_hash_json,
                   '$.digest'
                 ) = ?
                 AND json_extract(
                   grant_row.resolved_intent_hash_json,
                   '$.digest'
                 ) = ?
                 AND json_extract(
                   grant_row.wire_request_hmac_json,
                   '$.digest'
                 ) = ?
                 AND grant_row.purpose = ?
                 AND grant_row.adapter_kind = ?
                 AND grant_row.session_ref_json IS NULL
                 AND grant_row.test_object_ref_json IS NULL
                 AND (
                   (
                     grant_row.identity_ref_json IS NULL
                     AND proposal_row.identity_id IS NULL
                   )
                   OR (
                     grant_row.identity_ref_json IS NOT NULL
                     AND proposal_row.identity_id = json_extract(
                       grant_row.identity_ref_json,
                       '$.id'
                     )
                     AND grant_row.owner_ref = target_row.id
                     AND json_extract(
                       grant_row.identity_ref_json,
                       '$.ownerRef'
                     ) = target_row.id
                     AND json_extract(
                       grant_row.identity_ref_json,
                       '$.scopeSnapshotId'
                     ) = grant_row.scope_snapshot_id
                     AND json_extract(
                       grant_row.identity_ref_json,
                       '$.statusSummary'
                     ) = 'active'
                     AND EXISTS (
                       SELECT 1
                       FROM identities AS identity_row
                       INNER JOIN scan_identities AS scan_identity_row
                         ON scan_identity_row.identity_id = identity_row.id
                        AND scan_identity_row.scan_id = scan_row.id
                       WHERE identity_row.id = json_extract(
                           grant_row.identity_ref_json,
                           '$.id'
                         )
                         AND identity_row.target_id = target_row.id
                         AND identity_row.is_test_identity = 1
                         AND identity_row.updated_at = json_extract(
                           grant_row.identity_ref_json,
                           '$.version'
                         )
                         AND (
                           (
                             grant_row.credential_ref_json IS NULL
                             AND (
                               identity_row.credential_id IS NULL
                               OR grant_row.parent_grant_id IS NOT NULL
                             )
                           )
                           OR (
                             identity_row.credential_id = json_extract(
                               grant_row.credential_ref_json,
                               '$.id'
                             )
                             AND json_extract(
                               grant_row.credential_ref_json,
                               '$.kind'
                             ) = 'identity'
                           )
                         )
                         AND EXISTS (
                           SELECT 1
                           FROM json_each(
                             scan_row.config_json,
                             '$.identityIds'
                           ) AS configured_identity
                           WHERE configured_identity.type = 'text'
                             AND configured_identity.value = identity_row.id
                         )
                         AND EXISTS (
                           SELECT 1
                           FROM json_each(
                             scope_row.allowed_identity_ids
                           ) AS allowed_identity
                           WHERE allowed_identity.type = 'text'
                             AND allowed_identity.value = identity_row.id
                         )
                     )
                   )
                 )
                 AND (
                   (
                     grant_row.adapter_kind = 'http'
                     AND EXISTS (
                       SELECT 1
                       FROM json_each(grant_row.capability_ids_json)
                       WHERE value = 'http.reviewed-read'
                     )
                   )
                   OR (
                     grant_row.adapter_kind = 'browser-offline'
                     AND EXISTS (
                       SELECT 1
                       FROM json_each(grant_row.capability_ids_json)
                       WHERE value = 'browser.offline-replay'
                     )
                   )
                 )
                 AND grant_row.valid_from <= ?
                 AND grant_row.valid_until > ?
                 AND scan_row.status = 'running'
                 AND EXISTS (
                   SELECT 1
                   FROM tool_calls AS tool_call_row
                   WHERE tool_call_row.execution_lease_id
                     = execution_leases.id
                     AND tool_call_row.status = 'running'
                 )
                 AND scan_row.module_snapshots_sealed = 1
                 AND scan_row.scope_snapshot_id = grant_row.scope_snapshot_id
                 AND json_valid(scan_row.budget_json)
                 AND json_type(scan_row.budget_json, '$.maxRequests') = 'integer'
                 AND scan_row.request_count
                       + json_extract(grant_row.budget_json, '$.requestUnits')
                     <= json_extract(scan_row.budget_json, '$.maxRequests')
                 AND decision_row.allowed = 1
                 AND decision_row.requires_approval = 0
                 AND decision_row.valid_until IS NOT NULL
                 AND decision_row.valid_until > ?
                 AND decision_row.authorized_wire_request_hmac_json IS NOT NULL
                 AND json_extract(
                   decision_row.authorized_wire_request_hmac_json,
                   '$.domain'
                 ) = json_extract(grant_row.wire_request_hmac_json, '$.domain')
                 AND json_extract(
                   decision_row.authorized_wire_request_hmac_json,
                   '$.algorithm'
                 ) = json_extract(grant_row.wire_request_hmac_json, '$.algorithm')
                 AND json_extract(
                   decision_row.authorized_wire_request_hmac_json,
                   '$.keyRef'
                 ) = json_extract(grant_row.wire_request_hmac_json, '$.keyRef')
                 AND json_extract(
                   decision_row.authorized_wire_request_hmac_json,
                   '$.keyVersion'
                 ) = json_extract(grant_row.wire_request_hmac_json, '$.keyVersion')
                 AND json_extract(
                   decision_row.authorized_wire_request_hmac_json,
                   '$.digest'
                 ) = json_extract(grant_row.wire_request_hmac_json, '$.digest')
                 AND (scope_row.valid_from IS NULL OR scope_row.valid_from <= ?)
                 AND (scope_row.valid_until IS NULL OR scope_row.valid_until > ?)
             )
           RETURNING id`
        )
        .get(
          now,
          runnerInstanceId,
          claimTokenHash,
          input.leaseId,
          now,
          now,
          binding.grantId,
          binding.scanId,
          binding.scopeSnapshotId,
          binding.moduleSnapshotId,
          binding.planId,
          binding.stepId,
          binding.templateIntentHash.digest,
          binding.resolvedIntentHash.digest,
          binding.wireRequestHmac.digest,
          binding.purpose,
          binding.adapterKind,
          now,
          now,
          now,
          now,
          now
        ) as { id: string } | undefined
      if (!claimed) {
        native.exec('ROLLBACK')
        transactionStarted = false
        throw new Error('Execution lease claim was rejected.')
      }
      const usage = native
        .prepare(
          `UPDATE scans AS scan_row
           SET request_count = scan_row.request_count + (
                 SELECT json_extract(grant_row.budget_json, '$.requestUnits')
                 FROM execution_grants AS grant_row
                 WHERE grant_row.id = ?
               ),
               updated_at = ?
           WHERE scan_row.id = ?
             AND scan_row.request_count + (
                   SELECT json_extract(grant_row.budget_json, '$.requestUnits')
                   FROM execution_grants AS grant_row
                   WHERE grant_row.id = ?
                 )
                 <= json_extract(scan_row.budget_json, '$.maxRequests')`
        )
        .run(binding.grantId, now, binding.scanId, binding.grantId)
      if (usage.changes !== 1) {
        native.exec('ROLLBACK')
        transactionStarted = false
        throw new Error('Execution lease claim was rejected.')
      }
      native.exec('COMMIT')
      transactionStarted = false
    } catch (error) {
      if (transactionStarted) native.exec('ROLLBACK')
      throw error
    }

    const claimedLease = await this.getExecutionLease(input.leaseId)
    if (!claimedLease || claimedLease.state !== 'claimed') {
      throw new Error('Claimed execution lease could not be reloaded.')
    }
    return { lease: claimedLease, claimToken }
  }

  async markExecutionLeaseDelivery(input: {
    leaseId: string
    claimToken: string
    deliveryState: 'possibly-sent' | 'response-started'
  }): Promise<ExecutionLease> {
    const tokenHash = sha256Text(input.claimToken)
    const previousDeliveryState =
      input.deliveryState === 'possibly-sent'
        ? 'not-dispatched'
        : 'possibly-sent'
    const now = Date.now()
    const updated = this.database.native
      .prepare(
        `UPDATE execution_leases
         SET delivery_state = ?
         WHERE id = ?
           AND state = 'claimed'
           AND claim_token_hash = ?
           AND delivery_state = ?
           AND expires_at > ?
           AND EXISTS (
             SELECT 1
             FROM execution_grants AS grant_row
             INNER JOIN scans AS scan_row
               ON scan_row.id = grant_row.scan_id
             INNER JOIN targets AS target_row
               ON target_row.id = scan_row.target_id
             INNER JOIN target_scopes AS scope_row
               ON scope_row.id = grant_row.scope_snapshot_id
              AND scope_row.target_id = target_row.id
             INNER JOIN policy_decisions AS decision_row
               ON decision_row.id = grant_row.policy_decision_id
             INNER JOIN probe_proposals AS proposal_row
               ON proposal_row.id = decision_row.proposal_id
              AND proposal_row.scan_id = scan_row.id
             WHERE grant_row.id = execution_leases.grant_id
               AND scan_row.status = 'running'
               AND scan_row.module_snapshots_sealed = 1
               AND scan_row.scope_snapshot_id
                 = grant_row.scope_snapshot_id
               AND decision_row.scope_snapshot_id
                 = grant_row.scope_snapshot_id
               AND EXISTS (
                 SELECT 1
                 FROM tool_calls AS tool_call_row
                 WHERE tool_call_row.execution_lease_id
                   = execution_leases.id
                   AND tool_call_row.status = 'running'
               )
               AND grant_row.session_ref_json IS NULL
               AND grant_row.test_object_ref_json IS NULL
               AND (
                 (
                   grant_row.identity_ref_json IS NULL
                   AND proposal_row.identity_id IS NULL
                 )
                 OR (
                   grant_row.identity_ref_json IS NOT NULL
                   AND proposal_row.identity_id = json_extract(
                     grant_row.identity_ref_json,
                     '$.id'
                   )
                   AND grant_row.owner_ref = target_row.id
                   AND json_extract(
                     grant_row.identity_ref_json,
                     '$.ownerRef'
                   ) = target_row.id
                   AND json_extract(
                     grant_row.identity_ref_json,
                     '$.scopeSnapshotId'
                   ) = grant_row.scope_snapshot_id
                   AND json_extract(
                     grant_row.identity_ref_json,
                     '$.statusSummary'
                   ) = 'active'
                   AND EXISTS (
                     SELECT 1
                     FROM identities AS identity_row
                     INNER JOIN scan_identities AS scan_identity_row
                       ON scan_identity_row.identity_id = identity_row.id
                      AND scan_identity_row.scan_id = scan_row.id
                     WHERE identity_row.id = json_extract(
                         grant_row.identity_ref_json,
                         '$.id'
                       )
                       AND identity_row.target_id = target_row.id
                       AND identity_row.is_test_identity = 1
                       AND identity_row.updated_at = json_extract(
                         grant_row.identity_ref_json,
                         '$.version'
                       )
                       AND (
                         (
                           grant_row.credential_ref_json IS NULL
                           AND (
                             identity_row.credential_id IS NULL
                             OR grant_row.parent_grant_id IS NOT NULL
                           )
                         )
                         OR (
                           identity_row.credential_id = json_extract(
                             grant_row.credential_ref_json,
                             '$.id'
                           )
                           AND json_extract(
                             grant_row.credential_ref_json,
                             '$.kind'
                           ) = 'identity'
                         )
                       )
                       AND EXISTS (
                         SELECT 1
                         FROM json_each(
                           scan_row.config_json,
                           '$.identityIds'
                         ) AS configured_identity
                         WHERE configured_identity.type = 'text'
                           AND configured_identity.value = identity_row.id
                       )
                       AND EXISTS (
                         SELECT 1
                         FROM json_each(
                           scope_row.allowed_identity_ids
                         ) AS allowed_identity
                         WHERE allowed_identity.type = 'text'
                           AND allowed_identity.value = identity_row.id
                       )
                   )
                 )
               )
               AND (
                 (
                   grant_row.adapter_kind = 'http'
                   AND EXISTS (
                     SELECT 1
                     FROM json_each(grant_row.capability_ids_json)
                     WHERE value = 'http.reviewed-read'
                   )
                 )
                 OR (
                   grant_row.adapter_kind = 'browser-offline'
                   AND EXISTS (
                     SELECT 1
                     FROM json_each(grant_row.capability_ids_json)
                     WHERE value = 'browser.offline-replay'
                   )
                 )
               )
               AND json_valid(scan_row.budget_json)
               AND json_type(
                 scan_row.budget_json,
                 '$.maxRequests'
               ) = 'integer'
               AND scan_row.request_count <= json_extract(
                 scan_row.budget_json,
                 '$.maxRequests'
               )
               AND grant_row.valid_from <= ?
               AND grant_row.valid_until > ?
               AND decision_row.allowed = 1
               AND decision_row.requires_approval = 0
               AND decision_row.valid_until IS NOT NULL
               AND decision_row.valid_until > ?
               AND decision_row.authorized_wire_request_hmac_json IS NOT NULL
               AND (
                 SELECT COUNT(*)
                 FROM json_each(
                   decision_row.authorized_wire_request_hmac_json
                 )
               ) = 5
               AND json_extract(
                 decision_row.authorized_wire_request_hmac_json,
                 '$.domain'
               ) = json_extract(
                 grant_row.wire_request_hmac_json,
                 '$.domain'
               )
               AND json_extract(
                 decision_row.authorized_wire_request_hmac_json,
                 '$.algorithm'
               ) = json_extract(
                 grant_row.wire_request_hmac_json,
                 '$.algorithm'
               )
               AND json_extract(
                 decision_row.authorized_wire_request_hmac_json,
                 '$.keyRef'
               ) = json_extract(
                 grant_row.wire_request_hmac_json,
                 '$.keyRef'
               )
               AND json_extract(
                 decision_row.authorized_wire_request_hmac_json,
                 '$.keyVersion'
               ) = json_extract(
                 grant_row.wire_request_hmac_json,
                 '$.keyVersion'
               )
               AND json_extract(
                 decision_row.authorized_wire_request_hmac_json,
                 '$.digest'
               ) = json_extract(
                 grant_row.wire_request_hmac_json,
                 '$.digest'
               )
               AND (scope_row.valid_from IS NULL
                 OR scope_row.valid_from <= ?)
               AND (scope_row.valid_until IS NULL
                 OR scope_row.valid_until > ?)
           )
         RETURNING id`
      )
      .get(
        input.deliveryState,
        input.leaseId,
        tokenHash,
        previousDeliveryState,
        now,
        now,
        now,
        now,
        now,
        now
      ) as { id: string } | undefined
    if (!updated) {
      throw new Error('Execution lease delivery transition was rejected.')
    }
    const lease = await this.getExecutionLease(input.leaseId)
    if (!lease) throw new Error('Execution lease disappeared after delivery transition.')
    return lease
  }

  async finalizeExecutionLease(
    input: FinalizeExecutionLeaseInput
  ): Promise<ExecutionLease> {
    const outcomeSummary = ExecutionLeaseOutcomeSummarySchema.parse(
      input.outcomeSummary
    )
    const leaseId = SystemIssuedOpaqueIdSchema.parse(input.leaseId)
    const evidenceRefs = ExecutionEvidenceRefsSchema.parse(input.evidenceRefs)
    const expectedExecutionState =
      input.state === 'completed'
        ? 'succeeded'
        : input.terminalReason === 'cancelled'
          ? 'cancelled'
          : input.terminalReason === 'timed-out'
            ? 'timed-out'
            : 'failed'
    if (
      outcomeSummary.deliveryState !== input.deliveryState ||
      outcomeSummary.executionState !== expectedExecutionState ||
      input.terminalReason === 'interrupted' ||
      (input.state === 'completed' &&
        (input.terminalReason !== 'completed' ||
          input.deliveryState !== 'completed' ||
          outcomeSummary.executionState !== 'succeeded')) ||
      (input.state === 'failed' &&
        (input.terminalReason === 'completed' ||
          input.terminalReason === 'expired' ||
          input.terminalReason === 'revoked' ||
          input.deliveryState === 'completed'))
    ) {
      throw new Error('Execution lease terminal input is inconsistent.')
    }
    const tokenHash = sha256Text(input.claimToken)
    const now = Date.now()
    return this.database.orm.transaction(
      async (transaction) => {
        const [context] = await transaction
          .select({
            lease: executionLeases,
            grant: executionGrants
          })
          .from(executionLeases)
          .innerJoin(
            executionGrants,
            eq(executionGrants.id, executionLeases.grantId)
          )
          .where(
            and(
              eq(executionLeases.id, leaseId),
              eq(executionLeases.state, 'claimed'),
              eq(executionLeases.claimTokenHash, tokenHash)
            )
          )
          .limit(1)
        if (
          !context ||
          (input.state === 'completed'
            ? context.lease.deliveryState !== 'response-started'
            : context.lease.deliveryState !== input.deliveryState)
        ) {
          throw new Error('Execution lease delivery finalization was rejected.')
        }
        const grant = mapExecutionGrant(context.grant)
        const dispatched = input.deliveryState !== 'not-dispatched'
        if (
          (outcomeSummary.wireRequestHmacDigest !== undefined &&
            outcomeSummary.wireRequestHmacDigest !==
              grant.wireRequestHmac.digest) ||
          (outcomeSummary.requestBytes !== undefined &&
            outcomeSummary.requestBytes !== grant.budget.requestBytes) ||
          (outcomeSummary.responseBytes !== undefined &&
            outcomeSummary.responseBytes > grant.budget.maxResponseBytes) ||
          (dispatched &&
            (outcomeSummary.wireRequestHmacDigest === undefined ||
              outcomeSummary.requestBytes === undefined)) ||
          (input.state === 'completed' &&
            outcomeSummary.responseBytes === undefined)
        ) {
          throw new Error(
            'Execution outcome does not match the immutable wire proof and budget.'
          )
        }
        const linked = await transaction
          .select({
            evidenceId: executionLeaseEvidence.evidenceId,
            executionState: executionCaptureDecisions.executionState,
            captureSource: executionCaptureDecisions.source,
            evidenceType: evidenceItems.type,
            evidenceSource: evidenceItems.source,
            redactionState: evidenceItems.redactionState,
            integrityStatus: evidenceItems.integrityStatus
          })
          .from(executionLeaseEvidence)
          .innerJoin(
            executionCaptureDecisions,
            eq(
              executionCaptureDecisions.id,
              executionLeaseEvidence.captureDecisionId
            )
          )
          .innerJoin(
            evidenceItems,
            eq(evidenceItems.id, executionLeaseEvidence.evidenceId)
          )
          .where(eq(executionLeaseEvidence.leaseId, leaseId))
        const requestedEvidence = new Set(evidenceRefs)
        if (
          linked.length !== evidenceRefs.length ||
          linked.some(
            ({
              evidenceId,
              executionState,
              captureSource,
              evidenceType,
              evidenceSource,
              redactionState,
              integrityStatus
            }) =>
              !requestedEvidence.has(evidenceId) ||
              executionState !== outcomeSummary.executionState ||
              evidenceType !== 'evidence-capture-hash-only' ||
              evidenceSource !== captureSource ||
              redactionState !== 'redacted' ||
              integrityStatus !== 'verified'
          ) ||
          (dispatched &&
            outcomeSummary.errorCode !==
              'execution.audit-persistence-failed' &&
            linked.length !== 2) ||
          (input.state === 'completed' && linked.length !== 2)
        ) {
          throw new Error(
            'Execution evidence must exactly match the terminal capture state.'
          )
        }
        const [updated] = await transaction
          .update(executionLeases)
          .set({
            state: input.state,
            deliveryState: input.deliveryState,
            terminalAt: now,
            terminalReason: input.terminalReason,
            outcomeSummary,
            evidenceRefs: [...evidenceRefs]
          })
          .where(
            and(
              eq(executionLeases.id, leaseId),
              eq(executionLeases.state, 'claimed'),
              eq(executionLeases.claimTokenHash, tokenHash)
            )
          )
          .returning()
        if (!updated) {
          throw new Error('Execution lease finalization was rejected.')
        }
        const terminalToolCalls = await transaction
          .update(toolCalls)
          .set({
            status:
              input.state === 'completed'
                ? 'succeeded'
                : input.terminalReason === 'cancelled'
                  ? 'cancelled'
                  : 'failed',
            error:
              input.state === 'completed' ? null : input.terminalReason
          })
          .where(
            and(
              eq(toolCalls.executionLeaseId, leaseId),
              eq(toolCalls.status, 'running')
            )
          )
          .returning({ id: toolCalls.id })
        if (terminalToolCalls.length !== 1) {
          throw new Error('Execution ToolCall finalization was rejected.')
        }
        return mapExecutionLease(updated)
      },
      { behavior: 'immediate' }
    )
  }

  async revokeExecutionLease(input: {
    leaseId: string
    reason: 'revoked' | 'guard-rejected' | 'unsupported-adapter'
  }): Promise<ExecutionLease> {
    const leaseId = SystemIssuedOpaqueIdSchema.parse(input.leaseId)
    return this.database.orm.transaction(
      async (transaction) => {
        const [updated] = await transaction
          .update(executionLeases)
          .set({
            state: 'revoked',
            terminalAt: Date.now(),
            terminalReason: input.reason
          })
          .where(
            and(
              eq(executionLeases.id, leaseId),
              eq(executionLeases.state, 'issued')
            )
          )
          .returning()
        if (!updated) {
          throw new Error('Execution lease revocation was rejected.')
        }
        await transaction
          .update(toolCalls)
          .set({ status: 'failed', error: input.reason })
          .where(
            and(
              eq(toolCalls.executionLeaseId, leaseId),
              eq(toolCalls.status, 'running')
            )
          )
        return mapExecutionLease(updated)
      },
      { behavior: 'immediate' }
    )
  }

  async expireIssuedExecutionLeases(): Promise<ExecutionLease[]> {
    const now = Date.now()
    return this.database.orm.transaction(
      async (transaction) => {
        const rows = await transaction
          .update(executionLeases)
          .set({
            state: 'expired',
            terminalAt: now,
            terminalReason: 'expired'
          })
          .where(
            and(
              eq(executionLeases.state, 'issued'),
              lte(executionLeases.expiresAt, now)
            )
          )
          .returning()
        const leaseIds = rows.map(({ id }) => id)
        if (leaseIds.length > 0) {
          await transaction
            .update(toolCalls)
            .set({ status: 'failed', error: 'expired' })
            .where(
              and(
                inArray(toolCalls.executionLeaseId, leaseIds),
                eq(toolCalls.status, 'running')
              )
            )
        }
        return rows.map(mapExecutionLease)
      },
      { behavior: 'immediate' }
    )
  }

  async listClaimedExecutionLeasesForRecovery(): Promise<
    InterruptedExecutionRecoveryContext[]
  > {
    const rows = await this.database.orm
      .select()
      .from(executionLeases)
      .where(eq(executionLeases.state, 'claimed'))
      .orderBy(asc(executionLeases.id))
    const contexts: InterruptedExecutionRecoveryContext[] = []
    for (const row of rows) {
      const lease = mapExecutionLease(row)
      const grant = await this.getExecutionGrant(lease.grantId)
      const captureDecisionSet = grant
        ? await this.getExecutionCaptureDecisionSet(grant.id)
        : undefined
      const captureDecision = captureDecisionSet?.decisions.find(
        (decision) =>
          decision.source === 'execution-interruption-summary' &&
          decision.executionState === 'interrupted'
      )
      const [runningToolCall] = await this.database.orm
        .select({ id: toolCalls.id })
        .from(toolCalls)
        .where(
          and(
            eq(toolCalls.executionLeaseId, lease.id),
            eq(toolCalls.status, 'running')
          )
        )
        .limit(1)
      const [recoveryAuthority] = grant
        ? await this.database.orm
            .select({ scanId: scans.id })
            .from(scans)
            .innerJoin(targets, eq(targets.id, scans.targetId))
            .innerJoin(
              targetScopes,
              and(
                eq(targetScopes.id, grant.scopeSnapshotId),
                eq(targetScopes.targetId, targets.id)
              )
            )
            .innerJoin(
              policyDecisions,
              and(
                eq(policyDecisions.id, grant.policyDecisionId),
                eq(
                  policyDecisions.scopeSnapshotId,
                  grant.scopeSnapshotId
                )
              )
            )
            .innerJoin(
              probeProposals,
              and(
                eq(
                  probeProposals.id,
                  policyDecisions.proposalId
                ),
                eq(probeProposals.scanId, scans.id)
              )
            )
            .where(eq(scans.id, grant.scanId))
            .limit(1)
        : []
      if (
        !grant ||
        !captureDecisionSet ||
        !captureDecision ||
        !runningToolCall ||
        !recoveryAuthority ||
        !verifyExecutionCaptureDecisionSetHash(
          assertCaptureDecisionSetBinding(captureDecisionSet, grant),
          grant.captureDecisionSetHash
        )
      ) {
        throw new Error(
          'Interrupted execution recovery proof verification failed.'
        )
      }
      contexts.push({ lease, grant, captureDecision })
    }
    return contexts
  }

  async listInterruptedExecutionLeasesForScanRecovery(): Promise<
    InterruptedExecutionScanRecoveryContext[]
  > {
    const rows = await this.database.orm
      .select()
      .from(executionLeases)
      .where(
        and(
          eq(executionLeases.state, 'failed'),
          eq(executionLeases.terminalReason, 'interrupted'),
          eq(executionLeases.deliveryState, 'unknown')
        )
      )
      .orderBy(asc(executionLeases.id))
    const contexts: InterruptedExecutionScanRecoveryContext[] = []
    for (const row of rows) {
      const lease = mapExecutionLease(row)
      const grant = await this.getExecutionGrant(lease.grantId)
      const captureDecisionSet = grant
        ? await this.getExecutionCaptureDecisionSet(grant.id)
        : undefined
      const interruptionDecision = captureDecisionSet?.decisions.find(
        (decision) =>
          decision.source === 'execution-interruption-summary' &&
          decision.executionState === 'interrupted' &&
          decision.role === 'interruption-summary'
      )
      const terminalToolCalls = await this.database.orm
        .select({ id: toolCalls.id })
        .from(toolCalls)
        .where(
          and(
            eq(toolCalls.executionLeaseId, lease.id),
            eq(toolCalls.status, 'failed'),
            eq(toolCalls.error, 'interrupted')
          )
        )
      const [recoveryAuthority] = grant
        ? await this.database.orm
            .select({ scanId: scans.id })
            .from(scans)
            .innerJoin(targets, eq(targets.id, scans.targetId))
            .innerJoin(
              targetScopes,
              and(
                eq(targetScopes.id, grant.scopeSnapshotId),
                eq(targetScopes.targetId, targets.id)
              )
            )
            .innerJoin(
              policyDecisions,
              and(
                eq(policyDecisions.id, grant.policyDecisionId),
                eq(
                  policyDecisions.scopeSnapshotId,
                  grant.scopeSnapshotId
                )
              )
            )
            .innerJoin(
              probeProposals,
              and(
                eq(probeProposals.id, policyDecisions.proposalId),
                eq(probeProposals.scanId, scans.id)
              )
            )
            .where(eq(scans.id, grant.scanId))
            .limit(1)
        : []
      const evidenceLinks = await this.listExecutionLeaseEvidence(lease.id)
      const interruptionLinks = interruptionDecision
        ? evidenceLinks.filter(
            (link) =>
              link.captureDecisionId === interruptionDecision.id &&
              link.role === 'interruption-summary'
          )
        : []
      const linkedEvidenceIds = new Set(
        evidenceLinks.map(({ evidenceId }) => evidenceId)
      )
      if (
        !grant ||
        !captureDecisionSet ||
        !interruptionDecision ||
        terminalToolCalls.length !== 1 ||
        !recoveryAuthority ||
        !verifyExecutionCaptureDecisionSetHash(
          assertCaptureDecisionSetBinding(captureDecisionSet, grant),
          grant.captureDecisionSetHash
        ) ||
        evidenceLinks.length !== lease.evidenceRefs.length ||
        lease.evidenceRefs.some(
          (evidenceId) => !linkedEvidenceIds.has(evidenceId)
        ) ||
        interruptionLinks.length > 1
      ) {
        throw new Error(
          'Interrupted execution scan recovery proof verification failed.'
        )
      }
      contexts.push({
        lease,
        grant,
        ...(interruptionLinks[0]
          ? { interruptionEvidenceId: interruptionLinks[0].evidenceId }
          : {})
      })
    }
    return contexts
  }

  async recoverInterruptedExecutionLeaseWithCleanup(
    input: RecoverInterruptedExecutionLeaseWithCleanupInput
  ): Promise<InterruptedExecutionRecoveryResult> {
    const leaseId = SystemIssuedOpaqueIdSchema.parse(input.leaseId)
    const evidenceId =
      input.evidenceId === undefined
        ? undefined
        : SystemIssuedOpaqueIdSchema.parse(input.evidenceId)
    const discardUnboundEvidenceId =
      input.discardUnboundEvidenceId === undefined
        ? undefined
        : SystemIssuedOpaqueIdSchema.parse(input.discardUnboundEvidenceId)
    if (evidenceId && discardUnboundEvidenceId) {
      throw new Error(
        'Interrupted execution recovery cannot bind and discard the same artifact.'
      )
    }
    const lease = await this.getExecutionLease(leaseId)
    const grant = lease
      ? await this.getExecutionGrant(lease.grantId)
      : undefined
    const captureDecisionSet = grant
      ? await this.getExecutionCaptureDecisionSet(grant.id)
      : undefined
    if (
      !lease ||
      lease.state !== 'claimed' ||
      !grant ||
      !captureDecisionSet ||
      !verifyExecutionCaptureDecisionSetHash(
        assertCaptureDecisionSetBinding(captureDecisionSet, grant),
        grant.captureDecisionSetHash
      )
    ) {
      throw new Error(
        'Interrupted execution recovery proof verification failed.'
      )
    }
    const now = Date.now()
    const outcome = ExecutionLeaseOutcomeSummarySchema.parse({
      executionState: 'interrupted',
      deliveryState: 'unknown',
      verdictImpact: 'inconclusive',
      errorCode: 'execution.interrupted'
    })
    return this.database.orm.transaction(
      async (transaction) => {
        const [current] = await transaction
          .select({
            lease: executionLeases,
            grant: executionGrants
          })
          .from(executionLeases)
          .innerJoin(
            executionGrants,
            eq(executionGrants.id, executionLeases.grantId)
          )
          .innerJoin(
            scans,
            eq(scans.id, executionGrants.scanId)
          )
          .innerJoin(targets, eq(targets.id, scans.targetId))
          .innerJoin(
            targetScopes,
            and(
              eq(targetScopes.id, executionGrants.scopeSnapshotId),
              eq(targetScopes.targetId, targets.id)
            )
          )
          .innerJoin(
            policyDecisions,
            and(
              eq(
                policyDecisions.id,
                executionGrants.policyDecisionId
              ),
              eq(
                policyDecisions.scopeSnapshotId,
                executionGrants.scopeSnapshotId
              )
            )
          )
          .innerJoin(
            probeProposals,
            and(
              eq(
                probeProposals.id,
                policyDecisions.proposalId
              ),
              eq(probeProposals.scanId, scans.id)
            )
          )
          .where(
            and(
              eq(executionLeases.id, leaseId),
              eq(executionLeases.state, 'claimed'),
              eq(executionGrants.id, grant.id)
            )
          )
          .limit(1)
        if (!current) {
          throw new Error('Interrupted execution is no longer recoverable.')
        }
        const [interruptionDecision] = await transaction
          .select()
          .from(executionCaptureDecisions)
          .where(
            and(
              eq(executionCaptureDecisions.grantId, grant.id),
              eq(
                executionCaptureDecisions.source,
                'execution-interruption-summary'
              ),
              eq(executionCaptureDecisions.executionState, 'interrupted')
            )
          )
          .limit(1)
        if (
          !interruptionDecision ||
          interruptionDecision.role !== 'interruption-summary' ||
          interruptionDecision.action !== 'hash-only'
        ) {
          throw new Error(
            'Interrupted execution capture authority is unavailable.'
          )
        }
        const discardedEvidence: DiscardedExecutionEvidence[] = []
        const discardCandidate = async (
          candidate: typeof evidenceItems.$inferSelect
        ): Promise<boolean> => {
          if (
            isEvidenceItemReferenced(
              this.database.native,
              candidate.id
            )
          ) {
            return false
          }
          const [discarded] = await transaction
            .delete(evidenceItems)
            .where(
              and(
                eq(evidenceItems.id, candidate.id),
                eq(evidenceItems.scanId, grant.scanId),
                eq(
                  evidenceItems.policyDecisionId,
                  grant.policyDecisionId
                ),
                isNull(evidenceItems.interactionId)
              )
            )
            .returning({
              id: evidenceItems.id,
              filePath: evidenceItems.filePath,
              sha256: evidenceItems.sha256
            })
          if (!discarded) return false
          discardedEvidence.push(discarded)
          return true
        }
        if (evidenceId) {
          await transaction
            .insert(executionLeaseEvidence)
            .values({
              leaseId,
              evidenceId,
              captureDecisionId: interruptionDecision.id,
              role: interruptionDecision.role,
              ordinal: 0
            })
            .onConflictDoNothing()
          const [interruptionEvidenceLink] = await transaction
            .select()
            .from(executionLeaseEvidence)
            .where(
              and(
                eq(executionLeaseEvidence.leaseId, leaseId),
                eq(
                  executionLeaseEvidence.captureDecisionId,
                  interruptionDecision.id
                )
              )
            )
            .limit(1)
          if (
            !interruptionEvidenceLink ||
            interruptionEvidenceLink.evidenceId !== evidenceId
          ) {
            throw new Error(
              'Interrupted execution evidence is already bound elsewhere.'
            )
          }
        }
        if (discardUnboundEvidenceId) {
          const [candidate] = await transaction
            .select()
            .from(evidenceItems)
            .where(eq(evidenceItems.id, discardUnboundEvidenceId))
            .limit(1)
          if (
            !candidate ||
            candidate.scanId !== grant.scanId ||
            candidate.policyDecisionId !== grant.policyDecisionId ||
            candidate.interactionId !== null ||
            candidate.type !== 'evidence-capture-hash-only' ||
            candidate.mimeType !== 'application/json' ||
            candidate.source !== interruptionDecision.source ||
            candidate.createdBy !== 'application-service' ||
            candidate.captureTool !== 'evidence-capture-policy' ||
            candidate.redactionState !== 'redacted' ||
            candidate.integrityStatus !== 'verified' ||
            !(await discardCandidate(candidate))
          ) {
            throw new Error(
              'Unbound interruption Evidence is not eligible for atomic discard.'
            )
          }
        }
        if (input.discardUnboundStagedEvidence) {
          const authorizedCaptureSources = [
            ...new Set(
              captureDecisionSet.decisions.map(({ source }) => source)
            )
          ]
          const stagedEvidence = await transaction
            .select()
            .from(evidenceItems)
            .where(
              and(
                eq(evidenceItems.scanId, grant.scanId),
                eq(
                  evidenceItems.policyDecisionId,
                  grant.policyDecisionId
                ),
                isNull(evidenceItems.interactionId),
                eq(evidenceItems.type, 'evidence-capture-hash-only'),
                eq(evidenceItems.mimeType, 'application/json'),
                eq(evidenceItems.captureTool, 'evidence-capture-policy'),
                eq(evidenceItems.redactionState, 'redacted'),
                eq(evidenceItems.integrityStatus, 'verified'),
                or(
                  and(
                    eq(evidenceItems.createdBy, 'execution-service'),
                    inArray(
                      evidenceItems.source,
                      authorizedCaptureSources
                    )
                  ),
                  and(
                    eq(evidenceItems.createdBy, 'application-service'),
                    eq(
                      evidenceItems.source,
                      interruptionDecision.source
                    )
                  )
                )
              )
            )
            .orderBy(asc(evidenceItems.createdAt), asc(evidenceItems.id))
          for (const candidate of stagedEvidence) {
            if (candidate.id === evidenceId) continue
            await discardCandidate(candidate)
          }
        }
        const captureEvidence = await transaction
          .select({ evidenceId: executionLeaseEvidence.evidenceId })
          .from(executionLeaseEvidence)
          .where(eq(executionLeaseEvidence.leaseId, leaseId))
          .orderBy(
            asc(executionLeaseEvidence.ordinal),
            asc(executionLeaseEvidence.evidenceId)
          )
        const evidenceRefs = ExecutionEvidenceRefsSchema.parse(
          captureEvidence.map(({ evidenceId: id }) => id)
        )
        const [updated] = await transaction
          .update(executionLeases)
          .set({
            state: 'failed',
            deliveryState: 'unknown',
            terminalAt: now,
            terminalReason: 'interrupted',
            outcomeSummary: outcome,
            evidenceRefs: [...evidenceRefs]
          })
          .where(
            and(
              eq(executionLeases.id, leaseId),
              eq(executionLeases.state, 'claimed')
            )
          )
          .returning()
        if (!updated) {
          throw new Error('Interrupted execution recovery was rejected.')
        }
        const terminalToolCalls = await transaction
          .update(toolCalls)
          .set({ status: 'failed', error: 'interrupted' })
          .where(
            and(
              eq(toolCalls.executionLeaseId, leaseId),
              eq(toolCalls.status, 'running')
            )
          )
          .returning({ id: toolCalls.id })
        if (terminalToolCalls.length !== 1) {
          throw new Error(
            'Interrupted execution ToolCall finalization was rejected.'
          )
        }
        return Object.freeze({
          lease: mapExecutionLease(updated),
          discardedEvidence: Object.freeze([...discardedEvidence])
        })
      },
      { behavior: 'immediate' }
    )
  }

  async recoverInterruptedExecutionLease(
    input: RecoverInterruptedExecutionLeaseInput
  ): Promise<ExecutionLease> {
    return (
      await this.recoverInterruptedExecutionLeaseWithCleanup({
        ...input,
        discardUnboundStagedEvidence: false
      })
    ).lease
  }

  async recoverInterruptedExecutionLeaseWithEvidence(
    input: RecoverInterruptedExecutionLeaseWithEvidenceInput
  ): Promise<ExecutionLease> {
    return (
      await this.recoverInterruptedExecutionLeaseWithCleanup({
        ...input,
        discardUnboundStagedEvidence: false
      })
    ).lease
  }

  issueReplacementExecutionLease(input: {
    grantId: string
    previousLeaseId: string
    expiresAt: string
    integrityKey: ExecutionGrantIntegrityKey
  }): Promise<ExecutionLease> {
    const now = Date.now()
    const expiresAt = Date.parse(input.expiresAt)
    return this.database.orm.transaction(
      async (transaction) => {
        const [grantRow] = await transaction
          .select()
          .from(executionGrants)
          .where(eq(executionGrants.id, input.grantId))
          .limit(1)
        const [previous] = await transaction
          .select()
          .from(executionLeases)
          .where(eq(executionLeases.id, input.previousLeaseId))
          .limit(1)
        const [latest] = await transaction
          .select({ attempt: executionLeases.attempt })
          .from(executionLeases)
          .where(eq(executionLeases.grantId, input.grantId))
          .orderBy(desc(executionLeases.attempt))
          .limit(1)
        const captureRows = await transaction
          .select({ decision: executionCaptureDecisions.decision })
          .from(executionCaptureDecisions)
          .where(eq(executionCaptureDecisions.grantId, input.grantId))
          .orderBy(
            asc(executionCaptureDecisions.source),
            asc(executionCaptureDecisions.executionState)
          )
        const storedGrant = grantRow
          ? mapExecutionGrant(grantRow)
          : undefined
        const captureDecisionSet =
          captureRows.length > 0
            ? ExecutionCaptureDecisionSetSchema.parse({
                schemaVersion: 'execution-capture-decision-set.v1',
                decisions: captureRows.map(({ decision }) => decision)
              })
            : undefined
        if (
          !grantRow ||
          !storedGrant ||
          !captureDecisionSet ||
          !verifyExecutionGrantIntegrity(
            executionGrantIntegrityBindingForGrant(storedGrant),
            storedGrant.integrityHmac,
            input.integrityKey
          ) ||
          !verifyExecutionCaptureDecisionSetHash(
            assertCaptureDecisionSetBinding(
              captureDecisionSet,
              storedGrant
            ),
            storedGrant.captureDecisionSetHash
          ) ||
          !previous ||
          previous.grantId !== grantRow.id ||
          previous.attempt !== latest?.attempt ||
          previous.state !== 'failed' ||
          previous.deliveryState !== 'not-dispatched' ||
          grantRow.retryClass !== 'deterministic-readonly' ||
          grantRow.purpose !== 'read' ||
          grantRow.validFrom > now ||
          grantRow.validUntil <= now ||
          !Number.isFinite(expiresAt) ||
          expiresAt <= now ||
          expiresAt > grantRow.validUntil
        ) {
          throw new Error(
            'Execution replacement requires an eligible deterministic read with proven non-delivery.'
          )
        }
        const row: typeof executionLeases.$inferInsert = {
          schemaVersion: 'execution-lease.v1',
          id: randomUUID(),
          grantId: grantRow.id,
          parentLeaseId: previous.id,
          attempt: previous.attempt + 1,
          state: 'issued',
          issuedAt: now,
          expiresAt,
          claimedAt: null,
          claimedBy: null,
          claimTokenHash: null,
          deliveryState: 'not-dispatched',
          terminalAt: null,
          terminalReason: null,
          outcomeSummary: null,
          evidenceRefs: []
        }
        const [inserted] = await transaction
          .insert(executionLeases)
          .values(row)
          .returning()
        if (!inserted) {
          throw new Error('Replacement execution lease was not persisted.')
        }
        return mapExecutionLease(inserted)
      },
      { behavior: 'immediate' }
    )
  }

  async recordExecutionInteractionAudit(
    input: RecordExecutionInteractionAuditInput
  ): Promise<string> {
    const leaseId = SystemIssuedOpaqueIdSchema.parse(input.leaseId)
    const interactionId = SystemIssuedOpaqueIdSchema.parse(
      input.interaction.id ?? randomUUID()
    )
    const claimTokenHash = sha256Text(input.claimToken)
    const links = input.evidenceLinks.map((inputLink) => ({
      leaseId: SystemIssuedOpaqueIdSchema.parse(inputLink.leaseId),
      evidenceId: SystemIssuedOpaqueIdSchema.parse(inputLink.evidenceId),
      captureDecisionId: SystemIssuedOpaqueIdSchema.parse(
        inputLink.captureDecisionId
      ),
      role: inputLink.role,
      ordinal: inputLink.ordinal
    }))
    if (
      links.length !== 2 ||
      links.some(
        (link) =>
          link.leaseId !== leaseId ||
          link.role !== link.role.trim() ||
          link.role.length < 1 ||
          link.role.length > 100 ||
          !Number.isSafeInteger(link.ordinal) ||
          link.ordinal !== 0
      ) ||
      new Set(links.map(({ evidenceId }) => evidenceId)).size !== 2 ||
      new Set(links.map(({ captureDecisionId }) => captureDecisionId)).size !==
        2 ||
      links[0]!.evidenceId !== input.interaction.requestRef ||
      links[1]!.evidenceId !== input.interaction.responseRef ||
      links[0]!.role !== 'request-summary' ||
      (links[1]!.role !== 'response-summary' &&
        links[1]!.role !== 'result-summary')
    ) {
      throw new Error('Execution interaction audit binding is invalid.')
    }
    return this.database.orm.transaction(
      async (transaction) => {
        const [context] = await transaction
          .select({
            lease: executionLeases,
            grant: executionGrants
          })
          .from(executionLeases)
          .innerJoin(
            executionGrants,
            eq(executionGrants.id, executionLeases.grantId)
          )
          .where(
            and(
              eq(executionLeases.id, leaseId),
              eq(executionLeases.state, 'claimed'),
              eq(executionLeases.claimTokenHash, claimTokenHash)
            )
          )
          .limit(1)
        if (
          !context ||
          input.interaction.scanId !== context.grant.scanId ||
          input.interaction.policyDecisionId !==
            context.grant.policyDecisionId ||
          (context.grant.identityRef?.id ?? undefined) !==
            input.interaction.identityId
        ) {
          throw new Error('Execution interaction authority is invalid.')
        }
        const captureRows = await transaction
          .select()
          .from(executionCaptureDecisions)
          .where(
            inArray(
              executionCaptureDecisions.id,
              links.map(({ captureDecisionId }) => captureDecisionId)
            )
          )
        const captureById = new Map(
          captureRows.map((capture) => [capture.id, capture])
        )
        if (
          captureRows.length !== 2 ||
          links.some(
            (link) => {
              const capture = captureById.get(link.captureDecisionId)
              return (
                !capture ||
                capture.grantId !== context.grant.id ||
                capture.role !== link.role
              )
            }
          ) ||
          new Set(captureRows.map(({ executionState }) => executionState))
            .size !== 1
        ) {
          throw new Error('Execution capture authority is invalid.')
        }
        const evidenceRows = await transaction
          .select()
          .from(evidenceItems)
          .where(
            inArray(
              evidenceItems.id,
              links.map(({ evidenceId }) => evidenceId)
            )
          )
        if (
          evidenceRows.length !== 2 ||
          evidenceRows.some(
            (evidence) =>
              evidence.scanId !== context.grant.scanId ||
              evidence.policyDecisionId !== context.grant.policyDecisionId ||
              evidence.interactionId !== null
          )
        ) {
          throw new Error('Execution evidence authority is invalid.')
        }
        await transaction.insert(executionLeaseEvidence).values(links)
        const evidenceRefs = links.map(({ evidenceId }) => evidenceId)
        const [leaseWithEvidence] = await transaction
          .update(executionLeases)
          .set({ evidenceRefs })
          .where(
            and(
              eq(executionLeases.id, leaseId),
              eq(executionLeases.state, 'claimed'),
              eq(executionLeases.claimTokenHash, claimTokenHash)
            )
          )
          .returning({ id: executionLeases.id })
        if (!leaseWithEvidence) {
          throw new Error('Execution lease evidence synchronization failed.')
        }
        await transaction.insert(interactions).values({
          id: interactionId,
          scanId: input.interaction.scanId,
          endpointId: input.interaction.endpointId ?? null,
          identityId: input.interaction.identityId ?? null,
          policyDecisionId: input.interaction.policyDecisionId,
          executionLeaseId: leaseId,
          requestRef: input.interaction.requestRef,
          responseRef: input.interaction.responseRef,
          requestSummaryJson: input.interaction.requestSummary,
          responseSummaryJson: input.interaction.responseSummary,
          statusCode: input.interaction.statusCode ?? null,
          durationMs: input.interaction.durationMs ?? null,
          stateBeforeHash: input.interaction.stateBeforeHash ?? null,
          stateAfterHash: input.interaction.stateAfterHash ?? null,
          createdAt: Date.now()
        })
        const attachedEvidence = await transaction
          .update(evidenceItems)
          .set({ interactionId })
          .where(
            and(
              inArray(evidenceItems.id, evidenceRefs),
              isNull(evidenceItems.interactionId)
            )
          )
          .returning({ id: evidenceItems.id })
        if (attachedEvidence.length !== 2) {
          throw new Error('Execution evidence interaction attachment failed.')
        }
        return interactionId
      },
      { behavior: 'immediate' }
    )
  }

  async listExecutionLeaseEvidence(
    leaseId: string
  ): Promise<ExecutionLeaseEvidenceLink[]> {
    return this.database.orm
      .select({
        leaseId: executionLeaseEvidence.leaseId,
        evidenceId: executionLeaseEvidence.evidenceId,
        captureDecisionId: executionLeaseEvidence.captureDecisionId,
        role: executionLeaseEvidence.role,
        ordinal: executionLeaseEvidence.ordinal
      })
      .from(executionLeaseEvidence)
      .innerJoin(
        evidenceItems,
        eq(executionLeaseEvidence.evidenceId, evidenceItems.id)
      )
      .where(eq(executionLeaseEvidence.leaseId, leaseId))
      .orderBy(
        asc(executionLeaseEvidence.ordinal),
        asc(executionLeaseEvidence.evidenceId)
      )
  }
}
