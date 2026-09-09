import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import {
  ActorContextSchema,
  ApprovalRecordViewSchema,
  type ActorContext,
  type ActorContextPayload,
  type ApprovalMode,
  type ApprovalProposal,
  type ApprovalReasonCode,
  type ApprovalRecordView,
  type L2ActionBundle,
  type L2BundleStep
} from '@agentgo/contracts'
import {
  actorContextPayloadHash,
  attachActorProofHandle,
  hashL2Value,
  sealApprovalProposal,
  sealApprovalRecord,
  unsignedActorContext
} from '@agentgo/domain'
import type { IdentitySessionRepository } from '@agentgo/db'
import type { L2BindingService } from './l2-binding-service'
import {
  L2ProtocolError,
  L2ProtocolService,
  type L2BundleView
} from './l2-protocol-service'

const HMAC_KEY_BYTES = 32
const ACTOR_TTL_MS = 30 * 60_000
const PROPOSAL_TTL_MS = 15 * 60_000
const APPROVAL_TTL_MS = 15 * 60_000

export class ApprovalError extends Error {
  readonly reasonCode: ApprovalReasonCode

  constructor(reasonCode: ApprovalReasonCode, message: string) {
    super(message)
    this.name = 'ApprovalError'
    this.reasonCode = reasonCode
  }
}

export interface ApprovalDecisionResult {
  readonly ok: true
  readonly view: ApprovalRecordView
  readonly ignoredUserApproved: boolean
}

export interface ApprovalDenialResult {
  readonly ok: false
  readonly reasonCode: ApprovalReasonCode
  readonly message: string
}

export type ApprovalPortResult = ApprovalDecisionResult | ApprovalDenialResult

export interface ApprovalPort {
  createProposal(bundleId: string, bundleVersion: number): Promise<ApprovalProposal>
  getProposal(proposalId: string): Promise<ApprovalProposal | undefined>
  approve(input: ApprovalDecisionInput): Promise<ApprovalPortResult>
  reject(input: ApprovalDecisionInput): Promise<ApprovalPortResult>
  revoke(input: ApprovalRevokeInput): Promise<ApprovalPortResult>
}

export interface ApprovalDecisionInput {
  readonly actor: ActorContext
  readonly proposalId: string
  /**
   * Legacy field. Never authorizes. When true the trusted actor decision
   * still proceeds (if otherwise valid) and the ignore is recorded.
   */
  readonly userApproved?: boolean
}

export interface ApprovalRevokeInput {
  readonly actor: ActorContext
  readonly approvalId: string
  readonly reason: string
}

export interface ApprovalServiceDependencies {
  readonly identitySessionRepository: IdentitySessionRepository
  readonly l2ProtocolService: L2ProtocolService
  readonly bindingService: L2BindingService
  readonly approvalMode: ApprovalMode
  readonly now?: () => Date
}

/**
 * Backend-only approval boundary. ActorContext proof handles are HMAC'd with
 * a process-local key; Renderer, Agent, and ordinary IPC cannot mint them.
 * Product composition must use `trusted-backend` and must not register
 * `FixtureApprovalAdapter`.
 */
export class ApprovalService implements ApprovalPort {
  readonly #identitySessions: IdentitySessionRepository
  readonly #l2: L2ProtocolService
  readonly #bindings: L2BindingService
  readonly #mode: ApprovalMode
  readonly #now: () => Date
  readonly #hmacKey: Uint8Array
  readonly #revokedActors = new Set<string>()

  constructor(dependencies: ApprovalServiceDependencies) {
    this.#identitySessions = dependencies.identitySessionRepository
    this.#l2 = dependencies.l2ProtocolService
    this.#bindings = dependencies.bindingService
    this.#mode = dependencies.approvalMode
    this.#now = dependencies.now ?? (() => new Date())
    this.#hmacKey = randomBytes(HMAC_KEY_BYTES)
  }

  get approvalMode(): ApprovalMode {
    return this.#mode
  }

  /**
   * Test/fixture composition only. Product builds must not call this.
   */
  mintFixtureActor(input: {
    readonly actorId?: string
    readonly allowedTargetIds: readonly string[]
    readonly auditSource?: string
  }): ActorContext {
    if (this.#mode !== 'fixture-only') {
      throw new ApprovalError(
        'fixture-mode-forbidden',
        'Fixture actors cannot be minted outside fixture-only composition.'
      )
    }
    return this.#mintActor({
      actorId: input.actorId ?? randomUUID(),
      authStrength: 'fixture-stub',
      allowedTargetIds: input.allowedTargetIds,
      auditSource: input.auditSource ?? 'fixture-approval-adapter'
    })
  }

  mintTrustedActor(input: {
    readonly actorId: string
    readonly allowedTargetIds: readonly string[]
    readonly auditSource: string
  }): ActorContext {
    if (this.#mode !== 'trusted-backend') {
      throw new ApprovalError(
        'fixture-mode-forbidden',
        'Trusted actors cannot be minted by a fixture-only approval service.'
      )
    }
    return this.#mintActor({
      actorId: input.actorId,
      authStrength: 'interactive-human',
      allowedTargetIds: input.allowedTargetIds,
      auditSource: input.auditSource
    })
  }

  revokeActor(actorId: string): void {
    this.#revokedActors.add(actorId)
  }

  async createProposal(bundleId: string, bundleVersion: number): Promise<ApprovalProposal> {
    const view = await this.#requireView(bundleId, bundleVersion)
    if (view.runtime.state !== 'pending-approval') {
      throw new ApprovalError(
        'bundle-not-pending',
        'An approval proposal can only be created for a pending-approval bundle.'
      )
    }
    const freshness = await this.#bindings.assertBindingsFresh(view.bundle)
    if (freshness !== 'ok') {
      throw new ApprovalError(
        'binding-version-drift',
        `Bundle bindings are no longer current: ${freshness}.`
      )
    }
    const now = this.#now()
    const primaryStep = view.bundle.steps.find((step) => step.kind === 'primary')
    if (primaryStep?.kind !== 'primary') {
      throw new ApprovalError('bundle-not-pending', 'Bundle is missing a primary step.')
    }
    const proposal = sealApprovalProposal({
      schemaVersion: 'agentgo-l2-approval/1.0',
      proposalId: randomUUID(),
      bundleId: view.bundle.bundleId,
      bundleVersion: view.bundle.bundleVersion,
      bundleHash: view.bundle.bundleHash,
      scanId: view.bundle.scanId,
      targetId: view.bundle.targetId,
      scopeSnapshotId: view.bundle.scopeSnapshotId,
      moduleId: primaryStep.binding.moduleId,
      moduleVersion: primaryStep.binding.moduleVersion,
      techniqueId: primaryStep.binding.techniqueId,
      techniqueVersion: primaryStep.binding.techniqueVersion,
      steps: Object.freeze(view.bundle.steps.map((step, index) => summarizeStep(step, index))),
      bindings: {
        identityContextVersion: slotVersion(view.bundle.identityContextVersion),
        sessionGeneration: slotVersion(view.bundle.sessionGeneration),
        csrfBindingVersion: slotVersion(view.bundle.csrfBindingVersion),
        authorizationMatrixVersion: slotVersion(view.bundle.authorizationMatrixVersion)
      },
      testObjectRef: {
        id: view.testObject.testObjectId,
        version: view.testObject.objectVersion,
        ownerRef: view.testObject.targetId,
        scopeSnapshotId: view.testObject.scopeSnapshotId,
        statusSummary: 'ready'
      },
      testObjectHash: view.testObject.objectHash,
      ownershipProofSummary: hashL2Value({
        ownershipProofRef: view.testObject.ownershipProofRef,
        attestationHash: view.testObject.creationAttestation.attestationHash
      }),
      sideEffectEnvelope: view.bundle.sideEffectEnvelope,
      cleanupCapabilityId: view.testObject.cleanupProtocol.capabilityId,
      expectedTerminalState: view.testObject.cleanupProtocol.expectedTerminalState,
      unknowns: [...view.bundle.sideEffectEnvelope.unknownSideEffects],
      freezeRules: Object.freeze([
        'cleanup-failed freezes ordinary execution for this target and TestObject'
      ]),
      humanRiskNotes: Object.freeze([
        'Primary is single-use. Unknown send state cannot replay.',
        ...(this.#mode === 'fixture-only'
          ? ['approvalMode=fixture-only; this is not a production human approval.']
          : [])
      ]),
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + PROPOSAL_TTL_MS).toISOString()
    })
    return this.#identitySessions.insertApprovalProposal(proposal)
  }

  async getProposal(proposalId: string): Promise<ApprovalProposal | undefined> {
    return this.#identitySessions.getApprovalProposal(proposalId)
  }

  async approve(input: ApprovalDecisionInput): Promise<ApprovalPortResult> {
    return this.#decide(input, 'approved')
  }

  async reject(input: ApprovalDecisionInput): Promise<ApprovalPortResult> {
    return this.#decide(input, 'rejected')
  }

  async revoke(input: ApprovalRevokeInput): Promise<ApprovalPortResult> {
    const actorCheck = this.#verifyActor(input.actor)
    if (!actorCheck.ok) return actorCheck
    const existing = await this.#identitySessions.getApprovalRecord(input.approvalId)
    if (!existing) {
      return deny('proposal-missing', 'Approval record does not exist.')
    }
    if (existing.status !== 'active') {
      if (existing.status === 'consumed') {
        return deny(
          'already-consumed',
          'A consumed approval cannot be revoked; interrupt the running bundle instead.'
        )
      }
      return deny('already-decided', `Approval is already ${existing.status}.`)
    }
    const view = await this.#l2.getBundleView(
      existing.record.bundleId,
      existing.record.bundleVersion
    )
    if (view && !input.actor.allowedTargetIds.includes(view.bundle.targetId)) {
      return deny('actor-scope-mismatch', 'Actor is not authorized for this target.')
    }
    const revoked = await this.#identitySessions.revokeApproval(input.approvalId, {
      now: this.#now().getTime(),
      reason: input.reason
    })
    if (!revoked) {
      return deny('already-decided', 'Approval could not be revoked.')
    }
    if (view && (view.runtime.state === 'pending-approval' || view.runtime.state === 'approved')) {
      try {
        await this.#l2.applyEvent({
          bundleId: view.bundle.bundleId,
          bundleVersion: view.bundle.bundleVersion,
          event: 'revoke',
          expectedRowVersion: view.runtime.rowVersion
        })
      } catch (error) {
        if (!(error instanceof L2ProtocolError)) throw error
      }
    } else if (view && view.runtime.state.startsWith('running')) {
      try {
        await this.#l2.applyEvent({
          bundleId: view.bundle.bundleId,
          bundleVersion: view.bundle.bundleVersion,
          event: 'interrupt',
          expectedRowVersion: view.runtime.rowVersion
        })
      } catch (error) {
        if (!(error instanceof L2ProtocolError)) throw error
      }
    }
    return {
      ok: true,
      view: ApprovalRecordViewSchema.parse(revoked),
      ignoredUserApproved: false
    }
  }

  async requireLiveApproval(input: {
    readonly bundle: L2ActionBundle
    readonly consumedOk?: boolean
  }): Promise<ApprovalRecordView> {
    const record = await this.#identitySessions.getLatestApprovalForBundle(
      input.bundle.bundleHash
    )
    if (!record) {
      throw new ApprovalError('approval-revoked', 'No live approval is bound to this bundle.')
    }
    if (record.record.bundleHash !== input.bundle.bundleHash) {
      throw new ApprovalError('bundle-hash-mismatch', 'Approval is bound to a different bundle hash.')
    }
    if (Date.parse(record.record.expiresAt) <= this.#now().getTime() && record.status === 'active') {
      throw new ApprovalError('approval-expired', 'The approval record has expired.')
    }
    if (record.status === 'active') return record
    if (input.consumedOk && record.status === 'consumed') return record
    throw new ApprovalError(
      record.status === 'consumed' ? 'already-consumed' : 'approval-revoked',
      `Approval status ${record.status} cannot authorize this step.`
    )
  }

  async consumeForPrimary(approvalId: string): Promise<ApprovalRecordView> {
    const consumed = await this.#identitySessions.consumeApproval(
      approvalId,
      this.#now().getTime()
    )
    if (!consumed) {
      throw new ApprovalError(
        'already-consumed',
        'The approval record could not be consumed for primary.'
      )
    }
    return consumed
  }

  async #decide(
    input: ApprovalDecisionInput,
    decision: 'approved' | 'rejected'
  ): Promise<ApprovalPortResult> {
    const ignoredUserApproved = input.userApproved === true
    const actorCheck = this.#verifyActor(input.actor)
    if (!actorCheck.ok) {
      if (ignoredUserApproved && actorCheck.reasonCode === 'untrusted-actor') {
        return deny(
          'legacy-user-approved-ignored',
          'userApproved is not an authorization signal; the actor proof was rejected.'
        )
      }
      return actorCheck
    }
    const proposal = await this.#identitySessions.getApprovalProposal(input.proposalId)
    if (!proposal) {
      return deny('proposal-missing', 'Approval proposal does not exist.')
    }
    if (Date.parse(proposal.expiresAt) <= this.#now().getTime()) {
      return deny('proposal-expired', 'The approval proposal has expired.')
    }
    const view = await this.#l2.getBundleView(proposal.bundleId, proposal.bundleVersion)
    if (!view) {
      return deny('proposal-missing', 'The proposal bundle no longer exists.')
    }
    if (view.bundle.bundleHash !== proposal.bundleHash) {
      return deny('bundle-hash-mismatch', 'Proposal bundle hash does not match the stored bundle.')
    }
    if (view.runtime.state !== 'pending-approval') {
      return deny('bundle-not-pending', 'Bundle is not awaiting approval.')
    }
    if (!input.actor.allowedTargetIds.includes(view.bundle.targetId)) {
      return deny('actor-scope-mismatch', 'Actor is not authorized for this target.')
    }
    const freshness = await this.#bindings.assertBindingsFresh(view.bundle)
    if (freshness !== 'ok') {
      return deny('binding-version-drift', `Bundle bindings drifted: ${freshness}.`)
    }
    if (
      slotVersion(view.bundle.identityContextVersion) !== proposal.bindings.identityContextVersion ||
      slotVersion(view.bundle.sessionGeneration) !== proposal.bindings.sessionGeneration ||
      slotVersion(view.bundle.csrfBindingVersion) !== proposal.bindings.csrfBindingVersion ||
      slotVersion(view.bundle.authorizationMatrixVersion) !==
        proposal.bindings.authorizationMatrixVersion
    ) {
      return deny('binding-version-drift', 'Proposal bindings no longer match the bundle.')
    }

    const now = this.#now()
    const record = sealApprovalRecord({
      schemaVersion: 'agentgo-l2-approval/1.0',
      approvalId: randomUUID(),
      proposalHash: proposal.proposalHash,
      bundleId: view.bundle.bundleId,
      bundleVersion: view.bundle.bundleVersion,
      bundleHash: view.bundle.bundleHash,
      decision,
      approvalMode: this.#mode,
      actorId: input.actor.actorId,
      actorContextHash: input.actor.contextHash,
      authStrength: input.actor.authStrength,
      authenticatedAt: input.actor.authenticatedAt,
      bindingHashes: {
        identityContextVersion: proposal.bindings.identityContextVersion,
        sessionGeneration: proposal.bindings.sessionGeneration,
        csrfBindingVersion: proposal.bindings.csrfBindingVersion,
        authorizationMatrixVersion: proposal.bindings.authorizationMatrixVersion,
        testObjectHash: view.testObject.objectHash,
        sideEffectEnvelopeHash: hashL2Value(view.bundle.sideEffectEnvelope),
        cleanupCapabilityId: view.testObject.cleanupProtocol.capabilityId
      },
      singleUse: true,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + APPROVAL_TTL_MS).toISOString()
    })

    const stored = await this.#identitySessions.insertApprovalRecord(
      record,
      decision === 'approved' ? 'active' : 'rejected'
    )

    if (decision === 'approved') {
      try {
        await this.#l2.applyEvent({
          bundleId: view.bundle.bundleId,
          bundleVersion: view.bundle.bundleVersion,
          event: 'approve',
          expectedRowVersion: view.runtime.rowVersion,
          trustedApprovalPresent: true
        })
      } catch (error) {
        await this.#identitySessions.revokeApproval(record.approvalId, {
          now: now.getTime(),
          reason: 'bundle-transition-failed'
        })
        if (error instanceof L2ProtocolError) {
          return deny('bundle-not-pending', error.message)
        }
        throw error
      }
    } else {
      try {
        await this.#l2.applyEvent({
          bundleId: view.bundle.bundleId,
          bundleVersion: view.bundle.bundleVersion,
          event: 'reject',
          expectedRowVersion: view.runtime.rowVersion,
          trustedApprovalPresent: true
        })
      } catch (error) {
        if (!(error instanceof L2ProtocolError)) throw error
      }
    }

    return {
      ok: true,
      view: ApprovalRecordViewSchema.parse(stored),
      ignoredUserApproved
    }
  }

  #mintActor(input: {
    readonly actorId: string
    readonly authStrength: ActorContextPayload['authStrength']
    readonly allowedTargetIds: readonly string[]
    readonly auditSource: string
  }): ActorContext {
    const now = this.#now()
    const payload: ActorContextPayload = {
      schemaVersion: 'agentgo-l2-approval/1.0',
      actorId: input.actorId,
      roles: Object.freeze(['l2-approver' as const]),
      authenticatedAt: now.toISOString(),
      authStrength: input.authStrength,
      trustedSessionId: randomUUID(),
      auditSource: input.auditSource,
      channel: 'backend-composition-root',
      allowedTargetIds: Object.freeze([...input.allowedTargetIds]),
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ACTOR_TTL_MS).toISOString()
    }
    const contextHash = actorContextPayloadHash(payload)
    const handleId = randomUUID()
    const digest = signActorProof(this.#hmacKey, handleId, contextHash)
    return ActorContextSchema.parse(
      attachActorProofHandle(payload, {
        handleId,
        algorithm: 'hmac-sha256',
        digest
      })
    )
  }

  #verifyActor(actor: ActorContext): ApprovalPortResult | { readonly ok: true } {
    if (this.#revokedActors.has(actor.actorId)) {
      return deny('actor-revoked', 'ActorContext has been revoked.')
    }
    if (Date.parse(actor.expiresAt) <= this.#now().getTime()) {
      return deny('actor-expired', 'ActorContext has expired.')
    }
    if (!actor.roles.includes('l2-approver')) {
      return deny('untrusted-actor', 'ActorContext lacks the l2-approver role.')
    }
    if (actor.channel !== 'backend-composition-root') {
      return deny('untrusted-actor', 'ActorContext channel is not the backend composition root.')
    }
    if (this.#mode === 'fixture-only' && actor.authStrength !== 'fixture-stub') {
      return deny('untrusted-actor', 'Fixture-only composition rejects non-fixture actors.')
    }
    if (this.#mode === 'trusted-backend' && actor.authStrength !== 'interactive-human') {
      return deny('untrusted-actor', 'Trusted-backend composition rejects fixture stub actors.')
    }
    const expected = signActorProof(this.#hmacKey, actor.handle.handleId, actor.contextHash)
    if (!safeDigestEqual(expected, actor.handle.digest)) {
      return deny('untrusted-actor', 'ActorContext proof handle is not authentic.')
    }
    if (actor.contextHash !== actorContextPayloadHash(unsignedActorContext(actor))) {
      return deny('untrusted-actor', 'ActorContext hash does not match the payload.')
    }
    return { ok: true }
  }

  async #requireView(bundleId: string, bundleVersion: number): Promise<L2BundleView> {
    const view = await this.#l2.getBundleView(bundleId, bundleVersion)
    if (!view) {
      throw new ApprovalError('proposal-missing', 'L2 bundle does not exist.')
    }
    return view
  }
}

/**
 * Test-only adapter. Must never be imported by product composition roots.
 * Records are forced to `approvalMode=fixture-only`.
 */
export class FixtureApprovalAdapter {
  readonly #service: ApprovalService

  constructor(service: ApprovalService) {
    if (service.approvalMode !== 'fixture-only') {
      throw new ApprovalError(
        'fixture-mode-forbidden',
        'FixtureApprovalAdapter requires a fixture-only ApprovalService.'
      )
    }
    this.#service = service
  }

  mint(allowedTargetIds: readonly string[]): ActorContext {
    return this.#service.mintFixtureActor({ allowedTargetIds })
  }

  approve(input: ApprovalDecisionInput): Promise<ApprovalPortResult> {
    return this.#service.approve(input)
  }

  reject(input: ApprovalDecisionInput): Promise<ApprovalPortResult> {
    return this.#service.reject(input)
  }
}

function deny(reasonCode: ApprovalReasonCode, message: string): ApprovalDenialResult {
  return { ok: false, reasonCode, message }
}

function slotVersion(slot: L2ActionBundle['identityContextVersion']): string {
  if (slot.status !== 'resolved') {
    throw new ApprovalError('binding-version-drift', 'A required binding slot is unresolved.')
  }
  return slot.version
}

function summarizeStep(step: L2BundleStep, index: number) {
  if (step.kind === 'cleanup-not-needed') {
    return {
      ordinal: index + 1,
      kind: step.kind,
      intentHash: hashL2Value({ kind: step.kind, justification: step.justification }),
      maxRequests: 1,
      maxDurationMs: 5_000,
      maxConcurrency: 1 as const
    }
  }
  return {
    ordinal: index + 1,
    kind: step.kind,
    intentHash: step.binding.templateIntentHash.digest,
    maxRequests: step.binding.budget.maxRequests,
    maxDurationMs: step.binding.budget.maxDurationMs,
    maxConcurrency: 1 as const
  }
}

function signActorProof(key: Uint8Array, handleId: string, contextHash: string): string {
  return createHmac('sha256', key).update(`${handleId}:${contextHash}`, 'utf8').digest('hex')
}

function safeDigestEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8')
  const rightBytes = Buffer.from(right, 'utf8')
  if (leftBytes.byteLength !== rightBytes.byteLength) return false
  return timingSafeEqual(leftBytes, rightBytes)
}
