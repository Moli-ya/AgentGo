import { randomUUID } from 'node:crypto'
import {
  L2ActionBundlePayloadSchema,
  L2ExecutionFreezeSchema,
  type CanonicalTestResourceIdentifier,
  type CleanupReceipt,
  type CleanupReceiptPayload,
  type DeclaredCleanupProtocol,
  type IdentityRecord,
  type L2ActionBundle,
  type L2BundleEventType,
  type L2BundleState,
  type L2BundleStep,
  type L2ProtocolReasonCode,
  type ScanRecord,
  type SideEffectEnvelope,
  type TestObject,
  type TestObjectCloseCondition,
  type TestObjectType
} from '@agentgo/contracts'
import type { AgentGoRepository, L2BundleRuntimeRecord, L2PrimarySentProof, L2Repository } from '@agentgo/db'
import {
  bundleMatchesTestObject,
  cleanupReceiptEligibility,
  hashL2Value,
  sealCleanupReceipt,
  sealL2ActionBundle,
  sealTestObject,
  sideEffectEnvelopeEligibility,
  testObjectL2Eligibility,
  transitionL2
} from '@agentgo/domain'

const CANDIDATE_STATES = new Set<L2BundleState>([
  'draft',
  'ineligible',
  'pending-approval',
  'approved'
])

export class L2ProtocolError extends Error {
  readonly reasonCode: L2ProtocolReasonCode

  constructor(reasonCode: L2ProtocolReasonCode, message?: string) {
    super(message ?? reasonCode)
    this.name = 'L2ProtocolError'
    this.reasonCode = reasonCode
  }
}

export interface L2CreateTestObjectInput {
  readonly scanId: string
  readonly targetId: string
  readonly identityId: string
  readonly tenantRef?: string
  readonly objectType: TestObjectType
  readonly allowedFields: readonly string[]
  readonly allowedStates: readonly string[]
  readonly canonicalResource: CanonicalTestResourceIdentifier
  readonly cleanupProtocol: DeclaredCleanupProtocol
  readonly closeConditions: readonly TestObjectCloseCondition[]
  readonly expiresAt: string
  readonly creationEvidenceHash: string
  readonly baselineEvidenceHash: string
}

export interface L2ProposeBundleInput {
  readonly scanId: string
  readonly targetId: string
  readonly testObjectId: string
  readonly testObjectVersion: number
  readonly sideEffectEnvelope: SideEffectEnvelope
  readonly steps: readonly L2BundleStep[]
  readonly isRecoveryProposal?: boolean
}

export interface L2ApplyEventInput {
  readonly bundleId: string
  readonly bundleVersion: number
  readonly event: L2BundleEventType
  readonly expectedRowVersion: number
  /**
   * Trusted-approval hook only. Production L2 callers must leave this false; it does
   * not create an ActorContext or ApprovalService record.
   */
  readonly trustedApprovalPresent?: boolean
  readonly isRecoveryProposal?: boolean
}

export interface L2BundleView {
  readonly bundle: L2ActionBundle
  readonly testObject: TestObject
  readonly runtime: L2BundleRuntimeRecord
}

function isConcurrentConflict(error: unknown): boolean {
  return error instanceof Error && error.message.includes('L2 concurrent version conflict')
}

const BINDING_GATED_EVENTS = new Set<L2BundleEventType>([
  'submit-for-approval',
  'approve',
  'start-pre-read',
  'start-primary',
  'start-post-read',
  'start-cleanup',
  'start-cleanup-verify',
  'start-terminal-read'
])

export type L2BindingFreshnessVerifier = (
  bundle: L2ActionBundle
) => Promise<'ok' | L2ProtocolReasonCode>

export class L2ProtocolService {
  private readonly l2: L2Repository
  private readonly scans: AgentGoRepository
  private readonly now: () => Date
  private bindingFreshnessVerifier?: L2BindingFreshnessVerifier

  constructor(dependencies: {
    l2Repository: L2Repository
    scanRepository: AgentGoRepository
    now?: () => Date
    bindingFreshnessVerifier?: L2BindingFreshnessVerifier
  }) {
    this.l2 = dependencies.l2Repository
    this.scans = dependencies.scanRepository
    this.now = dependencies.now ?? (() => new Date())
    this.bindingFreshnessVerifier = dependencies.bindingFreshnessVerifier
  }

  /**
   * Installed by the composition root once identity/session/CSRF/matrix
   * services exist. Until then every binding-gated transition keeps failing
   * closed on the unresolved slots.
   */
  setBindingFreshnessVerifier(verifier: L2BindingFreshnessVerifier): void {
    this.bindingFreshnessVerifier = verifier
  }

  async createTestObject(input: L2CreateTestObjectInput): Promise<TestObject> {
    const scan = await this.requireScan(input.scanId, input.targetId)
    const identity = await this.requireIdentity(input.identityId, input.targetId)
    if (!identity.isTestIdentity) {
      throw new L2ProtocolError(
        'real-business-object-forbidden',
        'L2 TestObjects require a test identity.'
      )
    }
    const createdAt = this.now().toISOString()
    const testObjectId = randomUUID()
    const ownershipProofRef = randomUUID()
    const attestedAt = createdAt
    const attestationHash = hashL2Value({
      source: 'agentgo-application',
      createdByAgentGo: true,
      attestedAt,
      testObjectId,
      scanId: scan.id,
      targetId: scan.targetId,
      identityId: identity.id,
      ownershipProofRef,
      canonicalResource: input.canonicalResource
    })
    const sealed = sealTestObject({
      schemaVersion: 'agentgo-l2-protocol/1.0',
      testObjectId,
      objectVersion: 1,
      scanId: scan.id,
      targetId: scan.targetId,
      scopeSnapshotId: scan.scopeSnapshotId,
      identityId: identity.id,
      ...(input.tenantRef ? { tenantRef: input.tenantRef } : {}),
      objectType: input.objectType,
      disposable: true,
      createdAt,
      expiresAt: input.expiresAt,
      allowedFields: [...input.allowedFields],
      allowedStates: [...input.allowedStates],
      ownershipProofRef,
      creationEvidenceHash: input.creationEvidenceHash,
      baselineEvidenceHash: input.baselineEvidenceHash,
      canonicalResource: input.canonicalResource,
      cleanupProtocol: input.cleanupProtocol,
      closeConditions: [...input.closeConditions],
      creationAttestation: {
        source: 'agentgo-application',
        createdByAgentGo: true,
        attestedAt,
        attestationHash
      }
    })
    return this.l2.insertTestObject(sealed)
  }

  async proposeBundle(input: L2ProposeBundleInput): Promise<L2BundleView> {
    const object = await this.requireTestObject(input.testObjectId, input.testObjectVersion)
    if (object.scanId !== input.scanId || object.targetId !== input.targetId) {
      throw new L2ProtocolError('ownership-or-tenant-mismatch')
    }
    const freeze = await this.l2.getActiveFreeze(object.targetId, object.testObjectId)
    if (freeze && !input.isRecoveryProposal) {
      throw new L2ProtocolError('cleanup-failed-frozen')
    }
    const envelopeReason = sideEffectEnvelopeEligibility(input.sideEffectEnvelope)
    const objectReason = testObjectL2Eligibility(object, this.now())
    const createdAt = this.now().toISOString()
    const payload = L2ActionBundlePayloadSchema.parse({
      schemaVersion: 'agentgo-l2-protocol/1.0',
      bundleId: randomUUID(),
      bundleVersion: 1,
      scanId: object.scanId,
      targetId: object.targetId,
      testObjectId: object.testObjectId,
      testObjectVersion: object.objectVersion,
      testObjectHash: object.objectHash,
      identityId: object.identityId,
      ...(object.tenantRef ? { tenantRef: object.tenantRef } : {}),
      scopeSnapshotId: object.scopeSnapshotId,
      sideEffectEnvelope: input.sideEffectEnvelope,
      identityContextVersion: { status: 'unresolved' },
      sessionGeneration: { status: 'unresolved' },
      csrfBindingVersion: { status: 'unresolved' },
      authorizationMatrixVersion: { status: 'unresolved' },
      steps: input.steps,
      createdAt
    })
    const match = bundleMatchesTestObject(payload, object)
    if (match !== 'ok') throw new L2ProtocolError(match)
    const sealed = sealL2ActionBundle(payload)
    const state: L2BundleState =
      envelopeReason === 'ok' && objectReason === 'ok' ? 'draft' : 'ineligible'
    await this.revokeOpenCandidates(object.testObjectId)
    await this.l2.insertBundle({
      bundle: sealed,
      state,
      now: Date.parse(createdAt)
    })
    return this.requireView(sealed.bundleId, sealed.bundleVersion)
  }

  async applyEvent(input: L2ApplyEventInput): Promise<L2BundleView> {
    const view = await this.requireView(input.bundleId, input.bundleVersion)
    if (
      this.bindingFreshnessVerifier &&
      BINDING_GATED_EVENTS.has(input.event)
    ) {
      const freshness = await this.bindingFreshnessVerifier(view.bundle)
      if (freshness !== 'ok') {
        throw new L2ProtocolError(freshness)
      }
    }
    const freeze = await this.l2.getActiveFreeze(
      view.testObject.targetId,
      view.testObject.testObjectId
    )
    const result = transitionL2({
      state: view.runtime.state,
      event: input.event,
      context: {
        now: this.now(),
        bundle: view.bundle,
        testObject: view.testObject,
        trustedApprovalPresent: input.trustedApprovalPresent === true,
        expectedRowVersion: input.expectedRowVersion,
        actualRowVersion: view.runtime.rowVersion,
        primaryAlreadyStarted: view.runtime.primaryStarted,
        primarySentProof: view.runtime.primarySentProof,
        freezeActive: Boolean(freeze),
        isRecoveryProposal: input.isRecoveryProposal === true
      }
    })
    if (!result.ok) {
      throw new L2ProtocolError(result.reasonCode)
    }
    let freezeId = view.runtime.freezeId
    if (result.activateFreeze) {
      const stored = await this.l2.insertFreeze(
        L2ExecutionFreezeSchema.parse({
          freezeId: randomUUID(),
          targetId: view.testObject.targetId,
          testObjectId: view.testObject.testObjectId,
          bundleId: view.bundle.bundleId,
          bundleHash: view.bundle.bundleHash,
          reasonCode: 'cleanup-failed-frozen',
          allows: 'recovery-proposal-or-manual',
          createdAt: this.now().toISOString()
        })
      )
      freezeId = stored.freezeId
    }
    const primarySentProof = nextSentProof(
      view.runtime.primarySentProof,
      input.event,
      result.primaryStarted
    )
    try {
      await this.l2.applyRuntimeTransition({
        bundleId: view.bundle.bundleId,
        bundleVersion: view.bundle.bundleVersion,
        expectedRowVersion: input.expectedRowVersion,
        fromState: view.runtime.state,
        toState: result.nextState,
        eventType: input.event,
        reasonCode: 'ok',
        primaryStarted: result.primaryStarted,
        primarySentProof,
        freezeId
      })
    } catch (error) {
      if (isConcurrentConflict(error)) {
        throw new L2ProtocolError('concurrent-version-conflict')
      }
      throw error
    }
    return this.requireView(input.bundleId, input.bundleVersion)
  }

  async issueCleanupReceipt(
    payload: Omit<CleanupReceiptPayload, 'schemaVersion' | 'actorSlot'> & {
      schemaVersion?: CleanupReceiptPayload['schemaVersion']
      actorSlot?: CleanupReceiptPayload['actorSlot']
    }
  ): Promise<CleanupReceipt> {
    const view = await this.requireViewByHash(payload.bundleHash)
    if (
      view.bundle.bundleId !== payload.bundleId ||
      view.bundle.bundleHash !== payload.bundleHash ||
      view.testObject.testObjectId !== payload.testObjectId ||
      view.testObject.objectVersion !== payload.testObjectVersion ||
      view.testObject.objectHash !== payload.testObjectHash
    ) {
      throw new L2ProtocolError('bundle-hash-mismatch')
    }
    const actorSlot =
      payload.actorSlot?.status === 'resolved'
        ? payload.actorSlot
        : { status: 'unresolved' as const }
    const candidate: CleanupReceiptPayload = {
      schemaVersion: 'agentgo-l2-protocol/1.0',
      receiptId: payload.receiptId,
      kind: payload.kind,
      bundleId: payload.bundleId,
      bundleHash: payload.bundleHash,
      testObjectId: payload.testObjectId,
      testObjectVersion: payload.testObjectVersion,
      testObjectHash: payload.testObjectHash,
      stepEvidenceHashes: payload.stepEvidenceHashes,
      actorSlot,
      issuedAt: payload.issuedAt,
      terminalResourceState: payload.terminalResourceState,
      cleanupCapabilityId: payload.cleanupCapabilityId,
      requestExecutionState: payload.requestExecutionState
    }
    const eligibility = cleanupReceiptEligibility(candidate)
    if (eligibility !== 'ok') throw new L2ProtocolError(eligibility)
    return this.l2.insertReceipt(sealCleanupReceipt(candidate), view.runtime.bundleVersion)
  }

  async isOrdinaryQueueFrozen(targetId: string, testObjectId: string): Promise<boolean> {
    return Boolean(await this.l2.getActiveFreeze(targetId, testObjectId))
  }

  async getBundleView(
    bundleId: string,
    bundleVersion: number
  ): Promise<L2BundleView | undefined> {
    const bundle = await this.l2.getBundle(bundleId, bundleVersion)
    const runtime = await this.l2.getRuntime(bundleId, bundleVersion)
    if (!bundle || !runtime) return undefined
    const testObject = await this.l2.getTestObject(bundle.testObjectId, bundle.testObjectVersion)
    if (!testObject) return undefined
    return { bundle, testObject, runtime }
  }

  private async requireView(bundleId: string, bundleVersion: number): Promise<L2BundleView> {
    const view = await this.getBundleView(bundleId, bundleVersion)
    if (!view) throw new L2ProtocolError('missing-test-object')
    return view
  }

  private async requireViewByHash(bundleHash: string): Promise<L2BundleView> {
    const bundle = await this.l2.getBundleByHash(bundleHash)
    if (!bundle) throw new L2ProtocolError('bundle-hash-mismatch')
    return this.requireView(bundle.bundleId, bundle.bundleVersion)
  }

  private async requireScan(scanId: string, targetId: string): Promise<ScanRecord> {
    const scan = await this.scans.getScan(scanId)
    if (!scan) throw new L2ProtocolError('ownership-or-tenant-mismatch')
    if (scan.targetId !== targetId) {
      throw new L2ProtocolError('ownership-or-tenant-mismatch')
    }
    return scan
  }

  private async requireIdentity(
    identityId: string,
    targetId: string
  ): Promise<IdentityRecord> {
    const identity = await this.scans.getIdentity(identityId)
    if (!identity) throw new L2ProtocolError('identity-mismatch')
    if (identity.targetId !== targetId) throw new L2ProtocolError('identity-mismatch')
    return identity
  }

  private async requireTestObject(
    testObjectId: string,
    objectVersion: number
  ): Promise<TestObject> {
    const object = await this.l2.getTestObject(testObjectId, objectVersion)
    if (!object) throw new L2ProtocolError('missing-test-object')
    return object
  }

  private async revokeOpenCandidates(testObjectId: string): Promise<void> {
    const runtimes = await this.l2.listRuntimesForTestObject(testObjectId)
    for (const runtime of runtimes) {
      if (!CANDIDATE_STATES.has(runtime.state)) continue
      const bundle = await this.l2.getBundle(runtime.bundleId, runtime.bundleVersion)
      const object = bundle
        ? await this.l2.getTestObject(bundle.testObjectId, bundle.testObjectVersion)
        : undefined
      if (!bundle || !object) continue
      const result = transitionL2({
        state: runtime.state,
        event: 'revoke',
        context: {
          now: this.now(),
          bundle,
          testObject: object,
          trustedApprovalPresent: false,
          expectedRowVersion: runtime.rowVersion,
          actualRowVersion: runtime.rowVersion,
          primaryAlreadyStarted: runtime.primaryStarted,
          primarySentProof: runtime.primarySentProof,
          freezeActive: false,
          isRecoveryProposal: false
        }
      })
      if (!result.ok) continue
      await this.l2.applyRuntimeTransition({
        bundleId: runtime.bundleId,
        bundleVersion: runtime.bundleVersion,
        expectedRowVersion: runtime.rowVersion,
        fromState: runtime.state,
        toState: result.nextState,
        eventType: 'revoke',
        reasonCode: 'ok',
        primaryStarted: result.primaryStarted,
        primarySentProof: runtime.primarySentProof,
        freezeId: runtime.freezeId
      })
    }
  }
}

function nextSentProof(
  current: L2PrimarySentProof,
  event: L2BundleEventType,
  primaryStarted: boolean
): L2PrimarySentProof {
  if (event === 'complete-primary') return 'sent'
  if (event === 'start-primary' || event === 'mark-primary-unknown') return 'unknown'
  if (event === 'interrupt' && primaryStarted) return 'unknown'
  return current
}
