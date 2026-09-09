import { describe, expect, it } from 'vitest'
import {
  L2_CLEANUP_CAPABILITY_ID,
  type L2ActionBundlePayload,
  type SideEffectEnvelope,
  type TestObjectPayload
} from '@agentgo/contracts'
import { evaluateCleanupCapability } from './cleanup-policy'
import {
  sessionBindingsResolved,
  bundleMatchesTestObject,
  sideEffectEnvelopeEligibility
} from './eligibility'
import { hashL2Value, sealL2ActionBundle, sealTestObject, unsignedL2ActionBundle } from './hash'
import { cleanupReceiptEligibility } from './receipt'
import { transitionL2, type L2TransitionContext } from './state-machine'

const HASH = 'b'.repeat(64)
const NOW = '2026-08-20T12:00:00.000Z'
const LATER = '2026-08-22T12:00:00.000Z'

let nextId = 0

function uuid(): string {
  nextId += 1
  return `00000000-0000-4000-8000-${nextId.toString(16).padStart(12, '0')}`
}

function envelope(overrides: Partial<SideEffectEnvelope> = {}): SideEffectEnvelope {
  return {
    expectedStateChange: 'status:draft-to-submitted',
    maxImpactScope: 'single-test-object-fields',
    writableResourceId: 'obj-1',
    fieldWrites: [
      {
        fieldPath: 'status',
        oldValueConstraint: 'draft',
        newValueConstraint: 'submitted'
      }
    ],
    externalSideEffects: [],
    observationRoles: {
      preRead: 'pre-read',
      postRead: 'post-read',
      terminalRead: 'terminal-read'
    },
    unknownSideEffects: [],
    unobservableSideEffects: [],
    irreversibleItems: [],
    ...overrides
  }
}

function payload(): TestObjectPayload {
  const scopeSnapshotId = uuid()
  return {
    schemaVersion: 'agentgo-l2-protocol/1.0',
    testObjectId: uuid(),
    objectVersion: 1,
    scanId: uuid(),
    targetId: uuid(),
    scopeSnapshotId,
    identityId: uuid(),
    objectType: 'record',
    disposable: true,
    createdAt: NOW,
    expiresAt: LATER,
    allowedFields: ['status'],
    allowedStates: ['draft', 'submitted', 'absent'],
    ownershipProofRef: uuid(),
    creationEvidenceHash: HASH,
    baselineEvidenceHash: HASH,
    canonicalResource: {
      kind: 'http-resource',
      origin: 'https://lab.example.test',
      method: 'GET',
      path: '/test-objects/obj-1',
      resourceId: 'obj-1'
    },
    cleanupProtocol: {
      kind: 'reset',
      declaredByTarget: true,
      capabilityId: L2_CLEANUP_CAPABILITY_ID,
      method: 'POST',
      path: '/test-objects/obj-1',
      expectedTerminalState: 'absent',
      maxRequests: 1
    },
    closeConditions: ['expired', 'externally-modified'],
    creationAttestation: {
      source: 'agentgo-application',
      createdByAgentGo: true,
      attestedAt: NOW,
      attestationHash: HASH
    }
  }
}

function binding(
  purpose: 'read' | 'primary' | 'cleanup',
  object: TestObjectPayload
) {
  return {
    purpose,
    testObjectVersion: object.objectVersion,
    scopeSnapshotId: object.scopeSnapshotId,
    familyId: 'sqli',
    moduleId: 'legacy.sqli.boolean-differential',
    moduleVersion: '1.0.0',
    techniqueId: 'sqli.boolean-differential',
    techniqueVersion: '1.0.0',
    templateIntentHash: {
      domain: 'agentgo.template-intent.v1' as const,
      algorithm: 'sha256' as const,
      digest: HASH
    },
    budget: { maxRequests: 1, maxDurationMs: 5_000 }
  }
}

function bundlePayload(object: TestObjectPayload): L2ActionBundlePayload {
  return {
    schemaVersion: 'agentgo-l2-protocol/1.0',
    bundleId: uuid(),
    bundleVersion: 1,
    scanId: object.scanId,
    targetId: object.targetId,
    testObjectId: object.testObjectId,
    testObjectVersion: object.objectVersion,
    testObjectHash: HASH,
    identityId: object.identityId,
    scopeSnapshotId: object.scopeSnapshotId,
    sideEffectEnvelope: envelope(),
    identityContextVersion: { status: 'unresolved' },
    sessionGeneration: { status: 'unresolved' },
    csrfBindingVersion: { status: 'unresolved' },
    authorizationMatrixVersion: { status: 'unresolved' },
    steps: [
      { kind: 'pre-read', binding: binding('read', object) },
      { kind: 'primary', binding: binding('primary', object) },
      { kind: 'post-read', binding: binding('read', object) },
      {
        kind: 'cleanup',
        binding: binding('cleanup', object),
        cleanupProtocol: object.cleanupProtocol
      },
      { kind: 'cleanup-verify', binding: binding('read', object) },
      { kind: 'terminal-read', binding: binding('read', object) }
    ],
    createdAt: NOW
  }
}

function context(
  object: TestObjectPayload,
  overrides: Partial<L2TransitionContext> = {}
): L2TransitionContext {
  const testObject = sealTestObject(object)
  const bundle = sealL2ActionBundle({
    ...bundlePayload(object),
    testObjectHash: testObject.objectHash
  })
  return {
    now: new Date('2026-08-20T13:00:00.000Z'),
    bundle,
    testObject,
    trustedApprovalPresent: false,
    expectedRowVersion: 1,
    actualRowVersion: 1,
    primaryAlreadyStarted: false,
    primarySentProof: 'unknown',
    freezeActive: false,
    isRecoveryProposal: false,
    ...overrides
  }
}

describe('L2 domain protocol', () => {
  it('changes bundle hash when any bound input changes', () => {
    const object = payload()
    const draft = bundlePayload(object)
    const first = sealL2ActionBundle(draft)
    expect(first.bundleHash).toBe(hashL2Value(unsignedL2ActionBundle(first)))
    const second = sealL2ActionBundle({
      ...draft,
      identityContextVersion: { status: 'resolved', version: 'ctx-1' }
    })
    expect(second.bundleHash).not.toBe(first.bundleHash)
  })

  it('keeps unresolved session bindings from reaching pending-approval', () => {
    const result = transitionL2({
      state: 'draft',
      event: 'submit-for-approval',
      context: context(payload())
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reasonCode).toBe('session-binding-unresolved')
    expect(sessionBindingsResolved(bundlePayload(payload()))).toBe(false)
  })

  it('rejects approve and running transitions without trusted approval', () => {
    const object = payload()
    const resolved = sealL2ActionBundle({
      ...bundlePayload(object),
      testObjectHash: sealTestObject(object).objectHash,
      identityContextVersion: { status: 'resolved', version: 'identity-1' },
      sessionGeneration: { status: 'resolved', version: 'session-1' },
      csrfBindingVersion: { status: 'resolved', version: 'csrf-1' },
      authorizationMatrixVersion: { status: 'resolved', version: 'matrix-1' }
    })
    const ctx = context(object, { bundle: resolved, testObject: sealTestObject(object) })
    expect(
      transitionL2({ state: 'draft', event: 'submit-for-approval', context: ctx }).ok
    ).toBe(true)
    const approved = transitionL2({
      state: 'pending-approval',
      event: 'approve',
      context: ctx
    })
    expect(approved.ok).toBe(false)
    if (!approved.ok) expect(approved.reasonCode).toBe('trusted-approval-missing')
  })

  it('refuses unknown side effects, generic DELETE and cross-bundle cleanup', () => {
    expect(
      sideEffectEnvelopeEligibility(envelope({ unknownSideEffects: ['webhook?'] }))
    ).toBe('unknown-side-effect')
    const object = payload()
    const bundle = sealL2ActionBundle({
      ...bundlePayload(object),
      testObjectHash: sealTestObject(object).objectHash
    })
    expect(
      evaluateCleanupCapability({
        protocol: object.cleanupProtocol,
        testObject: object,
        bundle,
        requestedMethod: 'DELETE'
      })
    ).toBe('generic-http-delete-forbidden')
    expect(
      evaluateCleanupCapability({
        protocol: object.cleanupProtocol,
        testObject: object,
        bundle,
        requestedBundleHash: 'c'.repeat(64)
      })
    ).toBe('cross-bundle-cleanup-forbidden')
  })

  it('never auto-replays primary-unknown and freezes after cleanup failure', () => {
    const ctx = context(payload(), {
      trustedApprovalPresent: true,
      primaryAlreadyStarted: true,
      primarySentProof: 'unknown'
    })
    const unknown = transitionL2({
      state: 'running-primary',
      event: 'mark-primary-unknown',
      context: ctx
    })
    expect(unknown.ok).toBe(true)
    const replay = transitionL2({
      state: 'primary-unknown',
      event: 'start-primary',
      context: ctx
    })
    expect(replay.ok).toBe(false)
    const unsent = transitionL2({
      state: 'primary-unknown',
      event: 'observe-primary-unsent',
      context: { ...ctx, primarySentProof: 'unknown' }
    })
    expect(unsent.ok).toBe(false)
    if (!unsent.ok) expect(unsent.reasonCode).toBe('primary-unknown-no-replay')
    const freeze = transitionL2({
      state: 'cleanup-running',
      event: 'fail-cleanup',
      context: ctx
    })
    expect(freeze.ok).toBe(true)
    if (freeze.ok) expect(freeze.activateFreeze).toBe(true)
    const blocked = transitionL2({
      state: 'draft',
      event: 'submit-for-approval',
      context: { ...ctx, freezeActive: true }
    })
    expect(blocked.ok).toBe(false)
    if (!blocked.ok) expect(blocked.reasonCode).toBe('cleanup-failed-frozen')
  })

  it('rejects not-needed receipts without consistent known evidence', () => {
    expect(
      cleanupReceiptEligibility({
        schemaVersion: 'agentgo-l2-protocol/1.0',
        receiptId: uuid(),
        kind: 'not-needed-no-state-change',
        bundleId: uuid(),
        bundleHash: HASH,
        testObjectId: uuid(),
        testObjectVersion: 1,
        testObjectHash: HASH,
        stepEvidenceHashes: {
          preRead: HASH,
          postRead: 'd'.repeat(64),
          cleanupVerify: HASH,
          terminalRead: HASH
        },
        actorSlot: { status: 'unresolved' },
        issuedAt: NOW,
        terminalResourceState: 'unchanged',
        cleanupCapabilityId: L2_CLEANUP_CAPABILITY_ID,
        requestExecutionState: 'timeout'
      })
    ).toBe('request-execution-state-unknown')
  })

  it('rejects concurrent version conflicts and repeat primary', () => {
    const ctx = context(payload(), {
      trustedApprovalPresent: true,
      expectedRowVersion: 1,
      actualRowVersion: 2
    })
    expect(
      transitionL2({ state: 'draft', event: 'mark-ineligible', context: ctx }).reasonCode
    ).toBe('concurrent-version-conflict')
    const started = context(payload(), {
      trustedApprovalPresent: true,
      primaryAlreadyStarted: true
    })
    expect(
      transitionL2({
        state: 'running-primary',
        event: 'start-primary',
        context: started
      }).reasonCode
    ).toBe('repeat-primary-forbidden')
  })

  it('rejects identity mismatch, crash replay, and non-AgentGo cleanup', () => {
    const object = payload()
    expect(
      bundleMatchesTestObject(
        { ...bundlePayload(object), identityId: uuid() },
        object
      )
    ).toBe('identity-mismatch')
    const crash = context(object, {
      trustedApprovalPresent: true,
      primaryAlreadyStarted: true,
      primarySentProof: 'unknown'
    })
    const interrupted = transitionL2({
      state: 'running-primary',
      event: 'interrupt',
      context: crash
    })
    expect(interrupted.ok).toBe(true)
    if (interrupted.ok) expect(interrupted.nextState).toBe('primary-unknown')
    expect(
      transitionL2({
        state: 'draft',
        event: 'approve',
        context: crash
      }).reasonCode
    ).toBe('illegal-transition')
    const sealed = sealTestObject(object)
    const bundle = sealL2ActionBundle({
      ...bundlePayload(object),
      testObjectHash: sealed.objectHash
    })
    expect(
      evaluateCleanupCapability({
        protocol: object.cleanupProtocol,
        testObject: {
          ...object,
          creationAttestation: {
            ...object.creationAttestation,
            createdByAgentGo: false
          }
        } as unknown as typeof object,
        bundle
      })
    ).toBe('non-agentgo-object-forbidden')
    expect(
      evaluateCleanupCapability({
        protocol: object.cleanupProtocol,
        testObject: { ...object, disposable: false } as unknown as typeof object,
        bundle
      })
    ).toBe('real-business-object-forbidden')
  })
})
