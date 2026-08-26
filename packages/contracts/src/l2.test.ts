import { describe, expect, it } from 'vitest'
import {
  CleanupReceiptPayloadSchema,
  L2ActionBundlePayloadSchema,
  L2_CLEANUP_CAPABILITY_ID,
  SideEffectEnvelopeSchema,
  TestObjectPayloadSchema,
  isExactL2FieldPath,
  type CanonicalTestResourceIdentifier,
  type DeclaredCleanupProtocol,
  type L2ActionBundlePayload,
  type SideEffectEnvelope,
  type TestObjectPayload
} from './l2'

const HASH = 'a'.repeat(64)
const NOW = '2026-08-20T10:00:00.000Z'
const LATER = '2026-08-21T10:00:00.000Z'

let nextId = 0

function uuid(): string {
  nextId += 1
  return `00000000-0000-4000-8000-${nextId.toString(16).padStart(12, '0')}`
}

function resource(): CanonicalTestResourceIdentifier {
  return {
    kind: 'http-resource',
    origin: 'https://lab.example.test',
    method: 'GET',
    path: '/test-objects/obj-1',
    resourceId: 'obj-1'
  }
}

function cleanupProtocol(): DeclaredCleanupProtocol {
  return {
    kind: 'reset',
    declaredByTarget: true,
    capabilityId: L2_CLEANUP_CAPABILITY_ID,
    method: 'POST',
    path: '/test-objects/obj-1',
    expectedTerminalState: 'absent',
    maxRequests: 1
  }
}

function intentHash() {
  return {
    domain: 'agentgo.template-intent.v1' as const,
    algorithm: 'sha256' as const,
    digest: HASH
  }
}

function binding(purpose: 'read' | 'primary' | 'cleanup') {
  return {
    purpose,
    testObjectVersion: 1,
    scopeSnapshotId: uuid(),
    familyId: 'sqli',
    moduleId: 'legacy.sqli.boolean-differential',
    moduleVersion: '1.0.0',
    techniqueId: 'sqli.boolean-differential',
    techniqueVersion: '1.0.0',
    templateIntentHash: intentHash(),
    budget: { maxRequests: 1, maxDurationMs: 5_000 }
  }
}

function envelope(): SideEffectEnvelope {
  return SideEffectEnvelopeSchema.parse({
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
    irreversibleItems: []
  })
}

function testObject(overrides: Record<string, unknown> = {}): TestObjectPayload {
  const scanId = uuid()
  const targetId = uuid()
  const identityId = uuid()
  const scopeSnapshotId = uuid()
  return TestObjectPayloadSchema.parse({
    schemaVersion: 'agentgo-l2-protocol/1.0',
    testObjectId: uuid(),
    objectVersion: 1,
    scanId,
    targetId,
    scopeSnapshotId,
    identityId,
    objectType: 'record',
    disposable: true,
    createdAt: NOW,
    expiresAt: LATER,
    allowedFields: ['status', 'title'],
    allowedStates: ['draft', 'submitted', 'absent'],
    ownershipProofRef: uuid(),
    creationEvidenceHash: HASH,
    baselineEvidenceHash: HASH,
    canonicalResource: resource(),
    cleanupProtocol: cleanupProtocol(),
    closeConditions: ['expired', 'externally-modified', 'ownership-changed'],
    creationAttestation: {
      source: 'agentgo-application',
      createdByAgentGo: true,
      attestedAt: NOW,
      attestationHash: HASH
    },
    ...overrides
  })
}

function bundleSteps(scopeSnapshotId: string) {
  const bind = (purpose: 'read' | 'primary' | 'cleanup') => ({
    ...binding(purpose),
    scopeSnapshotId
  })
  return [
    { kind: 'pre-read' as const, binding: bind('read') },
    { kind: 'primary' as const, binding: bind('primary') },
    { kind: 'post-read' as const, binding: bind('read') },
    {
      kind: 'cleanup' as const,
      binding: bind('cleanup'),
      cleanupProtocol: cleanupProtocol()
    },
    { kind: 'cleanup-verify' as const, binding: bind('read') },
    { kind: 'terminal-read' as const, binding: bind('read') }
  ]
}

function bundleInput(
  object: TestObjectPayload,
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
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
    ...(object.tenantRef ? { tenantRef: object.tenantRef } : {}),
    scopeSnapshotId: object.scopeSnapshotId,
    sideEffectEnvelope: envelope(),
    identityContextVersion: { status: 'unresolved' },
    sessionGeneration: { status: 'unresolved' },
    csrfBindingVersion: { status: 'unresolved' },
    steps: bundleSteps(object.scopeSnapshotId),
    createdAt: NOW,
    ...overrides
  }
}

function bundle(
  object: TestObjectPayload,
  overrides: Record<string, unknown> = {}
): L2ActionBundlePayload {
  return L2ActionBundlePayloadSchema.parse(bundleInput(object, overrides))
}

describe('L2 contracts', () => {
  it('accepts an AgentGo-created disposable TestObject with exact fields', () => {
    expect(testObject().disposable).toBe(true)
    expect(isExactL2FieldPath('status')).toBe(true)
    expect(isExactL2FieldPath('*')).toBe(false)
    expect(isExactL2FieldPath('entire-object')).toBe(false)
  })

  it('rejects missing AgentGo attestation, non-disposable objects and broad fields', () => {
    expect(
      TestObjectPayloadSchema.safeParse({
        ...testObject(),
        creationAttestation: {
          source: 'agent-model',
          createdByAgentGo: true,
          attestedAt: NOW,
          attestationHash: HASH
        }
      }).success
    ).toBe(false)
    expect(
      TestObjectPayloadSchema.safeParse({
        ...testObject(),
        disposable: false
      }).success
    ).toBe(false)
    expect(
      TestObjectPayloadSchema.safeParse({
        ...testObject(),
        allowedFields: ['*']
      }).success
    ).toBe(false)
  })

  it('rejects unknown, unobservable or irreversible side effects only at eligibility, but accepts the envelope schema lists', () => {
    const dirty = SideEffectEnvelopeSchema.parse({
      ...envelope(),
      unknownSideEffects: ['possible webhook']
    })
    expect(dirty.unknownSideEffects).toHaveLength(1)
  })

  it('rejects misordered steps, two primaries and missing cleanup', () => {
    const object = testObject()
    const steps = bundleSteps(object.scopeSnapshotId)
    expect(
      L2ActionBundlePayloadSchema.safeParse(
        bundleInput(object, {
          steps: [steps[1], steps[0], steps[2], steps[3], steps[4], steps[5]]
        })
      ).success
    ).toBe(false)
    expect(
      L2ActionBundlePayloadSchema.safeParse(
        bundleInput(object, {
          steps: [steps[0], steps[1], steps[1], steps[3], steps[4], steps[5]]
        })
      ).success
    ).toBe(false)
  })

  it('rejects generic HTTP DELETE cleanup protocols and expired objects', () => {
    expect(
      TestObjectPayloadSchema.safeParse({
        ...testObject(),
        cleanupProtocol: {
          ...cleanupProtocol(),
          method: 'DELETE'
        }
      }).success
    ).toBe(false)
    expect(
      TestObjectPayloadSchema.safeParse({
        ...testObject(),
        createdAt: LATER,
        expiresAt: NOW
      }).success
    ).toBe(false)
  })

  it('accepts cleanup-not-needed as step 4 when the remaining order is intact', () => {
    const object = testObject()
    const steps = bundleSteps(object.scopeSnapshotId)
    const parsed = L2ActionBundlePayloadSchema.safeParse(
      bundleInput(object, {
        steps: [
          steps[0],
          steps[1],
          steps[2],
          { kind: 'cleanup-not-needed', justification: 'not-needed-no-state-change' },
          steps[4],
          steps[5]
        ]
      })
    )
    expect(parsed.success).toBe(true)
  })

  it('accepts unresolved session-binding slots on a draft-capable bundle payload', () => {
    const parsed = bundle(testObject())
    expect(parsed.identityContextVersion.status).toBe('unresolved')
    expect(parsed.sessionGeneration.status).toBe('unresolved')
    expect(parsed.csrfBindingVersion.status).toBe('unresolved')
  })

  it('rejects not-needed receipts that omit required evidence hashes', () => {
    expect(
      CleanupReceiptPayloadSchema.safeParse({
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
          postRead: HASH
        },
        actorSlot: { status: 'unresolved' },
        issuedAt: NOW,
        terminalResourceState: 'unchanged',
        cleanupCapabilityId: L2_CLEANUP_CAPABILITY_ID,
        requestExecutionState: 'sent-known-complete'
      }).success
    ).toBe(false)
  })
})
