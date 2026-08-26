import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  L2_CLEANUP_CAPABILITY_ID,
  ScanModuleSnapshotDraftSchema,
  type L2ActionBundlePayload,
  type SideEffectEnvelope,
  type TestObjectPayload
} from '@agentgo/contracts'
import { sealL2ActionBundle, sealTestObject } from '@agentgo/domain'
import { openAgentGoDatabase, type AgentGoDatabase } from './database'
import { L2Repository } from './l2-repository'
import { AgentGoRepository } from './repository'

const HASH = 'b'.repeat(64)
const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

const temporaryDirectories: string[] = []
const openDatabases: AgentGoDatabase[] = []

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function trackDatabase(database: AgentGoDatabase): AgentGoDatabase {
  openDatabases.push(database)
  return database
}

async function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-l2-'))
  temporaryDirectories.push(directory)
  const database = trackDatabase(openAgentGoDatabase(join(directory, 'agentgo.sqlite')))
  const repository = new AgentGoRepository(database)
  const l2 = new L2Repository(database)
  const workspace = await repository.createWorkspace({
    name: 'L2 fixture',
    description: 'Network-free L2 persistence tests.'
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'L2 lab',
    baseUrl: 'https://lab.example.test',
    description: 'No network.',
    authorizationReference: 'l2-db-test',
    scope: {
      allowedOrigins: ['https://lab.example.test'],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [443],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: true,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      networkEntries: [],
      maxRequestsPerMinute: 20,
      maxConcurrency: 2,
      authorizationReference: 'l2-db-test'
    }
  })
  const identity = await repository.saveIdentity({
    targetId: target.target.id,
    label: 'L2 test identity',
    role: 'owner',
    authType: 'none',
    isTestIdentity: true,
    ownedResourceIds: []
  })
  await repository.updateTarget({
    id: target.target.id,
    scope: {
      allowedOrigins: target.scope.allowedOrigins,
      allowedPathPrefixes: target.scope.allowedPathPrefixes,
      deniedPathPrefixes: target.scope.deniedPathPrefixes,
      allowedPorts: target.scope.allowedPorts,
      allowedIdentityIds: [identity.id],
      allowActiveProbing: true,
      allowSensitiveProbing: true,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      networkEntries: target.scope.networkEntries,
      maxRequestsPerMinute: 20,
      maxConcurrency: 2,
      authorizationReference: 'l2-db-test'
    }
  })
  const moduleDraft = ScanModuleSnapshotDraftSchema.parse({
    familyId: 'sqli',
    moduleId: 'test.sqli.module',
    moduleVersion: '1.0.0',
    definitionHash: sha256('l2-module-definition'),
    techniqueId: 'sqli.query-differential',
    techniqueVersion: '1.0.0',
    strategyRefs: [{ id: 'test.sqli.strategy', version: '1.0.0' }],
    confirmationRuleRefs: [{ id: 'test.sqli.rule', version: '1.0.0' }],
    evidenceProfileRefs: [{ id: 'test.sqli.evidence', version: '1.0.0' }],
    remediationRefs: [{ id: 'test.sqli.remediation', version: '1.0.0' }],
    requiredCapabilityIds: ['http.reviewed-read'],
    capabilityDescriptors: [
      {
        id: 'http.reviewed-read',
        riskFloor: 'l1',
        descriptorHash: sha256('http.reviewed-read')
      }
    ],
    capabilitySnapshotHash: sha256('l2-capability-snapshot'),
    selectedCapabilitiesHash: sha256('l2-selected-capabilities'),
    selectedDefinitionsHash: sha256('l2-selected-definitions'),
    registrySnapshotHash: sha256('l2-registry-snapshot'),
    environment: 'authorized-test-environment',
    authorization: 'qualified'
  })
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'L2 scan',
      description: 'Persistence only.',
      families: ['sqli'],
      identityIds: [identity.id],
      budget: {
        maxRequests: 8,
        maxRequestsPerMinute: 20,
        maxConcurrency: 2,
        maxPlanRevisions: 0,
        maxDurationMinutes: 10,
        maxModelTokens: 0,
        maxEstimatedCost: 0,
        maxRequestBytes: 1_146_880,
        maxResponseBytes: 16_777_216
      }
    },
    { version: '1.0.0', steps: ['l2.protocol'] },
    {},
    [{ draft: moduleDraft, snapshotHash: sha256('l2-module-snapshot') }]
  )
  return {
    database,
    repository,
    l2,
    scan,
    identity,
    scopeSnapshotId: scan.scopeSnapshotId,
    targetId: target.target.id
  }
}

function envelope(): SideEffectEnvelope {
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
    irreversibleItems: []
  }
}

function objectPayload(input: {
  scanId: string
  targetId: string
  identityId: string
  scopeSnapshotId: string
}): TestObjectPayload {
  const now = '2026-08-20T12:00:00.000Z'
  return {
    schemaVersion: 'agentgo-l2-protocol/1.0',
    testObjectId: randomUUID(),
    objectVersion: 1,
    scanId: input.scanId,
    targetId: input.targetId,
    scopeSnapshotId: input.scopeSnapshotId,
    identityId: input.identityId,
    objectType: 'record',
    disposable: true,
    createdAt: now,
    expiresAt: '2026-08-22T12:00:00.000Z',
    allowedFields: ['status'],
    allowedStates: ['draft', 'submitted', 'absent'],
    ownershipProofRef: randomUUID(),
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
      attestedAt: now,
      attestationHash: HASH
    }
  }
}

function binding(object: TestObjectPayload, purpose: 'read' | 'primary' | 'cleanup') {
  return {
    purpose,
    testObjectVersion: object.objectVersion,
    scopeSnapshotId: object.scopeSnapshotId,
    familyId: 'sqli' as const,
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
    bundleId: randomUUID(),
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
    steps: [
      { kind: 'pre-read', binding: binding(object, 'read') },
      { kind: 'primary', binding: binding(object, 'primary') },
      { kind: 'post-read', binding: binding(object, 'read') },
      {
        kind: 'cleanup',
        binding: binding(object, 'cleanup'),
        cleanupProtocol: object.cleanupProtocol
      },
      { kind: 'cleanup-verify', binding: binding(object, 'read') },
      { kind: 'terminal-read', binding: binding(object, 'read') }
    ],
    createdAt: object.createdAt
  }
}

afterEach(() => {
  expect(fetchMock).not.toHaveBeenCalled()
  fetchMock.mockClear()
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('L2 repository', () => {
  it('persists immutable TestObjects and optimistic bundle runtime', async () => {
    const fixture = await createFixture()
    const payload = objectPayload({
      scanId: fixture.scan.id,
      targetId: fixture.targetId,
      identityId: fixture.identity.id,
      scopeSnapshotId: fixture.scopeSnapshotId
    })
    const object = await fixture.l2.insertTestObject(sealTestObject(payload))
    const loaded = await fixture.l2.getTestObject(object.testObjectId, 1)
    expect(loaded?.objectHash).toBe(object.objectHash)

    const update = fixture.database.native.prepare(
      'UPDATE test_objects SET object_hash = ? WHERE test_object_id = ?'
    )
    expect(() => update.run('c'.repeat(64), object.testObjectId)).toThrow(
      /test objects are immutable/i
    )

    const bundle = sealL2ActionBundle({
      ...bundlePayload(payload),
      testObjectHash: object.objectHash
    })
    const runtime = await fixture.l2.insertBundle({ bundle, state: 'draft' })
    expect(runtime.rowVersion).toBe(1)
    await fixture.l2.applyRuntimeTransition({
      bundleId: bundle.bundleId,
      bundleVersion: 1,
      expectedRowVersion: 1,
      fromState: 'draft',
      toState: 'revoked',
      eventType: 'revoke',
      reasonCode: 'ok',
      primaryStarted: false,
      primarySentProof: 'not-sent'
    })
    await expect(
      fixture.l2.applyRuntimeTransition({
        bundleId: bundle.bundleId,
        bundleVersion: 1,
        expectedRowVersion: 1,
        fromState: 'draft',
        toState: 'expired',
        eventType: 'expire',
        reasonCode: 'ok',
        primaryStarted: false,
        primarySentProof: 'not-sent'
      })
    ).rejects.toThrow(/concurrent version conflict/i)
  })

  it('stores a single freeze per target and TestObject', async () => {
    const fixture = await createFixture()
    const payload = objectPayload({
      scanId: fixture.scan.id,
      targetId: fixture.targetId,
      identityId: fixture.identity.id,
      scopeSnapshotId: fixture.scopeSnapshotId
    })
    const object = await fixture.l2.insertTestObject(sealTestObject(payload))
    const bundle = sealL2ActionBundle({
      ...bundlePayload(payload),
      testObjectHash: object.objectHash
    })
    await fixture.l2.insertBundle({ bundle, state: 'cleanup-failed' })
    const freeze = await fixture.l2.insertFreeze({
      freezeId: randomUUID(),
      targetId: object.targetId,
      testObjectId: object.testObjectId,
      bundleId: bundle.bundleId,
      bundleHash: bundle.bundleHash,
      reasonCode: 'cleanup-failed-frozen',
      allows: 'recovery-proposal-or-manual',
      createdAt: object.createdAt
    })
    const duplicate = await fixture.l2.insertFreeze({
      freezeId: randomUUID(),
      targetId: object.targetId,
      testObjectId: object.testObjectId,
      bundleId: bundle.bundleId,
      bundleHash: bundle.bundleHash,
      reasonCode: 'cleanup-failed-frozen',
      allows: 'recovery-proposal-or-manual',
      createdAt: object.createdAt
    })
    expect(duplicate.freezeId).toBe(freeze.freezeId)
  })
})
