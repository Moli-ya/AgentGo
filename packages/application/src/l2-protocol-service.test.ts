import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  L2_CLEANUP_CAPABILITY_ID,
  ScanModuleSnapshotDraftSchema,
  type L2BundleStep,
  type SideEffectEnvelope,
  type TestObject
} from '@agentgo/contracts'
import { sealL2ActionBundle } from '@agentgo/domain'
import {
  AgentGoRepository,
  L2Repository,
  openAgentGoDatabase,
  type AgentGoDatabase
} from '@agentgo/db'
import {
  L2ProtocolError,
  L2ProtocolService
} from './l2-protocol-service'

const HASH = 'b'.repeat(64)
const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

const temporaryDirectories: string[] = []
const openDatabases: AgentGoDatabase[] = []

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

async function createHarness(now = new Date('2026-08-20T12:00:00.000Z')) {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-l2-app-'))
  temporaryDirectories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const scanRepository = new AgentGoRepository(database)
  const l2Repository = new L2Repository(database)
  const workspace = await scanRepository.createWorkspace({
    name: 'L2 application fixture',
    description: 'Zero-network L2 protocol service tests.'
  })
  const created = await scanRepository.createTarget({
    workspaceId: workspace.id,
    name: 'L2 app lab',
    baseUrl: 'https://lab.example.test',
    description: 'No I/O.',
    authorizationReference: 'l2-app-test',
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
      authorizationReference: 'l2-app-test'
    }
  })
  const identity = await scanRepository.saveIdentity({
    targetId: created.target.id,
    label: 'L2 test identity',
    role: 'owner',
    authType: 'none',
    isTestIdentity: true,
    ownedResourceIds: []
  })
  await scanRepository.updateTarget({
    id: created.target.id,
    scope: {
      allowedOrigins: created.scope.allowedOrigins,
      allowedPathPrefixes: created.scope.allowedPathPrefixes,
      deniedPathPrefixes: created.scope.deniedPathPrefixes,
      allowedPorts: created.scope.allowedPorts,
      allowedIdentityIds: [identity.id],
      allowActiveProbing: true,
      allowSensitiveProbing: true,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      networkEntries: created.scope.networkEntries,
      maxRequestsPerMinute: 20,
      maxConcurrency: 2,
      authorizationReference: 'l2-app-test'
    }
  })
  const moduleDraft = ScanModuleSnapshotDraftSchema.parse({
    familyId: 'sqli',
    moduleId: 'test.sqli.module',
    moduleVersion: '1.0.0',
    definitionHash: sha256('l2-app-module'),
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
    capabilitySnapshotHash: sha256('l2-app-capability'),
    selectedCapabilitiesHash: sha256('l2-app-selected-cap'),
    selectedDefinitionsHash: sha256('l2-app-selected-def'),
    registrySnapshotHash: sha256('l2-app-registry'),
    environment: 'authorized-test-environment',
    authorization: 'qualified'
  })
  const scan = await scanRepository.createScan(
    {
      targetId: created.target.id,
      name: 'L2 application scan',
      description: 'Protocol only.',
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
    [{ draft: moduleDraft, snapshotHash: sha256('l2-app-snapshot') }]
  )
  const service = new L2ProtocolService({
    l2Repository,
    scanRepository,
    now: () => now
  })
  return { service, l2Repository, scan, identity, targetId: created.target.id }
}

function envelope(unknown: string[] = []): SideEffectEnvelope {
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
    unknownSideEffects: unknown,
    unobservableSideEffects: [],
    irreversibleItems: []
  }
}

function steps(object: TestObject): L2BundleStep[] {
  const bind = (purpose: 'read' | 'primary' | 'cleanup') => ({
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
  })
  return [
    { kind: 'pre-read', binding: bind('read') },
    { kind: 'primary', binding: bind('primary') },
    { kind: 'post-read', binding: bind('read') },
    {
      kind: 'cleanup',
      binding: bind('cleanup'),
      cleanupProtocol: object.cleanupProtocol
    },
    { kind: 'cleanup-verify', binding: bind('read') },
    { kind: 'terminal-read', binding: bind('read') }
  ]
}

async function createObject(service: L2ProtocolService, scanId: string, targetId: string, identityId: string) {
  return service.createTestObject({
    scanId,
    targetId,
    identityId,
    objectType: 'record',
    allowedFields: ['status'],
    allowedStates: ['draft', 'submitted', 'absent'],
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
    expiresAt: '2026-08-22T12:00:00.000Z',
    creationEvidenceHash: HASH,
    baselineEvidenceHash: HASH
  })
}

afterEach(() => {
  expect(fetchMock).not.toHaveBeenCalled()
  fetchMock.mockClear()
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('L2 protocol service', () => {
  it('issues AgentGo attestations and keeps unresolved session-binding bundles in draft', async () => {
    const harness = await createHarness()
    const object = await createObject(
      harness.service,
      harness.scan.id,
      harness.targetId,
      harness.identity.id
    )
    expect(object.creationAttestation.source).toBe('agentgo-application')
    expect(object.creationAttestation.createdByAgentGo).toBe(true)
    expect(object.disposable).toBe(true)
    const view = await harness.service.proposeBundle({
      scanId: harness.scan.id,
      targetId: harness.targetId,
      testObjectId: object.testObjectId,
      testObjectVersion: 1,
      sideEffectEnvelope: envelope(),
      steps: steps(object)
    })
    expect(view.runtime.state).toBe('draft')
    expect(view.bundle.identityContextVersion.status).toBe('unresolved')
    const submitError = await harness.service
      .applyEvent({
        bundleId: view.bundle.bundleId,
        bundleVersion: 1,
        event: 'submit-for-approval',
        expectedRowVersion: view.runtime.rowVersion
      })
      .then(
        () => undefined,
        (error: unknown) => error
      )
    expect(submitError).toBeInstanceOf(L2ProtocolError)
    expect((submitError as L2ProtocolError).reasonCode).toBe('session-binding-unresolved')
    const approveError = await harness.service
      .applyEvent({
        bundleId: view.bundle.bundleId,
        bundleVersion: 1,
        event: 'approve',
        expectedRowVersion: view.runtime.rowVersion
      })
      .then(
        () => undefined,
        (error: unknown) => error
      )
    expect(approveError).toBeInstanceOf(L2ProtocolError)
    expect((approveError as L2ProtocolError).reasonCode).toBe('trusted-approval-missing')
  })

  it('persists unknown side effects as ineligible and rejects forged receipts', async () => {
    const harness = await createHarness()
    const object = await createObject(
      harness.service,
      harness.scan.id,
      harness.targetId,
      harness.identity.id
    )
    const dirty = await harness.service.proposeBundle({
      scanId: harness.scan.id,
      targetId: harness.targetId,
      testObjectId: object.testObjectId,
      testObjectVersion: 1,
      sideEffectEnvelope: envelope(['possible webhook']),
      steps: steps(object)
    })
    expect(dirty.runtime.state).toBe('ineligible')
    await expect(
      harness.service.issueCleanupReceipt({
        receiptId: randomUUID(),
        kind: 'not-needed-no-state-change',
        bundleId: dirty.bundle.bundleId,
        bundleHash: dirty.bundle.bundleHash,
        testObjectId: object.testObjectId,
        testObjectVersion: 1,
        testObjectHash: object.objectHash,
        stepEvidenceHashes: {
          preRead: HASH,
          postRead: HASH,
          cleanupVerify: HASH,
          terminalRead: HASH
        },
        issuedAt: '2026-08-20T12:00:00.000Z',
        terminalResourceState: 'unchanged',
        cleanupCapabilityId: L2_CLEANUP_CAPABILITY_ID,
        requestExecutionState: 'timeout'
      })
    ).rejects.toBeInstanceOf(L2ProtocolError)
  })

  it('walks cleanup failure freeze without sending requests and blocks later candidates', async () => {
    const harness = await createHarness()
    const object = await createObject(
      harness.service,
      harness.scan.id,
      harness.targetId,
      harness.identity.id
    )
    const sealed = sealL2ActionBundle({
      schemaVersion: 'agentgo-l2-protocol/1.0',
      bundleId: randomUUID(),
      bundleVersion: 1,
      scanId: object.scanId,
      targetId: object.targetId,
      testObjectId: object.testObjectId,
      testObjectVersion: 1,
      testObjectHash: object.objectHash,
      identityId: object.identityId,
      scopeSnapshotId: object.scopeSnapshotId,
      sideEffectEnvelope: envelope(),
      identityContextVersion: { status: 'resolved', version: 'identity-1' },
      sessionGeneration: { status: 'resolved', version: 'session-1' },
      csrfBindingVersion: { status: 'resolved', version: 'csrf-1' },
      steps: steps(object),
      createdAt: object.createdAt
    })
    await harness.l2Repository.insertBundle({ bundle: sealed, state: 'draft' })
    let view = await harness.service.applyEvent({
      bundleId: sealed.bundleId,
      bundleVersion: 1,
      event: 'submit-for-approval',
      expectedRowVersion: 1
    })
    await expect(
      harness.service.applyEvent({
        bundleId: sealed.bundleId,
        bundleVersion: 1,
        event: 'approve',
        expectedRowVersion: view.runtime.rowVersion
      })
    ).rejects.toMatchObject({ reasonCode: 'trusted-approval-missing' })
    const sequence = [
      'approve',
      'start-pre-read',
      'complete-pre-read',
      'start-primary',
      'complete-primary',
      'complete-post-read',
      'start-cleanup',
      'fail-cleanup'
    ] as const
    for (const event of sequence) {
      view = await harness.service.applyEvent({
        bundleId: sealed.bundleId,
        bundleVersion: 1,
        event,
        expectedRowVersion: view.runtime.rowVersion,
        trustedApprovalPresent: true
      })
    }
    expect(view.runtime.state).toBe('cleanup-failed')
    expect(await harness.service.isOrdinaryQueueFrozen(object.targetId, object.testObjectId)).toBe(
      true
    )
    await expect(
      harness.service.proposeBundle({
        scanId: object.scanId,
        targetId: object.targetId,
        testObjectId: object.testObjectId,
        testObjectVersion: 1,
        sideEffectEnvelope: envelope(),
        steps: steps(object)
      })
    ).rejects.toMatchObject({ reasonCode: 'cleanup-failed-frozen' })
    expect(fetchMock.mock.calls).toEqual([])
  })
})
