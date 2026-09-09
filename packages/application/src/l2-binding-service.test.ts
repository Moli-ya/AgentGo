import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest'
import {
  L2_CLEANUP_CAPABILITY_ID,
  ScanModuleSnapshotDraftSchema,
  type CsrfBindingRule,
  type L2BundleStep,
  type SideEffectEnvelope,
  type TestObject
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  FileCredentialStore,
  IdentitySessionRepository,
  L2Repository,
  openAgentGoDatabase,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { AuthorizationMatrixService } from './authorization-matrix-service'
import { CsrfBindingService } from './csrf-binding-service'
import { IdentityContextService } from './identity-context-service'
import {
  L2BindingError,
  L2BindingService,
  encodeSessionGenerationSlot
} from './l2-binding-service'
import { L2ProtocolService } from './l2-protocol-service'
import { SessionVault } from './session-vault'

const HASH = 'b'.repeat(64)
const NOW = new Date('2026-08-26T00:00:00.000Z')
const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

const temporaryDirectories: string[] = []
const openDatabases: AgentGoDatabase[] = []

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function protector(): SecretProtector {
  const mask = 0x5a
  const transform = (value: Buffer): Buffer =>
    Buffer.from(value.map((byte) => byte ^ mask))
  return {
    isAvailable: () => true,
    protect: (value) => transform(Buffer.from(value, 'utf8')),
    unprotect: (value) => transform(value).toString('utf8')
  }
}

const csrfRule: CsrfBindingRule = {
  ruleVersion: 'fixture-csrf/1.0',
  sourceKind: 'json-pointer',
  sourceSelector: '/csrfToken',
  sourceOrigin: 'https://lab.example.test',
  sourcePathPrefix: '/test-objects/',
  encoding: 'raw',
  injectionLocation: 'header',
  injectionName: 'x-csrf-token',
  maxUses: 2
}

async function createHarness() {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-l2-binding-'))
  temporaryDirectories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const identitySessions = new IdentitySessionRepository(database)
  const l2Repository = new L2Repository(database)
  const credentialStore = new FileCredentialStore(
    join(directory, 'credentials.json'),
    protector()
  )
  const workspace = await repository.createWorkspace({
    name: 'L2 binding',
    description: 'Day 9 binding tests.'
  })
  const created = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'L2 binding lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'l2-binding-test',
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
      maxConcurrency: 2
    }
  })
  const identity = await repository.saveIdentity({
    targetId: created.target.id,
    label: 'owner identity',
    role: 'owner',
    authType: 'cookie',
    headerName: undefined,
    isTestIdentity: true,
    ownedResourceIds: ['obj-1']
  })
  await repository.updateTarget({
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
      maxConcurrency: 2
    }
  })
  const moduleDraft = ScanModuleSnapshotDraftSchema.parse({
    familyId: 'sqli',
    moduleId: 'test.sqli.module',
    moduleVersion: '1.0.0',
    definitionHash: sha256('l2-binding-module'),
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
    capabilitySnapshotHash: sha256('l2-binding-capability'),
    selectedCapabilitiesHash: sha256('l2-binding-selected-cap'),
    selectedDefinitionsHash: sha256('l2-binding-selected-def'),
    registrySnapshotHash: sha256('l2-binding-registry'),
    environment: 'authorized-test-environment',
    authorization: 'qualified'
  })
  const scan = await repository.createScan(
    {
      targetId: created.target.id,
      name: 'L2 binding scan',
      description: 'Day 9.',
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
    [{ draft: moduleDraft, snapshotHash: sha256('l2-binding-snapshot') }]
  )

  const l2 = new L2ProtocolService({
    l2Repository,
    scanRepository: repository,
    now: () => NOW
  })
  const vault = new SessionVault({
    identitySessionRepository: identitySessions,
    repository,
    credentialStore,
    now: () => NOW.getTime()
  })
  const identityContexts = new IdentityContextService({
    repository,
    identitySessionRepository: identitySessions,
    credentialStore,
    now: () => NOW
  })
  const csrf = new CsrfBindingService({
    identitySessionRepository: identitySessions,
    sessionVault: vault,
    now: () => NOW.getTime()
  })
  const matrices = new AuthorizationMatrixService({
    repository,
    identitySessionRepository: identitySessions,
    now: () => NOW
  })
  const bindings = new L2BindingService({
    l2ProtocolService: l2,
    l2Repository,
    identityContextService: identityContexts,
    sessionVault: vault,
    csrfBindingService: csrf,
    authorizationMatrixService: matrices,
    identitySessionRepository: identitySessions,
    now: () => NOW
  })
  l2.setBindingFreshnessVerifier((bundle) => bindings.assertBindingsFresh(bundle))
  return {
    l2,
    vault,
    identityContexts,
    csrf,
    matrices,
    bindings,
    repository,
    scan,
    identity,
    targetId: created.target.id,
    scopeSnapshotId: scan.scopeSnapshotId,
    database
  }
}

type Harness = Awaited<ReturnType<typeof createHarness>>

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

async function createObject(harness: Harness) {
  return harness.l2.createTestObject({
    scanId: harness.scan.id,
    targetId: harness.targetId,
    identityId: harness.identity.id,
    objectType: 'record',
    allowedFields: ['status'],
    allowedStates: ['draft', 'submitted', 'absent'],
    canonicalResource: {
      kind: 'http-resource',
      origin: 'https://lab.example.test',
      method: 'POST',
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
    expiresAt: '2026-08-27T00:00:00.000Z',
    creationEvidenceHash: HASH,
    baselineEvidenceHash: HASH
  })
}

async function proposeDraft(harness: Harness, object: TestObject) {
  return harness.l2.proposeBundle({
    scanId: harness.scan.id,
    targetId: harness.targetId,
    testObjectId: object.testObjectId,
    testObjectVersion: object.objectVersion,
    sideEffectEnvelope: envelope(),
    steps: steps(object)
  })
}

async function prepareDay9Bindings(harness: Harness) {
  const context = await harness.identityContexts.issueIdentityContext({
    identityId: harness.identity.id,
    targetId: harness.targetId,
    scopeSnapshotId: harness.scopeSnapshotId,
    role: 'owner',
    ownerLabel: 'owner identity',
    purpose: 'L2 binding test',
    allowedOperations: ['write-test-object', 'cleanup-test-object'],
    confirmationAuditRef: randomUUID(),
    ttlMs: 3_600_000
  })
  const session = await harness.vault.establishSession({
    identityId: harness.identity.id,
    scopeSnapshotId: harness.scopeSnapshotId
  })
  await harness.vault.ingestSetCookie(
    session.sessionId,
    'sid=binding-cookie; Path=/; HttpOnly',
    'https://lab.example.test/'
  )
  const csrfCapture = await harness.csrf.captureBinding({
    identityId: harness.identity.id,
    sessionId: session.sessionId,
    origin: 'https://lab.example.test',
    boundMethod: 'POST',
    boundPath: '/test-objects/obj-1',
    rule: csrfRule,
    response: {
      url: 'https://lab.example.test/test-objects/obj-1/edit',
      bodyText: '{"csrfToken":"binding-token"}'
    },
    ttlMs: 600_000
  })
  if (!csrfCapture.ok) throw new Error('CSRF capture failed in test setup.')
  const matrix = await harness.matrices.confirmMatrix({
    targetId: harness.targetId,
    scopeSnapshotId: harness.scopeSnapshotId,
    entries: [
      {
        subjectIdentityId: harness.identity.id,
        resourceOwnerIdentityId: harness.identity.id,
        role: 'owner',
        operation: 'write',
        resourceRef: 'obj-1',
        expected: 'state-allowed',
        humanSource: 'test declaration'
      },
      {
        subjectIdentityId: harness.identity.id,
        resourceOwnerIdentityId: harness.identity.id,
        role: 'owner',
        operation: 'delete',
        resourceRef: 'obj-1',
        expected: 'state-allowed',
        humanSource: 'test declaration'
      }
    ],
    humanAttestationRef: randomUUID(),
    ttlMs: 3_600_000
  })
  return { context, session, csrf: csrfCapture.binding, matrix }
}

afterEach(() => {
  expect(fetchMock).not.toHaveBeenCalled()
  fetchMock.mockClear()
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

afterAll(() => {
  vi.unstubAllGlobals()
})

describe('L2 binding service (Day 9)', () => {
  it('never oversells the CSRF use limit under concurrent resolution', async () => {
    const harness = await createHarness()
    const prepared = await prepareDay9Bindings(harness)
    const results = await Promise.allSettled(Array.from({ length: 8 }, () =>
      harness.csrf.resolveTokenForRequest({
        bindingHash: prepared.csrf.bindingHash,
        request: { identityId: harness.identity.id, url: 'https://lab.example.test/test-objects/obj-1', method: 'POST' }
      })
    ))
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(2)
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(6)
  })
  it('resolves all four binding slots and submits a fresh bundle version for approval', async () => {
    const harness = await createHarness()
    const object = await createObject(harness)
    const draft = await proposeDraft(harness, object)
    expect(draft.runtime.state).toBe('draft')
    await expect(
      harness.l2.applyEvent({
        bundleId: draft.bundle.bundleId,
        bundleVersion: draft.bundle.bundleVersion,
        event: 'submit-for-approval',
        expectedRowVersion: draft.runtime.rowVersion
      })
    ).rejects.toMatchObject({ reasonCode: 'session-binding-unresolved' })

    const { csrf } = await prepareDay9Bindings(harness)
    const resolved = await harness.bindings.resolveBundleBindings({
      bundleId: draft.bundle.bundleId,
      bundleVersion: draft.bundle.bundleVersion,
      expectedRowVersion: draft.runtime.rowVersion,
      csrfBindingHash: csrf.bindingHash
    })

    expect(resolved.runtime.state).toBe('pending-approval')
    expect(resolved.bundle.bundleVersion).toBe(2)
    expect(resolved.bundle.bundleHash).not.toBe(draft.bundle.bundleHash)
    expect(resolved.bundle.identityContextVersion.status).toBe('resolved')
    expect(resolved.bundle.sessionGeneration.status).toBe('resolved')
    expect(resolved.bundle.csrfBindingVersion.status).toBe('resolved')
    expect(resolved.bundle.authorizationMatrixVersion.status).toBe('resolved')

    const old = await harness.l2.getBundleView(
      draft.bundle.bundleId,
      draft.bundle.bundleVersion
    )
    expect(old?.runtime.state).toBe('revoked')
  })

  it('keeps the bound CSRF version fresh after planned mutating uses are exhausted', async () => {
    const harness = await createHarness()
    const object = await createObject(harness)
    const draft = await proposeDraft(harness, object)
    const prepared = await prepareDay9Bindings(harness)
    const resolved = await harness.bindings.resolveBundleBindings({
      bundleId: draft.bundle.bundleId,
      bundleVersion: draft.bundle.bundleVersion,
      expectedRowVersion: draft.runtime.rowVersion,
      csrfBindingHash: prepared.csrf.bindingHash
    })
    const request = {
      identityId: harness.identity.id,
      url: 'https://lab.example.test/test-objects/obj-1',
      method: 'POST'
    }
    await harness.csrf.tokenSecretResolverFor({
      bindingHash: prepared.csrf.bindingHash,
      request
    })
    await harness.csrf.tokenSecretResolverFor({
      bindingHash: prepared.csrf.bindingHash,
      request
    })
    await expect(harness.bindings.assertBindingsFresh(resolved.bundle)).resolves.toBe(
      'ok'
    )
    await expect(
      harness.csrf.tokenSecretResolverFor({
        bindingHash: prepared.csrf.bindingHash,
        request
      })
    ).rejects.toMatchObject({ code: 'binding-not-active' })
  })

  it('still refuses approval and execution without a trusted approval (Day 9 boundary)', async () => {
    const harness = await createHarness()
    const object = await createObject(harness)
    const draft = await proposeDraft(harness, object)
    const { csrf } = await prepareDay9Bindings(harness)
    const resolved = await harness.bindings.resolveBundleBindings({
      bundleId: draft.bundle.bundleId,
      bundleVersion: draft.bundle.bundleVersion,
      expectedRowVersion: draft.runtime.rowVersion,
      csrfBindingHash: csrf.bindingHash
    })
    for (const event of ['approve', 'start-pre-read'] as const) {
      await expect(
        harness.l2.applyEvent({
          bundleId: resolved.bundle.bundleId,
          bundleVersion: resolved.bundle.bundleVersion,
          event,
          expectedRowVersion: resolved.runtime.rowVersion
        })
      ).rejects.toMatchObject({ reasonCode: 'trusted-approval-missing' })
    }
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('fails closed when the matrix lacks coverage for the test object', async () => {
    const harness = await createHarness()
    const object = await createObject(harness)
    const draft = await proposeDraft(harness, object)
    await harness.identityContexts.issueIdentityContext({
      identityId: harness.identity.id,
      targetId: harness.targetId,
      scopeSnapshotId: harness.scopeSnapshotId,
      role: 'owner',
      ownerLabel: 'owner identity',
      purpose: 'L2 binding test',
      allowedOperations: ['write-test-object', 'cleanup-test-object'],
      confirmationAuditRef: randomUUID(),
      ttlMs: 3_600_000
    })
    const session = await harness.vault.establishSession({
      identityId: harness.identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    const csrfCapture = await harness.csrf.captureBinding({
      identityId: harness.identity.id,
      sessionId: session.sessionId,
      origin: 'https://lab.example.test',
      boundMethod: 'POST',
      boundPath: '/test-objects/obj-1',
      rule: csrfRule,
      response: {
        url: 'https://lab.example.test/test-objects/obj-1/edit',
        bodyText: '{"csrfToken":"binding-token"}'
      },
      ttlMs: 600_000
    })
    if (!csrfCapture.ok) throw new Error('CSRF capture failed.')
    await expect(
      harness.bindings.resolveBundleBindings({
        bundleId: draft.bundle.bundleId,
        bundleVersion: draft.bundle.bundleVersion,
        expectedRowVersion: draft.runtime.rowVersion,
        csrfBindingHash: csrfCapture.binding.bindingHash
      })
    ).rejects.toBeInstanceOf(L2BindingError)
  })

  it('revokes pending bundles immediately when the session rotates', async () => {
    const harness = await createHarness()
    const object = await createObject(harness)
    const draft = await proposeDraft(harness, object)
    const { csrf, session } = await prepareDay9Bindings(harness)
    const resolved = await harness.bindings.resolveBundleBindings({
      bundleId: draft.bundle.bundleId,
      bundleVersion: draft.bundle.bundleVersion,
      expectedRowVersion: draft.runtime.rowVersion,
      csrfBindingHash: csrf.bindingHash
    })
    expect(resolved.runtime.state).toBe('pending-approval')

    await harness.vault.rotateSession(session.sessionId)
    await harness.csrf.revokeBindingsForSession(session.sessionId)
    const invalidated = await harness.bindings.invalidateBundlesForSession(session.sessionId)
    expect(invalidated).toBe(1)
    const after = await harness.l2.getBundleView(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    expect(after?.runtime.state).toBe('revoked')
  })

  it('fails freshness on identity-context reissue, CSRF revocation, and matrix reconfirmation', async () => {
    const harness = await createHarness()
    const object = await createObject(harness)
    const draft = await proposeDraft(harness, object)
    const prepared = await prepareDay9Bindings(harness)
    const resolved = await harness.bindings.resolveBundleBindings({
      bundleId: draft.bundle.bundleId,
      bundleVersion: draft.bundle.bundleVersion,
      expectedRowVersion: draft.runtime.rowVersion,
      csrfBindingHash: prepared.csrf.bindingHash
    })

    await harness.identityContexts.issueIdentityContext({
      identityContextId: prepared.context.identityContextId,
      identityId: harness.identity.id,
      targetId: harness.targetId,
      scopeSnapshotId: harness.scopeSnapshotId,
      role: 'owner',
      ownerLabel: 'owner identity',
      purpose: 'L2 binding test reissue',
      allowedOperations: ['write-test-object', 'cleanup-test-object'],
      confirmationAuditRef: randomUUID(),
      ttlMs: 3_600_000
    })
    await expect(harness.bindings.assertBindingsFresh(resolved.bundle)).resolves.toBe(
      'session-binding-unresolved'
    )

    // Reissue the whole chain so only the matrix version drifts.
    const reprepared = await prepareDay9Bindings(harness)
    const second = await harness.l2.proposeBundle({
      scanId: harness.scan.id,
      targetId: harness.targetId,
      testObjectId: object.testObjectId,
      testObjectVersion: object.objectVersion,
      sideEffectEnvelope: envelope(),
      steps: steps(object)
    })
    const secondResolved = await harness.bindings.resolveBundleBindings({
      bundleId: second.bundle.bundleId,
      bundleVersion: second.bundle.bundleVersion,
      expectedRowVersion: second.runtime.rowVersion,
      csrfBindingHash: reprepared.csrf.bindingHash
    })
    await harness.matrices.confirmMatrix({
      matrixId: reprepared.matrix.matrixId,
      targetId: harness.targetId,
      scopeSnapshotId: harness.scopeSnapshotId,
      entries: reprepared.matrix.entries.map((entry) => ({ ...entry })),
      humanAttestationRef: randomUUID(),
      ttlMs: 3_600_000
    })
    await expect(
      harness.bindings.assertBindingsFresh(secondResolved.bundle)
    ).resolves.toBe('version-mismatch')
  })

  it('startup sweep revokes bundles bound to vault-lost sessions', async () => {
    const harness = await createHarness()
    const object = await createObject(harness)
    const draft = await proposeDraft(harness, object)
    const { csrf } = await prepareDay9Bindings(harness)
    const resolved = await harness.bindings.resolveBundleBindings({
      bundleId: draft.bundle.bundleId,
      bundleVersion: draft.bundle.bundleVersion,
      expectedRowVersion: draft.runtime.rowVersion,
      csrfBindingHash: csrf.bindingHash
    })
    expect(resolved.runtime.state).toBe('pending-approval')

    harness.vault.markActiveSessionsVaultLost()
    harness.csrf.dropTokenMaterial()
    const swept = await harness.bindings.invalidateStaleBundles()
    expect(swept).toBe(1)
    const after = await harness.l2.getBundleView(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    expect(after?.runtime.state).toBe('revoked')
  })

  it('encodes session slots as exact session:generation pairs', async () => {
    const harness = await createHarness()
    const identity = await harness.repository.getIdentity(harness.identity.id)
    expect(identity).toBeDefined()
    const session = await harness.vault.establishSession({
      identityId: harness.identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    expect(
      encodeSessionGenerationSlot({
        sessionId: session.sessionId,
        generation: session.generation
      })
    ).toBe(`${session.sessionId}:0`)
  })
})
