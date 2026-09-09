import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import {
  ApprovalService,
  AuthorizationMatrixService,
  CsrfBindingService,
  EphemeralRequestHashKeyProvider,
  EvidenceCapturePolicy,
  ExecutionAuthority,
  ExecutionService,
  FixtureApprovalAdapter,
  IdentityContextService,
  L2BindingService,
  L2ProbeOrchestrator,
  L2ProtocolService,
  LegacyV1RequestCompilerAdapter,
  PolicyBroker,
  PolicyExecutionGuard,
  SessionVault
} from '@agentgo/application'
import type { BrowserRunner } from '@agentgo/browser-runner'
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
  EvidenceStore,
  FileCredentialStore,
  IdentitySessionRepository,
  L2Repository,
  openAgentGoDatabase,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { UndiciHttpRunner } from '@agentgo/http-runner'
import { startLocalBenchmarkFixture, type LocalBenchmarkFixture } from './local-fixture'

const HASH = createHash('sha256').update('l2-fixture-loop', 'utf8').digest('hex')

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

const unusedBrowserRunner: BrowserRunner = {
  async execute() {
    throw new Error('L2 fixture loop does not use the browser runner.')
  },
  async cancel(_requestId: string) {
    return
  }
}

function envelope(resourceId: string): SideEffectEnvelope {
  return {
    expectedStateChange: 'status:draft-to-submitted',
    maxImpactScope: 'single-test-object-fields',
    writableResourceId: resourceId,
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

let fixture: LocalBenchmarkFixture

beforeAll(async () => {
  fixture = await startLocalBenchmarkFixture()
})

afterAll(async () => {
  await fixture.close()
})

afterEach(() => {
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('L2 loopback fixture closed loop (Day 10)', () => {
  it('creates a disposable TestObject, fixture-only approves, and restores baseline', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-l2-loop-'))
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
    const evidenceStore = new EvidenceStore(database, join(directory, 'evidence'))
    const origin = fixture.baseUrl
    const resourceId = 'fixture-loop-1'
    const resourcePath = `/l2/objects/${resourceId}`
    const workspace = await repository.createWorkspace({
      name: 'L2 fixture loop',
      description: 'Day 10 loopback closed loop.'
    })
    const created = await repository.createTarget({
      workspaceId: workspace.id,
      name: 'L2 fixture',
      baseUrl: origin,
      description: '',
      authorizationReference: 'l2-fixture-loop',
      scope: {
        allowedOrigins: [origin],
        allowedPathPrefixes: ['/l2/'],
        deniedPathPrefixes: [],
        allowedPorts: [fixture.port],
        allowedIdentityIds: [],
        allowActiveProbing: true,
        allowSensitiveProbing: true,
        allowPrivateNetworkTargets: true,
        allowLoopbackTargets: true,
        networkEntries: [
          {
            id: 'l2-fixture-loopback',
            addressClass: 'loopback',
            ip: '127.0.0.1',
            ports: [fixture.port],
            purpose: 'execution'
          }
        ],
        maxRequestsPerMinute: 60,
        maxConcurrency: 2
      }
    })
    const identity = await repository.saveIdentity({
      targetId: created.target.id,
      label: 'fixture owner',
      role: 'owner',
      authType: 'cookie',
      headerName: undefined,
      isTestIdentity: true,
      ownedResourceIds: [resourceId]
    })
    await repository.updateTarget({
      id: created.target.id,
      scope: {
        allowedOrigins: [origin],
        allowedPathPrefixes: ['/l2/'],
        deniedPathPrefixes: [],
        allowedPorts: [fixture.port],
        allowedIdentityIds: [identity.id],
        allowActiveProbing: true,
        allowSensitiveProbing: true,
        allowPrivateNetworkTargets: true,
        allowLoopbackTargets: true,
        networkEntries: [
          {
            id: 'l2-fixture-loopback',
            addressClass: 'loopback',
            ip: '127.0.0.1',
            ports: [fixture.port],
            purpose: 'execution'
          }
        ],
        maxRequestsPerMinute: 60,
        maxConcurrency: 2
      }
    })
    const moduleDraft = ScanModuleSnapshotDraftSchema.parse({
      familyId: 'sqli',
      moduleId: 'test.sqli.module',
      moduleVersion: '1.0.0',
      definitionHash: sha256('l2-loop-module'),
      techniqueId: 'sqli.query-differential',
      techniqueVersion: '1.0.0',
      strategyRefs: [{ id: 'test.sqli.strategy', version: '1.0.0' }],
      confirmationRuleRefs: [{ id: 'test.sqli.rule', version: '1.0.0' }],
      evidenceProfileRefs: [{ id: 'test.sqli.evidence', version: '1.0.0' }],
      remediationRefs: [{ id: 'test.sqli.remediation', version: '1.0.0' }],
      requiredCapabilityIds: ['http.reviewed-read', 'http.test-object-write'],
      capabilityDescriptors: [
        {
          id: 'http.reviewed-read',
          riskFloor: 'l1',
          descriptorHash: sha256('http.reviewed-read')
        },
        {
          id: 'http.test-object-write',
          riskFloor: 'l2',
          descriptorHash: sha256('http.test-object-write')
        }
      ],
      capabilitySnapshotHash: sha256('l2-loop-capability'),
      selectedCapabilitiesHash: sha256('l2-loop-selected-cap'),
      selectedDefinitionsHash: sha256('l2-loop-selected-def'),
      registrySnapshotHash: sha256('l2-loop-registry'),
      environment: 'authorized-test-environment',
      authorization: 'qualified'
    })
    const scan = await repository.createScan(
      {
        targetId: created.target.id,
        name: 'L2 fixture loop scan',
        description: 'Day 10 closed loop.',
        families: ['sqli'],
        identityIds: [identity.id],
        budget: {
          maxRequests: 16,
          maxRequestsPerMinute: 60,
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
      { phase: 'intake', status: 'running' },
      [{ draft: moduleDraft, snapshotHash: sha256('l2-loop-snapshot') }]
    )
    await repository.updateScan(scan.id, { status: 'running', startedAt: Date.now() })
    const agentRun = await repository.createAgentRun({
      scanId: scan.id,
      role: 'strategy',
      promptId: 'strategy-safe-probe',
      promptVersion: '1.0.0',
      promptHash: HASH,
      modelProfileId: 'deterministic-strategy'
    })

    const l2 = new L2ProtocolService({
      l2Repository,
      scanRepository: repository
    })
    const vault = new SessionVault({
      identitySessionRepository: identitySessions,
      repository,
      credentialStore
    })
    const identityContexts = new IdentityContextService({
      repository,
      identitySessionRepository: identitySessions,
      credentialStore
    })
    const csrf = new CsrfBindingService({
      identitySessionRepository: identitySessions,
      sessionVault: vault
    })
    const matrices = new AuthorizationMatrixService({
      repository,
      identitySessionRepository: identitySessions
    })
    const bindings = new L2BindingService({
      l2ProtocolService: l2,
      l2Repository,
      identityContextService: identityContexts,
      sessionVault: vault,
      csrfBindingService: csrf,
      authorizationMatrixService: matrices,
      identitySessionRepository: identitySessions
    })
    l2.setBindingFreshnessVerifier((bundle) => bindings.assertBindingsFresh(bundle))
    const approvals = new ApprovalService({
      identitySessionRepository: identitySessions,
      l2ProtocolService: l2,
      bindingService: bindings,
      approvalMode: 'fixture-only'
    })
    const requestHashKeyProvider = new EphemeralRequestHashKeyProvider()
    const requestAdapter = new LegacyV1RequestCompilerAdapter({
      repository,
      credentialStore,
      hashKeyProvider: requestHashKeyProvider,
      hashKey: requestHashKeyProvider.reference
    })
    const authority = new ExecutionAuthority(
      repository,
      requestHashKeyProvider,
      Date.now,
      vault
    )
    const policyBroker = new PolicyBroker(repository)
    const executionGuard = new PolicyExecutionGuard(
      repository,
      requestHashKeyProvider,
      credentialStore,
      vault
    )
    const executionService = new ExecutionService({
      repository,
      evidenceStore,
      httpRunner: new UndiciHttpRunner(executionGuard),
      browserRunner: unusedBrowserRunner,
      requestAdapter,
      authority,
      policyBroker,
      executionGuard,
      evidenceCapturePolicy: new EvidenceCapturePolicy(),
      hashKeyProvider: requestHashKeyProvider,
      sessionVault: vault,
      csrfBindingService: csrf
    })

    const sessionResponse = await fetch(new URL('/l2/session', origin))
    expect(sessionResponse.status).toBe(200)
    const setCookie = sessionResponse.headers.get('set-cookie')
    expect(setCookie).toBeTruthy()
    const sessionJson = (await sessionResponse.json()) as { csrfToken: string }
    const cookieValue = /(?:^|,)\s*sid=([^;]+)/u.exec(setCookie ?? '')?.[1]
    expect(cookieValue).toBeTruthy()

    await identityContexts.issueIdentityContext({
      identityId: identity.id,
      targetId: created.target.id,
      scopeSnapshotId: scan.scopeSnapshotId,
      role: 'owner',
      ownerLabel: 'fixture owner',
      purpose: 'L2 fixture loop',
      allowedOperations: ['write-test-object', 'cleanup-test-object'],
      confirmationAuditRef: randomUUID(),
      ttlMs: 3_600_000
    })
    const session = await vault.establishSession({
      identityId: identity.id,
      scopeSnapshotId: scan.scopeSnapshotId
    })
    await vault.ingestSetCookie(session.sessionId, setCookie!, `${origin}/l2/session`)
    const csrfRule: CsrfBindingRule = {
      ruleVersion: 'fixture-csrf/1.0',
      sourceKind: 'json-pointer',
      sourceSelector: '/csrfToken',
      sourceOrigin: origin,
      sourcePathPrefix: '/l2/',
      encoding: 'raw',
      injectionLocation: 'header',
      injectionName: 'x-csrf-token',
      maxUses: 2
    }
    const csrfCapture = await csrf.captureBinding({
      identityId: identity.id,
      sessionId: session.sessionId,
      origin,
      boundMethod: 'POST',
      boundPath: resourcePath,
      rule: csrfRule,
      response: {
        url: `${origin}/l2/session`,
        bodyText: JSON.stringify(sessionJson)
      },
      ttlMs: 600_000
    })
    if (!csrfCapture.ok) {
      throw new Error(`CSRF capture failed: ${csrfCapture.reason}`)
    }
    await matrices.confirmMatrix({
      targetId: created.target.id,
      scopeSnapshotId: scan.scopeSnapshotId,
      entries: [
        {
          subjectIdentityId: identity.id,
          resourceOwnerIdentityId: identity.id,
          role: 'owner',
          operation: 'write',
          resourceRef: resourceId,
          expected: 'state-allowed',
          humanSource: 'fixture declaration'
        },
        {
          subjectIdentityId: identity.id,
          resourceOwnerIdentityId: identity.id,
          role: 'owner',
          operation: 'delete',
          resourceRef: resourceId,
          expected: 'state-allowed',
          humanSource: 'fixture declaration'
        }
      ],
      humanAttestationRef: randomUUID(),
      ttlMs: 3_600_000
    })

    const object = await l2.createTestObject({
      scanId: scan.id,
      targetId: created.target.id,
      identityId: identity.id,
      objectType: 'record',
      allowedFields: ['status'],
      allowedStates: ['draft', 'submitted'],
      canonicalResource: {
        kind: 'http-resource',
        origin,
        method: 'POST',
        path: resourcePath,
        resourceId
      },
      cleanupProtocol: {
        kind: 'reset',
        declaredByTarget: true,
        capabilityId: L2_CLEANUP_CAPABILITY_ID,
        method: 'POST',
        path: resourcePath,
        expectedTerminalState: 'draft',
        maxRequests: 1
      },
      closeConditions: ['expired', 'externally-modified'],
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      creationEvidenceHash: HASH,
      baselineEvidenceHash: HASH
    })
    const draft = await l2.proposeBundle({
      scanId: scan.id,
      targetId: created.target.id,
      testObjectId: object.testObjectId,
      testObjectVersion: object.objectVersion,
      sideEffectEnvelope: envelope(resourceId),
      steps: steps(object)
    })
    const resolved = await bindings.resolveBundleBindings({
      bundleId: draft.bundle.bundleId,
      bundleVersion: draft.bundle.bundleVersion,
      expectedRowVersion: draft.runtime.rowVersion,
      csrfBindingHash: csrfCapture.binding.bindingHash
    })
    expect(resolved.runtime.state).toBe('pending-approval')

    const actor = new FixtureApprovalAdapter(approvals).mint([created.target.id])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: l2,
      approvalService: approvals,
      bindingService: bindings,
      executionPort: executionService
    })
    const result = await orchestrator.run({
      bundleId: resolved.bundle.bundleId,
      bundleVersion: resolved.bundle.bundleVersion,
      actor,
      agentRunId: agentRun.id,
      sessionId: session.sessionId,
      csrfBindingHash: csrfCapture.binding.bindingHash,
      identityId: identity.id
    })

    expect(result.approvalMode).toBe('fixture-only')
    expect(result.primaryRequestCount).toBe(1)
    expect(result.receipt?.kind).toBe('cleanup-completed')
    expect(result.view.runtime.state).toBe('clean')
    const terminal = await fetch(new URL(resourcePath, origin), {
      headers: { cookie: `sid=${cookieValue}` }
    })
    expect(await terminal.json()).toMatchObject({ id: resourceId, status: 'draft' })

    const serialized = JSON.stringify({
      result,
      proposal: await identitySessions.getLatestApprovalProposalForBundle(
        resolved.bundle.bundleId,
        resolved.bundle.bundleVersion
      )
    })
    expect(serialized).not.toContain(cookieValue)
    expect(serialized).not.toContain(sessionJson.csrfToken)
    expect(serialized).toContain('fixture-only')
    await expect(repository.getScan(scan.id)).resolves.toMatchObject({ status: 'running' })
    const snapshots = await repository.listScanModuleSnapshots(scan.id)
    const capabilityIds = snapshots.flatMap((item) =>
      item.capabilityDescriptors.map((descriptor) => descriptor.id)
    )
    expect(capabilityIds).toEqual(
      expect.arrayContaining(['http.reviewed-read', 'http.test-object-write'])
    )
  })
})
