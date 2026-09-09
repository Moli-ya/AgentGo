import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  L2_CLEANUP_CAPABILITY_ID,
  ScanModuleSnapshotDraftSchema,
  type CsrfBindingRule,
  type L2BundleStep,
  type SideEffectEnvelope,
  type TestObject
} from '@agentgo/contracts'
import { evaluateCleanupCapability } from '@agentgo/domain'
import {
  AgentGoRepository,
  FileCredentialStore,
  IdentitySessionRepository,
  L2Repository,
  openAgentGoDatabase,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { ApprovalService, FixtureApprovalAdapter } from './approval-service'
import { AuthorizationMatrixService } from './authorization-matrix-service'
import { CsrfBindingService } from './csrf-binding-service'
import type {
  BrowserExecutionResultView,
  BrowserOfflineExecutionStepInput,
  ExecutionPort,
  ExecutionPortInput,
  HttpExecutionResultView,
  HttpExecutionStepInput,
  L2HttpExecutionStepInput,
  StoredExecutionResult,
  UnsupportedExecutionStepInput
} from './execution-port'
import { IdentityContextService } from './identity-context-service'
import { L2BindingService } from './l2-binding-service'
import { L2ProtocolError, L2ProtocolService } from './l2-protocol-service'
import { L2ProbeOrchestrator } from './l2-probe-orchestrator'
import { SessionVault } from './session-vault'

const HASH = 'b'.repeat(64)
const NOW = new Date('2026-08-26T00:00:00.000Z')

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
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-l2-orch-'))
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
    name: 'L2 orchestrator',
    description: 'Day 10 orchestrator tests.'
  })
  const created = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'L2 orchestrator lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'l2-orch-test',
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
    definitionHash: sha256('l2-orch-module'),
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
    capabilitySnapshotHash: sha256('l2-orch-capability'),
    selectedCapabilitiesHash: sha256('l2-orch-selected-cap'),
    selectedDefinitionsHash: sha256('l2-orch-selected-def'),
    registrySnapshotHash: sha256('l2-orch-registry'),
    environment: 'authorized-test-environment',
    authorization: 'qualified'
  })
  const scan = await repository.createScan(
    {
      targetId: created.target.id,
      name: 'L2 orchestrator scan',
      description: 'Day 10.',
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
    [{ draft: moduleDraft, snapshotHash: sha256('l2-orch-snapshot') }]
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
  const approvals = new ApprovalService({
    identitySessionRepository: identitySessions,
    l2ProtocolService: l2,
    bindingService: bindings,
    approvalMode: 'fixture-only',
    now: () => NOW
  })
  return {
    l2,
    vault,
    identityContexts,
    csrf,
    matrices,
    bindings,
    approvals,
    identitySessions,
    repository,
    scan,
    identity,
    targetId: created.target.id,
    scopeSnapshotId: scan.scopeSnapshotId
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
      expectedTerminalState: 'draft',
      maxRequests: 1
    },
    closeConditions: ['expired', 'externally-modified'],
    expiresAt: '2026-08-27T00:00:00.000Z',
    creationEvidenceHash: HASH,
    baselineEvidenceHash: HASH
  })
}

async function preparePending(harness: Harness) {
  const object = await createObject(harness)
  const draft = await harness.l2.proposeBundle({
    scanId: harness.scan.id,
    targetId: harness.targetId,
    testObjectId: object.testObjectId,
    testObjectVersion: object.objectVersion,
    sideEffectEnvelope: envelope(),
    steps: steps(object)
  })
  await harness.identityContexts.issueIdentityContext({
    identityId: harness.identity.id,
    targetId: harness.targetId,
    scopeSnapshotId: harness.scopeSnapshotId,
    role: 'owner',
    ownerLabel: 'owner identity',
    purpose: 'L2 orchestrator test',
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
    'sid=orch-cookie; Path=/; HttpOnly',
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
      bodyText: '{"csrfToken":"orch-token"}'
    },
    ttlMs: 600_000
  })
  if (!csrfCapture.ok) throw new Error('CSRF capture failed in test setup.')
  await harness.matrices.confirmMatrix({
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
  const resolved = await harness.bindings.resolveBundleBindings({
    bundleId: draft.bundle.bundleId,
    bundleVersion: draft.bundle.bundleVersion,
    expectedRowVersion: draft.runtime.rowVersion,
    csrfBindingHash: csrfCapture.binding.bindingHash
  })
  return {
    object,
    resolved,
    session,
    csrf: csrfCapture.binding
  }
}

class RecordingL2Port implements ExecutionPort {
  readonly calls: L2HttpExecutionStepInput[] = []
  testObjectStatus: 'draft' | 'submitted' = 'draft'

  execute(
    input: HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>>
  execute(
    _input: BrowserOfflineExecutionStepInput
  ): Promise<StoredExecutionResult<BrowserExecutionResultView>>
  execute(_input: UnsupportedExecutionStepInput): Promise<never>
  execute(_input: ExecutionPortInput): never {
    throw new Error('L1 execute is not used by the L2 orchestrator.')
  }

  async executeL2Http(
    input: L2HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>> {
    this.calls.push(input)
    if (input.purpose === 'primary') this.testObjectStatus = 'submitted'
    if (input.purpose === 'cleanup') this.testObjectStatus = 'draft'
    const responseBody = new TextEncoder().encode(
      JSON.stringify({ status: this.testObjectStatus })
    )
    const result: HttpExecutionResultView = {
      requestId: randomUUID(),
      status: 'succeeded',
      finalUrl: input.desiredUrl,
      method: input.method,
      statusCode: 200,
      requestHeaders: [],
      responseHeaders: { 'content-type': 'application/json' },
      responseBody,
      responseBodySha256: sha256(Buffer.from(responseBody).toString('utf8')),
      responseBytes: responseBody.byteLength,
      durationMs: 1,
      resolvedAddresses: ['203.0.113.8'],
      redirectChain: []
    }
    return {
      result,
      interactionIds: [],
      evidenceRefs: [],
      toolCallId: randomUUID(),
      toolCallIds: [],
      proposalIds: [],
      policyDecisionIds: [],
      grantIds: [],
      leaseIds: []
    }
  }

  executeMediatedHttp(): Promise<StoredExecutionResult<HttpExecutionResultView>> {
    throw new Error('L2 orchestrator does not execute mediated HTTP.')
  }
}

function runInput(
  harness: Harness,
  pending: Awaited<ReturnType<typeof preparePending>>,
  actor: ReturnType<FixtureApprovalAdapter['mint']>
): Parameters<L2ProbeOrchestrator['run']>[0] {
  return {
    bundleId: pending.resolved.bundle.bundleId,
    bundleVersion: pending.resolved.bundle.bundleVersion,
    actor,
    agentRunId: randomUUID(),
    sessionId: pending.session.sessionId,
    csrfBindingHash: pending.csrf.bindingHash,
    identityId: harness.identity.id
  }
}

afterEach(() => {
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('L2ProbeOrchestrator (Day 10 faults)', () => {
  it('completes a fixture-only loop over a recording port without sending DELETE', async () => {
    const harness = await createHarness()
    const pending = await preparePending(harness)
    const port = new RecordingL2Port()
    const actor = new FixtureApprovalAdapter(harness.approvals).mint([
      harness.targetId
    ])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: harness.l2,
      approvalService: harness.approvals,
      bindingService: harness.bindings,
      executionPort: port
    })
    const result = await orchestrator.run(runInput(harness, pending, actor))
    expect(result.approvalMode).toBe('fixture-only')
    expect(result.primaryRequestCount).toBe(1)
    expect(result.receipt?.kind).toBe('cleanup-completed')
    expect(result.view.runtime.state).toBe('clean')
    expect(port.calls.filter((call) => call.purpose === 'primary')).toHaveLength(1)
    expect(
      port.calls
        .filter((call) => call.purpose === 'primary' || call.purpose === 'cleanup')
        .every((call) => call.method === 'POST')
    ).toBe(true)
  })

  it('requires a new bundle after a crash before primary send', async () => {
    const harness = await createHarness()
    const pending = await preparePending(harness)
    const port = new RecordingL2Port()
    const actor = new FixtureApprovalAdapter(harness.approvals).mint([
      harness.targetId
    ])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: harness.l2,
      approvalService: harness.approvals,
      bindingService: harness.bindings,
      executionPort: port
    })
    await expect(
      orchestrator.run({
        ...runInput(harness, pending, actor),
        fault: 'crash-before-primary'
      })
    ).rejects.toThrow(/Injected crash before primary send/)
    expect(port.calls.filter((call) => call.purpose === 'primary')).toHaveLength(0)
    await expect(
      orchestrator.run(runInput(harness, pending, actor))
    ).rejects.toMatchObject({ reasonCode: 'bundle-not-pending' })

    const retryDraft = await harness.l2.proposeBundle({
      scanId: harness.scan.id,
      targetId: harness.targetId,
      testObjectId: pending.object.testObjectId,
      testObjectVersion: pending.object.objectVersion,
      sideEffectEnvelope: envelope(),
      steps: steps(pending.object)
    })
    const retryResolved = await harness.bindings.resolveBundleBindings({
      bundleId: retryDraft.bundle.bundleId,
      bundleVersion: retryDraft.bundle.bundleVersion,
      expectedRowVersion: retryDraft.runtime.rowVersion,
      csrfBindingHash: pending.csrf.bindingHash
    })
    const retry = await orchestrator.run({
      bundleId: retryResolved.bundle.bundleId,
      bundleVersion: retryResolved.bundle.bundleVersion,
      actor,
      agentRunId: randomUUID(),
      sessionId: pending.session.sessionId,
      csrfBindingHash: pending.csrf.bindingHash,
      identityId: harness.identity.id
    })
    expect(retry.primaryRequestCount).toBe(1)
    expect(retry.view.runtime.state).toBe('clean')
  })

  it('observes state and cleans up after a dropped primary response without replay', async () => {
    const harness = await createHarness()
    const pending = await preparePending(harness)
    const port = new RecordingL2Port()
    const actor = new FixtureApprovalAdapter(harness.approvals).mint([
      harness.targetId
    ])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: harness.l2,
      approvalService: harness.approvals,
      bindingService: harness.bindings,
      executionPort: port
    })
    const result = await orchestrator.run({
      ...runInput(harness, pending, actor),
      fault: 'drop-primary-response'
    })
    expect(result.view.runtime.state).toBe('clean')
    expect(result.receipt?.requestExecutionState).toBe('response-missing')
    expect(result.evidenceHashes.primary).toBeUndefined()
    expect(result.evidenceHashes.postRead).toMatch(/^[a-f0-9]{64}$/u)
    expect(port.calls.filter((call) => call.purpose === 'primary')).toHaveLength(1)
    expect(port.calls.filter((call) => call.purpose === 'cleanup')).toHaveLength(1)
    expect(port.testObjectStatus).toBe('draft')
    await expect(
      orchestrator.run(runInput(harness, pending, actor))
    ).rejects.toMatchObject({ reasonCode: 'bundle-not-pending' })
    expect(port.calls.filter((call) => call.purpose === 'primary')).toHaveLength(1)
  })

  it('freezes ordinary execution after cleanup failure', async () => {
    const harness = await createHarness()
    const pending = await preparePending(harness)
    const port = new RecordingL2Port()
    const actor = new FixtureApprovalAdapter(harness.approvals).mint([
      harness.targetId
    ])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: harness.l2,
      approvalService: harness.approvals,
      bindingService: harness.bindings,
      executionPort: port
    })
    await expect(
      orchestrator.run({
        ...runInput(harness, pending, actor),
        fault: 'fail-cleanup'
      })
    ).rejects.toMatchObject({ reasonCode: 'cleanup-failed-frozen' })
    await expect(
      harness.l2.proposeBundle({
        scanId: harness.scan.id,
        targetId: harness.targetId,
        testObjectId: pending.object.testObjectId,
        testObjectVersion: pending.object.objectVersion,
        sideEffectEnvelope: envelope(),
        steps: steps(pending.object)
      })
    ).rejects.toMatchObject({ reasonCode: 'cleanup-failed-frozen' })
  })

  it('freezes when cleanup-verify still observes the mutated TestObject state', async () => {
    const harness = await createHarness()
    const pending = await preparePending(harness)
    const encoder = new TextEncoder()
    const port = new RecordingL2Port()
    const original = port.executeL2Http.bind(port)
    port.executeL2Http = async (input) => {
      const stored = await original(input)
      const status =
        input.purpose === 'primary' || input.stepId === 'l2.post-read'
          ? 'submitted'
          : input.purpose === 'cleanup' ||
              input.stepId === 'l2.cleanup-verify' ||
              input.stepId === 'l2.terminal-read'
            ? 'submitted'
            : 'draft'
      return {
        ...stored,
        result: {
          ...stored.result,
          responseBody: encoder.encode(JSON.stringify({ status }))
        }
      }
    }
    const actor = new FixtureApprovalAdapter(harness.approvals).mint([
      harness.targetId
    ])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: harness.l2,
      approvalService: harness.approvals,
      bindingService: harness.bindings,
      executionPort: port
    })
    await expect(orchestrator.run(runInput(harness, pending, actor))).rejects.toMatchObject({
      reasonCode: 'cleanup-failed-frozen'
    })
  })

  it.each([
    ['an empty body', new Uint8Array()],
    ['a non-JSON body', new TextEncoder().encode('cleanup status unavailable')]
  ])('freezes instead of reporting clean when cleanup-verify returns %s', async (_label, body) => {
    const harness = await createHarness()
    const pending = await preparePending(harness)
    const port = new RecordingL2Port()
    const original = port.executeL2Http.bind(port)
    port.executeL2Http = async (input) => {
      const stored = await original(input)
      if (input.stepId !== 'l2.cleanup-verify') return stored
      return {
        ...stored,
        result: {
          ...stored.result,
          responseBody: body,
          responseBodySha256: sha256(Buffer.from(body).toString('utf8')),
          responseBytes: body.byteLength
        }
      }
    }
    const actor = new FixtureApprovalAdapter(harness.approvals).mint([
      harness.targetId
    ])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: harness.l2,
      approvalService: harness.approvals,
      bindingService: harness.bindings,
      executionPort: port
    })

    await expect(orchestrator.run(runInput(harness, pending, actor))).rejects.toMatchObject({
      reasonCode: 'cleanup-failed-frozen'
    })
    const view = await harness.l2.getBundleView(
      pending.resolved.bundle.bundleId,
      pending.resolved.bundle.bundleVersion
    )
    expect(view?.runtime.state).toBe('cleanup-failed')
    expect(
      await harness.l2.isOrdinaryQueueFrozen(harness.targetId, pending.object.testObjectId)
    ).toBe(true)
  })

  it('freezes when the cleanup execution port throws', async () => {
    const harness = await createHarness()
    const pending = await preparePending(harness)
    const port = new RecordingL2Port()
    const original = port.executeL2Http.bind(port)
    port.executeL2Http = async (input) => {
      if (input.purpose === 'cleanup') throw new Error('injected cleanup transport failure')
      return original(input)
    }
    const actor = new FixtureApprovalAdapter(harness.approvals).mint([
      harness.targetId
    ])
    const orchestrator = new L2ProbeOrchestrator({
      l2ProtocolService: harness.l2,
      approvalService: harness.approvals,
      bindingService: harness.bindings,
      executionPort: port
    })

    await expect(orchestrator.run(runInput(harness, pending, actor))).rejects.toMatchObject({
      reasonCode: 'cleanup-failed-frozen'
    })
    const view = await harness.l2.getBundleView(
      pending.resolved.bundle.bundleId,
      pending.resolved.bundle.bundleVersion
    )
    expect(view?.runtime.state).toBe('cleanup-failed')
    expect(
      await harness.l2.isOrdinaryQueueFrozen(harness.targetId, pending.object.testObjectId)
    ).toBe(true)
  })

  it('rejects generic HTTP DELETE as cleanup', () => {
    expect(
      evaluateCleanupCapability({
        protocol: {
          kind: 'reset',
          declaredByTarget: true,
          capabilityId: L2_CLEANUP_CAPABILITY_ID,
          method: 'POST',
          path: '/test-objects/obj-1',
          expectedTerminalState: 'absent',
          maxRequests: 1
        },
        testObject: {
          disposable: true,
          canonicalResource: {
            kind: 'http-resource',
            origin: 'https://lab.example.test',
            method: 'POST',
            path: '/test-objects/obj-1',
            resourceId: 'obj-1'
          },
          creationAttestation: { createdByAgentGo: true }
        } as TestObject,
        bundle: {
          bundleHash: HASH,
          steps: []
        } as never,
        requestedMethod: 'DELETE'
      })
    ).toBe('generic-http-delete-forbidden')
    expect(L2ProtocolError).toBeDefined()
  })
})
