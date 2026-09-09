import { createHash, randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  ExecutionCaptureDecisionSetSchema,
  PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
  PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
  PROTECTED_EVIDENCE_POLICY_VERSION,
  PROTECTED_EVIDENCE_PROTECTION_SCHEME,
  ScanModuleSnapshotDraftSchema,
  type ExecutionClaimBinding,
  type ExecutionCaptureDecisionSet,
  type EvidenceCaptureDecision,
  type EvidenceCaptureExecutionState,
  type WireRequestHmac
} from '@agentgo/contracts'
import { canonicalJson } from '@agentgo/domain'
import {
  applyDatabaseMigrations,
  openAgentGoDatabase,
  type AgentGoDatabase
} from './database'
import { EvidenceStore } from './evidence-store'
import {
  EXECUTION_DISPATCH_HARDENING_MIGRATION,
  EXECUTION_RECOVERY_HARDENING_MIGRATION
} from './execution-migration'
import {
  AgentGoRepository,
  executionClaimBindingForGrant,
  type ExecutionGrantIntegrityKey,
  type IssueExecutionGrantInput
} from './repository'

type GrantDraft = IssueExecutionGrantInput['grant']

interface ExecutionFixture {
  directory: string
  filePath: string
  database: AgentGoDatabase
  repository: AgentGoRepository
  workspaceId: string
  targetId: string
  scanId: string
  scopeSnapshotId: string
  scopeSnapshotHash: string
  identityId?: string
  identityVersion?: number
  moduleSnapshot: Awaited<
    ReturnType<AgentGoRepository['listScanModuleSnapshots']>
  >[number]
  agentRunId: string
  plan: Record<string, unknown>
  integrityKey: ExecutionGrantIntegrityKey
}

interface IssueGrantOptions {
  wire?: WireRequestHmac
  authorizedWire?: WireRequestHmac
  parentLeaseId?: string
  leaseExpiresAt?: string
  overrides?: Omit<Partial<GrantDraft>, 'budget'> & {
    budget?: Partial<GrantDraft['budget']>
  }
}

const temporaryDirectories: string[] = []
const openDatabases: AgentGoDatabase[] = []
let proofSequence = 0

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function errorChainText(error: unknown): string {
  const messages: string[] = []
  const seen = new Set<object>()
  let current = error
  while (
    current !== null &&
    (typeof current === 'object' || typeof current === 'function') &&
    !seen.has(current as object) &&
    messages.length < 8
  ) {
    const object = current as object
    seen.add(object)
    const message = Reflect.get(object, 'message')
    if (typeof message === 'string') messages.push(message)
    current = Reflect.get(object, 'cause')
  }
  return messages.join('\ncaused by: ')
}

async function expectRejectionCause(
  operation: Promise<unknown>,
  pattern: RegExp
): Promise<void> {
  const result = await operation.then(
    () => ({ status: 'fulfilled' as const }),
    (error: unknown) => ({ status: 'rejected' as const, error })
  )
  expect(result.status).toBe('rejected')
  if (result.status === 'rejected') {
    expect(errorChainText(result.error)).toMatch(pattern)
  }
}

function trackDatabase(database: AgentGoDatabase): AgentGoDatabase {
  openDatabases.push(database)
  return database
}

function nextWireProof(
  fixture: Pick<ExecutionFixture, 'integrityKey'>,
  label = 'wire'
): WireRequestHmac {
  proofSequence += 1
  return {
    domain: 'agentgo.wire-request.v2',
    algorithm: 'hmac-sha256',
    keyRef: fixture.integrityKey.keyRef,
    keyVersion: fixture.integrityKey.keyVersion,
    digest: sha256(`${label}:${proofSequence}`)
  }
}

async function createExecutionFixture(
  maxRequests = 20,
  withIdentity = false,
  limits: {
    maxConcurrency?: number
    maxRequestsPerMinute?: number
    maxDurationMinutes?: number
    maxRequestBytes?: number
    maxResponseBytes?: number
  } = {}
): Promise<ExecutionFixture> {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-execution-execution-'))
  temporaryDirectories.push(directory)
  const filePath = join(directory, 'agentgo.sqlite')
  const database = trackDatabase(openAgentGoDatabase(filePath))
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({
    name: 'Execution fixture',
    description: 'Single-use execution lease repository tests.'
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Authorized execution lab',
    baseUrl: 'https://lab.example.test',
    description: 'Network-free database fixture.',
    authorizationReference: 'execution-db-test-authorization',
    scope: {
      allowedOrigins: ['https://lab.example.test'],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [443],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      networkEntries: [],
      maxRequestsPerMinute: limits.maxRequestsPerMinute ?? 100,
      maxConcurrency: limits.maxConcurrency ?? 4,
      authorizationReference: 'execution-db-test-authorization'
    }
  })
  const identity = withIdentity
    ? await repository.saveIdentity({
        targetId: target.target.id,
        label: 'Dispatch identity',
        role: 'owner',
        authType: 'none',
        isTestIdentity: true,
        ownedResourceIds: []
      })
    : undefined
  const scope = identity
    ? (
        await repository.updateTarget({
          id: target.target.id,
          scope: {
            allowedOrigins: target.scope.allowedOrigins,
            allowedPathPrefixes: target.scope.allowedPathPrefixes,
            deniedPathPrefixes: target.scope.deniedPathPrefixes,
            allowedPorts: target.scope.allowedPorts,
            allowedIdentityIds: [identity.id],
            allowActiveProbing: target.scope.allowActiveProbing,
            allowSensitiveProbing: target.scope.allowSensitiveProbing,
            allowPrivateNetworkTargets:
              target.scope.allowPrivateNetworkTargets,
            allowLoopbackTargets: target.scope.allowLoopbackTargets,
            networkEntries: target.scope.networkEntries,
            maxRequestsPerMinute: target.scope.maxRequestsPerMinute,
            maxConcurrency: target.scope.maxConcurrency,
            ...(target.scope.authorizationReference
              ? {
                  authorizationReference:
                    target.scope.authorizationReference
                }
              : {})
          }
        })
      ).scope
    : target.scope
  if (!scope) throw new Error('Execution fixture has no scope snapshot.')
  const plan: Record<string, unknown> = {
    version: '1.0.0',
    steps: ['sqli.baseline']
  }
  const moduleDraft = ScanModuleSnapshotDraftSchema.parse({
    familyId: 'sqli',
    moduleId: 'test.sqli.module',
    moduleVersion: '1.0.0',
    definitionHash: sha256('execution-module-definition'),
    techniqueId: 'sqli.query-differential',
    techniqueVersion: '1.0.0',
    strategyRefs: [{ id: 'test.sqli.strategy', version: '1.0.0' }],
    confirmationRuleRefs: [{ id: 'test.sqli.rule', version: '1.0.0' }],
    evidenceProfileRefs: [{ id: 'test.sqli.evidence', version: '1.0.0' }],
    remediationRefs: [{ id: 'test.sqli.remediation', version: '1.0.0' }],
    requiredCapabilityIds: ['http.reviewed-read', 'browser.offline-replay'],
    capabilityDescriptors: [
      {
        id: 'http.reviewed-read',
        riskFloor: 'l1',
        descriptorHash: sha256('http.reviewed-read')
      },
      {
        id: 'browser.offline-replay',
        riskFloor: 'l1',
        descriptorHash: sha256('browser.offline-replay')
      }
    ],
    capabilitySnapshotHash: sha256('execution-capability-snapshot'),
    selectedCapabilitiesHash: sha256('execution-selected-capabilities'),
    selectedDefinitionsHash: sha256('execution-selected-definitions'),
    registrySnapshotHash: sha256('execution-registry-snapshot'),
    environment: 'authorized-test-environment',
    authorization: 'qualified'
  })
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'Execution scan',
      description: 'Exercises immutable grants and single-use leases.',
      families: ['sqli'],
      identityIds: identity ? [identity.id] : [],
      budget: {
        maxRequests,
        maxRequestsPerMinute: limits.maxRequestsPerMinute ?? 100,
        maxConcurrency: limits.maxConcurrency ?? 4,
        maxPlanRevisions: 0,
        maxDurationMinutes: limits.maxDurationMinutes ?? 10,
        maxModelTokens: 0,
        maxEstimatedCost: 0,
        maxRequestBytes: limits.maxRequestBytes ?? maxRequests * 1_146_880,
        maxResponseBytes:
          limits.maxResponseBytes ??
          Math.min(maxRequests * 16_777_216, 1_073_741_824)
      }
    },
    plan,
    {},
    [{ draft: moduleDraft, snapshotHash: sha256('execution-module-snapshot') }]
  )
  const [moduleSnapshot] = await repository.listScanModuleSnapshots(scan.id)
  if (!moduleSnapshot) throw new Error('Execution fixture has no module snapshot.')
  await repository.updateScan(scan.id, {
    status: 'running',
    startedAt: Date.now()
  })
  const agentRun = await repository.createAgentRun({
    scanId: scan.id,
    role: 'strategy',
    promptId: 'execution-db-test',
    promptVersion: '1.0.0',
    promptHash: sha256('execution-db-test-prompt'),
    modelProfileId: 'deterministic-test-profile'
  })
  return {
    directory,
    filePath,
    database,
    repository,
    workspaceId: workspace.id,
    targetId: target.target.id,
    scanId: scan.id,
    scopeSnapshotId: scan.scopeSnapshotId,
    scopeSnapshotHash: scope.snapshotHash,
    ...(identity
      ? {
          identityId: identity.id,
          identityVersion: Date.parse(identity.updatedAt)
        }
      : {}),
    moduleSnapshot,
    agentRunId: agentRun.id,
    plan,
    integrityKey: {
      keyRef: randomUUID(),
      keyVersion: 0,
      keyMaterial: Buffer.alloc(32, 0x5a)
    }
  }
}

async function authorizeWire(
  fixture: ExecutionFixture,
  wire: WireRequestHmac
): Promise<string> {
  const proposal = await fixture.repository.createProbeProposal({
    scanId: fixture.scanId,
    agentRunId: fixture.agentRunId,
    action: {
      id: randomUUID(),
      kind: 'http-request',
      targetUrl: `https://lab.example.test/items?case=${proofSequence}`,
      method: 'GET',
      scopeSnapshotId: fixture.scopeSnapshotId,
      probeLevel: 'active-safe',
      sideEffect: 'none',
      summary: 'Database-bound read probe.',
      expectedEvidence: 'Minimized response summary.',
      ...(fixture.identityId ? { identityId: fixture.identityId } : {}),
      maxRequests: 1,
      timeoutMs: 5_000,
      userApproved: false
    },
    stopConditions: ['single request']
  })
  const decision = await fixture.repository.recordPolicyDecision({
    proposalId: proposal.id,
    scopeSnapshotId: fixture.scopeSnapshotId,
    decision: {
      allowed: true,
      requiresApproval: false,
      code: 'allowed',
      reasons: ['authorized test fixture'],
      normalizedTarget: 'https://lab.example.test/items'
    },
    validityMs: 120_000,
    authorizedWireRequestHmac: wire
  })
  return decision.id
}

function grantDraft(
  fixture: ExecutionFixture,
  policyDecisionId: string,
  wire: WireRequestHmac,
  overrides: IssueGrantOptions['overrides'] = {}
): GrantDraft {
  const now = Date.now()
  const base: GrantDraft = {
    scanId: fixture.scanId,
    scopeSnapshotId: fixture.scopeSnapshotId,
    scopeSnapshotHash: fixture.scopeSnapshotHash,
    moduleSnapshotId: fixture.moduleSnapshot.id,
    moduleSnapshotHash: fixture.moduleSnapshot.snapshotHash,
    moduleId: fixture.moduleSnapshot.moduleId,
    moduleVersion: fixture.moduleSnapshot.moduleVersion,
    techniqueId: fixture.moduleSnapshot.techniqueId,
    techniqueVersion: fixture.moduleSnapshot.techniqueVersion,
    planId: fixture.scanId,
    planVersion: String(fixture.plan.version),
    planHash: sha256(canonicalJson(fixture.plan)),
    stepId: 'sqli.baseline',
    templateIntentHash: {
      domain: 'agentgo.template-intent.v1',
      algorithm: 'sha256',
      digest: sha256(`template:${wire.digest}`)
    },
    resolvedIntentHash: {
      domain: 'agentgo.resolved-intent.v1',
      algorithm: 'sha256',
      commitmentKeyRef: fixture.integrityKey.keyRef,
      commitmentKeyVersion: fixture.integrityKey.keyVersion,
      digest: sha256(`resolved:${wire.digest}`)
    },
    wireRequestHmac: wire,
    capabilityIds: ['http.reviewed-read'],
    ...(fixture.identityId && fixture.identityVersion !== undefined
      ? {
          ownerRef: fixture.targetId,
          identityRef: {
            id: fixture.identityId,
            version: fixture.identityVersion,
            ownerRef: fixture.targetId,
            scopeSnapshotId: fixture.scopeSnapshotId,
            statusSummary: 'active' as const
          }
        }
      : {}),
    credentialRef: null,
    budget: {
      requestUnits: 1,
      requestBytes: 0,
      maxResponseBytes: 65_536,
      timeoutMs: 5_000,
      maxRedirects: 1
    },
    purpose: 'read',
    adapterKind: 'http',
    retryClass: 'never',
    policyDecisionId,
    redirectHop: 0,
    validFrom: new Date(now - 1_000).toISOString(),
    validUntil: new Date(now + 60_000).toISOString()
  }
  return {
    ...base,
    ...overrides,
    budget: {
      ...base.budget,
      ...overrides?.budget
    }
  }
}

function captureDecisionSet(
  draft: GrantDraft
): ExecutionCaptureDecisionSet {
  const normalStates = [
    'cancelled',
    'failed',
    'succeeded',
    'timed-out'
  ] as const
  const normalSources =
    draft.adapterKind === 'http'
      ? [
          ['http-request-summary', 'request-summary'],
          ['http-response-summary', 'response-summary']
        ] as const
      : draft.adapterKind === 'browser-offline'
        ? [
            ['browser-request-summary', 'request-summary'],
            ['browser-result-summary', 'result-summary']
          ] as const
        : undefined
  if (!normalSources) {
    throw new Error('Test capture decisions require a supported adapter.')
  }
  const bindings = [
    ...normalSources.flatMap(([source, role]) =>
      normalStates.map((executionState) => ({
        source,
        role,
        executionState,
        action: 'hash-only' as const
      }))
    ),
    ...(draft.adapterKind === 'browser-offline'
      ? (
          [
            ['dom-snapshot', 'dom-snapshot'],
            ['browser-screenshot', 'screenshot']
          ] as const
        ).flatMap(([source, role]) =>
          normalStates.map((executionState) => ({
            source,
            role,
            executionState,
            action: 'protected-original' as const
          }))
        )
      : []),
    {
      source: 'execution-interruption-summary',
      role: 'interruption-summary',
      executionState: 'interrupted',
      action: 'hash-only' as const
    }
  ]
  return ExecutionCaptureDecisionSetSchema.parse({
    schemaVersion: 'execution-capture-decision-set.v1',
    decisions: bindings
      .map(({ source, role, executionState, action }) => ({
        id: randomUUID(),
        scanId: draft.scanId,
        policyDecisionId: draft.policyDecisionId,
        capturePolicyId: 'execution-summary-capture',
        capturePolicyVersion: '1.0.0',
        techniqueId: draft.techniqueId,
        techniqueVersion: draft.techniqueVersion,
        stepId: draft.stepId,
        executionState,
        source,
        role,
        action,
        validFrom: draft.validFrom,
        validUntil: draft.validUntil,
        maxSourceBytes: action === 'protected-original' ? 16_777_216 : 65_536,
        maxExcerptBytes: 256,
        jsonPointers: [],
        oobMetadataFields: [],
        ...(action === 'protected-original'
          ? {
              protectedOriginalPlan: {
                protectionScheme: PROTECTED_EVIDENCE_PROTECTION_SCHEME,
                accessPolicyId: PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
                accessPolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
                derivativePolicyId: PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
                derivativePolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
                retentionSeconds: 7 * 24 * 60 * 60,
                maxScanPlaintextBytes: 16_777_216,
                maxWorkspacePlaintextBytes: 16_777_216
              }
            }
          : {})
      }))
      .sort((left, right) => {
        const leftKey = `${left.source}\u0000${left.executionState}`
        const rightKey = `${right.source}\u0000${right.executionState}`
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
      })
  })
}

async function issueGrant(
  fixture: ExecutionFixture,
  options: IssueGrantOptions = {}
): ReturnType<AgentGoRepository['issueExecutionGrant']> {
  const wire = options.wire ?? nextWireProof(fixture)
  const authorizedWire = options.authorizedWire ?? wire
  const policyDecisionId = await authorizeWire(fixture, authorizedWire)
  const draft = grantDraft(
    fixture,
    policyDecisionId,
    wire,
    options.overrides
  )
  const latestSafeExpiry = Date.parse(draft.validUntil) - 1
  const leaseExpiresAt =
    options.leaseExpiresAt ??
    new Date(Math.min(Date.now() + 30_000, latestSafeExpiry)).toISOString()
  const issued = await fixture.repository.issueExecutionGrant({
    grant: draft,
    captureDecisionSet: captureDecisionSet(draft),
    integrityKey: fixture.integrityKey,
    leaseExpiresAt,
    ...(options.parentLeaseId
      ? { parentLeaseId: options.parentLeaseId }
      : {})
  })
  await fixture.repository.recordToolCall({
    scanId: fixture.scanId,
    policyDecisionId: issued.grant.policyDecisionId,
    executionLeaseId: issued.lease.id,
    toolName: issued.grant.adapterKind,
    toolVersion: '1.0.0',
    argumentHash: sha256(issued.grant.wireRequestHmac.digest),
    status: 'running'
  })
  return issued
}

async function claimLease(
  repository: AgentGoRepository,
  issued: Awaited<ReturnType<typeof issueGrant>>,
  integrityKey: ExecutionGrantIntegrityKey
) {
  return repository.claimExecutionLease({
    leaseId: issued.lease.id,
    runnerInstanceId: randomUUID(),
    binding: executionClaimBindingForGrant(issued.grant),
    integrityKey
  })
}

type NormalExecutionState = Exclude<
  EvidenceCaptureExecutionState,
  'interrupted'
>

async function recordAuditPair(
  fixture: ExecutionFixture,
  issued: Awaited<ReturnType<typeof issueGrant>>,
  claimed: Awaited<ReturnType<typeof claimLease>>,
  executionState: NormalExecutionState,
  contentTag = 'shared-summary',
  createdBy = 'execution-db-test',
  captureTool = 'execution-db-test'
) {
  const decisionSet = await fixture.repository.getExecutionCaptureDecisionSet(
    issued.grant.id
  )
  const requestDecision = decisionSet?.decisions.find(
    (decision) =>
      decision.executionState === executionState &&
      decision.role === 'request-summary'
  )
  const resultDecision = decisionSet?.decisions.find(
    (decision) =>
      decision.executionState === executionState &&
      (decision.role === 'response-summary' ||
        decision.role === 'result-summary')
  )
  if (!requestDecision || !resultDecision) {
    throw new Error('Test execution capture authority is incomplete.')
  }
  const evidenceStore = new EvidenceStore(
    fixture.database,
    join(fixture.directory, 'evidence')
  )
  const saveSummary = (
    decision: EvidenceCaptureDecision,
    kind: 'request' | 'result'
  ) =>
    evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: issued.grant.policyDecisionId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: canonicalJson({
        kind,
        contentTag,
        executionState
      }),
      source: decision.source,
      createdBy,
      captureTool,
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
  const requestEvidence = await saveSummary(requestDecision, 'request')
  const resultEvidence = await saveSummary(resultDecision, 'result')
  const interactionId =
    await fixture.repository.recordExecutionInteractionAudit({
      leaseId: issued.lease.id,
      claimToken: claimed.claimToken,
      interaction: {
        scanId: fixture.scanId,
        policyDecisionId: issued.grant.policyDecisionId,
        requestRef: requestEvidence.id,
        responseRef: resultEvidence.id,
        requestSummary: { method: 'GET' },
        responseSummary: { status: 200 },
        statusCode: 200
      },
      evidenceLinks: [
        {
          leaseId: issued.lease.id,
          evidenceId: requestEvidence.id,
          captureDecisionId: requestDecision.id,
          role: requestDecision.role,
          ordinal: 0
        },
        {
          leaseId: issued.lease.id,
          evidenceId: resultEvidence.id,
          captureDecisionId: resultDecision.id,
          role: resultDecision.role,
          ordinal: 0
        }
      ]
    })
  return {
    interactionId,
    requestDecision,
    resultDecision,
    requestEvidence,
    resultEvidence
  }
}

async function completeLease(
  fixture: ExecutionFixture,
  issued: Awaited<ReturnType<typeof issueGrant>>
) {
  const claimed = await claimLease(
    fixture.repository,
    issued,
    fixture.integrityKey
  )
  await fixture.repository.markExecutionLeaseDelivery({
    leaseId: issued.lease.id,
    claimToken: claimed.claimToken,
    deliveryState: 'possibly-sent'
  })
  await fixture.repository.markExecutionLeaseDelivery({
    leaseId: issued.lease.id,
    claimToken: claimed.claimToken,
    deliveryState: 'response-started'
  })
  const audit = await recordAuditPair(
    fixture,
    issued,
    claimed,
    'succeeded'
  )
  return fixture.repository.finalizeExecutionLease({
    leaseId: issued.lease.id,
    claimToken: claimed.claimToken,
    state: 'completed',
    terminalReason: 'completed',
    deliveryState: 'completed',
    outcomeSummary: {
      executionState: 'succeeded',
      deliveryState: 'completed',
      verdictImpact: 'none',
      wireRequestHmacDigest: issued.grant.wireRequestHmac.digest,
      requestBytes: issued.grant.budget.requestBytes,
      responseBytes: 0
    },
    evidenceRefs: [
      audit.requestEvidence.id,
      audit.resultEvidence.id
    ]
  })
}

async function failLease(
  fixture: ExecutionFixture,
  issued: Awaited<ReturnType<typeof issueGrant>>,
  options: {
    deliveryState: 'not-dispatched' | 'possibly-sent' | 'response-started'
    terminalReason: 'guard-rejected' | 'network-failed' | 'response-read-failed'
  }
) {
  const claimed = await claimLease(
    fixture.repository,
    issued,
    fixture.integrityKey
  )
  if (
    options.deliveryState === 'possibly-sent' ||
    options.deliveryState === 'response-started'
  ) {
    await fixture.repository.markExecutionLeaseDelivery({
      leaseId: issued.lease.id,
      claimToken: claimed.claimToken,
      deliveryState: 'possibly-sent'
    })
  }
  if (options.deliveryState === 'response-started') {
    await fixture.repository.markExecutionLeaseDelivery({
      leaseId: issued.lease.id,
      claimToken: claimed.claimToken,
      deliveryState: 'response-started'
    })
  }
  const audit =
    options.deliveryState === 'not-dispatched'
      ? undefined
      : await recordAuditPair(
          fixture,
          issued,
          claimed,
          'failed'
        )
  return fixture.repository.finalizeExecutionLease({
    leaseId: issued.lease.id,
    claimToken: claimed.claimToken,
    state: 'failed',
    terminalReason: options.terminalReason,
    deliveryState: options.deliveryState,
    outcomeSummary: {
      executionState: 'failed',
      deliveryState: options.deliveryState,
      verdictImpact:
        options.deliveryState === 'not-dispatched' ? 'none' : 'inconclusive',
      wireRequestHmacDigest: issued.grant.wireRequestHmac.digest,
      requestBytes: issued.grant.budget.requestBytes,
      errorCode: `execution.${options.terminalReason}`
    },
    evidenceRefs: audit
      ? [audit.requestEvidence.id, audit.resultEvidence.id]
      : []
  })
}

afterEach(() => {
  vi.restoreAllMocks()
  for (const database of openDatabases.splice(0).reverse()) {
    database.close()
  }
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
  proofSequence = 0
})

describe('Execution grant and lease repository', () => {
  it('binds issuance and claim to the exact policy-authorized wire proof', async () => {
    const fixture = await createExecutionFixture()
    const authorizedWire = nextWireProof(fixture, 'authorized')
    const differentWire = nextWireProof(fixture, 'different')

    await expect(
      issueGrant(fixture, {
        wire: differentWire,
        authorizedWire
      })
    ).rejects.toThrow(/policy|wire|binding/i)

    const issued = await issueGrant(fixture)
    const exactBinding = executionClaimBindingForGrant(issued.grant)
    const tamperedBinding: ExecutionClaimBinding = {
      ...exactBinding,
      stepId: 'sqli.tampered-step'
    }
    await expect(
      fixture.repository.claimExecutionLease({
        leaseId: issued.lease.id,
        runnerInstanceId: randomUUID(),
        binding: tamperedBinding,
        integrityKey: fixture.integrityKey
      })
    ).rejects.toThrow(/binding|grant/i)

    await expect(
      fixture.repository.claimExecutionLease({
        leaseId: issued.lease.id,
        runnerInstanceId: randomUUID(),
        binding: exactBinding,
        integrityKey: {
          keyRef: randomUUID(),
          keyVersion: 0,
          keyMaterial: Buffer.alloc(32, 0x33)
        }
      })
    ).rejects.toThrow(/integrity/i)

    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(0)
    const claimed = await claimLease(
      fixture.repository,
      issued,
      fixture.integrityKey
    )
    expect(claimed.lease.state).toBe('claimed')
    expect(claimed.lease.claimTokenHash).not.toBe(claimed.claimToken)
    expect(
      JSON.stringify(
        fixture.database.native
          .prepare('SELECT * FROM execution_leases WHERE id = ?')
          .get(issued.lease.id)
      )
    ).not.toContain(claimed.claimToken)

    await expect(
      claimLease(fixture.repository, issued, fixture.integrityKey)
    ).rejects.toThrow(/claim/i)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(1)
    expect(() =>
      fixture.database.native
        .prepare('UPDATE execution_grants SET step_id = ? WHERE id = ?')
        .run('sqli.database-tamper', issued.grant.id)
    ).toThrow(/immutable/i)
  })

  it('rejects audit rows bound to a different lease policy decision', async () => {
    const fixture = await createExecutionFixture()
    const first = await issueGrant(fixture)
    const second = await issueGrant(fixture)

    await expectRejectionCause(
      fixture.repository.recordToolCall({
        scanId: fixture.scanId,
        policyDecisionId: second.grant.policyDecisionId,
        executionLeaseId: first.lease.id,
        toolName: 'http',
        toolVersion: '1.0.0',
        argumentHash: sha256('cross-policy-tool-call'),
        status: 'running'
      }),
      /binding/i
    )
    await expectRejectionCause(
      fixture.repository.recordInteraction({
        scanId: fixture.scanId,
        policyDecisionId: second.grant.policyDecisionId,
        executionLeaseId: first.lease.id,
        requestRef: randomUUID(),
        responseRef: randomUUID(),
        requestSummary: { method: 'GET' },
        responseSummary: { status: 200 }
      }),
      /binding/i
    )
    const unboundToolCallId = await fixture.repository.recordToolCall({
      scanId: fixture.scanId,
      policyDecisionId: first.grant.policyDecisionId,
      toolName: 'http',
      toolVersion: '1.0.0',
      argumentHash: sha256('unbound-tool-call'),
      status: 'running'
    })
    expect(() =>
      fixture.database.native
        .prepare(
          'UPDATE tool_calls SET execution_lease_id = ? WHERE id = ?'
        )
        .run(first.lease.id, unboundToolCallId)
    ).toThrow(/immutable|binding/i)
    const unboundInteractionId =
      await fixture.repository.recordInteraction({
        scanId: fixture.scanId,
        policyDecisionId: first.grant.policyDecisionId,
        requestRef: randomUUID(),
        responseRef: randomUUID(),
        requestSummary: { method: 'GET' },
        responseSummary: { status: 200 }
      })
    expect(() =>
      fixture.database.native
        .prepare(
          'UPDATE interactions SET execution_lease_id = ? WHERE id = ?'
        )
        .run(first.lease.id, unboundInteractionId)
    ).toThrow(/immutable|binding/i)
    expect(
      fixture.database.native
        .prepare('SELECT COUNT(*) AS count FROM tool_calls')
        .get()
    ).toEqual({ count: 3 })
    expect(
      fixture.database.native
        .prepare('SELECT COUNT(*) AS count FROM interactions')
        .get()
    ).toEqual({ count: 1 })
  })

  it('allows exactly one concurrent claim of a single lease', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture)
    const secondDatabase = trackDatabase(openAgentGoDatabase(fixture.filePath))
    const secondRepository = new AgentGoRepository(secondDatabase)

    const attempts = await Promise.allSettled([
      claimLease(fixture.repository, issued, fixture.integrityKey),
      claimLease(secondRepository, issued, fixture.integrityKey)
    ])

    expect(attempts.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    expect(attempts.filter(({ status }) => status === 'rejected')).toHaveLength(1)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(1)
    expect((await fixture.repository.getExecutionLease(issued.lease.id))?.state).toBe(
      'claimed'
    )
  })

  it('consumes request budget atomically across distinct concurrent leases', async () => {
    const fixture = await createExecutionFixture(1)
    const first = await issueGrant(fixture)
    const second = await issueGrant(fixture)
    const secondDatabase = trackDatabase(openAgentGoDatabase(fixture.filePath))
    const secondRepository = new AgentGoRepository(secondDatabase)

    const attempts = await Promise.allSettled([
      claimLease(fixture.repository, first, fixture.integrityKey),
      claimLease(secondRepository, second, fixture.integrityKey)
    ])

    expect(attempts.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    expect(attempts.filter(({ status }) => status === 'rejected')).toHaveLength(1)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(1)
    const states = await Promise.all([
      fixture.repository.getExecutionLease(first.lease.id),
      fixture.repository.getExecutionLease(second.lease.id)
    ])
    expect(states.map((lease) => lease?.state).sort()).toEqual([
      'claimed',
      'issued'
    ])
  })

  it('does not oversell concurrency below the remaining request budget', async () => {
    const fixture = await createExecutionFixture(20, false, {
      maxConcurrency: 1
    })
    const first = await issueGrant(fixture)
    const second = await issueGrant(fixture)
    await claimLease(fixture.repository, first, fixture.integrityKey)
    await expect(
      claimLease(fixture.repository, second, fixture.integrityKey)
    ).rejects.toThrow(/budget-exhausted-concurrency/)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(
      1
    )
    expect(
      (await fixture.repository.getExecutionLease(second.lease.id))?.state
    ).toBe('issued')
    const counters = fixture.database.native
      .prepare(
        'SELECT security_counters_json AS counters FROM scans WHERE id = ?'
      )
      .get(fixture.scanId) as { counters: string }
    expect(JSON.parse(counters.counters)).toMatchObject({
      'budget-exhausted-concurrency': 1
    })
  })

  it('preserves the underlying cause when a claim is rejected', async () => {
    const fixture = await createExecutionFixture(20, false, {
      maxConcurrency: 1
    })
    const first = await issueGrant(fixture)
    const second = await issueGrant(fixture)
    await claimLease(fixture.repository, first, fixture.integrityKey)
    const rejection = await claimLease(
      fixture.repository,
      second,
      fixture.integrityKey
    ).catch((error: unknown) => error)
    expect(rejection).toBeInstanceOf(Error)
    expect((rejection as Error).message).toMatch(/budget-exhausted-concurrency/)
    expect((rejection as Error & { cause?: unknown }).cause).toBeDefined()
  })

  it('does not oversell the sliding-window request rate', async () => {
    const fixture = await createExecutionFixture(20, false, {
      maxRequestsPerMinute: 1
    })
    const first = await issueGrant(fixture)
    const second = await issueGrant(fixture)
    await claimLease(fixture.repository, first, fixture.integrityKey)
    await expect(
      claimLease(fixture.repository, second, fixture.integrityKey)
    ).rejects.toThrow(/budget-exhausted-rpm/)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(
      1
    )
  })

  it('does not oversell reserved response bytes', async () => {
    const fixture = await createExecutionFixture(20, false, {
      maxResponseBytes: 1
    })
    const issued = await issueGrant(fixture)
    await expect(
      claimLease(fixture.repository, issued, fixture.integrityKey)
    ).rejects.toThrow(/claim/i)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(
      0
    )
  })

  it('does not claim after the scan duration budget has elapsed', async () => {
    const fixture = await createExecutionFixture(20, false, {
      maxDurationMinutes: 1
    })
    const issued = await issueGrant(fixture)
    await fixture.repository.updateScan(fixture.scanId, {
      startedAt: Date.now() - 61_000
    })
    await expect(
      claimLease(fixture.repository, issued, fixture.integrityKey)
    ).rejects.toThrow(/claim/i)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(
      0
    )
  })

  it('fails closed for expired, revoked, and replayed leases without budget drift', async () => {
    const baseTime = Date.parse('2026-07-24T08:00:00.000Z')
    const clock = vi.spyOn(Date, 'now').mockReturnValue(baseTime)
    const fixture = await createExecutionFixture(5)
    const expiring = await issueGrant(fixture, {
      leaseExpiresAt: new Date(baseTime + 1_000).toISOString()
    })

    clock.mockReturnValue(baseTime + 2_000)
    await expect(
      claimLease(fixture.repository, expiring, fixture.integrityKey)
    ).rejects.toThrow(/claim/i)
    const expired = await fixture.repository.expireIssuedExecutionLeases()
    expect(expired.map(({ id }) => id)).toContain(expiring.lease.id)
    expect(
      (await fixture.repository.getExecutionLease(expiring.lease.id))?.state
    ).toBe('expired')

    const revoked = await issueGrant(fixture)
    await fixture.repository.revokeExecutionLease({
      leaseId: revoked.lease.id,
      reason: 'revoked'
    })
    await expect(
      claimLease(fixture.repository, revoked, fixture.integrityKey)
    ).rejects.toThrow(/claim/i)
    expect((await fixture.repository.getScan(fixture.scanId))?.requestCount).toBe(0)
  })

  it('rechecks authority immediately before dispatch without losing terminalization', async () => {
    const baseTime = Date.parse('2026-07-24T09:00:00.000Z')
    const clock = vi.spyOn(Date, 'now').mockReturnValue(baseTime)
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture, {
      leaseExpiresAt: new Date(baseTime + 1_000).toISOString()
    })
    const claimed = await claimLease(
      fixture.repository,
      issued,
      fixture.integrityKey
    )
    clock.mockReturnValue(baseTime + 2_000)

    await expect(
      fixture.repository.markExecutionLeaseDelivery({
        leaseId: issued.lease.id,
        claimToken: claimed.claimToken,
        deliveryState: 'possibly-sent'
      })
    ).rejects.toThrow(/delivery|transition|rejected/i)
    expect(
      await fixture.repository.getExecutionLease(issued.lease.id)
    ).toMatchObject({
      state: 'claimed',
      deliveryState: 'not-dispatched'
    })
    const terminal = await fixture.repository.finalizeExecutionLease({
      leaseId: issued.lease.id,
      claimToken: claimed.claimToken,
      state: 'failed',
      terminalReason: 'timed-out',
      deliveryState: 'not-dispatched',
      outcomeSummary: {
        executionState: 'timed-out',
        deliveryState: 'not-dispatched',
        verdictImpact: 'none',
        errorCode: 'execution.timeout'
      },
      evidenceRefs: []
    })
    expect(terminal).toMatchObject({
      state: 'failed',
      deliveryState: 'not-dispatched',
      terminalReason: 'timed-out'
    })
    expect(
      fixture.database.native
        .prepare(
          'SELECT status, error FROM tool_calls WHERE execution_lease_id = ?'
        )
        .get(issued.lease.id)
    ).toEqual({ status: 'failed', error: 'timed-out' })
  })

  it('upgrades the delivery guard and rejects an identity rotation during DNS work', async () => {
    const fixture = await createExecutionFixture(20, true)
    const identityId = fixture.identityId
    if (!identityId) throw new Error('Identity fixture was not created.')
    fixture.database.native.exec(`
      DROP TRIGGER execution_leases_delivery_guard;
      CREATE TRIGGER execution_leases_delivery_guard
      BEFORE UPDATE OF delivery_state ON execution_leases
      WHEN OLD.state = 'claimed' AND NEW.state = 'claimed' AND NOT (
        NEW.delivery_state = OLD.delivery_state
        OR (
          OLD.delivery_state = 'not-dispatched'
          AND NEW.delivery_state = 'possibly-sent'
        )
        OR (
          OLD.delivery_state = 'possibly-sent'
          AND NEW.delivery_state = 'response-started'
        )
      )
      BEGIN
        SELECT RAISE(
          ABORT,
          'execution delivery transition is invalid'
        );
      END;
    `)
    fixture.database.native
      .prepare('DELETE FROM __agentgo_migrations WHERE id = ?')
      .run(EXECUTION_DISPATCH_HARDENING_MIGRATION.id)
    applyDatabaseMigrations(fixture.database.native, {
      migrations: [EXECUTION_DISPATCH_HARDENING_MIGRATION],
      appliedAt: () => Date.parse('2026-07-28T00:00:00.000Z')
    })
    const upgradedTrigger = fixture.database.native
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'trigger'
           AND name = 'execution_leases_delivery_guard'`
      )
      .get() as { sql: string }
    expect(upgradedTrigger.sql).toContain(
      'scan_row.module_snapshots_sealed = 1'
    )
    expect(upgradedTrigger.sql).toContain(
      'identity_row.updated_at = json_extract'
    )

    const issued = await issueGrant(fixture)
    const claimed = await claimLease(
      fixture.repository,
      issued,
      fixture.integrityKey
    )

    const rotated = fixture.database.native
      .prepare(
        `UPDATE identities
         SET updated_at = updated_at + 1
         WHERE id = ?`
      )
      .run(identityId)
    expect(rotated.changes).toBe(1)

    await expect(
      fixture.repository.markExecutionLeaseDelivery({
        leaseId: issued.lease.id,
        claimToken: claimed.claimToken,
        deliveryState: 'possibly-sent'
      })
    ).rejects.toThrow(/delivery|transition|rejected/i)
    expect(
      await fixture.repository.getExecutionLease(issued.lease.id)
    ).toMatchObject({
      state: 'claimed',
      deliveryState: 'not-dispatched'
    })

    const terminal = await fixture.repository.finalizeExecutionLease({
      leaseId: issued.lease.id,
      claimToken: claimed.claimToken,
      state: 'failed',
      terminalReason: 'guard-rejected',
      deliveryState: 'not-dispatched',
      outcomeSummary: {
        executionState: 'failed',
        deliveryState: 'not-dispatched',
        verdictImpact: 'none',
        wireRequestHmacDigest: issued.grant.wireRequestHmac.digest,
        errorCode: 'execution.identity-version-changed'
      },
      evidenceRefs: []
    })
    expect(terminal).toMatchObject({
      state: 'failed',
      deliveryState: 'not-dispatched',
      terminalReason: 'guard-rejected'
    })
  })

  it('replays the recovery hardening migration exactly and idempotently', async () => {
    const fixture = await createExecutionFixture()
    const readTrigger = (): string => {
      const row = fixture.database.native
        .prepare(
          `SELECT sql
           FROM sqlite_master
           WHERE type = 'trigger'
             AND name = 'execution_leases_finalization_proof_guard'`
        )
        .get() as { sql?: unknown } | undefined
      if (typeof row?.sql !== 'string') {
        throw new Error('Recovery finalization trigger is unavailable.')
      }
      return row.sql.replace(/\s+/gu, ' ').trim()
    }
    const before = readTrigger()

    fixture.database.native
      .prepare('DELETE FROM __agentgo_migrations WHERE id = ?')
      .run(EXECUTION_RECOVERY_HARDENING_MIGRATION.id)
    applyDatabaseMigrations(fixture.database.native, {
      migrations: [EXECUTION_RECOVERY_HARDENING_MIGRATION],
      appliedAt: () => Date.parse('2026-07-28T00:00:00.000Z')
    })

    expect(readTrigger()).toBe(before)
    expect(
      fixture.database.native
        .prepare('SELECT id FROM __agentgo_migrations WHERE id = ?')
        .get(EXECUTION_RECOVERY_HARDENING_MIGRATION.id)
    ).toEqual({ id: EXECUTION_RECOVERY_HARDENING_MIGRATION.id })
  })

  it('validates Evidence refs before commit and finalizes tool traces atomically', async () => {
    const fixture = await createExecutionFixture(10)
    const invalidEvidence = await issueGrant(fixture)
    const invalidEvidenceClaim = await claimLease(
      fixture.repository,
      invalidEvidence,
      fixture.integrityKey
    )

    await expect(
      fixture.repository.finalizeExecutionLease({
        leaseId: invalidEvidence.lease.id,
        claimToken: invalidEvidenceClaim.claimToken,
        state: 'completed',
        terminalReason: 'completed',
        deliveryState: 'completed',
        outcomeSummary: {
          executionState: 'succeeded',
          deliveryState: 'completed',
          verdictImpact: 'none',
          wireRequestHmacDigest:
            invalidEvidence.grant.wireRequestHmac.digest
        },
        evidenceRefs: ['not-an-opaque-evidence-id']
      })
    ).rejects.toThrow(/Evidence|reference|opaque|UUID/i)
    expect(
      fixture.database.native
        .prepare(
          'SELECT state, delivery_state AS deliveryState FROM execution_leases WHERE id = ?'
        )
        .get(invalidEvidence.lease.id)
    ).toEqual({
      state: 'claimed',
      deliveryState: 'not-dispatched'
    })
    const captureDecisions =
      await fixture.repository.getExecutionCaptureDecisionSet(
        invalidEvidence.grant.id
      )
    const requestDecision = captureDecisions?.decisions.find(
      (decision) =>
        decision.executionState === 'succeeded' &&
        decision.role === 'request-summary'
    )
    const responseDecision = captureDecisions?.decisions.find(
      (decision) =>
        decision.executionState === 'succeeded' &&
        decision.role === 'response-summary'
    )
    if (!requestDecision || !responseDecision) {
      throw new Error('Expected HTTP success capture decisions.')
    }
    const evidenceStore = new EvidenceStore(
      fixture.database,
      join(fixture.directory, 'evidence')
    )
    const wrongTypeEvidence = await evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: invalidEvidence.grant.policyDecisionId,
      type: 'execution-request-summary',
      mimeType: 'application/json',
      content: '{"kind":"wrong-type"}',
      source: requestDecision.source,
      createdBy: 'execution-db-test',
      captureTool: 'execution-db-test',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
    const exactResponseEvidence = await evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: invalidEvidence.grant.policyDecisionId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: '{"kind":"exact-response"}',
      source: responseDecision.source,
      createdBy: 'execution-db-test',
      captureTool: 'execution-db-test',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
    await expect(
      fixture.repository.recordExecutionInteractionAudit({
        leaseId: invalidEvidence.lease.id,
        claimToken: invalidEvidenceClaim.claimToken,
        interaction: {
          scanId: fixture.scanId,
          policyDecisionId: invalidEvidence.grant.policyDecisionId,
          requestRef: wrongTypeEvidence.id,
          responseRef: exactResponseEvidence.id,
          requestSummary: { method: 'GET' },
          responseSummary: { status: 200 }
        },
        evidenceLinks: [
          {
            leaseId: invalidEvidence.lease.id,
            evidenceId: wrongTypeEvidence.id,
            captureDecisionId: requestDecision.id,
            role: requestDecision.role,
            ordinal: 0
          },
          {
            leaseId: invalidEvidence.lease.id,
            evidenceId: exactResponseEvidence.id,
            captureDecisionId: responseDecision.id,
            role: responseDecision.role,
            ordinal: 0
          }
        ]
      })
    ).rejects.toThrow(/evidence|capture|binding/i)
    expect(
      await fixture.repository.listExecutionLeaseEvidence(
        invalidEvidence.lease.id
      )
    ).toEqual([])

    const atomic = await issueGrant(fixture)
    const atomicClaim = await claimLease(
      fixture.repository,
      atomic,
      fixture.integrityKey
    )
    fixture.database.native.exec(`
      CREATE TRIGGER synthetic_tool_call_finalize_failure
      BEFORE UPDATE OF status ON tool_calls
      BEGIN
        SELECT RAISE(ABORT, 'synthetic tool-call finalize failure');
      END;
    `)

    await expectRejectionCause(
      fixture.repository.finalizeExecutionLease({
        leaseId: atomic.lease.id,
        claimToken: atomicClaim.claimToken,
        state: 'failed',
        terminalReason: 'guard-rejected',
        deliveryState: 'not-dispatched',
        outcomeSummary: {
          executionState: 'failed',
          deliveryState: 'not-dispatched',
          verdictImpact: 'none',
          wireRequestHmacDigest: atomic.grant.wireRequestHmac.digest,
          errorCode: 'execution.guard-rejected'
        },
        evidenceRefs: []
      }),
      /synthetic tool-call finalize failure/i
    )
    expect(
      fixture.database.native
        .prepare(
          'SELECT state, delivery_state AS deliveryState FROM execution_leases WHERE id = ?'
        )
        .get(atomic.lease.id)
    ).toEqual({
      state: 'claimed',
      deliveryState: 'not-dispatched'
    })
    expect(
      fixture.database.native
        .prepare(
          'SELECT status FROM tool_calls WHERE execution_lease_id = ?'
        )
        .get(atomic.lease.id)
    ).toEqual({ status: 'running' })
  })

  it('recovers claimed work as unknown and never auto-replays it', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture, {
      overrides: {
        purpose: 'read',
        retryClass: 'deterministic-readonly'
      }
    })
    const claimed = await claimLease(
      fixture.repository,
      issued,
      fixture.integrityKey
    )
    const priorAudit = await recordAuditPair(
      fixture,
      issued,
      claimed,
      'failed',
      'captured-before-crash'
    )
    const recoveryContexts =
      await fixture.repository.listClaimedExecutionLeasesForRecovery()
    expect(recoveryContexts).toHaveLength(1)
    expect(recoveryContexts[0]).toMatchObject({
      lease: { id: issued.lease.id, state: 'claimed' },
      grant: { id: issued.grant.id },
      captureDecision: {
        source: 'execution-interruption-summary',
        executionState: 'interrupted',
        role: 'interruption-summary'
      }
    })
    const captureDecision = recoveryContexts[0]!.captureDecision
    const evidenceStore = new EvidenceStore(
      fixture.database,
      join(fixture.directory, 'evidence')
    )
    const recoveredAt = Date.now()
    const interruptionEvidence = await evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: issued.grant.policyDecisionId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: canonicalJson({
        interruptionTime: 'unknown',
        recoveredAt: new Date(recoveredAt).toISOString(),
        authorizationWindowUpperBound: new Date(
          Math.min(
            recoveredAt,
            Date.parse(issued.lease.expiresAt),
            Date.parse(captureDecision.validUntil)
          )
        ).toISOString()
      }),
      source: captureDecision.source,
      createdBy: 'execution-db-test',
      captureTool: 'execution-db-test',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })

    await expect(
      fixture.repository.recoverInterruptedExecutionLeaseWithEvidence({
        leaseId: issued.lease.id,
        evidenceId: randomUUID()
      })
    ).rejects.toThrow(/evidence|foreign|binding/i)
    expect(
      await fixture.repository.getExecutionLease(issued.lease.id)
    ).toMatchObject({
      state: 'claimed',
      deliveryState: 'not-dispatched'
    })
    expect(
      await fixture.repository.listExecutionLeaseEvidence(issued.lease.id)
    ).toHaveLength(2)

    const recovered =
      await fixture.repository.recoverInterruptedExecutionLeaseWithEvidence({
        leaseId: issued.lease.id,
        evidenceId: interruptionEvidence.id
      })
    expect(recovered).toMatchObject({
      id: issued.lease.id,
      state: 'failed',
      deliveryState: 'unknown',
      terminalReason: 'interrupted',
      outcomeSummary: {
        executionState: 'interrupted',
        deliveryState: 'unknown',
        verdictImpact: 'inconclusive'
      }
    })
    expect(new Set(recovered.evidenceRefs)).toEqual(
      new Set([
        priorAudit.requestEvidence.id,
        priorAudit.resultEvidence.id,
        interruptionEvidence.id
      ])
    )
    expect(
      await fixture.repository.listClaimedExecutionLeasesForRecovery()
    ).toEqual([])
    const recoveryEvidence =
      await fixture.repository.listExecutionLeaseEvidence(issued.lease.id)
    expect(recoveryEvidence).toHaveLength(3)
    expect(recoveryEvidence).toEqual(
      expect.arrayContaining([
        {
          leaseId: issued.lease.id,
          evidenceId: priorAudit.requestEvidence.id,
          captureDecisionId: priorAudit.requestDecision.id,
          role: 'request-summary',
          ordinal: 0
        },
        {
          leaseId: issued.lease.id,
          evidenceId: priorAudit.resultEvidence.id,
          captureDecisionId: priorAudit.resultDecision.id,
          role: priorAudit.resultDecision.role,
          ordinal: 0
        },
        {
          leaseId: issued.lease.id,
          evidenceId: interruptionEvidence.id,
          captureDecisionId: captureDecision.id,
          role: 'interruption-summary',
          ordinal: 0
        }
      ])
    )
    expect(
      fixture.database.native
        .prepare(
          'SELECT status, error FROM tool_calls WHERE execution_lease_id = ?'
        )
        .get(issued.lease.id)
    ).toEqual({ status: 'failed', error: 'interrupted' })
    await expect(
      fixture.repository.issueReplacementExecutionLease({
        grantId: issued.grant.id,
        previousLeaseId: issued.lease.id,
        expiresAt: new Date(Date.now() + 10_000).toISOString(),
        integrityKey: fixture.integrityKey
      })
    ).rejects.toThrow(/non-delivery|eligible/i)
    await expect(
      claimLease(fixture.repository, issued, fixture.integrityKey)
    ).rejects.toThrow(/claim/i)
  })

  it('terminalizes claimed work as unknown without inventing recovery Evidence', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture, {
      overrides: {
        purpose: 'read',
        retryClass: 'deterministic-readonly'
      }
    })
    await claimLease(fixture.repository, issued, fixture.integrityKey)

    const recovered =
      await fixture.repository.recoverInterruptedExecutionLease({
        leaseId: issued.lease.id
      })

    expect(recovered).toMatchObject({
      id: issued.lease.id,
      state: 'failed',
      deliveryState: 'unknown',
      terminalReason: 'interrupted',
      outcomeSummary: {
        executionState: 'interrupted',
        deliveryState: 'unknown',
        verdictImpact: 'inconclusive'
      },
      evidenceRefs: []
    })
    expect(
      fixture.database.native
        .prepare(
          'SELECT status, error FROM tool_calls WHERE execution_lease_id = ?'
        )
        .get(issued.lease.id)
    ).toEqual({ status: 'failed', error: 'interrupted' })

    const restarted = new AgentGoRepository(
      trackDatabase(openAgentGoDatabase(fixture.filePath))
    )
    expect(
      await restarted.listClaimedExecutionLeasesForRecovery()
    ).toEqual([])
    expect(
      await restarted.listInterruptedExecutionLeasesForScanRecovery()
    ).toEqual([
      expect.objectContaining({
        lease: expect.objectContaining({
          id: issued.lease.id,
          state: 'failed',
          deliveryState: 'unknown'
        }),
        grant: expect.objectContaining({ id: issued.grant.id })
      })
    ])
    expect(
      (
        await restarted.listInterruptedExecutionLeasesForScanRecovery()
      )[0]
    ).not.toHaveProperty('interruptionEvidenceId')
    await expect(
      restarted.issueReplacementExecutionLease({
        grantId: issued.grant.id,
        previousLeaseId: issued.lease.id,
        expiresAt: new Date(Date.now() + 10_000).toISOString(),
        integrityKey: fixture.integrityKey
      })
    ).rejects.toThrow(/non-delivery|eligible/i)
  })

  it('atomically discards only safe crash-staged Evidence during recovery', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture)
    const claimed = await claimLease(
      fixture.repository,
      issued,
      fixture.integrityKey
    )
    const decisionSet =
      await fixture.repository.getExecutionCaptureDecisionSet(issued.grant.id)
    const stagedDecision = decisionSet?.decisions.find(
      (decision) =>
        decision.executionState === 'failed' &&
        decision.role === 'request-summary'
    )
    if (!stagedDecision) {
      throw new Error('Crash-staging capture authority is unavailable.')
    }
    const evidenceStore = new EvidenceStore(
      fixture.database,
      join(fixture.directory, 'evidence')
    )
    const saveStaged = (tag: string) =>
      evidenceStore.save({
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId,
        policyDecisionId: issued.grant.policyDecisionId,
        type: 'evidence-capture-hash-only',
        mimeType: 'application/json',
        content: canonicalJson({ tag }),
        source: stagedDecision.source,
        createdBy: 'execution-service',
        captureTool: 'evidence-capture-policy',
        captureToolVersion: '2.0.0',
        redactionState: 'redacted'
      })
    const safe = await saveStaged('safe-unbound')
    const derivedSource = await saveStaged('derived-source')
    const derivative = await evidenceStore.createRedactedTextDerivative(
      derivedSource.id,
      'execution-db-test'
    )
    const findingEvidence = await saveStaged('finding-evidence')
    const agentEvidence = await saveStaged('agent-input-evidence')
    const signalEvidence = await saveStaged('signal-evidence')
    const reportEvidence = await evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: issued.grant.policyDecisionId,
      type: 'report-markdown',
      mimeType: 'text/markdown',
      content: '# Redacted recovery reference',
      source: 'reporting',
      createdBy: 'report-service',
      captureTool: 'agentgo-reporting',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
    const ruleSourceEvidence = await saveStaged('rule-source-evidence')
    await fixture.repository.createAgentRun({
      scanId: fixture.scanId,
      role: 'analysis',
      promptId: 'recovery-reference-test',
      promptVersion: '1.0.0',
      promptHash: sha256('recovery-reference-test@1.0.0'),
      modelProfileId: randomUUID(),
      inputRefs: [agentEvidence.id]
    })
    const signalEndpointId = randomUUID()
    const signalEndpointCreatedAt = Date.now()
    fixture.database.native
      .prepare(
        `INSERT INTO endpoints (
          id, scan_id, page_id, method, url_template, normalized_url,
          canonical_route, content_type, source, status, lifecycle_status,
          created_at, updated_at
        ) VALUES (?, ?, NULL, 'GET', ?, ?, '/recovery-reference',
                  'application/json', 'automated-test', 'active',
                  'active', ?, ?)`
      )
      .run(
        signalEndpointId,
        fixture.scanId,
        'https://lab.example.test/recovery-reference',
        'https://lab.example.test/recovery-reference',
        signalEndpointCreatedAt,
        signalEndpointCreatedAt
      )
    await fixture.repository.createSignal({
      scanId: fixture.scanId,
      family: 'sqli',
      endpointId: signalEndpointId,
      hypothesis: 'Recovery reference protection',
      observedDifference: 'Synthetic reference only.',
      confidenceHint: 0.5,
      evidenceRefs: [signalEvidence.id]
    })
    await fixture.repository.createReport({
      scanId: fixture.scanId,
      title: 'Recovery reference protection',
      format: 'markdown',
      sha256: reportEvidence.sha256,
      redacted: true,
      contentRef: reportEvidence.id
    })
    await fixture.repository.ensureConfirmationRule({
      id: 'test.sqli.source-rule',
      version: '1.0.0',
      family: 'sqli',
      rule: { kind: 'differential' },
      requiredChecks: [],
      sourceRefs: [ruleSourceEvidence.id]
    })
    await fixture.repository.ensureConfirmationRule({
      id: 'test.sqli.rule',
      version: '1.0.0',
      family: 'sqli',
      rule: { kind: 'differential' },
      requiredChecks: [],
      sourceRefs: []
    })
    await fixture.repository.createFinding({
      scanId: fixture.scanId,
      family: 'sqli',
      title: 'Recovery reference protection',
      verdict: 'inconclusive',
      severity: 'info',
      confidence: 0.5,
      confirmationRuleId: 'test.sqli.rule',
      confirmationRuleVersion: '1.0.0',
      reproducibility: 'Crash-recovery reference fixture.',
      remediation: [],
      evidenceRefs: [findingEvidence.id]
    })
    const bound = await recordAuditPair(
      fixture,
      issued,
      claimed,
      'failed',
      'bound-before-crash',
      'execution-service',
      'evidence-capture-policy'
    )

    const recovered =
      await fixture.repository.recoverInterruptedExecutionLeaseWithCleanup({
        leaseId: issued.lease.id,
        discardUnboundStagedEvidence: true
      })

    expect(recovered.lease).toMatchObject({
      state: 'failed',
      deliveryState: 'unknown',
      terminalReason: 'interrupted'
    })
    expect(recovered.discardedEvidence).toEqual([
      {
        id: safe.id,
        filePath: safe.filePath,
        sha256: safe.sha256
      }
    ])
    expect(await evidenceStore.getMetadata(safe.id)).toBeUndefined()
    expect(existsSync(evidenceStore.resolveStoredPath(safe.filePath))).toBe(true)
    expect(await evidenceStore.getMetadata(derivedSource.id)).toBeDefined()
    expect(await evidenceStore.getMetadata(derivative.id)).toBeDefined()
    expect(await evidenceStore.getMetadata(findingEvidence.id)).toBeDefined()
    expect(await evidenceStore.getMetadata(agentEvidence.id)).toBeDefined()
    expect(await evidenceStore.getMetadata(signalEvidence.id)).toBeDefined()
    expect(await evidenceStore.getMetadata(reportEvidence.id)).toBeDefined()
    expect(
      await evidenceStore.getMetadata(ruleSourceEvidence.id)
    ).toBeDefined()
    expect(
      await evidenceStore.getMetadata(bound.requestEvidence.id)
    ).toBeDefined()
    expect(
      await evidenceStore.getMetadata(bound.resultEvidence.id)
    ).toBeDefined()
    expect(
      fixture.database.native
        .prepare(
          'SELECT status, error FROM tool_calls WHERE execution_lease_id = ?'
        )
        .get(issued.lease.id)
    ).toEqual({ status: 'failed', error: 'interrupted' })
  })

  it('binds the newest interruption summary and discards one left by a second recovery crash', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture)
    await claimLease(fixture.repository, issued, fixture.integrityKey)
    const [context] =
      await fixture.repository.listClaimedExecutionLeasesForRecovery()
    if (!context) {
      throw new Error('Interrupted recovery context is unavailable.')
    }
    const evidenceStore = new EvidenceStore(
      fixture.database,
      join(fixture.directory, 'evidence')
    )
    const saveInterruptionSummary = (attempt: string) =>
      evidenceStore.save({
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId,
        policyDecisionId: issued.grant.policyDecisionId,
        type: 'evidence-capture-hash-only',
        mimeType: 'application/json',
        content: canonicalJson({ attempt }),
        source: context.captureDecision.source,
        createdBy: 'application-service',
        captureTool: 'evidence-capture-policy',
        captureToolVersion: '2.0.0',
        redactionState: 'redacted'
      })
    const abandoned = await saveInterruptionSummary('abandoned-before-txn')
    const current = await saveInterruptionSummary('current-recovery')

    const recovered =
      await fixture.repository.recoverInterruptedExecutionLeaseWithCleanup({
        leaseId: issued.lease.id,
        evidenceId: current.id,
        discardUnboundStagedEvidence: true
      })

    expect(recovered.lease.evidenceRefs).toEqual([current.id])
    expect(recovered.discardedEvidence).toEqual([
      {
        id: abandoned.id,
        filePath: abandoned.filePath,
        sha256: abandoned.sha256
      }
    ])
    expect(await evidenceStore.getMetadata(abandoned.id)).toBeUndefined()
    expect(await evidenceStore.getMetadata(current.id)).toBeDefined()
    expect(
      await fixture.repository.listExecutionLeaseEvidence(issued.lease.id)
    ).toEqual([
      expect.objectContaining({
        leaseId: issued.lease.id,
        evidenceId: current.id,
        captureDecisionId: context.captureDecision.id,
        role: 'interruption-summary'
      })
    ])
  })

  it('preserves staged metadata when the caller cannot garbage-collect files', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture)
    await claimLease(fixture.repository, issued, fixture.integrityKey)
    const decisionSet =
      await fixture.repository.getExecutionCaptureDecisionSet(issued.grant.id)
    const stagedDecision = decisionSet?.decisions.find(
      (decision) =>
        decision.executionState === 'failed' &&
        decision.role === 'request-summary'
    )
    if (!stagedDecision) {
      throw new Error('Crash-staging capture authority is unavailable.')
    }
    const evidenceStore = new EvidenceStore(
      fixture.database,
      join(fixture.directory, 'evidence')
    )
    const staged = await evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: issued.grant.policyDecisionId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: canonicalJson({ staged: true }),
      source: stagedDecision.source,
      createdBy: 'execution-service',
      captureTool: 'evidence-capture-policy',
      captureToolVersion: '2.0.0',
      redactionState: 'redacted'
    })

    const recovered =
      await fixture.repository.recoverInterruptedExecutionLeaseWithCleanup({
        leaseId: issued.lease.id,
        discardUnboundStagedEvidence: false
      })

    expect(recovered.discardedEvidence).toEqual([])
    expect(await evidenceStore.getMetadata(staged.id)).toBeDefined()
    expect(existsSync(evidenceStore.resolveStoredPath(staged.filePath))).toBe(
      true
    )
  })

  it('rejects an explicitly named recovery artifact with a non-summary MIME type', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture)
    await claimLease(fixture.repository, issued, fixture.integrityKey)
    const [context] =
      await fixture.repository.listClaimedExecutionLeasesForRecovery()
    if (!context) throw new Error('Recovery context is unavailable.')
    const evidenceStore = new EvidenceStore(
      fixture.database,
      join(fixture.directory, 'evidence')
    )
    const disguised = await evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: issued.grant.policyDecisionId,
      type: 'evidence-capture-hash-only',
      mimeType: 'text/plain',
      content: canonicalJson({ leaseId: issued.lease.id, pending: true }),
      source: context.captureDecision.source,
      createdBy: 'application-service',
      captureTool: 'evidence-capture-policy',
      captureToolVersion: '2.0.0',
      redactionState: 'redacted'
    })

    await expect(
      fixture.repository.recoverInterruptedExecutionLease({
        leaseId: issued.lease.id,
        discardUnboundEvidenceId: disguised.id
      })
    ).rejects.toThrow(/not eligible/i)
    expect(
      await fixture.repository.getExecutionLease(issued.lease.id)
    ).toMatchObject({ state: 'claimed' })
    expect(await evidenceStore.getMetadata(disguised.id)).toBeDefined()
    expect(
      existsSync(evidenceStore.resolveStoredPath(disguised.filePath))
    ).toBe(true)
  })

  it('atomically rolls back recovery and unbound-Evidence discard', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture)
    await claimLease(fixture.repository, issued, fixture.integrityKey)
    const [context] =
      await fixture.repository.listClaimedExecutionLeasesForRecovery()
    if (!context) throw new Error('Recovery context is unavailable.')
    const evidenceStore = new EvidenceStore(
      fixture.database,
      join(fixture.directory, 'evidence')
    )
    const pendingEvidence = await evidenceStore.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      policyDecisionId: issued.grant.policyDecisionId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: canonicalJson({ leaseId: issued.lease.id, pending: true }),
      source: context.captureDecision.source,
      createdBy: 'application-service',
      captureTool: 'evidence-capture-policy',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
    const pendingPath = evidenceStore.resolveStoredPath(
      pendingEvidence.filePath
    )
    fixture.database.native.exec(`
      CREATE TRIGGER synthetic_recovery_tool_call_failure
      BEFORE UPDATE OF status ON tool_calls
      BEGIN
        SELECT RAISE(ABORT, 'synthetic recovery tool-call failure');
      END;
    `)

    await expectRejectionCause(
      fixture.repository.recoverInterruptedExecutionLease({
        leaseId: issued.lease.id,
        discardUnboundEvidenceId: pendingEvidence.id
      }),
      /synthetic recovery tool-call failure/i
    )
    expect(
      await fixture.repository.getExecutionLease(issued.lease.id)
    ).toMatchObject({ state: 'claimed' })
    expect(await evidenceStore.getMetadata(pendingEvidence.id)).toBeDefined()
    expect(existsSync(pendingPath)).toBe(true)
    expect(
      fixture.database.native
        .prepare(
          'SELECT status FROM tool_calls WHERE execution_lease_id = ?'
        )
        .get(issued.lease.id)
    ).toEqual({ status: 'running' })

    fixture.database.native.exec(
      'DROP TRIGGER synthetic_recovery_tool_call_failure'
    )
    const recovered =
      await fixture.repository.recoverInterruptedExecutionLease({
        leaseId: issued.lease.id,
        discardUnboundEvidenceId: pendingEvidence.id
      })
    expect(recovered).toMatchObject({
      state: 'failed',
      deliveryState: 'unknown',
      terminalReason: 'interrupted'
    })
    expect(await evidenceStore.getMetadata(pendingEvidence.id)).toBeUndefined()
    expect(
      await evidenceStore.deleteUnreferencedFiles([
        pendingEvidence.filePath
      ])
    ).toBe(1)
    expect(existsSync(pendingPath)).toBe(false)
  })

  it('permits replacement only for the latest deterministic read proven not dispatched', async () => {
    const fixture = await createExecutionFixture(10)
    const retryable = await issueGrant(fixture, {
      overrides: {
        purpose: 'read',
        retryClass: 'deterministic-readonly'
      }
    })
    await failLease(fixture, retryable, {
      deliveryState: 'not-dispatched',
      terminalReason: 'guard-rejected'
    })
    const replacement = await fixture.repository.issueReplacementExecutionLease({
      grantId: retryable.grant.id,
      previousLeaseId: retryable.lease.id,
      expiresAt: new Date(Date.now() + 10_000).toISOString(),
      integrityKey: fixture.integrityKey
    })
    expect(replacement).toMatchObject({
      grantId: retryable.grant.id,
      parentLeaseId: retryable.lease.id,
      attempt: 2,
      state: 'issued',
      deliveryState: 'not-dispatched'
    })
    await expect(
      fixture.repository.issueReplacementExecutionLease({
        grantId: retryable.grant.id,
        previousLeaseId: retryable.lease.id,
        expiresAt: new Date(Date.now() + 10_000).toISOString(),
        integrityKey: fixture.integrityKey
      })
    ).rejects.toThrow(/latest|eligible|non-delivery/i)

    const cannotDowngrade = await issueGrant(fixture, {
      overrides: {
        purpose: 'read',
        retryClass: 'deterministic-readonly'
      }
    })
    const cannotDowngradeClaim = await claimLease(
      fixture.repository,
      cannotDowngrade,
      fixture.integrityKey
    )
    await fixture.repository.markExecutionLeaseDelivery({
      leaseId: cannotDowngrade.lease.id,
      claimToken: cannotDowngradeClaim.claimToken,
      deliveryState: 'possibly-sent'
    })
    await expect(
      fixture.repository.finalizeExecutionLease({
        leaseId: cannotDowngrade.lease.id,
        claimToken: cannotDowngradeClaim.claimToken,
        state: 'failed',
        terminalReason: 'network-failed',
        deliveryState: 'not-dispatched',
        outcomeSummary: {
          executionState: 'failed',
          deliveryState: 'not-dispatched',
          verdictImpact: 'none',
          wireRequestHmacDigest:
            cannotDowngrade.grant.wireRequestHmac.digest,
          errorCode: 'execution.network-failed'
        },
        evidenceRefs: []
      })
    ).rejects.toThrow(/delivery|transition|finalization/i)
    expect(
      await fixture.repository.getExecutionLease(cannotDowngrade.lease.id)
    ).toMatchObject({
      state: 'claimed',
      deliveryState: 'possibly-sent'
    })

    const maybeSent = await issueGrant(fixture, {
      overrides: {
        purpose: 'read',
        retryClass: 'deterministic-readonly'
      }
    })
    await failLease(fixture, maybeSent, {
      deliveryState: 'possibly-sent',
      terminalReason: 'network-failed'
    })
    await expect(
      fixture.repository.issueReplacementExecutionLease({
        grantId: maybeSent.grant.id,
        previousLeaseId: maybeSent.lease.id,
        expiresAt: new Date(Date.now() + 10_000).toISOString(),
        integrityKey: fixture.integrityKey
      })
    ).rejects.toThrow(/non-delivery|eligible/i)

    const neverRetry = await issueGrant(fixture, {
      overrides: { purpose: 'read', retryClass: 'never' }
    })
    await failLease(fixture, neverRetry, {
      deliveryState: 'not-dispatched',
      terminalReason: 'guard-rejected'
    })
    await expect(
      fixture.repository.issueReplacementExecutionLease({
        grantId: neverRetry.grant.id,
        previousLeaseId: neverRetry.lease.id,
        expiresAt: new Date(Date.now() + 10_000).toISOString(),
        integrityKey: fixture.integrityKey
      })
    ).rejects.toThrow(/deterministic|eligible/i)
  })

  it('requires a completed parent lease and enforces redirect-hop budget', async () => {
    const fixture = await createExecutionFixture(10)
    const parent = await issueGrant(fixture, {
      overrides: { budget: { maxRedirects: 1 } }
    })
    const parentClaim = await claimLease(
      fixture.repository,
      parent,
      fixture.integrityKey
    )
    const childWireBeforeCompletion = nextWireProof(fixture, 'redirect-before')
    await expect(
      issueGrant(fixture, {
        wire: childWireBeforeCompletion,
        parentLeaseId: parent.lease.id,
        overrides: {
          parentGrantId: parent.grant.id,
          redirectHop: 1,
          stepId: parent.grant.stepId,
          validUntil: parent.grant.validUntil,
          budget: { maxRedirects: 1 }
        }
      })
    ).rejects.toThrow(/completed parent|preceding grant|lease/i)

    await fixture.repository.markExecutionLeaseDelivery({
      leaseId: parent.lease.id,
      claimToken: parentClaim.claimToken,
      deliveryState: 'possibly-sent'
    })
    await fixture.repository.markExecutionLeaseDelivery({
      leaseId: parent.lease.id,
      claimToken: parentClaim.claimToken,
      deliveryState: 'response-started'
    })
    const parentAudit = await recordAuditPair(
      fixture,
      parent,
      parentClaim,
      'succeeded',
      'redirect-parent'
    )
    await fixture.repository.finalizeExecutionLease({
      leaseId: parent.lease.id,
      claimToken: parentClaim.claimToken,
      state: 'completed',
      terminalReason: 'completed',
      deliveryState: 'completed',
      outcomeSummary: {
        executionState: 'succeeded',
        deliveryState: 'completed',
        verdictImpact: 'none',
        wireRequestHmacDigest: parent.grant.wireRequestHmac.digest,
        requestBytes: parent.grant.budget.requestBytes,
        responseBytes: 0
      },
      evidenceRefs: [
        parentAudit.requestEvidence.id,
        parentAudit.resultEvidence.id
      ]
    })
    const child = await issueGrant(fixture, {
      wire: nextWireProof(fixture, 'redirect-child'),
      parentLeaseId: parent.lease.id,
      overrides: {
        parentGrantId: parent.grant.id,
        redirectHop: 1,
        stepId: parent.grant.stepId,
        validUntil: parent.grant.validUntil,
        budget: { maxRedirects: 1, requestBytes: 128 }
      }
    })
    expect(child.grant).toMatchObject({
      parentGrantId: parent.grant.id,
      redirectHop: 1,
      budget: { requestBytes: 128 }
    })
    expect(child.lease.parentLeaseId).toBe(parent.lease.id)
    expect(
      (await claimLease(fixture.repository, child, fixture.integrityKey)).lease.state
    ).toBe('claimed')

    const noRedirectParent = await issueGrant(fixture, {
      overrides: { budget: { maxRedirects: 0 } }
    })
    await completeLease(fixture, noRedirectParent)
    await expect(
      issueGrant(fixture, {
        wire: nextWireProof(fixture, 'redirect-over-budget'),
        parentLeaseId: noRedirectParent.lease.id,
        overrides: {
          parentGrantId: noRedirectParent.grant.id,
          redirectHop: 1,
          stepId: noRedirectParent.grant.stepId,
          validUntil: noRedirectParent.grant.validUntil,
          budget: { maxRedirects: 0 }
        }
      })
    ).rejects.toThrow(/redirect|budget|binding/i)
  })

  it('keeps identical Evidence content separately attributable to each lease', async () => {
    const fixture = await createExecutionFixture(10)
    const first = await issueGrant(fixture)
    const second = await issueGrant(fixture)
    const firstClaim = await claimLease(
      fixture.repository,
      first,
      fixture.integrityKey
    )
    const secondClaim = await claimLease(
      fixture.repository,
      second,
      fixture.integrityKey
    )
    for (const [issued, claimed] of [
      [first, firstClaim],
      [second, secondClaim]
    ] as const) {
      for (const deliveryState of [
        'possibly-sent',
        'response-started'
      ] as const) {
        await fixture.repository.markExecutionLeaseDelivery({
          leaseId: issued.lease.id,
          claimToken: claimed.claimToken,
          deliveryState
        })
      }
    }
    const firstAudit = await recordAuditPair(
      fixture,
      first,
      firstClaim,
      'succeeded',
      'identical-content'
    )
    const secondAudit = await recordAuditPair(
      fixture,
      second,
      secondClaim,
      'succeeded',
      'identical-content'
    )
    expect(firstAudit.interactionId).not.toBe(secondAudit.interactionId)
    expect(firstAudit.requestEvidence.id).not.toBe(
      secondAudit.requestEvidence.id
    )
    expect(firstAudit.requestEvidence.sha256).toBe(
      secondAudit.requestEvidence.sha256
    )
    expect(firstAudit.requestEvidence.filePath).toBe(
      secondAudit.requestEvidence.filePath
    )
    expect(firstAudit.resultEvidence.id).not.toBe(
      secondAudit.resultEvidence.id
    )
    expect(firstAudit.resultEvidence.sha256).toBe(
      secondAudit.resultEvidence.sha256
    )
    expect(firstAudit.resultEvidence.filePath).toBe(
      secondAudit.resultEvidence.filePath
    )

    for (const [issued, claimed, audit] of [
      [first, firstClaim, firstAudit],
      [second, secondClaim, secondAudit]
    ] as const) {
      await fixture.repository.finalizeExecutionLease({
        leaseId: issued.lease.id,
        claimToken: claimed.claimToken,
        state: 'completed',
        terminalReason: 'completed',
        deliveryState: 'completed',
        outcomeSummary: {
          executionState: 'succeeded',
          deliveryState: 'completed',
          verdictImpact: 'none',
          wireRequestHmacDigest: issued.grant.wireRequestHmac.digest,
          requestBytes: issued.grant.budget.requestBytes,
          responseBytes: 0
        },
        evidenceRefs: [
          audit.requestEvidence.id,
          audit.resultEvidence.id
        ]
      })
      const links = await fixture.repository.listExecutionLeaseEvidence(
        issued.lease.id
      )
      expect(links).toHaveLength(2)
      expect(links).toEqual(
        expect.arrayContaining([
          {
            leaseId: issued.lease.id,
            evidenceId: audit.requestEvidence.id,
            captureDecisionId: audit.requestDecision.id,
            role: 'request-summary',
            ordinal: 0
          },
          {
            leaseId: issued.lease.id,
            evidenceId: audit.resultEvidence.id,
            captureDecisionId: audit.resultDecision.id,
            role: audit.resultDecision.role,
            ordinal: 0
          }
        ])
      )
    }

    expect(() =>
      fixture.database.native
        .prepare(
          'UPDATE tool_calls SET tool_name = ? WHERE execution_lease_id = ?'
        )
        .run('tampered-terminal-tool', first.lease.id)
    ).toThrow(/immutable/i)
    expect(() =>
      fixture.database.native
        .prepare('DELETE FROM tool_calls WHERE execution_lease_id = ?')
        .run(first.lease.id)
    ).toThrow(/immutable/i)
    expect(() =>
      fixture.database.native
        .prepare('UPDATE evidence_items SET source = ? WHERE id = ?')
        .run(
          'tampered-terminal-source',
          firstAudit.requestEvidence.id
        )
    ).toThrow(/immutable/i)
    expect(() =>
      fixture.database.native
        .prepare('DELETE FROM evidence_items WHERE id = ?')
        .run(firstAudit.requestEvidence.id)
    ).toThrow(/immutable/i)
    expect(() =>
      fixture.database.native
        .prepare('DELETE FROM interactions WHERE id = ?')
        .run(firstAudit.interactionId)
    ).toThrow(/immutable/i)
  })

  it('persists seventeen offline-browser capture decisions including reviewable originals', async () => {
    const fixture = await createExecutionFixture()
    const issued = await issueGrant(fixture, {
      overrides: {
        adapterKind: 'browser-offline',
        capabilityIds: ['browser.offline-replay'],
        stepId: 'xss.verify'
      }
    })
    const rows = fixture.database.native
      .prepare(
        `SELECT source, action, COUNT(*) AS n
         FROM execution_capture_decisions
         WHERE grant_id = ?
         GROUP BY source, action
         ORDER BY source, action`
      )
      .all(issued.grant.id) as Array<{
      source: string
      action: string
      n: number
    }>
    expect(rows).toEqual([
      { source: 'browser-request-summary', action: 'hash-only', n: 4 },
      { source: 'browser-result-summary', action: 'hash-only', n: 4 },
      { source: 'browser-screenshot', action: 'protected-original', n: 4 },
      { source: 'dom-snapshot', action: 'protected-original', n: 4 },
      {
        source: 'execution-interruption-summary',
        action: 'hash-only',
        n: 1
      }
    ])
  })
})
