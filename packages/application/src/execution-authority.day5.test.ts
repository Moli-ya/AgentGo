import { describe, expect, it, vi } from 'vitest'
import {
  EvidenceCaptureDecisionSchema,
  ExecutionGrantIntegrityBindingSchema,
  ExecutionGrantSchema,
  ExecutionLeaseSchema,
  ScanModuleSnapshotRecordSchema,
  type ExecutionCredentialRef,
  type ExecutionGrant,
  type ExecutionLease,
  type ScanModuleSnapshotRecord
} from '@agentgo/contracts'
import { canonicalJson, sha256Text } from '@agentgo/domain'
import {
  hashExecutionCaptureDecisionSet,
  signExecutionGrantIntegrity,
  type AgentGoRepository,
  type IssueExecutionGrantInput
} from '@agentgo/db'
import {
  ExecutionAuthority,
  type ExecutionEvidenceCaptureDecisionSet
} from './execution-authority'
import { EphemeralRequestHashKeyProvider } from './request-hash-key-provider'
import {
  CompiledWireRequest,
  computeWireRequestHmac,
  createWireRequestAuthorizationContext,
  type CompiledProbeRequest,
  type MaterializedWireRequest
} from './request-compiler'

const NOW = '2026-07-24T00:00:00.000Z'
const NOW_MS = Date.parse(NOW)
const ids = {
  scan: '00000000-0000-4000-8000-000000000001',
  scope: '00000000-0000-4000-8000-000000000002',
  module: '00000000-0000-4000-8000-000000000003',
  decision1: '00000000-0000-4000-8000-000000000004',
  decision2: '00000000-0000-4000-8000-000000000005',
  proposal1: '00000000-0000-4000-8000-000000000006',
  proposal2: '00000000-0000-4000-8000-000000000007',
  target: '00000000-0000-4000-8000-000000000008',
  workspace: '00000000-0000-4000-8000-000000000009',
  identity: '00000000-0000-4000-8000-00000000000a',
  session: '00000000-0000-4000-8000-00000000000b',
  testObject: '00000000-0000-4000-8000-00000000000c',
  grant1: '00000000-0000-4000-8000-00000000000d',
  grant2: '00000000-0000-4000-8000-00000000000e',
  lease1: '00000000-0000-4000-8000-00000000000f',
  lease2: '00000000-0000-4000-8000-000000000010',
  runner: '00000000-0000-4000-8000-000000000011',
  credential: '00000000-0000-4000-8000-000000000012'
} as const

const digest = (character: string): string => character.repeat(64)

function makeWire(path = '/root'): MaterializedWireRequest {
  return Object.freeze({
    method: 'GET',
    url: 'http://127.0.0.1:3100' + path,
    headers: Object.freeze([
      Object.freeze({ name: 'accept', value: 'text/plain' }),
      Object.freeze({ name: 'user-agent', value: 'AgentGo-Day5-Test' })
    ])
  })
}

function makeCompiled(
  provider: EphemeralRequestHashKeyProvider,
  wire: MaterializedWireRequest = makeWire(),
  enabledCapabilityIds: readonly string[] = ['http.reviewed-read'],
  executionBinding: Readonly<{
    stepId: string
    purpose: 'primary' | 'read' | 'cleanup'
    adapterKind: 'http' | 'browser-offline'
  }> = {
    stepId: 'step.root',
    purpose: 'read',
    adapterKind: 'http'
  },
  credentialRef: ExecutionCredentialRef | null = null
): CompiledProbeRequest {
  const templateIntentHash = {
    domain: 'agentgo.template-intent.v1' as const,
    algorithm: 'sha256' as const,
    digest: digest('a')
  }
  const resolvedIntentHash = {
    domain: 'agentgo.resolved-intent.v1' as const,
    algorithm: 'sha256' as const,
    commitmentKeyRef: provider.reference.keyRef,
    commitmentKeyVersion: provider.reference.keyVersion,
    digest: digest('b')
  }
  const authorizationContext = createWireRequestAuthorizationContext({
    templateIntentHash,
    enabledCapabilityIds,
    ownerRef: ids.target,
    scopeSnapshotId: ids.scope,
    identityRef: {
      id: ids.identity,
      version: NOW_MS,
      ownerRef: ids.target,
      scopeSnapshotId: ids.scope,
      statusSummary: 'active'
    },
    ...(credentialRef
      ? { credentialRef }
      : {}),
    sessionRef: {
      id: ids.session,
      generation: 1,
      ownerRef: ids.target,
      scopeSnapshotId: ids.scope,
      statusSummary: 'active'
    },
    testObjectRef: {
      id: ids.testObject,
      version: 1,
      ownerRef: ids.target,
      scopeSnapshotId: ids.scope,
      statusSummary: 'ready'
    },
    executionBinding
  })
  const wireRequestHmac = computeWireRequestHmac(
    {
      hashKey: provider.reference,
      resolvedIntentHash,
      authorizationContext,
      request: wire
    },
    provider
  )
  return Object.freeze({
    request: new CompiledWireRequest(wire),
    templateIntentHash,
    resolvedIntentHash,
    authorizationContext,
    enabledCapabilityIds: Object.freeze([...enabledCapabilityIds]),
    wireRequestHmac
  })
}

function exactWireBytes(wire: MaterializedWireRequest): number {
  return (
    Buffer.byteLength(wire.method, 'utf8') +
    Buffer.byteLength(wire.url, 'utf8') +
    wire.headers.reduce(
      (total, header) =>
        total +
        Buffer.byteLength(header.name, 'ascii') +
        Buffer.byteLength(header.value, 'ascii') +
        4,
      0
    ) +
    (wire.bodyBytes?.length ?? 0)
  )
}

function captureDecisionValues(
  set: ExecutionEvidenceCaptureDecisionSet
) {
  return Object.values(set).flatMap((stateMap) => Object.values(stateMap))
}

function makeSnapshot(
  overrides: Partial<ScanModuleSnapshotRecord> = {}
): ScanModuleSnapshotRecord {
  return ScanModuleSnapshotRecordSchema.parse({
    id: ids.module,
    scanId: ids.scan,
    familyId: 'sqli',
    moduleId: 'module.sqli',
    moduleVersion: '1.0.0',
    definitionHash: digest('1'),
    techniqueId: 'sqli.boolean',
    techniqueVersion: '1.0.0',
    strategyRefs: [{ id: 'sqli.strategy', version: '1.0.0' }],
    confirmationRuleRefs: [{ id: 'sqli.confirm', version: '1.0.0' }],
    evidenceProfileRefs: [{ id: 'sqli.evidence', version: '1.0.0' }],
    remediationRefs: [{ id: 'sqli.remediation', version: '1.0.0' }],
    requiredCapabilityIds: ['http.reviewed-read'],
    capabilityDescriptors: [
      {
        id: 'http.reviewed-read',
        riskFloor: 'l1',
        descriptorHash: digest('2')
      }
    ],
    capabilitySnapshotHash: digest('3'),
    selectedCapabilitiesHash: digest('4'),
    selectedDefinitionsHash: digest('5'),
    registrySnapshotHash: digest('6'),
    environment: 'legacy-unknown',
    authorization: 'legacy-v1-compatibility',
    snapshotHash: digest('7'),
    createdAt: NOW,
    ...overrides
  })
}

function makeContext(
  decisionId: string,
  proposalId: string,
  compiled: CompiledProbeRequest,
  adapterKind: 'http' | 'browser-offline' = 'http'
) {
  return {
    decision: {
      id: decisionId,
      proposalId,
      scopeSnapshotId: ids.scope,
      allowed: true,
      requiresApproval: false,
      code: 'allowed' as const,
      reasons: [],
      validUntil: '2099-01-01T00:00:00.000Z',
      authorizedWireRequestHmac: compiled.wireRequestHmac,
      createdAt: NOW
    },
    proposal: {
      id: proposalId,
      scanId: ids.scan,
      agentRunId: ids.runner,
      action: {
        id: proposalId,
        kind:
          adapterKind === 'http'
            ? ('http-request' as const)
            : ('browser-action' as const),
        targetUrl: compiled.request.url,
        method: adapterKind === 'http' ? compiled.request.method : 'GET',
        identityId: ids.identity,
        scopeSnapshotId: ids.scope,
        probeLevel: 'active-safe' as const,
        sideEffect: 'none' as const,
        summary: 'read-only test request',
        expectedEvidence: 'response summary',
        maxRequests: 1,
        timeoutMs: 5_000,
        userApproved: false
      },
      stopConditions: [],
      createdAt: NOW
    },
    scope: {
      id: ids.scope,
      targetId: ids.target,
      revision: 1,
      snapshotHash: digest('8'),
      createdAt: NOW,
      allowedOrigins: [
        'http://127.0.0.1:3100',
        'http://localhost:3100'
      ],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [3100],
      allowedIdentityIds: [ids.identity],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: true,
      allowLoopbackTargets: true,
      maxRequestsPerMinute: 20,
      maxConcurrency: 1,
      validFrom: '2020-01-01T00:00:00.000Z',
      validUntil: '2099-01-01T00:00:00.000Z'
    },
    scanStatus: 'running' as const,
    scanBudget: {
      maxRequests: 10,
      maxRequestsPerMinute: 20,
      maxConcurrency: 1,
      maxPlanRevisions: 2,
      maxDurationMinutes: 30,
      maxModelTokens: 10_000,
      maxEstimatedCost: 10
    },
    requestCount: 0,
    scanId: ids.scan,
    targetId: ids.target,
    workspaceId: ids.workspace
  }
}

function completedLease(lease: ExecutionLease): ExecutionLease {
  return ExecutionLeaseSchema.parse({
    ...lease,
    state: 'completed',
    claimedAt: '2026-07-24T00:00:01.000Z',
    claimedBy: ids.runner,
    claimTokenHash: digest('f'),
    deliveryState: 'completed',
    terminalAt: '2026-07-24T00:00:02.000Z',
    terminalReason: 'completed',
    outcomeSummary: {
      executionState: 'succeeded',
      deliveryState: 'completed',
      verdictImpact: 'none',
      wireRequestHmacDigest: digest('e'),
      requestBytes: 1,
      responseBytes: 1
    }
  })
}

function createFixture(
  credentialRef: ExecutionCredentialRef | null = null
) {
  const provider = new EphemeralRequestHashKeyProvider()
  const compiled = makeCompiled(
    provider,
    makeWire(),
    ['http.reviewed-read'],
    undefined,
    credentialRef
  )
  const planJson = {
    version: '2026-07-10',
    phases: [{ id: 'active-validation', steps: [{ id: 'step.root' }] }]
  }
  const scan = {
    id: ids.scan,
    targetId: ids.target,
    name: 'Day 5 test scan',
    scopeSnapshotId: ids.scope,
    status: 'running',
    phase: 'active-validation',
    progress: 50,
    budgetJson: {
      maxRequests: 10,
      maxRequestsPerMinute: 20,
      maxConcurrency: 1,
      maxPlanRevisions: 2,
      maxDurationMinutes: 30,
      maxModelTokens: 10_000,
      maxEstimatedCost: 10
    },
    configJson: {
      description: 'Day 5 authority fixture',
      families: ['sqli'],
      identityIds: [ids.identity],
      modelProfileIds: {}
    },
    planJson,
    runtimeJson: {},
    requestCount: 0,
    modelTokens: 0,
    estimatedCostMicros: 0,
    checkpointCount: 0,
    lastError: null,
    moduleSnapshotsSealed: true,
    createdAt: NOW_MS,
    updatedAt: NOW_MS,
    startedAt: NOW_MS,
    completedAt: null
  }
  const snapshots = [makeSnapshot()]
  const contexts = new Map<string, ReturnType<typeof makeContext>>([
    [ids.decision1, makeContext(ids.decision1, ids.proposal1, compiled)]
  ])
  const grants = new Map<string, ExecutionGrant>()
  const leases = new Map<string, ExecutionLease>()
  const keyObservations: {
    last?: Uint8Array
    nonzeroDuringIssue: boolean
  } = { nonzeroDuringIssue: false }
  let issueIndex = 0
  const grantIds = [ids.grant1, ids.grant2] as const
  const leaseIds = [ids.lease1, ids.lease2] as const
  const methods = {
    getScanRow: vi.fn(async (scanId: string) =>
      scanId === scan.id ? scan : undefined
    ),
    listScanModuleSnapshots: vi.fn(async (scanId: string) =>
      scanId === scan.id ? snapshots : []
    ),
    getExecutionDecision: vi.fn(async (decisionId: string) =>
      contexts.get(decisionId)
    ),
    getIdentity: vi.fn(async (identityId: string) =>
      identityId === ids.identity
        ? {
            id: ids.identity,
            targetId: ids.target,
            label: 'test identity',
            role: 'owner',
            authType: credentialRef ? 'cookie' : 'none',
            credentialId: credentialRef?.id,
            isTestIdentity: true,
            ownedResourceIds: [],
            createdAt: NOW,
            updatedAt: NOW
          }
        : undefined
    ),
    getExecutionGrant: vi.fn(async (grantId: string) => grants.get(grantId)),
    getExecutionLease: vi.fn(async (leaseId: string) => leases.get(leaseId)),
    issueExecutionGrant: vi.fn(async (input: IssueExecutionGrantInput) => {
      const current = issueIndex
      const grantId = grantIds[current]
      const leaseId = leaseIds[current]
      if (!grantId || !leaseId) throw new Error('Unexpected extra issuance.')
      keyObservations.last = input.integrityKey.keyMaterial
      keyObservations.nonzeroDuringIssue = input.integrityKey.keyMaterial.some(
        (byte) => byte !== 0
      )
      const integrityBinding = ExecutionGrantIntegrityBindingSchema.parse({
        ...input.grant,
        captureDecisionSetHash: hashExecutionCaptureDecisionSet(
          input.captureDecisionSet
        ),
        schemaVersion: 'execution-grant.v1',
        id: grantId,
        issuedAt: NOW
      })
      const grant = ExecutionGrantSchema.parse({
        ...integrityBinding,
        integrityHmac: signExecutionGrantIntegrity(
          integrityBinding,
          input.integrityKey
        )
      })
      const lease = ExecutionLeaseSchema.parse({
        schemaVersion: 'execution-lease.v1',
        id: leaseId,
        grantId,
        ...(input.parentLeaseId
          ? { parentLeaseId: input.parentLeaseId }
          : {}),
        attempt: 1,
        state: 'issued',
        issuedAt: NOW,
        expiresAt: input.leaseExpiresAt,
        deliveryState: 'not-dispatched',
        evidenceRefs: []
      })
      issueIndex += 1
      grants.set(grant.id, grant)
      leases.set(lease.id, lease)
      return Object.freeze({ grant, lease })
    })
  }
  const repository = methods as unknown as AgentGoRepository
  const authority = new ExecutionAuthority(repository, provider, () => NOW_MS)
  const identityRef = {
    id: ids.identity,
    version: NOW_MS,
    ownerRef: ids.target,
    scopeSnapshotId: ids.scope,
    statusSummary: 'active' as const
  }
  const rootInput = {
    scanId: ids.scan,
    familyId: 'sqli' as const,
    policyDecisionId: ids.decision1,
    stepId: 'step.root',
    compiled,
    capabilityIds: ['http.reviewed-read'] as const,
    ownerRef: ids.target,
    identityRef,
    credentialRef,
    sessionRef: {
      id: ids.session,
      generation: 1,
      ownerRef: ids.target,
      scopeSnapshotId: ids.scope,
      statusSummary: 'active' as const
    },
    testObjectRef: {
      id: ids.testObject,
      version: 1,
      ownerRef: ids.target,
      scopeSnapshotId: ids.scope,
      statusSummary: 'ready' as const
    },
    purpose: 'read' as const,
    adapterKind: 'http' as const,
    retryClass: 'deterministic-readonly' as const,
    limits: {
      timeoutMs: 5_000,
      maxResponseBytes: 4_096,
      maxRedirects: 2
    },
    grantValidUntil: '2026-07-24T00:05:00.000Z',
    leaseExpiresAt: '2026-07-24T00:04:00.000Z'
  }
  return {
    provider,
    authority,
    compiled,
    scan,
    planJson,
    snapshots,
    contexts,
    grants,
    leases,
    keyObservations,
    methods,
    rootInput
  }
}

describe('ExecutionAuthority Day 5 issuance boundary', () => {
  it('rejects an integrity key whose overridden length hides a one-byte backing store', async () => {
    const fixture = createFixture()
    class ForgedKey extends Uint8Array {
      override get byteLength(): number {
        return 32
      }

      override fill(): this {
        return this
      }

      override [Symbol.iterator](): ArrayIterator<number> {
        return new Uint8Array(40).fill(7).values()
      }
    }
    let resolveCount = 0
    const maliciousProvider = {
      reference: fixture.provider.reference,
      resolveKey: (
        input: Parameters<EphemeralRequestHashKeyProvider['resolveKey']>[0]
      ) => {
        resolveCount += 1
        return resolveCount === 1
          ? fixture.provider.resolveKey(input)
          : new ForgedKey(1)
      }
    } as unknown as EphemeralRequestHashKeyProvider
    const authority = new ExecutionAuthority(
      fixture.methods as unknown as AgentGoRepository,
      maliciousProvider,
      () => NOW_MS
    )

    await expect(authority.issue(fixture.rootInput)).rejects.toThrow(
      'Execution grant integrity key is invalid.'
    )
    expect(fixture.methods.issueExecutionGrant).not.toHaveBeenCalled()
    expect(resolveCount).toBe(2)
    fixture.provider.dispose()
  })

  it('binds the exact plan, module, proofs, refs, budgets and wipes its signing-key copy', async () => {
    const fixture = createFixture()
    const issued = await fixture.authority.issue(fixture.rootInput)
    const wire = fixture.compiled.request.materialize()

    expect(issued.grant).toMatchObject({
      scanId: ids.scan,
      scopeSnapshotId: ids.scope,
      scopeSnapshotHash: digest('8'),
      moduleSnapshotId: ids.module,
      moduleSnapshotHash: digest('7'),
      moduleId: 'module.sqli',
      moduleVersion: '1.0.0',
      techniqueId: 'sqli.boolean',
      techniqueVersion: '1.0.0',
      planId: ids.scan,
      planVersion: '2026-07-10',
      planHash: sha256Text(canonicalJson(fixture.planJson)),
      stepId: 'step.root',
      templateIntentHash: fixture.compiled.templateIntentHash,
      resolvedIntentHash: fixture.compiled.resolvedIntentHash,
      wireRequestHmac: fixture.compiled.wireRequestHmac,
      capabilityIds: ['http.reviewed-read'],
      ownerRef: ids.target,
      identityRef: fixture.rootInput.identityRef,
      credentialRef: null,
      sessionRef: fixture.rootInput.sessionRef,
      testObjectRef: fixture.rootInput.testObjectRef,
      purpose: 'read',
      adapterKind: 'http',
      retryClass: 'deterministic-readonly',
      policyDecisionId: ids.decision1,
      redirectHop: 0,
      validFrom: NOW,
      validUntil: fixture.rootInput.grantValidUntil
    })
    expect(issued.grant.budget).toEqual({
      requestUnits: 1,
      requestBytes: exactWireBytes(wire),
      timeoutMs: 5_000,
      maxResponseBytes: 4_096,
      maxRedirects: 2
    })
    expect(issued.lease.expiresAt).toBe(fixture.rootInput.leaseExpiresAt)
    expect(Object.keys(issued.evidenceCaptureDecisions).sort()).toEqual([
      'execution-interruption-summary',
      'http-request-summary',
      'http-response-summary'
    ])
    const stateNames = ['cancelled', 'failed', 'succeeded', 'timed-out']
    for (const [source, stateMap] of Object.entries(
      issued.evidenceCaptureDecisions
    )) {
      expect(Object.keys(stateMap).sort()).toEqual(
        source === 'execution-interruption-summary'
          ? ['interrupted']
          : stateNames
      )
      expect(Object.isFrozen(stateMap)).toBe(true)
    }
    const captureDecisions = captureDecisionValues(
      issued.evidenceCaptureDecisions
    )
    expect(captureDecisions).toHaveLength(9)
    expect(new Set(captureDecisions.map((decision) => decision.id)).size).toBe(9)
    for (const decision of captureDecisions) {
      expect(EvidenceCaptureDecisionSchema.safeParse(decision).success).toBe(true)
      expect(decision).toMatchObject({
        scanId: ids.scan,
        policyDecisionId: ids.decision1,
        capturePolicyId: 'evidence-summary-v1',
        capturePolicyVersion: '1.0.0',
        techniqueId: 'sqli.boolean',
        techniqueVersion: '1.0.0',
        stepId: 'step.root',
        action: 'hash-only',
        validFrom: NOW,
        validUntil: fixture.rootInput.grantValidUntil,
        maxSourceBytes: 65_536,
        maxExcerptBytes: 32,
        jsonPointers: [],
        oobMetadataFields: []
      })
      expect(decision.role).toBe(
        decision.source === 'http-request-summary'
          ? 'request-summary'
          : decision.source === 'http-response-summary'
            ? 'response-summary'
            : 'interruption-summary'
      )
      expect(Object.isFrozen(decision)).toBe(true)
      expect(Object.isFrozen(decision.jsonPointers)).toBe(true)
      expect(Object.isFrozen(decision.oobMetadataFields)).toBe(true)
    }
    expect(Object.isFrozen(issued.evidenceCaptureDecisions)).toBe(true)
    expect(fixture.methods.issueExecutionGrant).toHaveBeenCalledOnce()
    expect(
      fixture.methods.issueExecutionGrant.mock.calls[0]?.[0]
    ).not.toHaveProperty('evidenceCaptureDecisions')
    expect(fixture.keyObservations.nonzeroDuringIssue).toBe(true)
    expect([...fixture.keyObservations.last!]).toEqual(new Array(32).fill(0))
    const providerCopy = fixture.provider.resolveKey(fixture.provider.reference)
    expect(providerCopy.some((byte) => byte !== 0)).toBe(true)
    providerCopy.fill(0)
    fixture.provider.dispose()
  })

  it('pre-issues the browser request and result state matrix before persistence', async () => {
    const fixture = createFixture()
    const browserWire = Object.freeze({
      method: 'BROWSER-OFFLINE',
      url: 'http://127.0.0.1:3100/browser',
      headers: Object.freeze([
        Object.freeze({
          name: 'x-agentgo-browser-action',
          value: 'render-offline'
        })
      ]),
      bodyBytes: Object.freeze([...Buffer.from('<main>safe</main>', 'utf8')])
    })
    const browserCompiled = makeCompiled(
      fixture.provider,
      browserWire,
      ['browser.offline-replay'],
      {
        stepId: 'step.root',
        purpose: 'read',
        adapterKind: 'browser-offline'
      }
    )
    fixture.scan.configJson.families = ['xss']
    fixture.snapshots.splice(
      0,
      1,
      makeSnapshot({
        familyId: 'xss',
        moduleId: 'module.xss',
        techniqueId: 'xss.reflected',
        requiredCapabilityIds: [
          'browser.offline-replay',
          'http.reviewed-read'
        ],
        capabilityDescriptors: [
          {
            id: 'browser.offline-replay',
            riskFloor: 'l1',
            descriptorHash: digest('2')
          },
          {
            id: 'http.reviewed-read',
            riskFloor: 'l1',
            descriptorHash: digest('3')
          }
        ]
      })
    )
    fixture.contexts.set(
      ids.decision1,
      makeContext(
        ids.decision1,
        ids.proposal1,
        browserCompiled,
        'browser-offline'
      )
    )

    const issued = await fixture.authority.issue({
      ...fixture.rootInput,
      adapterKind: 'browser-offline',
      familyId: 'xss',
      capabilityIds: ['browser.offline-replay'],
      compiled: browserCompiled
    })

    expect(Object.keys(issued.evidenceCaptureDecisions).sort()).toEqual([
      'browser-request-summary',
      'browser-result-summary',
      'execution-interruption-summary'
    ])
    for (const decision of captureDecisionValues(
      issued.evidenceCaptureDecisions
    )) {
      expect(decision.role).toBe(
        decision.source === 'browser-request-summary'
          ? 'request-summary'
          : decision.source === 'browser-result-summary'
            ? 'result-summary'
            : 'interruption-summary'
      )
      expect(decision.action).toBe('hash-only')
      expect(decision.maxSourceBytes).toBe(65_536)
      expect(decision.maxExcerptBytes).toBe(32)
    }
    expect(fixture.methods.issueExecutionGrant).toHaveBeenCalledOnce()
    fixture.provider.dispose()
  })

  it('rejects unsealed, ambiguous, unauthorized and tampered root issuance before persistence', async () => {
    const unsealed = createFixture()
    unsealed.scan.moduleSnapshotsSealed = false
    await expect(unsealed.authority.issue(unsealed.rootInput)).rejects.toThrow(
      'policy or scan binding'
    )
    expect(unsealed.methods.issueExecutionGrant).not.toHaveBeenCalled()
    unsealed.provider.dispose()

    const ambiguous = createFixture()
    ambiguous.snapshots.push(
      makeSnapshot({
        id: '00000000-0000-4000-8000-000000000012',
        snapshotHash: digest('9')
      })
    )
    await expect(ambiguous.authority.issue(ambiguous.rootInput)).rejects.toThrow(
      'exactly one'
    )
    expect(ambiguous.methods.issueExecutionGrant).not.toHaveBeenCalled()
    ambiguous.provider.dispose()

    const missingCapability = createFixture()
    await expect(
      missingCapability.authority.issue({
        ...missingCapability.rootInput,
        capabilityIds: ['http.unavailable']
      })
    ).rejects.toThrow('mandatory capability')
    expect(
      missingCapability.methods.issueExecutionGrant
    ).not.toHaveBeenCalled()
    missingCapability.provider.dispose()

    const tampered = createFixture()
    await expect(
      tampered.authority.issue({
        ...tampered.rootInput,
        compiled: {
          ...tampered.compiled,
          wireRequestHmac: {
            ...tampered.compiled.wireRequestHmac,
            digest: digest('0')
          }
        }
      })
    ).rejects.toThrow('proof verification')
    expect(tampered.methods.issueExecutionGrant).not.toHaveBeenCalled()
    tampered.provider.dispose()

    const contextTampering = createFixture()
    const baseContext = contextTampering.compiled.authorizationContext
    const compiledVariants: CompiledProbeRequest[] = [
      {
        ...contextTampering.compiled,
        enabledCapabilityIds: ['http.other']
      },
      {
        ...contextTampering.compiled,
        authorizationContext: {
          ...baseContext,
          enabledCapabilityIds: ['http.other']
        }
      },
      {
        ...contextTampering.compiled,
        authorizationContext: {
          ...baseContext,
          ownerRef: ids.workspace,
          identityRef: {
            ...baseContext.identityRef!,
            ownerRef: ids.workspace
          },
          sessionRef: {
            ...baseContext.sessionRef!,
            ownerRef: ids.workspace
          },
          testObjectRef: {
            ...baseContext.testObjectRef!,
            ownerRef: ids.workspace
          }
        }
      },
      {
        ...contextTampering.compiled,
        authorizationContext: {
          ...baseContext,
          identityRef: {
            ...baseContext.identityRef!,
            version: baseContext.identityRef!.version + 1
          }
        }
      },
      {
        ...contextTampering.compiled,
        authorizationContext: {
          ...baseContext,
          executionBinding: {
            ...baseContext.executionBinding!,
            stepId: 'step.tampered'
          }
        }
      }
    ]
    for (const compiled of compiledVariants) {
      await expect(
        contextTampering.authority.issue({
          ...contextTampering.rootInput,
          compiled
        })
      ).rejects.toThrow('authorization context')
    }
    expect(
      contextTampering.methods.issueExecutionGrant
    ).not.toHaveBeenCalled()
    contextTampering.provider.dispose()
    const wrongOwner = createFixture()
    await expect(
      wrongOwner.authority.issue({
        ...wrongOwner.rootInput,
        ownerRef: ids.workspace
      })
    ).rejects.toThrow('owner')
    expect(wrongOwner.methods.issueExecutionGrant).not.toHaveBeenCalled()
    wrongOwner.provider.dispose()
  })

  it('fails closed on request-byte, redirect and validity upper bounds', async () => {
    const oversized = createFixture()
    expect(() =>
      makeCompiled(
        oversized.provider,
        makeWire('/' + 'x'.repeat(1_146_880))
      )
    ).toThrow()
    expect(oversized.methods.issueExecutionGrant).not.toHaveBeenCalled()
    oversized.provider.dispose()

    const redirectLimit = createFixture()
    await expect(
      redirectLimit.authority.issue({
        ...redirectLimit.rootInput,
        limits: { ...redirectLimit.rootInput.limits, maxRedirects: 11 }
      })
    ).rejects.toThrow()
    expect(redirectLimit.methods.issueExecutionGrant).not.toHaveBeenCalled()
    redirectLimit.provider.dispose()

    const validity = createFixture()
    await expect(
      validity.authority.issue({
        ...validity.rootInput,
        grantValidUntil: '2100-01-01T00:00:00.000Z'
      })
    ).rejects.toThrow('policy or scan binding')
    expect(validity.methods.issueExecutionGrant).not.toHaveBeenCalled()
    validity.provider.dispose()
  })

  it('issues a redirect child with immutable parent context and a fresh exact proof', async () => {
    const fixture = createFixture()
    const parent = await fixture.authority.issue(fixture.rootInput)
    fixture.leases.set(parent.lease.id, completedLease(parent.lease))
    const childCompiled = makeCompiled(fixture.provider, makeWire('/next'))
    fixture.contexts.set(
      ids.decision2,
      makeContext(ids.decision2, ids.proposal2, childCompiled)
    )

    await expect(
      fixture.authority.issueRedirectChild({
        parentGrantId: parent.grant.id,
        parentLeaseId: parent.lease.id,
        policyDecisionId: ids.decision2,
        stepId: 'step.redirect',
        compiled: childCompiled,
        credentialRef: null,
        limits: fixture.rootInput.limits,
        grantValidUntil: fixture.rootInput.grantValidUntil,
        leaseExpiresAt: '2026-07-24T00:04:30.000Z'
      })
    ).rejects.toThrow('preserve its parent execution step')
    expect(fixture.methods.issueExecutionGrant).toHaveBeenCalledOnce()

    const child = await fixture.authority.issueRedirectChild({
      parentGrantId: parent.grant.id,
      parentLeaseId: parent.lease.id,
      policyDecisionId: ids.decision2,
      stepId: 'step.root',
      compiled: childCompiled,
      credentialRef: null,
      limits: fixture.rootInput.limits,
      grantValidUntil: fixture.rootInput.grantValidUntil,
      leaseExpiresAt: '2026-07-24T00:04:30.000Z'
    })

    expect(child.grant).toMatchObject({
      scanId: parent.grant.scanId,
      scopeSnapshotId: parent.grant.scopeSnapshotId,
      scopeSnapshotHash: parent.grant.scopeSnapshotHash,
      moduleSnapshotId: parent.grant.moduleSnapshotId,
      moduleSnapshotHash: parent.grant.moduleSnapshotHash,
      moduleId: parent.grant.moduleId,
      moduleVersion: parent.grant.moduleVersion,
      techniqueId: parent.grant.techniqueId,
      techniqueVersion: parent.grant.techniqueVersion,
      planId: parent.grant.planId,
      planVersion: parent.grant.planVersion,
      planHash: parent.grant.planHash,
      capabilityIds: parent.grant.capabilityIds,
      ownerRef: parent.grant.ownerRef,
      identityRef: parent.grant.identityRef,
      credentialRef: null,
      sessionRef: parent.grant.sessionRef,
      testObjectRef: parent.grant.testObjectRef,
      purpose: parent.grant.purpose,
      adapterKind: parent.grant.adapterKind,
      retryClass: parent.grant.retryClass,
      parentGrantId: parent.grant.id,
      policyDecisionId: ids.decision2,
      stepId: 'step.root',
      templateIntentHash: childCompiled.templateIntentHash,
      resolvedIntentHash: childCompiled.resolvedIntentHash,
      wireRequestHmac: childCompiled.wireRequestHmac,
      redirectHop: 1
    })
    expect(child.lease.parentLeaseId).toBe(parent.lease.id)
    const parentCaptureIds = new Set(
      captureDecisionValues(parent.evidenceCaptureDecisions).map(
        (decision) => decision.id
      )
    )
    const childCaptureDecisions = captureDecisionValues(
      child.evidenceCaptureDecisions
    )
    expect(childCaptureDecisions).toHaveLength(9)
    for (const decision of childCaptureDecisions) {
      expect(decision).toMatchObject({
        scanId: parent.grant.scanId,
        policyDecisionId: ids.decision2,
        techniqueId: parent.grant.techniqueId,
        techniqueVersion: parent.grant.techniqueVersion,
        stepId: 'step.root',
        action: 'hash-only',
        validFrom: NOW,
        validUntil: fixture.rootInput.grantValidUntil,
        maxSourceBytes: 65_536,
        maxExcerptBytes: 32
      })
      expect(parentCaptureIds.has(decision.id)).toBe(false)
    }
    expect(fixture.methods.issueExecutionGrant).toHaveBeenCalledTimes(2)
    expect([...fixture.keyObservations.last!]).toEqual(new Array(32).fill(0))
    fixture.provider.dispose()
  })

  it('permits credential downgrade only when the trusted redirect origin changes', async () => {
    const credentialRef = {
      id: ids.credential,
      kind: 'identity' as const,
      generation: 7
    }
    const fixture = createFixture(credentialRef)
    const parent = await fixture.authority.issue(fixture.rootInput)
    fixture.leases.set(parent.lease.id, completedLease(parent.lease))

    const sameOriginCompiled = makeCompiled(
      fixture.provider,
      makeWire('/same-origin')
    )
    fixture.contexts.set(
      ids.decision2,
      makeContext(ids.decision2, ids.proposal2, sameOriginCompiled)
    )
    await expect(
      fixture.authority.issueRedirectChild({
        parentGrantId: parent.grant.id,
        parentLeaseId: parent.lease.id,
        policyDecisionId: ids.decision2,
        stepId: 'step.root',
        compiled: sameOriginCompiled,
        credentialRef: null,
        limits: fixture.rootInput.limits,
        grantValidUntil: fixture.rootInput.grantValidUntil,
        leaseExpiresAt: '2026-07-24T00:04:30.000Z'
      })
    ).rejects.toThrow('Same-origin')

    const crossOriginWire = Object.freeze({
      ...makeWire('/cross-origin'),
      url: 'http://localhost:3100/cross-origin'
    })
    const crossOriginCompiled = makeCompiled(
      fixture.provider,
      crossOriginWire
    )
    fixture.contexts.set(
      ids.decision2,
      makeContext(ids.decision2, ids.proposal2, crossOriginCompiled)
    )
    const child = await fixture.authority.issueRedirectChild({
      parentGrantId: parent.grant.id,
      parentLeaseId: parent.lease.id,
      policyDecisionId: ids.decision2,
      stepId: 'step.root',
      compiled: crossOriginCompiled,
      credentialRef: null,
      limits: fixture.rootInput.limits,
      grantValidUntil: fixture.rootInput.grantValidUntil,
      leaseExpiresAt: '2026-07-24T00:04:30.000Z'
    })

    expect(parent.grant.credentialRef).toEqual(credentialRef)
    expect(child.grant.credentialRef).toBeNull()
    fixture.provider.dispose()
  })

  it('rejects incomplete parents and every relaxed redirect limit', async () => {
    const incomplete = createFixture()
    const parent = await incomplete.authority.issue(incomplete.rootInput)
    const childCompiled = makeCompiled(incomplete.provider, makeWire('/next'))
    await expect(
      incomplete.authority.issueRedirectChild({
        parentGrantId: parent.grant.id,
        parentLeaseId: parent.lease.id,
        policyDecisionId: ids.decision2,
        stepId: 'step.root',
        compiled: childCompiled,
        credentialRef: null,
        limits: incomplete.rootInput.limits,
        grantValidUntil: incomplete.rootInput.grantValidUntil,
        leaseExpiresAt: '2026-07-24T00:04:30.000Z'
      })
    ).rejects.toThrow('completed parent')
    expect(incomplete.methods.issueExecutionGrant).toHaveBeenCalledOnce()
    incomplete.provider.dispose()

    const relaxed = createFixture()
    const relaxedParent = await relaxed.authority.issue(relaxed.rootInput)
    relaxed.leases.set(
      relaxedParent.lease.id,
      completedLease(relaxedParent.lease)
    )
    const sameSizedChild = makeCompiled(relaxed.provider, makeWire('/next'))
    relaxed.contexts.set(
      ids.decision2,
      makeContext(ids.decision2, ids.proposal2, sameSizedChild)
    )
    const childBase = {
      parentGrantId: relaxedParent.grant.id,
      parentLeaseId: relaxedParent.lease.id,
      policyDecisionId: ids.decision2,
      stepId: 'step.root',
      compiled: sameSizedChild,
      credentialRef: null,
      limits: relaxed.rootInput.limits,
      grantValidUntil: relaxed.rootInput.grantValidUntil,
      leaseExpiresAt: '2026-07-24T00:04:30.000Z'
    }
    await expect(
      relaxed.authority.issueRedirectChild({
        ...childBase,
        limits: {
          ...childBase.limits,
          timeoutMs: childBase.limits.timeoutMs + 1
        }
      })
    ).rejects.toThrow('limits exceed')
    await expect(
      relaxed.authority.issueRedirectChild({
        ...childBase,
        limits: {
          ...childBase.limits,
          maxResponseBytes: childBase.limits.maxResponseBytes + 1
        }
      })
    ).rejects.toThrow('limits exceed')
    await expect(
      relaxed.authority.issueRedirectChild({
        ...childBase,
        limits: {
          ...childBase.limits,
          maxRedirects: childBase.limits.maxRedirects + 1
        }
      })
    ).rejects.toThrow('limits exceed')
    expect(relaxed.methods.issueExecutionGrant).toHaveBeenCalledOnce()
    relaxed.provider.dispose()
  })
})
