import { describe, expect, it, vi } from 'vitest'
import {
  ExecutionGrantIntegrityBindingSchema,
  ExecutionGrantSchema,
  ExecutionLeaseSchema,
  type ExecutionGrant,
  type WireRequestHmac
} from '@agentgo/contracts'
import {
  signExecutionGrantIntegrity,
  type AgentGoRepository,
  type ExecutionGrantIntegrityKey
} from '@agentgo/db'
import {
  computeWireRequestHmac,
  createWireRequestAuthorizationContext,
  type RequestHashKeyProvider
} from './request-compiler'
import {
  PolicyBroker,
  PolicyExecutionGuard,
  createBrowserOfflineExactWire
} from './execution-policy'

const ids = {
  scan: '00000000-0000-4000-8000-000000000001',
  scope: '00000000-0000-4000-8000-000000000002',
  module: '00000000-0000-4000-8000-000000000003',
  plan: '00000000-0000-4000-8000-000000000001',
  grant: '00000000-0000-4000-8000-000000000004',
  lease: '00000000-0000-4000-8000-000000000005',
  decision: '00000000-0000-4000-8000-000000000006',
  proposal: '00000000-0000-4000-8000-000000000007',
  runner: '00000000-0000-4000-8000-000000000008',
  key: '00000000-0000-4000-8000-000000000009',
  target: '00000000-0000-4000-8000-00000000000a',
  workspace: '00000000-0000-4000-8000-00000000000b',
  identity: '00000000-0000-4000-8000-00000000000c',
  credential: '00000000-0000-4000-8000-00000000000d'
} as const

const digest = (character: string): string => character.repeat(64)
const keyBytes = Uint8Array.from({ length: 32 }, (_value, index) => index + 1)

class CopyingKeyProvider implements RequestHashKeyProvider {
  resolveKey(input: { keyRef: string; keyVersion: number }): Uint8Array {
    if (input.keyRef !== ids.key || input.keyVersion !== 1) {
      throw new Error('unknown key')
    }
    return Uint8Array.from(keyBytes)
  }
}

function wireBytes(wire: {
  method: string
  url: string
  headers: readonly { name: string; value: string }[]
  bodyBytes?: readonly number[]
}): number {
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

function createFixture(options: {
  adapterKind?: 'http' | 'browser-offline'
  actionKind?: 'http-request' | 'browser-action'
  wire?: {
    readonly method: string
    readonly url: string
    readonly headers: readonly { readonly name: string; readonly value: string }[]
    readonly bodyBytes?: readonly number[]
  }
  credentialGenerations?: readonly [number, ...number[]]
} = {}) {
  const provider = new CopyingKeyProvider()
  const credentialRef = options.credentialGenerations
    ? {
        id: ids.credential,
        kind: 'identity' as const,
        generation: options.credentialGenerations[0]
      }
    : null
  const wire =
    options.wire ??
    Object.freeze({
      method: 'GET',
      url: 'http://127.0.0.1:3100/search?q=baseline',
      headers: Object.freeze([
        Object.freeze({ name: 'accept', value: 'text/plain' }),
        Object.freeze({ name: 'user-agent', value: 'AgentGo-Test' })
      ])
    })
  const resolvedIntentHash = {
    domain: 'agentgo.resolved-intent.v1' as const,
    algorithm: 'sha256' as const,
    commitmentKeyRef: ids.key,
    commitmentKeyVersion: 1,
    digest: digest('b')
  }
  const templateIntentHash = {
    domain: 'agentgo.template-intent.v1' as const,
    algorithm: 'sha256' as const,
    digest: digest('a')
  }
  const adapterKind = options.adapterKind ?? 'http'
  const capabilityIds =
    adapterKind === 'http'
      ? (['http.reviewed-read'] as const)
      : (['browser.offline-replay'] as const)
  const authorizationContext = createWireRequestAuthorizationContext({
    templateIntentHash,
    enabledCapabilityIds: capabilityIds,
    scopeSnapshotId: ids.scope,
    ...(credentialRef
      ? {
          ownerRef: ids.target,
          identityRef: {
            id: ids.identity,
            version: Date.parse('2026-01-01T00:00:00.000Z'),
            ownerRef: ids.target,
            scopeSnapshotId: ids.scope,
            statusSummary: 'active' as const
          },
          credentialRef
        }
      : {}),
    executionBinding: {
      stepId: 'step.baseline',
      purpose: 'read',
      adapterKind
    }
  })
  const wireRequestHmac = computeWireRequestHmac(
    {
      hashKey: { keyRef: ids.key, keyVersion: 1 },
      resolvedIntentHash,
      authorizationContext,
      request: wire
    },
    provider
  )
  const integrityBinding = ExecutionGrantIntegrityBindingSchema.parse({
    schemaVersion: 'execution-grant.v1',
    id: ids.grant,
    scanId: ids.scan,
    scopeSnapshotId: ids.scope,
    scopeSnapshotHash: digest('c'),
    moduleSnapshotId: ids.module,
    moduleSnapshotHash: digest('d'),
    moduleId: 'module.sqli',
    moduleVersion: '1.0.0',
    techniqueId: 'sqli.boolean',
    techniqueVersion: '1.0.0',
    planId: ids.plan,
    planVersion: '2026-07-10',
    planHash: digest('e'),
    stepId: 'step.baseline',
    templateIntentHash,
    resolvedIntentHash,
    wireRequestHmac,
    captureDecisionSetHash: {
      domain: 'agentgo.execution-capture-decision-set.v1',
      algorithm: 'sha256',
      digest: digest('f')
    },
    capabilityIds,
    ...(credentialRef
      ? {
          ownerRef: ids.target,
          identityRef: {
            id: ids.identity,
            version: Date.parse('2026-01-01T00:00:00.000Z'),
            ownerRef: ids.target,
            scopeSnapshotId: ids.scope,
            statusSummary: 'active' as const
          }
        }
      : {}),
    credentialRef,
    budget: {
      requestUnits: 1,
      requestBytes: wireBytes(wire),
      maxResponseBytes: 4_096,
      timeoutMs: 5_000,
      maxRedirects: 0
    },
    purpose: 'read',
    adapterKind,
    retryClass: 'deterministic-readonly',
    policyDecisionId: ids.decision,
    redirectHop: 0,
    validFrom: '2020-01-01T00:00:00.000Z',
    validUntil: '2099-01-01T00:00:00.000Z',
    issuedAt: '2026-01-01T00:00:00.000Z'
  })
  const integrityKey: ExecutionGrantIntegrityKey = {
    keyRef: ids.key,
    keyVersion: 1,
    keyMaterial: Uint8Array.from(keyBytes)
  }
  const grant = ExecutionGrantSchema.parse({
    ...integrityBinding,
    integrityHmac: signExecutionGrantIntegrity(
      integrityBinding,
      integrityKey
    )
  })
  integrityKey.keyMaterial.fill(0)
  const issuedLease = ExecutionLeaseSchema.parse({
    schemaVersion: 'execution-lease.v1',
    id: ids.lease,
    grantId: ids.grant,
    attempt: 1,
    state: 'issued',
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2099-01-01T00:00:00.000Z',
    deliveryState: 'not-dispatched',
    evidenceRefs: []
  })
  const scope = {
    id: ids.scope,
    targetId: ids.target,
    revision: 1,
    snapshotHash: digest('c'),
    createdAt: '2026-01-01T00:00:00.000Z',
    allowedOrigins: ['http://127.0.0.1:3100'],
    allowedPathPrefixes: ['/'],
    deniedPathPrefixes: [],
    allowedPorts: [3100],
    allowedIdentityIds: credentialRef ? [ids.identity] : [],
    allowActiveProbing: true,
    allowSensitiveProbing: false,
    allowPrivateNetworkTargets: true,
    allowLoopbackTargets: true,
    maxRequestsPerMinute: 20,
    maxConcurrency: 1
  }
  const context = {
    decision: {
      id: ids.decision,
      proposalId: ids.proposal,
      scopeSnapshotId: ids.scope,
      allowed: true,
      requiresApproval: false,
      code: 'allowed',
      reasons: [],
      validUntil: '2099-01-01T00:00:00.000Z',
      authorizedWireRequestHmac: wireRequestHmac,
      createdAt: '2026-01-01T00:00:00.000Z'
    },
    proposal: {
      id: ids.proposal,
      scanId: ids.scan,
      agentRunId: ids.runner,
      action: {
        id: ids.proposal,
        kind: options.actionKind ?? 'http-request',
        targetUrl: wire.url,
        method: options.adapterKind === 'browser-offline' ? 'GET' : wire.method,
        scopeSnapshotId: ids.scope,
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: 'read-only verification',
        expectedEvidence: 'response summary',
        ...(credentialRef ? { identityId: ids.identity } : {}),
        maxRequests: 1,
        timeoutMs: 5_000,
        userApproved: false
      },
      stopConditions: [],
      createdAt: '2026-01-01T00:00:00.000Z'
    },
    scope,
    scanStatus: 'running',
    scanBudget: {
      maxRequests: 10,
      maxRequestsPerMinute: 20,
      maxConcurrency: 1,
      maxPlanRevisions: 1,
      maxDurationMinutes: 10,
      maxModelTokens: 1_000,
      maxEstimatedCost: 1
    },
    requestCount: 0,
    scanId: ids.scan,
    targetId: ids.target,
    workspaceId: ids.workspace
  }
  let claimed = false
  const claimedLease = {
    ...issuedLease,
    state: 'claimed' as const,
    claimedAt: '2026-01-01T00:00:01.000Z',
    claimedBy: ids.runner,
    claimTokenHash: digest('f')
  }
  const methods = {
    getExecutionLease: vi.fn(async () =>
      claimed ? claimedLease : issuedLease
    ),
    getExecutionGrant: vi.fn(async () => grant),
    getExecutionDecision: vi.fn(async () => context),
    getIdentity: vi.fn(async () =>
      credentialRef
        ? {
            id: ids.identity,
            targetId: ids.target,
            label: 'test identity',
            role: 'owner',
            authType: 'bearer',
            credentialId: ids.credential,
            isTestIdentity: true,
            ownedResourceIds: [],
            createdAt: '2026-01-01T00:00:00.000Z',
            updatedAt: '2026-01-01T00:00:00.000Z'
          }
        : undefined
    ),
    getScanRow: vi.fn(async () => ({
      id: ids.scan,
      targetId: ids.target,
      configJson: { identityIds: credentialRef ? [ids.identity] : [] }
    })),
    claimExecutionLease: vi.fn(async () => {
      if (claimed) throw new Error('already claimed')
      claimed = true
      return { lease: claimedLease, claimToken: 'raw-claim-secret' }
    }),
    markExecutionLeaseDelivery: vi.fn(async () => claimedLease),
    finalizeExecutionLease: vi.fn(async (input: unknown) => ({
      ...claimedLease,
      input
    })),
    revokeExecutionLease: vi.fn(async () => issuedLease)
  }
  const repository = methods as unknown as AgentGoRepository
  let credentialListCall = 0
  const credentialMetadataAuthority = credentialRef
    ? {
        isAvailable: vi.fn(() => true),
        list: vi.fn(() => {
          const generations = options.credentialGenerations!
          const generation =
            generations[Math.min(credentialListCall, generations.length - 1)]!
          credentialListCall += 1
          return [{
            id: ids.credential,
            kind: 'identity' as const,
            label: 'test identity',
            generation,
            createdAt: '2026-01-01T00:00:00.000Z',
            updatedAt: '2026-01-01T00:00:00.000Z'
          }]
        })
      }
    : undefined
  const guard = new PolicyExecutionGuard(
    repository, provider, credentialMetadataAuthority, ids.runner
  )
  const claimInput = {
    leaseId: ids.lease,
    wire,
    limits: { timeoutMs: 5_000, maxResponseBytes: 4_096 }
  }
  return {
    provider,
    wire,
    wireRequestHmac,
    grant,
    context,
    credentialMetadataAuthority,
    methods,
    guard,
    claimInput
  }
}

function withTamperedWire(
  wire: ReturnType<typeof createFixture>['wire'],
  kind: 'method' | 'url' | 'header-order' | 'body'
) {
  switch (kind) {
    case 'method':
      return { ...wire, method: 'POST' }
    case 'url':
      return { ...wire, url: wire.url + '&tampered=1' }
    case 'header-order':
      return { ...wire, headers: [...wire.headers].reverse() }
    case 'body':
      return { ...wire, bodyBytes: [1] }
  }
}

describe('PolicyExecutionGuard Day 5 lease boundary', () => {
  it.each(['method', 'url', 'header-order', 'body'] as const)(
    'rejects %s tampering before the atomic claim',
    async (kind) => {
      const fixture = createFixture()
      await expect(
        fixture.guard.claim({
          ...fixture.claimInput,
          wire: withTamperedWire(fixture.wire, kind)
        })
      ).rejects.toThrow()
      expect(fixture.methods.claimExecutionLease).not.toHaveBeenCalled()
    }
  )

  it('rejects identity, purpose, and limit tampering before claim', async () => {
    const identityFixture = createFixture()
    identityFixture.methods.getExecutionDecision.mockResolvedValueOnce({
      ...identityFixture.context,
      proposal: {
        ...identityFixture.context.proposal,
        action: {
          ...identityFixture.context.proposal.action,
          identityId: ids.identity
        }
      }
    } as never)
    await expect(
      identityFixture.guard.claim(identityFixture.claimInput)
    ).rejects.toThrow('identity')
    expect(identityFixture.methods.claimExecutionLease).not.toHaveBeenCalled()

    const purposeFixture = createFixture()
    purposeFixture.methods.getExecutionGrant.mockResolvedValueOnce({
      ...purposeFixture.grant,
      purpose: 'cleanup',
      retryClass: 'never'
    } as unknown as ExecutionGrant)
    await expect(
      purposeFixture.guard.claim(purposeFixture.claimInput)
    ).rejects.toThrow()
    expect(purposeFixture.methods.claimExecutionLease).not.toHaveBeenCalled()

    const limitFixture = createFixture()
    await expect(
      limitFixture.guard.claim({
        ...limitFixture.claimInput,
        limits: { timeoutMs: 5_001, maxResponseBytes: 4_096 }
      })
    ).rejects.toThrow('limits')
    expect(limitFixture.methods.claimExecutionLease).not.toHaveBeenCalled()
  })

  it('claims before DNS and rejects unsafe addresses before dispatch', async () => {
    const dnsFixture = createFixture()
    const token = await dnsFixture.guard.claim(dnsFixture.claimInput)
    await expect(
      dnsFixture.guard.validateResolvedAddresses(token, [
        { address: '169.254.169.254', family: 4 }
      ])
    ).rejects.toThrow()
    expect(dnsFixture.methods.claimExecutionLease).toHaveBeenCalledOnce()
    expect(dnsFixture.methods.markExecutionLeaseDelivery).not.toHaveBeenCalled()
  })

  it('returns an opaque identity token and rejects a second lease claim', async () => {
    const fixture = createFixture()
    const token = await fixture.guard.claim(fixture.claimInput)
    expect(Object.keys(token)).toEqual([])
    expect(Reflect.ownKeys(token)).toEqual([])
    expect(JSON.stringify(token)).toBe('{}')
    expect(Object.keys(fixture.guard)).toEqual([])
    expect(JSON.stringify(fixture.guard)).toBe('{}')
    expect(JSON.stringify(fixture.guard)).not.toContain('raw-claim-secret')
    await expect(
      fixture.guard.claim(fixture.claimInput)
    ).rejects.toThrow('not claimable')
  })

  it('tracks delivery and maps terminal failure deterministically', async () => {
    const fixture = createFixture()
    const token = await fixture.guard.claim(fixture.claimInput)
    await expect(fixture.guard.markDispatched(token)).rejects.toThrow(
      'authorized resolved addresses'
    )
    await fixture.guard.validateResolvedAddresses(token, [
      { address: '127.0.0.1', family: 4 }
    ])
    await fixture.guard.markDispatched(token)
    await fixture.guard.markResponseStarted(token)
    await fixture.guard.finalizeFailed(token, {
      code: 'timeout',
      responseBytes: 17
    })
    expect(fixture.methods.markExecutionLeaseDelivery).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ deliveryState: 'possibly-sent' })
    )
    expect(fixture.methods.markExecutionLeaseDelivery).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ deliveryState: 'response-started' })
    )
    expect(fixture.methods.finalizeExecutionLease).toHaveBeenCalledWith(
      expect.objectContaining({
        state: 'failed',
        terminalReason: 'timed-out',
        deliveryState: 'response-started',
        outcomeSummary: expect.objectContaining({
          executionState: 'timed-out',
          verdictImpact: 'inconclusive'
        })
      })
    )
    await expect(fixture.guard.markDispatched(token)).rejects.toThrow('unknown')
    await expect(
      fixture.guard.markDispatched(Object.freeze({}) as never)
    ).rejects.toThrow('unknown')
  })

  it('closes a claimed lease when the credential generation rotates at the claim edge', async () => {
    const fixture = createFixture({
      credentialGenerations: [7, 8]
    })

    await expect(
      fixture.guard.claim(fixture.claimInput)
    ).rejects.toThrow('credential changed')

    expect(fixture.methods.claimExecutionLease).toHaveBeenCalledOnce()
    expect(fixture.credentialMetadataAuthority?.list).toHaveBeenCalledTimes(2)
    expect(fixture.methods.finalizeExecutionLease).toHaveBeenCalledWith(
      expect.objectContaining({
        claimToken: 'raw-claim-secret',
        state: 'failed',
        terminalReason: 'guard-rejected',
        deliveryState: 'not-dispatched',
        outcomeSummary: expect.objectContaining({
          executionState: 'failed',
          deliveryState: 'not-dispatched',
          verdictImpact: 'none',
          errorCode: 'execution.credential-generation-changed'
        })
      })
    )
  })

  it('stops before send when credential generation rotates during DNS work', async () => {
    const fixture = createFixture({
      credentialGenerations: [7, 7, 8]
    })
    const token = await fixture.guard.claim(fixture.claimInput)
    await fixture.guard.validateResolvedAddresses(token, [
      { address: '127.0.0.1', family: 4 }
    ])

    await expect(
      fixture.guard.markDispatched(token)
    ).rejects.toThrow(/credential generation/i)
    expect(fixture.methods.markExecutionLeaseDelivery).not.toHaveBeenCalled()
    expect(fixture.credentialMetadataAuthority?.list).toHaveBeenCalledTimes(3)

    await fixture.guard.finalizeFailed(token, {
      code: 'dispatch-mark-failed'
    })
    expect(fixture.methods.finalizeExecutionLease).toHaveBeenCalledWith(
      expect.objectContaining({
        state: 'failed',
        terminalReason: 'guard-rejected',
        deliveryState: 'not-dispatched',
        outcomeSummary: expect.objectContaining({
          executionState: 'failed',
          deliveryState: 'not-dispatched',
          verdictImpact: 'none',
          errorCode: 'execution.dispatch-mark-failed'
        })
      })
    )
  })

  it('fails conservatively if credential generation rotates during the durable dispatch transition', async () => {
    const fixture = createFixture({
      credentialGenerations: [7, 7, 7, 8]
    })
    const token = await fixture.guard.claim(fixture.claimInput)
    await fixture.guard.validateResolvedAddresses(token, [
      { address: '127.0.0.1', family: 4 }
    ])

    await expect(
      fixture.guard.markDispatched(token)
    ).rejects.toThrow(/credential generation/i)
    expect(fixture.methods.markExecutionLeaseDelivery).toHaveBeenCalledWith(
      expect.objectContaining({ deliveryState: 'possibly-sent' })
    )
    expect(fixture.credentialMetadataAuthority?.list).toHaveBeenCalledTimes(4)

    await fixture.guard.finalizeFailed(token, {
      code: 'dispatch-mark-failed'
    })
    expect(fixture.methods.finalizeExecutionLease).toHaveBeenCalledWith(
      expect.objectContaining({
        state: 'failed',
        terminalReason: 'guard-rejected',
        deliveryState: 'possibly-sent',
        outcomeSummary: expect.objectContaining({
          executionState: 'failed',
          deliveryState: 'possibly-sent',
          verdictImpact: 'inconclusive',
          errorCode: 'execution.dispatch-mark-failed'
        })
      })
    )
  })

  it('maps invalid runner output to a response-read failure', async () => {
    const fixture = createFixture()
    const token = await fixture.guard.claim(fixture.claimInput)

    await fixture.guard.finalizeFailed(token, {
      code: 'runner-output-invalid'
    })

    expect(fixture.methods.finalizeExecutionLease).toHaveBeenCalledWith(
      expect.objectContaining({
        terminalReason: 'response-read-failed',
        outcomeSummary: expect.objectContaining({
          errorCode: 'execution.runner-output-invalid'
        })
      })
    )
  })

  it('binds invalid runner output cleanup to the expected lease identity', async () => {
    const fixture = createFixture()
    const token = await fixture.guard.claim(fixture.claimInput)

    await fixture.guard.rejectInvalidRunnerOutput(ids.lease, token)

    expect(fixture.methods.finalizeExecutionLease).toHaveBeenCalledWith(
      expect.objectContaining({
        leaseId: ids.lease,
        terminalReason: 'response-read-failed'
      })
    )

    const unclaimedFixture = createFixture()
    await unclaimedFixture.guard.rejectInvalidRunnerOutput(
      ids.lease,
      Object.freeze({}) as never
    )
    expect(
      unclaimedFixture.methods.finalizeExecutionLease
    ).not.toHaveBeenCalled()
    expect(
      unclaimedFixture.methods.revokeExecutionLease
    ).toHaveBeenCalledExactlyOnceWith({
      leaseId: ids.lease,
      reason: 'guard-rejected'
    })

    const mismatchedFixture = createFixture()
    const mismatchedToken = await mismatchedFixture.guard.claim(
      mismatchedFixture.claimInput
    )
    const otherLeaseId = '00000000-0000-4000-8000-000000000099'
    await mismatchedFixture.guard.rejectInvalidRunnerOutput(
      otherLeaseId,
      mismatchedToken
    )
    expect(
      mismatchedFixture.methods.finalizeExecutionLease
    ).not.toHaveBeenCalled()
    expect(
      mismatchedFixture.methods.revokeExecutionLease
    ).toHaveBeenCalledExactlyOnceWith({
      leaseId: otherLeaseId,
      reason: 'guard-rejected'
    })
  })

  it('claims browser-offline synthetic wire without a DNS input', async () => {
    const offlineWire = createBrowserOfflineExactWire({
      baseUrl: 'http://127.0.0.1:3100/',
      html: '<main>offline</main>',
      action: 'inspect-dom'
    })
    const fixture = createFixture({
      adapterKind: 'browser-offline',
      actionKind: 'browser-action',
      wire: offlineWire
    })
    await expect(
      fixture.guard.claimOffline({
        leaseId: ids.lease,
        wire: offlineWire,
        limits: { timeoutMs: 5_000, maxResponseBytes: 4_096 }
      })
    ).resolves.toBeDefined()
    expect(fixture.methods.claimExecutionLease).toHaveBeenCalledTimes(1)
  })
})

describe('PolicyBroker Day 5 wire authorization', () => {
  it('passes the compiled wire proof into policy persistence', async () => {
    const fixture = createFixture()
    const recordPolicyDecision = vi.fn(async (input: {
      authorizedWireRequestHmac?: WireRequestHmac
    }) => ({
      id: ids.decision,
      proposalId: ids.proposal,
      scopeSnapshotId: ids.scope,
      allowed: true,
      requiresApproval: false,
      code: 'allowed' as const,
      reasons: [],
      authorizedWireRequestHmac: input.authorizedWireRequestHmac,
      validUntil: '2099-01-01T00:00:00.000Z',
      createdAt: '2026-01-01T00:00:00.000Z'
    }))
    const repository = {
      getScanRow: vi.fn(async () => ({ scopeSnapshotId: ids.scope })),
      getScope: vi.fn(async () => fixture.context.scope),
      createProbeProposal: vi.fn(async (input: { action: unknown }) => ({
        id: ids.proposal,
        scanId: ids.scan,
        agentRunId: ids.runner,
        action: input.action,
        stopConditions: [],
        createdAt: '2026-01-01T00:00:00.000Z'
      })),
      recordPolicyDecision,
      addScanEvent: vi.fn(async () => undefined)
    } as unknown as AgentGoRepository
    await new PolicyBroker(repository).evaluate({
      scanId: ids.scan,
      agentRunId: ids.runner,
      action: fixture.context.proposal.action as Parameters<
        PolicyBroker['evaluate']
      >[0]['action'],
      stopConditions: [],
      authorizedWireRequestHmac: fixture.wireRequestHmac
    })
    expect(recordPolicyDecision).toHaveBeenCalledWith(
      expect.objectContaining({
        authorizedWireRequestHmac: fixture.wireRequestHmac
      })
    )
  })
})
