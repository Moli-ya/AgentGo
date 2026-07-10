import { describe, expect, it } from 'vitest'
import { openAgentGoDatabase, AgentGoRepository } from '@agentgo/db'
import { PolicyBroker, PolicyExecutionGuard } from './execution-policy'

async function fixture(): Promise<{
  database: ReturnType<typeof openAgentGoDatabase>
  repository: AgentGoRepository
  scanId: string
  agentRunId: string
}> {
  const database = openAgentGoDatabase(':memory:')
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({ name: 'Policy', description: '' })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Local lab',
    baseUrl: 'http://127.0.0.1:3100',
    description: '',
    authorizationReference: 'approval',
    scope: {
      allowedOrigins: ['http://127.0.0.1:3100'],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: ['/forbidden'],
      allowedPorts: [3100],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: true,
      allowLoopbackTargets: true,
      maxRequestsPerMinute: 20,
      maxConcurrency: 1
    }
  })
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'Policy scan',
      description: 'SecurityPolicy 授权测试夹具。',
      families: ['sqli'],
      identityIds: [],
      budget: {
        maxRequests: 10,
        maxRequestsPerMinute: 20,
        maxConcurrency: 1,
        maxPlanRevisions: 1,
        maxDurationMinutes: 10,
        maxModelTokens: 1_000,
        maxEstimatedCost: 1
      }
    },
    {},
    { phase: 'intake', status: 'running' }
  )
  await repository.updateScan(scan.id, { status: 'running', startedAt: Date.now() })
  const agentRun = await repository.createAgentRun({
    scanId: scan.id,
    role: 'strategy',
    promptId: 'strategy-safe-probe',
    promptVersion: '1.0.0',
    promptHash: 'hash',
    modelProfileId: 'deterministic-strategy'
  })
  return { database, repository, scanId: scan.id, agentRunId: agentRun.id }
}

describe('PolicyBroker and execution guard', () => {
  it('persists a proposal and revalidates URL plus resolved addresses at execution time', async () => {
    const state = await fixture()
    const broker = new PolicyBroker(state.repository)
    const result = await broker.evaluate({
      scanId: state.scanId,
      agentRunId: state.agentRunId,
      action: {
        kind: 'http-request',
        targetUrl: 'http://127.0.0.1:3100/search?q=marker',
        method: 'GET',
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: '只读差异验证',
        expectedEvidence: '请求响应摘要',
        maxRequests: 1,
        timeoutMs: 5_000,
        userApproved: false
      },
      stopConditions: ['获得最小证据']
    })
    expect(result.decision.allowed).toBe(true)

    const guard = new PolicyExecutionGuard(state.repository)
    await expect(
      guard.authorize({
        policyDecisionId: result.decision.id,
        url: 'http://127.0.0.1:3100/search?q=marker',
        method: 'GET',
        addresses: [{ address: '127.0.0.1', family: 4 }]
      })
    ).resolves.toBeUndefined()
    await expect(
      guard.authorize({
        policyDecisionId: result.decision.id,
        url: 'http://127.0.0.1:3100/forbidden',
        method: 'GET',
        redirectFrom: 'http://127.0.0.1:3100/search',
        addresses: [{ address: '127.0.0.1', family: 4 }]
      })
    ).rejects.toThrow('revalidation failed')
    await expect(
      guard.authorize({
        policyDecisionId: result.decision.id,
        url: 'http://127.0.0.1:3100/search',
        method: 'GET',
        addresses: [{ address: '169.254.169.254', family: 4 }]
      })
    ).rejects.toThrow('元数据')
    state.database.close()
  })

  it('never turns a denied destructive decision into an executable token', async () => {
    const state = await fixture()
    const result = await new PolicyBroker(state.repository).evaluate({
      scanId: state.scanId,
      agentRunId: state.agentRunId,
      action: {
        kind: 'http-request',
        targetUrl: 'http://127.0.0.1:3100/query',
        method: 'POST',
        probeLevel: 'destructive',
        sideEffect: 'destructive',
        summary: 'DROP TABLE users',
        payloadSummary: 'DROP TABLE users',
        expectedEvidence: 'must not execute',
        maxRequests: 1,
        timeoutMs: 5_000,
        userApproved: true
      },
      stopConditions: []
    })
    expect(result.decision.allowed).toBe(false)
    await expect(
      new PolicyExecutionGuard(state.repository).authorize({
        policyDecisionId: result.decision.id,
        url: 'http://127.0.0.1:3100/query',
        method: 'POST',
        addresses: [{ address: '127.0.0.1', family: 4 }]
      })
    ).rejects.toThrow('does not authorize')
    state.database.close()
  })
})
