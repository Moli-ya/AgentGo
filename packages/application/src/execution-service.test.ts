import { createServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import type { BrowserRunner } from '@agentgo/browser-runner'
import {
  AgentGoRepository,
  EvidenceStore,
  openAgentGoDatabase
} from '@agentgo/db'
import { UndiciHttpRunner } from '@agentgo/http-runner'
import { PolicyBroker, PolicyExecutionGuard } from './execution-policy'
import { ExecutionService } from './execution-service'

const directories: string[] = []

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('ExecutionService HTTP evidence loop', () => {
  it('executes only an approved request and persists immutable raw plus redacted evidence', async () => {
    const urlSecret = 'DAY3_SENTINEL_SECRET_must-not-leak'
    const server = createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('Authorization: Bearer response-secret\nresult=ok')
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as AddressInfo
    const baseUrl = `http://127.0.0.1:${address.port}`
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-execution-'))
    directories.push(directory)
    const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
    const repository = new AgentGoRepository(database)
    const workspace = await repository.createWorkspace({ name: 'Execution', description: '' })
    const target = await repository.createTarget({
      workspaceId: workspace.id,
      name: 'Local HTTP fixture',
      baseUrl,
      description: '',
      authorizationReference: 'test-owner',
      scope: {
        allowedOrigins: [baseUrl],
        allowedPathPrefixes: ['/'],
        deniedPathPrefixes: [],
        allowedPorts: [address.port],
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
        name: 'Execution scan',
        description: 'ExecutionService 授权测试夹具。',
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
      { phase: 'validation', status: 'running' }
    )
    await repository.updateScan(scan.id, {
      status: 'running',
      phase: 'validation',
      startedAt: Date.now()
    })
    const agentRun = await repository.createAgentRun({
      scanId: scan.id,
      role: 'strategy',
      promptId: 'safe-http',
      promptVersion: '1.0.0',
      promptHash: 'hash',
      modelProfileId: 'deterministic'
    })
    const policy = await new PolicyBroker(repository).evaluate({
      scanId: scan.id,
      agentRunId: agentRun.id,
      action: {
        kind: 'http-request',
        targetUrl: `${baseUrl}/search?token=${urlSecret}&q=baseline`,
        method: 'GET',
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: '低影响基线请求',
        expectedEvidence: '请求和响应摘要',
        maxRequests: 1,
        timeoutMs: 2_000,
        userApproved: false
      },
      stopConditions: ['获得响应后停止']
    })
    const evidenceStore = new EvidenceStore(database, join(directory, 'artifacts'))
    const guard = new PolicyExecutionGuard(repository)
    const unusedBrowserRunner: BrowserRunner = {
      execute: async () => {
        throw new Error('not used')
      },
      cancel: async () => undefined
    }
    const service = new ExecutionService(
      repository,
      evidenceStore,
      new UndiciHttpRunner(guard),
      unusedBrowserRunner
    )
    const execution = await service.executeHttp({
      scanId: scan.id,
      policyDecisionId: policy.decision.id,
      request: {
        targetUrl: `${baseUrl}/search?token=${urlSecret}&q=baseline`,
        method: 'GET',
        headers: { Authorization: 'Bearer request-secret' },
        timeoutMs: 2_000
      }
    })

    expect(execution.result.status).toBe('succeeded')
    expect(execution.evidenceRefs.length).toBeGreaterThanOrEqual(4)
    const evidence = await evidenceStore.list(scan.id)
    const raw = evidence.find((item) => item.type === 'http-response-body')
    const redacted = evidence.find((item) => item.type === 'http-response-body-redacted')
    expect(raw).toBeDefined()
    expect(redacted?.derivedFrom).toBe(raw?.id)
    expect((await evidenceStore.read(raw!.id)).content.toString()).toContain('response-secret')
    expect((await evidenceStore.read(redacted!.id)).content.toString()).not.toContain(
      'response-secret'
    )
    const requestSummary = evidence.find(
      (item) => item.type === 'http-request-summary'
    )
    expect(requestSummary).toBeDefined()
    expect((await evidenceStore.read(requestSummary!.id)).content.toString()).not.toContain(
      urlSecret
    )
    const persistedAuditText = JSON.stringify({
      proposals: database.native.prepare('SELECT target_url FROM probe_proposals').all(),
      decisions: database.native
        .prepare('SELECT normalized_target FROM policy_decisions')
        .all(),
      interactions: database.native
        .prepare('SELECT request_summary_json, response_summary_json FROM interactions')
        .all(),
      events: database.native
        .prepare('SELECT message, detail_json FROM scan_events')
        .all(),
      tools: database.native.prepare('SELECT error FROM tool_calls').all()
    })
    expect(persistedAuditText).not.toContain(urlSecret)
    expect(persistedAuditText).not.toContain('request-secret')
    expect((await repository.getScan(scan.id))?.requestCount).toBe(1)

    await new Promise<void>((resolve) => server.close(() => resolve()))
    database.close()
  })
})
