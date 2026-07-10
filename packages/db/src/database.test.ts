import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import { openAgentGoDatabase } from './database'
import { AgentGoRepository } from './repository'

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('AgentGo SQLite repository', () => {
  it('persists workspace, target, scope, identity and scan lifecycle data', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-db-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    const database = openAgentGoDatabase(filePath)
    const repository = new AgentGoRepository(database)

    await repository.initializeDefaults()
    const [workspace] = await repository.listWorkspaces()
    expect(workspace?.name).toBe('默认工作区')

    const targetBundle = await repository.createTarget({
      workspaceId: workspace!.id,
      name: '本地靶场',
      baseUrl: 'http://127.0.0.1:3000/',
      description: '固定版本测试目标',
      authorizationReference: 'lab-owner-approval-001',
      scope: {
        allowedOrigins: ['http://127.0.0.1:3000'],
        allowedPathPrefixes: ['/'],
        deniedPathPrefixes: ['/admin/destructive'],
        allowedPorts: [3000],
        allowedIdentityIds: [],
        allowActiveProbing: true,
        allowSensitiveProbing: false,
        allowPrivateNetworkTargets: true,
        allowLoopbackTargets: true,
        maxRequestsPerMinute: 30,
        maxConcurrency: 2,
        authorizationReference: 'lab-owner-approval-001'
      }
    })
    expect(targetBundle.scope.snapshotHash).toHaveLength(64)

    const identity = await repository.saveIdentity(
      {
        targetId: targetBundle.target.id,
        label: '测试用户 A',
        role: 'owner',
        authType: 'bearer',
        secret: 'not-stored-by-repository',
        isTestIdentity: true,
        ownedResourceIds: ['resource-1001']
      },
      'credential-test-a'
    )
    expect(identity.credentialId).toBe('credential-test-a')
    expect(identity.ownedResourceIds).toEqual(['resource-1001'])

    const targetWithIdentityScope = await repository.updateTarget({
      id: targetBundle.target.id,
      scope: {
        ...targetBundle.scope,
        allowedIdentityIds: [identity.id]
      }
    })

    const plan = createDefaultScanPlan()
    const scan = await repository.createScan(
      {
        targetId: targetBundle.target.id,
        name: '四类漏洞安全验证',
        description: '验证授权本地靶场的四类 V1 漏洞闭环。',
        families: ['sqli', 'xss', 'ssrf', 'idor'],
        identityIds: [identity.id],
        modelProfileIds: { planner: 'planner-profile-test' },
        budget: plan.budget
      },
      { ...plan },
      { ...createRuntimeState() }
    )
    expect(scan.status).toBe('draft')
    expect(scan.scopeSnapshotId).toBe(targetWithIdentityScope.scope?.id)
    expect(scan.description).toBe('验证授权本地靶场的四类 V1 漏洞闭环。')
    expect(scan.modelProfileIds).toEqual({ planner: 'planner-profile-test' })
    expect((await repository.listScanEvents(scan.id)).length).toBe(1)

    database.close()

    const reopened = openAgentGoDatabase(filePath)
    const reopenedRepository = new AgentGoRepository(reopened)
    expect((await reopenedRepository.listWorkspaces()).length).toBe(1)
    expect((await reopenedRepository.listTargets(workspace!.id)).length).toBe(1)
    const [reopenedScan] = await reopenedRepository.listScans({
      targetId: targetBundle.target.id
    })
    expect(reopenedScan?.description).toBe('验证授权本地靶场的四类 V1 漏洞闭环。')
    expect(reopenedScan?.modelProfileIds).toEqual({ planner: 'planner-profile-test' })
    reopened.close()
  })

  it('keeps scope snapshots immutable and reuses an identical snapshot', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const workspace = await repository.createWorkspace({ name: '研究', description: '' })
    const created = await repository.createTarget({
      workspaceId: workspace.id,
      name: 'Example Lab',
      baseUrl: 'https://lab.example.test',
      authorizationReference: 'written-authorization',
      description: '',
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
        maxRequestsPerMinute: 20,
        maxConcurrency: 1
      }
    })

    const updated = await repository.updateTarget({
      id: created.target.id,
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
        maxRequestsPerMinute: 20,
        maxConcurrency: 1
      }
    })

    expect(updated.scope?.id).toBe(created.scope.id)
    database.close()
  })

  it('indexes curated knowledge with FTS5 and family-scoped fallback', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    await repository.upsertKnowledgeEntries([
      {
        id: 'sqli-safe-validation',
        family: 'sqli',
        title: 'SQL 注入非写入式差异验证',
        content: '使用参数化查询修复 SQL 注入，并通过布尔真条件和负对照验证。',
        tags: ['sqli', 'parameterized-query'],
        applicability: ['查询参数进入数据库语句']
      },
      {
        id: 'xss-inert-marker',
        family: 'xss',
        title: 'XSS 惰性标记',
        content: '在断网隔离浏览器中确认标记是否执行。',
        tags: ['xss', 'browser'],
        applicability: ['输入进入 HTML 上下文']
      }
    ])

    expect(
      repository.searchKnowledgeEntryIds({ query: 'parameterized', families: [], limit: 10 })
    ).toEqual(['sqli-safe-validation'])
    expect(
      repository.searchKnowledgeEntryIds({ query: '注入', families: ['sqli'], limit: 10 })
    ).toEqual(['sqli-safe-validation'])
    expect(
      repository.searchKnowledgeEntryIds({ query: 'unmatched', families: ['xss'], limit: 10 })
    ).toEqual(['xss-inert-marker'])

    database.close()
  })

  it('persists MCP configuration and aggregates per-profile token usage', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const workspace = await repository.createWorkspace({ name: 'MCP', description: '' })
    const target = await repository.createTarget({
      workspaceId: workspace.id,
      name: 'Token fixture',
      baseUrl: 'https://lab.example.test',
      description: '',
      authorizationReference: 'test-authorization',
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
        maxRequestsPerMinute: 10,
        maxConcurrency: 1
      }
    })
    const profile = await repository.saveModelProfile({
      name: 'Token planner',
      agentRole: 'planner',
      provider: 'deterministic',
      model: 'rules',
      timeoutMs: 5_000,
      rpmLimit: 10,
      tpmLimit: 10_000,
      tokenBudget: 100_000,
      costBudget: 0
    })
    const plan = createDefaultScanPlan()
    const scan = await repository.createScan(
      {
        targetId: target.target.id,
        name: 'Token scan',
        description: 'Token usage persistence fixture.',
        families: ['sqli'],
        identityIds: [],
        modelProfileIds: { planner: profile.id },
        budget: plan.budget
      },
      { ...plan },
      { ...createRuntimeState() }
    )
    const run = await repository.createAgentRun({
      scanId: scan.id,
      role: 'planner',
      promptId: 'planner',
      promptVersion: '1.0.0',
      promptHash: 'hash',
      modelProfileId: profile.id
    })
    await repository.recordModelInvocation({
      agentRunId: run.id,
      profileId: profile.id,
      provider: 'deterministic',
      model: 'rules',
      promptVersion: '1.0.0',
      inputHashSource: 'input',
      outputHashSource: 'output',
      promptTokens: 12,
      completionTokens: 4,
      estimatedCost: 99,
      durationMs: 1,
      redactionStatus: 'redacted'
    })
    await repository.recordModelProfileUsage({
      profileId: profile.id,
      source: 'connection-test',
      promptTokens: 3,
      completionTokens: 1
    })
    expect(await repository.listModelProfileUsage()).toMatchObject([
      {
        profileId: profile.id,
        invocationCount: 2,
        promptTokens: 15,
        completionTokens: 5,
        totalTokens: 20
      }
    ])

    const mcp = await repository.saveMcpServer(
      {
        name: 'Local MCP',
        transport: 'stdio',
        enabled: false,
        command: 'node',
        args: ['server.mjs'],
        authType: 'none',
        environmentKeys: ['MCP_TOKEN'],
        headerNames: [],
        timeoutMs: 5_000,
        roots: ['F:\\Agentgo'],
        allowedAgentRoles: ['strategy'],
        riskLabels: ['command-execution', 'file-access']
      },
      'credential-mcp'
    )
    expect(mcp).toMatchObject({
      status: 'disabled',
      credentialId: 'credential-mcp',
      environmentKeys: ['MCP_TOKEN']
    })
    const tested = await repository.updateMcpServerTestResult(mcp.id, {
      ok: true,
      message: 'ready',
      durationMs: 10,
      serverName: 'fixture',
      serverVersion: '1.0.0',
      tools: [{ name: 'ping' }],
      resources: [],
      prompts: []
    })
    expect(tested.status).toBe('ready')
    expect(tested.tools).toEqual([{ name: 'ping' }])
    database.close()
  })
})
