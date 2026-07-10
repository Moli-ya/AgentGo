import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  openAgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import type { McpConnectionSecrets, McpHub } from '@agentgo/mcp-hub'
import { DefaultModelGateway, type ModelGateway } from '@agentgo/model-gateway'
import { AgentGoApplicationService, AgentPromptCatalog } from './index'

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

const protector: SecretProtector = {
  isAvailable: () => true,
  protect: (value) => Buffer.from(value, 'utf8'),
  unprotect: (value) => value.toString('utf8')
}

describe('AgentGoApplicationService recovery', () => {
  it('pauses an interrupted scan and records a checkpoint plus warning event', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-recovery-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const workspace = await repository.createWorkspace({
        name: 'Recovery test',
        description: ''
      })
      const target = await repository.createTarget({
        workspaceId: workspace.id,
        name: 'Authorized local fixture',
        baseUrl: 'http://127.0.0.1:3000/',
        description: '',
        authorizationReference: 'automated-recovery-test',
        scope: {
          allowedOrigins: ['http://127.0.0.1:3000'],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [3000],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          maxRequestsPerMinute: 30,
          maxConcurrency: 1,
          authorizationReference: 'automated-recovery-test'
        }
      })
      const plan = createDefaultScanPlan()
      const scan = await repository.createScan(
        {
          targetId: target.target.id,
          name: 'Interrupted scan',
          description: '中断恢复授权测试夹具。',
          families: ['sqli'],
          identityIds: [],
          budget: plan.budget
        },
        { ...plan },
        { ...createRuntimeState() }
      )
      await repository.updateScan(scan.id, {
        status: 'running',
        phase: 'validation',
        startedAt: Date.now(),
        runtimeJson: { ...createRuntimeState(), phase: 'validation', status: 'running' }
      })

      const application = new AgentGoApplicationService({
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        )
      })
      await application.initialize()

      const recovered = await repository.getScanRow(scan.id)
      expect(recovered?.status).toBe('paused')
      expect(recovered?.phase).toBe('validation')
      expect(recovered?.runtimeJson).toMatchObject({
        phase: 'validation',
        status: 'paused'
      })
      expect(recovered?.checkpointCount).toBe(1)

      const checkpoint = await repository.getLatestCheckpoint(scan.id)
      expect(checkpoint).toMatchObject({
        scanId: scan.id,
        phase: 'validation',
        reason: 'recovered-after-interruption',
        state: { phase: 'validation', status: 'paused' }
      })

      const recoveryEvent = (await repository.listScanEvents(scan.id)).at(-1)
      expect(recoveryEvent).toMatchObject({
        type: 'status',
        level: 'warning',
        detail: { recoveredPhase: 'validation' }
      })
      expect(recoveryEvent?.message).toContain('已安全恢复为暂停状态')
    } finally {
      database.close()
    }
  })

  it('freezes explicit per-agent model profiles and rejects cross-role routing', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-profile-routing-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    const modelGateway = {
      testConnection: async () => ({
        ok: true,
        message: 'model ready',
        promptTokens: 7,
        completionTokens: 3,
        totalTokens: 10
      }),
      structuredCompletion: async () => {
        throw new Error('not used in this test')
      }
    } as ModelGateway
    const application = new AgentGoApplicationService({
      repository,
      credentialStore,
      modelGateway
    })

    try {
      await application.initialize()
      const deterministicPlanner = (await application.listModelProfiles()).find(
        (profile) => profile.agentRole === 'planner' && profile.provider === 'deterministic'
      )
      expect(deterministicPlanner).toBeDefined()
      const externalPlanner = await application.saveModelProfile({
        name: 'External planner routing test',
        agentRole: 'planner',
        provider: 'openai-compatible',
        baseUrl: 'https://planner.example.test/v1/',
        model: 'planner-model',
        apiKey: 'routing-test-key',
        timeoutMs: 5_000,
        rpmLimit: 30,
        tpmLimit: 100_000,
        tokenBudget: 1_000_000,
        costBudget: 1
      })
      expect(externalPlanner.costBudget).toBe(0)
      const connection = await application.testModelProfile(externalPlanner.id)
      expect(connection.totalTokens).toBe(10)
      expect(await application.listModelProfileUsage()).toMatchObject([
        {
          profileId: externalPlanner.id,
          invocationCount: 1,
          promptTokens: 7,
          completionTokens: 3,
          totalTokens: 10
        }
      ])
      const workspace = await application.createWorkspace({
        name: 'Routing test',
        description: ''
      })
      const target = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Routing fixture',
        baseUrl: 'https://lab.example.test/',
        description: '',
        authorizationReference: 'routing-test-authorization',
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
      const plan = createDefaultScanPlan()
      const scan = await application.createScan({
        targetId: target.target.id,
        name: 'Frozen routing scan',
        description: '明确使用本地 Planner，其余角色采用当前首选 Profile。',
        families: ['sqli'],
        identityIds: [],
        modelProfileIds: { planner: deterministicPlanner!.id },
        budget: plan.budget
      })

      expect(scan.description).toBe('明确使用本地 Planner，其余角色采用当前首选 Profile。')
      expect(scan.modelProfileIds.planner).toBe(deterministicPlanner!.id)
      expect(scan.modelProfileIds.planner).not.toBe(externalPlanner.id)
      expect(Object.values(scan.modelProfileIds)).toHaveLength(5)

      await expect(
        application.createScan({
          targetId: target.target.id,
          name: 'Invalid cross-role scan',
          description: '该任务应因 Profile 角色不匹配而拒绝。',
          families: ['sqli'],
          identityIds: [],
          modelProfileIds: { knowledge: externalPlanner.id },
          budget: plan.budget
        })
      ).rejects.toThrow('不属于 knowledge Agent')
    } finally {
      database.close()
    }
  })

  it('extracts, independently reviews and publishes imported vulnerability intelligence', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-knowledge-ingestion-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    const modelGateway = new DefaultModelGateway({
      profiles: repository,
      credentials: credentialStore,
      prompts: new AgentPromptCatalog(),
      invocations: repository
    })
    const application = new AgentGoApplicationService({
      repository,
      credentialStore,
      modelGateway
    })

    try {
      await application.initialize()
      const profiles = await application.listModelProfiles()
      const extractor = profiles.find(
        (profile) => profile.agentRole === 'knowledge' && profile.provider === 'deterministic'
      )
      const reviewer = profiles.find(
        (profile) => profile.agentRole === 'verifier' && profile.provider === 'deterministic'
      )
      expect(extractor).toBeDefined()
      expect(reviewer).toBeDefined()

      const imported = await application.createKnowledgeImport({
        sourceType: 'public-poc',
        title: 'Acme Portal SQL Injection CVE-2026-12345',
        sourceUrl: 'https://example.test/acme-poc',
        author: 'Security Researcher',
        license: 'MIT',
        vendorHint: 'Acme',
        productHint: 'Portal',
        rawContent: [
          'Acme Portal SQL Injection CVE-2026-12345',
          'POST /api/products/query?id=1 HTTP/1.1',
          'Host: target.example',
          'Content-Type: application/json',
          'Authorization: Bearer public-poc-placeholder',
          '',
          '{"productId":"1"}'
        ].join('\n')
      })
      expect(imported.status).toBe('needs-review')
      expect(imported.instructionFlags).toContain('sensitive-data-redacted')
      expect(imported.rawContent).not.toContain('public-poc-placeholder')

      const extracted = await application.extractKnowledgeImport({
        id: imported.id,
        extractorProfileId: extractor!.id,
        reviewerProfileId: reviewer!.id
      })
      expect(extracted.status).toBe('ready-for-review')
      expect(extracted.candidate).toMatchObject({
        vendor: 'Acme',
        product: 'Portal',
        family: 'sqli',
        identifiers: { cve: ['CVE-2026-12345'] }
      })
      expect(extracted.candidate?.affectedEndpoints[0]).toMatchObject({
        method: 'POST',
        pathTemplate: '/api/products/query?id=%7B%7BID_VALUE%7D%7D',
        unsafeToExecute: true,
        headersTemplate: { Authorization: '{{TEST_CREDENTIAL}}' }
      })
      expect(extracted.runs).toHaveLength(2)
      expect(extracted.runs[1]?.parentRunId).toBe(extracted.runs[0]?.id)

      const published = await application.reviewKnowledgeImport({
        id: imported.id,
        action: 'publish'
      })
      expect(published.status).toBe('published')
      const search = await application.searchKnowledge({
        query: 'Acme Portal',
        families: [],
        limit: 20
      })
      expect(search).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ vendor: 'Acme', product: 'Portal' })
        ])
      )
      const usage = await application.listModelProfileUsage()
      expect(usage.find((item) => item.profileId === extractor!.id)?.totalTokens).toBeGreaterThan(0)
      expect(usage.find((item) => item.profileId === reviewer!.id)?.totalTokens).toBeGreaterThan(0)

      await expect(
        application.extractKnowledgeImport({
          id: imported.id,
          extractorProfileId: extractor!.id,
          reviewerProfileId: reviewer!.id
        })
      ).rejects.toThrow('必须先重新打开审核')
      await expect(
        application.updateKnowledgeCandidate({
          id: imported.id,
          candidate: published.candidate!
        })
      ).rejects.toThrow('必须先重新打开审核')
      await expect(application.deleteKnowledgeImport(imported.id)).rejects.toThrow(
        '必须先重新打开审核'
      )
      await application.reviewKnowledgeImport({ id: imported.id, action: 'reopen' })
      await expect(application.deleteKnowledgeImport(imported.id)).resolves.toEqual({
        deleted: true
      })
    } finally {
      database.close()
    }
  })

  it('blocks deletion during execution and removes target credentials plus artifacts', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-delete-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    const evidenceStore = new EvidenceStore(database, join(directory, 'artifacts'))
    const application = new AgentGoApplicationService({
      repository,
      credentialStore,
      evidenceStore
    })

    try {
      await application.initialize()
      const workspace = await application.createWorkspace({
        name: 'Deletion test',
        description: ''
      })
      const target = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Disposable fixture',
        baseUrl: 'http://127.0.0.1:3000/',
        description: '',
        authorizationReference: 'automated-deletion-test',
        scope: {
          allowedOrigins: ['http://127.0.0.1:3000'],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [3000],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          maxRequestsPerMinute: 30,
          maxConcurrency: 1,
          authorizationReference: 'automated-deletion-test'
        }
      })
      const identity = await application.saveIdentity({
        targetId: target.target.id,
        label: 'Disposable identity',
        role: 'test-user',
        authType: 'bearer',
        secret: 'delete-me',
        isTestIdentity: true,
        ownedResourceIds: []
      })
      const plan = createDefaultScanPlan()
      const scan = await application.createScan({
        targetId: target.target.id,
        name: 'Disposable scan',
        description: '目标删除和证据清理授权测试夹具。',
        families: ['sqli'],
        identityIds: [],
        budget: plan.budget
      })
      const evidence = await evidenceStore.save({
        workspaceId: workspace.id,
        scanId: scan.id,
        type: 'test-response',
        mimeType: 'text/plain',
        content: 'disposable evidence',
        source: 'automated-test',
        createdBy: 'test',
        captureTool: 'test',
        captureToolVersion: '1.0.0'
      })
      const evidencePath = evidenceStore.resolveStoredPath(evidence.filePath)
      expect(existsSync(evidencePath)).toBe(true)
      expect(identity.credentialId && credentialStore.get(identity.credentialId)).toBe(
        'delete-me'
      )

      await repository.updateScan(scan.id, {
        status: 'running',
        runtimeJson: { ...createRuntimeState(), status: 'running' }
      })
      await expect(application.deleteTarget(target.target.id)).rejects.toThrow(
        '请先暂停或取消任务'
      )
      expect(existsSync(evidencePath)).toBe(true)

      await repository.updateScan(scan.id, {
        status: 'paused',
        runtimeJson: { ...createRuntimeState(), status: 'paused' }
      })
      await expect(application.deleteTarget(target.target.id)).resolves.toEqual({
        deleted: true
      })
      expect(await repository.getTarget(target.target.id)).toBeUndefined()
      expect(identity.credentialId && credentialStore.get(identity.credentialId)).toBeUndefined()
      expect(existsSync(evidencePath)).toBe(false)

      const workspaceTarget = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Workspace cleanup fixture',
        baseUrl: 'http://127.0.0.1:3001/',
        description: '',
        authorizationReference: 'automated-workspace-deletion-test',
        scope: {
          allowedOrigins: ['http://127.0.0.1:3001'],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [3001],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          maxRequestsPerMinute: 30,
          maxConcurrency: 1,
          authorizationReference: 'automated-workspace-deletion-test'
        }
      })
      const workspaceIdentity = await application.saveIdentity({
        targetId: workspaceTarget.target.id,
        label: 'Workspace identity',
        role: 'test-user',
        authType: 'bearer',
        secret: 'delete-workspace-secret',
        isTestIdentity: true,
        ownedResourceIds: []
      })
      const workspaceScan = await application.createScan({
        targetId: workspaceTarget.target.id,
        name: 'Workspace scan',
        description: '工作区删除和凭据清理授权测试夹具。',
        families: ['xss'],
        identityIds: [],
        budget: plan.budget
      })
      const workspaceEvidence = await evidenceStore.save({
        workspaceId: workspace.id,
        scanId: workspaceScan.id,
        type: 'workspace-test-response',
        mimeType: 'text/plain',
        content: 'workspace disposable evidence',
        source: 'automated-test',
        createdBy: 'test',
        captureTool: 'test',
        captureToolVersion: '1.0.0'
      })
      const workspaceEvidencePath = evidenceStore.resolveStoredPath(
        workspaceEvidence.filePath
      )

      await expect(application.deleteWorkspace(workspace.id)).resolves.toEqual({
        deleted: true
      })
      expect(await repository.getWorkspace(workspace.id)).toBeUndefined()
      expect(
        workspaceIdentity.credentialId &&
          credentialStore.get(workspaceIdentity.credentialId)
      ).toBeUndefined()
      expect(existsSync(workspaceEvidencePath)).toBe(false)
    } finally {
      database.close()
    }
  })

  it('stores MCP secrets outside SQLite and persists capability discovery', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-mcp-config-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    let receivedSecrets: McpConnectionSecrets | undefined
    const mcpHub: McpHub = {
      testConnection: async (_server, secrets) => {
        receivedSecrets = secrets
        return {
          ok: true,
          message: 'MCP ready',
          durationMs: 5,
          serverName: 'test-mcp',
          serverVersion: '1.0.0',
          tools: [{ name: 'safe-tool', description: 'fixture' }],
          resources: [],
          prompts: []
        }
      }
    }
    const application = new AgentGoApplicationService({
      repository,
      credentialStore,
      mcpHub
    })

    try {
      await application.initialize()
      const saved = await application.saveMcpServer({
        name: 'Local test MCP',
        transport: 'stdio',
        enabled: false,
        command: 'node',
        args: ['server.mjs'],
        authType: 'none',
        environment: { MCP_TOKEN: 'mcp-secret-value' },
        timeoutMs: 5_000,
        roots: ['F:\\Agentgo'],
        allowedAgentRoles: ['strategy'],
        riskLabels: []
      })

      expect(saved.enabled).toBe(false)
      expect(saved.riskLabels).toEqual(
        expect.arrayContaining(['command-execution', 'file-access'])
      )
      expect(JSON.stringify(saved)).not.toContain('mcp-secret-value')
      expect(saved.credentialId && credentialStore.get(saved.credentialId)).toContain(
        'mcp-secret-value'
      )

      const result = await application.testMcpServer(saved.id)
      expect(result.ok).toBe(true)
      expect(receivedSecrets?.environment).toEqual({ MCP_TOKEN: 'mcp-secret-value' })
      expect((await application.listMcpServers())[0]).toMatchObject({
        status: 'ready',
        serverName: 'test-mcp',
        tools: [{ name: 'safe-tool', description: 'fixture' }]
      })

      await expect(application.deleteMcpServer(saved.id)).resolves.toEqual({ deleted: true })
      expect(saved.credentialId && credentialStore.get(saved.credentialId)).toBeUndefined()
    } finally {
      database.close()
    }
  })
})
