import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, sep } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import type { TargetScope } from '@agentgo/contracts'
import { openAgentGoDatabase } from './database'
import { DATABASE_MIGRATIONS } from './migrations'
import { AgentGoRepository } from './repository'

const temporaryDirectories: string[] = []

function scopeInput(
  overrides: Partial<Omit<TargetScope, 'id'>> = {}
): Omit<TargetScope, 'id'> {
  return {
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
    maxConcurrency: 1,
    ...overrides
  }
}

function createLegacyDatabaseWithSameMillisecondScopes(filePath: string): void {
  const database = new DatabaseSync(filePath, {
    enableForeignKeyConstraints: true
  })
  database.exec(`
    CREATE TABLE __agentgo_migrations (
      id TEXT PRIMARY KEY,
      applied_at INTEGER NOT NULL
    );
  `)
  const recordMigration = database.prepare(
    'INSERT INTO __agentgo_migrations (id, applied_at) VALUES (?, ?)'
  )
  for (const migration of DATABASE_MIGRATIONS.slice(0, 4)) {
    database.exec(migration.sql)
    recordMigration.run(migration.id, 1_783_920_144_304)
  }

  database.prepare(
    `INSERT INTO workspaces (id, name, description, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)`
  ).run('workspace-legacy', 'Synthetic legacy workspace', '', 1, 1)
  database.prepare(
    `INSERT INTO targets (
       id, workspace_id, name, base_url, description,
       authorization_reference, default_identity_id, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    'target-legacy',
    'workspace-legacy',
    'Synthetic legacy target',
    'https://lab.example.test/',
    '',
    'synthetic-test-authorization',
    null,
    1,
    1
  )
  const insertScope = database.prepare(
    `INSERT INTO target_scopes (
       id, target_id, allowed_origins, allowed_path_prefixes,
       denied_path_prefixes, allowed_ports, allowed_identity_ids,
       allow_active_probing, allow_sensitive_probing,
       allow_private_network_targets, allow_loopback_targets,
       max_requests_per_minute, max_concurrency, authorization_reference,
       valid_from, valid_until, snapshot_hash, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  const commonValues = [
    'target-legacy',
    JSON.stringify(['https://lab.example.test']),
    JSON.stringify(['/']),
    JSON.stringify([]),
    JSON.stringify([443]),
    1,
    0,
    0,
    0,
    20,
    1,
    'synthetic-test-authorization',
    null,
    null
  ] as const
  insertScope.run(
    'scope-legacy-old',
    ...commonValues.slice(0, 5),
    JSON.stringify([]),
    ...commonValues.slice(5),
    'a'.repeat(64),
    1_783_920_144_304
  )
  insertScope.run(
    'scope-legacy-new',
    ...commonValues.slice(0, 5),
    JSON.stringify(['identity-legacy']),
    ...commonValues.slice(5),
    'b'.repeat(64),
    1_783_920_144_304
  )
  database.close()
}

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
    expect(targetBundle.scope.revision).toBe(1)

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
    expect(targetWithIdentityScope.scope?.revision).toBe(2)
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

  it('freezes the exact current scope when snapshots share a millisecond', async () => {
    const now = 1_783_920_144_304
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(now)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const workspace = await repository.createWorkspace({
        name: 'Same millisecond scope test',
        description: ''
      })
      const created = await repository.createTarget({
        workspaceId: workspace.id,
        name: 'Scope fixture',
        baseUrl: 'https://lab.example.test',
        authorizationReference: 'synthetic-scope-test',
        description: '',
        scope: scopeInput()
      })
      const identity = await repository.saveIdentity(
        {
          targetId: created.target.id,
          label: 'Synthetic identity',
          role: 'owner',
          authType: 'none',
          isTestIdentity: true,
          ownedResourceIds: []
        },
        null
      )
      const second = await repository.updateTarget({
        id: created.target.id,
        scope: scopeInput({ allowedIdentityIds: [identity.id] })
      })

      expect(created.scope.createdAt).toBe(second.scope?.createdAt)
      expect(second.scope?.revision).toBe(2)
      expect((await repository.getLatestScope(created.target.id))?.id).toBe(
        second.scope?.id
      )

      const plan = createDefaultScanPlan()
      const scan = await repository.createScan(
        {
          targetId: created.target.id,
          name: 'Frozen same-millisecond scan',
          description: 'Synthetic regression fixture.',
          families: ['idor'],
          identityIds: [identity.id],
          budget: plan.budget
        },
        { ...plan },
        { ...createRuntimeState() }
      )
      const third = await repository.updateTarget({
        id: created.target.id,
        scope: scopeInput({
          allowedIdentityIds: [identity.id],
          maxRequestsPerMinute: 21
        })
      })

      expect(scan.scopeSnapshotId).toBe(second.scope?.id)
      expect((await repository.getScope(scan.scopeSnapshotId))?.revision).toBe(2)
      expect(third.scope?.revision).toBe(3)
      expect((await repository.getLatestScope(created.target.id))?.id).toBe(
        third.scope?.id
      )
      expect(() =>
        database.native
          .prepare('UPDATE target_scopes SET allowed_origins = ? WHERE id = ?')
          .run(JSON.stringify(['https://mutated.example.test']), scan.scopeSnapshotId)
      ).toThrow(/target scope snapshots are immutable/)
      expect((await repository.getScope(scan.scopeSnapshotId))?.allowedOrigins).toEqual([
        'https://lab.example.test'
      ])
    } finally {
      database.close()
      nowSpy.mockRestore()
    }
  })

  it('serializes concurrent scope revisions and keeps one explicit current head', async () => {
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(1_783_920_144_304)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const workspace = await repository.createWorkspace({
        name: 'Concurrent scope test',
        description: ''
      })
      const created = await repository.createTarget({
        workspaceId: workspace.id,
        name: 'Concurrent scope fixture',
        baseUrl: 'https://lab.example.test',
        authorizationReference: 'synthetic-concurrency-test',
        description: '',
        scope: scopeInput()
      })

      const [concurrentCreated, updates] = await Promise.all([
        repository.createTarget({
          workspaceId: workspace.id,
          name: 'Concurrent initial scope fixture',
          baseUrl: 'https://second-lab.example.test',
          authorizationReference: 'synthetic-concurrent-create-test',
          description: '',
          scope: scopeInput({
            allowedOrigins: ['https://second-lab.example.test']
          })
        }),
        Promise.all(
          [21, 22, 23, 24, 25].map((maxRequestsPerMinute) =>
            repository.updateTarget({
              id: created.target.id,
              scope: scopeInput({ maxRequestsPerMinute })
            })
          )
        )
      ])

      expect(concurrentCreated.scope.revision).toBe(1)
      expect(updates.map((update) => update.scope?.revision)).toEqual([
        2, 3, 4, 5, 6
      ])
      expect((await repository.getLatestScope(created.target.id))?.revision).toBe(6)
      expect(
        (await repository.getLatestScope(created.target.id))?.maxRequestsPerMinute
      ).toBe(25)
    } finally {
      database.close()
      nowSpy.mockRestore()
    }
  })

  it('serializes scope revisions across aliased database paths', async () => {
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(1_783_920_144_304)
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-concurrent-scope-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    const firstDatabase = openAgentGoDatabase(filePath)
    const firstRepository = new AgentGoRepository(firstDatabase)

    try {
      const workspace = await firstRepository.createWorkspace({
        name: 'Cross connection scope test',
        description: ''
      })
      const created = await firstRepository.createTarget({
        workspaceId: workspace.id,
        name: 'Cross connection fixture',
        baseUrl: 'https://lab.example.test',
        authorizationReference: 'synthetic-cross-connection-test',
        description: '',
        scope: scopeInput()
      })
      const aliasedFilePath = `${directory}${sep}.${sep}agentgo.sqlite`
      const secondDatabase = openAgentGoDatabase(aliasedFilePath)
      const secondRepository = new AgentGoRepository(secondDatabase)

      try {
        const [first, second] = await Promise.all([
          firstRepository.updateTarget({
            id: created.target.id,
            scope: scopeInput({ maxRequestsPerMinute: 21 })
          }),
          secondRepository.updateTarget({
            id: created.target.id,
            scope: scopeInput({ maxRequestsPerMinute: 22 })
          })
        ])

        expect(
          [first.scope?.revision, second.scope?.revision].sort((left, right) =>
            (left ?? 0) - (right ?? 0)
          )
        ).toEqual([2, 3])
        expect((await firstRepository.getLatestScope(created.target.id))?.revision).toBe(3)
      } finally {
        secondDatabase.close()
      }
    } finally {
      firstDatabase.close()
      nowSpy.mockRestore()
    }
  })

  it('backfills legacy same-millisecond scopes by insertion order', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-legacy-scope-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    createLegacyDatabaseWithSameMillisecondScopes(filePath)

    const database = openAgentGoDatabase(filePath)
    try {
      const repository = new AgentGoRepository(database)
      const latest = await repository.getLatestScope('target-legacy')
      expect(latest).toMatchObject({
        id: 'scope-legacy-new',
        revision: 2,
        allowedIdentityIds: ['identity-legacy']
      })
      expect(
        database.native
          .prepare(
            'SELECT id, revision FROM target_scopes WHERE target_id = ? ORDER BY revision'
          )
          .all('target-legacy')
      ).toEqual([
        { id: 'scope-legacy-old', revision: 1 },
        { id: 'scope-legacy-new', revision: 2 }
      ])
      expect(
        database.native
          .prepare('SELECT current_scope_id FROM targets WHERE id = ?')
          .get('target-legacy')
      ).toEqual({ current_scope_id: 'scope-legacy-new' })
      expect(() =>
        database.native
          .prepare('UPDATE targets SET current_scope_id = ? WHERE id = ?')
          .run('scope-missing', 'target-legacy')
      ).toThrow()
      expect(() =>
        database.native
          .prepare('UPDATE targets SET current_scope_id = NULL WHERE id = ?')
          .run('target-legacy')
      ).toThrow(/current scope cannot be cleared/)
      expect((await repository.getLatestScope('target-legacy'))?.id).toBe(
        'scope-legacy-new'
      )

      const plan = createDefaultScanPlan()
      const scan = await repository.createScan(
        {
          targetId: 'target-legacy',
          name: 'Legacy scope head remains usable',
          description: 'The authoritative scope head survives rejected corruption.',
          families: ['sqli'],
          identityIds: [],
          modelProfileIds: {},
          budget: plan.budget
        },
        { ...plan },
        { ...createRuntimeState() }
      )
      expect(scan.scopeSnapshotId).toBe('scope-legacy-new')

      const otherTarget = await repository.createTarget({
        workspaceId: 'workspace-legacy',
        name: 'Synthetic second legacy target',
        baseUrl: 'https://second-lab.example.test',
        description: '',
        authorizationReference: 'synthetic-second-target-authorization',
        scope: scopeInput({
          allowedOrigins: ['https://second-lab.example.test']
        })
      })
      expect(() =>
        database.native
          .prepare('UPDATE targets SET current_scope_id = ? WHERE id = ?')
          .run(otherTarget.scope.id, 'target-legacy')
      ).toThrow(/current scope must belong to target/)

      expect(() =>
        database.native
          .prepare(
            `INSERT INTO target_scopes (
               id, target_id, allowed_origins, allowed_path_prefixes,
               denied_path_prefixes, allowed_ports, allowed_identity_ids,
               allow_active_probing, allow_sensitive_probing,
               allow_private_network_targets, allow_loopback_targets,
               max_requests_per_minute, max_concurrency,
               authorization_reference, valid_from, valid_until,
               snapshot_hash, created_at
             )
             SELECT ?, target_id, allowed_origins, allowed_path_prefixes,
                    denied_path_prefixes, allowed_ports, allowed_identity_ids,
                    allow_active_probing, allow_sensitive_probing,
                    allow_private_network_targets, allow_loopback_targets,
                    max_requests_per_minute, max_concurrency,
                    authorization_reference, valid_from, valid_until,
                    ?, created_at
             FROM target_scopes
             WHERE id = ?`
          )
          .run('scope-without-revision', 'c'.repeat(64), 'scope-legacy-old')
      ).toThrow(/revision must be a positive integer/)

      expect(() =>
        database.native
          .prepare(
            `INSERT INTO target_scopes (
               id, target_id, allowed_origins, allowed_path_prefixes,
               denied_path_prefixes, allowed_ports, allowed_identity_ids,
               allow_active_probing, allow_sensitive_probing,
               allow_private_network_targets, allow_loopback_targets,
               max_requests_per_minute, max_concurrency,
               authorization_reference, valid_from, valid_until,
               snapshot_hash, created_at, revision
             )
             SELECT ?, target_id, allowed_origins, allowed_path_prefixes,
                    denied_path_prefixes, allowed_ports, allowed_identity_ids,
                    allow_active_probing, allow_sensitive_probing,
                    allow_private_network_targets, allow_loopback_targets,
                    max_requests_per_minute, max_concurrency,
                    authorization_reference, valid_from, valid_until,
                    ?, created_at, revision
             FROM target_scopes
             WHERE id = ?`
          )
          .run('scope-duplicate-revision', 'd'.repeat(64), 'scope-legacy-old')
      ).toThrow()
      expect(database.native.prepare('PRAGMA foreign_key_check').all()).toHaveLength(0)
    } finally {
      database.close()
    }
  })

  it('rolls back scope and target changes when the current pointer update fails', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const workspace = await repository.createWorkspace({
        name: 'Atomic pointer test',
        description: ''
      })
      const created = await repository.createTarget({
        workspaceId: workspace.id,
        name: 'Atomic pointer fixture',
        baseUrl: 'https://lab.example.test',
        authorizationReference: 'synthetic-atomic-pointer-test',
        description: '',
        scope: scopeInput()
      })
      database.native.exec(`
        CREATE TRIGGER synthetic_pointer_failure
        BEFORE UPDATE OF current_scope_id ON targets
        BEGIN
          SELECT RAISE(ABORT, 'synthetic pointer update failure');
        END;
      `)

      await expect(
        repository.updateTarget({
          id: created.target.id,
          name: 'This name must roll back',
          scope: scopeInput({ maxRequestsPerMinute: 21 })
        })
      ).rejects.toThrow()

      expect(
        database.native
          .prepare('SELECT COUNT(*) AS count FROM target_scopes WHERE target_id = ?')
          .get(created.target.id)
      ).toEqual({ count: 1 })
      expect((await repository.getTarget(created.target.id))?.name).toBe(
        'Atomic pointer fixture'
      )
      expect((await repository.getLatestScope(created.target.id))?.id).toBe(
        created.scope.id
      )
    } finally {
      database.close()
    }
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

    const changed = await repository.updateTarget({
      id: created.target.id,
      scope: scopeInput({ maxRequestsPerMinute: 21 })
    })
    const updated = await repository.updateTarget({
      id: created.target.id,
      scope: scopeInput()
    })

    expect(changed.scope?.revision).toBe(2)
    expect(updated.scope?.id).toBe(created.scope.id)
    expect(updated.scope?.revision).toBe(1)
    expect((await repository.getLatestScope(created.target.id))?.id).toBe(
      created.scope.id
    )

    const withCanonicalTime = await repository.updateTarget({
      id: created.target.id,
      scope: scopeInput({ validFrom: '2026-01-01T00:00:00Z' })
    })
    const withEquivalentTime = await repository.updateTarget({
      id: created.target.id,
      scope: scopeInput({ validFrom: '2026-01-01T00:00:00.000Z' })
    })
    expect(withEquivalentTime.scope?.id).toBe(withCanonicalTime.scope?.id)
    expect(withEquivalentTime.scope?.revision).toBe(withCanonicalTime.scope?.revision)
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
