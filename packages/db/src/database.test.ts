import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, sep } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  InventoryEndpointRecordSchema,
  InventorySourceRecordSchema,
  RequestVariantRecordSchema,
  ScanModuleSnapshotRecordSchema,
  TargetSchema,
  type TargetScope
} from '@agentgo/contracts'
import { deriveScopeNetworkEntriesFromOrigins } from '@agentgo/security-policy'
import {
  applyDatabaseMigrations,
  openAgentGoDatabase
} from './database'
import {
  DATABASE_MIGRATIONS,
  type DatabaseMigration
} from './migrations'
import {
  AgentGoRepository,
  type PreparedInventoryWrite
} from './repository'

const temporaryDirectories: string[] = []

function canonicalTestHash(value: unknown): string {
  const normalize = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map(normalize)
    if (input !== null && typeof input === 'object') {
      return Object.fromEntries(
        Object.entries(input as Record<string, unknown>)
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
          .map(([key, nested]) => [key, normalize(nested)])
      )
    }
    return input
  }
  return createHash('sha256').update(JSON.stringify(normalize(value))).digest('hex')
}

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
    networkEntries: [],
    maxRequestsPerMinute: 20,
    maxConcurrency: 1,
    ...overrides
  }
}

function preparedInventoryWrite(scanId: string): PreparedInventoryWrite {
  const selector = {
    kind: 'query' as const,
    name: 'id',
    valueType: 'number' as const,
    required: true
  }
  const selectors = [selector]
  const structuralValue = {
    contentType: null,
    bodyShape: { rootType: 'none' as const, fields: [] },
    codec: 'none' as const,
    transport: 'standard-http' as const,
    allowedHeaders: [],
    templateVersion: '1.0.0',
    requiredCapabilityIds: ['http.reviewed-read'],
    selectors
  }
  const structureHash = canonicalTestHash(structuralValue)
  const sourceHash = 'c'.repeat(64)
  return {
    scanId,
    method: 'GET',
    canonicalRoute: 'https://lab.example.test/items',
    compatibilityUrl:
      'https://lab.example.test/items?id=%5BREDACTED%5D',
    bodyShape: structuralValue.bodyShape,
    codec: structuralValue.codec,
    transport: structuralValue.transport,
    allowedHeaders: [],
    templateVersion: structuralValue.templateVersion,
    requiredCapabilityIds: structuralValue.requiredCapabilityIds,
    redactedPreview: { url: 'https://lab.example.test/items?id=%5BREDACTED%5D' },
    executionClass: 'active-l1',
    structureHash,
    selectors: [
      {
        selector,
        structureHash: canonicalTestHash(selector)
      }
    ],
    source: {
      type: 'concurrency-regression',
      sourceHash,
      provenanceHash: canonicalTestHash({
        scanId,
        method: 'GET',
        canonicalRoute: 'https://lab.example.test/items',
        structureHash,
        type: 'concurrency-regression',
        sourceHash,
        pageId: null,
        evidenceRef: null,
        initiator: null
      }),
      confidencePpm: 1_000_000
    }
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

function createLegacyDatabaseWithDuplicateLoopbackScopes(filePath: string): void {
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
  ).run('workspace-dup', 'Synthetic duplicate-origin workspace', '', 1, 1)
  const insertTarget = database.prepare(
    `INSERT INTO targets (
       id, workspace_id, name, base_url, description,
       authorization_reference, default_identity_id, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  const baseUrlByTarget: Record<string, string> = {
    'target-dup-a': 'http://127.0.0.1:8080/',
    'target-dup-b': 'http://127.0.0.1:8081/'
  }
  for (const targetId of ['target-dup-a', 'target-dup-b']) {
    insertTarget.run(
      targetId,
      'workspace-dup',
      'Duplicate-origin target',
      baseUrlByTarget[targetId]!,
      '',
      'synthetic-test-authorization',
      null,
      1,
      1
    )
  }
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
  const scopeValues = [
    JSON.stringify(['http://127.0.0.1:8080']),
    JSON.stringify(['/']),
    JSON.stringify([]),
    JSON.stringify([8080]),
    JSON.stringify([]),
    1,
    0,
    1,
    1,
    20,
    1,
    'synthetic-test-authorization',
    null,
    null
  ] as const
  insertScope.run(
    'scope-dup-a',
    'target-dup-a',
    ...scopeValues,
    'c'.repeat(64),
    1_783_920_144_304
  )
  insertScope.run(
    'scope-dup-b',
    'target-dup-b',
    ...scopeValues,
    'd'.repeat(64),
    1_783_920_144_304
  )
  database.close()
}

function createLegacyInventoryDatabase(filePath: string): void {
  const database = new DatabaseSync(filePath, {
    enableForeignKeyConstraints: true
  })
  applyDatabaseMigrations(database, {
    migrations: DATABASE_MIGRATIONS.slice(0, 5),
    appliedAt: () => 1_783_920_144_304
  })
  database.exec(`
    INSERT INTO workspaces (id, name, description, created_at, updated_at)
    VALUES ('workspace-legacy', 'legacy migration fixture', '', 1, 1);

    INSERT INTO targets (
      id, workspace_id, name, base_url, description,
      authorization_reference, default_identity_id, current_scope_id,
      created_at, updated_at
    ) VALUES
      (
        'target-legacy', 'workspace-legacy', 'legacy target',
        'https://legacy-user:sentinel-target-password@LAB.EXAMPLE.test/base/AbCdEfGhIjKlMnOpQrStUvWxYz012345?token=inventory-sentinel-target-token#sentinel-target-fragment',
        '', 'synthetic-authorization',
        NULL, NULL, 1, 1
      ),
      (
        'target-legacy-collision', 'workspace-legacy', 'legacy target collision',
        'https://other-user:must-not-leak@lab.example.test/base/ZyXwVuTsRqPoNmLkJiHgFeDcBa987654?token=must-not-store#must-not-leak-fragment',
        '', 'synthetic-authorization',
        NULL, NULL, 2, 2
      ),
      (
        'target-legacy-benign', 'workspace-legacy', 'legacy benign query target',
        'https://LAB.EXAMPLE.test:443/search?id=1&q=hello&url=agentgo-invalid-url',
        '', 'synthetic-authorization',
        NULL, NULL, 3, 3
      ),
      (
        'target-legacy-credential-host', 'workspace-legacy', 'legacy credential-shaped host',
        'https://abcdefgh.ijklmnop.qrstuvwx.example.test/',
        '', 'synthetic-authorization',
        NULL, NULL, 4, 4
      ),
      (
        'target-legacy-invalid', 'workspace-legacy', 'legacy invalid target',
        'not-a-target-url',
        '', 'synthetic-authorization',
        NULL, NULL, 5, 5
      );

    INSERT INTO audit_logs (
      id, workspace_id, scan_id, event, actor, detail_json, created_at
    ) VALUES
      (
        'audit-target-legacy', 'workspace-legacy', NULL, 'target.created', 'user',
        '{"targetId":"target-legacy","baseUrl":"https://legacy-user:sentinel-target-password@LAB.EXAMPLE.test/base/AbCdEfGhIjKlMnOpQrStUvWxYz012345?token=inventory-sentinel-target-token#sentinel-target-fragment"}',
        1
      ),
      (
        'audit-target-legacy-benign', 'workspace-legacy', NULL, 'target.created', 'user',
        '{"targetId":"target-legacy-benign","baseUrl":"https://LAB.EXAMPLE.test:443/search?id=1&q=hello&url=agentgo-invalid-url"}',
        3
      );

    INSERT INTO target_scopes (
      id, target_id, allowed_origins, allowed_path_prefixes,
      denied_path_prefixes, allowed_ports, allowed_identity_ids,
      allow_active_probing, allow_sensitive_probing,
      allow_private_network_targets, allow_loopback_targets,
      max_requests_per_minute, max_concurrency, authorization_reference,
      valid_from, valid_until, snapshot_hash, created_at, revision
    ) VALUES (
      'scope-legacy', 'target-legacy', '["https://lab.example.test"]', '["/"]',
      '[]', '[443]', '[]', 1, 0, 0, 0, 10, 1,
      'synthetic-authorization', NULL, NULL,
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 1
    );
    UPDATE targets SET current_scope_id = 'scope-legacy' WHERE id = 'target-legacy';

    INSERT INTO scans (
      id, target_id, name, scope_snapshot_id, status, phase, progress,
      budget_json, config_json, plan_json, runtime_json,
      request_count, model_tokens, estimated_cost_micros,
      checkpoint_count, last_error, created_at, updated_at,
      started_at, completed_at
    ) VALUES
      (
        'scan-legacy-a', 'target-legacy', 'Legacy scan A', 'scope-legacy',
        'paused', 'discovery', 50, '{}',
        '{"families":["unknown.future","xss","sqli","sqli"]}', '{}', '{}',
        0, 0, 0, 0, NULL, 10, 10, NULL, NULL
      ),
      (
        'scan-legacy-b', 'target-legacy', 'Legacy scan B', 'scope-legacy',
        'paused', 'discovery', 50, '{}',
        '{"families":["idor"]}', '{}', '{}',
        0, 0, 0, 0, NULL, 20, 20, NULL, NULL
      );

    INSERT INTO pages (
      id, scan_id, url, title, depth, discovered_from,
      state_hash, status, created_at, updated_at
    ) VALUES
      (
        'page-legacy-a', 'scan-legacy-a',
        'https://legacy-user:sentinel-page-password@LAB.EXAMPLE.test/landing/AbCdEfGhIjKlMnOpQrStUvWxYz012345?q=sentinel-page-query&token=inventory-sentinel-page-token#sentinel-page-fragment',
        'Authorization: Bearer inventory-sentinel-page-title',
        0, NULL, NULL, 'done', 1, 1
      ),
      (
        'page-legacy-a-collision', 'scan-legacy-a',
        'https://other-user:must-not-leak@lab.example.test/landing/ZyXwVuTsRqPoNmLkJiHgFeDcBa987654?token=must-not-store&q=sentinel-page-other#must-not-leak-fragment',
        NULL, 0, NULL, NULL, 'done', 2, 2
      ),
      ('page-legacy-b', 'scan-legacy-b', 'https://lab.example.test/other', NULL, 0, NULL, NULL, 'done', 1, 1);

    INSERT INTO endpoints (
      id, scan_id, page_id, method, url_template, normalized_url,
      content_type, source, status, created_at, updated_at
    ) VALUES
      (
        'endpoint-legacy-a', 'scan-legacy-a', 'page-legacy-a', 'get',
        'https://LAB.EXAMPLE.test/search/sentinel-secret-token/abcdefgh.ijklmnop.qrstuvwx/AbCdEfGhIjKlMnOpQrStUvWxYz012345?token=sentinel-query-a&q=one',
        'https://lab.example.test/search/sentinel-secret-token/abcdefgh.ijklmnop.qrstuvwx/AbCdEfGhIjKlMnOpQrStUvWxYz012345?q=one&token=sentinel-query-a',
        'application/json; boundary=sentinel-mime-secret', 'xhr', 'discovered', 10, 10
      ),
      (
        'endpoint-legacy-b', 'scan-legacy-a', 'page-legacy-a-collision', 'GET',
        'https://lab.example.test/search/inventory-sentinel-credential/ABCDEFGH.IJKLMNOP.QRSTUVWX/ZyXwVuTsRqPoNmLkJiHgFeDcBa987654?q=two&token=sentinel-query-b',
        'https://lab.example.test/search/inventory-sentinel-credential/ABCDEFGH.IJKLMNOP.QRSTUVWX/ZyXwVuTsRqPoNmLkJiHgFeDcBa987654?q=two&token=sentinel-query-b',
        'application/graphql', 'form', 'discovered', 20, 20
      ),
      (
        'endpoint-legacy-c', 'scan-legacy-b', 'page-legacy-b', 'GET',
        'https://lab.example.test/same?left=one',
        'https://lab.example.test/same?left=one',
        NULL, 'link', 'discovered', 30, 30
      ),
      (
        'endpoint-legacy-d', 'scan-legacy-b', 'page-legacy-b', 'get',
        'https://lab.example.test/same?right=two',
        'https://lab.example.test/same?right=two',
        NULL, 'link', 'discovered', 31, 31
      );

    INSERT INTO parameters (
      id, endpoint_id, name, location, data_type,
      required, example_masked, created_at
    ) VALUES
      ('parameter-query-a', 'endpoint-legacy-a', 'q', 'query', 'string', 1, 'sentinel-query-a', 10),
      ('parameter-query-b', 'endpoint-legacy-b', 'q', 'query', 'string', 1, 'sentinel-query-b', 20),
      ('parameter-json', 'endpoint-legacy-a', 'profile/token', 'json', 'string', 0, 'sentinel-body', 11),
      ('parameter-header', 'endpoint-legacy-a', 'Bad Header Name', 'header', 'string', 0, 'Bearer sentinel-auth', 12),
      ('parameter-cookie', 'endpoint-legacy-a', 'session', 'cookie', 'string', 0, 'sentinel-cookie', 13),
      ('parameter-form', 'endpoint-legacy-b', 'bad-name', 'form', 'string', 1, 'sentinel-form', 21),
      ('parameter-left', 'endpoint-legacy-c', 'left', 'query', 'string', 1, 'one', 30),
      ('parameter-right', 'endpoint-legacy-d', 'right', 'query', 'string', 1, 'two', 31);

    INSERT INTO interactions (
      id, scan_id, endpoint_id, identity_id, policy_decision_id,
      request_ref, response_ref, request_summary_json,
      response_summary_json, status_code, duration_ms,
      state_before_hash, state_after_hash, created_at
    ) VALUES (
      'interaction-legacy', 'scan-legacy-a', 'endpoint-legacy-b', NULL, NULL,
      'request-ref', 'response-ref', '{}', '{}', 200, 1, NULL, NULL, 30
    );

    INSERT INTO signals (
      id, scan_id, interaction_id, family, endpoint_id, parameter_id,
      identity_id, hypothesis, observed_difference, confidence_hint,
      evidence_refs, status, created_at
    ) VALUES (
      'signal-legacy', 'scan-legacy-a', 'interaction-legacy', 'sqli',
      'endpoint-legacy-b', 'parameter-query-b', NULL,
      'synthetic', 'synthetic', 1, '[]', 'new', 31
    );

    INSERT INTO confirmation_rules (
      id, version, family, rule_json, required_checks, source_refs, created_at
    ) VALUES ('rule-legacy', '1.0.0', 'sqli', '{}', '[]', '[]', 1);

    INSERT INTO findings (
      id, scan_id, family, title, verdict, status, severity, confidence,
      endpoint_id, parameter_id, identity_id, affected_resource, cwe, owasp,
      confirmation_rule_id, confirmation_rule_version, reproducibility,
      remediation_json, first_seen_at, last_verified_at
    ) VALUES (
      'finding-legacy', 'scan-legacy-a', 'sqli', 'Synthetic', 'inconclusive',
      'draft', 'info', 0, 'endpoint-legacy-b', 'parameter-query-b', NULL,
      NULL, NULL, NULL, 'rule-legacy', '1.0.0', 'synthetic', '[]', 31, 31
    );
  `)
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

    const credentialBearingTargetUrl =
      'https://alice:must-not-leak@lab.example.test/reset/N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa?token=inventory-sentinel-target'
    await expect(
      repository.createTarget({
        workspaceId: workspace!.id,
        name: 'Rejected credential-bearing target',
        baseUrl: credentialBearingTargetUrl,
        description: '',
        authorizationReference: 'lab-owner-approval-rejected',
        scope: scopeInput()
      })
    ).rejects.toBeDefined()
    expect(
      JSON.stringify([
        ...database.native.prepare('SELECT * FROM targets').all(),
        ...database.native.prepare('SELECT * FROM audit_logs').all()
      ])
    ).not.toMatch(/must-not-leak|N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa|sentinel/iu)

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
        networkEntries: [],
        maxRequestsPerMinute: 30,
        maxConcurrency: 2,
        authorizationReference: 'lab-owner-approval-001'
      }
    })
    expect(targetBundle.scope.snapshotHash).toHaveLength(64)
    expect(targetBundle.scope.revision).toBe(1)
    await expect(
      repository.updateTarget({
        id: targetBundle.target.id,
        baseUrl: 'https://lab.example.test/?password=inventory-sentinel-update'
      })
    ).rejects.toBeDefined()
    expect((await repository.getTarget(targetBundle.target.id))?.baseUrl).toBe(
      'http://127.0.0.1:3000/'
    )
    expect(JSON.stringify(database.native.prepare('SELECT * FROM audit_logs').all())).not.toContain(
      'inventory-sentinel-update'
    )

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

    const plan = createDefaultScanPlan(['sqli', 'xss', 'ssrf', 'idor'])
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

    const page = await repository.upsertPage({
      scanId: scan.id,
      url: 'http://legacy-user:must-not-leak@127.0.0.1:3000/reset/N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa?token=inventory-sentinel-page-token#sentinel-fragment',
      depth: 0
    })
    expect(page.url).toBe(
      'http://127.0.0.1:3000/reset/:redacted?token=%5BREDACTED%5D'
    )
    expect(
      JSON.stringify(
        database.native.prepare('SELECT url FROM pages WHERE id = ?').get(page.id)
      )
    ).not.toMatch(/must-not-leak|N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa|sentinel/iu)

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

      const plan = createDefaultScanPlan(['idor'])
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

  it('serializes idempotent inventory upserts on one and aliased connections', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-concurrent-inventory-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    const firstDatabase = openAgentGoDatabase(filePath)
    const firstRepository = new AgentGoRepository(firstDatabase)

    try {
      const workspace = await firstRepository.createWorkspace({
        name: 'Concurrent inventory workspace',
        description: ''
      })
      const target = await firstRepository.createTarget({
        workspaceId: workspace.id,
        name: 'Concurrent inventory fixture',
        baseUrl: 'https://lab.example.test',
        authorizationReference: 'synthetic-concurrent-inventory',
        description: '',
        scope: scopeInput()
      })
      const plan = createDefaultScanPlan(['sqli'])
      const scan = await firstRepository.createScan(
        {
          targetId: target.target.id,
          name: 'Concurrent inventory scan',
          description: '',
          families: ['sqli'],
          identityIds: [],
          budget: plan.budget
        },
        { ...plan },
        { ...createRuntimeState() }
      )
      const input = preparedInventoryWrite(scan.id)
      const oversizedCanonicalRoute = `https://lab.example.test/${'a'.repeat(16_384)}`
      const invalidInput: PreparedInventoryWrite = {
        ...input,
        canonicalRoute: oversizedCanonicalRoute,
        source: {
          ...input.source,
          provenanceHash: canonicalTestHash({
            scanId: scan.id,
            method: input.method,
            canonicalRoute: oversizedCanonicalRoute,
            structureHash: input.structureHash,
            type: input.source.type,
            sourceHash: input.source.sourceHash,
            pageId: null,
            evidenceRef: null,
            initiator: null
          })
        }
      }
      expect(() => firstRepository.persistInventory(invalidInput)).toThrow()
      expect(
        firstDatabase.native.prepare('SELECT COUNT(*) AS count FROM endpoints').get()
      ).toEqual({ count: 0 })
      const sameConnection = await Promise.all(
        Array.from({ length: 8 }, () => firstRepository.persistInventory(input))
      )
      expect(new Set(sameConnection.map(({ endpoint }) => endpoint.id)).size).toBe(1)
      expect(
        new Set(sameConnection.map(({ requestVariant }) => requestVariant.id)).size
      ).toBe(1)
      expect(new Set(sameConnection.map(({ source }) => source.id)).size).toBe(1)

      const aliasedFilePath = `${directory}${sep}.${sep}agentgo.sqlite`
      const secondDatabase = openAgentGoDatabase(aliasedFilePath)
      const secondRepository = new AgentGoRepository(secondDatabase)
      try {
        const crossConnection = await Promise.all([
          ...Array.from({ length: 4 }, () =>
            firstRepository.persistInventory(input)
          ),
          ...Array.from({ length: 4 }, () =>
            secondRepository.persistInventory(input)
          )
        ])
        expect(
          new Set(crossConnection.map(({ endpoint }) => endpoint.id)).size
        ).toBe(1)
        expect(
          new Set(crossConnection.map(({ requestVariant }) => requestVariant.id)).size
        ).toBe(1)
        expect(new Set(crossConnection.map(({ source }) => source.id)).size).toBe(1)
        expect(
          firstDatabase.native.prepare('SELECT COUNT(*) AS count FROM endpoints').get()
        ).toEqual({ count: 1 })
        expect(
          firstDatabase.native
            .prepare('SELECT COUNT(*) AS count FROM request_variants')
            .get()
        ).toEqual({ count: 1 })
        expect(
          firstDatabase.native
            .prepare('SELECT COUNT(*) AS count FROM inventory_sources')
            .get()
        ).toEqual({ count: 1 })
      } finally {
        secondDatabase.close()
      }
    } finally {
      firstDatabase.close()
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

      const plan = createDefaultScanPlan(['sqli'])
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

  it('backfills scope-qualified network entries for duplicate legacy origins', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-budget-backfill-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    createLegacyDatabaseWithDuplicateLoopbackScopes(filePath)

    const database = openAgentGoDatabase(filePath)
    try {
      const repository = new AgentGoRepository(database)
      const derived = deriveScopeNetworkEntriesFromOrigins([
        'http://127.0.0.1:8080'
      ])
      const derivedIdByPurpose = new Map(
        derived.map((entry) => [entry.purpose, entry.id])
      )
      expect(derivedIdByPurpose.size).toBe(2)

      const rows = database.native
        .prepare(
          `SELECT id, scope_id, purpose
           FROM target_scope_network_entries
           ORDER BY scope_id, purpose`
        )
        .all() as Array<{ id: string; scope_id: string; purpose: string }>
      expect(rows).toHaveLength(4)
      for (const scopeId of ['scope-dup-a', 'scope-dup-b']) {
        const scoped = rows.filter((row) => row.scope_id === scopeId)
        expect(scoped.map((row) => row.purpose)).toEqual([
          'execution',
          'ssrf-target'
        ])
        for (const row of scoped) {
          const derivedId = derivedIdByPurpose.get(
            row.purpose as 'execution' | 'ssrf-target'
          )
          expect(row.id).toBe(
            createHash('sha256').update(`${scopeId}:${derivedId}`).digest('hex')
          )
        }
      }

      const scopeA = await repository.getScope('scope-dup-a')
      const scopeB = await repository.getScope('scope-dup-b')
      expect(scopeA?.networkEntries).toHaveLength(2)
      expect(scopeB?.networkEntries).toHaveLength(2)
    } finally {
      database.close()
    }
  })

  it('migrates and merges legacy inventory without retaining query or preview secrets', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-inventory-migrate-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    createLegacyInventoryDatabase(filePath)

    const database = openAgentGoDatabase(filePath)
    try {
      expect(
        database.native
          .prepare(
            `SELECT id, method, url_template, normalized_url,
                    canonical_route, content_type, lifecycle_status
             FROM endpoints
             WHERE scan_id = 'scan-legacy-a'`
          )
          .all()
      ).toEqual([
        {
          id: 'endpoint-legacy-a',
          method: 'GET',
          url_template: 'https://lab.example.test/search/:redacted/:redacted/:redacted',
          normalized_url: 'https://lab.example.test/search/:redacted/:redacted/:redacted',
          canonical_route: 'https://lab.example.test/search/:redacted/:redacted/:redacted',
          content_type: 'application/json',
          lifecycle_status: 'active'
        }
      ])

      const migratedPages = database.native
        .prepare(
          `SELECT id, url, title
           FROM pages
           WHERE scan_id = 'scan-legacy-a'
           ORDER BY id ASC`
        )
        .all() as unknown as Array<{ id: string; url: string; title: string | null }>
      expect(migratedPages.map(({ id }) => id)).toEqual([
        'page-legacy-a',
        'page-legacy-a-collision'
      ])
      expect(new Set(migratedPages.map(({ url }) => url)).size).toBe(2)
      for (const { url } of migratedPages) {
        const parsed = new URL(url)
        expect(parsed.username).toBe('')
        expect(parsed.password).toBe('')
        expect(parsed.hash).toBe('')
        expect(parsed.pathname).toBe('/landing/:redacted')
        expect(parsed.searchParams.get('q')).toBe('[REDACTED]')
        expect(parsed.searchParams.get('token')).toBe('[REDACTED]')
        expect([...parsed.searchParams.values()].every((value) => value === '[REDACTED]')).toBe(
          true
        )
      }
      expect(JSON.stringify(migratedPages)).not.toMatch(
        /sentinel|must-not|AbCdEfGhIjKlMnOpQrStUvWxYz012345|ZyXwVuTsRqPoNmLkJiHgFeDcBa987654/iu
      )
      expect(migratedPages.find(({ id }) => id === 'page-legacy-a')?.title).toContain(
        '[REDACTED]'
      )
      const migratedTargets = database.native
        .prepare(
          `SELECT id, base_url
           FROM targets
           WHERE workspace_id = 'workspace-legacy'
           ORDER BY id ASC`
        )
        .all()
      expect(migratedTargets).toEqual([
        {
          id: 'target-legacy',
          base_url:
            'https://legacy-target-review.invalid/reconfigure/required/instance-1'
        },
        {
          id: 'target-legacy-benign',
          base_url:
            'https://lab.example.test/search?id=1&q=hello&url=agentgo-invalid-url'
        },
        {
          id: 'target-legacy-collision',
          base_url:
            'https://legacy-target-review.invalid/reconfigure/required/instance-2'
        },
        {
          id: 'target-legacy-credential-host',
          base_url:
            'https://legacy-target-review.invalid/reconfigure/required/instance-3'
        },
        {
          id: 'target-legacy-invalid',
          base_url:
            'https://legacy-target-review.invalid/reconfigure/required/instance-4'
        }
      ])
      expect(new Set(migratedTargets.map((row) => (row as { base_url: string }).base_url)).size).toBe(
        migratedTargets.length
      )
      const benignTarget = migratedTargets.find(
        (row) => (row as { id: string }).id === 'target-legacy-benign'
      ) as { id: string; base_url: string } | undefined
      expect(benignTarget?.base_url).toBe(
        'https://lab.example.test/search?id=1&q=hello&url=agentgo-invalid-url'
      )
      expect(
        migratedTargets
          .filter((row) => (row as { id: string }).id !== 'target-legacy-benign')
          .every((row) => {
            const url = new URL((row as { base_url: string }).base_url)
            return (
              url.hostname === 'legacy-target-review.invalid' &&
              url.pathname.startsWith('/reconfigure/')
            )
          })
      ).toBe(true)
      expect(JSON.stringify(migratedTargets)).not.toMatch(
        /sentinel|must-not|AbCdEfGhIjKlMnOpQrStUvWxYz012345|ZyXwVuTsRqPoNmLkJiHgFeDcBa987654|abcdefgh\.ijklmnop\.qrstuvwx/iu
      )
      expect(
        JSON.parse(
          (
            database.native
              .prepare('SELECT detail_json FROM audit_logs WHERE id = ?')
              .get('audit-target-legacy') as { detail_json: string }
          ).detail_json
        )
      ).toMatchObject({
        targetId: 'target-legacy',
        baseUrl:
          'https://legacy-target-review.invalid/reconfigure/required/instance-1'
      })
      expect(
        JSON.parse(
          (
            database.native
              .prepare('SELECT detail_json FROM audit_logs WHERE id = ?')
              .get('audit-target-legacy-benign') as { detail_json: string }
          ).detail_json
        )
      ).toMatchObject({
        targetId: 'target-legacy-benign',
        baseUrl: 'https://lab.example.test/search?id=1&q=hello&url=agentgo-invalid-url'
      })

      const variants = database.native
        .prepare(
          `SELECT id, content_type, body_shape_json, codec,
                   allowed_headers_json, redacted_preview_json,
                   template_version, required_capability_ids_json, review_status,
                  execution_class, lifecycle_status
           FROM request_variants
           WHERE scan_id = 'scan-legacy-a'
           ORDER BY codec ASC`
        )
        .all() as unknown as Array<Record<string, string>>
      expect(variants).toHaveLength(2)
      expect(variants.map(({ codec }) => codec)).toEqual(['graphql', 'json'])
      expect(variants.map(({ content_type }) => content_type)).toEqual([
        'application/graphql',
        'application/json'
      ])
      expect(
        variants.every(
          (variant) =>
            variant.review_status === 'unreviewed' &&
            variant.execution_class === 'inventory-only' &&
            variant.lifecycle_status === 'active' &&
            variant.template_version === '1.0.0' &&
            variant.required_capability_ids_json === '[]'
        )
      ).toBe(true)
      expect(
        variants.map(({ redacted_preview_json }) => JSON.parse(redacted_preview_json!))
      ).toEqual([
        { url: 'https://lab.example.test/search/:redacted/:redacted/:redacted' },
        { url: 'https://lab.example.test/search/:redacted/:redacted/:redacted' }
      ])
      expect(
        variants.map(({ body_shape_json }) => JSON.parse(body_shape_json!).rootType)
      ).toEqual(['object', 'object'])
      expect(
        variants.flatMap(({ allowed_headers_json }) => JSON.parse(allowed_headers_json!))
      ).toEqual([
        { name: 'bad-header-name', required: false, valueType: 'string' }
      ])

      const selectors = database.native
        .prepare(
          `SELECT kind, selector_json
           FROM request_variant_selectors
           WHERE scan_id = 'scan-legacy-a'
           ORDER BY kind ASC, selector_json ASC`
        )
        .all() as unknown as Array<{ kind: string; selector_json: string }>
      expect(selectors.map(({ kind }) => kind)).toEqual([
        'cookie',
        'graphql-variable',
        'header',
        'json-pointer',
        'query',
        'query'
      ])
      expect(
        selectors.find(({ kind }) => kind === 'json-pointer')?.selector_json
      ).toContain('/profile~1token')
      expect(
        JSON.parse(
          selectors.find(({ kind }) => kind === 'graphql-variable')!.selector_json
        ).variableName
      ).toMatch(/^legacy_[a-f0-9]{32}$/u)
      expect(selectors.some(({ selector_json }) => selector_json.includes('sentinel'))).toBe(
        false
      )

      const collisionVariants = database.native
        .prepare(
          `SELECT id, content_type, body_shape_json, codec, transport,
                  allowed_headers_json, template_version,
                  required_capability_ids_json, structure_hash
           FROM request_variants
           WHERE scan_id = 'scan-legacy-b'
           ORDER BY id ASC`
        )
        .all() as unknown as Array<Record<string, string | null>>
      expect(collisionVariants).toHaveLength(2)
      const collisionSelectorNames: string[][] = []
      for (const variant of collisionVariants) {
        const variantSelectors = database.native
          .prepare(
            `SELECT selector_json
             FROM request_variant_selectors
             WHERE request_variant_id = ?
             ORDER BY selector_json ASC`
          )
          .all(variant.id!) as unknown as Array<{ selector_json: string }>
        const parsedSelectors = variantSelectors.map(({ selector_json }) =>
          JSON.parse(selector_json)
        )
        collisionSelectorNames.push(
          parsedSelectors.map((selector) => String(selector.name)).sort()
        )
        expect(variant.structure_hash).toBe(
          canonicalTestHash({
            contentType: variant.content_type,
            bodyShape: JSON.parse(variant.body_shape_json!),
            codec: variant.codec,
            transport: variant.transport,
            allowedHeaders: JSON.parse(variant.allowed_headers_json!),
            templateVersion: variant.template_version,
            requiredCapabilityIds: JSON.parse(
              variant.required_capability_ids_json!
            ),
            selectors: parsedSelectors
          })
        )
      }
      expect(collisionSelectorNames.sort()).toEqual([['left'], ['right']])
      expect(new Set(collisionVariants.map(({ structure_hash }) => structure_hash)).size).toBe(2)

      expect(
        database.native
          .prepare(
          `SELECT source_type, confidence_ppm, initiator, review_status
             FROM inventory_sources
             WHERE scan_id = 'scan-legacy-a'
             ORDER BY source_type ASC`
          )
          .all()
      ).toEqual([
        {
          source_type: 'form',
          confidence_ppm: 0,
          initiator: null,
          review_status: 'unreviewed'
        },
        {
          source_type: 'xhr',
          confidence_ppm: 0,
          initiator: null,
          review_status: 'unreviewed'
        }
      ])
      expect(
        database.native
          .prepare('SELECT endpoint_id, parameter_id FROM signals WHERE id = ?')
          .get('signal-legacy')
      ).toEqual({
        endpoint_id: 'endpoint-legacy-a',
        parameter_id: 'parameter-query-a'
      })
      expect(
        database.native
          .prepare('SELECT endpoint_id, parameter_id FROM findings WHERE id = ?')
          .get('finding-legacy')
      ).toEqual({
        endpoint_id: 'endpoint-legacy-a',
        parameter_id: 'parameter-query-a'
      })
      expect(
        database.native
          .prepare('SELECT endpoint_id FROM interactions WHERE id = ?')
          .get('interaction-legacy')
      ).toEqual({ endpoint_id: 'endpoint-legacy-a' })
      expect(
        database.native
          .prepare('SELECT COUNT(*) AS count FROM parameters WHERE example_masked IS NOT NULL')
          .get()
      ).toEqual({ count: 0 })
      expect(
        JSON.stringify([
          ...database.native.prepare('SELECT * FROM targets').all(),
          ...database.native.prepare('SELECT * FROM pages').all(),
          ...database.native.prepare('SELECT * FROM endpoints').all(),
          ...database.native.prepare('SELECT * FROM request_variants').all(),
          ...database.native.prepare('SELECT * FROM request_variant_selectors').all(),
          ...database.native.prepare('SELECT * FROM inventory_sources').all(),
          ...database.native.prepare('SELECT * FROM parameters').all(),
          ...database.native.prepare('SELECT * FROM audit_logs').all()
        ])
      ).not.toContain('sentinel-')
      expect(
        JSON.stringify(database.native.prepare('SELECT * FROM endpoints').all())
      ).not.toMatch(/abcdefgh\.ijklmnop\.qrstuvwx|AbCdEfGhIjKlMnOpQrStUvWxYz012345/u)

      expect(
        database.native
          .prepare(
            `SELECT scan_id, family_id, module_id, module_version,
                    definition_hash, technique_id, technique_version,
                    strategy_refs_json, confirmation_rule_refs_json,
                    evidence_profile_refs_json, remediation_refs_json,
                    required_capability_ids_json, capability_descriptors_json,
                    capability_snapshot_hash, selected_capabilities_hash,
                    selected_definitions_hash, registry_snapshot_hash,
                    environment, authorization, snapshot_hash
             FROM scan_module_snapshots
             WHERE scan_id = 'scan-legacy-a'
             ORDER BY family_id ASC`
          )
          .all()
          .map((row) => (row as { family_id: string }).family_id)
      ).toEqual(['sqli', 'xss'])
      const snapshot = database.native
        .prepare(
          `SELECT family_id, module_id, module_version, definition_hash,
                  technique_id, technique_version, strategy_refs_json,
                  confirmation_rule_refs_json, evidence_profile_refs_json,
                  remediation_refs_json, required_capability_ids_json,
                  capability_descriptors_json, capability_snapshot_hash,
                  selected_capabilities_hash, selected_definitions_hash,
                  registry_snapshot_hash, environment, authorization, snapshot_hash
           FROM scan_module_snapshots
           WHERE scan_id = 'scan-legacy-a' AND family_id = 'sqli'`
        )
        .get() as Record<string, string>
      const snapshotDraft = {
        familyId: snapshot.family_id,
        moduleId: snapshot.module_id,
        moduleVersion: snapshot.module_version,
        definitionHash: snapshot.definition_hash,
        techniqueId: snapshot.technique_id,
        techniqueVersion: snapshot.technique_version,
        strategyRefs: JSON.parse(snapshot.strategy_refs_json!),
        confirmationRuleRefs: JSON.parse(snapshot.confirmation_rule_refs_json!),
        evidenceProfileRefs: JSON.parse(snapshot.evidence_profile_refs_json!),
        remediationRefs: JSON.parse(snapshot.remediation_refs_json!),
        requiredCapabilityIds: JSON.parse(snapshot.required_capability_ids_json!),
        capabilityDescriptors: JSON.parse(snapshot.capability_descriptors_json!),
        capabilitySnapshotHash: snapshot.capability_snapshot_hash,
        selectedCapabilitiesHash: snapshot.selected_capabilities_hash,
        selectedDefinitionsHash: snapshot.selected_definitions_hash,
        registrySnapshotHash: snapshot.registry_snapshot_hash,
        environment: snapshot.environment,
        authorization: snapshot.authorization
      }
      expect(snapshot.environment).toBe('legacy-unknown')
      expect(snapshot.selected_capabilities_hash).toBe(
        canonicalTestHash({ descriptors: snapshotDraft.capabilityDescriptors })
      )
      expect(snapshot.selected_definitions_hash).toBe(
        canonicalTestHash({
          familyId: snapshotDraft.familyId,
          moduleId: snapshotDraft.moduleId,
          moduleVersion: snapshotDraft.moduleVersion,
          moduleDefinitionHash: snapshotDraft.definitionHash,
          techniqueId: snapshotDraft.techniqueId,
          techniqueVersion: snapshotDraft.techniqueVersion,
          strategyRefs: snapshotDraft.strategyRefs,
          confirmationRuleRefs: snapshotDraft.confirmationRuleRefs,
          evidenceProfileRefs: snapshotDraft.evidenceProfileRefs,
          remediationRefs: snapshotDraft.remediationRefs
        })
      )
      expect(snapshot.snapshot_hash).toBe(canonicalTestHash(snapshotDraft))
      const migratedRepository = new AgentGoRepository(database)
      for (const target of await migratedRepository.listTargets('workspace-legacy')) {
        TargetSchema.parse(target)
      }
      InventoryEndpointRecordSchema.parse(
        await migratedRepository.getInventoryEndpointRecord(
          'endpoint-legacy-a',
          'scan-legacy-a'
        )
      )
      for (const variant of await migratedRepository.listInventoryRequestVariants(
        'scan-legacy-a'
      )) {
        RequestVariantRecordSchema.parse(variant)
      }
      for (const source of await migratedRepository.listInventorySources('scan-legacy-a')) {
        InventorySourceRecordSchema.parse(source)
      }
      for (const moduleSnapshot of await migratedRepository.listScanModuleSnapshots(
        'scan-legacy-a'
      )) {
        ScanModuleSnapshotRecordSchema.parse(moduleSnapshot)
      }
      expect(database.native.prepare('PRAGMA foreign_key_check').all()).toHaveLength(0)
    } finally {
      database.close()
    }

    const reopened = openAgentGoDatabase(filePath)
    try {
      expect(
        reopened.native
          .prepare('SELECT COUNT(*) AS count FROM endpoints WHERE scan_id = ?')
          .get('scan-legacy-a')
      ).toEqual({ count: 1 })
      expect(
        reopened.native
          .prepare('SELECT COUNT(*) AS count FROM inventory_sources WHERE scan_id = ?')
          .get('scan-legacy-a')
      ).toEqual({ count: 2 })
      expect(
        reopened.native
          .prepare('SELECT COUNT(*) AS count FROM scan_module_snapshots')
          .get()
      ).toEqual({ count: 3 })
    } finally {
      reopened.close()
    }
  })

  it('rejects cross-scan inventory links and keeps module snapshots immutable', () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-inventory-guards-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    createLegacyInventoryDatabase(filePath)
    const database = openAgentGoDatabase(filePath)
    const hash = 'b'.repeat(64)

    try {
      expect(() =>
        database.native
          .prepare(
            `INSERT INTO endpoints (
               id, scan_id, page_id, method, url_template, normalized_url,
               canonical_route, content_type, source, status, lifecycle_status,
               created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            'endpoint-cross-scan',
            'scan-legacy-b',
            'page-legacy-a',
            'GET',
            'https://lab.example.test/cross',
            'https://lab.example.test/cross',
            'https://lab.example.test/cross',
            null,
            'test',
            'discovered',
            'active',
            1,
            1
          )
      ).toThrow(/endpoint page must belong to scan/)

      expect(() =>
        database.native
          .prepare(
            `INSERT INTO request_variants (
               id, scan_id, endpoint_id, content_type, body_shape_json,
               codec, transport, allowed_headers_json, redacted_preview_json,
               template_version, required_capability_ids_json, review_status,
               reviewed_by, reviewed_at, execution_class, lifecycle_status,
               retired_at, structure_hash, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            'variant-cross-scan',
            'scan-legacy-b',
            'endpoint-legacy-a',
            null,
            '{"fields":[],"rootType":"none"}',
            'none',
            'standard-http',
            '[]',
            '{"url":"https://lab.example.test/search/:redacted/:redacted/:redacted"}',
            '1.0.0',
            '[]',
            'unreviewed',
            null,
            null,
            'inventory-only',
            'active',
            null,
            hash,
            1,
            1
          )
      ).toThrow(/request variant endpoint must belong to scan/)

      const variantId = (
        database.native
          .prepare('SELECT id FROM request_variants WHERE scan_id = ? LIMIT 1')
          .get('scan-legacy-a') as { id: string }
      ).id
      expect(() =>
        database.native
          .prepare(
            `INSERT INTO request_variant_selectors (
               id, scan_id, request_variant_id, kind,
               selector_json, structure_hash, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            'selector-cross-scan',
            'scan-legacy-b',
            variantId,
            'query',
            '{"kind":"query","name":"q","required":false,"valueType":"string"}',
            hash,
            1
          )
      ).toThrow(/request selector variant must belong to scan/)

      expect(() =>
        database.native
          .prepare(
            `INSERT INTO inventory_sources (
               id, scan_id, endpoint_id, request_variant_id,
               source_type, source_hash, provenance_hash, page_id,
               evidence_ref, initiator, confidence_ppm, discovered_at,
               review_status, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            'source-cross-scan',
            'scan-legacy-b',
            'endpoint-legacy-a',
            variantId,
            'test',
            hash,
            hash,
            null,
            null,
            null,
            0,
            1,
            'unreviewed',
            1
          )
      ).toThrow(/inventory source references must belong to one scan/)

      const snapshotId = (
        database.native
          .prepare('SELECT id FROM scan_module_snapshots WHERE scan_id = ?')
          .get('scan-legacy-b') as { id: string }
      ).id
      expect(() =>
        database.native
          .prepare('UPDATE scan_module_snapshots SET environment = ? WHERE id = ?')
          .run('authorized-real-target', snapshotId)
      ).toThrow(/scan module snapshots are immutable/)
      expect(() =>
        database.native
          .prepare('DELETE FROM scan_module_snapshots WHERE id = ?')
          .run(snapshotId)
      ).toThrow(/scan module snapshots are immutable/)
      expect(
        database.native
          .prepare(
            `SELECT module_snapshots_sealed AS sealed
             FROM scans
             WHERE id = 'scan-legacy-b'`
          )
          .get()
      ).toEqual({ sealed: 1 })
      expect(() =>
        database.native
          .prepare(
            `UPDATE scans
             SET module_snapshots_sealed = 0
             WHERE id = 'scan-legacy-b'`
          )
          .run()
      ).toThrow(/seal is immutable/)
      expect(() =>
        database.native
          .prepare(
            `INSERT INTO scan_module_snapshots (
               id, scan_id, family_id, module_id, module_version,
               definition_hash, technique_id, technique_version,
               strategy_refs_json, confirmation_rule_refs_json,
               evidence_profile_refs_json, remediation_refs_json,
               required_capability_ids_json, capability_descriptors_json,
               capability_snapshot_hash, selected_capabilities_hash,
               selected_definitions_hash, registry_snapshot_hash, environment,
               authorization, snapshot_hash, created_at
             )
             SELECT 'snapshot-sealed-extra', scan_id, 'synthetic.extra',
                    module_id, module_version, definition_hash,
                    'synthetic.extra.technique', technique_version,
                    strategy_refs_json, confirmation_rule_refs_json,
                    evidence_profile_refs_json, remediation_refs_json,
                    required_capability_ids_json, capability_descriptors_json,
                    capability_snapshot_hash, selected_capabilities_hash,
                    selected_definitions_hash, registry_snapshot_hash,
                    environment, authorization, snapshot_hash, created_at
             FROM scan_module_snapshots
             WHERE id = ?`
          )
          .run(snapshotId)
      ).toThrow(/snapshot set is sealed/)

      database.native.prepare('DELETE FROM scans WHERE id = ?').run('scan-legacy-b')
      expect(
        database.native
          .prepare('SELECT COUNT(*) AS count FROM scan_module_snapshots WHERE scan_id = ?')
          .get('scan-legacy-b')
      ).toEqual({ count: 0 })
      expect(database.native.prepare('PRAGMA foreign_key_check').all()).toHaveLength(0)
    } finally {
      database.close()
    }
  })

  it('rolls back all 0006 SQL and data-hook changes when finalization fails', () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-inventory-atomic-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    createLegacyInventoryDatabase(filePath)
    const native = new DatabaseSync(filePath, {
      enableForeignKeyConstraints: true
    })
    const migration = DATABASE_MIGRATIONS.find(
      ({ id }) => id === '0006_unified_inventory_and_module_snapshots'
    )
    expect(migration?.id).toBe('0006_unified_inventory_and_module_snapshots')
    const failingMigration: DatabaseMigration = {
      ...migration!,
      finalizeSql: `${migration!.finalizeSql ?? ''}\nSELECT * FROM synthetic_missing_table;`
    }

    try {
      expect(() =>
        applyDatabaseMigrations(native, {
          migrations: [failingMigration],
          appliedAt: () => 1_783_920_144_305
        })
      ).toThrow(/synthetic_missing_table/)
      expect(
        native
          .prepare('SELECT 1 FROM __agentgo_migrations WHERE id = ?')
          .get(failingMigration.id)
      ).toBeUndefined()
      expect(
        native
          .prepare('PRAGMA table_info(endpoints)')
          .all()
          .map((column) => (column as { name: string }).name)
      ).not.toContain('canonical_route')
      expect(
        native
          .prepare(
            `SELECT COUNT(*) AS count
             FROM sqlite_schema
             WHERE type = 'table' AND name = 'request_variants'`
          )
          .get()
      ).toEqual({ count: 0 })
      expect(
        native.prepare('SELECT COUNT(*) AS count FROM endpoints').get()
      ).toEqual({ count: 4 })
      expect(
        native
          .prepare('SELECT endpoint_id, parameter_id FROM signals WHERE id = ?')
          .get('signal-legacy')
      ).toEqual({
        endpoint_id: 'endpoint-legacy-b',
        parameter_id: 'parameter-query-b'
      })
    } finally {
      native.close()
    }

    const migrated = openAgentGoDatabase(filePath)
    try {
      expect(
        migrated.native
          .prepare('SELECT COUNT(*) AS count FROM endpoints WHERE scan_id = ?')
          .get('scan-legacy-a')
      ).toEqual({ count: 1 })
      expect(
        migrated.native
          .prepare('SELECT 1 AS applied FROM __agentgo_migrations WHERE id = ?')
          .get('0006_unified_inventory_and_module_snapshots')
      ).toEqual({ applied: 1 })
    } finally {
      migrated.close()
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
        networkEntries: [],
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
        networkEntries: [],
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
    const plan = createDefaultScanPlan(['sqli'])
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

  it('upgrades an execution database to the additive protected Evidence schema exactly once', () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-migration-'))
    temporaryDirectories.push(directory)
    const filePath = join(directory, 'agentgo.sqlite')
    const database = new DatabaseSync(filePath, {
      enableForeignKeyConstraints: true
    })
    try {
      const protectedEvidenceIndex = DATABASE_MIGRATIONS.findIndex(
        (migration) => migration.id === '0010_protected_evidence_envelopes'
      )
      const previousMigrations = DATABASE_MIGRATIONS.slice(
        0,
        protectedEvidenceIndex
      )
      applyDatabaseMigrations(database, {
        migrations: previousMigrations,
        appliedAt: () => 1_785_340_800_000
      })
      expect(
        database
          .prepare(
            `SELECT name FROM sqlite_master
              WHERE type = 'table'
                AND name = 'protected_evidence_items'`
          )
          .get()
      ).toBeUndefined()

      applyDatabaseMigrations(database, {
        migrations: DATABASE_MIGRATIONS,
        appliedAt: () => 1_785_340_800_001
      })
      const columns = database
        .prepare('PRAGMA table_info(protected_evidence_items)')
        .all() as unknown as Array<{ name: string }>
      expect(columns.map(({ name }) => name)).toEqual(
        expect.arrayContaining([
          'evidence_id',
          'derivative_evidence_id',
          'derivative_sha256',
          'capture_artifact_json',
          'wrapped_data_key',
          'availability_state',
          'retention_until'
        ])
      )
      applyDatabaseMigrations(database, {
        migrations: DATABASE_MIGRATIONS,
        appliedAt: () => 1_785_340_800_002
      })
      const ledger = database
        .prepare(
          `SELECT count(*) AS count
             FROM __agentgo_migrations
            WHERE id = '0010_protected_evidence_envelopes'`
        )
        .get() as { count: number }
      expect(ledger.count).toBe(1)
    } finally {
      database.close()
    }
  })
})
