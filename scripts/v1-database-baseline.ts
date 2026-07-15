import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { createHash } from 'node:crypto'
import { basename, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import { DATABASE_MIGRATIONS } from '../packages/db/src/migrations'
import { sha256Text, stableJson } from '../packages/db/src/repository'

export const V1_BASELINE_FIXTURE_VERSION = 'agentgo-v1-synthetic-baseline@1'
export const V1_BASELINE_DATABASE_FILE = 'agentgo-v1-synthetic-baseline.sqlite'
export const V1_BASELINE_MANIFEST_FILE =
  'agentgo-v1-synthetic-baseline.manifest.json'

const FIXED_TIMESTAMP = 1_783_920_000_000
const FIXTURE_IDS = {
  workspace: 'synthetic-v1-workspace',
  target: 'synthetic-v1-target',
  scope: 'synthetic-v1-scope',
  scan: 'synthetic-v1-scan'
} as const
const FIXTURE_ORIGIN = 'https://v1-baseline.agentgo.invalid'
const FIXTURE_AUTHORIZATION_REFERENCE = 'synthetic-fixture-attestation-v1'
const EXPECTED_RECORD_COUNTS = {
  workspaces: 1,
  targets: 1,
  target_scopes: 1,
  scans: 1
} as const
const FTS_INTERNAL_TABLES = new Set([
  'knowledge_chunks_fts_data',
  'knowledge_chunks_fts_idx',
  'knowledge_chunks_fts_docsize',
  'knowledge_chunks_fts_config'
])

const fixtureScope = {
  allowedOrigins: [FIXTURE_ORIGIN],
  allowedPathPrefixes: ['/synthetic'],
  deniedPathPrefixes: ['/synthetic/destructive'],
  allowedPorts: [443],
  allowedIdentityIds: [],
  allowActiveProbing: true,
  allowSensitiveProbing: false,
  allowPrivateNetworkTargets: false,
  allowLoopbackTargets: false,
  maxRequestsPerMinute: 12,
  maxConcurrency: 1,
  authorizationReference: FIXTURE_AUTHORIZATION_REFERENCE
} as const

const fixtureBudget = {
  maxRequests: 24,
  maxRequestsPerMinute: 12,
  maxConcurrency: 1,
  maxPlanRevisions: 1,
  maxDurationMinutes: 10,
  maxModelTokens: 0,
  maxEstimatedCost: 0
} as const

const fixtureConfig = {
  description: 'Deterministic synthetic migration fixture; never execute.',
  families: ['sqli', 'xss', 'ssrf', 'idor'],
  identityIds: [],
  modelProfileIds: {}
} as const

const fixturePlan = {
  version: V1_BASELINE_FIXTURE_VERSION,
  phases: ['intake'],
  families: ['sqli', 'xss', 'ssrf', 'idor'],
  budget: fixtureBudget,
  stopConditions: ['Synthetic fixture only; no network execution is authorized.']
} as const

const fixtureRuntime = {
  phase: 'intake',
  status: 'running',
  checkpointRefs: [],
  actionFingerprints: [],
  planRevisions: 0,
  noEvidenceStreak: 0
} as const

export interface V1BaselineManifest {
  manifestVersion: 1
  fixtureVersion: string
  schemaVersion: string
  migrationIds: string[]
  databaseFile: string
  databaseSha256: string
  logicalContentSha256: string
  recordCounts: Record<keyof typeof EXPECTED_RECORD_COUNTS, number>
}

export interface V1BaselineArtifact extends V1BaselineManifest {
  outputDirectory: string
  databasePath: string
  manifestPath: string
}

export interface V1BaselineVerification {
  fixtureVersion: string
  schemaVersion: string
  migrationIds: string[]
  databaseSha256: string
  logicalContentSha256: string
  recordCounts: Record<keyof typeof EXPECTED_RECORD_COUNTS, number>
}

function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`V1 baseline verification failed: ${message}`)
  }
}

function sha256File(filePath: string): string {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex')
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`
}

function scalarCount(database: DatabaseSync, tableName: string): number {
  const row = database
    .prepare(`SELECT COUNT(*) AS count FROM ${quoteIdentifier(tableName)}`)
    .get() as { count: number | bigint } | undefined
  return Number(row?.count ?? 0)
}

function removeKnownFile(filePath: string): void {
  rmSync(filePath, { force: true })
}

function removeDatabaseSidecars(filePath: string): void {
  removeKnownFile(`${filePath}-wal`)
  removeKnownFile(`${filePath}-shm`)
  removeKnownFile(`${filePath}-journal`)
}

function applyCurrentMigrations(database: DatabaseSync): void {
  database.exec(`
    CREATE TABLE __agentgo_migrations (
      id TEXT PRIMARY KEY,
      applied_at INTEGER NOT NULL
    );
  `)
  const recordMigration = database.prepare(
    'INSERT INTO __agentgo_migrations (id, applied_at) VALUES (?, ?)'
  )

  for (const migration of DATABASE_MIGRATIONS) {
    database.exec('BEGIN IMMEDIATE')
    try {
      database.exec(migration.sql)
      recordMigration.run(migration.id, FIXED_TIMESTAMP)
      database.exec('COMMIT')
    } catch (error) {
      database.exec('ROLLBACK')
      throw error
    }
  }
}

function insertSyntheticFixture(database: DatabaseSync): void {
  const scopeHash = sha256Text(stableJson(fixtureScope))

  database.exec('BEGIN IMMEDIATE')
  try {
    database
      .prepare(
        `INSERT INTO workspaces (
           id, name, description, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?)`
      )
      .run(
        FIXTURE_IDS.workspace,
        'Synthetic V1 Migration Workspace',
        'Reserved deterministic data for migration verification only.',
        FIXED_TIMESTAMP,
        FIXED_TIMESTAMP
      )

    database
      .prepare(
        `INSERT INTO targets (
           id, workspace_id, name, base_url, description,
           authorization_reference, default_identity_id, current_scope_id,
           created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        FIXTURE_IDS.target,
        FIXTURE_IDS.workspace,
        'Synthetic V1 Migration Target',
        `${FIXTURE_ORIGIN}/`,
        'Reserved .invalid target; no network execution is authorized.',
        FIXTURE_AUTHORIZATION_REFERENCE,
        null,
        null,
        FIXED_TIMESTAMP,
        FIXED_TIMESTAMP
      )

    database
      .prepare(
        `INSERT INTO target_scopes (
           id, target_id, allowed_origins, allowed_path_prefixes,
           denied_path_prefixes, allowed_ports, allowed_identity_ids,
           allow_active_probing, allow_sensitive_probing,
           allow_private_network_targets, allow_loopback_targets,
           max_requests_per_minute, max_concurrency, authorization_reference,
           valid_from, valid_until, snapshot_hash, created_at, revision
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        FIXTURE_IDS.scope,
        FIXTURE_IDS.target,
        stableJson(fixtureScope.allowedOrigins),
        stableJson(fixtureScope.allowedPathPrefixes),
        stableJson(fixtureScope.deniedPathPrefixes),
        stableJson(fixtureScope.allowedPorts),
        stableJson(fixtureScope.allowedIdentityIds),
        Number(fixtureScope.allowActiveProbing),
        Number(fixtureScope.allowSensitiveProbing),
        Number(fixtureScope.allowPrivateNetworkTargets),
        Number(fixtureScope.allowLoopbackTargets),
        fixtureScope.maxRequestsPerMinute,
        fixtureScope.maxConcurrency,
        fixtureScope.authorizationReference,
        null,
        null,
        scopeHash,
        FIXED_TIMESTAMP,
        1
      )

    database
      .prepare('UPDATE targets SET current_scope_id = ? WHERE id = ?')
      .run(FIXTURE_IDS.scope, FIXTURE_IDS.target)

    database
      .prepare(
        `INSERT INTO scans (
           id, target_id, name, scope_snapshot_id, status, phase, progress,
           budget_json, config_json, plan_json, runtime_json,
           request_count, model_tokens, estimated_cost_micros,
           checkpoint_count, last_error, created_at, updated_at,
           started_at, completed_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        FIXTURE_IDS.scan,
        FIXTURE_IDS.target,
        'Synthetic V1 Migration Scan',
        FIXTURE_IDS.scope,
        'draft',
        'intake',
        0,
        stableJson(fixtureBudget),
        stableJson(fixtureConfig),
        stableJson(fixturePlan),
        stableJson(fixtureRuntime),
        0,
        0,
        0,
        0,
        null,
        FIXED_TIMESTAMP,
        FIXED_TIMESTAMP,
        null,
        null
      )

    database.exec('COMMIT')
  } catch (error) {
    database.exec('ROLLBACK')
    throw error
  }
}

function createDeterministicDatabase(filePath: string): void {
  removeKnownFile(filePath)
  removeDatabaseSidecars(filePath)

  const database = new DatabaseSync(filePath, {
    allowExtension: false,
    enableDoubleQuotedStringLiterals: false,
    enableForeignKeyConstraints: true,
    timeout: 5_000
  })

  try {
    database.exec('PRAGMA journal_mode = DELETE;')
    database.exec('PRAGMA synchronous = FULL;')
    database.exec('PRAGMA temp_store = MEMORY;')
    database.exec('PRAGMA page_size = 4096;')
    database.exec('PRAGMA auto_vacuum = NONE;')
    database.exec('PRAGMA trusted_schema = OFF;')
    applyCurrentMigrations(database)
    insertSyntheticFixture(database)
    database.exec(`PRAGMA user_version = ${DATABASE_MIGRATIONS.length};`)
    database.exec('VACUUM;')
  } finally {
    database.close()
  }

  removeDatabaseSidecars(filePath)
}

function expectedSchemaVersion(): string {
  const latest = DATABASE_MIGRATIONS.at(-1)
  invariant(latest, 'DATABASE_MIGRATIONS must not be empty')
  return latest.id
}

function validateManifest(value: unknown): V1BaselineManifest {
  invariant(value !== null && typeof value === 'object', 'manifest must be an object')
  const manifest = value as Record<string, unknown>
  invariant(manifest.manifestVersion === 1, 'manifestVersion must be 1')
  invariant(
    manifest.fixtureVersion === V1_BASELINE_FIXTURE_VERSION,
    `fixtureVersion must be ${V1_BASELINE_FIXTURE_VERSION}`
  )
  invariant(typeof manifest.schemaVersion === 'string', 'schemaVersion must be a string')
  invariant(Array.isArray(manifest.migrationIds), 'migrationIds must be an array')
  invariant(
    manifest.migrationIds.every((id) => typeof id === 'string'),
    'every migration ID must be a string'
  )
  invariant(
    manifest.databaseFile === V1_BASELINE_DATABASE_FILE,
    `databaseFile must be ${V1_BASELINE_DATABASE_FILE}`
  )
  invariant(
    typeof manifest.databaseSha256 === 'string' &&
      /^[a-f0-9]{64}$/.test(manifest.databaseSha256),
    'databaseSha256 must be a lowercase SHA-256 digest'
  )
  invariant(
    typeof manifest.logicalContentSha256 === 'string' &&
      /^[a-f0-9]{64}$/.test(manifest.logicalContentSha256),
    'logicalContentSha256 must be a lowercase SHA-256 digest'
  )
  invariant(
    manifest.recordCounts !== null && typeof manifest.recordCounts === 'object',
    'recordCounts must be an object'
  )
  const recordCounts = manifest.recordCounts as Record<string, unknown>
  for (const [tableName, count] of Object.entries(EXPECTED_RECORD_COUNTS)) {
    invariant(recordCounts[tableName] === count, `${tableName} manifest count must be ${count}`)
  }

  return {
    manifestVersion: 1,
    fixtureVersion: manifest.fixtureVersion,
    schemaVersion: manifest.schemaVersion,
    migrationIds: [...manifest.migrationIds] as string[],
    databaseFile: manifest.databaseFile,
    databaseSha256: manifest.databaseSha256,
    logicalContentSha256: manifest.logicalContentSha256,
    recordCounts: { ...EXPECTED_RECORD_COUNTS }
  }
}

function readAndValidateManifest(manifestPath: string): V1BaselineManifest {
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown
  } catch (error) {
    throw new Error(
      `V1 baseline verification failed: cannot parse manifest ${basename(manifestPath)}`,
      { cause: error }
    )
  }
  return validateManifest(parsed)
}

function readApplicationRows(database: DatabaseSync): unknown[] {
  const rows: unknown[] = []
  for (const tableName of Object.keys(EXPECTED_RECORD_COUNTS)) {
    rows.push(
      ...database.prepare(`SELECT * FROM ${quoteIdentifier(tableName)}`).all()
    )
  }
  return rows
}

function assertNoSensitiveOrLocalValues(database: DatabaseSync): void {
  const serializedRows = JSON.stringify(readApplicationRows(database))
  const forbiddenSecrets = [
    /api[_-]?key\s*[=:]/i,
    /(?:password|passwd)\s*[=:]/i,
    /authorization\s*:\s*(?:basic|bearer)\s+/i,
    /bearer\s+[a-z0-9._~+/=-]{8,}/i,
    /(?:cookie|session[_-]?token|access[_-]?token|refresh[_-]?token)\s*[=:]/i,
    /(?:client[_-]?secret|private[_-]?key)\s*[=:]/i
  ]
  const localPathPatterns = [
    /[a-z]:\\(?:users|windows|program files|tmp|temp)\\/i,
    /\\\\[^\\]+\\[^\\]+/,
    /\/(?:home|users|var|tmp|private)\//i,
    /file:\/\//i
  ]

  invariant(
    forbiddenSecrets.every((pattern) => !pattern.test(serializedRows)),
    'fixture data contains a credential- or secret-shaped value'
  )
  invariant(
    localPathPatterns.every((pattern) => !pattern.test(serializedRows)),
    'fixture data contains a local filesystem path'
  )
}

function assertExactSyntheticFixture(database: DatabaseSync): void {
  const workspace = database
    .prepare(
      `SELECT id, name, description, created_at, updated_at
       FROM workspaces`
    )
    .get() as Record<string, unknown> | undefined
  invariant(workspace?.id === FIXTURE_IDS.workspace, 'unexpected workspace ID')
  invariant(
    workspace.name === 'Synthetic V1 Migration Workspace',
    'unexpected workspace name'
  )
  invariant(workspace.created_at === FIXED_TIMESTAMP, 'workspace timestamp is not fixed')
  invariant(workspace.updated_at === FIXED_TIMESTAMP, 'workspace timestamp is not fixed')

  const target = database
    .prepare(
      `SELECT id, workspace_id, base_url, authorization_reference,
              default_identity_id, current_scope_id, created_at, updated_at
       FROM targets`
    )
    .get() as Record<string, unknown> | undefined
  invariant(target?.id === FIXTURE_IDS.target, 'unexpected target ID')
  invariant(target.workspace_id === FIXTURE_IDS.workspace, 'target workspace mismatch')
  invariant(target.base_url === `${FIXTURE_ORIGIN}/`, 'target must use the reserved .invalid URL')
  invariant(
    target.authorization_reference === FIXTURE_AUTHORIZATION_REFERENCE,
    'target attestation reference mismatch'
  )
  invariant(target.default_identity_id === null, 'fixture target must have no identity')
  invariant(target.current_scope_id === FIXTURE_IDS.scope, 'target scope head mismatch')
  invariant(target.created_at === FIXED_TIMESTAMP, 'target timestamp is not fixed')
  invariant(target.updated_at === FIXED_TIMESTAMP, 'target timestamp is not fixed')

  const scope = database
    .prepare(
      `SELECT id, target_id, allowed_origins, allowed_path_prefixes,
              denied_path_prefixes, allowed_ports, allowed_identity_ids,
              allow_active_probing, allow_sensitive_probing,
              allow_private_network_targets, allow_loopback_targets,
              max_requests_per_minute, max_concurrency,
              authorization_reference, valid_from, valid_until,
              snapshot_hash, created_at, revision
       FROM target_scopes`
    )
    .get() as Record<string, unknown> | undefined
  invariant(scope?.id === FIXTURE_IDS.scope, 'unexpected scope ID')
  invariant(scope.target_id === FIXTURE_IDS.target, 'scope target mismatch')
  invariant(scope.allowed_origins === stableJson(fixtureScope.allowedOrigins), 'scope origin mismatch')
  invariant(
    scope.allowed_path_prefixes === stableJson(fixtureScope.allowedPathPrefixes),
    'scope allowed paths mismatch'
  )
  invariant(
    scope.denied_path_prefixes === stableJson(fixtureScope.deniedPathPrefixes),
    'scope denied paths mismatch'
  )
  invariant(scope.allowed_ports === stableJson(fixtureScope.allowedPorts), 'scope ports mismatch')
  invariant(scope.allowed_identity_ids === '[]', 'fixture scope must have no identities')
  invariant(scope.allow_active_probing === 1, 'scope active-probing flag mismatch')
  invariant(scope.allow_sensitive_probing === 0, 'scope must disable sensitive probing')
  invariant(scope.allow_private_network_targets === 0, 'scope must disable private targets')
  invariant(scope.allow_loopback_targets === 0, 'scope must disable loopback targets')
  invariant(scope.valid_from === null && scope.valid_until === null, 'scope validity must be synthetic and open')
  invariant(scope.revision === 1, 'scope revision must be 1')
  invariant(
    scope.snapshot_hash === sha256Text(stableJson(fixtureScope)),
    'scope snapshot hash mismatch'
  )
  invariant(scope.created_at === FIXED_TIMESTAMP, 'scope timestamp is not fixed')

  const scan = database
    .prepare(
      `SELECT id, target_id, name, scope_snapshot_id, status, phase,
              progress, budget_json, config_json, plan_json, runtime_json,
              request_count, model_tokens, estimated_cost_micros,
              checkpoint_count, last_error, created_at, updated_at,
              started_at, completed_at
       FROM scans`
    )
    .get() as Record<string, unknown> | undefined
  invariant(scan?.id === FIXTURE_IDS.scan, 'unexpected scan ID')
  invariant(scan.target_id === FIXTURE_IDS.target, 'scan target mismatch')
  invariant(scan.scope_snapshot_id === FIXTURE_IDS.scope, 'scan scope snapshot mismatch')
  invariant(scan.status === 'draft' && scan.phase === 'intake', 'scan state mismatch')
  invariant(scan.progress === 0 && scan.request_count === 0, 'scan must have no activity')
  invariant(scan.model_tokens === 0 && scan.estimated_cost_micros === 0, 'scan must have no model usage')
  invariant(scan.checkpoint_count === 0, 'scan must have no checkpoints')
  invariant(scan.last_error === null, 'scan must not contain an error')
  invariant(scan.budget_json === stableJson(fixtureBudget), 'scan budget mismatch')
  invariant(scan.config_json === stableJson(fixtureConfig), 'scan configuration mismatch')
  invariant(scan.plan_json === stableJson(fixturePlan), 'scan plan mismatch')
  invariant(scan.runtime_json === stableJson(fixtureRuntime), 'scan runtime mismatch')
  invariant(scan.created_at === FIXED_TIMESTAMP, 'scan timestamp is not fixed')
  invariant(scan.updated_at === FIXED_TIMESTAMP, 'scan timestamp is not fixed')
  invariant(scan.started_at === null && scan.completed_at === null, 'scan must never have run')
}

function logicalContentSha256(
  database: DatabaseSync,
  migrationIds: string[]
): string {
  const rows = Object.fromEntries(
    Object.keys(EXPECTED_RECORD_COUNTS).map((tableName) => [
      tableName,
      database
        .prepare(`SELECT * FROM ${quoteIdentifier(tableName)} ORDER BY id ASC`)
        .all()
        .map((row) => ({ ...(row as Record<string, unknown>) }))
    ])
  )
  return sha256Text(stableJson({ migrationIds, rows }))
}

function verifyDatabaseContents(databasePath: string): {
  recordCounts: V1BaselineVerification['recordCounts']
  logicalContentSha256: string
} {
  const database = new DatabaseSync(databasePath, {
    allowExtension: false,
    enableDoubleQuotedStringLiterals: false,
    enableForeignKeyConstraints: true,
    readOnly: true,
    timeout: 5_000
  })

  try {
    const integrity = database.prepare('PRAGMA integrity_check').get() as
      | { integrity_check: string }
      | undefined
    invariant(integrity?.integrity_check === 'ok', 'SQLite integrity_check did not return ok')
    invariant(
      database.prepare('PRAGMA foreign_key_check').all().length === 0,
      'SQLite foreign_key_check found violations'
    )

    const recordedMigrations = database
      .prepare('SELECT id FROM __agentgo_migrations ORDER BY rowid ASC')
      .all()
      .map((row) => (row as { id: string }).id)
    const expectedMigrationIds = DATABASE_MIGRATIONS.map((migration) => migration.id)
    invariant(
      stableJson(recordedMigrations) === stableJson(expectedMigrationIds),
      'database migration IDs do not match DATABASE_MIGRATIONS'
    )
    const userVersion = database.prepare('PRAGMA user_version').get() as
      | { user_version: number }
      | undefined
    invariant(
      userVersion?.user_version === DATABASE_MIGRATIONS.length,
      'SQLite user_version does not match the migration count'
    )

    const recordCounts = {
      workspaces: scalarCount(database, 'workspaces'),
      targets: scalarCount(database, 'targets'),
      target_scopes: scalarCount(database, 'target_scopes'),
      scans: scalarCount(database, 'scans')
    }
    for (const [tableName, expectedCount] of Object.entries(EXPECTED_RECORD_COUNTS)) {
      invariant(
        recordCounts[tableName as keyof typeof recordCounts] === expectedCount,
        `${tableName} must contain exactly ${expectedCount} synthetic row(s)`
      )
    }

    const applicationTables = database
      .prepare(
        `SELECT name
         FROM sqlite_schema
         WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%'
         ORDER BY name ASC`
      )
      .all()
      .map((row) => (row as { name: string }).name)
    for (const tableName of applicationTables) {
      if (
        tableName === '__agentgo_migrations' ||
        tableName in EXPECTED_RECORD_COUNTS ||
        FTS_INTERNAL_TABLES.has(tableName)
      ) {
        continue
      }
      invariant(
        scalarCount(database, tableName) === 0,
        `${tableName} must be empty in a synthetic-only baseline`
      )
    }

    invariant(scalarCount(database, 'evidence_items') === 0, 'Evidence items must be empty')
    invariant(scalarCount(database, 'finding_evidence') === 0, 'Finding Evidence links must be empty')
    invariant(scalarCount(database, 'identities') === 0, 'Identities and credential references must be empty')
    invariant(scalarCount(database, 'model_profiles') === 0, 'Model profiles and credential references must be empty')
    invariant(scalarCount(database, 'mcp_servers') === 0, 'MCP servers and credential references must be empty')

    assertExactSyntheticFixture(database)
    assertNoSensitiveOrLocalValues(database)
    return {
      recordCounts,
      logicalContentSha256: logicalContentSha256(database, recordedMigrations)
    }
  } finally {
    database.close()
  }
}

function artifactPaths(directory: string): {
  outputDirectory: string
  databasePath: string
  manifestPath: string
} {
  const outputDirectory = resolve(directory)
  return {
    outputDirectory,
    databasePath: join(outputDirectory, V1_BASELINE_DATABASE_FILE),
    manifestPath: join(outputDirectory, V1_BASELINE_MANIFEST_FILE)
  }
}

export function generateV1DatabaseBaseline(outputDirectory: string): V1BaselineArtifact {
  invariant(outputDirectory.trim().length > 0, 'an output directory is required')
  const paths = artifactPaths(outputDirectory)
  mkdirSync(paths.outputDirectory, { recursive: true })

  const temporaryDatabasePath = join(
    paths.outputDirectory,
    `.${V1_BASELINE_DATABASE_FILE}.${process.pid}.tmp`
  )
  const temporaryManifestPath = join(
    paths.outputDirectory,
    `.${V1_BASELINE_MANIFEST_FILE}.${process.pid}.tmp`
  )
  removeKnownFile(temporaryDatabasePath)
  removeKnownFile(temporaryManifestPath)

  try {
    createDeterministicDatabase(temporaryDatabasePath)
    const verifiedDatabase = verifyDatabaseContents(temporaryDatabasePath)
    const manifest: V1BaselineManifest = {
      manifestVersion: 1,
      fixtureVersion: V1_BASELINE_FIXTURE_VERSION,
      schemaVersion: expectedSchemaVersion(),
      migrationIds: DATABASE_MIGRATIONS.map((migration) => migration.id),
      databaseFile: V1_BASELINE_DATABASE_FILE,
      databaseSha256: sha256File(temporaryDatabasePath),
      logicalContentSha256: verifiedDatabase.logicalContentSha256,
      recordCounts: verifiedDatabase.recordCounts
    }
    writeFileSync(temporaryManifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')

    removeKnownFile(paths.databasePath)
    removeDatabaseSidecars(paths.databasePath)
    renameSync(temporaryDatabasePath, paths.databasePath)
    removeKnownFile(paths.manifestPath)
    renameSync(temporaryManifestPath, paths.manifestPath)

    return { ...manifest, ...paths }
  } finally {
    removeKnownFile(temporaryDatabasePath)
    removeDatabaseSidecars(temporaryDatabasePath)
    removeKnownFile(temporaryManifestPath)
  }
}

export function verifyV1DatabaseBaseline(inputDirectory: string): V1BaselineVerification {
  invariant(inputDirectory.trim().length > 0, 'an input directory is required')
  const paths = artifactPaths(inputDirectory)
  invariant(existsSync(paths.manifestPath), `${V1_BASELINE_MANIFEST_FILE} is missing`)
  invariant(existsSync(paths.databasePath), `${V1_BASELINE_DATABASE_FILE} is missing`)
  invariant(!existsSync(`${paths.databasePath}-wal`), 'database WAL sidecar must not be present')
  invariant(!existsSync(`${paths.databasePath}-shm`), 'database SHM sidecar must not be present')

  const manifest = readAndValidateManifest(paths.manifestPath)
  const expectedMigrationIds = DATABASE_MIGRATIONS.map((migration) => migration.id)
  invariant(
    manifest.schemaVersion === expectedSchemaVersion(),
    'manifest schemaVersion does not match the latest migration'
  )
  invariant(
    stableJson(manifest.migrationIds) === stableJson(expectedMigrationIds),
    'manifest migration IDs do not match DATABASE_MIGRATIONS'
  )
  const databaseSha256 = sha256File(paths.databasePath)
  invariant(
    databaseSha256 === manifest.databaseSha256,
    'database SHA-256 does not match the manifest'
  )
  const verifiedDatabase = verifyDatabaseContents(paths.databasePath)
  invariant(
    verifiedDatabase.logicalContentSha256 === manifest.logicalContentSha256,
    'logical content SHA-256 does not match the manifest'
  )

  return {
    fixtureVersion: manifest.fixtureVersion,
    schemaVersion: manifest.schemaVersion,
    migrationIds: manifest.migrationIds,
    databaseSha256,
    logicalContentSha256: verifiedDatabase.logicalContentSha256,
    recordCounts: verifiedDatabase.recordCounts
  }
}

function usage(): string {
  return [
    'Usage:',
    '  pnpm db:baseline generate --output <directory>',
    '  pnpm db:baseline verify --input <directory>'
  ].join('\n')
}

function requiredFlag(args: string[], flag: '--output' | '--input'): string {
  const index = args.indexOf(flag)
  invariant(index >= 0, `${flag} is required\n${usage()}`)
  const value = args[index + 1]
  invariant(value && !value.startsWith('--'), `${flag} requires a directory value`)
  invariant(args.indexOf(flag, index + 1) === -1, `${flag} may only be specified once`)
  return value
}

function assertOnlyKnownArguments(
  args: string[],
  expectedFlag: '--output' | '--input'
): void {
  invariant(args.length === 2, `unexpected arguments\n${usage()}`)
  invariant(args[0] === expectedFlag, `expected ${expectedFlag}\n${usage()}`)
}

export function runV1DatabaseBaselineCli(
  args: string[],
  writeOutput: (value: string) => void = (value) => console.log(value)
): V1BaselineArtifact | V1BaselineVerification | undefined {
  const [command, ...commandArgs] = args
  if (command === '--help' || command === '-h' || command === undefined) {
    writeOutput(usage())
    return undefined
  }

  if (command === 'generate') {
    assertOnlyKnownArguments(commandArgs, '--output')
    const outputDirectory = requiredFlag(commandArgs, '--output')
    const result = generateV1DatabaseBaseline(outputDirectory)
    writeOutput(
      JSON.stringify({
        status: 'generated',
        outputDirectory: result.outputDirectory,
        databaseSha256: result.databaseSha256,
        logicalContentSha256: result.logicalContentSha256,
        schemaVersion: result.schemaVersion,
        fixtureVersion: result.fixtureVersion
      })
    )
    return result
  }

  if (command === 'verify') {
    assertOnlyKnownArguments(commandArgs, '--input')
    const inputDirectory = requiredFlag(commandArgs, '--input')
    const result = verifyV1DatabaseBaseline(inputDirectory)
    writeOutput(JSON.stringify({ status: 'verified', ...result }))
    return result
  }

  throw new Error(`Unknown V1 baseline command: ${command}\n${usage()}`)
}

function isDirectExecution(): boolean {
  const entryPoint = process.argv[1]
  if (!entryPoint) return false
  return pathToFileURL(resolve(entryPoint)).href.toLowerCase() === import.meta.url.toLowerCase()
}

if (isDirectExecution()) {
  try {
    runV1DatabaseBaselineCli(process.argv.slice(2))
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}
