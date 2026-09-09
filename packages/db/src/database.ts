import { existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync, type SQLInputValue } from 'node:sqlite'
import { drizzle, type SqliteRemoteDatabase } from 'drizzle-orm/sqlite-proxy'
import {
  DATABASE_MIGRATIONS,
  type DatabaseMigration
} from './migrations'
import * as schema from './schema'

export type AgentGoOrm = SqliteRemoteDatabase<typeof schema>

export interface AgentGoDatabase {
  readonly orm: AgentGoOrm
  readonly native: DatabaseSync
  readonly filePath: string
  close(): void
}

function prepareDatabaseDirectory(filePath: string): void {
  if (filePath === ':memory:') {
    return
  }

  const directory = dirname(filePath)
  if (!existsSync(directory)) {
    mkdirSync(directory, { recursive: true })
  }
}

function normalizeParameter(value: unknown): SQLInputValue {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'bigint' ||
    ArrayBuffer.isView(value)
  ) {
    return value as SQLInputValue
  }

  if (typeof value === 'boolean') {
    return value ? 1 : 0
  }

  throw new TypeError(`Unsupported SQLite parameter type: ${typeof value}`)
}

export interface ApplyDatabaseMigrationsOptions {
  readonly migrations?: readonly DatabaseMigration[]
  readonly appliedAt?: () => number
}

/**
 * Applies each migration atomically. SQL setup, deterministic TypeScript data
 * hooks, final SQL, and the migration ledger row all share one BEGIN IMMEDIATE.
 */
export function applyDatabaseMigrations(
  database: DatabaseSync,
  options: ApplyDatabaseMigrationsOptions = {}
): void {
  const migrations = options.migrations ?? DATABASE_MIGRATIONS
  const appliedAt = options.appliedAt ?? Date.now
  database.exec(`
    CREATE TABLE IF NOT EXISTS __agentgo_migrations (
      id TEXT PRIMARY KEY,
      applied_at INTEGER NOT NULL
    );
  `)

  const hasMigration = database.prepare(
    'SELECT 1 AS applied FROM __agentgo_migrations WHERE id = ? LIMIT 1'
  )
  const recordMigration = database.prepare(
    'INSERT INTO __agentgo_migrations (id, applied_at) VALUES (?, ?)'
  )

  const migrationIds = new Set<string>()
  for (const migration of migrations) {
    if (migrationIds.has(migration.id)) {
      throw new Error(`Duplicate database migration ID: ${migration.id}`)
    }
    migrationIds.add(migration.id)
    if (hasMigration.get(migration.id)) {
      continue
    }

    const disableForeignKeys = migration.foreignKeys === 'off'
    if (disableForeignKeys) {
      database.exec('PRAGMA foreign_keys = OFF')
    }
    try {
      database.exec('BEGIN IMMEDIATE')
      try {
        database.exec(migration.sql)
        migration.dataHook?.(database)
        if (migration.finalizeSql) database.exec(migration.finalizeSql)
        recordMigration.run(migration.id, appliedAt())
        database.exec('COMMIT')
      } catch (error) {
        database.exec('ROLLBACK')
        throw error
      }
    } finally {
      if (disableForeignKeys) {
        database.exec('PRAGMA foreign_keys = ON')
      }
    }
  }
}

export function openAgentGoDatabase(filePath: string): AgentGoDatabase {
  prepareDatabaseDirectory(filePath)

  const native = new DatabaseSync(filePath, {
    allowExtension: false,
    enableDoubleQuotedStringLiterals: false,
    enableForeignKeyConstraints: true,
    timeout: 5_000
  })

  native.exec('PRAGMA journal_mode = WAL;')
  native.exec('PRAGMA synchronous = NORMAL;')
  native.exec('PRAGMA temp_store = MEMORY;')
  native.exec('PRAGMA trusted_schema = OFF;')
  applyDatabaseMigrations(native)

  const orm = drizzle<typeof schema>(
    async (sql, params, method) => {
      const statement = native.prepare(sql)
      const normalized = params.map(normalizeParameter)

      if (method === 'run') {
        statement.run(...normalized)
        return { rows: [] }
      }

      statement.setReturnArrays(true)
      if (method === 'get') {
        const row = statement.get(...normalized)
        return { rows: row ? [row] : [] }
      }

      return { rows: statement.all(...normalized) }
    },
    { schema }
  )

  let closed = false
  return {
    orm,
    native,
    filePath,
    close: () => {
      if (!closed) {
        closed = true
        native.close()
      }
    }
  }
}
