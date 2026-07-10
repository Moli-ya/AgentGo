import { existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync, type SQLInputValue } from 'node:sqlite'
import { drizzle, type SqliteRemoteDatabase } from 'drizzle-orm/sqlite-proxy'
import { DATABASE_MIGRATIONS } from './migrations'
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

function applyMigrations(database: DatabaseSync): void {
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

  for (const migration of DATABASE_MIGRATIONS) {
    if (hasMigration.get(migration.id)) {
      continue
    }

    database.exec('BEGIN IMMEDIATE')
    try {
      database.exec(migration.sql)
      recordMigration.run(migration.id, Date.now())
      database.exec('COMMIT')
    } catch (error) {
      database.exec('ROLLBACK')
      throw error
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
  applyMigrations(native)

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
