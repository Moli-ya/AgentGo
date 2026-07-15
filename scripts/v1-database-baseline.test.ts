import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it } from 'vitest'
import { openAgentGoDatabase } from '../packages/db/src/database'
import { DATABASE_MIGRATIONS } from '../packages/db/src/migrations'
import {
  V1_BASELINE_DATABASE_FILE,
  V1_BASELINE_MANIFEST_FILE,
  generateV1DatabaseBaseline,
  runV1DatabaseBaselineCli,
  verifyV1DatabaseBaseline
} from './v1-database-baseline'

const temporaryDirectories: string[] = []

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-v1-baseline-'))
  temporaryDirectories.push(directory)
  return directory
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('synthetic V1 database baseline', () => {
  it('generates byte-identical SQLite databases and hashes repeatedly', () => {
    const root = temporaryDirectory()
    const first = generateV1DatabaseBaseline(join(root, 'first'))
    const second = generateV1DatabaseBaseline(join(root, 'second'))

    expect(first.databaseSha256).toBe(second.databaseSha256)
    expect(first.logicalContentSha256).toBe(second.logicalContentSha256)
    expect(first.databaseSha256).toMatch(/^[a-f0-9]{64}$/)
    expect(first.logicalContentSha256).toMatch(/^[a-f0-9]{64}$/)
    expect(readFileSync(first.databasePath)).toEqual(readFileSync(second.databasePath))
    expect(first.migrationIds).toEqual(DATABASE_MIGRATIONS.map(({ id }) => id))
    expect(first.schemaVersion).toBe(DATABASE_MIGRATIONS.at(-1)?.id)

    const firstManifest = JSON.parse(readFileSync(first.manifestPath, 'utf8')) as {
      databaseSha256: string
      logicalContentSha256: string
      databaseFile: string
    }
    expect(firstManifest.databaseSha256).toBe(first.databaseSha256)
    expect(firstManifest.logicalContentSha256).toBe(first.logicalContentSha256)
    expect(firstManifest.databaseFile).toBe(V1_BASELINE_DATABASE_FILE)
  })

  it('reopens through the application database and remains fully migrated', () => {
    const root = temporaryDirectory()
    const artifact = generateV1DatabaseBaseline(join(root, 'artifact'))
    const runtimeCopy = join(root, 'runtime-copy.sqlite')
    copyFileSync(artifact.databasePath, runtimeCopy)

    const database = openAgentGoDatabase(runtimeCopy)
    try {
      const migrationIds = database.native
        .prepare('SELECT id FROM __agentgo_migrations ORDER BY rowid ASC')
        .all()
        .map((row) => (row as { id: string }).id)
      expect(migrationIds).toEqual(DATABASE_MIGRATIONS.map(({ id }) => id))
      expect(
        database.native.prepare('PRAGMA foreign_key_check').all()
      ).toHaveLength(0)
      expect(
        (database.native.prepare('SELECT COUNT(*) AS count FROM scans').get() as {
          count: number
        }).count
      ).toBe(1)
    } finally {
      database.close()
    }
  })

  it('contains only exact synthetic records with no Evidence or credential references', () => {
    const root = temporaryDirectory()
    const artifact = generateV1DatabaseBaseline(root)
    const verified = verifyV1DatabaseBaseline(root)
    expect(verified.databaseSha256).toBe(artifact.databaseSha256)
    expect(verified.recordCounts).toEqual({
      workspaces: 1,
      targets: 1,
      target_scopes: 1,
      scans: 1
    })

    const database = new DatabaseSync(artifact.databasePath, { readOnly: true })
    try {
      expect(
        (database.prepare('SELECT COUNT(*) AS count FROM evidence_items').get() as {
          count: number
        }).count
      ).toBe(0)
      expect(
        (database.prepare('SELECT COUNT(*) AS count FROM finding_evidence').get() as {
          count: number
        }).count
      ).toBe(0)
      expect(
        (database.prepare('SELECT COUNT(*) AS count FROM identities').get() as {
          count: number
        }).count
      ).toBe(0)
      expect(
        (database.prepare('SELECT COUNT(*) AS count FROM model_profiles').get() as {
          count: number
        }).count
      ).toBe(0)
      expect(
        (database.prepare('SELECT COUNT(*) AS count FROM mcp_servers').get() as {
          count: number
        }).count
      ).toBe(0)
      const target = database
        .prepare('SELECT base_url, default_identity_id FROM targets')
        .get() as { base_url: string; default_identity_id: string | null }
      expect(new URL(target.base_url).hostname.endsWith('.invalid')).toBe(true)
      expect(target.default_identity_id).toBeNull()
    } finally {
      database.close()
    }
  })

  it('exercises CLI verify mode and rejects tampered logical and database hashes', () => {
    const root = temporaryDirectory()
    generateV1DatabaseBaseline(root)
    const output: string[] = []
    const result = runV1DatabaseBaselineCli(
      ['verify', '--input', root],
      (value) => output.push(value)
    )

    expect(result).toMatchObject({ schemaVersion: DATABASE_MIGRATIONS.at(-1)?.id })
    expect(JSON.parse(output.at(-1) ?? '{}')).toMatchObject({ status: 'verified' })

    const manifestPath = join(root, V1_BASELINE_MANIFEST_FILE)
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>
    const originalLogicalContentSha256 = manifest.logicalContentSha256
    manifest.logicalContentSha256 = '0'.repeat(64)
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    expect(() => verifyV1DatabaseBaseline(root)).toThrow(/logical content SHA-256/)

    manifest.logicalContentSha256 = originalLogicalContentSha256
    manifest.databaseSha256 = '0'.repeat(64)
    // The manifest is the artifact under test; writing it here deliberately simulates tampering.
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    expect(() => verifyV1DatabaseBaseline(root)).toThrow(/SHA-256 does not match/)
  })
})
