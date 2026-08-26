import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { openAgentGoDatabase } from './database'
import { EvidenceStore, redactEvidenceText } from './evidence-store'
import { AgentGoRepository } from './repository'

const directories: string[] = []

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

async function createScanFixture(directory: string): Promise<{
  database: ReturnType<typeof openAgentGoDatabase>
  workspaceId: string
  scanId: string
}> {
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({ name: 'Evidence', description: '' })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'approval',
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
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'Evidence scan',
      description: 'EvidenceStore 授权测试夹具。',
      families: ['sqli'],
      identityIds: [],
      budget: {
        maxRequests: 10,
        maxRequestsPerMinute: 10,
        maxConcurrency: 1,
        maxPlanRevisions: 1,
        maxDurationMinutes: 10,
        maxModelTokens: 1_000,
        maxEstimatedCost: 1,
        maxRequestBytes: 10 * 1_146_880,
        maxResponseBytes: 10 * 16_777_216
      }
    },
    {},
    {}
  )
  return { database, workspaceId: workspace.id, scanId: scan.id }
}

describe('EvidenceStore', () => {
  it('writes only explicitly redacted content-addressed evidence', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const store = new EvidenceStore(fixture.database, join(directory, 'artifacts'))
    const evidence = await store.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'http-response',
      mimeType: 'text/plain',
      content: 'Authorization: [REDACTED]\nbody=ok',
      source: 'http-runner',
      createdBy: 'analysis',
      captureTool: 'undici',
      captureToolVersion: '7.16.0',
      redactionState: 'redacted'
    })

    expect(evidence.sha256).toHaveLength(64)
    expect(
      readFileSync(store.resolveStoredPath(evidence.filePath), 'utf8')
    ).toContain('[REDACTED]')
    expect((await store.read(evidence.id)).content.toString('utf8')).not.toContain(
      'secret-token'
    )
    fixture.database.close()
  })

  it('rejects ordinary writes that are not explicitly redacted', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const store = new EvidenceStore(fixture.database, join(directory, 'artifacts'))

    await expect(
      store.save({
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId,
        type: 'http-response',
        mimeType: 'text/plain',
        content: 'Authorization: Bearer secret-token',
        source: 'http-runner',
        createdBy: 'analysis',
        captureTool: 'undici',
        captureToolVersion: '7.16.0'
      } as never)
    ).rejects.toThrow('explicitly redacted')
    expect(await store.list(fixture.scanId)).toEqual([])
    fixture.database.close()
  })

  it('detects file tampering instead of silently accepting changed evidence', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const store = new EvidenceStore(fixture.database, join(directory, 'artifacts'))
    const evidence = await store.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'response-summary',
      mimeType: 'application/json',
      content: '{"status":200}',
      source: 'http-runner',
      createdBy: 'analysis',
      captureTool: 'undici',
      captureToolVersion: '7.16.0',
      redactionState: 'redacted'
    })
    writeFileSync(store.resolveStoredPath(evidence.filePath), 'tampered')

    await expect(store.read(evidence.id)).rejects.toThrow('integrity')
    expect((await store.getMetadata(evidence.id))?.integrityStatus).toBe('failed')
    fixture.database.close()
  })

  it('normalizes JSON content types with charset and redacts quoted secret keys', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const store = new EvidenceStore(fixture.database, join(directory, 'artifacts'))
    const redactedContent = redactEvidenceText(
      '{"authorization":"Bearer json-secret","status":200}'
    )
    const original = await store.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'json-response',
      mimeType: 'application/json; charset=utf-8',
      content: redactedContent,
      source: 'http-runner',
      createdBy: 'analysis',
      captureTool: 'undici',
      captureToolVersion: '7.16.0',
      redactionState: 'redacted'
    })

    const redacted = await store.createRedactedTextDerivative(original.id, 'reporting')
    const content = (await store.read(redacted.id)).content.toString('utf8')
    expect(content).not.toContain('json-secret')
    expect(content).toContain('[REDACTED]')
    fixture.database.close()
  })

  it('removes a newly written content file when the metadata insert fails', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const root = join(directory, 'artifacts')
    const store = new EvidenceStore(fixture.database, root)
    const content = 'synthetic metadata failure'
    const digest = createHash('sha256').update(content).digest('hex')
    const workspaceDirectory = createHash('sha256')
      .update(fixture.workspaceId)
      .digest('hex')
      .slice(0, 20)
    const expectedPath = join(
      root,
      workspaceDirectory,
      'evidence',
      digest.slice(0, 2),
      `${digest}.txt`
    )
    fixture.database.native.exec(`
      CREATE TRIGGER synthetic_evidence_insert_failure
      BEFORE INSERT ON evidence_items
      BEGIN
        SELECT RAISE(ABORT, 'synthetic Evidence insert failure');
      END;
    `)

    await expect(
      store.save({
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId,
        type: 'test-response',
        mimeType: 'text/plain',
        content,
        source: 'automated-test',
        createdBy: 'test',
        captureTool: 'test',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
    ).rejects.toThrow()
    expect(() => readFileSync(expectedPath)).toThrow()
    fixture.database.close()
  })

  it('reports an atomic metadata discard even when file cleanup must be retried', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const store = new EvidenceStore(fixture.database, join(directory, 'artifacts'))
    const evidence = await store.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: '{"cleanup":"retry"}',
      source: 'automated-test',
      createdBy: 'test',
      captureTool: 'test',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
    const absolutePath = store.resolveStoredPath(evidence.filePath)

    rmSync(absolutePath)
    mkdirSync(absolutePath)

    await expect(store.discardUnboundEvidence(evidence)).resolves.toBe(true)
    expect(await store.getMetadata(evidence.id)).toBeUndefined()
    expect(existsSync(absolutePath)).toBe(true)
    fixture.database.close()
  })

  it('refuses to discard Evidence referenced outside Interaction and Finding tables', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const repository = new AgentGoRepository(fixture.database)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts')
    )
    const evidence = await store.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'report-markdown',
      mimeType: 'text/markdown',
      content: '# Redacted report',
      source: 'reporting',
      createdBy: 'reporting',
      captureTool: 'agentgo-reporting',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
    await repository.createReport({
      scanId: fixture.scanId,
      title: 'Reference guard',
      format: 'markdown',
      sha256: evidence.sha256,
      redacted: true,
      contentRef: evidence.id
    })

    await expect(store.discardUnboundEvidence(evidence)).resolves.toBe(false)
    expect(await store.getMetadata(evidence.id)).toBeDefined()
    expect(existsSync(store.resolveStoredPath(evidence.filePath))).toBe(true)
    fixture.database.close()
  })

  it('serializes same-address save and discard mutations on one store instance', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const store = new EvidenceStore(fixture.database, join(directory, 'artifacts'))
    const input = {
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: '{"contentAddress":"shared"}',
      source: 'automated-test',
      createdBy: 'test',
      captureTool: 'test',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted' as const
    }
    const first = await store.save(input)

    const [discarded, replacement] = await Promise.all([
      store.discardUnboundEvidence(first),
      store.save(input)
    ])

    expect(discarded).toBe(true)
    expect(replacement.id).not.toBe(first.id)
    expect(replacement.filePath).toBe(first.filePath)
    expect(await store.getMetadata(first.id)).toBeUndefined()
    expect((await store.read(replacement.id)).content.toString('utf8')).toBe(
      input.content
    )
    expect(existsSync(store.resolveStoredPath(replacement.filePath))).toBe(true)
    fixture.database.close()
  })

  it('serializes startup sweep and same-address save across store instances', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const artifactRoot = join(directory, 'artifacts')
    const firstStore = new EvidenceStore(fixture.database, artifactRoot)
    const secondDatabase = openAgentGoDatabase(
      join(directory, 'agentgo.sqlite')
    )
    const secondStore = new EvidenceStore(secondDatabase, artifactRoot)
    const input = {
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'evidence-capture-hash-only',
      mimeType: 'application/json',
      content: '{"contentAddress":"cross-store"}',
      source: 'automated-test',
      createdBy: 'test',
      captureTool: 'test',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted' as const
    }

    try {
      const orphaned = await firstStore.save(input)
      fixture.database.native
        .prepare('DELETE FROM evidence_items WHERE id = ?')
        .run(orphaned.id)

      const [deleted, replacement] = await Promise.all([
        firstStore.sweepUnreferencedContentFiles(),
        secondStore.save(input)
      ])

      expect(deleted).toBe(1)
      expect(await secondStore.getMetadata(replacement.id)).toBeDefined()
      expect((await secondStore.read(replacement.id)).content.toString('utf8')).toBe(
        input.content
      )
      expect(
        existsSync(secondStore.resolveStoredPath(replacement.filePath))
      ).toBe(true)
    } finally {
      secondDatabase.close()
      fixture.database.close()
    }
  })

  it('sweeps only controlled content-addressed files with no metadata', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const artifactRoot = join(directory, 'artifacts')
    const store = new EvidenceStore(fixture.database, artifactRoot)
    const save = (content: string) =>
      store.save({
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId,
        type: 'response-summary',
        mimeType: 'application/json',
        content,
        source: 'automated-test',
        createdBy: 'test',
        captureTool: 'test',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
    const referenced = await save('{"state":"referenced"}')
    const orphaned = await save('{"state":"metadata-committed-then-cleaned"}')
    const referencedPath = store.resolveStoredPath(referenced.filePath)
    const orphanedPath = store.resolveStoredPath(orphaned.filePath)
    const unknownPath = join(dirname(orphanedPath), 'operator-note.txt')
    writeFileSync(unknownPath, 'not managed by EvidenceStore')
    fixture.database.native
      .prepare('UPDATE evidence_items SET file_path = ? WHERE id = ?')
      .run(referenced.filePath.replace(/\//gu, '\\'), referenced.id)
    fixture.database.native
      .prepare('DELETE FROM evidence_items WHERE id = ?')
      .run(orphaned.id)
    const externalDirectory = join(directory, 'external-evidence')
    const externalBucket = join(externalDirectory, 'aa')
    const externalFile = join(
      externalBucket,
      `${'aa'}${'0'.repeat(62)}.json`
    )
    mkdirSync(externalBucket, { recursive: true })
    writeFileSync(externalFile, '{"outside":"artifact-root"}')
    const linkedWorkspace = join(artifactRoot, 'f'.repeat(20))
    mkdirSync(linkedWorkspace)
    let linked = false
    try {
      symlinkSync(
        externalDirectory,
        join(linkedWorkspace, 'evidence'),
        process.platform === 'win32' ? 'junction' : 'dir'
      )
      linked = true
    } catch (error) {
      if (
        !error ||
        typeof error !== 'object' ||
        !('code' in error) ||
        !['EPERM', 'EACCES', 'ENOTSUP'].includes(String(error.code))
      ) {
        throw error
      }
    }

    await expect(store.sweepUnreferencedContentFiles()).resolves.toBe(1)

    expect(existsSync(orphanedPath)).toBe(false)
    expect(existsSync(referencedPath)).toBe(true)
    expect(existsSync(unknownPath)).toBe(true)
    if (linked) {
      expect(existsSync(externalFile)).toBe(true)
    }
    fixture.database.close()
  })
})
