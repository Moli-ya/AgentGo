import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { openAgentGoDatabase } from './database'
import { EvidenceStore } from './evidence-store'
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
        maxEstimatedCost: 1
      }
    },
    {},
    {}
  )
  return { database, workspaceId: workspace.id, scanId: scan.id }
}

describe('EvidenceStore', () => {
  it('writes immutable content-addressed evidence and creates a redacted derivative', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-evidence-'))
    directories.push(directory)
    const fixture = await createScanFixture(directory)
    const store = new EvidenceStore(fixture.database, join(directory, 'artifacts'))
    const original = await store.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'http-response',
      mimeType: 'text/plain',
      content: 'Authorization: Bearer secret-token\nbody=ok',
      source: 'http-runner',
      createdBy: 'analysis',
      captureTool: 'undici',
      captureToolVersion: '7.16.0'
    })

    expect(original.sha256).toHaveLength(64)
    expect(readFileSync(store.resolveStoredPath(original.filePath), 'utf8')).toContain(
      'secret-token'
    )
    const redacted = await store.createRedactedTextDerivative(original.id, 'reporting')
    expect(redacted.derivedFrom).toBe(original.id)
    expect((await store.read(redacted.id)).content.toString('utf8')).toContain('[REDACTED]')
    expect((await store.read(original.id)).content.toString('utf8')).toContain('secret-token')
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
      captureToolVersion: '7.16.0'
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
    const original = await store.save({
      workspaceId: fixture.workspaceId,
      scanId: fixture.scanId,
      type: 'json-response',
      mimeType: 'application/json; charset=utf-8',
      content: '{"authorization":"Bearer json-secret","status":200}',
      source: 'http-runner',
      createdBy: 'analysis',
      captureTool: 'undici',
      captureToolVersion: '7.16.0'
    })

    const redacted = await store.createRedactedTextDerivative(original.id, 'reporting')
    const content = (await store.read(redacted.id)).content.toString('utf8')
    expect(content).not.toContain('json-secret')
    expect(content).toContain('[REDACTED]')
    fixture.database.close()
  })
})
