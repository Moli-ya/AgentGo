import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  AgentGoRepository,
  DiscoveryRuntimeRepository,
  ImportDiscoveryRepository,
  openAgentGoDatabase,
  type AgentGoDatabase
} from '@agentgo/db'
import { DEFAULT_PROBE_CAPABILITY_CATALOG } from '@agentgo/security-policy'
import { DependencyGraphService } from './dependency-graph-service'
import { InventoryMergeService } from './inventory-merge-service'
import { InventoryService } from './inventory-service'

const directories: string[] = []
const openDatabases: AgentGoDatabase[] = []

afterEach(() => {
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

async function harness() {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-merge-graph-'))
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({ name: 'merge', description: '' })
  const created = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'merge-test',
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
  const plan = createDefaultScanPlan(['xss'])
  const scan = await repository.createScan(
    {
      targetId: created.target.id,
      name: 'merge scan',
      description: '',
      families: ['xss'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() }
  )
  const inventory = new InventoryService(repository, DEFAULT_PROBE_CAPABILITY_CATALOG)
  const runtime = new DiscoveryRuntimeRepository(database)
  const discovery = new ImportDiscoveryRepository(database)
  const merge = new InventoryMergeService(inventory, repository, runtime)
  const graph = new DependencyGraphService(discovery, runtime)
  const scope = await repository.getLatestScope(created.target.id)
  if (!scope) throw new Error('missing scope')
  return { repository, scan, scope, merge, graph, runtime }
}

describe('InventoryMergeService', () => {
  it('merges the same operation identity and keeps provenance', async () => {
    const { scan, scope, merge, repository, runtime } = await harness()
    const inventory = {
      scanId: scan.id,
      method: 'GET',
      url: 'https://lab.example.test/api/read',
      bodyShape: { rootType: 'none' as const, fields: [] },
      codec: 'none' as const,
      transport: 'standard-http' as const,
      allowedHeaders: [],
      templateVersion: '1.0.0',
      requiredCapabilityIds: [],
      selectors: [],
      preview: { url: 'https://lab.example.test/api/read' },
      source: {
        type: 'static.offline',
        sourceHash: sha256('static-read'),
        confidence: 1
      }
    }
    const first = await merge.ingest({
      producer: 'static.offline',
      scope,
      inventory
    })
    const second = await merge.ingest({
      producer: 'browser.recon',
      scope,
      inventory: {
        ...inventory,
        source: {
          type: 'browser.recon',
          sourceHash: sha256('browser-read'),
          confidence: 1
        }
      }
    })
    expect(first.result?.requestVariant.id).toBe(second.result?.requestVariant.id)
    expect(second.reportDelta.merged).toBe(1)
    const sources = await repository.listInventorySources(
      scan.id,
      second.result?.requestVariant.id
    )
    expect(sources.map((source) => source.type).sort()).toEqual([
      'browser.recon',
      'static.offline'
    ])
    const report = await merge.persistReport({
      scanId: scan.id,
      scopeSnapshotId: scan.scopeSnapshotId,
      deltas: [
        { producer: 'static.offline', capabilityId: 'none', counts: first.reportDelta },
        { producer: 'browser.recon', capabilityId: 'none', counts: second.reportDelta }
      ]
    })
    expect(report.totals.created + report.totals.merged).toBe(2)
    const listed = await runtime.listMergeReports(scan.id)
    expect(listed[0]?.reportId).toBe(report.reportId)
  })

  it('rejects out-of-scope URLs without writing inventory', async () => {
    const { scan, scope, merge, repository } = await harness()
    const result = await merge.ingest({
      producer: 'browser.recon',
      scope,
      inventory: {
        scanId: scan.id,
        method: 'GET',
        url: 'https://evil.example.test/x',
        bodyShape: { rootType: 'none', fields: [] },
        codec: 'none',
        transport: 'standard-http',
        allowedHeaders: [],
        templateVersion: '1.0.0',
        requiredCapabilityIds: [],
        selectors: [],
        preview: { url: 'https://evil.example.test/x' },
        source: {
          type: 'browser.recon',
          sourceHash: sha256('out'),
          confidence: 1
        }
      }
    })
    expect(result.result).toBeUndefined()
    expect(result.reportDelta.outOfScope).toBe(1)
    expect(await repository.listInventoryEndpoints(scan.id)).toEqual([])
  })

  it('does not loosen an existing variant execution class', async () => {
    const { scan, scope, merge, repository } = await harness()
    const inventory = {
      scanId: scan.id,
      method: 'GET',
      url: 'https://lab.example.test/api/strict',
      bodyShape: { rootType: 'none' as const, fields: [] },
      codec: 'none' as const,
      transport: 'standard-http' as const,
      allowedHeaders: [],
      templateVersion: '1.0.0',
      requiredCapabilityIds: ['http.reviewed-read'],
      selectors: [],
      preview: { url: 'https://lab.example.test/api/strict' },
      source: {
        type: 'static.offline',
        sourceHash: sha256('strict-read'),
        confidence: 1
      }
    }
    const first = await merge.ingest({
      producer: 'static.offline',
      scope,
      inventory
    })
    expect(first.result?.requestVariant.executionClass).toBe('active-l1')
    const looser = await merge.ingest({
      producer: 'browser.recon',
      scope,
      inventory: {
        ...inventory,
        requiredCapabilityIds: [],
        source: {
          type: 'browser.recon',
          sourceHash: sha256('looser-read'),
          confidence: 1
        }
      }
    })
    expect(looser.result?.requestVariant.id).not.toBe(first.result?.requestVariant.id)
    expect(looser.result?.requestVariant.executionClass).toBe('inventory-only')
    const original = (await repository.listInventoryRequestVariants(scan.id)).find(
      (variant) => variant.id === first.result?.requestVariant.id
    )
    expect(original?.executionClass).toBe('active-l1')
  })
})

describe('DependencyGraphService', () => {
  it('detects cycles, secret-sink mismatch, and cross-identity edges', async () => {
    const { scan, graph } = await harness()
    const now = new Date().toISOString()
    const identityA = randomUUID()
    const identityB = randomUUID()
    const sourceRef = randomUUID()
    const cycle = graph.graphFromRules(scan.id, scan.scopeSnapshotId, [
      {
        scanId: scan.id,
        name: 'extract.a',
        sourceKind: 'json-pointer',
        sourceSelector: '/a',
        valueType: 'string',
        secretClassification: 'none',
        targetVariable: 'extract.b',
        sourceRef,
        version: '1.0.0',
        ruleId: randomUUID(),
        ruleHash: sha256('a'),
        reviewStatus: 'reviewed',
        frozen: true,
        createdAt: now,
        identityScope: identityA
      },
      {
        scanId: scan.id,
        name: 'extract.b',
        sourceKind: 'json-pointer',
        sourceSelector: '/b',
        valueType: 'string',
        secretClassification: 'likely-secret',
        targetVariable: 'extract.a',
        sourceRef,
        version: '1.0.0',
        ruleId: randomUUID(),
        ruleHash: sha256('b'),
        reviewStatus: 'reviewed',
        frozen: true,
        createdAt: now,
        identityScope: identityB
      }
    ])
    expect(cycle.paused).toBe(true)
    expect(cycle.issues.some((issue) => issue.code === 'cycle')).toBe(true)
    expect(cycle.issues.some((issue) => issue.code === 'secret-sink-mismatch')).toBe(true)
    expect(cycle.issues.some((issue) => issue.code === 'cross-identity')).toBe(true)
  })

  it('keeps Agent suggestions in the unreviewed candidate sink', async () => {
    const { scan, graph, runtime } = await harness()
    await graph.proposeEdge({
      scanId: scan.id,
      fromNodeId: 'var.alpha',
      toNodeId: 'var.beta',
      ruleId: randomUUID(),
      sourceRef: randomUUID(),
      proposedBy: 'knowledge.agent'
    })
    const candidates = await runtime.listUnreviewedDependencyCandidates(scan.id)
    expect(candidates).toHaveLength(1)
    expect(await runtime.getLatestDependencyGraph(scan.id)).toBeUndefined()
  })
})
