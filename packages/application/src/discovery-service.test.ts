import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  AgentGoRepository,
  EvidenceStore,
  ImportDiscoveryRepository,
  openAgentGoDatabase,
  type AgentGoDatabase
} from '@agentgo/db'
import { AssetManifestService, assertFrozenAssetManifest } from './asset-manifest-service'
import { StaticDiscoveryService } from './discovery/static-discovery-service'
import { ExtractionRuleService } from './extraction-rule-service'

const directories: string[] = []
const openDatabases: AgentGoDatabase[] = []

afterEach(() => {
  vi.restoreAllMocks()
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function installNetworkSpies() {
  return {
    fetch: vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new Error('network forbidden')
    })
  }
}

async function createHarness(suffix: string) {
  const directory = mkdtempSync(join(tmpdir(), `agentgo-discovery-${suffix}-`))
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({
    name: `Discovery ${suffix}`,
    description: ''
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: `Discovery target ${suffix}`,
    baseUrl: 'https://app.example.test/',
    description: '',
    authorizationReference: `discovery-${suffix}`,
    scope: {
      allowedOrigins: ['https://app.example.test'],
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
      maxConcurrency: 1,
      authorizationReference: `discovery-${suffix}`
    }
  })
  const plan = createDefaultScanPlan(['xss'])
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: `Discovery scan ${suffix}`,
      description: 'static-discovery',
      families: ['xss'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() }
  )
  const discoveryRepository = new ImportDiscoveryRepository(database)
  const evidenceStore = new EvidenceStore(database, join(directory, 'artifacts'))
  return {
    repository,
    scan,
    evidenceStore,
    workspaceId: workspace.id,
    discovery: new StaticDiscoveryService(repository, discoveryRepository, evidenceStore),
    manifests: new AssetManifestService(repository, discoveryRepository),
    rules: new ExtractionRuleService(repository, discoveryRepository)
  }
}

async function saveArtifact(
  harness: Awaited<ReturnType<typeof createHarness>>,
  content: string,
  mimeType: string
) {
  const saved = await harness.evidenceStore.save({
    workspaceId: harness.workspaceId,
    scanId: harness.scan.id,
    type: 'static-discovery-artifact',
    mimeType,
    content,
    source: 'discovery-test',
    createdBy: 'discovery.test-harness',
    captureTool: 'discovery-test',
    captureToolVersion: '1.0.0',
    redactionState: 'redacted'
  })
  return { saved, hash: sha256(content) }
}

describe('StaticDiscoveryService', () => {
  it('extracts HTML, JS and source map candidates offline with artifact-local dedupe', async () => {
    const spies = installNetworkSpies()
    const harness = await createHarness('static')
    const htmlMapHint = `<!--${'#'} sourceMappingURL=https://cdn.example.test/app.js.map -->`
    const html = `<!doctype html>
<html>
<head>
  <base href="https://app.example.test/app/">
  <link rel="manifest" href="/manifest.json">
  <meta http-equiv="refresh" content="0;url=/next">
</head>
<body>
  <form method="post" action="/login">
    <input name="user">
  </form>
  <script src="/app.js"></script>
  <iframe src="https://outside.example.test/embed"></iframe>
  ${htmlMapHint}
</body>
</html>`
    const htmlArtifact = await saveArtifact(harness, html, 'text/html')
    const htmlBatch = await harness.discovery.analyze({
      scanId: harness.scan.id,
      artifactRef: htmlArtifact.saved.id,
      expectedHash: htmlArtifact.hash,
      mediaType: 'text/html',
      scopeSnapshotId: harness.scan.scopeSnapshotId,
      baseUrlHint: 'https://app.example.test/'
    })
    expect(htmlBatch.producer).toBe('static-offline')
    expect(htmlBatch.candidates.some((item) => item.kind === 'form')).toBe(true)
    expect(htmlBatch.candidates.some((item) => item.kind === 'script')).toBe(true)
    expect(
      htmlBatch.candidates.every((item) =>
        item.capabilityStatus === 'inventory-only' || item.capabilityStatus === 'unsupported'
      )
    ).toBe(true)
    const keys = htmlBatch.candidates.map((item) => item.key)
    expect(new Set(keys).size).toBe(keys.length)

    const sourceMapComment = `//${'#'} sourceMappingURL=https://cdn.example.test/app.js.map`
    const js = `
      fetch('/api/items');
      fetch('/api/save', { method: 'post' });
      fetch('/api/dynamic', { method: runtimeMethod });
      const xhr = new XMLHttpRequest();
      xhr.open('PATCH', '/api/update');
      unrelated.open('DELETE', '/api/false-positive');
      new Worker('/workers/dedicated.js');
      new SharedWorker('/workers/shared.js');
      navigator.serviceWorker.register('/workers/service.js');
      importScripts('/workers/imported.js');
      new WebSocket('wss://app.example.test/ws');
      new EventSource('/events');
      const q = 'query GetPet { pet { id } }';
      ${sourceMapComment}
    `
    const jsArtifact = await saveArtifact(harness, js, 'text/plain')
    const jsBatch = await harness.discovery.analyze({
      scanId: harness.scan.id,
      artifactRef: jsArtifact.saved.id,
      expectedHash: jsArtifact.hash,
      mediaType: 'application/javascript',
      scopeSnapshotId: harness.scan.scopeSnapshotId,
      baseUrlHint: 'https://app.example.test/'
    })
    expect(jsBatch.candidates.some((item) => item.kind === 'http-endpoint')).toBe(true)
    expect(
      jsBatch.candidates.find((item) => item.url.endsWith('/api/items'))?.method
    ).toBe('GET')
    expect(jsBatch.candidates.find((item) => item.url.endsWith('/api/save'))?.method).toBe(
      'POST'
    )
    expect(jsBatch.candidates.find((item) => item.url.endsWith('/api/update'))?.method).toBe(
      'PATCH'
    )
    expect(jsBatch.candidates.find((item) => item.url.endsWith('/api/dynamic'))?.method).toBe(
      undefined
    )
    expect(jsBatch.candidates.some((item) => item.url.endsWith('/api/false-positive'))).toBe(
      false
    )
    expect(jsBatch.candidates.filter((item) => item.kind === 'worker')).toHaveLength(4)
    expect(
      jsBatch.candidates
        .filter((item) => item.kind === 'worker')
        .every((item) => item.capabilityStatus === 'unsupported')
    ).toBe(true)
    expect(jsBatch.warnings.some((warning) => /never .*executed/i.test(warning))).toBe(true)
    expect(jsBatch.candidates.some((item) => item.kind === 'websocket')).toBe(true)
    expect(jsBatch.candidates.some((item) => item.kind === 'sse')).toBe(true)
    expect(
      jsBatch.candidates.find((item) => item.kind === 'source-map')?.capabilityStatus
    ).toBe('unsupported')
    expect(jsBatch.warnings.some((warning) => /never downloaded/i.test(warning))).toBe(true)

    const map = JSON.stringify({
      version: 3,
      file: 'app.js',
      sources: ['https://cdn.example.test/src/app.ts', 'src/local.ts'],
      names: [],
      mappings: 'AAAA;AACA'
    })
    const mapArtifact = await saveArtifact(harness, map, 'application/json')
    const mapBatch = await harness.discovery.analyze({
      scanId: harness.scan.id,
      artifactRef: mapArtifact.saved.id,
      expectedHash: mapArtifact.hash,
      mediaType: 'application/json',
      scopeSnapshotId: harness.scan.scopeSnapshotId,
      baseUrlHint: 'https://app.example.test/app.js'
    })
    expect(mapBatch.candidates.every((item) => item.kind === 'source-map')).toBe(true)
    expect(mapBatch.warnings.some((warning) => /never fetched/i.test(warning))).toBe(true)
    const decodedMappings = mapBatch.candidates.filter(
      (item) => item.sourceProvenance?.original !== undefined
    )
    expect(decodedMappings).toHaveLength(2)
    expect(decodedMappings[0]?.sourceProvenance).toMatchObject({
      generated: { line: 1, column: 0 },
      original: { line: 1, column: 0 }
    })
    expect(decodedMappings[1]?.sourceProvenance).toMatchObject({
      generated: { line: 2, column: 0 },
      original: { line: 2, column: 0 }
    })

    const again = await harness.discovery.analyze({
      scanId: harness.scan.id,
      artifactRef: htmlArtifact.saved.id,
      expectedHash: htmlArtifact.hash,
      mediaType: 'text/html',
      scopeSnapshotId: harness.scan.scopeSnapshotId,
      baseUrlHint: 'https://app.example.test/'
    })
    expect(again.batchId).toBe(htmlBatch.batchId)

    expect(spies.fetch).not.toHaveBeenCalled()
  })

  it('fails closed on hash mismatch, oversize files and broken JavaScript without regex fallback', async () => {
    const harness = await createHarness('limits')
    const artifact = await saveArtifact(harness, '<html></html>', 'text/html')
    await expect(
      harness.discovery.analyze({
        scanId: harness.scan.id,
        artifactRef: artifact.saved.id,
        expectedHash: 'd'.repeat(64),
        mediaType: 'text/html',
        scopeSnapshotId: harness.scan.scopeSnapshotId
      })
    ).rejects.toThrow(/hash mismatch/i)

    const huge = await saveArtifact(harness, 'x'.repeat(100), 'text/html')
    await expect(
      harness.discovery.analyze({
        scanId: harness.scan.id,
        artifactRef: huge.saved.id,
        expectedHash: huge.hash,
        mediaType: 'text/html',
        scopeSnapshotId: harness.scan.scopeSnapshotId,
        budget: {
          maxFileBytes: 16,
          maxTotalBytes: 32,
          maxAstNodes: 10,
          maxParseTimeMs: 5_000,
          maxRecursionDepth: 8,
          maxSources: 8,
          maxStringCandidates: 8,
          maxRegexSteps: 100
        }
      })
    ).rejects.toThrow(/size budget/i)

    const broken = await saveArtifact(harness, 'function (', 'text/plain')
    const batch = await harness.discovery.analyze({
      scanId: harness.scan.id,
      artifactRef: broken.saved.id,
      expectedHash: broken.hash,
      mediaType: 'application/javascript',
      scopeSnapshotId: harness.scan.scopeSnapshotId
    })
    expect(batch.candidates).toEqual([])
    expect(batch.warnings.some((warning) => /failed closed/i.test(warning))).toBe(true)
  })

  it('decodes bounded inline source maps without loading or executing referenced code', async () => {
    const spies = installNetworkSpies()
    const workerConstructor = vi.fn(() => {
      throw new Error('worker execution forbidden')
    })
    vi.stubGlobal('Worker', workerConstructor)
    const harness = await createHarness('inline-map')
    const inlineMap = Buffer.from(
      JSON.stringify({
        version: 3,
        file: 'inline.js',
        sources: ['src/inline.ts'],
        names: [],
        mappings: 'AAAA'
      })
    ).toString('base64')
    const js = `new Worker('/must-not-run.js');\n//# sourceMappingURL=data:application/json;base64,${inlineMap}`
    const artifact = await saveArtifact(harness, js, 'text/plain')
    const batch = await harness.discovery.analyze({
      scanId: harness.scan.id,
      artifactRef: artifact.saved.id,
      expectedHash: artifact.hash,
      mediaType: 'application/javascript',
      scopeSnapshotId: harness.scan.scopeSnapshotId,
      baseUrlHint: 'https://app.example.test/assets/inline.js'
    })

    expect(batch.candidates.some((item) => item.kind === 'worker')).toBe(true)
    expect(
      batch.candidates.some((item) => item.sourceProvenance?.original?.line === 1)
    ).toBe(true)
    expect(workerConstructor).not.toHaveBeenCalled()
    expect(spies.fetch).not.toHaveBeenCalled()
  })
})

describe('AssetManifestService', () => {
  it('freezes exact assets and rejects unfrozen consumption', async () => {
    const harness = await createHarness('manifest')
    const artifact = await saveArtifact(harness, 'console.log(1)', 'text/plain')
    const draft = await harness.manifests.saveDraft({
      scanId: harness.scan.id,
      scopeSnapshotId: harness.scan.scopeSnapshotId,
      reviewer: 'day12.reviewer',
      entries: [
        {
          origin: 'https://app.example.test',
          normalizedPath: '/app.js',
          resourceType: 'javascript',
          artifactRef: artifact.saved.id,
          contentHash: artifact.hash,
          maxResponseBytes: 65_536,
          scopeSnapshotId: harness.scan.scopeSnapshotId
        }
      ]
    })
    expect(draft.frozen).toBe(false)
    expect(() => assertFrozenAssetManifest(draft)).toThrow(/frozen/i)

    const frozen = await harness.manifests.freeze({
      manifestId: draft.manifestId,
      manifestHash: draft.manifestHash,
      reviewer: 'day12.reviewer',
      scopeSnapshotId: harness.scan.scopeSnapshotId
    })
    expect(frozen.frozen).toBe(true)
    expect(assertFrozenAssetManifest(frozen).manifestId).toBe(draft.manifestId)

    await expect(
      harness.manifests.freeze({
        manifestId: draft.manifestId,
        manifestHash: 'e'.repeat(64),
        reviewer: 'day12.reviewer',
        scopeSnapshotId: harness.scan.scopeSnapshotId
      })
    ).rejects.toThrow(/hash mismatch/i)
  })
})

describe('ExtractionRuleService', () => {
  it('cannot freeze unreviewed, secret, or catastrophic regex rules', async () => {
    const harness = await createHarness('rules')
    const source = await saveArtifact(harness, '{"token":"x"}', 'application/json')
    const draft = await harness.rules.createDraft({
      scanId: harness.scan.id,
      name: 'extract.request-id',
      sourceKind: 'json-pointer',
      sourceSelector: '/id',
      valueType: 'string',
      secretClassification: 'none',
      targetVariable: 'request.id',
      sourceRef: source.saved.id,
      version: '1.0.0'
    })
    await expect(
      harness.rules.freeze({ ruleId: draft.ruleId, ruleHash: draft.ruleHash })
    ).rejects.toThrow(/Unreviewed/i)

    const reviewed = await harness.rules.review({
      ruleId: draft.ruleId,
      reviewStatus: 'reviewed',
      reviewedBy: 'day12.reviewer'
    })
    const frozen = await harness.rules.freeze({
      ruleId: reviewed.ruleId,
      ruleHash: reviewed.ruleHash
    })
    expect(frozen.frozen).toBe(true)

    await expect(
      harness.rules.createDraft({
        scanId: harness.scan.id,
        name: 'extract.secret',
        sourceKind: 'regex-capture',
        sourceSelector: '(a+)+b',
        valueType: 'string',
        secretClassification: 'none',
        targetVariable: 'bad.regex',
        sourceRef: source.saved.id,
        version: '1.0.0'
      })
    ).rejects.toThrow(/regex/i)

    const secret = await harness.rules.createDraft({
      scanId: harness.scan.id,
      name: 'extract.cookie',
      sourceKind: 'header',
      sourceSelector: 'set-cookie',
      valueType: 'string',
      secretClassification: 'likely-secret',
      targetVariable: 'session.cookie',
      sourceRef: source.saved.id,
      version: '1.0.0'
    })
    const secretReviewed = await harness.rules.review({
      ruleId: secret.ruleId,
      reviewStatus: 'reviewed',
      reviewedBy: 'day12.reviewer'
    })
    await expect(
      harness.rules.freeze({
        ruleId: secretReviewed.ruleId,
        ruleHash: secretReviewed.ruleHash
      })
    ).rejects.toThrow(/secret/i)
  })
})
