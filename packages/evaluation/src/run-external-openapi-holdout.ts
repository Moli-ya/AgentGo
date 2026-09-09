import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  EphemeralRequestHashKeyProvider,
  EvidenceCapturePolicy,
  ExecutionAuthority,
  ExecutionService,
  ImportService,
  InventoryService,
  LegacyV1RequestCompilerAdapter,
  PolicyBroker,
  PolicyExecutionGuard,
  buildScanModuleSnapshotDrafts,
  computeScanModuleSnapshotHash,
  createVulnerabilityPlatform
} from '@agentgo/application'
import { PlaywrightBrowserRunner } from '@agentgo/browser-runner'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  ImportDiscoveryRepository,
  openAgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { UndiciHttpRunner } from '@agentgo/http-runner'
import { preflightExternalOpenApiHoldout } from './external-openapi-holdout'

const IMAGE =
  'swaggerapi/petstore3@sha256:221da3038bf91fad98e249d5f123cbca21d5bfc8e10a786c8c060ec8058cc522'

function timestampId(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')
}

function createEphemeralProtector(): SecretProtector {
  const key = randomBytes(32)
  return {
    isAvailable: () => true,
    protect: (value) => {
      const iv = randomBytes(12)
      const cipher = createCipheriv('aes-256-gcm', key, iv)
      const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
      return Buffer.concat([iv, cipher.getAuthTag(), encrypted])
    },
    unprotect: (value) => {
      const iv = value.subarray(0, 12)
      const tag = value.subarray(12, 28)
      const encrypted = value.subarray(28)
      const decipher = createDecipheriv('aes-256-gcm', key, iv)
      decipher.setAuthTag(tag)
      return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8')
    }
  }
}

function parseBaseUrl(argv: readonly string[]): string {
  const index = argv.indexOf('--base-url')
  const value = index >= 0 ? argv[index + 1] : undefined
  if (!value || value.startsWith('--') || argv.length !== index + 2) {
    throw new Error('Usage: --base-url http://127.0.0.1:<port>')
  }
  return value
}

const baseUrl = parseBaseUrl(process.argv.slice(2))
const preflight = await preflightExternalOpenApiHoldout({ baseUrl })
const downloadedOpenApiBytes = new Uint8Array(await (await fetch(preflight.openApiUrl)).arrayBuffer())
const openApiDocument = JSON.parse(new TextDecoder().decode(downloadedOpenApiBytes)) as {
  servers?: Array<{ url?: string }>
}
openApiDocument.servers = [{ url: `${preflight.baseUrl}/api/v3` }]
const openApiBytes = new TextEncoder().encode(JSON.stringify(openApiDocument))
const importedSpecificationSha256 = createHash('sha256').update(openApiBytes).digest('hex')
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const outputDirectory = join(root, 'benchmark-results', `day20-external-petstore-${timestampId()}`)
await mkdir(join(outputDirectory, 'data'), { recursive: true })
await mkdir(join(outputDirectory, 'artifacts'), { recursive: true })
const database = openAgentGoDatabase(join(outputDirectory, 'data', 'agentgo.sqlite'))

try {
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({
    name: `AgentGo external Petstore ${preflight.packVersion}`,
    description: 'Pinned local third-party OpenAPI compatibility replay.'
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Swagger Petstore V3 local holdout',
    baseUrl: preflight.baseUrl,
    description: 'Loopback-only external holdout.',
    authorizationReference: 'external-holdout:swagger-petstore-v3/1.0.16',
    scope: {
      allowedOrigins: [preflight.baseUrl],
      allowedPathPrefixes: ['/api/v3'],
      deniedPathPrefixes: [],
      allowedPorts: [Number(new URL(preflight.baseUrl).port)],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: true,
      allowLoopbackTargets: true,
      networkEntries: [{
        id: 'external-petstore-loopback',
        addressClass: 'loopback',
        ip: '127.0.0.1',
        ports: [Number(new URL(preflight.baseUrl).port)],
        purpose: 'execution'
      }],
      maxRequestsPerMinute: 10,
      maxConcurrency: 1,
      authorizationReference: 'external-holdout:swagger-petstore-v3/1.0.16'
    }
  })
  const platform = createVulnerabilityPlatform()
  const plan = createDefaultScanPlan(['sqli'])
  const moduleSnapshotDrafts = buildScanModuleSnapshotDrafts(
    ['sqli'],
    'authorized-test-environment',
    platform
  )
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'Swagger Petstore external read-only replay',
      description: 'OpenAPI import, human review, and mediated GET replay.',
      families: ['sqli'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() },
    moduleSnapshotDrafts.map((draft) => ({
      draft,
      snapshotHash: computeScanModuleSnapshotHash(draft)
    }))
  )
  await repository.updateScan(scan.id, { status: 'running', startedAt: Date.now() })
  const inventory = new InventoryService(repository, platform.capabilityCatalog)
  const discovery = new ImportDiscoveryRepository(database)
  const evidenceStore = new EvidenceStore(database, join(outputDirectory, 'artifacts'), {
    protector: createEphemeralProtector()
  })
  const importer = new ImportService(repository, inventory, discovery, evidenceStore)
  const preview = await importer.preview({
    scanId: scan.id,
    bytes: openApiBytes,
    mediaType: 'application/json',
    importActorRef: 'external-holdout-preflight'
  })
  if (preview.operations.length === 0) {
    throw new Error(`External OpenAPI import accepted no operations: ${JSON.stringify({ stats: preview.stats, rejected: preview.rejectedOperations.slice(0, 5) })}`)
  }
  const commit = await importer.commit({
    previewId: preview.previewId,
    previewHash: preview.previewHash,
    sourceBytesHash: preview.sourceBytesHash,
    parserVersion: preview.parserVersion,
    importActorRef: 'external-holdout-review'
  })

  const variants = await repository.listInventoryRequestVariants(scan.id)
  const endpoints = await repository.listInventoryEndpoints(scan.id)
  const selectedPaths = ['/api/v3/store/inventory', '/api/v3/pet/findByStatus']
  const selected: Array<{ endpointId: string; requestVariantId: string; url: string }> = []
  for (const endpoint of endpoints) {
    if (endpoint.method !== 'GET' || !selectedPaths.includes(new URL(endpoint.url).pathname)) continue
    const imported = variants.find((variant) => variant.endpointId === endpoint.id)
    if (!imported) continue
    const promoted = await inventory.upsertInventory({
      scanId: scan.id,
      method: 'GET',
      url: endpoint.url,
      bodyShape: imported.bodyShape,
      codec: imported.codec,
      transport: imported.transport,
      allowedHeaders: imported.allowedHeaders,
      templateVersion: imported.templateVersion,
      requiredCapabilityIds: ['http.reviewed-read'],
      selectors: imported.selectors,
      preview: { url: endpoint.url },
      source: {
        type: 'external-holdout.review',
        sourceHash: importedSpecificationSha256,
        confidence: 1,
        initiator: 'swagger-petstore-v3/1.0.16'
      }
    })
    await inventory.reviewVariant({
      scanId: scan.id,
      requestVariantId: promoted.requestVariant.id,
      reviewStatus: 'reviewed',
      reviewedBy: 'external-holdout-review'
    })
    const url = new URL(endpoint.url)
    if (url.pathname.endsWith('/findByStatus')) url.searchParams.set('status', 'available')
    selected.push({ endpointId: promoted.endpoint.id, requestVariantId: promoted.requestVariant.id, url: url.href })
  }
  if (selected.length < 2) {
    throw new Error(
      `External holdout did not yield the two reviewed GET variants: ${JSON.stringify(
        endpoints.map((endpoint) => ({ method: endpoint.method, url: endpoint.url }))
      )}`
    )
  }

  const credentials = new FileCredentialStore(join(outputDirectory, 'data', 'credentials.json'), createEphemeralProtector())
  const hashKeys = new EphemeralRequestHashKeyProvider()
  const adapter = new LegacyV1RequestCompilerAdapter({ repository, credentialStore: credentials, hashKeyProvider: hashKeys, hashKey: hashKeys.reference })
  const authority = new ExecutionAuthority(repository, hashKeys)
  const policyBroker = new PolicyBroker(repository)
  const executionGuard = new PolicyExecutionGuard(repository, hashKeys, credentials)
  const execution = new ExecutionService({
    repository,
    evidenceStore,
    httpRunner: new UndiciHttpRunner(executionGuard),
    browserRunner: new PlaywrightBrowserRunner({ headless: true }),
    requestAdapter: adapter,
    authority,
    policyBroker,
    executionGuard,
    evidenceCapturePolicy: new EvidenceCapturePolicy(),
    hashKeyProvider: hashKeys
  })
  const agentRun = await repository.createAgentRun({
    scanId: scan.id,
    role: 'strategy',
    promptId: 'external-openapi-reviewed-replay',
    promptVersion: '1.0.0',
    promptHash: importedSpecificationSha256,
    modelProfileId: 'deterministic-external-holdout'
  })
  const replays = []
  for (const [index, item] of selected.entries()) {
    const result = await execution.executeMediatedHttp({
      scanId: scan.id,
      agentRunId: agentRun.id,
      familyId: 'sqli',
      stepId: `external.petstore.get.${index + 1}`,
      purpose: 'read',
      summary: 'Pinned third-party OpenAPI reviewed GET replay',
      expectedEvidence: 'HTTP response hash-only evidence',
      adapterKind: 'http',
      method: 'GET',
      endpointId: item.endpointId,
      requestVariantId: item.requestVariantId,
      desiredUrl: item.url,
      timeoutMs: 10_000,
      maxResponseBytes: 1_048_576
    })
    replays.push({
      url: item.url,
      status: result.result.status,
      statusCode: result.result.statusCode,
      responseBodySha256: result.result.responseBodySha256,
      responseBytes: result.result.responseBytes,
      policyDecisionIds: result.policyDecisionIds,
      grantIds: result.grantIds,
      leaseIds: result.leaseIds,
      evidenceRefs: result.evidenceRefs
    })
  }
  await repository.finishAgentRun({ id: agentRun.id, status: 'completed' })
  const artifact = {
    schemaVersion: 'agentgo-external-openapi-holdout/1.0',
    resultClass: 'external-local-holdout',
    status: 'completed',
    image: IMAGE,
    preflight,
    import: {
      sourceBytesHash: preview.sourceBytesHash,
      downloadedSpecificationSha256: preflight.specificationSha256,
      importedSpecificationSha256,
      previewHash: preview.previewHash,
      acceptedOperations: preview.stats.accepted,
      committedSources: commit.sourceIds.length,
      selectedReviewedVariants: selected.length
    },
    replays,
    scoreScope: 'compatibility-and-policy-replay-only; no vulnerability accuracy claim'
  }
  await writeFile(join(outputDirectory, 'external-result.json'), JSON.stringify(artifact, null, 2), 'utf8')
  console.log(JSON.stringify({ ...artifact, outputDirectory }, null, 2))
} finally {
  database.close()
}
