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
import { IMPORT_PARSER_VERSION } from './importers'
import { ImportService } from './import-service'
import { InventoryService } from './inventory-service'
import { createVulnerabilityPlatform } from './vulnerability-platform'

const SENTINEL = 'IMPORT_SENTINEL_SECRET_must-not-leak'
const directories: string[] = []
const openDatabases: AgentGoDatabase[] = []

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

function encode(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function installNetworkSpies() {
  return {
    fetch: vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new Error('network forbidden')
    })
  }
}

async function createHarness(suffix: string) {
  const directory = mkdtempSync(join(tmpdir(), `agentgo-import-${suffix}-`))
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({
    name: `Import ${suffix}`,
    description: ''
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: `Import target ${suffix}`,
    baseUrl: 'https://inventory.example.test/',
    description: '',
    authorizationReference: `import-${suffix}`,
    scope: {
      allowedOrigins: ['https://inventory.example.test'],
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
      authorizationReference: `import-${suffix}`
    }
  })
  const plan = createDefaultScanPlan(['sqli'])
  const platform = createVulnerabilityPlatform()
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: `Import scan ${suffix}`,
      description: 'offline-import',
      families: ['sqli'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() }
  )
  const discoveryRepository = new ImportDiscoveryRepository(database)
  const inventoryService = new InventoryService(repository, platform.capabilityCatalog)
  const evidenceStore = new EvidenceStore(database, join(directory, 'artifacts'))
  const service = new ImportService(
    repository,
    inventoryService,
    discoveryRepository,
    evidenceStore
  )
  return { database, repository, scan, service, evidenceStore, workspaceId: workspace.id }
}

function persistedText(database: AgentGoDatabase): string {
  const rows = database.native
    .prepare(
      `SELECT canonical_route AS value FROM endpoints
       UNION ALL SELECT redacted_preview_json FROM request_variants
       UNION ALL SELECT initiator FROM inventory_sources WHERE initiator IS NOT NULL
       UNION ALL SELECT payload_json FROM import_previews`
    )
    .all()
  return JSON.stringify(rows)
}

describe('ImportService', () => {
  it('previews and commits OpenAPI 3.0, 3.1, Swagger, HAR, Postman and GraphQL without network', async () => {
    const spies = installNetworkSpies()
    const { service, scan, database } = await createHarness('formats')

    const openapi30 = encode(`{
      "openapi": "3.0.3",
      "info": { "title": "Pets", "version": "1" },
      "servers": [{ "url": "https://inventory.example.test" }],
      "paths": {
        "/pets": {
          "get": { "parameters": [{ "name": "limit", "in": "query" }] },
          "post": {
            "requestBody": {
              "content": { "application/json": { "schema": { "type": "object" } } }
            }
          }
        }
      }
    }`)
    const preview30 = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      mediaType: 'application/json',
      bytes: openapi30
    })
    expect(preview30.format).toBe('openapi-3.0')
    expect(preview30.stats.accepted).toBe(2)
    expect(
      preview30.operations.find((operation) => operation.method === 'GET')?.parameters
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'limit', location: 'query' })
      ])
    )
    const commit30 = await service.commit({
      previewId: preview30.previewId,
      previewHash: preview30.previewHash,
      sourceBytesHash: preview30.sourceBytesHash,
      parserVersion: IMPORT_PARSER_VERSION,
      importActorRef: 'import.test-harness'
    })
    expect(commit30.acceptedCount).toBe(2)
    expect(commit30.idempotentReplay).toBe(false)

    const replay = await service.commit({
      previewId: preview30.previewId,
      previewHash: preview30.previewHash,
      sourceBytesHash: preview30.sourceBytesHash,
      parserVersion: IMPORT_PARSER_VERSION,
      importActorRef: 'import.test-harness'
    })
    expect(replay.idempotentReplay).toBe(true)
    expect(replay.commitId).toBe(commit30.commitId)

    const openapi31 = encode(`{
      "openapi": "3.1.0",
      "info": { "title": "Pets", "version": "1" },
      "servers": [{ "url": "https://inventory.example.test" }],
      "paths": {
        "/status": {
          "get": {
            "requestBody": {
              "content": {
                "application/json": {
                  "schema": { "type": "object", "unevaluatedProperties": false }
                }
              }
            }
          }
        }
      }
    }`)
    const preview31 = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes: openapi31
    })
    expect(preview31.format).toBe('openapi-3.1')
    expect(preview31.warnings.some((warning) => warning.code === 'unsupported-keyword')).toBe(true)

    const swagger = encode(`{
      "swagger": "2.0",
      "info": { "title": "Pets", "version": "1" },
      "host": "inventory.example.test",
      "basePath": "/v2",
      "schemes": ["https"],
      "paths": { "/pets": { "get": {} } }
    }`)
    const previewSwagger = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes: swagger
    })
    expect(previewSwagger.format).toBe('swagger-2.0')
    expect(previewSwagger.operations[0]?.url).toContain('/v2/pets')

    const har = encode(
      JSON.stringify({
        log: {
          version: '1.2',
          entries: [
            {
              initiator: 'script',
              request: {
                method: 'GET',
                url: `https://inventory.example.test/items?token=${SENTINEL}`,
                headers: [
                  { name: 'Authorization', value: `Bearer ${SENTINEL}` },
                  { name: 'Content-Type', value: 'application/json' }
                ]
              }
            }
          ]
        }
      })
    )
    const previewHar = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      mediaType: 'application/har+json',
      bytes: har
    })
    expect(previewHar.format).toBe('har-1.2')
    const serialized = JSON.stringify(previewHar)
    expect(serialized).not.toContain(SENTINEL)
    expect(decodeURIComponent(previewHar.operations[0]?.url ?? '')).toContain('[REDACTED]')

    const postman = encode(
      JSON.stringify({
        info: {
          name: 'Pets',
          schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
        },
        variable: [{ key: 'base', value: 'https://inventory.example.test' }],
        item: [
          {
            name: 'List',
            request: { method: 'GET', url: '{{base}}/collection' }
          }
        ]
      })
    )
    const previewPostman = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes: postman
    })
    expect(previewPostman.format).toBe('postman-2.1')
    expect(previewPostman.stats.accepted).toBe(1)

    const sdl = encode(`# endpoint: https://inventory.example.test/graphql
type Query {
  pet(id: ID!): Pet
}
type Pet { id: ID! }
`)
    const previewSdl = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      mediaType: 'application/graphql',
      bytes: sdl
    })
    expect(previewSdl.format).toBe('graphql-sdl')
    expect(previewSdl.adapterStatus).toBe('partial-inventory')

    const variants = database.native
      .prepare(
        `SELECT execution_class AS executionClass, review_status AS reviewStatus
         FROM request_variants WHERE scan_id = ?`
      )
      .all(scan.id) as Array<{ executionClass: string; reviewStatus: string }>
    expect(variants.length).toBeGreaterThan(0)
    expect(variants.every((row) => row.executionClass === 'inventory-only')).toBe(true)
    expect(variants.every((row) => row.reviewStatus === 'unreviewed')).toBe(true)
    expect(persistedText(database)).not.toContain(SENTINEL)
    expect(spies.fetch).not.toHaveBeenCalled()
  })

  it('fails closed on remote $ref, YAML bombs, malformed docs and over-limit operations', async () => {
    const { service, scan } = await createHarness('fail-closed')
    await expect(
      service.preview({
        scanId: scan.id,
        importActorRef: 'import.test-harness',
        bytes: encode(
          JSON.stringify({
            openapi: '3.0.3',
            paths: { '/x': { get: { $ref: 'https://evil.example.test/x.json' } } }
          })
        )
      })
    ).rejects.toThrow(/Remote \$ref/i)

    const aliases = Array.from({ length: 40 }, (_, index) => `a${index}: &a${index} x`).join('\n')
    await expect(
      service.preview({
        scanId: scan.id,
        importActorRef: 'import.test-harness',
        mediaType: 'application/yaml',
        bytes: encode(`openapi: 3.0.3\n${aliases}`)
      })
    ).rejects.toThrow(/alias/i)

    await expect(
      service.preview({
        scanId: scan.id,
        importActorRef: 'import.test-harness',
        bytes: encode('!!python/object:os.system\ncmd: rm')
      })
    ).rejects.toThrow(/tag/i)

    await expect(
      service.preview({
        scanId: scan.id,
        importActorRef: 'import.test-harness',
        bytes: encode('{')
      })
    ).rejects.toThrow()

    const hugePaths = Object.fromEntries(
      Array.from({ length: 8 }, (_, index) => [`/p${index}`, { get: {} }])
    )
    const limited = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes: encode(
        JSON.stringify({
          openapi: '3.0.3',
          info: { title: 't', version: '1' },
          servers: [{ url: 'https://inventory.example.test' }],
          paths: hugePaths
        })
      ),
      limits: {
        maxFileBytes: 2_097_152,
        maxDocumentDepth: 32,
        maxObjectCount: 50_000,
        maxOperations: 3,
        maxStringLength: 16_384,
        maxYamlAliases: 32,
        maxParseTimeMs: 5_000
      }
    })
    expect(limited.warnings.some((warning) => warning.code === 'too-many-operations')).toBe(true)
    expect(limited.operations.length).toBeLessThanOrEqual(3)
  })

  it('keeps out-of-scope and unresolved operations out of inventory', async () => {
    const { service, scan, database } = await createHarness('scope')
    const preview = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes: encode(
        JSON.stringify({
          openapi: '3.0.3',
          info: { title: 't', version: '1' },
          servers: [{ url: 'https://outside.example.test' }],
          paths: {
            '/pets': { get: {} },
            '/relative': { get: {} }
          }
        })
      )
    })
    expect(preview.stats.accepted).toBe(0)
    expect(preview.stats.rejectedOutOfScope).toBeGreaterThan(0)
    const commit = await service.commit({
      previewId: preview.previewId,
      previewHash: preview.previewHash,
      sourceBytesHash: preview.sourceBytesHash,
      parserVersion: IMPORT_PARSER_VERSION,
      importActorRef: 'import.test-harness'
    })
    expect(commit.acceptedCount).toBe(0)
    const count = database.native
      .prepare('SELECT count(*) AS n FROM endpoints WHERE scan_id = ?')
      .get(scan.id) as { n: number }
    expect(count.n).toBe(0)
  })

  it('rejects preview hash mismatch, expiry, terminal scans, parser drift and asyncapi execution claims', async () => {
    const { service, scan, repository } = await createHarness('guards')
    const bytes = encode(
      JSON.stringify({
        openapi: '3.0.3',
        info: { title: 't', version: '1' },
        servers: [{ url: 'https://inventory.example.test' }],
        paths: { '/ok': { get: {} } }
      })
    )
    const preview = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes
    })
    await expect(
      service.commit({
        previewId: preview.previewId,
        previewHash: 'b'.repeat(64),
        sourceBytesHash: preview.sourceBytesHash,
        parserVersion: IMPORT_PARSER_VERSION,
        importActorRef: 'import.test-harness'
      })
    ).rejects.toThrow(/hash mismatch/i)

    vi.useFakeTimers()
    vi.setSystemTime(new Date(Date.parse(preview.expiresAt) + 1_000))
    await expect(
      service.commit({
        previewId: preview.previewId,
        previewHash: preview.previewHash,
        sourceBytesHash: preview.sourceBytesHash,
        parserVersion: IMPORT_PARSER_VERSION,
        importActorRef: 'import.test-harness'
      })
    ).rejects.toThrow(/expired/i)
    vi.useRealTimers()

    const asyncapi = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes: encode(JSON.stringify({ asyncapi: '2.6.0', info: { title: 'bus' } }))
    })
    expect(asyncapi.format).toBe('asyncapi')
    expect(asyncapi.adapterStatus).toBe('unsupported')
    expect(asyncapi.warnings.some((warning) => warning.code === 'unsupported-format')).toBe(true)

    await repository.updateScan(scan.id, { status: 'completed', completedAt: Date.now() })
    await expect(
      service.preview({
        scanId: scan.id,
        importActorRef: 'import.test-harness',
        bytes
      })
    ).rejects.toThrow(/Terminal/i)
  })

  it('imports from an evidence artifact after hash verification', async () => {
    const { service, scan, evidenceStore, workspaceId } = await createHarness('evidence')
    const bytes = encode(
      JSON.stringify({
        openapi: '3.0.3',
        info: { title: 't', version: '1' },
        servers: [{ url: 'https://inventory.example.test' }],
        paths: { '/from-evidence': { get: {} } }
      })
    )
    const saved = await evidenceStore.save({
      workspaceId,
      scanId: scan.id,
      type: 'imported-openapi',
      mimeType: 'application/json',
      content: bytes,
      source: 'import-test',
      createdBy: 'import.test-harness',
      captureTool: 'import-test',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
    const preview = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      evidenceRef: saved.id,
      expectedHash: sha256(bytes)
    })
    expect(preview.stats.accepted).toBe(1)
    await expect(
      service.preview({
        scanId: scan.id,
        importActorRef: 'import.test-harness',
        evidenceRef: saved.id,
        expectedHash: 'c'.repeat(64)
      })
    ).rejects.toThrow(/hash mismatch/i)
  })

  it('promotes OpenAPI parameter and response schema into inventory selectors', async () => {
    const { service, scan } = await createHarness('schema')
    const preview = await service.preview({
      scanId: scan.id,
      importActorRef: 'import.test-harness',
      bytes: encode(
        JSON.stringify({
          openapi: '3.0.3',
          info: { title: 'Orders', version: '1' },
          servers: [{ url: 'https://inventory.example.test' }],
          paths: {
            '/orders/{orderId}': {
              get: {
                parameters: [
                  {
                    name: 'orderId',
                    in: 'path',
                    required: true,
                    schema: { type: 'integer' }
                  },
                  {
                    name: 'trace',
                    in: 'query',
                    schema: { type: 'string', format: 'uuid' }
                  }
                ],
                responses: {
                  '200': {
                    content: {
                      'application/json': {
                        schema: {
                          type: 'object',
                          properties: {
                            id: { type: 'integer' },
                            owner_id: { type: 'string' }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        })
      )
    })
    const operation = preview.operations[0]
    expect(operation?.parameters).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'orderId',
          location: 'path',
          valueType: 'integer',
          resourceKind: 'resource-id',
          ownerField: 'owner_id',
          responseIdentityField: 'id'
        }),
        expect.objectContaining({
          name: 'trace',
          location: 'query',
          format: 'uuid',
          resourceKind: 'resource-id'
        })
      ])
    )
    const committed = await service.commit({
      previewId: preview.previewId,
      previewHash: preview.previewHash,
      sourceBytesHash: preview.sourceBytesHash,
      parserVersion: IMPORT_PARSER_VERSION,
      importActorRef: 'import.test-harness'
    })
    expect(committed.acceptedCount).toBe(1)
  })
})
