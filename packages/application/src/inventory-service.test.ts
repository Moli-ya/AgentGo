import { randomUUID } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import type { Environment } from '@agentgo/contracts'
import {
  AgentGoRepository,
  openAgentGoDatabase,
  type AgentGoDatabase
} from '@agentgo/db'
import { InventoryService } from './inventory-service'
import {
  buildScanModuleSnapshotDrafts,
  computeScanModuleSnapshotHash
} from './scan-module-snapshot'
import { createDay2VulnerabilityPlatform } from './vulnerability-platform'

const sentinel = 'DAY3_SENTINEL_SECRET_must-not-leak'
const highEntropy = 'N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa'
const jwt =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXkzLXVzZXIifQ.QWx3YXlzUmVkYWN0VGhpc1NpZ25hdHVyZQ'

afterEach(() => {
  vi.restoreAllMocks()
})

async function createScan(
  repository: AgentGoRepository,
  suffix: string,
  environment?: Environment
) {
  const workspace = await repository.createWorkspace({
    name: `Inventory workspace ${suffix}`,
    description: ''
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: `Authorized inventory fixture ${suffix}`,
    baseUrl: 'https://inventory.example.test/',
    description: '',
    authorizationReference: `inventory-test-${suffix}`,
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
      maxRequestsPerMinute: 10,
      maxConcurrency: 1,
      authorizationReference: `inventory-test-${suffix}`
    }
  })
  const plan = createDefaultScanPlan(['sqli'])
  const platform = createDay2VulnerabilityPlatform()
  const snapshots = environment
    ? buildScanModuleSnapshotDrafts(['sqli'], environment, platform).map(
        (draft) => ({
          draft,
          snapshotHash: computeScanModuleSnapshotHash(draft)
        })
      )
    : []
  return repository.createScan(
    {
      targetId: target.target.id,
      name: `Inventory scan ${suffix}`,
      description: '',
      families: ['sqli'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() },
    snapshots
  )
}

function noneVariant(scanId: string, sourceHash = '1'.repeat(64)) {
  return {
    scanId,
    method: 'GET',
    url: 'https://inventory.example.test/items?id=1',
    bodyShape: { rootType: 'none' as const, fields: [] },
    codec: 'none' as const,
    transport: 'standard-http' as const,
    allowedHeaders: [],
    templateVersion: '1.0.0',
    requiredCapabilityIds: ['http.reviewed-read'],
    selectors: [
      {
        kind: 'query' as const,
        name: 'id',
        valueType: 'number' as const,
        required: true
      }
    ],
    preview: { url: 'https://inventory.example.test/items?id=1' },
    source: {
      type: 'target-base',
      sourceHash,
      confidence: 1
    }
  }
}

function persistedInventoryText(database: AgentGoDatabase): string {
  const rows = database.native
    .prepare(
      `SELECT canonical_route AS value FROM endpoints
       UNION ALL SELECT normalized_url FROM endpoints
       UNION ALL SELECT url_template FROM endpoints
       UNION ALL SELECT body_shape_json FROM request_variants
       UNION ALL SELECT allowed_headers_json FROM request_variants
       UNION ALL SELECT redacted_preview_json FROM request_variants
       UNION ALL SELECT selector_json FROM request_variant_selectors
       UNION ALL SELECT initiator FROM inventory_sources WHERE initiator IS NOT NULL
       UNION ALL SELECT name FROM parameters`
    )
    .all()
  return JSON.stringify(rows)
}

function insertSyntheticEvidence(database: AgentGoDatabase, scanId: string): string {
  const id = randomUUID()
  const owner = database.native
    .prepare(
      `SELECT targets.workspace_id
       FROM scans
       INNER JOIN targets ON targets.id = scans.target_id
       WHERE scans.id = ?`
    )
    .get(scanId) as { workspace_id: string }
  database.native
    .prepare(
      `INSERT INTO evidence_items (
         id, workspace_id, scan_id, interaction_id, policy_decision_id,
         type, mime_type, file_path, sha256, size, source, created_by,
         capture_tool, capture_tool_version, derived_from, redaction_state,
         integrity_status, retention_until, created_at
       ) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, 0, ?, ?, ?, ?, NULL, ?, ?, NULL, ?)`
    )
    .run(
      id,
      owner.workspace_id,
      scanId,
      'synthetic-inventory-source',
      'application/json',
      `synthetic/${id}.json`,
      'e'.repeat(64),
      'inventory-test',
      'inventory-test',
      'vitest',
      '1.0.0',
      'redacted',
      'verified',
      Date.now()
    )
  return id
}

describe('InventoryService unified write port', () => {
  it('keeps JSON/form/XML variants and provenance idempotent and scan-scoped', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const platform = createDay2VulnerabilityPlatform()
    const service = new InventoryService(repository, platform.capabilityCatalog)
    try {
      const firstScan = await createScan(repository, 'first')
      const secondScan = await createScan(repository, 'second')
      const route = 'https://inventory.example.test/api/profile?token=one'
      const base = {
        scanId: firstScan.id,
        method: 'POST',
        url: route,
        transport: 'standard-http' as const,
        allowedHeaders: [
          { name: 'content-type', valueType: 'string' as const, required: true }
        ],
        templateVersion: '1.0.0',
        requiredCapabilityIds: ['http.test-object-write'],
        preview: { url: route },
        source: {
          type: 'openapi-import',
          sourceHash: '2'.repeat(64),
          confidence: 0.9
        }
      }
      const jsonInput = {
        ...base,
        contentType: 'application/json',
        bodyShape: {
          rootType: 'object' as const,
          fields: [
            { path: '/profile/name', valueType: 'string' as const, required: true }
          ]
        },
        codec: 'json' as const,
        selectors: [
          {
            kind: 'json-pointer' as const,
            pointer: '/profile/name',
            valueType: 'string' as const,
            required: true
          }
        ]
      }
      const jsonFirst = await service.upsertInventory(jsonInput)
      const jsonRepeat = await service.upsertInventory(jsonInput)
      expect(jsonRepeat).toEqual(jsonFirst)

      const secondSource = await service.upsertInventory({
        ...jsonInput,
        source: {
          type: 'har-import',
          sourceHash: '3'.repeat(64),
          confidence: 0.8
        }
      })
      expect(secondSource.endpoint.id).toBe(jsonFirst.endpoint.id)
      expect(secondSource.requestVariant.id).toBe(jsonFirst.requestVariant.id)
      expect(secondSource.source.id).not.toBe(jsonFirst.source.id)

      for (const variant of [
        {
          codec: 'form' as const,
          contentType: 'application/x-www-form-urlencoded',
          selector: {
            kind: 'form' as const,
            name: 'name',
            valueType: 'string' as const,
            required: true
          },
          path: '/name',
          hash: '4'.repeat(64)
        },
        {
          codec: 'xml' as const,
          contentType: 'application/xml',
          selector: {
            kind: 'xml-path' as const,
            path: '/profile/name',
            valueType: 'string' as const,
            required: true
          },
          path: '/profile/name',
          hash: '5'.repeat(64)
        }
      ]) {
        const result = await service.upsertInventory({
          ...base,
          contentType: variant.contentType,
          bodyShape: {
            rootType: 'object',
            fields: [
              { path: variant.path, valueType: 'string', required: true }
            ]
          },
          codec: variant.codec,
          selectors: [variant.selector],
          source: { ...base.source, sourceHash: variant.hash }
        })
        expect(result.endpoint.id).toBe(jsonFirst.endpoint.id)
        expect(result.requestVariant.id).not.toBe(jsonFirst.requestVariant.id)
      }

      expect(await repository.listInventoryRequestVariants(firstScan.id)).toHaveLength(3)
      expect(await repository.listInventorySources(firstScan.id)).toHaveLength(4)
      expect(await repository.listInventoryEndpoints(firstScan.id)).toHaveLength(1)

      const isolated = await service.upsertInventory({
        ...jsonInput,
        scanId: secondScan.id
      })
      expect(isolated.endpoint.id).not.toBe(jsonFirst.endpoint.id)
      expect(isolated.requestVariant.id).not.toBe(jsonFirst.requestVariant.id)
      expect(await repository.listInventoryRequestVariants(secondScan.id)).toHaveLength(1)
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      database.close()
    }
  })

  it('redacts URL/header/body secrets before any SQLite inventory write', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const platform = createDay2VulnerabilityPlatform()
    const service = new InventoryService(repository, platform.capabilityCatalog)
    try {
      const scan = await createScan(repository, 'secret')
      const url = `https://alice:${sentinel}@inventory.example.test/reset/${highEntropy}?token=${sentinel}&next=${jwt}#private`
      const result = await service.upsertInventory({
        scanId: scan.id,
        method: 'POST',
        url,
        contentType: `application/json; boundary=${highEntropy}`,
        bodyShape: {
          rootType: 'object',
          fields: [
            { path: `/${highEntropy}`, valueType: 'string', required: true }
          ]
        },
        codec: 'json',
        transport: 'standard-http',
        allowedHeaders: [
          { name: highEntropy, valueType: 'string', required: false },
          { name: 'authorization', valueType: 'string', required: true }
        ],
        templateVersion: '1.0.0',
        requiredCapabilityIds: ['http.test-object-write'],
        selectors: [
          {
            kind: 'json-pointer',
            pointer: `/${highEntropy}`,
            valueType: 'string',
            required: true
          }
        ],
        preview: {
          url,
          headers: {
            Authorization: `Bearer ${highEntropy}`,
            Cookie: `sid=${sentinel}`,
            'X-Trace': jwt
          },
          body: JSON.stringify({
            password: sentinel,
            token: highEntropy,
            jwt
          })
        },
        source: {
          type: 'har-import',
          sourceHash: '6'.repeat(64),
          initiator: `https://inventory.example.test/source?token=${sentinel}`,
          confidence: 1
        }
      })
      expect(result.endpoint.canonicalRoute).toBe(
        'https://inventory.example.test/reset/:redacted'
      )
      expect(result.requestVariant.redactedPreview.url).not.toContain(sentinel)
      const persisted = persistedInventoryText(database)
      for (const secret of [sentinel, highEntropy, jwt, `Bearer ${highEntropy}`]) {
        expect(persisted).not.toContain(secret)
      }
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      database.close()
    }
  })

  it('bounds Unicode-expanded canonical routes before the atomic write', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const service = new InventoryService(
      repository,
      createDay2VulnerabilityPlatform().capabilityCatalog
    )
    try {
      const scan = await createScan(repository, 'unicode-route')
      const url = `https://inventory.example.test/${String.fromCodePoint(0x1f600).repeat(4_000)}`
      const result = await service.upsertInventory({
        ...noneVariant(scan.id, '7'.repeat(64)),
        url,
        preview: { url }
      })

      expect(result.endpoint.canonicalRoute).toMatch(
        /^https:\/\/inventory\.example\.test\/_redacted-path-[a-f0-9]{16}$/u
      )
      expect(result.endpoint.canonicalRoute.length).toBeLessThanOrEqual(16_384)
      expect(
        database.native
          .prepare('SELECT COUNT(*) AS count FROM endpoints WHERE scan_id = ?')
          .get(scan.id)
      ).toEqual({ count: 1 })
    } finally {
      database.close()
    }
  })

  it('accepts only same-scan system-issued evidence references', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const service = new InventoryService(
      repository,
      createDay2VulnerabilityPlatform().capabilityCatalog
    )
    try {
      const firstScan = await createScan(repository, 'evidence-first')
      const secondScan = await createScan(repository, 'evidence-second')
      const evidenceRef = insertSyntheticEvidence(database, firstScan.id)
      const valid = await service.upsertInventory({
        ...noneVariant(firstScan.id),
        source: {
          ...noneVariant(firstScan.id).source,
          evidenceRef
        }
      })
      expect(valid.source.evidenceRef).toBe(evidenceRef)

      await expect(
        service.upsertInventory({
          ...noneVariant(secondScan.id),
          source: {
            ...noneVariant(secondScan.id).source,
            evidenceRef
          }
        })
      ).rejects.toThrow(/does not belong to this scan/)
      expect(await repository.listInventoryEndpoints(secondScan.id)).toEqual([])
    } finally {
      database.close()
    }
  })

  it('keeps deterministic execution class separate from review and retirement', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const platform = createDay2VulnerabilityPlatform()
    const service = new InventoryService(repository, platform.capabilityCatalog)
    try {
      const scan = await createScan(
        repository,
        'state',
        'authorized-real-target'
      )
      const initial = await service.upsertInventory(noneVariant(scan.id))
      expect(initial.requestVariant).toMatchObject({
        reviewStatus: 'unreviewed',
        executionClass: 'active-l1',
        lifecycleStatus: 'active'
      })
      expect(await repository.listLegacyV1ExecutionEndpoints(scan.id)).toEqual([])

      await expect(
        service.upsertInventory({
          ...noneVariant(scan.id, '2'.repeat(64)),
          reviewStatus: 'reviewed',
          executionClass: 'active-l1'
        })
      ).rejects.toBeDefined()
      expect(await repository.listInventorySources(scan.id)).toHaveLength(1)

      const reviewed = await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: initial.requestVariant.id,
        reviewStatus: 'reviewed',
        reviewedBy: 'review-audit-1'
      })
      expect(reviewed).toMatchObject({
        reviewStatus: 'reviewed',
        executionClass: 'active-l1'
      })
      expect(await repository.listLegacyV1ExecutionEndpoints(scan.id)).toHaveLength(1)
      expect(
        (await repository.listInventorySources(scan.id, initial.requestVariant.id)).every(
          (source) => source.reviewStatus === 'reviewed'
        )
      ).toBe(true)
      const rejected = await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: initial.requestVariant.id,
        reviewStatus: 'rejected',
        reviewedBy: 'review-audit-2'
      })
      expect(rejected).toMatchObject({
        reviewStatus: 'rejected',
        executionClass: 'active-l1'
      })
      expect(await repository.listLegacyV1ExecutionEndpoints(scan.id)).toEqual([])

      const externalUrl = 'https://inventory.example.test/external?id=1'
      const external = await service.upsertInventory({
        ...noneVariant(scan.id, 'a'.repeat(64)),
        url: externalUrl,
        preview: { url: externalUrl },
        source: {
          type: 'har-import',
          sourceHash: 'a'.repeat(64),
          confidence: 1
        }
      })
      expect(external.requestVariant.executionClass).toBe('active-l1')
      expect(await repository.listLegacyV1ExecutionEndpoints(scan.id)).toEqual([])
      await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: external.requestVariant.id,
        reviewStatus: 'reviewed',
        reviewedBy: 'review-audit-external'
      })
      expect(await repository.listLegacyV1ExecutionEndpoints(scan.id)).toMatchObject([
        {
          id: external.endpoint.id,
          method: 'GET',
          parameters: [{ name: 'id', location: 'query' }]
        }
      ])

      const forbidden = await service.upsertInventory({
        ...noneVariant(scan.id, '7'.repeat(64)),
        method: 'DELETE'
      })
      expect(forbidden.requestVariant.executionClass).toBe('forbidden')
      const unsupported = await service.upsertInventory({
        ...noneVariant(scan.id, '8'.repeat(64)),
        requiredCapabilityIds: ['http.future-read']
      })
      expect(unsupported.requestVariant.executionClass).toBe('unsupported')
      const activeL2 = await service.upsertInventory({
        ...noneVariant(scan.id, '9'.repeat(64)),
        method: 'POST',
        requiredCapabilityIds: ['http.test-object-write']
      })
      expect(activeL2.requestVariant.executionClass).toBe('active-l2')

      const retired = await service.retireVariant({
        scanId: scan.id,
        requestVariantId: initial.requestVariant.id
      })
      expect(retired).toMatchObject({ lifecycleStatus: 'retired' })
      await service.retireVariant({
        scanId: scan.id,
        requestVariantId: external.requestVariant.id
      })
      expect(await repository.listLegacyV1ExecutionEndpoints(scan.id)).toEqual([])
      await expect(
        service.reviewVariant({
          scanId: scan.id,
          requestVariantId: initial.requestVariant.id,
          reviewStatus: 'reviewed',
          reviewedBy: 'review-audit-3'
        })
      ).rejects.toThrow(/Retired/)
    } finally {
      database.close()
    }
  })

  it('binds the legacy executable URL to the same reviewed variant selectors', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const service = new InventoryService(
      repository,
      createDay2VulnerabilityPlatform().capabilityCatalog
    )
    try {
      const scan = await createScan(repository, 'variant-execution-url')
      const rejectedUrl = 'https://inventory.example.test/mixed?action=delete'
      const rejectedVariant = await service.upsertInventory({
        ...noneVariant(scan.id, 'b'.repeat(64)),
        url: rejectedUrl,
        contentType: 'application/x-rejected',
        selectors: [
          {
            kind: 'query',
            name: 'action',
            valueType: 'string',
            required: true
          }
        ],
        preview: { url: rejectedUrl },
        source: {
          type: 'har-import',
          sourceHash: 'b'.repeat(64),
          confidence: 1
        }
      })
      await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: rejectedVariant.requestVariant.id,
        reviewStatus: 'rejected',
        reviewedBy: 'review-audit-rejected-variant'
      })

      const retiredUrl = 'https://inventory.example.test/mixed?id=text'
      const retiredVariant = await service.upsertInventory({
        ...noneVariant(scan.id, 'c'.repeat(64)),
        url: retiredUrl,
        selectors: [
          {
            kind: 'query',
            name: 'id',
            valueType: 'string',
            required: false
          }
        ],
        preview: { url: retiredUrl },
        source: {
          type: 'har-import',
          sourceHash: 'c'.repeat(64),
          confidence: 1
        }
      })
      await service.retireVariant({
        scanId: scan.id,
        requestVariantId: retiredVariant.requestVariant.id
      })

      const safeUrl = 'https://inventory.example.test/mixed?id=1'
      const safeVariant = await service.upsertInventory({
        ...noneVariant(scan.id, 'd'.repeat(64)),
        url: safeUrl,
        contentType: 'application/json',
        selectors: [
          {
            kind: 'query',
            name: 'id',
            valueType: 'number',
            required: true
          }
        ],
        preview: { url: safeUrl },
        source: {
          type: 'target-base',
          sourceHash: 'd'.repeat(64),
          confidence: 1
        }
      })
      await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: safeVariant.requestVariant.id,
        reviewStatus: 'reviewed',
        reviewedBy: 'review-audit-safe-variant'
      })

      const executable = await repository.listLegacyV1ExecutionEndpoints(scan.id)
      const mixedExecutable = executable.find(({ id }) => id === safeVariant.endpoint.id)
      expect(mixedExecutable).toMatchObject({
        url: 'https://inventory.example.test/mixed?id=%5BREDACTED%5D',
        contentType: 'application/json',
        source: 'target-base',
        parameters: [
          {
            name: 'id',
            location: 'query',
            dataType: 'number',
            required: true
          }
        ]
      })
      expect(mixedExecutable?.url).not.toContain('action')

      const rejectedSemanticUrl =
        'https://inventory.example.test/rejected-semantic?id=false'
      const rejectedSemantic = await service.upsertInventory({
        ...noneVariant(scan.id, 'e'.repeat(64)),
        url: rejectedSemanticUrl,
        selectors: [
          {
            kind: 'query',
            name: 'id',
            valueType: 'boolean',
            required: false
          }
        ],
        preview: { url: rejectedSemanticUrl },
        source: {
          type: 'har-import',
          sourceHash: 'e'.repeat(64),
          confidence: 1
        }
      })
      await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: rejectedSemantic.requestVariant.id,
        reviewStatus: 'rejected',
        reviewedBy: 'review-audit-rejected-semantics'
      })
      const reviewedSemanticUrl =
        'https://inventory.example.test/rejected-semantic?id=1'
      const reviewedSemantic = await service.upsertInventory({
        ...noneVariant(scan.id, 'f'.repeat(64)),
        url: reviewedSemanticUrl,
        selectors: [
          {
            kind: 'query',
            name: 'id',
            valueType: 'number',
            required: true
          }
        ],
        preview: { url: reviewedSemanticUrl },
        source: {
          type: 'har-import',
          sourceHash: 'f'.repeat(64),
          confidence: 1
        }
      })
      await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: reviewedSemantic.requestVariant.id,
        reviewStatus: 'reviewed',
        reviewedBy: 'review-audit-reviewed-semantics'
      })
      expect(
        (await repository.listLegacyV1ExecutionEndpoints(scan.id)).find(
          ({ id }) => id === reviewedSemantic.endpoint.id
        )
      ).toMatchObject({
        parameters: [{ name: 'id', dataType: 'number', required: true }]
      })

      const mixedSelectorUrl =
        'https://inventory.example.test/mixed-selector?id=1'
      const mixedSelector = await service.upsertInventory({
        ...noneVariant(scan.id, '1'.repeat(64)),
        url: mixedSelectorUrl,
        allowedHeaders: [
          { name: 'x-tenant', valueType: 'string', required: true }
        ],
        selectors: [
          {
            kind: 'query',
            name: 'id',
            valueType: 'number',
            required: true
          },
          {
            kind: 'header',
            name: 'x-tenant',
            valueType: 'string',
            required: true
          }
        ],
        preview: { url: mixedSelectorUrl },
        source: {
          type: 'target-base',
          sourceHash: '1'.repeat(64),
          confidence: 1
        }
      })
      await service.reviewVariant({
        scanId: scan.id,
        requestVariantId: mixedSelector.requestVariant.id,
        reviewStatus: 'reviewed',
        reviewedBy: 'review-audit-mixed-selector'
      })
      expect(
        (await repository.listLegacyV1ExecutionEndpoints(scan.id)).some(
          ({ id }) => id === mixedSelector.endpoint.id
        )
      ).toBe(false)
    } finally {
      database.close()
    }
  })

  it('redacts untrusted page titles at the repository persistence sink', async () => {
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    try {
      const scan = await createScan(repository, 'page-title')
      const rawTitle = `Authorization: Bearer ${sentinel}-${highEntropy}`
      const page = await repository.upsertPage({
        scanId: scan.id,
        url: 'https://inventory.example.test/page',
        title: rawTitle,
        depth: 0
      })
      expect(page.title).toContain('[REDACTED]')
      expect(page.title).not.toContain(sentinel)
      expect(page.title).not.toContain(highEntropy)
      expect(
        database.native.prepare('SELECT title FROM pages WHERE id = ?').get(page.id)
      ).toEqual({ title: page.title })
      expect(
        JSON.stringify(database.native.prepare('SELECT title FROM pages').all())
      ).not.toMatch(/DAY3_SENTINEL_SECRET|must-not-leak|N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa/u)
    } finally {
      database.close()
    }
  })
})
