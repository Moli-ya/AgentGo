import { randomUUID } from 'node:crypto'
import {
  InventoryMergeReportSchema,
  type InventoryExecutionClass,
  type InventoryMergeCountBucket,
  type InventoryMergeProducer,
  type InventoryMergeReport,
  type TargetScopeRecord,
  type UpsertInventoryInput,
  type UpsertInventoryResult
} from '@agentgo/contracts'
import { canonicalizeInventoryUrl, redactInventoryUrlPreview } from '@agentgo/domain'
import {
  AgentGoRepository,
  DiscoveryRuntimeRepository
} from '@agentgo/db'
import { evaluateProbe } from '@agentgo/security-policy'
import { InventoryService } from './inventory-service'

type MutableMergeBucket = {
  created: number
  merged: number
  conflict: number
  rejected: number
  outOfScope: number
  secretRedacted: number
  inventoryOnly: number
  awaitingReview: number
  unsupported: number
}

function emptyBucket(): MutableMergeBucket {
  return {
    created: 0,
    merged: 0,
    conflict: 0,
    rejected: 0,
    outOfScope: 0,
    secretRedacted: 0,
    inventoryOnly: 0,
    awaitingReview: 0,
    unsupported: 0
  }
}

function add(
  target: MutableMergeBucket,
  key: keyof MutableMergeBucket
): void {
  target[key] += 1
}

const CLASS_RANK: Record<InventoryExecutionClass, number> = {
  forbidden: 4,
  unsupported: 3,
  'inventory-only': 2,
  'active-l2': 1,
  'active-l1': 0
}

export interface InventoryMergeIngestInput {
  readonly producer: InventoryMergeProducer
  readonly scope: TargetScopeRecord
  readonly inventory: UpsertInventoryInput
}

export class InventoryMergeService {
  constructor(
    private readonly inventory: InventoryService,
    private readonly repository: AgentGoRepository,
    private readonly runtime: DiscoveryRuntimeRepository
  ) {}

  async ingest(input: InventoryMergeIngestInput): Promise<{
    readonly result?: UpsertInventoryResult
    readonly reportDelta: InventoryMergeCountBucket
  }> {
    const delta = emptyBucket()
    const redactedUrl = redactInventoryUrlPreview(input.inventory.url)
    if (redactedUrl !== input.inventory.preview.url) {
      add(delta, 'secretRedacted')
    }
    if (!this.inScope(input.inventory.url, input.scope)) {
      add(delta, 'outOfScope')
      add(delta, 'rejected')
      return { reportDelta: delta }
    }

    const before = await this.findExistingVariant(
      input.inventory.scanId,
      input.inventory.method,
      input.inventory.url
    )
    const result = await this.inventory.upsertInventory(input.inventory)
    if (
      before &&
      CLASS_RANK[before.executionClass] >
        CLASS_RANK[result.requestVariant.executionClass]
    ) {
      add(delta, 'conflict')
    }
    if (before?.variantId === result.requestVariant.id) {
      add(delta, 'merged')
    } else {
      add(delta, 'created')
    }
    if (result.requestVariant.executionClass === 'inventory-only') {
      add(delta, 'inventoryOnly')
    }
    if (result.requestVariant.executionClass === 'unsupported') {
      add(delta, 'unsupported')
    }
    if (
      result.requestVariant.reviewStatus === 'unreviewed' &&
      (result.requestVariant.executionClass === 'active-l1' ||
        result.requestVariant.executionClass === 'active-l2')
    ) {
      add(delta, 'awaitingReview')
    }
    return { result, reportDelta: delta }
  }

  async persistReport(input: {
    readonly scanId: string
    readonly scopeSnapshotId: string
    readonly deltas: readonly {
      readonly producer: InventoryMergeProducer
      readonly capabilityId: string
      readonly counts: InventoryMergeCountBucket
    }[]
  }): Promise<InventoryMergeReport> {
    const totals = emptyBucket()
    const byProducer = new Map<InventoryMergeProducer, MutableMergeBucket>()
    const byCapability = new Map<string, MutableMergeBucket>()
    for (const delta of input.deltas) {
      const producer = byProducer.get(delta.producer) ?? emptyBucket()
      const capability = byCapability.get(delta.capabilityId) ?? emptyBucket()
      for (const key of Object.keys(totals) as (keyof MutableMergeBucket)[]) {
        totals[key] += delta.counts[key]
        producer[key] += delta.counts[key]
        capability[key] += delta.counts[key]
      }
      byProducer.set(delta.producer, producer)
      byCapability.set(delta.capabilityId, capability)
    }
    const report = InventoryMergeReportSchema.parse({
      schemaVersion: 'agentgo.inventory-merge-report.v1',
      reportId: randomUUID(),
      scanId: input.scanId,
      scopeSnapshotId: input.scopeSnapshotId,
      totals,
      byProducer: [...byProducer.entries()].map(([producer, counts]) => ({
        producer,
        counts
      })),
      byCapability: [...byCapability.entries()].map(([capabilityId, counts]) => ({
        capabilityId: capabilityId === '' ? 'none' : capabilityId,
        counts
      })),
      createdAt: new Date().toISOString()
    })
    return this.runtime.saveMergeReport(report)
  }

  private inScope(url: string, scope: TargetScopeRecord): boolean {
    return evaluateProbe(
      {
        id: 'inventory-merge-scope',
        kind: 'http-request',
        targetUrl: url,
        method: 'GET',
        probeLevel: 'passive',
        sideEffect: 'none',
        summary: 'Inventory merge scope check',
        expectedEvidence: 'none',
        maxRequests: 1,
        timeoutMs: 1_000,
        userApproved: false
      },
      scope
    ).allowed
  }

  private async findExistingVariant(
    scanId: string,
    method: string,
    url: string
  ): Promise<{ variantId: string; executionClass: InventoryExecutionClass } | undefined> {
    const canonical = canonicalizeInventoryUrl(url)
    const endpoints = await this.repository.listInventoryEndpoints(scanId)
    const endpoint = endpoints.find(
      (item) =>
        item.method === method && canonicalizeInventoryUrl(item.url) === canonical
    )
    if (!endpoint) return undefined
    const variants = await this.repository.listInventoryRequestVariants(scanId)
    const variant = variants.find((item) => item.endpointId === endpoint.id)
    if (!variant) return undefined
    return { variantId: variant.id, executionClass: variant.executionClass }
  }
}
