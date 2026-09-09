import { and, asc, desc, eq } from 'drizzle-orm'
import {
  AssetManifestSchema,
  ExtractionRuleSchema,
  ImportCommitResultSchema,
  ImportPreviewSchema,
  StaticDiscoveryCandidateBatchSchema,
  type AssetManifest,
  type ExtractionRule,
  type ImportCommitResult,
  type ImportPreview,
  type StaticDiscoveryCandidateBatch
} from '@agentgo/contracts'
import type { AgentGoDatabase } from './database'
import {
  assetManifests,
  extractionRules,
  importCommits,
  importPreviews,
  staticDiscoveryBatches
} from './schema'

export interface ImportCommitRecord {
  readonly commitId: string
  readonly previewId: string
  readonly scanId: string
  readonly sourceBytesHash: string
  readonly parserVersion: string
  readonly importActorRef: string
  readonly acceptedCount: number
  readonly sourceIds: readonly string[]
  readonly createdAt: number
}

function epochMs(iso: string): number {
  const value = Date.parse(iso)
  if (!Number.isFinite(value)) {
    throw new TypeError('Import/discovery timestamp is not a valid ISO-8601 instant.')
  }
  return value
}

export class ImportDiscoveryRepository {
  constructor(private readonly database: AgentGoDatabase) {}

  async saveImportPreview(preview: ImportPreview): Promise<ImportPreview> {
    const parsed = ImportPreviewSchema.parse(preview)
    await this.database.orm.insert(importPreviews).values({
      previewId: parsed.previewId,
      previewHash: parsed.previewHash,
      scanId: parsed.scanId,
      workspaceId: parsed.workspaceId,
      scopeSnapshotId: parsed.scopeSnapshotId,
      sourceBytesHash: parsed.sourceBytesHash,
      parserName: parsed.parserName,
      parserVersion: parsed.parserVersion,
      status: 'active',
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt),
      expiresAt: epochMs(parsed.expiresAt)
    })
    return parsed
  }

  async getImportPreview(previewId: string): Promise<ImportPreview | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(importPreviews)
      .where(eq(importPreviews.previewId, previewId))
      .limit(1)
    if (!row) return undefined
    return ImportPreviewSchema.parse(row.payloadJson)
  }

  async markImportPreviewCommitted(previewId: string): Promise<void> {
    await this.database.orm
      .update(importPreviews)
      .set({ status: 'committed' })
      .where(eq(importPreviews.previewId, previewId))
  }

  async listCommittedImportPreviews(scanId: string): Promise<ImportPreview[]> {
    const rows = await this.database.orm
      .select()
      .from(importPreviews)
      .where(
        and(eq(importPreviews.scanId, scanId), eq(importPreviews.status, 'committed'))
      )
      .orderBy(desc(importPreviews.createdAt))
    return rows.map((row) => ImportPreviewSchema.parse(row.payloadJson))
  }

  async getImportCommitByIdempotency(input: {
    readonly scanId: string
    readonly sourceBytesHash: string
    readonly parserVersion: string
  }): Promise<ImportCommitResult | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(importCommits)
      .where(
        and(
          eq(importCommits.scanId, input.scanId),
          eq(importCommits.sourceBytesHash, input.sourceBytesHash),
          eq(importCommits.parserVersion, input.parserVersion)
        )
      )
      .limit(1)
    if (!row) return undefined
    return ImportCommitResultSchema.parse({
      commitId: row.commitId,
      previewId: row.previewId,
      idempotentReplay: true,
      acceptedCount: row.acceptedCount,
      sourceIds: row.sourceIdsJson
    })
  }

  async saveImportCommit(input: {
    readonly commitId: string
    readonly previewId: string
    readonly scanId: string
    readonly sourceBytesHash: string
    readonly parserVersion: string
    readonly importActorRef: string
    readonly acceptedCount: number
    readonly sourceIds: readonly string[]
    readonly createdAt: number
  }): Promise<ImportCommitResult> {
    await this.database.orm.insert(importCommits).values({
      commitId: input.commitId,
      previewId: input.previewId,
      scanId: input.scanId,
      sourceBytesHash: input.sourceBytesHash,
      parserVersion: input.parserVersion,
      importActorRef: input.importActorRef,
      acceptedCount: input.acceptedCount,
      sourceIdsJson: [...input.sourceIds],
      createdAt: input.createdAt
    })
    return ImportCommitResultSchema.parse({
      commitId: input.commitId,
      previewId: input.previewId,
      idempotentReplay: false,
      acceptedCount: input.acceptedCount,
      sourceIds: [...input.sourceIds]
    })
  }

  async saveStaticDiscoveryBatch(
    batch: StaticDiscoveryCandidateBatch
  ): Promise<StaticDiscoveryCandidateBatch> {
    const parsed = StaticDiscoveryCandidateBatchSchema.parse(batch)
    const [existing] = await this.database.orm
      .select()
      .from(staticDiscoveryBatches)
      .where(
        and(
          eq(staticDiscoveryBatches.scanId, parsed.scanId),
          eq(staticDiscoveryBatches.artifactHash, parsed.artifactHash)
        )
      )
      .limit(1)
    if (existing) {
      return StaticDiscoveryCandidateBatchSchema.parse(existing.payloadJson)
    }
    await this.database.orm.insert(staticDiscoveryBatches).values({
      batchId: parsed.batchId,
      scanId: parsed.scanId,
      artifactRef: parsed.artifactRef,
      artifactHash: parsed.artifactHash,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt)
    })
    return parsed
  }

  async saveAssetManifest(manifest: AssetManifest): Promise<AssetManifest> {
    const parsed = AssetManifestSchema.parse(manifest)
    await this.database.orm.insert(assetManifests).values({
      manifestId: parsed.manifestId,
      manifestVersion: parsed.manifestVersion,
      manifestHash: parsed.manifestHash,
      scanId: parsed.scanId,
      scopeSnapshotId: parsed.scopeSnapshotId,
      frozen: parsed.frozen,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt),
      frozenAt: parsed.frozenAt ? epochMs(parsed.frozenAt) : null
    })
    return parsed
  }

  async getAssetManifest(
    manifestId: string,
    manifestVersion?: number
  ): Promise<AssetManifest | undefined> {
    const rows = await this.database.orm
      .select()
      .from(assetManifests)
      .where(eq(assetManifests.manifestId, manifestId))
      .orderBy(desc(assetManifests.manifestVersion))
    const row =
      manifestVersion === undefined
        ? rows[0]
        : rows.find((item) => item.manifestVersion === manifestVersion)
    if (!row) return undefined
    return AssetManifestSchema.parse(row.payloadJson)
  }

  async freezeAssetManifest(manifest: AssetManifest): Promise<AssetManifest> {
    const parsed = AssetManifestSchema.parse(manifest)
    if (!parsed.frozen || parsed.frozenAt === undefined) {
      throw new Error('Frozen asset manifests require frozenAt.')
    }
    await this.database.orm
      .update(assetManifests)
      .set({
        frozen: true,
        frozenAt: epochMs(parsed.frozenAt),
        payloadJson: parsed,
        manifestHash: parsed.manifestHash
      })
      .where(
        and(
          eq(assetManifests.manifestId, parsed.manifestId),
          eq(assetManifests.manifestVersion, parsed.manifestVersion)
        )
      )
    return parsed
  }

  async saveExtractionRule(rule: ExtractionRule): Promise<ExtractionRule> {
    const parsed = ExtractionRuleSchema.parse(rule)
    await this.database.orm.insert(extractionRules).values({
      ruleId: parsed.ruleId,
      ruleHash: parsed.ruleHash,
      scanId: parsed.scanId,
      reviewStatus: parsed.reviewStatus,
      frozen: parsed.frozen,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt)
    })
    return parsed
  }

  async getExtractionRule(ruleId: string): Promise<ExtractionRule | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(extractionRules)
      .where(eq(extractionRules.ruleId, ruleId))
      .limit(1)
    if (!row) return undefined
    return ExtractionRuleSchema.parse(row.payloadJson)
  }

  async updateExtractionRule(rule: ExtractionRule): Promise<ExtractionRule> {
    const parsed = ExtractionRuleSchema.parse(rule)
    await this.database.orm
      .update(extractionRules)
      .set({
        ruleHash: parsed.ruleHash,
        reviewStatus: parsed.reviewStatus,
        frozen: parsed.frozen,
        payloadJson: parsed
      })
      .where(eq(extractionRules.ruleId, parsed.ruleId))
    return parsed
  }

  async listFrozenAssetManifests(scanId: string): Promise<AssetManifest[]> {
    const rows = await this.database.orm
      .select()
      .from(assetManifests)
      .where(and(eq(assetManifests.scanId, scanId), eq(assetManifests.frozen, true)))
      .orderBy(desc(assetManifests.createdAt))
    return rows.map((row) => AssetManifestSchema.parse(row.payloadJson))
  }

  async listFrozenExtractionRules(scanId: string): Promise<ExtractionRule[]> {
    const rows = await this.database.orm
      .select()
      .from(extractionRules)
      .where(and(eq(extractionRules.scanId, scanId), eq(extractionRules.frozen, true)))
      .orderBy(asc(extractionRules.createdAt))
    return rows.map((row) => ExtractionRuleSchema.parse(row.payloadJson))
  }
}
