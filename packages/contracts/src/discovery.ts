import { z } from 'zod'
import {
  InventoryHashSchema,
  SystemIssuedOpaqueIdSchema
} from './inventory'
import {
  CapabilityIdSchema,
  DefinitionIdSchema,
  ModuleVersionSchema
} from './vulnerability'

const IsoDateSchema = z.string().datetime()
const SafeTextSchema = z
  .string()
  .trim()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value))

export const StaticDiscoveryMediaTypeSchema = z.enum([
  'text/html',
  'application/javascript',
  'text/javascript',
  'application/json',
  'application/octet-stream'
])

export type StaticDiscoveryMediaType = z.infer<typeof StaticDiscoveryMediaTypeSchema>

export const StaticDiscoveryResourceBudgetSchema = z
  .strictObject({
    maxFileBytes: z.number().int().positive().max(8_388_608),
    maxTotalBytes: z.number().int().positive().max(33_554_432),
    maxAstNodes: z.number().int().positive().max(500_000),
    maxParseTimeMs: z.number().int().positive().max(30_000),
    maxRecursionDepth: z.number().int().positive().max(64),
    maxSources: z.number().int().positive().max(4_096),
    maxStringCandidates: z.number().int().positive().max(8_192),
    maxRegexSteps: z.number().int().positive().max(100_000)
  })
  .readonly()

export type StaticDiscoveryResourceBudget = z.infer<
  typeof StaticDiscoveryResourceBudgetSchema
>

export const DEFAULT_STATIC_DISCOVERY_BUDGET: StaticDiscoveryResourceBudget =
  Object.freeze({
    maxFileBytes: 1_048_576,
    maxTotalBytes: 4_194_304,
    maxAstNodes: 80_000,
    maxParseTimeMs: 5_000,
    maxRecursionDepth: 24,
    maxSources: 256,
    maxStringCandidates: 2_048,
    maxRegexSteps: 20_000
  })

export const StaticDiscoveryInputSchema = z
  .strictObject({
    scanId: SystemIssuedOpaqueIdSchema,
    artifactRef: SystemIssuedOpaqueIdSchema,
    expectedHash: InventoryHashSchema,
    mediaType: StaticDiscoveryMediaTypeSchema,
    baseUrlHint: z.string().url().max(16_384).optional(),
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    budget: StaticDiscoveryResourceBudgetSchema.optional()
  })
  .readonly()

export type StaticDiscoveryInput = z.infer<typeof StaticDiscoveryInputSchema>

export const StaticDiscoveryCandidateKindSchema = z.enum([
  'http-endpoint',
  'form',
  'script',
  'worker',
  'iframe',
  'manifest',
  'websocket',
  'sse',
  'graphql',
  'source-map',
  'extraction-rule'
])

export type StaticDiscoveryCandidateKind = z.infer<
  typeof StaticDiscoveryCandidateKindSchema
>

export const StaticDiscoverySourcePositionSchema = z
  .strictObject({
    file: SafeTextSchema,
    line: z.number().int().positive(),
    column: z.number().int().nonnegative()
  })
  .readonly()

export type StaticDiscoverySourcePosition = z.infer<
  typeof StaticDiscoverySourcePositionSchema
>

export const StaticDiscoverySourceProvenanceSchema = z
  .strictObject({
    generated: StaticDiscoverySourcePositionSchema.optional(),
    original: StaticDiscoverySourcePositionSchema.optional(),
    name: SafeTextSchema.optional()
  })
  .readonly()
  .refine(
    (value) => value.generated !== undefined || value.original !== undefined,
    'Source provenance requires a generated or original position.'
  )

export type StaticDiscoverySourceProvenance = z.infer<
  typeof StaticDiscoverySourceProvenanceSchema
>

export const StaticDiscoveryCandidateSchema = z
  .strictObject({
    key: SafeTextSchema,
    kind: StaticDiscoveryCandidateKindSchema,
    method: z.string().regex(/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u).optional(),
    url: z.string().max(16_384),
    location: SafeTextSchema,
    sourceProvenance: StaticDiscoverySourceProvenanceSchema.optional(),
    confidence: z.number().min(0).max(1),
    capabilityStatus: z.enum(['inventory-only', 'unsupported']),
    secretClassification: z.enum(['none', 'likely-secret']).default('none'),
    warnings: z.array(SafeTextSchema).max(32)
  })
  .readonly()

export type StaticDiscoveryCandidate = z.infer<typeof StaticDiscoveryCandidateSchema>

export const StaticDiscoveryCandidateBatchSchema = z
  .strictObject({
    schemaVersion: z.literal('agentgo.static-discovery.v1'),
    batchId: SystemIssuedOpaqueIdSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    artifactRef: SystemIssuedOpaqueIdSchema,
    artifactHash: InventoryHashSchema,
    mediaType: StaticDiscoveryMediaTypeSchema,
    producer: z.literal('static-offline'),
    candidates: z.array(StaticDiscoveryCandidateSchema).max(8_192),
    warnings: z.array(SafeTextSchema).max(256),
    createdAt: IsoDateSchema
  })
  .readonly()

export type StaticDiscoveryCandidateBatch = z.infer<
  typeof StaticDiscoveryCandidateBatchSchema
>

export const AssetResourceTypeSchema = z.enum([
  'html',
  'javascript',
  'css',
  'source-map',
  'image',
  'font',
  'other'
])

export type AssetResourceType = z.infer<typeof AssetResourceTypeSchema>

export const AssetManifestEntrySchema = z
  .strictObject({
    origin: z.string().url().max(2_048),
    normalizedPath: z
      .string()
      .min(1)
      .max(2_048)
      .refine((value) => value.startsWith('/'), 'Asset path must be origin-absolute.'),
    resourceType: AssetResourceTypeSchema,
    artifactRef: SystemIssuedOpaqueIdSchema,
    contentHash: InventoryHashSchema,
    sri: z.string().trim().min(8).max(200).optional(),
    maxResponseBytes: z.number().int().positive().max(16_777_216),
    scopeSnapshotId: SystemIssuedOpaqueIdSchema
  })
  .readonly()
  .superRefine((entry, context) => {
    if (/[?#]/.test(entry.normalizedPath)) {
      context.addIssue({
        code: 'custom',
        message: 'Asset path cannot contain query or fragment.',
        path: ['normalizedPath']
      })
    }
    if (entry.origin.includes('*') || entry.normalizedPath.includes('*')) {
      context.addIssue({
        code: 'custom',
        message: 'Wildcard origin or path is not a freezeable asset.',
        path: ['origin']
      })
    }
  })

export type AssetManifestEntry = z.infer<typeof AssetManifestEntrySchema>

export const AssetManifestSchema = z
  .strictObject({
    schemaVersion: z.literal('agentgo.asset-manifest.v1'),
    manifestId: SystemIssuedOpaqueIdSchema,
    manifestVersion: z.number().int().positive(),
    manifestHash: InventoryHashSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    reviewer: DefinitionIdSchema,
    frozen: z.boolean(),
    entries: z.array(AssetManifestEntrySchema).max(4_096),
    createdAt: IsoDateSchema,
    frozenAt: IsoDateSchema.optional()
  })
  .readonly()
  .superRefine((manifest, context) => {
    if (manifest.frozen && manifest.frozenAt === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Frozen manifests require frozenAt.',
        path: ['frozenAt']
      })
    }
    const seen = new Set<string>()
    for (const [index, entry] of manifest.entries.entries()) {
      const key = `${entry.origin}\0${entry.normalizedPath}`
      if (seen.has(key)) {
        context.addIssue({
          code: 'custom',
          message: 'Duplicate asset identity.',
          path: ['entries', index]
        })
      }
      seen.add(key)
      if (entry.scopeSnapshotId !== manifest.scopeSnapshotId) {
        context.addIssue({
          code: 'custom',
          message: 'Asset scope snapshot must match the manifest.',
          path: ['entries', index, 'scopeSnapshotId']
        })
      }
    }
  })

export type AssetManifest = z.infer<typeof AssetManifestSchema>

export const ExtractionRuleSourceKindSchema = z.enum([
  'json-pointer',
  'header',
  'cookie',
  'html-selector',
  'regex-capture'
])

export type ExtractionRuleSourceKind = z.infer<
  typeof ExtractionRuleSourceKindSchema
>

const ExtractionRuleDraftFields = {
  scanId: SystemIssuedOpaqueIdSchema,
  name: DefinitionIdSchema,
  sourceKind: ExtractionRuleSourceKindSchema,
  sourceSelector: SafeTextSchema,
  valueType: z.enum(['string', 'number', 'integer', 'boolean']),
  secretClassification: z.enum(['none', 'likely-secret']),
  targetVariable: DefinitionIdSchema,
  identityScope: SystemIssuedOpaqueIdSchema.optional(),
  tenantScope: z.string().trim().min(1).max(200).optional(),
  sourceRef: SystemIssuedOpaqueIdSchema,
  version: ModuleVersionSchema
} as const

export const ExtractionRuleDraftSchema = z
  .strictObject(ExtractionRuleDraftFields)
  .readonly()

export type ExtractionRuleDraft = z.infer<typeof ExtractionRuleDraftSchema>

export const ExtractionRuleSchema = z
  .strictObject({
    ...ExtractionRuleDraftFields,
    ruleId: SystemIssuedOpaqueIdSchema,
    ruleHash: InventoryHashSchema,
    reviewStatus: z.enum(['unreviewed', 'reviewed', 'rejected']),
    frozen: z.boolean(),
    createdAt: IsoDateSchema,
    reviewedBy: DefinitionIdSchema.optional(),
    reviewedAt: IsoDateSchema.optional()
  })
  .readonly()

export type ExtractionRule = z.infer<typeof ExtractionRuleSchema>

export const InventoryMergeProducerSchema = z.enum([
  'seed',
  'import.openapi',
  'import.har',
  'import.postman',
  'import.graphql',
  'static.offline',
  'browser.recon'
])

export type InventoryMergeProducer = z.infer<
  typeof InventoryMergeProducerSchema
>

export const InventoryMergeCountBucketSchema = z
  .strictObject({
    created: z.number().int().nonnegative(),
    merged: z.number().int().nonnegative(),
    conflict: z.number().int().nonnegative(),
    rejected: z.number().int().nonnegative(),
    outOfScope: z.number().int().nonnegative(),
    secretRedacted: z.number().int().nonnegative(),
    inventoryOnly: z.number().int().nonnegative(),
    awaitingReview: z.number().int().nonnegative(),
    unsupported: z.number().int().nonnegative()
  })
  .readonly()

export type InventoryMergeCountBucket = z.infer<
  typeof InventoryMergeCountBucketSchema
>

export const InventoryMergeReportSchema = z
  .strictObject({
    schemaVersion: z.literal('agentgo.inventory-merge-report.v1'),
    reportId: SystemIssuedOpaqueIdSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    totals: InventoryMergeCountBucketSchema,
    byProducer: z
      .array(
        z
          .strictObject({
            producer: InventoryMergeProducerSchema,
            counts: InventoryMergeCountBucketSchema
          })
          .readonly()
      )
      .max(32),
    byCapability: z
      .array(
        z
          .strictObject({
            capabilityId: z.union([CapabilityIdSchema, z.literal('none')]),
            counts: InventoryMergeCountBucketSchema
          })
          .readonly()
      )
      .max(128),
    createdAt: IsoDateSchema
  })
  .readonly()

export type InventoryMergeReport = z.infer<typeof InventoryMergeReportSchema>
