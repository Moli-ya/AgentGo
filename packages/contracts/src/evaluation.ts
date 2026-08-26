import { z } from 'zod'
import { InventoryHashSchema } from './inventory'
import {
  BodyEncodingSchema,
  CapabilityIdSchema,
  DeclaredModeSchema,
  DefinitionIdSchema,
  EnvironmentSchema,
  EvidenceRoleSchema,
  LEGACY_V1_FAMILY_IDS,
  ModuleVersionSchema,
  ProtocolDescriptorSchema,
  SelectorKindSchema,
  TransportKindSchema,
  VulnerabilityFamilyIdSchema,
  VulnerabilityTechniqueIdSchema
} from './vulnerability'
import { VerdictSchema } from './workflow'

const DisplayTextSchema = z.string().trim().min(1).max(500)
const DescriptionSchema = z.string().trim().min(1).max(8_000)
const IsoDateSchema = z.string().datetime()
const ContentHashSchema = InventoryHashSchema

function addDuplicateStringIssues(
  values: readonly string[],
  context: z.RefinementCtx,
  label: string,
  path: Array<string | number> = []
): void {
  const seen = new Set<string>()
  for (const [index, value] of values.entries()) {
    if (seen.has(value)) {
      context.addIssue({
        code: 'custom',
        message: `Duplicate ${label}.`,
        path: [...path, index]
      })
    }
    seen.add(value)
  }
}

export const BenchmarkCaseCategorySchema = z.enum([
  'positive',
  'negative',
  'inconclusive',
  'policy-denied',
  'version-mismatch',
  'cleanup-failure'
])

export type BenchmarkCaseCategory = z.infer<typeof BenchmarkCaseCategorySchema>

export const BenchmarkResultClassSchema = z.enum([
  'self-built-fixture',
  'external-local-holdout',
  'authorized-pilot',
  'not-run'
])

export type BenchmarkResultClass = z.infer<typeof BenchmarkResultClassSchema>

export const BenchmarkIdentityRequirementSchema = z.enum([
  'none',
  'single-test-identity',
  'two-test-identities'
])

export type BenchmarkIdentityRequirement = z.infer<
  typeof BenchmarkIdentityRequirementSchema
>

export const BenchmarkRiskLevelSchema = z.enum(['l0', 'l1', 'l2', 'l3'])

export type BenchmarkRiskLevel = z.infer<typeof BenchmarkRiskLevelSchema>

export const FixturePortPolicySchema = z.literal('ephemeral')

export type FixturePortPolicy = z.infer<typeof FixturePortPolicySchema>

export const FixtureBindAddressSchema = z.literal('127.0.0.1')

export type FixtureBindAddress = z.infer<typeof FixtureBindAddressSchema>

export const QualificationRecordSchemaVersionSchema = z.literal(
  'agentgo-qualification-record/1.0'
)

export const BenchmarkSuiteSchemaVersionSchema = z.literal(
  'agentgo-benchmark-suite/1.0'
)

export const LegacyV1GroundTruthSchemaVersionSchema = z.literal(
  'agentgo-ground-truth/1.0'
)

export const LegacyV1GroundTruthCaseSchema = z
  .strictObject({
    caseId: z.string().min(1).max(200),
    name: DisplayTextSchema,
    targetVersion: z.string().min(1).max(200),
    family: VulnerabilityFamilyIdSchema,
    endpoint: z.string().min(1).max(2_048),
    parameter: z.string().min(1).max(200).optional(),
    identityPlan: z.record(z.string(), z.unknown()).default({}),
    expectedVerdict: z.enum(['confirmed', 'not-confirmed']),
    confirmationRule: z.string().min(1).max(200),
    requiredEvidence: z.array(z.string().min(1).max(200)).min(1).max(64),
    resetProcedure: DescriptionSchema,
    forbiddenActions: z.array(z.string().min(1).max(500)).min(1).max(64),
    source: z.string().min(1).max(500),
    license: z.string().min(1).max(200),
    reviewer: z.string().min(1).max(200)
  })
  .readonly()

export type LegacyV1GroundTruthCase = z.infer<
  typeof LegacyV1GroundTruthCaseSchema
>

/** Compatibility alias used by the V1 40-case runner and tests. */
export const GroundTruthCaseSchema = LegacyV1GroundTruthCaseSchema
export type GroundTruthCase = LegacyV1GroundTruthCase

export const LegacyV1GroundTruthManifestSchema = z
  .strictObject({
    schemaVersion: LegacyV1GroundTruthSchemaVersionSchema,
    targetVersion: z.string().min(1).max(200),
    note: DescriptionSchema,
    cases: z.array(LegacyV1GroundTruthCaseSchema).min(40)
  })
  .superRefine((manifest, context) => {
    const ids = new Set<string>()
    for (const [index, item] of manifest.cases.entries()) {
      if (ids.has(item.caseId)) {
        context.addIssue({
          code: 'custom',
          message: `Duplicate caseId: ${item.caseId}`,
          path: ['cases', index, 'caseId']
        })
      }
      ids.add(item.caseId)
      if (item.targetVersion !== manifest.targetVersion) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} targetVersion does not match the manifest.`,
          path: ['cases', index, 'targetVersion']
        })
      }
    }

    for (const family of LEGACY_V1_FAMILY_IDS) {
      for (const expectedVerdict of ['confirmed', 'not-confirmed'] as const) {
        const count = manifest.cases.filter(
          (item) => item.family === family && item.expectedVerdict === expectedVerdict
        ).length
        if (count < 5) {
          context.addIssue({
            code: 'custom',
            message: `${family}/${expectedVerdict} requires at least five cases.`,
            path: ['cases']
          })
        }
      }
    }
  })
  .readonly()

export type LegacyV1GroundTruthManifest = z.infer<
  typeof LegacyV1GroundTruthManifestSchema
>

/** Compatibility alias used by the V1 40-case runner and tests. */
export const GroundTruthManifestSchema = LegacyV1GroundTruthManifestSchema
export type GroundTruthManifest = LegacyV1GroundTruthManifest

export const FixtureAttestationSchema = z
  .strictObject({
    fixtureId: DefinitionIdSchema,
    fixtureVersion: z.string().min(1).max(200),
    bindAddress: FixtureBindAddressSchema,
    portPolicy: FixturePortPolicySchema,
    outboundPolicy: z.literal('loopback-same-origin-callback-only'),
    resetPolicy: z.literal('fixture-namespace-only')
  })
  .readonly()

export type FixtureAttestation = z.infer<typeof FixtureAttestationSchema>

const UniqueEvidenceRoleListSchema = z
  .array(EvidenceRoleSchema)
  .min(1)
  .max(64)
  .superRefine((values, context) => {
    addDuplicateStringIssues(values, context, 'evidence role')
  })
  .readonly()

const UniqueCapabilityIdListSchema = z
  .array(CapabilityIdSchema)
  .max(64)
  .superRefine((values, context) => {
    addDuplicateStringIssues(values, context, 'capability ID')
  })
  .readonly()

export const EvaluationGroundTruthCaseSchema = z
  .strictObject({
    caseId: z.string().min(1).max(200),
    name: DisplayTextSchema,
    targetVersion: z.string().min(1).max(200),
    familyId: VulnerabilityFamilyIdSchema,
    techniqueId: VulnerabilityTechniqueIdSchema,
    moduleVersion: ModuleVersionSchema,
    fixtureVersion: z.string().min(1).max(200),
    category: BenchmarkCaseCategorySchema,
    expectedVerdict: VerdictSchema,
    expectedReasonCode: z.string().trim().min(1).max(200).optional(),
    protocol: ProtocolDescriptorSchema,
    selectorKind: SelectorKindSchema,
    requiredEvidenceRoles: UniqueEvidenceRoleListSchema,
    identityRequirement: BenchmarkIdentityRequirementSchema,
    workflowRequirement: z.literal('none'),
    testObjectRequirement: z.literal('none'),
    riskLevel: BenchmarkRiskLevelSchema,
    maxRequests: z.number().int().positive().max(10_000),
    forbiddenCapabilityIds: UniqueCapabilityIdListSchema,
    environment: EnvironmentSchema,
    executable: z.boolean(),
    endpoint: z.string().min(1).max(2_048).optional(),
    parameter: z.string().min(1).max(200).optional(),
    confirmationRule: z.string().min(1).max(200),
    resetProcedure: DescriptionSchema,
    forbiddenActions: z.array(z.string().min(1).max(500)).min(1).max(64).readonly(),
    source: z.string().min(1).max(500),
    license: z.string().min(1).max(200),
    reviewer: z.string().min(1).max(200)
  })
  .superRefine((item, context) => {
    if (item.category === 'cleanup-failure' && item.executable !== false) {
      context.addIssue({
        code: 'custom',
        message:
          'cleanup-failure cases cannot be executable until L2 cleanup execution is connected.',
        path: ['executable']
      })
    }
    if (item.category !== 'cleanup-failure' && item.executable !== true) {
      context.addIssue({
        code: 'custom',
        message: 'Non-cleanup cases must be executable.',
        path: ['executable']
      })
    }
    if (item.category === 'positive' && item.expectedVerdict !== 'confirmed') {
      context.addIssue({
        code: 'custom',
        message: 'positive cases must expect confirmed.',
        path: ['expectedVerdict']
      })
    }
    if (item.category === 'negative' && item.expectedVerdict !== 'not-confirmed') {
      context.addIssue({
        code: 'custom',
        message: 'negative cases must expect not-confirmed.',
        path: ['expectedVerdict']
      })
    }
    if (item.category === 'inconclusive' && item.expectedVerdict !== 'inconclusive') {
      context.addIssue({
        code: 'custom',
        message: 'inconclusive cases must expect inconclusive.',
        path: ['expectedVerdict']
      })
    }
    if (
      (item.category === 'policy-denied' || item.category === 'version-mismatch') &&
      item.expectedVerdict !== 'inconclusive'
    ) {
      context.addIssue({
        code: 'custom',
        message: `${item.category} cases must expect inconclusive, not a decided verdict.`,
        path: ['expectedVerdict']
      })
    }
  })
  .readonly()

export type EvaluationGroundTruthCase = z.infer<typeof EvaluationGroundTruthCaseSchema>

export const BenchmarkSuiteManifestSchema = z
  .strictObject({
    schemaVersion: BenchmarkSuiteSchemaVersionSchema,
    suiteId: DefinitionIdSchema,
    suiteVersion: ModuleVersionSchema,
    familyId: VulnerabilityFamilyIdSchema,
    techniqueId: VulnerabilityTechniqueIdSchema,
    moduleVersion: ModuleVersionSchema,
    fixtureVersion: z.string().min(1).max(200),
    protocol: ProtocolDescriptorSchema,
    selectorKind: SelectorKindSchema,
    allowedMaturities: z
      .array(DeclaredModeSchema)
      .min(1)
      .max(6)
      .superRefine((values, context) => {
        addDuplicateStringIssues(values, context, 'maturity')
      })
      .readonly(),
    environment: EnvironmentSchema,
    requiredCaseCategories: z
      .array(BenchmarkCaseCategorySchema)
      .min(1)
      .max(6)
      .superRefine((values, context) => {
        addDuplicateStringIssues(values, context, 'case category')
      })
      .readonly(),
    attestation: FixtureAttestationSchema,
    cases: z.array(EvaluationGroundTruthCaseSchema).min(1).max(10_000)
  })
  .superRefine((suite, context) => {
    const ids = new Set<string>()
    const presentCategories = new Set<BenchmarkCaseCategory>()
    for (const [index, item] of suite.cases.entries()) {
      if (ids.has(item.caseId)) {
        context.addIssue({
          code: 'custom',
          message: `Duplicate caseId: ${item.caseId}`,
          path: ['cases', index, 'caseId']
        })
      }
      ids.add(item.caseId)
      presentCategories.add(item.category)
      if (item.familyId !== suite.familyId) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} familyId does not match the suite.`,
          path: ['cases', index, 'familyId']
        })
      }
      if (item.techniqueId !== suite.techniqueId) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} techniqueId does not match the suite.`,
          path: ['cases', index, 'techniqueId']
        })
      }
      if (item.moduleVersion !== suite.moduleVersion) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} moduleVersion does not match the suite.`,
          path: ['cases', index, 'moduleVersion']
        })
      }
      if (item.fixtureVersion !== suite.fixtureVersion) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} fixtureVersion does not match the suite.`,
          path: ['cases', index, 'fixtureVersion']
        })
      }
      if (item.environment !== suite.environment) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} environment does not match the suite.`,
          path: ['cases', index, 'environment']
        })
      }
      if (
        item.protocol.transport !== suite.protocol.transport ||
        item.protocol.bodyEncoding !== suite.protocol.bodyEncoding
      ) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} protocol does not match the suite.`,
          path: ['cases', index, 'protocol']
        })
      }
      if (item.selectorKind !== suite.selectorKind) {
        context.addIssue({
          code: 'custom',
          message: `Case ${item.caseId} selectorKind does not match the suite.`,
          path: ['cases', index, 'selectorKind']
        })
      }
    }
    for (const [index, category] of suite.requiredCaseCategories.entries()) {
      if (!presentCategories.has(category)) {
        context.addIssue({
          code: 'custom',
          message: `Suite is missing required case category ${category}.`,
          path: ['requiredCaseCategories', index]
        })
      }
    }
  })
  .readonly()

export type BenchmarkSuiteManifest = z.infer<typeof BenchmarkSuiteManifestSchema>

const QualificationRecordFields = {
  schemaVersion: QualificationRecordSchemaVersionSchema,
  familyId: VulnerabilityFamilyIdSchema,
  techniqueId: VulnerabilityTechniqueIdSchema,
  techniqueVersion: ModuleVersionSchema,
  moduleId: DefinitionIdSchema,
  moduleVersion: ModuleVersionSchema,
  definitionHash: ContentHashSchema,
  definitionSnapshotHash: ContentHashSchema,
  buildHash: ContentHashSchema,
  suiteId: DefinitionIdSchema,
  suiteVersion: ModuleVersionSchema,
  suiteHash: ContentHashSchema,
  fixtureVersion: z.string().min(1).max(200),
  fixtureAttestationHash: ContentHashSchema,
  policyCatalogHash: ContentHashSchema,
  protocol: ProtocolDescriptorSchema,
  selectorKind: SelectorKindSchema,
  resultClass: BenchmarkResultClassSchema,
  result: z.literal('passed'),
  qualifiedEnvironments: z
    .array(EnvironmentSchema)
    .min(1)
    .max(4)
    .superRefine((values, context) => {
      addDuplicateStringIssues(values, context, 'environment')
    })
    .readonly(),
  issuedAt: IsoDateSchema,
  expiresAt: IsoDateSchema.optional()
}

export const QualificationRecordPayloadSchema = z
  .strictObject(QualificationRecordFields)
  .readonly()

export type QualificationRecordPayload = z.infer<
  typeof QualificationRecordPayloadSchema
>

export const QualificationRecordSchema = z
  .strictObject({
    ...QualificationRecordFields,
    recordHash: ContentHashSchema
  })
  .readonly()

export type QualificationRecord = z.infer<typeof QualificationRecordSchema>

export const LEGACY_V1_SUITE_ID = 'legacy-v1' as const
export const EVALUATION_CORE_META_SUITE_ID = 'evaluation-core-meta' as const

export const LOCAL_FIXTURE_ID = 'agentgo-local-fixture' as const
export const LOCAL_FIXTURE_VERSION = 'agentgo-local-fixture/1.0.0' as const

export const QUALIFICATION_RECORD_ISSUED_AT = '2026-08-20T00:00:00.000Z' as const

export const LEGACY_V1_HTTP_GET_QUERY_PROTOCOL = Object.freeze({
  transport: 'standard-http',
  bodyEncoding: 'none'
} as const satisfies {
  transport: z.infer<typeof TransportKindSchema>
  bodyEncoding: z.infer<typeof BodyEncodingSchema>
})
