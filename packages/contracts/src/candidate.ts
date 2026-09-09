import { z } from 'zod'
import {
  InventoryHashSchema,
  SystemIssuedOpaqueIdSchema,
  TestObjectRefSchema
} from './inventory'
import { ValidationSubjectRefSchema } from './validation'
import {
  DefinitionIdSchema,
  ModuleVersionSchema,
  VulnerabilityFamilyIdSchema,
  VulnerabilityTechniqueIdSchema
} from './vulnerability'

const IsoDateSchema = z.string().datetime()
const SafeTextSchema = z
  .string()
  .trim()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value))

export const CandidateAttemptStatusSchema = z.enum([
  'planned',
  'awaiting-approval',
  'awaiting-session',
  'awaiting-input',
  'running',
  'cleanup-pending',
  'interrupted',
  'cancelled',
  'failed',
  'completed',
  'inconclusive',
  'rejected'
])

export type CandidateAttemptStatus = z.infer<typeof CandidateAttemptStatusSchema>

export const CandidateCompilerDecisionSchema = z.enum([
  'executable',
  'inventory-only',
  'awaiting-user',
  'forbidden',
  'rejected'
])

export type CandidateCompilerDecision = z.infer<
  typeof CandidateCompilerDecisionSchema
>

export const PhaseOutcomeKindSchema = z.enum([
  'completed',
  'awaiting-user',
  'paused',
  'failed'
])

export type PhaseOutcomeKind = z.infer<typeof PhaseOutcomeKindSchema>

export const CandidateSeedSchema = z
  .strictObject({
    familyId: VulnerabilityFamilyIdSchema,
    techniqueId: VulnerabilityTechniqueIdSchema,
    moduleVersion: ModuleVersionSchema,
    detectorId: DefinitionIdSchema,
    subjectRefs: z.array(ValidationSubjectRefSchema).max(32),
    variantRefs: z.array(SystemIssuedOpaqueIdSchema).max(16),
    dependencyRefs: z.array(SystemIssuedOpaqueIdSchema).max(16).default([]),
    identityRefs: z.array(SystemIssuedOpaqueIdSchema).max(8).default([]),
    testObjectRefs: z.array(TestObjectRefSchema).max(8).default([]),
    matrixRefs: z.array(SystemIssuedOpaqueIdSchema).max(4).default([]),
    parameterId: SystemIssuedOpaqueIdSchema.optional(),
    reason: SafeTextSchema,
    expectedSignal: SafeTextSchema,
    suggestedStrategy: DefinitionIdSchema,
    confidenceHint: z.number().min(0).max(1)
  })
  .readonly()

export type CandidateSeed = z.infer<typeof CandidateSeedSchema>

export const CandidateSchema = z
  .strictObject({
    candidateId: SystemIssuedOpaqueIdSchema,
    familyId: VulnerabilityFamilyIdSchema,
    techniqueId: VulnerabilityTechniqueIdSchema,
    moduleVersion: ModuleVersionSchema,
    subjectRefs: z.array(ValidationSubjectRefSchema).max(32),
    variantRefs: z.array(SystemIssuedOpaqueIdSchema).max(16),
    dependencyRefs: z.array(SystemIssuedOpaqueIdSchema).max(16),
    identityRefs: z.array(SystemIssuedOpaqueIdSchema).max(8),
    testObjectRefs: z.array(TestObjectRefSchema).max(8),
    matrixRefs: z.array(SystemIssuedOpaqueIdSchema).max(4),
    parameterId: SystemIssuedOpaqueIdSchema.optional(),
    reason: SafeTextSchema,
    expectedSignal: SafeTextSchema,
    suggestedStrategy: DefinitionIdSchema,
    rank: z.number().int().min(0).max(10_000).optional()
  })
  .readonly()

export type Candidate = z.infer<typeof CandidateSchema>

export const CandidateAttemptSchema = z
  .strictObject({
    attemptId: SystemIssuedOpaqueIdSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    candidateId: SystemIssuedOpaqueIdSchema,
    candidate: CandidateSchema,
    status: CandidateAttemptStatusSchema,
    decision: CandidateCompilerDecisionSchema,
    planId: SystemIssuedOpaqueIdSchema.optional(),
    planHash: InventoryHashSchema.optional(),
    planRunId: SystemIssuedOpaqueIdSchema.optional(),
    bundleRef: SafeTextSchema.optional(),
    grantRefs: z.array(SystemIssuedOpaqueIdSchema).max(64),
    evidenceRefs: z.array(SystemIssuedOpaqueIdSchema).max(64),
    reason: SafeTextSchema.optional(),
    createdAt: IsoDateSchema,
    updatedAt: IsoDateSchema,
    completedAt: IsoDateSchema.optional()
  })
  .readonly()

export type CandidateAttempt = z.infer<typeof CandidateAttemptSchema>
