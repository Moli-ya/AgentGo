import { z } from 'zod'
import {
  InventoryHashSchema,
  SystemIssuedOpaqueIdSchema,
  TestObjectRefSchema
} from './inventory'
import { TemplateIntentHashSchema } from './security'
import {
  CapabilityIdSchema,
  DefinitionIdSchema,
  EnvironmentSchema,
  EvidenceRoleSchema,
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

export const ValidationStepKindSchema = z.enum([
  'passive-analysis',
  'http-request',
  'browser-offline-replay',
  'browser-mediated-read',
  'extract-value',
  'state-observe',
  'identity-switch',
  'callback-register',
  'callback-poll',
  'callback-consume',
  'bounded-parallel-group',
  'compare',
  'aggregate',
  'cleanup',
  'cleanup-verify'
])

export type ValidationStepKind = z.infer<typeof ValidationStepKindSchema>

export const ValidationSubjectKindSchema = z.enum([
  'endpoint',
  'identity',
  'session',
  'test-object',
  'artifact',
  'observation'
])

export type ValidationSubjectKind = z.infer<typeof ValidationSubjectKindSchema>

export const ValidationSubjectRefSchema = z
  .strictObject({
    kind: ValidationSubjectKindSchema,
    id: SystemIssuedOpaqueIdSchema
  })
  .readonly()

export type ValidationSubjectRef = z.infer<typeof ValidationSubjectRefSchema>

export const ValidationStopConditionSchema = z.enum([
  'on-step-failure',
  'on-budget-exhausted',
  'on-policy-deny',
  'on-dependency-pause'
])

export type ValidationStopCondition = z.infer<
  typeof ValidationStopConditionSchema
>

export const ValidationStepBudgetSchema = z
  .strictObject({
    maxRequests: z.number().int().min(0).max(64),
    maxResponseBytes: z.number().int().positive().max(16_777_216),
    timeoutMs: z.number().int().positive().max(120_000)
  })
  .readonly()

export type ValidationStepBudget = z.infer<typeof ValidationStepBudgetSchema>

const ValidationStepBaseFields = {
  stepId: DefinitionIdSchema,
  kind: ValidationStepKindSchema,
  familyId: VulnerabilityFamilyIdSchema,
  techniqueId: VulnerabilityTechniqueIdSchema,
  moduleVersion: ModuleVersionSchema,
  strategyVersion: ModuleVersionSchema,
  subjectRefs: z.array(ValidationSubjectRefSchema).max(32),
  capabilityIds: z.array(CapabilityIdSchema).max(16),
  environment: EnvironmentSchema,
  intentRef: TemplateIntentHashSchema.optional(),
  evidenceRoles: z.array(EvidenceRoleSchema).max(16),
  budget: ValidationStepBudgetSchema,
  stopConditions: z.array(ValidationStopConditionSchema).min(1).max(8)
} as const

export const PassiveAnalysisStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('passive-analysis'),
    capabilityIds: z.array(CapabilityIdSchema).max(0)
  })
  .readonly()

export const HttpRequestStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('http-request'),
    endpointId: SystemIssuedOpaqueIdSchema,
    desiredUrl: z.string().url().max(16_384),
    identityId: SystemIssuedOpaqueIdSchema.optional(),
    mutationName: DefinitionIdSchema.optional(),
    mutationValue: z.string().max(4_096).optional(),
    mutationKind: z.enum(['query', 'path']).optional(),
    mutationSegmentIndex: z.number().int().nonnegative().max(64).optional(),
    maxRedirects: z.number().int().min(0).max(16).optional(),
    summary: SafeTextSchema.optional(),
    payloadSummary: SafeTextSchema.optional(),
    purpose: z.enum(['primary', 'read', 'cleanup'])
  })
  .readonly()

export const BrowserOfflineReplayStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('browser-offline-replay'),
    htmlFromObservationId: DefinitionIdSchema,
    action: z.enum(['inspect-dom', 'verify-xss', 'capture-evidence']),
    markerFromObservationId: DefinitionIdSchema.optional(),
    marker: z.string().min(1).max(256).optional(),
    baseUrl: z.string().url().max(16_384).optional(),
    summary: SafeTextSchema.optional(),
    payloadSummary: SafeTextSchema.optional()
  })
  .readonly()

export const BrowserMediatedReadStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('browser-mediated-read'),
    endpointId: SystemIssuedOpaqueIdSchema,
    requestVariantId: SystemIssuedOpaqueIdSchema,
    desiredUrl: z.string().url().max(16_384),
    expectedContentHash: InventoryHashSchema.optional()
  })
  .readonly()

export const ExtractValueStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('extract-value'),
    ruleId: SystemIssuedOpaqueIdSchema,
    observationStepId: DefinitionIdSchema,
    targetVariable: DefinitionIdSchema
  })
  .readonly()

export const StateObserveStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('state-observe'),
    observationStepId: DefinitionIdSchema
  })
  .readonly()

export const IdentitySwitchStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('identity-switch'),
    identityId: SystemIssuedOpaqueIdSchema
  })
  .readonly()

export const CallbackRegisterStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('callback-register'),
    tokenSlot: DefinitionIdSchema
  })
  .readonly()

export const CallbackPollStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('callback-poll'),
    collectorFromStepId: DefinitionIdSchema
  })
  .readonly()

export const CallbackConsumeStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('callback-consume'),
    collectorFromStepId: DefinitionIdSchema
  })
  .readonly()

export const BoundedParallelGroupStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('bounded-parallel-group'),
    childStepIds: z.array(DefinitionIdSchema).min(1).max(8),
    maxFanOut: z.number().int().min(1).max(4),
    fixtureOnly: z.boolean()
  })
  .readonly()

export const CompareStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('compare'),
    leftStepId: DefinitionIdSchema,
    rightStepId: DefinitionIdSchema,
    comparator: z.enum(['status-diff', 'body-hash-diff', 'identity-visibility'])
  })
  .readonly()

export const AggregateStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('aggregate'),
    childStepIds: z.array(DefinitionIdSchema).min(1).max(16)
  })
  .readonly()

export const CleanupStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('cleanup'),
    testObjectRef: TestObjectRefSchema,
    approvalBundleRef: SystemIssuedOpaqueIdSchema
  })
  .readonly()

export const CleanupVerifyStepSchema = z
  .strictObject({
    ...ValidationStepBaseFields,
    kind: z.literal('cleanup-verify'),
    testObjectRef: TestObjectRefSchema,
    cleanupStepId: DefinitionIdSchema
  })
  .readonly()

export const ValidationStepSchema = z.discriminatedUnion('kind', [
  PassiveAnalysisStepSchema,
  HttpRequestStepSchema,
  BrowserOfflineReplayStepSchema,
  BrowserMediatedReadStepSchema,
  ExtractValueStepSchema,
  StateObserveStepSchema,
  IdentitySwitchStepSchema,
  CallbackRegisterStepSchema,
  CallbackPollStepSchema,
  CallbackConsumeStepSchema,
  BoundedParallelGroupStepSchema,
  CompareStepSchema,
  AggregateStepSchema,
  CleanupStepSchema,
  CleanupVerifyStepSchema
])

export type ValidationStep = z.infer<typeof ValidationStepSchema>

export const ValidationPlanBudgetSchema = z
  .strictObject({
    maxRequests: z.number().int().positive().max(256),
    maxBytes: z.number().int().positive().max(67_108_864),
    maxDurationMs: z.number().int().positive().max(600_000),
    maxFanOut: z.number().int().min(1).max(4)
  })
  .readonly()

export type ValidationPlanBudget = z.infer<typeof ValidationPlanBudgetSchema>

export const ValidationPlanSchema = z
  .strictObject({
    schemaVersion: z.literal('agentgo.validation-plan.v1'),
    planId: SystemIssuedOpaqueIdSchema,
    planHash: InventoryHashSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    familyId: VulnerabilityFamilyIdSchema,
    techniqueId: VulnerabilityTechniqueIdSchema,
    moduleVersion: ModuleVersionSchema,
    strategyVersion: ModuleVersionSchema,
    environment: EnvironmentSchema,
    steps: z.array(ValidationStepSchema).min(1).max(64),
    stopConditions: z.array(ValidationStopConditionSchema).min(1).max(8),
    budget: ValidationPlanBudgetSchema,
    createdAt: IsoDateSchema
  })
  .readonly()
  .superRefine((plan, context) => {
    const ids = new Set<string>()
    for (const [index, step] of plan.steps.entries()) {
      if (ids.has(step.stepId)) {
        context.addIssue({
          code: 'custom',
          message: 'Duplicate validation stepId.',
          path: ['steps', index, 'stepId']
        })
      }
      ids.add(step.stepId)
      if (step.familyId !== plan.familyId) {
        context.addIssue({
          code: 'custom',
          message: 'Step family must match the plan family.',
          path: ['steps', index, 'familyId']
        })
      }
      if (step.environment !== plan.environment) {
        context.addIssue({
          code: 'custom',
          message: 'Step environment must match the plan environment.',
          path: ['steps', index, 'environment']
        })
      }
    }
    for (const [index, step] of plan.steps.entries()) {
      if (step.kind !== 'bounded-parallel-group' && step.kind !== 'aggregate') {
        continue
      }
      for (const childId of step.childStepIds) {
        if (!ids.has(childId)) {
          context.addIssue({
            code: 'custom',
            message: 'Dangling child step reference.',
            path: ['steps', index, 'childStepIds']
          })
        }
      }
    }
  })

export type ValidationPlan = z.infer<typeof ValidationPlanSchema>

export const ValidationRunStatusSchema = z.enum([
  'pending',
  'running',
  'succeeded',
  'failed',
  'stopped',
  'fail-closed'
])

export type ValidationRunStatus = z.infer<typeof ValidationRunStatusSchema>

export const ValidationPlanRunSchema = z
  .strictObject({
    runId: SystemIssuedOpaqueIdSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    planId: SystemIssuedOpaqueIdSchema,
    planHash: InventoryHashSchema,
    status: ValidationRunStatusSchema,
    stopReason: SafeTextSchema.optional(),
    createdAt: IsoDateSchema,
    completedAt: IsoDateSchema.optional()
  })
  .readonly()

export type ValidationPlanRun = z.infer<typeof ValidationPlanRunSchema>

export const ValidationStepRunSchema = z
  .strictObject({
    stepRunId: SystemIssuedOpaqueIdSchema,
    runId: SystemIssuedOpaqueIdSchema,
    stepId: DefinitionIdSchema,
    kind: ValidationStepKindSchema,
    status: ValidationRunStatusSchema,
    ordinal: z.number().int().min(0).max(1_024),
    policyDecisionId: SystemIssuedOpaqueIdSchema.optional(),
    leaseId: SystemIssuedOpaqueIdSchema.optional(),
    errorCode: SafeTextSchema.optional(),
    createdAt: IsoDateSchema,
    completedAt: IsoDateSchema.optional()
  })
  .readonly()

export type ValidationStepRun = z.infer<typeof ValidationStepRunSchema>

export const ValidationObservationSchema = z
  .strictObject({
    observationId: SystemIssuedOpaqueIdSchema,
    runId: SystemIssuedOpaqueIdSchema,
    stepId: DefinitionIdSchema,
    kind: SafeTextSchema,
    payloadJson: z.record(z.string(), z.unknown()),
    createdAt: IsoDateSchema
  })
  .readonly()

export type ValidationObservation = z.infer<typeof ValidationObservationSchema>

export const ValidationEvidenceBindingSchema = z
  .strictObject({
    bindingId: SystemIssuedOpaqueIdSchema,
    runId: SystemIssuedOpaqueIdSchema,
    stepId: DefinitionIdSchema,
    evidenceRef: SystemIssuedOpaqueIdSchema,
    role: EvidenceRoleSchema,
    ordinal: z.number().int().min(0).max(64),
    profileId: DefinitionIdSchema,
    profileVersion: ModuleVersionSchema
  })
  .readonly()

export type ValidationEvidenceBinding = z.infer<
  typeof ValidationEvidenceBindingSchema
>
