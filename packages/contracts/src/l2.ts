import { z } from 'zod'
import { ExecutionPurposeSchema } from './execution'
import {
  InventoryHashSchema,
  SystemIssuedOpaqueIdSchema,
  TestObjectRefSchema
} from './inventory'
import { TemplateIntentHashSchema } from './security'
import {
  DefinitionIdSchema,
  ModuleVersionSchema,
  VulnerabilityFamilyIdSchema,
  VulnerabilityTechniqueIdSchema
} from './vulnerability'

const IsoDateSchema = z.string().datetime()
const ContentHashSchema = InventoryHashSchema
const DescriptionSchema = z.string().trim().min(1).max(8_000)

export const L2IsoDateSchema = IsoDateSchema
export const L2ContentHashSchema = ContentHashSchema
export const L2DescriptionSchema = DescriptionSchema

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return false
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) return false
      index += 1
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false
    }
  }
  return true
}

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

export const ExactTokenSchema = z
  .string()
  .min(1)
  .max(200)
  .refine((value) => value === value.trim(), 'Value must not contain surrounding whitespace.')
  .refine(
    (value) => value === value.normalize('NFC'),
    'Value must use Unicode NFC normalization.'
  )
  .refine(isWellFormedUnicode, 'Value must contain well-formed Unicode.')
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    'Value must not contain control characters.'
  )

export function isExactL2FieldPath(value: string): boolean {
  if (value !== value.trim() || value !== value.normalize('NFC')) return false
  if (value.includes('*') || value.includes('..') || value.includes('/')) return false
  if (/^(all|any|entire-object|entire_object|wildcard)$/iu.test(value)) return false
  return /^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*){0,7}$/u.test(value)
}

const ExactFieldPathSchema = ExactTokenSchema.refine(
  isExactL2FieldPath,
  'L2 field paths must be exact identifiers; wildcards and entire-object expressions are forbidden.'
)

export const L2_SCHEMA_VERSION = 'agentgo-l2-protocol/1.0' as const
export const L2_CLEANUP_CAPABILITY_ID =
  'cleanup.test-object-declared-protocol' as const

export const L2SchemaVersionSchema = z.literal(L2_SCHEMA_VERSION)
export const L2CleanupCapabilityIdSchema = z.literal(L2_CLEANUP_CAPABILITY_ID)

export const TestObjectTypeSchema = z.enum([
  'record',
  'document',
  'collection-item',
  'form-submission',
  'order',
  'coupon',
  'invitation',
  'quota',
  'webhook-subscription',
  'mailbox-message'
])

export type TestObjectType = z.infer<typeof TestObjectTypeSchema>

export const CleanupProtocolKindSchema = z.enum(['delete', 'revoke', 'reset'])

export type CleanupProtocolKind = z.infer<typeof CleanupProtocolKindSchema>

export const CleanupDeclaredHttpMethodSchema = z.enum(['POST', 'PUT', 'PATCH'])

export type CleanupDeclaredHttpMethod = z.infer<
  typeof CleanupDeclaredHttpMethodSchema
>

export const TestObjectCloseConditionSchema = z.enum([
  'expired',
  'externally-modified',
  'ownership-changed',
  'tenant-changed',
  'invalidated'
])

export type TestObjectCloseCondition = z.infer<
  typeof TestObjectCloseConditionSchema
>

export const L2BindingSlotSchema = z.discriminatedUnion('status', [
  z.strictObject({ status: z.literal('unresolved') }).readonly(),
  z
    .strictObject({
      status: z.literal('resolved'),
      version: ExactTokenSchema
    })
    .readonly()
])

export type L2BindingSlot = z.infer<typeof L2BindingSlotSchema>

export const L2ApprovalActorSlotSchema = z.discriminatedUnion('status', [
  z.strictObject({ status: z.literal('unresolved') }).readonly(),
  z
    .strictObject({
      status: z.literal('resolved'),
      actorId: SystemIssuedOpaqueIdSchema,
      approvalRecordHash: ContentHashSchema
    })
    .readonly()
])

export type L2ApprovalActorSlot = z.infer<typeof L2ApprovalActorSlotSchema>

const ExactResourcePathSchema = z
  .string()
  .min(1)
  .max(2_048)
  .refine((value) => value.startsWith('/'), 'Resource path must be absolute.')
  .refine(
    (value) => !value.includes('*') && !value.includes('?'),
    'Resource path must be exact; query strings and wildcards are forbidden.'
  )

export const CanonicalTestResourceIdentifierSchema = z
  .strictObject({
    kind: z.literal('http-resource'),
    origin: z.string().url().max(2_048),
    method: z.enum(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH']),
    path: ExactResourcePathSchema,
    resourceId: ExactTokenSchema.max(500)
  })
  .readonly()

export type CanonicalTestResourceIdentifier = z.infer<
  typeof CanonicalTestResourceIdentifierSchema
>

export const DeclaredCleanupProtocolSchema = z
  .strictObject({
    kind: CleanupProtocolKindSchema,
    declaredByTarget: z.literal(true),
    capabilityId: L2CleanupCapabilityIdSchema,
    method: CleanupDeclaredHttpMethodSchema,
    path: ExactResourcePathSchema,
    expectedTerminalState: ExactTokenSchema,
    maxRequests: z.number().int().positive().max(3)
  })
  .readonly()

export type DeclaredCleanupProtocol = z.infer<
  typeof DeclaredCleanupProtocolSchema
>

export const TestObjectCreationAttestationSchema = z
  .strictObject({
    source: z.literal('agentgo-application'),
    createdByAgentGo: z.literal(true),
    attestedAt: IsoDateSchema,
    attestationHash: ContentHashSchema
  })
  .readonly()

export type TestObjectCreationAttestation = z.infer<
  typeof TestObjectCreationAttestationSchema
>

const UniqueFieldPathListSchema = z
  .array(ExactFieldPathSchema)
  .min(1)
  .max(32)
  .superRefine((values, context) => {
    addDuplicateStringIssues(values, context, 'field path')
  })
  .readonly()

const UniqueStateListSchema = z
  .array(ExactTokenSchema)
  .min(1)
  .max(32)
  .superRefine((values, context) => {
    addDuplicateStringIssues(values, context, 'allowed state')
  })
  .readonly()

function refineTestObjectPayload(
  value: {
    createdAt: string
    expiresAt: string
    cleanupProtocol: { path: string }
    canonicalResource: { path: string }
  },
  context: z.RefinementCtx
): void {
  if (Date.parse(value.expiresAt) <= Date.parse(value.createdAt)) {
    context.addIssue({
      code: 'custom',
      message: 'TestObject expiresAt must be after createdAt.',
      path: ['expiresAt']
    })
  }
  if (value.cleanupProtocol.path !== value.canonicalResource.path) {
    context.addIssue({
      code: 'custom',
      message: 'Cleanup protocol path must equal the canonical resource path.',
      path: ['cleanupProtocol', 'path']
    })
  }
}

export const TestObjectPayloadSchema = z
  .strictObject({
    schemaVersion: L2SchemaVersionSchema,
    testObjectId: SystemIssuedOpaqueIdSchema,
    objectVersion: z.number().int().positive(),
    scanId: SystemIssuedOpaqueIdSchema,
    targetId: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    identityId: SystemIssuedOpaqueIdSchema,
    tenantRef: SystemIssuedOpaqueIdSchema.optional(),
    objectType: TestObjectTypeSchema,
    disposable: z.literal(true),
    createdAt: IsoDateSchema,
    expiresAt: IsoDateSchema,
    allowedFields: UniqueFieldPathListSchema,
    allowedStates: UniqueStateListSchema,
    ownershipProofRef: SystemIssuedOpaqueIdSchema,
    creationEvidenceHash: ContentHashSchema,
    baselineEvidenceHash: ContentHashSchema,
    canonicalResource: CanonicalTestResourceIdentifierSchema,
    cleanupProtocol: DeclaredCleanupProtocolSchema,
    closeConditions: z
      .array(TestObjectCloseConditionSchema)
      .min(1)
      .max(8)
      .readonly(),
    creationAttestation: TestObjectCreationAttestationSchema
  })
  .superRefine(refineTestObjectPayload)
  .readonly()

export type TestObjectPayload = z.infer<typeof TestObjectPayloadSchema>

export const TestObjectSchema = z
  .strictObject({
    schemaVersion: L2SchemaVersionSchema,
    testObjectId: SystemIssuedOpaqueIdSchema,
    objectVersion: z.number().int().positive(),
    scanId: SystemIssuedOpaqueIdSchema,
    targetId: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    identityId: SystemIssuedOpaqueIdSchema,
    tenantRef: SystemIssuedOpaqueIdSchema.optional(),
    objectType: TestObjectTypeSchema,
    disposable: z.literal(true),
    createdAt: IsoDateSchema,
    expiresAt: IsoDateSchema,
    allowedFields: UniqueFieldPathListSchema,
    allowedStates: UniqueStateListSchema,
    ownershipProofRef: SystemIssuedOpaqueIdSchema,
    creationEvidenceHash: ContentHashSchema,
    baselineEvidenceHash: ContentHashSchema,
    canonicalResource: CanonicalTestResourceIdentifierSchema,
    cleanupProtocol: DeclaredCleanupProtocolSchema,
    closeConditions: z
      .array(TestObjectCloseConditionSchema)
      .min(1)
      .max(8)
      .readonly(),
    creationAttestation: TestObjectCreationAttestationSchema,
    objectHash: ContentHashSchema
  })
  .superRefine(refineTestObjectPayload)
  .readonly()

export type TestObject = z.infer<typeof TestObjectSchema>

export const ExternalSideEffectKindSchema = z.enum([
  'email',
  'sms',
  'queue',
  'webhook',
  'billing',
  'cache-invalidation',
  'audit-alert'
])

export type ExternalSideEffectKind = z.infer<typeof ExternalSideEffectKindSchema>

export const FieldWriteConstraintSchema = z
  .strictObject({
    fieldPath: ExactFieldPathSchema,
    oldValueConstraint: ExactTokenSchema,
    newValueConstraint: ExactTokenSchema
  })
  .readonly()

export type FieldWriteConstraint = z.infer<typeof FieldWriteConstraintSchema>

export const SideEffectEnvelopeSchema = z
  .strictObject({
    expectedStateChange: ExactTokenSchema,
    maxImpactScope: z.enum(['single-test-object-fields']),
    writableResourceId: ExactTokenSchema,
    fieldWrites: z.array(FieldWriteConstraintSchema).min(1).max(16).readonly(),
    externalSideEffects: z
      .array(ExternalSideEffectKindSchema)
      .max(16)
      .readonly(),
    observationRoles: z
      .strictObject({
        preRead: z.literal('pre-read'),
        postRead: z.literal('post-read'),
        terminalRead: z.literal('terminal-read')
      })
      .readonly(),
    unknownSideEffects: z.array(DescriptionSchema).max(16).readonly(),
    unobservableSideEffects: z.array(DescriptionSchema).max(16).readonly(),
    irreversibleItems: z.array(DescriptionSchema).max(16).readonly()
  })
  .readonly()

export type SideEffectEnvelope = z.infer<typeof SideEffectEnvelopeSchema>

export const L2StepKindSchema = z.enum([
  'pre-read',
  'primary',
  'post-read',
  'cleanup',
  'cleanup-not-needed',
  'cleanup-verify',
  'terminal-read'
])

export type L2StepKind = z.infer<typeof L2StepKindSchema>

export const L2StepBudgetSchema = z
  .strictObject({
    maxRequests: z.number().int().positive().max(8),
    maxDurationMs: z.number().int().positive().max(60_000),
    maxRequestBytes: z.number().int().positive().max(1_146_880).optional()
  })
  .readonly()

export type L2StepBudget = z.infer<typeof L2StepBudgetSchema>

export const L2StepBindingSchema = z
  .strictObject({
    purpose: ExecutionPurposeSchema,
    testObjectVersion: z.number().int().positive(),
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    familyId: VulnerabilityFamilyIdSchema,
    moduleId: DefinitionIdSchema,
    moduleVersion: ModuleVersionSchema,
    techniqueId: VulnerabilityTechniqueIdSchema,
    techniqueVersion: ModuleVersionSchema,
    templateIntentHash: TemplateIntentHashSchema,
    budget: L2StepBudgetSchema
  })
  .readonly()

export type L2StepBinding = z.infer<typeof L2StepBindingSchema>

const NetworkedL2StepSchema = z
  .strictObject({
    kind: z.enum(['pre-read', 'primary', 'post-read', 'cleanup-verify', 'terminal-read']),
    binding: L2StepBindingSchema
  })
  .readonly()

const CleanupL2StepSchema = z
  .strictObject({
    kind: z.literal('cleanup'),
    binding: L2StepBindingSchema,
    cleanupProtocol: DeclaredCleanupProtocolSchema
  })
  .readonly()

const CleanupNotNeededL2StepSchema = z
  .strictObject({
    kind: z.literal('cleanup-not-needed'),
    justification: z.literal('not-needed-no-state-change')
  })
  .readonly()

export const L2BundleStepSchema = z.union([
  NetworkedL2StepSchema,
  CleanupL2StepSchema,
  CleanupNotNeededL2StepSchema
])

export type L2BundleStep = z.infer<typeof L2BundleStepSchema>

function assertStepOrder(
  steps: readonly L2BundleStep[],
  context: z.RefinementCtx
): void {
  if (steps.length !== 6) {
    context.addIssue({
      code: 'custom',
      message: 'L2ActionBundle must contain exactly six ordered steps.',
      path: ['steps']
    })
    return
  }
  const kinds = steps.map((step) => step.kind)
  if (kinds[0] !== 'pre-read' || kinds[1] !== 'primary' || kinds[2] !== 'post-read') {
    context.addIssue({
      code: 'custom',
      message: 'L2ActionBundle steps 1-3 must be pre-read, primary, post-read.',
      path: ['steps']
    })
  }
  if (kinds[3] !== 'cleanup' && kinds[3] !== 'cleanup-not-needed') {
    context.addIssue({
      code: 'custom',
      message: 'L2ActionBundle step 4 must be cleanup or cleanup-not-needed.',
      path: ['steps', 3]
    })
  }
  if (kinds[4] !== 'cleanup-verify' || kinds[5] !== 'terminal-read') {
    context.addIssue({
      code: 'custom',
      message: 'L2ActionBundle steps 5-6 must be cleanup-verify and terminal-read.',
      path: ['steps']
    })
  }
  if (kinds.filter((kind) => kind === 'primary').length !== 1) {
    context.addIssue({
      code: 'custom',
      message: 'L2ActionBundle must contain exactly one primary step.',
      path: ['steps']
    })
  }
}

function refineL2ActionBundle(
  value: {
    testObjectVersion: number
    scopeSnapshotId: string
    steps: readonly L2BundleStep[]
  },
  context: z.RefinementCtx
): void {
  assertStepOrder(value.steps, context)
  for (const [index, step] of value.steps.entries()) {
    if (!('binding' in step)) continue
    if (step.binding.testObjectVersion !== value.testObjectVersion) {
      context.addIssue({
        code: 'custom',
        message: 'Step TestObject version must match the bundle.',
        path: ['steps', index, 'binding', 'testObjectVersion']
      })
    }
    if (step.binding.scopeSnapshotId !== value.scopeSnapshotId) {
      context.addIssue({
        code: 'custom',
        message: 'Step Scope snapshot must match the bundle.',
        path: ['steps', index, 'binding', 'scopeSnapshotId']
      })
    }
    const expectedPurpose =
      step.kind === 'primary'
        ? 'primary'
        : step.kind === 'cleanup'
          ? 'cleanup'
          : 'read'
    if (step.binding.purpose !== expectedPurpose) {
      context.addIssue({
        code: 'custom',
        message: `Step ${step.kind} must bind grant purpose ${expectedPurpose}.`,
        path: ['steps', index, 'binding', 'purpose']
      })
    }
  }
}

export const L2ActionBundlePayloadSchema = z
  .strictObject({
    schemaVersion: L2SchemaVersionSchema,
    bundleId: SystemIssuedOpaqueIdSchema,
    bundleVersion: z.number().int().positive(),
    scanId: SystemIssuedOpaqueIdSchema,
    targetId: SystemIssuedOpaqueIdSchema,
    testObjectId: SystemIssuedOpaqueIdSchema,
    testObjectVersion: z.number().int().positive(),
    testObjectHash: ContentHashSchema,
    identityId: SystemIssuedOpaqueIdSchema,
    tenantRef: SystemIssuedOpaqueIdSchema.optional(),
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    sideEffectEnvelope: SideEffectEnvelopeSchema,
    identityContextVersion: L2BindingSlotSchema,
    sessionGeneration: L2BindingSlotSchema,
    csrfBindingVersion: L2BindingSlotSchema,
    authorizationMatrixVersion: L2BindingSlotSchema,
    steps: z.array(L2BundleStepSchema).min(6).max(6).readonly(),
    createdAt: IsoDateSchema
  })
  .superRefine(refineL2ActionBundle)
  .readonly()

export type L2ActionBundlePayload = z.infer<typeof L2ActionBundlePayloadSchema>

export const L2ActionBundleSchema = z
  .strictObject({
    schemaVersion: L2SchemaVersionSchema,
    bundleId: SystemIssuedOpaqueIdSchema,
    bundleVersion: z.number().int().positive(),
    scanId: SystemIssuedOpaqueIdSchema,
    targetId: SystemIssuedOpaqueIdSchema,
    testObjectId: SystemIssuedOpaqueIdSchema,
    testObjectVersion: z.number().int().positive(),
    testObjectHash: ContentHashSchema,
    identityId: SystemIssuedOpaqueIdSchema,
    tenantRef: SystemIssuedOpaqueIdSchema.optional(),
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    sideEffectEnvelope: SideEffectEnvelopeSchema,
    identityContextVersion: L2BindingSlotSchema,
    sessionGeneration: L2BindingSlotSchema,
    csrfBindingVersion: L2BindingSlotSchema,
    authorizationMatrixVersion: L2BindingSlotSchema,
    steps: z.array(L2BundleStepSchema).min(6).max(6).readonly(),
    createdAt: IsoDateSchema,
    bundleHash: ContentHashSchema
  })
  .superRefine(refineL2ActionBundle)
  .readonly()

export type L2ActionBundle = z.infer<typeof L2ActionBundleSchema>

export const L2BundleStateSchema = z.enum([
  'draft',
  'ineligible',
  'pending-approval',
  'approved',
  'running-pre-read',
  'running-primary',
  'primary-unknown',
  'running-post-read',
  'cleanup-pending',
  'cleanup-running',
  'cleanup-verifying',
  'clean',
  'cleanup-failed',
  'expired',
  'revoked',
  'interrupted',
  'inconclusive'
])

export type L2BundleState = z.infer<typeof L2BundleStateSchema>

export const L2ProtocolReasonCodeSchema = z.enum([
  'ok',
  'missing-test-object',
  'missing-agentgo-creation-attestation',
  'not-disposable',
  'ownership-or-tenant-mismatch',
  'identity-mismatch',
  'version-mismatch',
  'unknown-side-effect',
  'unobservable-side-effect',
  'irreversible-side-effect',
  'broad-resource-forbidden',
  'missing-cleanup-protocol',
  'generic-http-delete-forbidden',
  'real-business-object-forbidden',
  'non-agentgo-object-forbidden',
  'imprecise-resource-forbidden',
  'cross-bundle-cleanup-forbidden',
  'step-missing-or-misordered',
  'multiple-primary-steps',
  'bundle-hash-mismatch',
  'session-binding-unresolved',
  'trusted-approval-missing',
  'expired',
  'revoked',
  'illegal-transition',
  'repeat-primary-forbidden',
  'primary-unknown-no-replay',
  'concurrent-version-conflict',
  'cleanup-failed-frozen',
  'receipt-evidence-incomplete',
  'request-execution-state-unknown',
  'not-needed-requires-consistent-evidence'
])

export type L2ProtocolReasonCode = z.infer<typeof L2ProtocolReasonCodeSchema>

export const L2BundleEventTypeSchema = z.enum([
  'mark-ineligible',
  'submit-for-approval',
  'approve',
  'reject',
  'start-pre-read',
  'complete-pre-read',
  'start-primary',
  'complete-primary',
  'mark-primary-unknown',
  'observe-primary-unsent',
  'start-post-read',
  'complete-post-read',
  'start-cleanup',
  'complete-cleanup',
  'fail-cleanup',
  'start-cleanup-verify',
  'complete-cleanup-verify',
  'start-terminal-read',
  'complete-clean',
  'expire',
  'revoke',
  'interrupt',
  'mark-inconclusive',
  'propose-recovery'
])

export type L2BundleEventType = z.infer<typeof L2BundleEventTypeSchema>

export const CleanupReceiptKindSchema = z.enum([
  'cleanup-completed',
  'not-needed-no-state-change'
])

export type CleanupReceiptKind = z.infer<typeof CleanupReceiptKindSchema>

export const RequestExecutionStateSchema = z.enum([
  'not-sent',
  'sent-known-complete',
  'timeout',
  'response-missing',
  'unknown'
])

export type RequestExecutionState = z.infer<typeof RequestExecutionStateSchema>

export const CleanupReceiptPayloadSchema = z
  .strictObject({
    schemaVersion: L2SchemaVersionSchema,
    receiptId: SystemIssuedOpaqueIdSchema,
    kind: CleanupReceiptKindSchema,
    bundleId: SystemIssuedOpaqueIdSchema,
    bundleHash: ContentHashSchema,
    testObjectId: SystemIssuedOpaqueIdSchema,
    testObjectVersion: z.number().int().positive(),
    testObjectHash: ContentHashSchema,
    stepEvidenceHashes: z
      .strictObject({
        preRead: ContentHashSchema,
        primary: ContentHashSchema.optional(),
        postRead: ContentHashSchema,
        cleanup: ContentHashSchema.optional(),
        cleanupVerify: ContentHashSchema,
        terminalRead: ContentHashSchema
      })
      .readonly(),
    actorSlot: L2ApprovalActorSlotSchema,
    issuedAt: IsoDateSchema,
    terminalResourceState: ExactTokenSchema,
    cleanupCapabilityId: L2CleanupCapabilityIdSchema,
    requestExecutionState: RequestExecutionStateSchema
  })
  .readonly()

export type CleanupReceiptPayload = z.infer<typeof CleanupReceiptPayloadSchema>

export const CleanupReceiptSchema = z
  .strictObject({
    schemaVersion: L2SchemaVersionSchema,
    receiptId: SystemIssuedOpaqueIdSchema,
    kind: CleanupReceiptKindSchema,
    bundleId: SystemIssuedOpaqueIdSchema,
    bundleHash: ContentHashSchema,
    testObjectId: SystemIssuedOpaqueIdSchema,
    testObjectVersion: z.number().int().positive(),
    testObjectHash: ContentHashSchema,
    stepEvidenceHashes: z
      .strictObject({
        preRead: ContentHashSchema,
        primary: ContentHashSchema.optional(),
        postRead: ContentHashSchema,
        cleanup: ContentHashSchema.optional(),
        cleanupVerify: ContentHashSchema,
        terminalRead: ContentHashSchema
      })
      .readonly(),
    actorSlot: L2ApprovalActorSlotSchema,
    issuedAt: IsoDateSchema,
    terminalResourceState: ExactTokenSchema,
    cleanupCapabilityId: L2CleanupCapabilityIdSchema,
    requestExecutionState: RequestExecutionStateSchema,
    receiptHash: ContentHashSchema
  })
  .readonly()

export type CleanupReceipt = z.infer<typeof CleanupReceiptSchema>

export const L2ExecutionFreezeSchema = z
  .strictObject({
    freezeId: SystemIssuedOpaqueIdSchema,
    targetId: SystemIssuedOpaqueIdSchema,
    testObjectId: SystemIssuedOpaqueIdSchema,
    bundleId: SystemIssuedOpaqueIdSchema,
    bundleHash: ContentHashSchema,
    reasonCode: z.literal('cleanup-failed-frozen'),
    allows: z.enum(['recovery-proposal-or-manual']),
    createdAt: IsoDateSchema
  })
  .readonly()

export type L2ExecutionFreeze = z.infer<typeof L2ExecutionFreezeSchema>

export function testObjectRefFromL2(object: TestObjectPayload): z.infer<
  typeof TestObjectRefSchema
> {
  return TestObjectRefSchema.parse({
    id: object.testObjectId,
    version: object.objectVersion,
    ownerRef: object.identityId,
    scopeSnapshotId: object.scopeSnapshotId,
    statusSummary: 'ready'
  })
}
