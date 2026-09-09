import { z } from 'zod'
import {
  SystemIssuedOpaqueIdSchema,
  TestObjectRefSchema
} from './inventory'
import {
  ExactTokenSchema,
  L2ContentHashSchema,
  L2DescriptionSchema,
  L2IsoDateSchema,
  SideEffectEnvelopeSchema
} from './l2'
import {
  DefinitionIdSchema,
  ModuleVersionSchema,
  VulnerabilityTechniqueIdSchema
} from './vulnerability'

/**
 * Day 9 contracts: versioned IdentityContext, protected session metadata,
 * CSRF bindings, and the human-confirmed AuthorizationMatrix. These payloads
 * never carry Cookie, Authorization, token, password, or CSRF plaintext;
 * secret material stays inside the backend SessionVault boundary.
 *
 * Day 10 contracts: trusted ActorContext and Approval proposal/record. Only
 * the backend composition root can issue an ActorContext; Renderer payloads,
 * Agent output, and ordinary IPC cannot construct a valid proof handle.
 */

export const IDENTITY_SESSION_SCHEMA_VERSION =
  'agentgo-identity-session/1.0' as const
export const APPROVAL_SCHEMA_VERSION = 'agentgo-l2-approval/1.0' as const

export const IdentitySessionSchemaVersionSchema = z.literal(
  IDENTITY_SESSION_SCHEMA_VERSION
)
export const ApprovalSchemaVersionSchema = z.literal(APPROVAL_SCHEMA_VERSION)

const ContentHashSchema = L2ContentHashSchema
const IsoDateSchema = L2IsoDateSchema
const DescriptionSchema = L2DescriptionSchema

function addUniqueValueIssues(
  values: readonly string[],
  context: z.RefinementCtx,
  label: string,
  path: string
): void {
  const seen = new Set<string>()
  for (const [index, value] of values.entries()) {
    if (seen.has(value)) {
      context.addIssue({
        code: 'custom',
        message: `Duplicate ${label}.`,
        path: [path, index]
      })
    }
    seen.add(value)
  }
}

/* ------------------------------------------------------------------------ */
/* IdentityContext                                                           */
/* ------------------------------------------------------------------------ */

export const IdentityContextOperationSchema = z.enum([
  'read-self',
  'read-contrast',
  'write-test-object',
  'cleanup-test-object'
])

export type IdentityContextOperation = z.infer<
  typeof IdentityContextOperationSchema
>

export const IdentityCredentialKindSchema = z.enum([
  'none',
  'header',
  'bearer',
  'cookie',
  'basic'
])

export type IdentityCredentialKind = z.infer<typeof IdentityCredentialKindSchema>

export const IdentityCredentialRefSchema = z
  .strictObject({
    kind: IdentityCredentialKindSchema,
    credentialId: SystemIssuedOpaqueIdSchema.optional(),
    credentialGeneration: z.number().int().nonnegative().optional(),
    sensitiveLevel: z.enum(['standard', 'sensitive'])
  })
  .superRefine((value, context) => {
    const hasMaterial =
      value.credentialId !== undefined || value.credentialGeneration !== undefined
    if (value.kind === 'none' && hasMaterial) {
      context.addIssue({
        code: 'custom',
        message: 'Anonymous identity contexts must not reference credential material.',
        path: ['credentialId']
      })
    }
    if (value.kind !== 'none') {
      if (value.credentialId === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'Authenticated identity contexts require a credential reference.',
          path: ['credentialId']
        })
      }
      if (value.credentialGeneration === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'Authenticated identity contexts require a credential generation.',
          path: ['credentialGeneration']
        })
      }
    }
  })
  .readonly()

export type IdentityCredentialRef = z.infer<typeof IdentityCredentialRefSchema>

const IdentityContextPayloadFields = {
  schemaVersion: IdentitySessionSchemaVersionSchema,
  identityContextId: SystemIssuedOpaqueIdSchema,
  identityContextVersion: z.number().int().positive(),
  identityId: SystemIssuedOpaqueIdSchema,
  targetId: SystemIssuedOpaqueIdSchema,
  scopeSnapshotId: SystemIssuedOpaqueIdSchema,
  tenantRef: SystemIssuedOpaqueIdSchema.optional(),
  role: ExactTokenSchema,
  ownerLabel: ExactTokenSchema,
  purpose: DescriptionSchema.max(500),
  allowedOperations: z
    .array(IdentityContextOperationSchema)
    .min(1)
    .max(8)
    .superRefine((values, context) => {
      addUniqueValueIssues(values, context, 'identity operation', 'allowedOperations')
    })
    .readonly(),
  contrastIdentityIds: z
    .array(SystemIssuedOpaqueIdSchema)
    .max(8)
    .superRefine((values, context) => {
      addUniqueValueIssues(values, context, 'contrast identity', 'contrastIdentityIds')
    })
    .readonly(),
  exclusiveWith: z
    .array(SystemIssuedOpaqueIdSchema)
    .max(8)
    .superRefine((values, context) => {
      addUniqueValueIssues(values, context, 'exclusive identity', 'exclusiveWith')
    })
    .readonly(),
  credential: IdentityCredentialRefSchema,
  confirmationAuditRef: SystemIssuedOpaqueIdSchema,
  issuedAt: IsoDateSchema,
  expiresAt: IsoDateSchema
} as const

function refineIdentityContextPayload(
  value: {
    identityId: string
    contrastIdentityIds: readonly string[]
    issuedAt: string
    expiresAt: string
  },
  context: z.RefinementCtx
): void {
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    context.addIssue({
      code: 'custom',
      message: 'IdentityContext expiresAt must be after issuedAt.',
      path: ['expiresAt']
    })
  }
  if (value.contrastIdentityIds.includes(value.identityId)) {
    context.addIssue({
      code: 'custom',
      message: 'An identity cannot be its own contrast identity.',
      path: ['contrastIdentityIds']
    })
  }
}

export const IdentityContextPayloadSchema = z
  .strictObject(IdentityContextPayloadFields)
  .superRefine(refineIdentityContextPayload)
  .readonly()

export type IdentityContextPayload = z.infer<typeof IdentityContextPayloadSchema>

export const IdentityContextSchema = z
  .strictObject({
    ...IdentityContextPayloadFields,
    contextHash: ContentHashSchema
  })
  .superRefine(refineIdentityContextPayload)
  .readonly()

export type IdentityContext = z.infer<typeof IdentityContextSchema>

/* ------------------------------------------------------------------------ */
/* CSRF binding                                                              */
/* ------------------------------------------------------------------------ */

export const CsrfExtractionSourceKindSchema = z.enum([
  'html-input',
  'html-meta',
  'json-pointer',
  'response-header',
  'form-field'
])

export type CsrfExtractionSourceKind = z.infer<
  typeof CsrfExtractionSourceKindSchema
>

export const CsrfInjectionLocationSchema = z.enum([
  'header',
  'form-field',
  'json-pointer'
])

export type CsrfInjectionLocation = z.infer<typeof CsrfInjectionLocationSchema>

export const CsrfBindingRuleSchema = z
  .strictObject({
    ruleVersion: ExactTokenSchema,
    sourceKind: CsrfExtractionSourceKindSchema,
    sourceSelector: ExactTokenSchema,
    sourceOrigin: z.string().url().max(2_048),
    sourcePathPrefix: z.string().min(1).max(2_048),
    encoding: z.enum(['raw', 'url-form']),
    injectionLocation: CsrfInjectionLocationSchema,
    injectionName: ExactTokenSchema,
    maxUses: z.number().int().positive().max(16)
  })
  .superRefine((value, context) => {
    if (!value.sourcePathPrefix.startsWith('/')) {
      context.addIssue({
        code: 'custom',
        message: 'CSRF source path prefix must be absolute.',
        path: ['sourcePathPrefix']
      })
    }
    if (value.injectionLocation === 'json-pointer' && value.encoding !== 'raw') {
      context.addIssue({
        code: 'custom',
        message: 'JSON injection points must use raw encoding.',
        path: ['encoding']
      })
    }
  })
  .readonly()

export type CsrfBindingRule = z.infer<typeof CsrfBindingRuleSchema>

const CsrfBindingPayloadFields = {
  schemaVersion: IdentitySessionSchemaVersionSchema,
  csrfBindingId: SystemIssuedOpaqueIdSchema,
  csrfBindingVersion: z.number().int().positive(),
  identityId: SystemIssuedOpaqueIdSchema,
  sessionId: SystemIssuedOpaqueIdSchema,
  sessionGeneration: z.number().int().nonnegative(),
  origin: z.string().url().max(2_048),
  boundMethod: z.enum(['POST', 'PUT', 'PATCH']),
  boundPath: z.string().min(1).max(2_048),
  rule: CsrfBindingRuleSchema,
  tokenHash: ContentHashSchema,
  issuedAt: IsoDateSchema,
  expiresAt: IsoDateSchema
} as const

function refineCsrfBindingPayload(
  value: { boundPath: string; issuedAt: string; expiresAt: string },
  context: z.RefinementCtx
): void {
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    context.addIssue({
      code: 'custom',
      message: 'CSRF binding expiresAt must be after issuedAt.',
      path: ['expiresAt']
    })
  }
  if (!value.boundPath.startsWith('/')) {
    context.addIssue({
      code: 'custom',
      message: 'CSRF bound path must be absolute.',
      path: ['boundPath']
    })
  }
}

export const CsrfBindingPayloadSchema = z
  .strictObject(CsrfBindingPayloadFields)
  .superRefine(refineCsrfBindingPayload)
  .readonly()

export type CsrfBindingPayload = z.infer<typeof CsrfBindingPayloadSchema>

export const CsrfBindingSchema = z
  .strictObject({
    ...CsrfBindingPayloadFields,
    bindingHash: ContentHashSchema
  })
  .superRefine(refineCsrfBindingPayload)
  .readonly()

export type CsrfBinding = z.infer<typeof CsrfBindingSchema>

export const CsrfBindingFailureReasonSchema = z.enum([
  'token-missing',
  'token-ambiguous',
  'token-expired',
  'identity-mismatch',
  'session-generation-mismatch',
  'origin-mismatch',
  'method-path-mismatch',
  'untrusted-source',
  'rule-version-mismatch',
  'use-limit-exceeded'
])

export type CsrfBindingFailureReason = z.infer<
  typeof CsrfBindingFailureReasonSchema
>

/* ------------------------------------------------------------------------ */
/* AuthorizationMatrix                                                       */
/* ------------------------------------------------------------------------ */

export const AuthorizationOperationSchema = z.enum([
  'read',
  'write',
  'delete',
  'invoke'
])

export type AuthorizationOperation = z.infer<typeof AuthorizationOperationSchema>

export const AuthorizationExpectationSchema = z.enum([
  'visible',
  'not-visible',
  'state-allowed',
  'state-denied'
])

export type AuthorizationExpectation = z.infer<
  typeof AuthorizationExpectationSchema
>

export const AuthorizationMatrixEntrySchema = z
  .strictObject({
    subjectIdentityId: SystemIssuedOpaqueIdSchema,
    resourceOwnerIdentityId: SystemIssuedOpaqueIdSchema,
    tenantRef: SystemIssuedOpaqueIdSchema.optional(),
    role: ExactTokenSchema,
    operation: AuthorizationOperationSchema,
    resourceRef: ExactTokenSchema,
    expected: AuthorizationExpectationSchema,
    humanSource: DescriptionSchema.max(500),
    evidenceRef: SystemIssuedOpaqueIdSchema.optional()
  })
  .readonly()

export type AuthorizationMatrixEntry = z.infer<
  typeof AuthorizationMatrixEntrySchema
>

const AuthorizationMatrixPayloadFields = {
  schemaVersion: IdentitySessionSchemaVersionSchema,
  matrixId: SystemIssuedOpaqueIdSchema,
  matrixVersion: z.number().int().positive(),
  targetId: SystemIssuedOpaqueIdSchema,
  scopeSnapshotId: SystemIssuedOpaqueIdSchema,
  entries: z.array(AuthorizationMatrixEntrySchema).min(1).max(64).readonly(),
  humanAttestationRef: SystemIssuedOpaqueIdSchema,
  issuedAt: IsoDateSchema,
  expiresAt: IsoDateSchema
} as const

function refineAuthorizationMatrixPayload(
  value: { issuedAt: string; expiresAt: string },
  context: z.RefinementCtx
): void {
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    context.addIssue({
      code: 'custom',
      message: 'AuthorizationMatrix expiresAt must be after issuedAt.',
      path: ['expiresAt']
    })
  }
}

export const AuthorizationMatrixPayloadSchema = z
  .strictObject(AuthorizationMatrixPayloadFields)
  .superRefine(refineAuthorizationMatrixPayload)
  .readonly()

export type AuthorizationMatrixPayload = z.infer<
  typeof AuthorizationMatrixPayloadSchema
>

export const AuthorizationMatrixSchema = z
  .strictObject({
    ...AuthorizationMatrixPayloadFields,
    matrixHash: ContentHashSchema
  })
  .superRefine(refineAuthorizationMatrixPayload)
  .readonly()

export type AuthorizationMatrix = z.infer<typeof AuthorizationMatrixSchema>

/* ------------------------------------------------------------------------ */
/* ActorContext (Day 10)                                                     */
/* ------------------------------------------------------------------------ */

export const ActorAuthStrengthSchema = z.enum([
  'interactive-human',
  'fixture-stub'
])

export type ActorAuthStrength = z.infer<typeof ActorAuthStrengthSchema>

export const ActorRoleSchema = z.enum(['l2-approver'])

export type ActorRole = z.infer<typeof ActorRoleSchema>

const ActorContextPayloadFields = {
  schemaVersion: ApprovalSchemaVersionSchema,
  actorId: SystemIssuedOpaqueIdSchema,
  roles: z
    .array(ActorRoleSchema)
    .min(1)
    .max(4)
    .superRefine((values, context) => {
      addUniqueValueIssues(values, context, 'actor role', 'roles')
    })
    .readonly(),
  authenticatedAt: IsoDateSchema,
  authStrength: ActorAuthStrengthSchema,
  trustedSessionId: SystemIssuedOpaqueIdSchema,
  auditSource: ExactTokenSchema,
  channel: z.literal('backend-composition-root'),
  allowedTargetIds: z
    .array(SystemIssuedOpaqueIdSchema)
    .min(1)
    .max(64)
    .superRefine((values, context) => {
      addUniqueValueIssues(values, context, 'allowed target', 'allowedTargetIds')
    })
    .readonly(),
  issuedAt: IsoDateSchema,
  expiresAt: IsoDateSchema
} as const

function refineActorContextPayload(
  value: { authenticatedAt: string; issuedAt: string; expiresAt: string },
  context: z.RefinementCtx
): void {
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    context.addIssue({
      code: 'custom',
      message: 'ActorContext expiresAt must be after issuedAt.',
      path: ['expiresAt']
    })
  }
  if (Date.parse(value.authenticatedAt) > Date.parse(value.issuedAt)) {
    context.addIssue({
      code: 'custom',
      message: 'ActorContext authentication cannot postdate issuance.',
      path: ['authenticatedAt']
    })
  }
}

export const ActorContextPayloadSchema = z
  .strictObject(ActorContextPayloadFields)
  .superRefine(refineActorContextPayload)
  .readonly()

export type ActorContextPayload = z.infer<typeof ActorContextPayloadSchema>

/**
 * The proof handle is an HMAC over the context payload keyed by a
 * backend-held key. Callers outside the trusted composition root cannot
 * mint or recompute it.
 */
export const ActorProofHandleSchema = z
  .strictObject({
    handleId: SystemIssuedOpaqueIdSchema,
    algorithm: z.literal('hmac-sha256'),
    digest: ContentHashSchema
  })
  .readonly()

export type ActorProofHandle = z.infer<typeof ActorProofHandleSchema>

export const ActorContextSchema = z
  .strictObject({
    ...ActorContextPayloadFields,
    contextHash: ContentHashSchema,
    handle: ActorProofHandleSchema
  })
  .superRefine(refineActorContextPayload)
  .readonly()

export type ActorContext = z.infer<typeof ActorContextSchema>

/* ------------------------------------------------------------------------ */
/* Approval proposal & record (Day 10)                                       */
/* ------------------------------------------------------------------------ */

export const ApprovalModeSchema = z.enum(['fixture-only', 'trusted-backend'])

export type ApprovalMode = z.infer<typeof ApprovalModeSchema>

export const ApprovalDecisionSchema = z.enum(['approved', 'rejected'])

export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>

export const ApprovalReasonCodeSchema = z.enum([
  'ok',
  'untrusted-actor',
  'actor-expired',
  'actor-revoked',
  'actor-scope-mismatch',
  'proposal-missing',
  'proposal-expired',
  'bundle-not-pending',
  'bundle-hash-mismatch',
  'binding-version-drift',
  'already-consumed',
  'already-decided',
  'approval-expired',
  'approval-revoked',
  'fixture-mode-forbidden',
  'legacy-user-approved-ignored'
])

export type ApprovalReasonCode = z.infer<typeof ApprovalReasonCodeSchema>

export const ApprovalStepSummarySchema = z
  .strictObject({
    ordinal: z.number().int().positive().max(8),
    kind: ExactTokenSchema,
    intentHash: ContentHashSchema,
    maxRequests: z.number().int().positive().max(8),
    maxDurationMs: z.number().int().positive().max(60_000),
    maxConcurrency: z.literal(1)
  })
  .readonly()

export type ApprovalStepSummary = z.infer<typeof ApprovalStepSummarySchema>

export const ResolvedBindingVersionsSchema = z
  .strictObject({
    identityContextVersion: ExactTokenSchema,
    sessionGeneration: ExactTokenSchema,
    csrfBindingVersion: ExactTokenSchema,
    authorizationMatrixVersion: ExactTokenSchema
  })
  .readonly()

export type ResolvedBindingVersions = z.infer<typeof ResolvedBindingVersionsSchema>

const ApprovalProposalPayloadFields = {
  schemaVersion: ApprovalSchemaVersionSchema,
  proposalId: SystemIssuedOpaqueIdSchema,
  bundleId: SystemIssuedOpaqueIdSchema,
  bundleVersion: z.number().int().positive(),
  bundleHash: ContentHashSchema,
  scanId: SystemIssuedOpaqueIdSchema,
  targetId: SystemIssuedOpaqueIdSchema,
  scopeSnapshotId: SystemIssuedOpaqueIdSchema,
  moduleId: DefinitionIdSchema,
  moduleVersion: ModuleVersionSchema,
  techniqueId: VulnerabilityTechniqueIdSchema,
  techniqueVersion: ModuleVersionSchema,
  steps: z.array(ApprovalStepSummarySchema).min(6).max(6).readonly(),
  bindings: ResolvedBindingVersionsSchema,
  testObjectRef: TestObjectRefSchema,
  testObjectHash: ContentHashSchema,
  ownershipProofSummary: ContentHashSchema,
  sideEffectEnvelope: SideEffectEnvelopeSchema,
  cleanupCapabilityId: ExactTokenSchema,
  expectedTerminalState: ExactTokenSchema,
  unknowns: z.array(DescriptionSchema).max(16).readonly(),
  freezeRules: z.array(DescriptionSchema).min(1).max(8).readonly(),
  humanRiskNotes: z.array(DescriptionSchema).max(16).readonly(),
  issuedAt: IsoDateSchema,
  expiresAt: IsoDateSchema
} as const

function refineApprovalProposalPayload(
  value: { issuedAt: string; expiresAt: string },
  context: z.RefinementCtx
): void {
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    context.addIssue({
      code: 'custom',
      message: 'Approval proposal expiresAt must be after issuedAt.',
      path: ['expiresAt']
    })
  }
}

export const ApprovalProposalPayloadSchema = z
  .strictObject(ApprovalProposalPayloadFields)
  .superRefine(refineApprovalProposalPayload)
  .readonly()

export type ApprovalProposalPayload = z.infer<typeof ApprovalProposalPayloadSchema>

export const ApprovalProposalSchema = z
  .strictObject({
    ...ApprovalProposalPayloadFields,
    proposalHash: ContentHashSchema
  })
  .superRefine(refineApprovalProposalPayload)
  .readonly()

export type ApprovalProposal = z.infer<typeof ApprovalProposalSchema>

export const ApprovalBindingHashesSchema = z
  .strictObject({
    identityContextVersion: ExactTokenSchema,
    sessionGeneration: ExactTokenSchema,
    csrfBindingVersion: ExactTokenSchema,
    authorizationMatrixVersion: ExactTokenSchema,
    testObjectHash: ContentHashSchema,
    sideEffectEnvelopeHash: ContentHashSchema,
    cleanupCapabilityId: ExactTokenSchema
  })
  .readonly()

export type ApprovalBindingHashes = z.infer<typeof ApprovalBindingHashesSchema>

const ApprovalRecordPayloadFields = {
  schemaVersion: ApprovalSchemaVersionSchema,
  approvalId: SystemIssuedOpaqueIdSchema,
  proposalHash: ContentHashSchema,
  bundleId: SystemIssuedOpaqueIdSchema,
  bundleVersion: z.number().int().positive(),
  bundleHash: ContentHashSchema,
  decision: ApprovalDecisionSchema,
  approvalMode: ApprovalModeSchema,
  actorId: SystemIssuedOpaqueIdSchema,
  actorContextHash: ContentHashSchema,
  authStrength: ActorAuthStrengthSchema,
  authenticatedAt: IsoDateSchema,
  bindingHashes: ApprovalBindingHashesSchema,
  singleUse: z.literal(true),
  issuedAt: IsoDateSchema,
  expiresAt: IsoDateSchema
} as const

function refineApprovalRecordPayload(
  value: { issuedAt: string; expiresAt: string },
  context: z.RefinementCtx
): void {
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    context.addIssue({
      code: 'custom',
      message: 'Approval record expiresAt must be after issuedAt.',
      path: ['expiresAt']
    })
  }
}

export const ApprovalRecordPayloadSchema = z
  .strictObject(ApprovalRecordPayloadFields)
  .superRefine(refineApprovalRecordPayload)
  .readonly()

export type ApprovalRecordPayload = z.infer<typeof ApprovalRecordPayloadSchema>

export const ApprovalRecordSchema = z
  .strictObject({
    ...ApprovalRecordPayloadFields,
    approvalHash: ContentHashSchema
  })
  .superRefine(refineApprovalRecordPayload)
  .readonly()

export type ApprovalRecord = z.infer<typeof ApprovalRecordSchema>

export const ApprovalRecordStatusSchema = z.enum([
  'active',
  'consumed',
  'rejected',
  'revoked',
  'expired'
])

export type ApprovalRecordStatus = z.infer<typeof ApprovalRecordStatusSchema>

export const ApprovalRecordViewSchema = z
  .strictObject({
    record: ApprovalRecordSchema,
    status: ApprovalRecordStatusSchema,
    consumedAt: IsoDateSchema.optional(),
    revokedAt: IsoDateSchema.optional(),
    revocationReason: DescriptionSchema.max(500).optional()
  })
  .readonly()

export type ApprovalRecordView = z.infer<typeof ApprovalRecordViewSchema>
