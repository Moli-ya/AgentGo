import { z } from 'zod'
import {
  EvidenceCaptureDecisionSchema,
  type EvidenceCaptureDecision
} from './application'
import {
  IdentityRefSchema,
  SessionGenerationRefSchema,
  SystemIssuedOpaqueIdSchema,
  TestObjectRefSchema
} from './inventory'
import {
  ResolvedIntentHashSchema,
  TemplateIntentHashSchema,
  WireRequestHmacSchema
} from './security'
import {
  CapabilityIdSchema,
  DefinitionIdSchema,
  ModuleVersionSchema,
  VulnerabilityTechniqueIdSchema
} from './vulnerability'

const SHA256_DIGEST_PATTERN = /^[a-f0-9]{64}$/u
const IsoDateSchema = z.string().datetime()
const Sha256DigestSchema = z.string().regex(SHA256_DIGEST_PATTERN)

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

export const ExecutionPlanVersionSchema = z
  .string()
  .min(1)
  .max(256)
  .refine(
    (value) => value === value.trim(),
    'Execution plan versions must not contain surrounding whitespace.'
  )
  .refine(
    (value) => value === value.normalize('NFC'),
    'Execution plan versions must use Unicode NFC normalization.'
  )
  .refine(
    isWellFormedUnicode,
    'Execution plan versions must contain well-formed Unicode.'
  )
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    'Execution plan versions must not contain control characters.'
  )

export type ExecutionPlanVersion = z.infer<
  typeof ExecutionPlanVersionSchema
>

export const ExecutionPurposeSchema = z.enum(['primary', 'read', 'cleanup'])

export type ExecutionPurpose = z.infer<typeof ExecutionPurposeSchema>

export const ExecutionAdapterKindSchema = z.enum([
  'http',
  'browser-offline',
  'browser-network',
  'oob-poll',
  'cleanup'
])

export type ExecutionAdapterKind = z.infer<typeof ExecutionAdapterKindSchema>

export const ExecutionRetryClassSchema = z.enum([
  'never',
  'deterministic-readonly'
])

export type ExecutionRetryClass = z.infer<typeof ExecutionRetryClassSchema>

export const EXECUTION_GRANT_INTEGRITY_HMAC_DOMAIN =
  'agentgo.execution-grant.v1' as const

export const ExecutionGrantIntegrityHmacSchema = z
  .strictObject({
    domain: z.literal(EXECUTION_GRANT_INTEGRITY_HMAC_DOMAIN),
    algorithm: z.literal('hmac-sha256'),
    keyRef: SystemIssuedOpaqueIdSchema,
    keyVersion: z.number().int().nonnegative(),
    digest: Sha256DigestSchema
  })
  .readonly()

export type ExecutionGrantIntegrityHmac = z.infer<
  typeof ExecutionGrantIntegrityHmacSchema
>

export const ExecutionCapabilityIdsSchema = z
  .array(CapabilityIdSchema)
  .min(1)
  .max(128)
  .superRefine((ids, context) => {
    const seen = new Set<string>()
    for (const [index, id] of ids.entries()) {
      if (seen.has(id)) {
        context.addIssue({
          code: 'custom',
          message: `Duplicate execution capability ID: ${id}`,
          path: [index]
        })
      }
      seen.add(id)
      if (index > 0 && ids[index - 1]! >= id) {
        context.addIssue({
          code: 'custom',
          message: 'Execution capability IDs must use strict canonical ordering.',
          path: [index]
        })
      }
    }
  })
  .readonly()

export type ExecutionCapabilityIds = z.infer<
  typeof ExecutionCapabilityIdsSchema
>

export const ExecutionGrantBudgetSchema = z
  .strictObject({
    requestUnits: z.literal(1),
    requestBytes: z.number().int().nonnegative().max(1_146_880),
    maxResponseBytes: z.number().int().positive().max(16_777_216),
    timeoutMs: z.number().int().positive().max(120_000),
    maxRedirects: z.number().int().nonnegative().max(10)
  })
  .readonly()

export type ExecutionGrantBudget = z.infer<
  typeof ExecutionGrantBudgetSchema
>

/**
 * Opaque credential metadata only. Secret material and file paths are never
 * part of a grant; the Guard revalidates this generation at the claim edge.
 */
export const ExecutionCredentialRefSchema = z
  .strictObject({
    id: SystemIssuedOpaqueIdSchema,
    kind: z.literal('identity'),
    generation: z.number().int().nonnegative()
  })
  .readonly()

export type ExecutionCredentialRef = z.infer<
  typeof ExecutionCredentialRefSchema
>

export const EXECUTION_CAPTURE_DECISION_SET_HASH_DOMAIN =
  'agentgo.execution-capture-decision-set.v1' as const

export const ExecutionCaptureDecisionSetHashSchema = z
  .strictObject({
    domain: z.literal(EXECUTION_CAPTURE_DECISION_SET_HASH_DOMAIN),
    algorithm: z.literal('sha256'),
    digest: Sha256DigestSchema
  })
  .readonly()

export type ExecutionCaptureDecisionSetHash = z.infer<
  typeof ExecutionCaptureDecisionSetHashSchema
>

function captureDecisionCanonicalKey(
  decision: EvidenceCaptureDecision
): string {
  return `${decision.source}\u0000${decision.executionState}`
}

/**
 * The complete, immutable capture authority for one execution grant.
 *
 * Day 5 execution pre-authorizes two runtime summary sources for four normal
 * terminal states plus one crash-interruption summary. Canonical ordering
 * makes the signed set hash stable and
 * prevents semantically equivalent arrays from producing different proofs.
 */
export const ExecutionCaptureDecisionSetSchema = z
  .strictObject({
    schemaVersion: z.literal('execution-capture-decision-set.v1'),
    decisions: z
      .array(EvidenceCaptureDecisionSchema)
      .length(9)
      .superRefine((decisions, context) => {
        const ids = new Set<string>()
        const bindings = new Set<string>()
        for (const [index, decision] of decisions.entries()) {
          if (ids.has(decision.id)) {
            context.addIssue({
              code: 'custom',
              message: `Duplicate execution capture decision ID: ${decision.id}`,
              path: [index, 'id']
            })
          }
          ids.add(decision.id)
          const binding = captureDecisionCanonicalKey(decision)
          if (bindings.has(binding)) {
            context.addIssue({
              code: 'custom',
              message:
                'Execution capture decisions must bind each source/state pair exactly once.',
              path: [index]
            })
          }
          bindings.add(binding)
          if (
            index > 0 &&
            captureDecisionCanonicalKey(decisions[index - 1]!) >= binding
          ) {
            context.addIssue({
              code: 'custom',
              message:
                'Execution capture decisions must use strict canonical source/state ordering.',
              path: [index]
            })
          }
        }
      })
      .readonly()
  })
  .readonly()

export type ExecutionCaptureDecisionSet = z.infer<
  typeof ExecutionCaptureDecisionSetSchema
>

const ExecutionGrantBindingFields = {
  scanId: SystemIssuedOpaqueIdSchema,
  scopeSnapshotId: SystemIssuedOpaqueIdSchema,
  scopeSnapshotHash: Sha256DigestSchema,
  moduleSnapshotId: SystemIssuedOpaqueIdSchema,
  moduleSnapshotHash: Sha256DigestSchema,
  moduleId: DefinitionIdSchema,
  moduleVersion: ModuleVersionSchema,
  techniqueId: VulnerabilityTechniqueIdSchema,
  techniqueVersion: ModuleVersionSchema,
  planId: SystemIssuedOpaqueIdSchema,
  planVersion: ExecutionPlanVersionSchema,
  planHash: Sha256DigestSchema,
  stepId: DefinitionIdSchema,
  templateIntentHash: TemplateIntentHashSchema,
  resolvedIntentHash: ResolvedIntentHashSchema,
  wireRequestHmac: WireRequestHmacSchema,
  captureDecisionSetHash: ExecutionCaptureDecisionSetHashSchema,
  capabilityIds: ExecutionCapabilityIdsSchema,
  ownerRef: SystemIssuedOpaqueIdSchema.optional(),
  identityRef: IdentityRefSchema.optional(),
  credentialRef: ExecutionCredentialRefSchema.nullable(),
  sessionRef: SessionGenerationRefSchema.optional(),
  testObjectRef: TestObjectRefSchema.optional(),
  budget: ExecutionGrantBudgetSchema,
  purpose: ExecutionPurposeSchema,
  adapterKind: ExecutionAdapterKindSchema
} as const

type ExecutionBindingForRefinement = {
  scopeSnapshotId: string
  purpose: ExecutionPurpose
  ownerRef?: string | undefined
  identityRef?: z.infer<typeof IdentityRefSchema> | undefined
  credentialRef: z.infer<typeof ExecutionCredentialRefSchema> | null
  sessionRef?: z.infer<typeof SessionGenerationRefSchema> | undefined
  testObjectRef?: z.infer<typeof TestObjectRefSchema> | undefined
  resolvedIntentHash: z.infer<typeof ResolvedIntentHashSchema>
  wireRequestHmac: z.infer<typeof WireRequestHmacSchema>
  adapterKind: ExecutionAdapterKind
  capabilityIds: ExecutionCapabilityIds
}

function addExecutionBindingIssues(
  binding: ExecutionBindingForRefinement,
  context: z.RefinementCtx
): void {
  const refs = [
    binding.identityRef,
    binding.sessionRef,
    binding.testObjectRef
  ].filter(
    (
      value
    ): value is
      | z.infer<typeof IdentityRefSchema>
      | z.infer<typeof SessionGenerationRefSchema>
      | z.infer<typeof TestObjectRefSchema> => value !== undefined
  )
  if (refs.length > 0 && binding.ownerRef === undefined) {
    context.addIssue({
      code: 'custom',
      message: 'Opaque execution context references require an owner reference.',
      path: ['ownerRef']
    })
  }
  for (const ref of refs) {
    if (ref.ownerRef !== binding.ownerRef) {
      context.addIssue({
        code: 'custom',
        message: 'Opaque execution context references must share the grant owner.',
        path: ['ownerRef']
      })
    }
    if (ref.scopeSnapshotId !== binding.scopeSnapshotId) {
      context.addIssue({
        code: 'custom',
        message: 'Opaque execution context references must share the grant scope.',
        path: ['scopeSnapshotId']
      })
    }
  }
  if (binding.identityRef && binding.identityRef.statusSummary !== 'active') {
    context.addIssue({
      code: 'custom',
      message: 'Execution identity references must be active.',
      path: ['identityRef', 'statusSummary']
    })
  }
  if (binding.credentialRef !== null && !binding.identityRef) {
    context.addIssue({
      code: 'custom',
      message:
        'Identity credential metadata requires an authoritative identity reference.',
      path: ['credentialRef']
    })
  }
  if (binding.sessionRef && binding.sessionRef.statusSummary !== 'active') {
    context.addIssue({
      code: 'custom',
      message: 'Execution session references must be active.',
      path: ['sessionRef', 'statusSummary']
    })
  }
  if (
    binding.testObjectRef &&
    binding.testObjectRef.statusSummary !== 'ready' &&
    binding.testObjectRef.statusSummary !== 'in-use'
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Execution test-object references must be ready or in use.',
      path: ['testObjectRef', 'statusSummary']
    })
  }
  if (
    binding.resolvedIntentHash.commitmentKeyRef !==
      binding.wireRequestHmac.keyRef ||
    binding.resolvedIntentHash.commitmentKeyVersion !==
      binding.wireRequestHmac.keyVersion
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Resolved and wire request proofs must use the same key generation.',
      path: ['wireRequestHmac', 'keyRef']
    })
  }
  const mandatoryCapability =
    binding.adapterKind === 'http'
      ? 'http.reviewed-read'
      : binding.adapterKind === 'browser-offline'
        ? 'browser.offline-replay'
        : undefined
  if (
    mandatoryCapability !== undefined &&
    !binding.capabilityIds.includes(mandatoryCapability)
  ) {
    context.addIssue({
      code: 'custom',
      message: `Execution adapter requires capability: ${mandatoryCapability}`,
      path: ['capabilityIds']
    })
  }
}

const ExecutionGrantAuthorityFields = {
  retryClass: ExecutionRetryClassSchema,
  policyDecisionId: SystemIssuedOpaqueIdSchema,
  approvalBundleRef: SystemIssuedOpaqueIdSchema.optional(),
  parentGrantId: SystemIssuedOpaqueIdSchema.optional(),
  redirectHop: z.number().int().nonnegative().max(10),
  validFrom: IsoDateSchema,
  validUntil: IsoDateSchema,
  issuedAt: IsoDateSchema
} as const

type ExecutionGrantForRefinement = ExecutionBindingForRefinement & {
  budget: ExecutionGrantBudget
  retryClass: ExecutionRetryClass
  parentGrantId?: string | undefined
  redirectHop: number
  validFrom: string
  validUntil: string
  issuedAt: string
}

function addExecutionGrantIssues(
  grant: ExecutionGrantForRefinement,
  context: z.RefinementCtx
): void {
  addExecutionBindingIssues(grant, context)
  if (
    grant.retryClass === 'deterministic-readonly' &&
    grant.purpose !== 'read'
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Deterministic retries are restricted to read-purpose grants.',
      path: ['retryClass']
    })
  }
  const validFrom = Date.parse(grant.validFrom)
  const validUntil = Date.parse(grant.validUntil)
  const issuedAt = Date.parse(grant.issuedAt)
  if (validFrom > issuedAt || issuedAt >= validUntil) {
    context.addIssue({
      code: 'custom',
      message: 'Execution grant issuance must fall inside its validity window.',
      path: ['issuedAt']
    })
  }
  if (
    (grant.redirectHop === 0 && grant.parentGrantId !== undefined) ||
    (grant.redirectHop > 0 && grant.parentGrantId === undefined)
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Redirect grants must bind exactly one preceding grant.',
      path: ['parentGrantId']
    })
  }
  if (grant.redirectHop > grant.budget.maxRedirects) {
    context.addIssue({
      code: 'custom',
      message: 'Redirect hop exceeds the immutable execution budget.',
      path: ['redirectHop']
    })
  }
}

const ExecutionGrantIntegrityBindingFields = {
  schemaVersion: z.literal('execution-grant.v1'),
  id: SystemIssuedOpaqueIdSchema,
  ...ExecutionGrantBindingFields,
  ...ExecutionGrantAuthorityFields
} as const

/** Canonical immutable payload signed by the execution authority. */
export const ExecutionGrantIntegrityBindingSchema = z
  .strictObject(ExecutionGrantIntegrityBindingFields)
  .superRefine(addExecutionGrantIssues)
  .readonly()

export type ExecutionGrantIntegrityBinding = z.infer<
  typeof ExecutionGrantIntegrityBindingSchema
>

function addExecutionIntegrityProofIssues(
  value: {
    wireRequestHmac: z.infer<typeof WireRequestHmacSchema>
    integrityHmac: ExecutionGrantIntegrityHmac
  },
  context: z.RefinementCtx
): void {
  if (
    value.integrityHmac.keyRef !== value.wireRequestHmac.keyRef ||
    value.integrityHmac.keyVersion !== value.wireRequestHmac.keyVersion
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Grant and wire HMACs must use the same key generation.',
      path: ['integrityHmac', 'keyRef']
    })
  }
}

export const ExecutionClaimBindingSchema = z
  .strictObject({
    grantId: SystemIssuedOpaqueIdSchema,
    ...ExecutionGrantBindingFields,
    ...ExecutionGrantAuthorityFields,
    integrityHmac: ExecutionGrantIntegrityHmacSchema
  })
  .superRefine((binding, context) => {
    addExecutionGrantIssues(binding, context)
    addExecutionIntegrityProofIssues(binding, context)
  })
  .readonly()

export type ExecutionClaimBinding = z.infer<
  typeof ExecutionClaimBindingSchema
>

export const ExecutionGrantSchema = z
  .strictObject({
    ...ExecutionGrantIntegrityBindingFields,
    integrityHmac: ExecutionGrantIntegrityHmacSchema
  })
  .superRefine((grant, context) => {
    addExecutionGrantIssues(grant, context)
    addExecutionIntegrityProofIssues(grant, context)
  })
  .readonly()

export type ExecutionGrant = z.infer<typeof ExecutionGrantSchema>

export const ExecutionLeaseStateSchema = z.enum([
  'issued',
  'claimed',
  'completed',
  'failed',
  'expired',
  'revoked'
])

export type ExecutionLeaseState = z.infer<typeof ExecutionLeaseStateSchema>

export const ExecutionLeaseDeliveryStateSchema = z.enum([
  'not-dispatched',
  'possibly-sent',
  'response-started',
  'completed',
  'unknown'
])

export type ExecutionLeaseDeliveryState = z.infer<
  typeof ExecutionLeaseDeliveryStateSchema
>

export const ExecutionLeaseTerminalReasonSchema = z.enum([
  'completed',
  'guard-rejected',
  'expired',
  'revoked',
  'cancelled',
  'timed-out',
  'network-failed',
  'response-read-failed',
  'redirect-rejected',
  'unsupported-adapter',
  'interrupted'
])

export type ExecutionLeaseTerminalReason = z.infer<
  typeof ExecutionLeaseTerminalReasonSchema
>

export const ExecutionOutcomeStateSchema = z.enum([
  'succeeded',
  'failed',
  'cancelled',
  'timed-out',
  'interrupted'
])

export type ExecutionOutcomeState = z.infer<
  typeof ExecutionOutcomeStateSchema
>

export const ExecutionLeaseOutcomeSummarySchema = z
  .strictObject({
    executionState: ExecutionOutcomeStateSchema,
    deliveryState: ExecutionLeaseDeliveryStateSchema,
    verdictImpact: z.enum(['none', 'inconclusive']),
    wireRequestHmacDigest: Sha256DigestSchema.optional(),
    requestBytes: z.number().int().nonnegative().optional(),
    responseBytes: z.number().int().nonnegative().optional(),
    errorCode: DefinitionIdSchema.optional()
  })
  .superRefine((summary, context) => {
    const successful = summary.executionState === 'succeeded'
    const completed = summary.deliveryState === 'completed'
    if (successful !== completed) {
      context.addIssue({
        code: 'custom',
        message: 'Successful execution and completed delivery must agree.',
        path: ['executionState']
      })
    }
    const expectedVerdictImpact =
      summary.deliveryState === 'not-dispatched' ||
      summary.deliveryState === 'completed'
        ? 'none'
        : 'inconclusive'
    if (summary.verdictImpact !== expectedVerdictImpact) {
      context.addIssue({
        code: 'custom',
        message: 'Execution verdict impact must reflect delivery uncertainty.',
        path: ['verdictImpact']
      })
    }
    if (
      summary.deliveryState === 'unknown' &&
      summary.executionState !== 'interrupted'
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Unknown delivery is reserved for interrupted execution.',
        path: ['deliveryState']
      })
    }
    if (
      summary.executionState === 'interrupted' &&
      (summary.deliveryState !== 'unknown' ||
        summary.verdictImpact !== 'inconclusive')
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Interrupted execution outcomes must be unknown and inconclusive.',
        path: ['executionState']
      })
    }
  })
  .readonly()

export type ExecutionLeaseOutcomeSummary = z.infer<
  typeof ExecutionLeaseOutcomeSummarySchema
>

export const ExecutionEvidenceRefsSchema = z
  .array(SystemIssuedOpaqueIdSchema)
  .max(256)
  .superRefine((ids, context) => {
    const seen = new Set<string>()
    for (const [index, id] of ids.entries()) {
      if (seen.has(id)) {
        context.addIssue({
          code: 'custom',
          message: `Duplicate execution Evidence reference: ${id}`,
          path: [index]
        })
      }
      seen.add(id)
    }
  })
  .readonly()

export const ExecutionLeaseSchema = z
  .strictObject({
    schemaVersion: z.literal('execution-lease.v1'),
    id: SystemIssuedOpaqueIdSchema,
    grantId: SystemIssuedOpaqueIdSchema,
    parentLeaseId: SystemIssuedOpaqueIdSchema.optional(),
    attempt: z.number().int().positive(),
    state: ExecutionLeaseStateSchema,
    issuedAt: IsoDateSchema,
    expiresAt: IsoDateSchema,
    claimedAt: IsoDateSchema.optional(),
    claimedBy: SystemIssuedOpaqueIdSchema.optional(),
    claimTokenHash: Sha256DigestSchema.optional(),
    deliveryState: ExecutionLeaseDeliveryStateSchema,
    terminalAt: IsoDateSchema.optional(),
    terminalReason: ExecutionLeaseTerminalReasonSchema.optional(),
    outcomeSummary: ExecutionLeaseOutcomeSummarySchema.optional(),
    evidenceRefs: ExecutionEvidenceRefsSchema
  })
  .superRefine((lease, context) => {
    if (Date.parse(lease.issuedAt) >= Date.parse(lease.expiresAt)) {
      context.addIssue({
        code: 'custom',
        message: 'Execution leases must expire after issuance.',
        path: ['expiresAt']
      })
    }
    const hasClaim =
      lease.claimedAt !== undefined &&
      lease.claimedBy !== undefined &&
      lease.claimTokenHash !== undefined
    const hasAnyClaim =
      lease.claimedAt !== undefined ||
      lease.claimedBy !== undefined ||
      lease.claimTokenHash !== undefined
    const hasTerminal =
      lease.terminalAt !== undefined && lease.terminalReason !== undefined
    const hasAnyTerminal =
      lease.terminalAt !== undefined ||
      lease.terminalReason !== undefined ||
      lease.outcomeSummary !== undefined

    if (hasAnyClaim && !hasClaim) {
      context.addIssue({
        code: 'custom',
        message: 'Execution lease claim metadata must be complete.',
        path: ['claimedAt']
      })
    }
    if (
      lease.state === 'issued' &&
      (hasAnyClaim ||
        hasAnyTerminal ||
        lease.deliveryState !== 'not-dispatched')
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Issued execution leases cannot contain claim or terminal metadata.',
        path: ['state']
      })
    }
    if (
      lease.state === 'claimed' &&
      (!hasClaim ||
        hasAnyTerminal ||
        lease.deliveryState === 'completed' ||
        lease.deliveryState === 'unknown')
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Claimed execution leases require non-terminal claim metadata.',
        path: ['state']
      })
    }
    if (
      lease.state === 'completed' &&
      (!hasClaim ||
        !hasTerminal ||
        lease.terminalReason !== 'completed' ||
        lease.deliveryState !== 'completed' ||
        lease.outcomeSummary?.executionState !== 'succeeded')
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Completed execution leases require a successful completed outcome.',
        path: ['state']
      })
    }
    if (
      lease.state === 'failed' &&
      (!hasClaim ||
        !hasTerminal ||
        lease.terminalReason === 'completed' ||
        lease.terminalReason === 'expired' ||
        lease.terminalReason === 'revoked' ||
        lease.outcomeSummary === undefined ||
        lease.deliveryState === 'completed' ||
        (lease.terminalReason === 'cancelled'
          ? lease.outcomeSummary?.executionState !== 'cancelled'
          : lease.terminalReason === 'timed-out'
            ? lease.outcomeSummary?.executionState !== 'timed-out'
            : lease.terminalReason === 'interrupted'
              ? lease.outcomeSummary?.executionState !== 'interrupted'
              : lease.outcomeSummary?.executionState !== 'failed'))
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Failed execution leases require a matching non-completed terminal outcome.',
        path: ['state']
      })
    }
    if (
      (lease.state === 'expired' || lease.state === 'revoked') &&
      (hasAnyClaim ||
        !hasTerminal ||
        lease.outcomeSummary !== undefined ||
        lease.deliveryState !== 'not-dispatched' ||
        (lease.state === 'expired' && lease.terminalReason !== 'expired') ||
        (lease.state === 'revoked' &&
          lease.terminalReason !== 'revoked' &&
          lease.terminalReason !== 'guard-rejected' &&
          lease.terminalReason !== 'unsupported-adapter'))
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Unclaimed terminal leases must retain a non-dispatched outcome.',
        path: ['state']
      })
    }
    if (
      lease.outcomeSummary &&
      lease.outcomeSummary.deliveryState !== lease.deliveryState
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Lease and outcome delivery states must match.',
        path: ['outcomeSummary', 'deliveryState']
      })
    }
    if (
      lease.terminalAt !== undefined &&
      Date.parse(lease.terminalAt) < Date.parse(lease.issuedAt)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Execution lease terminal time cannot precede issuance.',
        path: ['terminalAt']
      })
    }
  })
  .readonly()

export type ExecutionLease = z.infer<typeof ExecutionLeaseSchema>
