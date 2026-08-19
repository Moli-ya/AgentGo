import { z } from 'zod'
import { SystemIssuedOpaqueIdSchema } from './inventory'
import { TargetScopeSchema } from './security'
import {
  ScanBudgetSchema,
  ScanControlActionSchema,
  ScanPhaseSchema,
  ScanStatusSchema,
  VerdictSchema
} from './workflow'
import {
  DefinitionIdSchema,
  EvidenceRoleSchema,
  ModuleVersionSchema,
  VulnerabilityFamilySchema,
  VulnerabilityTechniqueIdSchema
} from './vulnerability'

const IdSchema = z.string().min(1).max(200)
const IsoDateSchema = z.string().datetime()

const TARGET_BASE_SECRET_PATTERN =
  /(?:day\d*[-_ ]*)?sentinel(?:[-_ ]*(?:secret|token|password|credential))?|must[-_ ]?not[-_ ]?leak|do[-_ ]?not[-_ ]?store|super[-_ ]?secret/iu
const TARGET_BASE_JWT_PATTERN =
  /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u
const TARGET_BASE_TOKEN_PREFIX_PATTERN =
  /^(?:sk|pk|api|key|token|secret|ghp|github_pat|xox[baprs])[-_]/iu
const TARGET_BASE_SENSITIVE_QUERY_NAME_PATTERN =
  /(?:authorization|cookie|password|passwd|secret|token|api[-_.]?key|credential|csrf|xsrf|session)/iu

interface ParsedTargetBaseUrl {
  readonly protocol: string
  readonly origin: string
  readonly username: string
  readonly password: string
  readonly search: string
  readonly hash: string
  readonly hostname: string
  readonly pathname: string
  readonly searchParams: {
    entries(): IterableIterator<[string, string]>
  }
  toString(): string
}

const TargetBaseUrl = (globalThis as unknown as {
  URL: new (value: string) => ParsedTargetBaseUrl
}).URL

function targetBaseEntropy(value: string): number {
  const counts = new Map<string, number>()
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1)
  }
  let entropy = 0
  for (const count of counts.values()) {
    const probability = count / value.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

function isTargetBaseSecretShaped(value: string): boolean {
  const candidate = value.trim()
  if (!candidate) return false
  if (TARGET_BASE_SECRET_PATTERN.test(candidate)) return true
  if (TARGET_BASE_JWT_PATTERN.test(candidate)) return true
  if (TARGET_BASE_TOKEN_PREFIX_PATTERN.test(candidate) && candidate.length >= 16) {
    return true
  }
  if (
    candidate.length < 20 ||
    /\s/u.test(candidate) ||
    !/^[A-Za-z0-9._~+\/-]+={0,2}$/u.test(candidate)
  ) {
    return false
  }
  const uniqueRatio = new Set(candidate).size / candidate.length
  const minimumEntropy = /^[a-f0-9-]+$/iu.test(candidate) ? 3.2 : 3.6
  return uniqueRatio >= 0.25 && targetBaseEntropy(candidate) >= minimumEntropy
}

/** A target is an HTTP(S) seed URL, never a credential-bearing request URL. */
export const TargetBaseUrlSchema = z
  .string()
  .url()
  .max(16_384)
  .superRefine((value, context) => {
    let url: ParsedTargetBaseUrl
    try {
      url = new TargetBaseUrl(value)
    } catch {
      context.addIssue({
        code: 'custom',
        message: 'Target Base URL must be a valid absolute URL.'
      })
      return
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      context.addIssue({
        code: 'custom',
        message: 'Target Base URL must use HTTP or HTTPS.'
      })
    }
    if (url.username || url.password) {
      context.addIssue({
        code: 'custom',
        message: 'Target Base URL cannot contain userinfo or credentials.'
      })
    }
    if (url.hash) {
      context.addIssue({
        code: 'custom',
        message: 'Target Base URL cannot contain a fragment.'
      })
    }
    if (url.toString().length > 16_384) {
      context.addIssue({
        code: 'custom',
        message: 'Normalized Target Base URL is too long.'
      })
    }
    const encodedStructuralValues = [
      ...url.hostname.split('.'),
      ...url.pathname.split('/')
    ]
    if (
      TARGET_BASE_JWT_PATTERN.test(url.hostname) ||
      TARGET_BASE_SECRET_PATTERN.test(url.hostname) ||
      encodedStructuralValues.some((encoded) => {
        try {
          return isTargetBaseSecretShaped(decodeURIComponent(encoded))
        } catch {
          return true
        }
      })
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Target Base URL cannot contain credential-shaped host or path values.'
      })
    }
    if (
      [...url.searchParams.entries()].some(
        ([name, queryValue]) =>
          TARGET_BASE_SENSITIVE_QUERY_NAME_PATTERN.test(name) ||
          isTargetBaseSecretShaped(name) ||
          isTargetBaseSecretShaped(queryValue)
      )
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Target Base URL query cannot contain credential-shaped names or values.'
      })
    }
  })

export const AgentModelProfileSelectionSchema = z.object({
  planner: IdSchema.optional(),
  knowledge: IdSchema.optional(),
  strategy: IdSchema.optional(),
  analysis: IdSchema.optional(),
  verifier: IdSchema.optional()
})

export type AgentModelProfileSelection = z.infer<typeof AgentModelProfileSelectionSchema>

export const WorkspaceSchema = z.object({
  id: IdSchema,
  name: z.string().min(1).max(120),
  description: z.string().max(1_000).default(''),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})

export type WorkspaceRecord = z.infer<typeof WorkspaceSchema>

export const CreateWorkspaceInputSchema = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(1_000).default('')
})

export type CreateWorkspaceInput = z.infer<typeof CreateWorkspaceInputSchema>

export const TargetSchema = z.object({
  id: IdSchema,
  workspaceId: IdSchema,
  name: z.string().min(1).max(160),
  baseUrl: TargetBaseUrlSchema,
  description: z.string().max(2_000).default(''),
  authorizationReference: z.string().max(500).default(''),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})

export type TargetRecord = z.infer<typeof TargetSchema>

export const CreateTargetInputSchema = z.object({
  workspaceId: IdSchema,
  name: z.string().trim().min(1).max(160),
  baseUrl: TargetBaseUrlSchema,
  description: z.string().trim().max(2_000).default(''),
  authorizationReference: z.string().trim().min(1).max(500),
  scope: TargetScopeSchema.omit({ id: true })
})

export type CreateTargetInput = z.infer<typeof CreateTargetInputSchema>

export const UpdateTargetInputSchema = CreateTargetInputSchema.omit({
  workspaceId: true
}).partial().extend({
  id: IdSchema
})

export type UpdateTargetInput = z.infer<typeof UpdateTargetInputSchema>

export const TargetScopeRecordSchema = TargetScopeSchema.extend({
  targetId: IdSchema,
  revision: z.number().int().positive(),
  snapshotHash: z.string().min(1),
  createdAt: IsoDateSchema
})

export type TargetScopeRecord = z.infer<typeof TargetScopeRecordSchema>

export const IdentityAuthTypeSchema = z.enum([
  'none',
  'header',
  'bearer',
  'cookie',
  'basic'
])

export type IdentityAuthType = z.infer<typeof IdentityAuthTypeSchema>

export const IdentitySchema = z.object({
  id: IdSchema,
  targetId: IdSchema,
  label: z.string().min(1).max(120),
  role: z.string().min(1).max(120),
  authType: IdentityAuthTypeSchema,
  headerName: z.string().max(120).optional(),
  credentialId: IdSchema.optional(),
  isTestIdentity: z.boolean(),
  ownedResourceIds: z.array(z.string().trim().min(1).max(500)).default([]),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})

export type IdentityRecord = z.infer<typeof IdentitySchema>

export const TargetDetailSchema = z.object({
  target: TargetSchema,
  scope: TargetScopeRecordSchema,
  identities: z.array(IdentitySchema)
})

export type TargetDetail = z.infer<typeof TargetDetailSchema>

export const SaveIdentityInputSchema = z.object({
  id: IdSchema.optional(),
  targetId: IdSchema,
  label: z.string().trim().min(1).max(120),
  role: z.string().trim().min(1).max(120),
  authType: IdentityAuthTypeSchema,
  headerName: z.string().trim().min(1).max(120).optional(),
  secret: z.string().min(1).max(16_384).optional(),
  isTestIdentity: z.boolean().default(true),
  ownedResourceIds: z.array(z.string().trim().min(1).max(500)).max(100).default([])
}).superRefine((value, context) => {
  if (value.authType !== 'none' && !value.secret && !value.id) {
    context.addIssue({
      code: 'custom',
      message: '非匿名身份必须提供凭据。',
      path: ['secret']
    })
  }

  if (value.authType === 'header' && !value.headerName) {
    context.addIssue({
      code: 'custom',
      message: '自定义 Header 身份必须提供 Header 名称。',
      path: ['headerName']
    })
  }
})

export type SaveIdentityInput = z.infer<typeof SaveIdentityInputSchema>

export const ScanSchema = z.object({
  id: IdSchema,
  targetId: IdSchema,
  targetName: z.string().min(1),
  name: z.string().min(1).max(160),
  description: z.string().max(4_000),
  scopeSnapshotId: IdSchema,
  status: ScanStatusSchema,
  phase: ScanPhaseSchema,
  progress: z.number().int().min(0).max(100),
  families: z.array(VulnerabilityFamilySchema).min(1),
  modelProfileIds: AgentModelProfileSelectionSchema,
  budget: ScanBudgetSchema,
  requestCount: z.number().int().nonnegative(),
  modelTokens: z.number().int().nonnegative(),
  estimatedCost: z.number().nonnegative(),
  checkpointCount: z.number().int().nonnegative(),
  lastError: z.string().optional(),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema,
  startedAt: IsoDateSchema.optional(),
  completedAt: IsoDateSchema.optional()
})

export type ScanRecord = z.infer<typeof ScanSchema>

export const CreateScanInputSchema = z.strictObject({
  targetId: IdSchema,
  name: z.string().trim().min(1).max(160),
  description: z.string().trim().min(1).max(4_000),
  families: z.array(VulnerabilityFamilySchema).min(1).optional(),
  identityIds: z.array(IdSchema).default([]),
  callbackUrl: z.string().url().optional(),
  modelProfileIds: AgentModelProfileSelectionSchema.optional(),
  budget: ScanBudgetSchema
})

export type CreateScanInput = z.infer<typeof CreateScanInputSchema>

export const ControlScanInputSchema = z.object({
  scanId: IdSchema,
  action: ScanControlActionSchema
})

export type ControlScanInput = z.infer<typeof ControlScanInputSchema>

export const InventoryParameterSchema = z.object({
  id: IdSchema,
  name: z.string(),
  location: z.enum(['query', 'path', 'header', 'cookie', 'form', 'json']),
  dataType: z.string().optional(),
  required: z.boolean()
})

export const InventoryEndpointSchema = z.object({
  id: IdSchema,
  method: z.string(),
  url: z.string().url(),
  contentType: z.string().optional(),
  source: z.string(),
  parameters: z.array(InventoryParameterSchema)
})

export type InventoryEndpoint = z.infer<typeof InventoryEndpointSchema>

export const ScanEventSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  type: z.enum([
    'status',
    'phase',
    'agent',
    'policy',
    'execution',
    'evidence',
    'finding',
    'error'
  ]),
  level: z.enum(['info', 'warning', 'error']),
  message: z.string(),
  detail: z.record(z.string(), z.unknown()).default({}),
  createdAt: IsoDateSchema
})

export type ScanEvent = z.infer<typeof ScanEventSchema>

export const EVIDENCE_SOURCE_HASH_DOMAIN =
  'agentgo.evidence-source.v1' as const
export const OOB_TOKEN_COMMITMENT_DOMAIN =
  'agentgo.oob-token-commitment.v1' as const
export const PROTECTED_EVIDENCE_ARTIFACT_SCHEMA_VERSION =
  'protected-evidence-artifact.v1' as const
export const PROTECTED_EVIDENCE_PROTECTION_SCHEME =
  'os-wrapped-aes-256-gcm.v1' as const
export const PROTECTED_EVIDENCE_ACCESS_POLICY_ID =
  'backend-only-protected-evidence' as const
export const PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID =
  'metadata-only-redacted-derivative' as const
export const PROTECTED_EVIDENCE_POLICY_VERSION = '1.0.0' as const
export const MAX_PROTECTED_EVIDENCE_RETENTION_SECONDS =
  30 * 24 * 60 * 60

export const EvidenceCaptureSourceSchema = z.enum([
  'http-request-summary',
  'http-response-summary',
  'browser-request-summary',
  'browser-result-summary',
  'execution-interruption-summary',
  'http-response-body',
  'dom-snapshot',
  'browser-screenshot',
  'oob-event'
])

export type EvidenceCaptureSource = z.infer<
  typeof EvidenceCaptureSourceSchema
>

export const EvidenceCaptureExecutionStateSchema = z.enum([
  'succeeded',
  'failed',
  'cancelled',
  'timed-out',
  'interrupted'
])

export type EvidenceCaptureExecutionState = z.infer<
  typeof EvidenceCaptureExecutionStateSchema
>

export const EvidenceCaptureActionSchema = z.enum([
  'persist-minimized',
  'hash-only',
  'discard',
  'protected-original'
])

export type EvidenceCaptureAction = z.infer<
  typeof EvidenceCaptureActionSchema
>

export const EvidenceCaptureOutcomeSchema = z.enum([
  'captured',
  'hash-only',
  'discarded',
  'unsupported'
])

export type EvidenceCaptureOutcome = z.infer<
  typeof EvidenceCaptureOutcomeSchema
>

export const EvidenceCaptureReasonSchema = z.enum([
  'allowlisted-json-selection',
  'allowlisted-oob-metadata',
  'decision-hash-only',
  'decision-discard',
  'unstructured-text-source',
  'partial-source',
  'oversize-source',
  'empty-source',
  'compressed-source',
  'non-utf8-source',
  'xml-source',
  'binary-source',
  'json-parse-failed',
  'json-selection-failed',
  'protected-original-authorized',
  'protected-original-unsupported',
  'oob-commitment-unavailable'
])

export type EvidenceCaptureReason = z.infer<
  typeof EvidenceCaptureReasonSchema
>

export const EvidenceSourceHashSchema = z
  .strictObject({
    domain: z.literal(EVIDENCE_SOURCE_HASH_DOMAIN),
    algorithm: z.literal('sha256'),
    digest: z.string().regex(/^[a-f0-9]{64}$/u),
    basis: z.enum(['source-bytes', 'selected-oob-metadata']),
    coverage: z.enum(['complete', 'partial']),
    hashedBytes: z.number().int().nonnegative(),
    knownTotalBytes: z.number().int().nonnegative().optional()
  })
  .superRefine((hash, context) => {
    if (
      hash.coverage === 'complete' &&
      hash.knownTotalBytes !== undefined &&
      hash.hashedBytes !== hash.knownTotalBytes
    ) {
      context.addIssue({
        code: 'custom',
        message: 'A complete evidence hash must cover the known total byte length.',
        path: ['knownTotalBytes']
      })
    }
    if (
      hash.coverage === 'partial' &&
      hash.knownTotalBytes !== undefined &&
      hash.hashedBytes >= hash.knownTotalBytes
    ) {
      context.addIssue({
        code: 'custom',
        message: 'A partial evidence hash must cover fewer bytes than the known total byte length.',
        path: ['knownTotalBytes']
      })
    }
  })
  .readonly()

export type EvidenceSourceHash = z.infer<typeof EvidenceSourceHashSchema>

export const OobCaptureMetadataFieldSchema = z.enum([
  'channel',
  'eventType',
  'receivedAt',
  'requestMethod',
  'dnsRecordType',
  'statusCode'
])

export type OobCaptureMetadataField = z.infer<
  typeof OobCaptureMetadataFieldSchema
>

export const OobCaptureMetadataSchema = z
  .strictObject({
    channel: z.enum(['dns', 'http', 'smtp', 'other']).optional(),
    eventType: z
      .enum([
        'dns-query',
        'http-request',
        'smtp-message',
        'callback-observed'
      ])
      .optional(),
    receivedAt: IsoDateSchema.optional(),
    requestMethod: z
      .enum([
        'GET',
        'HEAD',
        'POST',
        'PUT',
        'PATCH',
        'DELETE',
        'OPTIONS',
        'OTHER'
      ])
      .optional(),
    dnsRecordType: z
      .enum([
        'A',
        'AAAA',
        'CNAME',
        'TXT',
        'MX',
        'NS',
        'PTR',
        'SRV',
        'HTTPS',
        'SVCB',
        'OTHER'
      ])
      .optional(),
    statusCode: z.number().int().min(100).max(599).optional()
  })
  .readonly()

export type OobCaptureMetadata = z.infer<
  typeof OobCaptureMetadataSchema
>

export const OobTokenCommitmentSchema = z
  .strictObject({
    domain: z.literal(OOB_TOKEN_COMMITMENT_DOMAIN),
    algorithm: z.literal('hmac-sha256'),
    keyRef: SystemIssuedOpaqueIdSchema,
    keyVersion: z.number().int().nonnegative(),
    captureDecisionId: SystemIssuedOpaqueIdSchema,
    capturePolicyId: DefinitionIdSchema,
    capturePolicyVersion: ModuleVersionSchema,
    selectedMetadata: OobCaptureMetadataSchema,
    sourceHash: EvidenceSourceHashSchema,
    digest: z.string().regex(/^[a-f0-9]{64}$/u)
  })
  .superRefine((commitment, context) => {
    if (
      commitment.sourceHash.basis !== 'selected-oob-metadata' ||
      commitment.sourceHash.coverage !== 'partial' ||
      commitment.sourceHash.knownTotalBytes !== undefined
    ) {
      context.addIssue({
        code: 'custom',
        message: 'An OOB token commitment requires a partial OOB metadata source hash.',
        path: ['sourceHash']
      })
    }
  })
  .readonly()

export type OobTokenCommitment = z.infer<
  typeof OobTokenCommitmentSchema
>

export const EvidenceResponseDescriptorSchema = z
  .strictObject({
    mediaType: z
      .string()
      .regex(/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u),
    charset: z.enum(['utf-8', 'non-utf-8', 'unknown', 'not-applicable']),
    contentEncoding: z.enum(['identity', 'compressed', 'unknown']),
    declaredSizeBytes: z.number().int().nonnegative().optional()
  })
  .readonly()

export type EvidenceResponseDescriptor = z.infer<
  typeof EvidenceResponseDescriptorSchema
>

export const ProtectedEvidencePlanSchema = z
  .strictObject({
    protectionScheme: z.literal(PROTECTED_EVIDENCE_PROTECTION_SCHEME),
    accessPolicyId: z.literal(PROTECTED_EVIDENCE_ACCESS_POLICY_ID),
    accessPolicyVersion: z.literal(PROTECTED_EVIDENCE_POLICY_VERSION),
    derivativePolicyId: z.literal(PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID),
    derivativePolicyVersion: z.literal(PROTECTED_EVIDENCE_POLICY_VERSION),
    retentionSeconds: z
      .number()
      .int()
      .positive()
      .max(MAX_PROTECTED_EVIDENCE_RETENTION_SECONDS),
    maxScanPlaintextBytes: z
      .number()
      .int()
      .positive()
      .max(1_073_741_824),
    maxWorkspacePlaintextBytes: z
      .number()
      .int()
      .positive()
      .max(1_073_741_824)
  })
  .superRefine((plan, context) => {
    if (plan.maxScanPlaintextBytes > plan.maxWorkspacePlaintextBytes) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected Evidence scan quota must not exceed its workspace quota.',
        path: ['maxScanPlaintextBytes']
      })
    }
  })
  .readonly()

export type ProtectedEvidencePlan = z.infer<
  typeof ProtectedEvidencePlanSchema
>

const EvidenceCaptureContextFields = {
  scanId: SystemIssuedOpaqueIdSchema,
  policyDecisionId: SystemIssuedOpaqueIdSchema,
  techniqueId: VulnerabilityTechniqueIdSchema,
  techniqueVersion: ModuleVersionSchema,
  stepId: DefinitionIdSchema,
  executionState: EvidenceCaptureExecutionStateSchema,
  role: EvidenceRoleSchema,
  occurredAt: IsoDateSchema
} as const

export const EvidenceCaptureContextSchema = z.discriminatedUnion('source', [
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('http-request-summary'),
      content: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('http-response-summary'),
      content: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('browser-request-summary'),
      content: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('execution-interruption-summary'),
      content: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('browser-result-summary'),
      content: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('http-response-body'),
      response: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('dom-snapshot'),
      response: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('browser-screenshot'),
      response: EvidenceResponseDescriptorSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceCaptureContextFields,
      source: z.literal('oob-event')
    })
    .readonly()
])

export type EvidenceCaptureContext = z.infer<
  typeof EvidenceCaptureContextSchema
>

const JsonCapturePointerSchema = z
  .string()
  .min(1)
  .max(2_048)
  .regex(/^(?:\/(?:[^~/\u0000-\u001f\u007f]|~[01])*)+$/u)
  .refine(
    (value) => value === value.normalize('NFC'),
    'Evidence JSON pointers must use Unicode NFC normalization.'
  )

function addDuplicateCaptureSelectionIssues(
  values: readonly string[],
  context: z.RefinementCtx,
  label: string
): void {
  const seen = new Set<string>()
  for (const [index, value] of values.entries()) {
    if (seen.has(value)) {
      context.addIssue({
        code: 'custom',
        message: `Duplicate ${label}.`,
        path: [index]
      })
    }
    seen.add(value)
  }
}

export const EvidenceCaptureDecisionSchema = z
  .strictObject({
    id: SystemIssuedOpaqueIdSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    policyDecisionId: SystemIssuedOpaqueIdSchema,
    capturePolicyId: DefinitionIdSchema,
    capturePolicyVersion: ModuleVersionSchema,
    techniqueId: VulnerabilityTechniqueIdSchema,
    techniqueVersion: ModuleVersionSchema,
    stepId: DefinitionIdSchema,
    executionState: EvidenceCaptureExecutionStateSchema,
    source: EvidenceCaptureSourceSchema,
    role: EvidenceRoleSchema,
    action: EvidenceCaptureActionSchema,
    validFrom: IsoDateSchema,
    validUntil: IsoDateSchema,
    maxSourceBytes: z.number().int().positive().max(16_777_216),
    maxExcerptBytes: z.number().int().min(32).max(65_536),
    jsonPointers: z.array(JsonCapturePointerSchema).max(128).readonly(),
    oobMetadataFields: z
      .array(OobCaptureMetadataFieldSchema)
      .max(6)
      .readonly(),
    oobCommitmentKeyRef: SystemIssuedOpaqueIdSchema.optional(),
    oobCommitmentKeyVersion: z.number().int().nonnegative().optional(),
    protectedOriginalPlan: ProtectedEvidencePlanSchema.optional()
  })
  .superRefine((decision, context) => {
    if (Date.parse(decision.validFrom) > Date.parse(decision.validUntil)) {
      context.addIssue({
        code: 'custom',
        message: 'Evidence capture validity start must not be after its end.',
        path: ['validUntil']
      })
    }
    if (decision.maxExcerptBytes > decision.maxSourceBytes) {
      context.addIssue({
        code: 'custom',
        message: 'Evidence excerpt limit must not exceed the source limit.',
        path: ['maxExcerptBytes']
      })
    }
    addDuplicateCaptureSelectionIssues(
      decision.jsonPointers,
      context,
      'evidence JSON pointer'
    )
    addDuplicateCaptureSelectionIssues(
      decision.oobMetadataFields,
      context,
      'OOB metadata field'
    )
    if (
      decision.source !== 'oob-event' &&
      decision.oobMetadataFields.length > 0
    ) {
      context.addIssue({
        code: 'custom',
        message: 'OOB metadata fields are valid only for OOB evidence.',
        path: ['oobMetadataFields']
      })
    }
    if (
      decision.source !== 'http-response-body' &&
      decision.jsonPointers.length > 0
    ) {
      context.addIssue({
        code: 'custom',
        message: 'JSON pointers are valid only for HTTP response body evidence.',
        path: ['jsonPointers']
      })
    }
    const requiresOobCommitment =
      decision.source === 'oob-event' &&
      (decision.action === 'persist-minimized' ||
        decision.action === 'hash-only')
    if (requiresOobCommitment) {
      if (decision.oobCommitmentKeyRef === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'OOB capture must bind an opaque commitment key reference.',
          path: ['oobCommitmentKeyRef']
        })
      }
      if (decision.oobCommitmentKeyVersion === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'OOB capture must bind a commitment key version.',
          path: ['oobCommitmentKeyVersion']
        })
      }
    } else if (
      decision.oobCommitmentKeyRef !== undefined ||
      decision.oobCommitmentKeyVersion !== undefined
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'OOB commitment keys are valid only when an OOB token commitment will be persisted.',
        path: ['oobCommitmentKeyRef']
      })
    }
    const protectsOriginal = decision.action === 'protected-original'
    if (protectsOriginal !== (decision.protectedOriginalPlan !== undefined)) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original decisions must bind exactly one protected Evidence plan.',
        path: ['protectedOriginalPlan']
      })
    }
    if (
      protectsOriginal &&
      ![
        'http-response-body',
        'dom-snapshot',
        'browser-screenshot'
      ].includes(decision.source)
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original capture is limited to response body, DOM, or screenshot bytes.',
        path: ['source']
      })
    }
    if (
      protectsOriginal &&
      (decision.jsonPointers.length > 0 ||
        decision.oobMetadataFields.length > 0)
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original capture cannot also select minimized JSON or OOB fields.',
        path: ['action']
      })
    }
    if (
      decision.protectedOriginalPlan !== undefined &&
      (decision.maxSourceBytes >
        decision.protectedOriginalPlan.maxScanPlaintextBytes ||
        decision.maxSourceBytes >
          decision.protectedOriginalPlan.maxWorkspacePlaintextBytes)
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original source limit must fit within scan and workspace quotas.',
        path: ['maxSourceBytes']
      })
    }
  })
  .readonly()

export type EvidenceCaptureDecision = z.infer<
  typeof EvidenceCaptureDecisionSchema
>

export type ProtectedOriginalEvidenceCaptureDecision = Omit<
  EvidenceCaptureDecision,
  | 'action'
  | 'oobCommitmentKeyRef'
  | 'oobCommitmentKeyVersion'
  | 'protectedOriginalPlan'
  | 'source'
> & {
  readonly action: 'protected-original'
  readonly source:
    | 'http-response-body'
    | 'dom-snapshot'
    | 'browser-screenshot'
  readonly protectedOriginalPlan: ProtectedEvidencePlan
  readonly oobCommitmentKeyRef?: never
  readonly oobCommitmentKeyVersion?: never
}

export type ProtectedOriginalEvidenceCaptureContext = Extract<
  EvidenceCaptureContext,
  {
    source:
      | 'http-response-body'
      | 'dom-snapshot'
      | 'browser-screenshot'
  }
>

export const EvidenceHashOnlyReasonSchema = z.enum([
  'decision-hash-only',
  'unstructured-text-source',
  'partial-source',
  'oversize-source',
  'empty-source',
  'compressed-source',
  'non-utf8-source',
  'xml-source',
  'binary-source',
  'json-parse-failed',
  'json-selection-failed'
])

export type EvidenceHashOnlyReason = z.infer<
  typeof EvidenceHashOnlyReasonSchema
>

const EvidenceArtifactSchemaVersion = z.literal(
  'evidence-capture-artifact.v1'
)

const EvidenceJsonSelectionValueSchema = z.union([
  z.null(),
  z.boolean(),
  z.number().finite(),
  z.literal('[REDACTED]')
])

const EvidenceJsonSelectionSchema = z
  .strictObject({
    pointer: JsonCapturePointerSchema,
    value: EvidenceJsonSelectionValueSchema
  })
  .readonly()

export const EvidenceJsonSelectionPayloadSchema = z
  .strictObject({
    schemaVersion: EvidenceArtifactSchemaVersion,
    kind: z.literal('allowlisted-json-selection'),
    selections: z
      .array(EvidenceJsonSelectionSchema)
      .min(1)
      .max(128)
      .superRefine((selections, context) => {
        addDuplicateCaptureSelectionIssues(
          selections.map(({ pointer }) => pointer),
          context,
          'evidence JSON selection'
        )
        for (let index = 1; index < selections.length; index += 1) {
          const previous = selections[index - 1]
          const current = selections[index]
          if (
            previous !== undefined &&
            current !== undefined &&
            previous.pointer > current.pointer
          ) {
            context.addIssue({
              code: 'custom',
              message: 'Evidence JSON selections must use canonical pointer order.',
              path: [index, 'pointer']
            })
          }
        }
      })
      .readonly(),
    sourceHash: EvidenceSourceHashSchema
  })
  .readonly()

export type EvidenceJsonSelectionPayload = z.infer<
  typeof EvidenceJsonSelectionPayloadSchema
>

export const EvidenceOobMetadataPayloadSchema = z
  .strictObject({
    schemaVersion: EvidenceArtifactSchemaVersion,
    kind: z.literal('allowlisted-oob-metadata'),
    metadata: OobCaptureMetadataSchema,
    tokenCommitment: OobTokenCommitmentSchema,
    sourceHash: EvidenceSourceHashSchema
  })
  .superRefine((payload, context) => {
    if (
      !evidenceSourceHashesEqual(
        payload.tokenCommitment.sourceHash,
        payload.sourceHash
      )
    ) {
      context.addIssue({
        code: 'custom',
        message: 'OOB payload commitment must bind its payload source hash.',
        path: ['tokenCommitment', 'sourceHash']
      })
    }
    if (
      !oobCaptureMetadataEqual(
        payload.metadata,
        payload.tokenCommitment.selectedMetadata
      )
    ) {
      context.addIssue({
        code: 'custom',
        message: 'OOB payload metadata must match its committed metadata.',
        path: ['metadata']
      })
    }
  })
  .readonly()

export type EvidenceOobMetadataPayload = z.infer<
  typeof EvidenceOobMetadataPayloadSchema
>

export const EvidenceHashOnlyPayloadSchema = z
  .strictObject({
    schemaVersion: EvidenceArtifactSchemaVersion,
    kind: z.literal('hash-only'),
    reason: EvidenceHashOnlyReasonSchema,
    sourceHash: EvidenceSourceHashSchema,
    tokenCommitment: OobTokenCommitmentSchema.optional()
  })
  .superRefine((payload, context) => {
    if (
      payload.tokenCommitment !== undefined &&
      !evidenceSourceHashesEqual(
        payload.tokenCommitment.sourceHash,
        payload.sourceHash
      )
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Hash-only commitment must bind its payload source hash.',
        path: ['tokenCommitment', 'sourceHash']
      })
    }
  })
  .readonly()

export type EvidenceHashOnlyPayload = z.infer<
  typeof EvidenceHashOnlyPayloadSchema
>

export const EvidenceProtectedOriginalPayloadSchema = z
  .strictObject({
    schemaVersion: z.literal(PROTECTED_EVIDENCE_ARTIFACT_SCHEMA_VERSION),
    kind: z.literal('protected-original-persistence-plan'),
    originalMimeType: z
      .string()
      .regex(/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u),
    plaintextSize: z.number().int().positive().max(16_777_216),
    retentionUntil: IsoDateSchema,
    protectionPlan: ProtectedEvidencePlanSchema,
    sourceHash: EvidenceSourceHashSchema,
    captureContext: EvidenceCaptureContextSchema,
    captureDecision: EvidenceCaptureDecisionSchema
  })
  .superRefine((payload, context) => {
    if (
      payload.sourceHash.basis !== 'source-bytes' ||
      payload.sourceHash.coverage !== 'complete' ||
      payload.sourceHash.knownTotalBytes !== payload.plaintextSize ||
      payload.sourceHash.hashedBytes !== payload.plaintextSize
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original persistence requires a complete plaintext source hash.',
        path: ['sourceHash']
      })
    }
    const captureContext = payload.captureContext
    const captureDecision = payload.captureDecision
    if (
      captureDecision.action !== 'protected-original' ||
      captureDecision.protectedOriginalPlan === undefined
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original persistence must carry an authorized protected capture decision.',
        path: ['captureDecision', 'action']
      })
      return
    }
    if (
      captureContext.source !== 'http-response-body' &&
      captureContext.source !== 'dom-snapshot' &&
      captureContext.source !== 'browser-screenshot'
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original persistence requires a byte-backed response, DOM, or screenshot context.',
        path: ['captureContext', 'source']
      })
      return
    }
    if (
      captureContext.scanId !== captureDecision.scanId ||
      captureContext.policyDecisionId !==
        captureDecision.policyDecisionId ||
      captureContext.techniqueId !== captureDecision.techniqueId ||
      captureContext.techniqueVersion !==
        captureDecision.techniqueVersion ||
      captureContext.stepId !== captureDecision.stepId ||
      captureContext.executionState !==
        captureDecision.executionState ||
      captureContext.source !== captureDecision.source ||
      captureContext.role !== captureDecision.role ||
      Date.parse(captureContext.occurredAt) <
        Date.parse(captureDecision.validFrom) ||
      Date.parse(captureContext.occurredAt) >
        Date.parse(captureDecision.validUntil)
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original capture context must exactly match its authorized decision and validity window.',
        path: ['captureDecision']
      })
    }
    if (
      !protectedEvidencePlansEqual(
        payload.protectionPlan,
        captureDecision.protectedOriginalPlan
      )
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original persistence plan must exactly match its capture decision.',
        path: ['protectionPlan']
      })
    }
    const responseDescriptor = captureContext.response
    if (payload.originalMimeType !== responseDescriptor.mediaType) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original MIME type must match the authorized source descriptor.',
        path: ['originalMimeType']
      })
    }
    if (payload.plaintextSize > captureDecision.maxSourceBytes) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original plaintext size exceeds its authorized source limit.',
        path: ['plaintextSize']
      })
    }
    const expectedRetentionUntil = new Date(
      Date.parse(captureContext.occurredAt) +
        payload.protectionPlan.retentionSeconds * 1_000
    ).toISOString()
    if (payload.retentionUntil !== expectedRetentionUntil) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original retention must be derived from the capture occurrence and authorized duration.',
        path: ['retentionUntil']
      })
    }
  })
  .readonly()

export type EvidenceProtectedOriginalPayload = z.infer<
  typeof EvidenceProtectedOriginalPayloadSchema
>

const EvidenceArtifactBindingFields = {
  role: EvidenceRoleSchema,
  captureDecisionId: SystemIssuedOpaqueIdSchema,
  capturePolicyId: DefinitionIdSchema,
  capturePolicyVersion: ModuleVersionSchema,
  sourceHash: EvidenceSourceHashSchema
} as const

export const EvidenceArtifactDraftSchema = z.discriminatedUnion('type', [
  z
    .strictObject({
      ...EvidenceArtifactBindingFields,
      type: z.literal('evidence-capture-json-selection'),
      mimeType: z.literal('application/json'),
      source: z.literal('http-response-body'),
      redactionState: z.literal('redacted'),
      payload: EvidenceJsonSelectionPayloadSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceArtifactBindingFields,
      type: z.literal('evidence-capture-oob-metadata'),
      mimeType: z.literal('application/json'),
      source: z.literal('oob-event'),
      redactionState: z.literal('redacted'),
      payload: EvidenceOobMetadataPayloadSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceArtifactBindingFields,
      type: z.literal('evidence-capture-hash-only'),
      mimeType: z.literal('application/json'),
      source: EvidenceCaptureSourceSchema,
      redactionState: z.literal('redacted'),
      payload: EvidenceHashOnlyPayloadSchema
    })
    .readonly(),
  z
    .strictObject({
      ...EvidenceArtifactBindingFields,
      type: z.literal('evidence-capture-protected-original'),
      mimeType: z.literal('application/vnd.agentgo.protected-evidence'),
      source: z.enum([
        'http-response-body',
        'dom-snapshot',
        'browser-screenshot'
      ]),
      redactionState: z.literal('original'),
      scanId: SystemIssuedOpaqueIdSchema,
      policyDecisionId: SystemIssuedOpaqueIdSchema,
      techniqueId: VulnerabilityTechniqueIdSchema,
      techniqueVersion: ModuleVersionSchema,
      stepId: DefinitionIdSchema,
      payload: EvidenceProtectedOriginalPayloadSchema
    })
    .readonly()
]).superRefine((artifact, context) => {
  if (
    !evidenceSourceHashesEqual(
      artifact.sourceHash,
      artifact.payload.sourceHash
    )
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Evidence artifact payload must bind its outer source hash.',
      path: ['payload', 'sourceHash']
    })
  }
  const tokenCommitment =
    artifact.type === 'evidence-capture-oob-metadata'
      ? artifact.payload.tokenCommitment
      : artifact.type === 'evidence-capture-hash-only'
        ? artifact.payload.tokenCommitment
        : undefined
  if (
    (artifact.source === 'oob-event') !==
    (tokenCommitment !== undefined)
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Only OOB evidence artifacts may carry an OOB token commitment.',
      path: ['payload', 'tokenCommitment']
    })
  }
  if (
    tokenCommitment !== undefined &&
    (tokenCommitment.captureDecisionId !== artifact.captureDecisionId ||
      tokenCommitment.capturePolicyId !== artifact.capturePolicyId ||
      tokenCommitment.capturePolicyVersion !== artifact.capturePolicyVersion ||
      !evidenceSourceHashesEqual(
        tokenCommitment.sourceHash,
        artifact.sourceHash
      ))
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Evidence artifact commitment must match its capture binding.',
      path: ['payload', 'tokenCommitment']
    })
  }
  if (artifact.type === 'evidence-capture-protected-original') {
    const captureContext = artifact.payload.captureContext
    const captureDecision = artifact.payload.captureDecision
    if (
      artifact.scanId !== captureContext.scanId ||
      artifact.policyDecisionId !== captureContext.policyDecisionId ||
      artifact.techniqueId !== captureContext.techniqueId ||
      artifact.techniqueVersion !== captureContext.techniqueVersion ||
      artifact.stepId !== captureContext.stepId ||
      artifact.source !== captureContext.source ||
      artifact.role !== captureContext.role ||
      artifact.captureDecisionId !== captureDecision.id ||
      artifact.capturePolicyId !== captureDecision.capturePolicyId ||
      artifact.capturePolicyVersion !==
        captureDecision.capturePolicyVersion
    ) {
      context.addIssue({
        code: 'custom',
        message:
          'Protected-original artifact must exactly bind its capture context and decision.',
        path: ['payload']
      })
    }
  }
})

export type EvidenceArtifactDraft = z.infer<
  typeof EvidenceArtifactDraftSchema
>

function evidenceSourceHashesEqual(
  left: EvidenceSourceHash,
  right: EvidenceSourceHash
): boolean {
  return (
    left.domain === right.domain &&
    left.algorithm === right.algorithm &&
    left.digest === right.digest &&
    left.basis === right.basis &&
    left.coverage === right.coverage &&
    left.hashedBytes === right.hashedBytes &&
    left.knownTotalBytes === right.knownTotalBytes
  )
}

function protectedEvidencePlansEqual(
  left: ProtectedEvidencePlan,
  right: ProtectedEvidencePlan
): boolean {
  return (
    left.protectionScheme === right.protectionScheme &&
    left.accessPolicyId === right.accessPolicyId &&
    left.accessPolicyVersion === right.accessPolicyVersion &&
    left.derivativePolicyId === right.derivativePolicyId &&
    left.derivativePolicyVersion === right.derivativePolicyVersion &&
    left.retentionSeconds === right.retentionSeconds &&
    left.maxScanPlaintextBytes === right.maxScanPlaintextBytes &&
    left.maxWorkspacePlaintextBytes === right.maxWorkspacePlaintextBytes
  )
}

function oobCaptureMetadataEqual(
  left: OobCaptureMetadata,
  right: OobCaptureMetadata
): boolean {
  return (
    left.channel === right.channel &&
    left.eventType === right.eventType &&
    left.receivedAt === right.receivedAt &&
    left.requestMethod === right.requestMethod &&
    left.dnsRecordType === right.dnsRecordType &&
    left.statusCode === right.statusCode
  )
}

function oobTokenCommitmentsEqual(
  left: OobTokenCommitment,
  right: OobTokenCommitment
): boolean {
  return (
    left.domain === right.domain &&
    left.algorithm === right.algorithm &&
    left.keyRef === right.keyRef &&
    left.keyVersion === right.keyVersion &&
    left.captureDecisionId === right.captureDecisionId &&
    left.capturePolicyId === right.capturePolicyId &&
    left.capturePolicyVersion === right.capturePolicyVersion &&
    oobCaptureMetadataEqual(
      left.selectedMetadata,
      right.selectedMetadata
    ) &&
    evidenceSourceHashesEqual(left.sourceHash, right.sourceHash) &&
    left.digest === right.digest
  )
}

export const EvidenceCaptureResultSchema = z
  .strictObject({
    state: EvidenceCaptureOutcomeSchema,
    reason: EvidenceCaptureReasonSchema,
    role: EvidenceRoleSchema,
    source: EvidenceCaptureSourceSchema,
    captureDecisionId: SystemIssuedOpaqueIdSchema,
    capturePolicyId: DefinitionIdSchema,
    capturePolicyVersion: ModuleVersionSchema,
    sourceHash: EvidenceSourceHashSchema,
    tokenCommitment: OobTokenCommitmentSchema.optional(),
    artifacts: z.array(EvidenceArtifactDraftSchema).max(1).readonly()
  })
  .superRefine((result, context) => {
    const mustPersistOne =
      result.state === 'captured' || result.state === 'hash-only'
    const reasonMatchesState =
      (result.state === 'captured' &&
        (result.reason === 'allowlisted-json-selection' ||
          result.reason === 'allowlisted-oob-metadata' ||
          result.reason === 'protected-original-authorized')) ||
      (result.state === 'hash-only' &&
        EvidenceHashOnlyReasonSchema.safeParse(result.reason).success) ||
      (result.state === 'discarded' &&
        result.reason === 'decision-discard') ||
      (result.state === 'unsupported' &&
        (result.reason === 'protected-original-unsupported' ||
          result.reason === 'oob-commitment-unavailable'))
    if (!reasonMatchesState) {
      context.addIssue({
        code: 'custom',
        message: 'Evidence capture reason must match its outcome state.',
        path: ['reason']
      })
    }
    if (mustPersistOne && result.artifacts.length !== 1) {
      context.addIssue({
        code: 'custom',
        message: 'Captured and hash-only results must contain exactly one artifact draft.',
        path: ['artifacts']
      })
    }
    if (!mustPersistOne && result.artifacts.length !== 0) {
      context.addIssue({
        code: 'custom',
        message: 'Discarded or unsupported capture cannot produce persistence drafts.',
        path: ['artifacts']
      })
    }
    const mustPersistOobCommitment =
      result.source === 'oob-event' && mustPersistOne
    if (
      !mustPersistOobCommitment &&
      result.tokenCommitment !== undefined
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Token commitments are valid only for persisted OOB evidence.',
        path: ['tokenCommitment']
      })
    }
    if (mustPersistOobCommitment && result.tokenCommitment === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Persisted OOB evidence must include its keyed token commitment.',
        path: ['tokenCommitment']
      })
    }
    if (
      result.source === 'oob-event'
        ? result.sourceHash.basis !== 'selected-oob-metadata' ||
          result.sourceHash.coverage !== 'partial' ||
          result.sourceHash.knownTotalBytes !== undefined
        : result.sourceHash.basis !== 'source-bytes'
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Evidence source hash semantics must match the evidence source.',
        path: ['sourceHash']
      })
    }
    if (
      result.reason === 'allowlisted-json-selection' &&
      result.source !== 'http-response-body'
    ) {
      context.addIssue({
        code: 'custom',
        message: 'JSON selections are valid only for HTTP response body evidence.',
        path: ['source']
      })
    }
    if (
      (result.reason === 'allowlisted-oob-metadata' ||
        result.reason === 'oob-commitment-unavailable') &&
      result.source !== 'oob-event'
    ) {
      context.addIssue({
        code: 'custom',
        message: 'The OOB capture outcome requires an OOB evidence source.',
        path: ['source']
      })
    }
    if (
      result.source === 'oob-event' &&
      result.state === 'hash-only' &&
      result.reason !== 'decision-hash-only'
    ) {
      context.addIssue({
        code: 'custom',
        message: 'OOB hash-only evidence requires an explicit hash-only decision.',
        path: ['reason']
      })
    }
    if (result.tokenCommitment) {
      if (
        result.tokenCommitment.captureDecisionId !==
          result.captureDecisionId ||
        result.tokenCommitment.capturePolicyId !== result.capturePolicyId ||
        result.tokenCommitment.capturePolicyVersion !==
          result.capturePolicyVersion ||
        !evidenceSourceHashesEqual(
          result.tokenCommitment.sourceHash,
          result.sourceHash
        )
      ) {
        context.addIssue({
          code: 'custom',
          message: 'OOB token commitment must match the capture and source hash binding.',
          path: ['tokenCommitment']
        })
      }
    }
    const artifact = result.artifacts[0]
    if (artifact) {
      if (
        artifact.role !== result.role ||
        artifact.source !== result.source ||
        artifact.captureDecisionId !== result.captureDecisionId ||
        artifact.capturePolicyId !== result.capturePolicyId ||
        artifact.capturePolicyVersion !== result.capturePolicyVersion ||
        !evidenceSourceHashesEqual(
          artifact.sourceHash,
          result.sourceHash
        ) ||
        !evidenceSourceHashesEqual(
          artifact.payload.sourceHash,
          result.sourceHash
        )
      ) {
        context.addIssue({
          code: 'custom',
          message: 'Evidence artifact binding must exactly match its capture result.',
          path: ['artifacts', 0]
        })
      }
      const artifactTypeMatches =
        (result.state === 'hash-only' &&
          artifact.type === 'evidence-capture-hash-only') ||
        (result.state === 'captured' &&
          result.reason === 'allowlisted-json-selection' &&
          artifact.type === 'evidence-capture-json-selection') ||
        (result.state === 'captured' &&
          result.reason === 'allowlisted-oob-metadata' &&
          artifact.type === 'evidence-capture-oob-metadata') ||
        (result.state === 'captured' &&
          result.reason === 'protected-original-authorized' &&
          artifact.type === 'evidence-capture-protected-original')
      if (!artifactTypeMatches) {
        context.addIssue({
          code: 'custom',
          message: 'Evidence artifact type must match the capture outcome.',
          path: ['artifacts', 0, 'type']
        })
      }
      if (
        artifact.type === 'evidence-capture-hash-only' &&
        (artifact.payload.reason !== result.reason ||
          (result.tokenCommitment === undefined) !==
            (artifact.payload.tokenCommitment === undefined) ||
          (result.tokenCommitment !== undefined &&
            artifact.payload.tokenCommitment !== undefined &&
            !oobTokenCommitmentsEqual(
              result.tokenCommitment,
              artifact.payload.tokenCommitment
            )))
      ) {
        context.addIssue({
          code: 'custom',
          message: 'Hash-only evidence payload must match its result binding.',
          path: ['artifacts', 0, 'payload']
        })
      }
      if (
        artifact.type === 'evidence-capture-oob-metadata' &&
        (result.tokenCommitment === undefined ||
          !oobTokenCommitmentsEqual(
            result.tokenCommitment,
            artifact.payload.tokenCommitment
          ) ||
          !oobCaptureMetadataEqual(
            artifact.payload.metadata,
            result.tokenCommitment.selectedMetadata
          ))
      ) {
        context.addIssue({
          code: 'custom',
          message: 'OOB evidence payload must match its result commitment.',
          path: ['artifacts', 0, 'payload', 'tokenCommitment']
        })
      }
      if (
        artifact.type === 'evidence-capture-protected-original' &&
        (artifact.scanId === undefined ||
          artifact.policyDecisionId === undefined ||
          artifact.sourceHash.coverage !== 'complete')
      ) {
        context.addIssue({
          code: 'custom',
          message:
            'Protected-original Evidence must preserve its complete execution binding.',
          path: ['artifacts', 0]
        })
      }
    }
  })
  .readonly()

export type EvidenceCaptureResult = z.infer<
  typeof EvidenceCaptureResultSchema
>

const EvidenceSummaryFields = {
  id: IdSchema,
  scanId: IdSchema,
  type: z.string(),
  mimeType: z.string(),
  sha256: z.string(),
  size: z.number().int().nonnegative(),
  integrityStatus: z.string(),
  createdAt: IsoDateSchema
} as const

export const EvidenceSummarySchema = z.discriminatedUnion(
  'protectionState',
  [
    z.strictObject({
      ...EvidenceSummaryFields,
      redactionState: z.literal('redacted'),
      protectionState: z.literal('unprotected'),
      derivedFrom: IdSchema.optional(),
      retentionUntil: IsoDateSchema.optional()
    }),
    z.strictObject({
      ...EvidenceSummaryFields,
      redactionState: z.literal('original'),
      protectionState: z.literal('protected-original'),
      availabilityState: z.enum(['available', 'expired']),
      retentionUntil: IsoDateSchema
    })
  ]
)

export type EvidenceSummary = z.infer<typeof EvidenceSummarySchema>

export const FindingSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  family: VulnerabilityFamilySchema,
  title: z.string().min(1),
  verdict: VerdictSchema,
  status: z.enum(['draft', 'reviewed', 'exported']),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  confidence: z.number().min(0).max(1),
  endpointUrl: z.string().url().optional(),
  parameterName: z.string().optional(),
  identityLabel: z.string().optional(),
  cwe: z.string().optional(),
  owasp: z.string().optional(),
  evidenceRefs: z.array(IdSchema),
  confirmationRuleId: IdSchema,
  confirmationRuleVersion: z.string().min(1),
  reproducibility: z.string(),
  remediation: z.array(z.string()),
  firstSeenAt: IsoDateSchema,
  lastVerifiedAt: IsoDateSchema
})

export type FindingRecord = z.infer<typeof FindingSchema>

export const KnowledgeSearchInputSchema = z.object({
  query: z.string().trim().max(500).default(''),
  families: z.array(VulnerabilityFamilySchema).default([]),
  limit: z.number().int().positive().max(100).default(20)
})

export type KnowledgeSearchInput = z.infer<typeof KnowledgeSearchInputSchema>

export const KnowledgeEntrySummarySchema = z.object({
  id: IdSchema,
  version: z.string(),
  family: VulnerabilityFamilySchema.optional(),
  title: z.string(),
  applicability: z.array(z.string()),
  confirmationRules: z.array(z.string()),
  remediationHints: z.array(z.string()),
  sourceTitles: z.array(z.string()),
  vendor: z.string().optional(),
  product: z.string().optional(),
  sourceType: z.string().optional()
})

export type KnowledgeEntrySummary = z.infer<typeof KnowledgeEntrySummarySchema>

export const KnowledgeSourceTypeSchema = z.enum([
  'vendor-advisory',
  'public-poc',
  'research',
  'repository',
  'other'
])
export type KnowledgeSourceType = z.infer<typeof KnowledgeSourceTypeSchema>

export const KnowledgeImportStatusSchema = z.enum([
  'draft',
  'extracting',
  'needs-review',
  'ready-for-review',
  'published',
  'rejected',
  'failed'
])
export type KnowledgeImportStatus = z.infer<typeof KnowledgeImportStatusSchema>

export const KnowledgeHttpRequestTemplateSchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']),
  pathTemplate: z.string().trim().min(1).max(2_048),
  contentType: z.string().trim().max(200).optional(),
  queryParameters: z.array(z.string().trim().min(1).max(200)).max(100).default([]),
  headersTemplate: z.record(
    z.string().trim().min(1).max(200),
    z.string().max(4_096)
  ).default({}),
  bodyTemplate: z.string().max(100_000).optional(),
  controllableFields: z.array(z.string().trim().min(1).max(500)).max(100).default([]),
  riskFlags: z.array(z.string().trim().min(1).max(500)).max(100).default([]),
  unsafeToExecute: z.literal(true).default(true)
})
export type KnowledgeHttpRequestTemplate = z.infer<typeof KnowledgeHttpRequestTemplateSchema>

export const KnowledgeFieldEvidenceSchema = z.object({
  field: z.string().trim().min(1).max(300),
  quote: z.string().trim().min(1).max(2_000),
  confidence: z.number().min(0).max(1)
})
export type KnowledgeFieldEvidence = z.infer<typeof KnowledgeFieldEvidenceSchema>

export const KnowledgeIntelligenceCandidateSchema = z.object({
  schemaVersion: z.literal('vulnerability-intel.v1'),
  title: z.string().trim().min(1).max(500),
  vendor: z.string().trim().min(1).max(300),
  product: z.string().trim().min(1).max(300),
  vulnerabilityType: z.string().trim().min(1).max(300),
  family: VulnerabilityFamilySchema.optional(),
  identifiers: z.object({
    cve: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/i)).max(100).default([]),
    cwe: z.array(z.string().regex(/^CWE-\d+$/i)).max(100).default([]),
    other: z.array(z.string().trim().min(1).max(300)).max(100).default([])
  }),
  affectedVersions: z.array(z.string().trim().min(1).max(500)).max(200).default([]),
  preconditions: z.array(z.string().trim().min(1).max(1_000)).max(100).default([]),
  affectedEndpoints: z.array(KnowledgeHttpRequestTemplateSchema).max(50).default([]),
  signals: z.array(z.string().trim().min(1).max(1_000)).max(100).default([]),
  confirmationRules: z.array(z.string().trim().min(1).max(1_000)).max(100).default([]),
  remediation: z.array(z.string().trim().min(1).max(1_000)).max(100).default([]),
  forbiddenActions: z.array(z.string().trim().min(1).max(1_000)).max(100).default([]),
  fieldEvidence: z.array(KnowledgeFieldEvidenceSchema).max(300).default([]),
  extractionConfidence: z.number().min(0).max(1)
})
export type KnowledgeIntelligenceCandidate = z.infer<typeof KnowledgeIntelligenceCandidateSchema>

export const KnowledgeReviewIssueSchema = z.object({
  severity: z.enum(['info', 'warning', 'error']),
  field: z.string().trim().min(1).max(300),
  message: z.string().trim().min(1).max(1_000)
})
export type KnowledgeReviewIssue = z.infer<typeof KnowledgeReviewIssueSchema>

export const KnowledgeAgentRunSchema = z.object({
  id: IdSchema,
  importId: IdSchema,
  parentRunId: IdSchema.optional(),
  role: z.enum(['intelligence-extractor', 'intelligence-reviewer']),
  promptId: z.string().min(1),
  promptVersion: z.string().min(1),
  modelProfileId: IdSchema,
  provider: z.string().optional(),
  model: z.string().optional(),
  status: z.enum(['running', 'completed', 'failed']),
  promptTokens: z.number().int().nonnegative(),
  completionTokens: z.number().int().nonnegative(),
  durationMs: z.number().int().nonnegative(),
  error: z.string().optional(),
  startedAt: IsoDateSchema,
  finishedAt: IsoDateSchema.optional()
})
export type KnowledgeAgentRunRecord = z.infer<typeof KnowledgeAgentRunSchema>

export const KnowledgeImportSummarySchema = z.object({
  id: IdSchema,
  documentId: IdSchema,
  sourceType: KnowledgeSourceTypeSchema,
  title: z.string().min(1),
  sourceUrl: z.string().optional(),
  author: z.string().optional(),
  license: z.string().optional(),
  status: KnowledgeImportStatusSchema,
  instructionFlags: z.array(z.string()),
  rawContentSha256: z.string().length(64),
  sourceExcerpt: z.string(),
  extractorProfileId: IdSchema.optional(),
  reviewerProfileId: IdSchema.optional(),
  reviewIssues: z.array(KnowledgeReviewIssueSchema),
  candidate: KnowledgeIntelligenceCandidateSchema.optional(),
  lastError: z.string().optional(),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})
export type KnowledgeImportSummary = z.infer<typeof KnowledgeImportSummarySchema>

export const KnowledgeImportDetailSchema = KnowledgeImportSummarySchema.extend({
  rawContent: z.string(),
  runs: z.array(KnowledgeAgentRunSchema)
})
export type KnowledgeImportDetail = z.infer<typeof KnowledgeImportDetailSchema>

export const CreateKnowledgeImportInputSchema = z.object({
  sourceType: KnowledgeSourceTypeSchema,
  title: z.string().trim().min(1).max(500),
  sourceUrl: z.string().trim().max(4_096).optional(),
  author: z.string().trim().max(300).optional(),
  license: z.string().trim().max(300).optional(),
  rawContent: z.string().min(1).max(1_000_000),
  vendorHint: z.string().trim().max(300).optional(),
  productHint: z.string().trim().max(300).optional()
})
export type CreateKnowledgeImportInput = z.infer<typeof CreateKnowledgeImportInputSchema>

export const ExtractKnowledgeImportInputSchema = z.object({
  id: IdSchema,
  extractorProfileId: IdSchema,
  reviewerProfileId: IdSchema
})
export type ExtractKnowledgeImportInput = z.infer<typeof ExtractKnowledgeImportInputSchema>

export const UpdateKnowledgeCandidateInputSchema = z.object({
  id: IdSchema,
  candidate: KnowledgeIntelligenceCandidateSchema
})
export type UpdateKnowledgeCandidateInput = z.infer<typeof UpdateKnowledgeCandidateInputSchema>

export const ReviewKnowledgeImportInputSchema = z.object({
  id: IdSchema,
  action: z.enum(['publish', 'reject', 'reopen'])
})
export type ReviewKnowledgeImportInput = z.infer<typeof ReviewKnowledgeImportInputSchema>

export const ModelProfileSchema = z.object({
  id: IdSchema,
  name: z.string().min(1).max(120),
  agentRole: z.enum(['planner', 'knowledge', 'strategy', 'analysis', 'verifier']),
  provider: z.enum(['deterministic', 'openai-compatible']),
  baseUrl: z.string().url().optional(),
  model: z.string().min(1),
  credentialId: IdSchema.optional(),
  timeoutMs: z.number().int().positive().max(120_000),
  rpmLimit: z.number().int().positive().max(10_000),
  tpmLimit: z.number().int().positive().max(10_000_000),
  tokenBudget: z.number().int().positive(),
  costBudget: z.number().nonnegative(),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})

export type ModelProfileRecord = z.infer<typeof ModelProfileSchema>

export const SaveModelProfileInputSchema = ModelProfileSchema.omit({
  id: true,
  credentialId: true,
  createdAt: true,
  updatedAt: true
}).extend({
  id: IdSchema.optional(),
  costBudget: z.number().nonnegative().default(0),
  apiKey: z.string().min(1).max(16_384).optional()
}).superRefine((value, context) => {
  if (value.provider === 'openai-compatible' && !value.baseUrl) {
    context.addIssue({
      code: 'custom',
      message: 'OpenAI-compatible Profile 必须提供 Base URL。',
      path: ['baseUrl']
    })
  }
  if (value.provider === 'openai-compatible' && !value.id && !value.apiKey) {
    context.addIssue({
      code: 'custom',
      message: '新建 OpenAI-compatible Profile 必须提供 API Key。',
      path: ['apiKey']
    })
  }
})

export type SaveModelProfileInput = z.infer<typeof SaveModelProfileInputSchema>

export const ModelProfileUsageSchema = z.object({
  profileId: IdSchema,
  invocationCount: z.number().int().nonnegative(),
  promptTokens: z.number().int().nonnegative(),
  completionTokens: z.number().int().nonnegative(),
  totalTokens: z.number().int().nonnegative(),
  lastUsedAt: IsoDateSchema.optional()
})

export type ModelProfileUsageRecord = z.infer<typeof ModelProfileUsageSchema>

export const McpTransportSchema = z.enum(['stdio', 'streamable-http'])
export type McpTransport = z.infer<typeof McpTransportSchema>

export const McpAuthTypeSchema = z.enum(['none', 'bearer', 'header'])
export type McpAuthType = z.infer<typeof McpAuthTypeSchema>

export const McpRiskLabelSchema = z.enum([
  'file-access',
  'command-execution',
  'network-access'
])
export type McpRiskLabel = z.infer<typeof McpRiskLabelSchema>

export const McpServerStatusSchema = z.enum([
  'disabled',
  'untested',
  'ready',
  'error'
])
export type McpServerStatus = z.infer<typeof McpServerStatusSchema>

export const McpToolSummarySchema = z.object({
  name: z.string().min(1).max(300),
  description: z.string().max(2_000).optional()
})
export type McpToolSummary = z.infer<typeof McpToolSummarySchema>

export const McpResourceSummarySchema = z.object({
  uri: z.string().min(1).max(4_000),
  name: z.string().max(300).optional()
})
export type McpResourceSummary = z.infer<typeof McpResourceSummarySchema>

export const McpPromptSummarySchema = z.object({
  name: z.string().min(1).max(300),
  description: z.string().max(2_000).optional()
})
export type McpPromptSummary = z.infer<typeof McpPromptSummarySchema>

export const McpServerSchema = z.object({
  id: IdSchema,
  name: z.string().min(1).max(120),
  transport: McpTransportSchema,
  enabled: z.boolean(),
  command: z.string().max(2_048).optional(),
  args: z.array(z.string().max(4_096)).max(128),
  cwd: z.string().max(2_048).optional(),
  url: z.string().url().optional(),
  authType: McpAuthTypeSchema,
  authHeaderName: z.string().max(200).optional(),
  credentialId: IdSchema.optional(),
  environmentKeys: z.array(z.string().max(200)).max(256),
  headerNames: z.array(z.string().max(200)).max(256),
  timeoutMs: z.number().int().min(1_000).max(120_000),
  roots: z.array(z.string().max(2_048)).max(64),
  allowedAgentRoles: z.array(z.enum([
    'planner',
    'knowledge',
    'strategy',
    'analysis',
    'verifier'
  ])).max(5),
  riskLabels: z.array(McpRiskLabelSchema).max(3),
  status: McpServerStatusSchema,
  protocolVersion: z.string().max(100).optional(),
  serverName: z.string().max(300).optional(),
  serverVersion: z.string().max(100).optional(),
  tools: z.array(McpToolSummarySchema).max(500),
  resources: z.array(McpResourceSummarySchema).max(500),
  prompts: z.array(McpPromptSummarySchema).max(500),
  lastTestedAt: IsoDateSchema.optional(),
  lastError: z.string().max(4_000).optional(),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})

export type McpServerRecord = z.infer<typeof McpServerSchema>

const McpEnvironmentSchema = z.record(
  z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).max(200),
  z.string().max(16_384)
)

const McpHeadersSchema = z.record(
  z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/).max(200),
  z.string().max(16_384)
)

export const SaveMcpServerInputSchema = z.object({
  id: IdSchema.optional(),
  name: z.string().trim().min(1).max(120),
  transport: McpTransportSchema,
  enabled: z.boolean().default(false),
  command: z.string().trim().max(2_048).optional(),
  args: z.array(z.string().max(4_096)).max(128).default([]),
  cwd: z.string().trim().max(2_048).optional(),
  url: z.string().url().optional(),
  authType: McpAuthTypeSchema.default('none'),
  authHeaderName: z.string().trim().max(200).optional(),
  token: z.string().min(1).max(16_384).optional(),
  environment: McpEnvironmentSchema.optional(),
  headers: McpHeadersSchema.optional(),
  timeoutMs: z.number().int().min(1_000).max(120_000).default(15_000),
  roots: z.array(z.string().trim().min(1).max(2_048)).max(64).default([]),
  allowedAgentRoles: z.array(z.enum([
    'planner',
    'knowledge',
    'strategy',
    'analysis',
    'verifier'
  ])).max(5).default([]),
  riskLabels: z.array(McpRiskLabelSchema).max(3).default([])
}).superRefine((value, context) => {
  if (value.transport === 'stdio' && !value.command) {
    context.addIssue({
      code: 'custom',
      message: '本地 STDIO MCP Server 必须提供启动命令。',
      path: ['command']
    })
  }
  if (value.transport === 'streamable-http') {
    if (!value.url || !/^https?:\/\//i.test(value.url)) {
      context.addIssue({
        code: 'custom',
        message: '远程 MCP Server 必须提供 HTTP 或 HTTPS URL。',
        path: ['url']
      })
    }
    if (value.authType === 'header' && !value.authHeaderName) {
      context.addIssue({
        code: 'custom',
        message: '自定义 Header 鉴权必须提供 Header 名称。',
        path: ['authHeaderName']
      })
    }
    if (value.authType !== 'none' && !value.id && !value.token) {
      context.addIssue({
        code: 'custom',
        message: '启用远程 MCP 鉴权时必须提供 Token。',
        path: ['token']
      })
    }
  }
})

export type SaveMcpServerInput = z.infer<typeof SaveMcpServerInputSchema>

export const McpConnectionTestResultSchema = z.object({
  ok: z.boolean(),
  message: z.string().min(1),
  durationMs: z.number().nonnegative(),
  protocolVersion: z.string().max(100).optional(),
  serverName: z.string().max(300).optional(),
  serverVersion: z.string().max(100).optional(),
  tools: z.array(McpToolSummarySchema).max(500),
  resources: z.array(McpResourceSummarySchema).max(500),
  prompts: z.array(McpPromptSummarySchema).max(500)
})

export type McpConnectionTestResult = z.infer<typeof McpConnectionTestResultSchema>

export const ReportSchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  title: z.string(),
  format: z.enum(['markdown', 'json', 'html']),
  filePath: z.string().optional(),
  sha256: z.string(),
  redacted: z.boolean(),
  createdAt: IsoDateSchema
})

export type ReportRecord = z.infer<typeof ReportSchema>

export const GenerateReportInputSchema = z.object({
  scanId: IdSchema,
  format: z.enum(['markdown', 'json', 'html']).default('markdown'),
  redacted: z.literal(true).default(true)
})

export type GenerateReportInput = z.infer<typeof GenerateReportInputSchema>

export const ExportReportInputSchema = z.object({
  reportId: IdSchema
})

export type ExportReportInput = z.infer<typeof ExportReportInputSchema>

export const AuditLogSchema = z.object({
  id: IdSchema,
  workspaceId: IdSchema,
  scanId: IdSchema.optional(),
  event: z.string(),
  actor: z.string(),
  detail: z.record(z.string(), z.unknown()),
  createdAt: IsoDateSchema
})

export type AuditLogRecord = z.infer<typeof AuditLogSchema>

export const DashboardSnapshotSchema = z.object({
  workspaceCount: z.number().int().nonnegative(),
  targetCount: z.number().int().nonnegative(),
  activeScanCount: z.number().int().nonnegative(),
  confirmedFindingCount: z.number().int().nonnegative(),
  recentScans: z.array(ScanSchema),
  recentFindings: z.array(FindingSchema)
})

export type DashboardSnapshot = z.infer<typeof DashboardSnapshotSchema>

export const ScanDetailSchema = z.object({
  scan: ScanSchema,
  target: TargetSchema,
  scope: TargetScopeRecordSchema,
  identities: z.array(IdentitySchema),
  endpoints: z.array(InventoryEndpointSchema),
  events: z.array(ScanEventSchema),
  evidence: z.array(EvidenceSummarySchema),
  findings: z.array(FindingSchema)
})

export type ScanDetail = z.infer<typeof ScanDetailSchema>

export const DeleteByIdInputSchema = z.object({ id: IdSchema })
export const OptionalWorkspaceFilterSchema = z.object({
  workspaceId: IdSchema.optional()
})
export const WorkspaceFilterSchema = z.object({ workspaceId: IdSchema })
export const TargetFilterSchema = z.object({ targetId: IdSchema })
export const ScanFilterSchema = z.object({ scanId: IdSchema })
export const ReportFilterSchema = z.object({ scanId: IdSchema })
export const ModelProfileFilterSchema = z.object({ id: IdSchema })
export const McpServerFilterSchema = z.object({ id: IdSchema })
export const FindingFilterSchema = z.object({
  workspaceId: IdSchema.optional(),
  scanId: IdSchema.optional(),
  verdict: VerdictSchema.optional(),
  family: VulnerabilityFamilySchema.optional()
})
export const AuditFilterSchema = z.object({
  workspaceId: IdSchema,
  scanId: IdSchema.optional(),
  limit: z.number().int().positive().max(500).default(100)
})
