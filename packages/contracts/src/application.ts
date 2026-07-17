import { z } from 'zod'
import { TargetScopeSchema } from './security'
import {
  ScanBudgetSchema,
  ScanControlActionSchema,
  ScanPhaseSchema,
  ScanStatusSchema,
  VerdictSchema
} from './workflow'
import { VulnerabilityFamilySchema } from './vulnerability'

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
    const url = new TargetBaseUrl(value)
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

export const EvidenceSummarySchema = z.object({
  id: IdSchema,
  scanId: IdSchema,
  type: z.string(),
  mimeType: z.string(),
  sha256: z.string(),
  size: z.number().int().nonnegative(),
  redactionState: z.string(),
  integrityStatus: z.string(),
  createdAt: IsoDateSchema
})

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
  redacted: z.boolean().default(true)
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
