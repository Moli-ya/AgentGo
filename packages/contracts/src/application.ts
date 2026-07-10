import { z } from 'zod'
import { TargetScopeSchema } from './security'
import {
  ScanBudgetSchema,
  ScanControlActionSchema,
  ScanPhaseSchema,
  ScanStatusSchema,
  VerdictSchema,
  VulnerabilityFamilySchema
} from './workflow'

const IdSchema = z.string().min(1).max(200)
const IsoDateSchema = z.string().datetime()

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
  baseUrl: z.string().url(),
  description: z.string().max(2_000).default(''),
  authorizationReference: z.string().max(500).default(''),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})

export type TargetRecord = z.infer<typeof TargetSchema>

export const CreateTargetInputSchema = z.object({
  workspaceId: IdSchema,
  name: z.string().trim().min(1).max(160),
  baseUrl: z.string().url(),
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

export const CreateScanInputSchema = z.object({
  targetId: IdSchema,
  name: z.string().trim().min(1).max(160),
  description: z.string().trim().min(1).max(4_000),
  families: z.array(VulnerabilityFamilySchema).min(1).default([
    'sqli',
    'xss',
    'ssrf',
    'idor'
  ]),
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
  family: VulnerabilityFamilySchema,
  title: z.string(),
  applicability: z.array(z.string()),
  confirmationRules: z.array(z.string()),
  remediationHints: z.array(z.string()),
  sourceTitles: z.array(z.string())
})

export type KnowledgeEntrySummary = z.infer<typeof KnowledgeEntrySummarySchema>

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
