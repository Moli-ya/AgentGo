import { z } from 'zod'
import {
  AuditLogSchema,
  DashboardSnapshotSchema,
  FindingSchema,
  IdentitySchema,
  KnowledgeEntrySummarySchema,
  KnowledgeImportDetailSchema,
  KnowledgeImportSummarySchema,
  McpConnectionTestResultSchema,
  McpServerSchema,
  ModelProfileSchema,
  ModelProfileUsageSchema,
  ReportSchema,
  ScanDetailSchema,
  ScanEventSchema,
  ScanSchema,
  TargetDetailSchema,
  TargetSchema,
  WorkspaceSchema
} from './application'
import type {
  AuditLogRecord,
  CreateKnowledgeImportInput,
  CreateScanInput,
  CreateTargetInput,
  CreateWorkspaceInput,
  DashboardSnapshot,
  ExportReportInput,
  FindingRecord,
  GenerateReportInput,
  IdentityRecord,
  KnowledgeEntrySummary,
  KnowledgeImportDetail,
  KnowledgeImportSummary,
  KnowledgeSearchInput,
  McpConnectionTestResult,
  McpServerRecord,
  ModelProfileRecord,
  ModelProfileUsageRecord,
  ReportRecord,
  ReviewKnowledgeImportInput,
  SaveIdentityInput,
  SaveMcpServerInput,
  SaveModelProfileInput,
  ScanDetail,
  ScanEvent,
  ScanRecord,
  TargetDetail,
  TargetRecord,
  ExtractKnowledgeImportInput,
  UpdateKnowledgeCandidateInput,
  UpdateTargetInput,
  WorkspaceRecord
} from './application'
import { PolicyDecisionSchema } from './security'
import {
  AgentRoleSchema,
  ScanPhaseSchema,
  VulnerabilityFamilySchema,
  type ScanControlAction,
  type VulnerabilityFamily
} from './workflow'

export const BootstrapStateSchema = z.object({
  appVersion: z.string().min(1),
  milestone: z.string().min(1),
  projectStatus: z.string().min(1),
  dataDirectory: z.string(),
  databaseReady: z.boolean(),
  agents: z.array(AgentRoleSchema),
  phases: z.array(ScanPhaseSchema),
  vulnerabilityFamilies: z.array(VulnerabilityFamilySchema),
  safeguards: z.array(z.string().min(1))
})

export type BootstrapState = z.infer<typeof BootstrapStateSchema>

export const PolicySelfCheckResultSchema = z.object({
  safeProbe: PolicyDecisionSchema,
  destructiveProbe: PolicyDecisionSchema,
  note: z.string().min(1)
})

export type PolicySelfCheckResult = z.infer<typeof PolicySelfCheckResultSchema>

export const DeleteResultSchema = z.object({ deleted: z.boolean() })

export type DeleteResult = z.infer<typeof DeleteResultSchema>

export const ConnectionTestResultSchema = z.object({
  ok: z.boolean(),
  message: z.string().min(1),
  provider: z.string().min(1).optional(),
  model: z.string().min(1).optional(),
  promptTokens: z.number().int().nonnegative().optional(),
  completionTokens: z.number().int().nonnegative().optional(),
  totalTokens: z.number().int().nonnegative().optional(),
  durationMs: z.number().nonnegative().optional()
})

export type ConnectionTestResult = z.infer<typeof ConnectionTestResultSchema>

export const ExportReportResultSchema = z.object({
  exported: z.boolean(),
  filePath: z.string().min(1).optional()
})

export type ExportReportResult = z.infer<typeof ExportReportResultSchema>

export const WorkspaceListSchema = z.array(WorkspaceSchema)
export const TargetListSchema = z.array(TargetSchema)
export const ScanListSchema = z.array(ScanSchema)
export const KnowledgeEntrySummaryListSchema = z.array(KnowledgeEntrySummarySchema)
export const KnowledgeImportSummaryListSchema = z.array(KnowledgeImportSummarySchema)
export const FindingListSchema = z.array(FindingSchema)
export const ReportListSchema = z.array(ReportSchema)
export const ModelProfileListSchema = z.array(ModelProfileSchema)
export const ModelProfileUsageListSchema = z.array(ModelProfileUsageSchema)
export const McpServerListSchema = z.array(McpServerSchema)
export const AuditLogListSchema = z.array(AuditLogSchema)

export const DesktopOutputSchemas = {
  bootstrapState: BootstrapStateSchema,
  policySelfCheck: PolicySelfCheckResultSchema,
  dashboard: DashboardSnapshotSchema,
  workspace: WorkspaceSchema,
  workspaces: WorkspaceListSchema,
  target: TargetSchema,
  targets: TargetListSchema,
  targetDetail: TargetDetailSchema,
  identity: IdentitySchema,
  scan: ScanSchema,
  scans: ScanListSchema,
  scanDetail: ScanDetailSchema,
  scanEvent: ScanEventSchema,
  knowledgeEntries: KnowledgeEntrySummaryListSchema,
  knowledgeImport: KnowledgeImportDetailSchema,
  knowledgeImports: KnowledgeImportSummaryListSchema,
  findings: FindingListSchema,
  report: ReportSchema,
  reports: ReportListSchema,
  modelProfile: ModelProfileSchema,
  modelProfiles: ModelProfileListSchema,
  modelProfileUsage: ModelProfileUsageListSchema,
  mcpServer: McpServerSchema,
  mcpServers: McpServerListSchema,
  mcpConnectionTest: McpConnectionTestResultSchema,
  auditLogs: AuditLogListSchema,
  deleteResult: DeleteResultSchema,
  connectionTest: ConnectionTestResultSchema,
  exportReport: ExportReportResultSchema
} as const

export interface AgentGoDesktopApi {
  getBootstrapState: () => Promise<BootstrapState>
  runPolicySelfCheck: () => Promise<PolicySelfCheckResult>
  getDashboard: (workspaceId?: string) => Promise<DashboardSnapshot>

  listWorkspaces: () => Promise<WorkspaceRecord[]>
  createWorkspace: (input: CreateWorkspaceInput) => Promise<WorkspaceRecord>
  deleteWorkspace: (id: string) => Promise<DeleteResult>

  listTargets: (workspaceId: string) => Promise<TargetRecord[]>
  getTargetDetail: (targetId: string) => Promise<TargetDetail>
  createTarget: (input: CreateTargetInput) => Promise<TargetDetail>
  updateTarget: (input: UpdateTargetInput) => Promise<TargetDetail>
  deleteTarget: (id: string) => Promise<DeleteResult>

  saveIdentity: (input: SaveIdentityInput) => Promise<IdentityRecord>
  deleteIdentity: (id: string) => Promise<DeleteResult>

  listScans: (workspaceId?: string) => Promise<ScanRecord[]>
  createScan: (input: CreateScanInput) => Promise<ScanRecord>
  controlScan: (scanId: string, action: ScanControlAction) => Promise<ScanRecord>
  getScanDetail: (scanId: string) => Promise<ScanDetail>
  onScanEvent: (listener: (event: ScanEvent) => void) => () => void

  searchKnowledge: (input: KnowledgeSearchInput) => Promise<KnowledgeEntrySummary[]>
  listKnowledgeImports: () => Promise<KnowledgeImportSummary[]>
  getKnowledgeImport: (id: string) => Promise<KnowledgeImportDetail>
  createKnowledgeImport: (input: CreateKnowledgeImportInput) => Promise<KnowledgeImportDetail>
  extractKnowledgeImport: (input: ExtractKnowledgeImportInput) => Promise<KnowledgeImportDetail>
  updateKnowledgeCandidate: (input: UpdateKnowledgeCandidateInput) => Promise<KnowledgeImportDetail>
  reviewKnowledgeImport: (input: ReviewKnowledgeImportInput) => Promise<KnowledgeImportDetail>
  deleteKnowledgeImport: (id: string) => Promise<DeleteResult>
  listFindings: (input?: {
    workspaceId?: string
    scanId?: string
    verdict?: 'confirmed' | 'not-confirmed' | 'inconclusive'
    family?: VulnerabilityFamily
  }) => Promise<FindingRecord[]>

  listReports: (scanId: string) => Promise<ReportRecord[]>
  generateReport: (input: GenerateReportInput) => Promise<ReportRecord>
  exportReport: (input: ExportReportInput) => Promise<ExportReportResult>

  listModelProfiles: () => Promise<ModelProfileRecord[]>
  listModelProfileUsage: () => Promise<ModelProfileUsageRecord[]>
  saveModelProfile: (input: SaveModelProfileInput) => Promise<ModelProfileRecord>
  deleteModelProfile: (id: string) => Promise<DeleteResult>
  testModelProfile: (id: string) => Promise<ConnectionTestResult>

  listMcpServers: () => Promise<McpServerRecord[]>
  saveMcpServer: (input: SaveMcpServerInput) => Promise<McpServerRecord>
  deleteMcpServer: (id: string) => Promise<DeleteResult>
  testMcpServer: (id: string) => Promise<McpConnectionTestResult>

  listAuditLogs: (workspaceId: string, scanId?: string) => Promise<AuditLogRecord[]>
  notifyRendererReady: () => void
}

export const IPC_CHANNELS = {
  getBootstrapState: 'agentgo:get-bootstrap-state',
  runPolicySelfCheck: 'agentgo:run-policy-self-check',
  getDashboard: 'agentgo:get-dashboard',
  listWorkspaces: 'agentgo:list-workspaces',
  createWorkspace: 'agentgo:create-workspace',
  deleteWorkspace: 'agentgo:delete-workspace',
  listTargets: 'agentgo:list-targets',
  getTargetDetail: 'agentgo:get-target-detail',
  createTarget: 'agentgo:create-target',
  updateTarget: 'agentgo:update-target',
  deleteTarget: 'agentgo:delete-target',
  saveIdentity: 'agentgo:save-identity',
  deleteIdentity: 'agentgo:delete-identity',
  listScans: 'agentgo:list-scans',
  createScan: 'agentgo:create-scan',
  controlScan: 'agentgo:control-scan',
  getScanDetail: 'agentgo:get-scan-detail',
  scanEvent: 'agentgo:scan-event',
  searchKnowledge: 'agentgo:search-knowledge',
  listKnowledgeImports: 'agentgo:list-knowledge-imports',
  getKnowledgeImport: 'agentgo:get-knowledge-import',
  createKnowledgeImport: 'agentgo:create-knowledge-import',
  extractKnowledgeImport: 'agentgo:extract-knowledge-import',
  updateKnowledgeCandidate: 'agentgo:update-knowledge-candidate',
  reviewKnowledgeImport: 'agentgo:review-knowledge-import',
  deleteKnowledgeImport: 'agentgo:delete-knowledge-import',
  listFindings: 'agentgo:list-findings',
  listReports: 'agentgo:list-reports',
  generateReport: 'agentgo:generate-report',
  exportReport: 'agentgo:export-report',
  listModelProfiles: 'agentgo:list-model-profiles',
  listModelProfileUsage: 'agentgo:list-model-profile-usage',
  saveModelProfile: 'agentgo:save-model-profile',
  deleteModelProfile: 'agentgo:delete-model-profile',
  testModelProfile: 'agentgo:test-model-profile',
  listMcpServers: 'agentgo:list-mcp-servers',
  saveMcpServer: 'agentgo:save-mcp-server',
  deleteMcpServer: 'agentgo:delete-mcp-server',
  testMcpServer: 'agentgo:test-mcp-server',
  listAuditLogs: 'agentgo:list-audit-logs',
  rendererReady: 'agentgo:renderer-ready'
} as const
