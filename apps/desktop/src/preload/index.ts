import { contextBridge, ipcRenderer } from 'electron'
import {
  IPC_CHANNELS,
  type AgentGoDesktopApi,
  type AuditLogRecord,
  type BootstrapState,
  type ConnectionTestResult,
  type CreateKnowledgeImportInput,
  type CreateScanInput,
  type CreateTargetInput,
  type CreateWorkspaceInput,
  type DashboardSnapshot,
  type DeleteResult,
  type ExportReportInput,
  type ExportReportResult,
  type FindingRecord,
  type GenerateReportInput,
  type IdentityRecord,
  type ExtractKnowledgeImportInput,
  type KnowledgeEntrySummary,
  type KnowledgeImportDetail,
  type KnowledgeImportSummary,
  type KnowledgeSearchInput,
  type McpConnectionTestResult,
  type McpServerRecord,
  type ModelProfileRecord,
  type ModelProfileUsageRecord,
  type PolicySelfCheckResult,
  type ReportRecord,
  type ReviewKnowledgeImportInput,
  type SaveIdentityInput,
  type SaveMcpServerInput,
  type SaveModelProfileInput,
  type ScanControlAction,
  type ScanDetail,
  type ScanEvent,
  type ScanRecord,
  type TargetDetail,
  type TargetRecord,
  type UpdateTargetInput,
  type UpdateKnowledgeCandidateInput,
  type WorkspaceRecord
} from '@agentgo/contracts'

const api: AgentGoDesktopApi = {
  getBootstrapState: () =>
    ipcRenderer.invoke(IPC_CHANNELS.getBootstrapState) as Promise<BootstrapState>,
  runPolicySelfCheck: () =>
    ipcRenderer.invoke(IPC_CHANNELS.runPolicySelfCheck) as Promise<PolicySelfCheckResult>,
  getDashboard: (workspaceId) =>
    ipcRenderer.invoke(IPC_CHANNELS.getDashboard, { workspaceId }) as Promise<DashboardSnapshot>,
  listWorkspaces: () =>
    ipcRenderer.invoke(IPC_CHANNELS.listWorkspaces) as Promise<WorkspaceRecord[]>,
  createWorkspace: (input: CreateWorkspaceInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.createWorkspace, input) as Promise<WorkspaceRecord>,
  deleteWorkspace: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.deleteWorkspace, { id }) as Promise<DeleteResult>,
  listTargets: (workspaceId) =>
    ipcRenderer.invoke(IPC_CHANNELS.listTargets, { workspaceId }) as Promise<TargetRecord[]>,
  getTargetDetail: (targetId) =>
    ipcRenderer.invoke(IPC_CHANNELS.getTargetDetail, { targetId }) as Promise<TargetDetail>,
  createTarget: (input: CreateTargetInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.createTarget, input) as Promise<TargetDetail>,
  updateTarget: (input: UpdateTargetInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.updateTarget, input) as Promise<TargetDetail>,
  deleteTarget: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.deleteTarget, { id }) as Promise<DeleteResult>,
  saveIdentity: (input: SaveIdentityInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.saveIdentity, input) as Promise<IdentityRecord>,
  deleteIdentity: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.deleteIdentity, { id }) as Promise<DeleteResult>,
  listScans: (workspaceId) =>
    ipcRenderer.invoke(IPC_CHANNELS.listScans, { workspaceId }) as Promise<ScanRecord[]>,
  createScan: (input: CreateScanInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.createScan, input) as Promise<ScanRecord>,
  controlScan: (scanId, action: ScanControlAction) =>
    ipcRenderer.invoke(IPC_CHANNELS.controlScan, { scanId, action }) as Promise<ScanRecord>,
  getScanDetail: (scanId) =>
    ipcRenderer.invoke(IPC_CHANNELS.getScanDetail, { scanId }) as Promise<ScanDetail>,
  onScanEvent: (listener: (event: ScanEvent) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, payload: ScanEvent): void => {
      listener(payload)
    }
    ipcRenderer.on(IPC_CHANNELS.scanEvent, handler)
    return () => ipcRenderer.removeListener(IPC_CHANNELS.scanEvent, handler)
  },
  searchKnowledge: (input: KnowledgeSearchInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.searchKnowledge, input) as Promise<KnowledgeEntrySummary[]>,
  listKnowledgeImports: () =>
    ipcRenderer.invoke(IPC_CHANNELS.listKnowledgeImports) as Promise<KnowledgeImportSummary[]>,
  getKnowledgeImport: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.getKnowledgeImport, { id }) as Promise<KnowledgeImportDetail>,
  createKnowledgeImport: (input: CreateKnowledgeImportInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.createKnowledgeImport, input) as Promise<KnowledgeImportDetail>,
  extractKnowledgeImport: (input: ExtractKnowledgeImportInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.extractKnowledgeImport, input) as Promise<KnowledgeImportDetail>,
  updateKnowledgeCandidate: (input: UpdateKnowledgeCandidateInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.updateKnowledgeCandidate, input) as Promise<KnowledgeImportDetail>,
  reviewKnowledgeImport: (input: ReviewKnowledgeImportInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.reviewKnowledgeImport, input) as Promise<KnowledgeImportDetail>,
  deleteKnowledgeImport: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.deleteKnowledgeImport, { id }) as Promise<DeleteResult>,
  listFindings: (input) =>
    ipcRenderer.invoke(IPC_CHANNELS.listFindings, input ?? {}) as Promise<FindingRecord[]>,
  listReports: (scanId) =>
    ipcRenderer.invoke(IPC_CHANNELS.listReports, { scanId }) as Promise<ReportRecord[]>,
  generateReport: (input: GenerateReportInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.generateReport, input) as Promise<ReportRecord>,
  exportReport: (input: ExportReportInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.exportReport, input) as Promise<ExportReportResult>,
  listModelProfiles: () =>
    ipcRenderer.invoke(IPC_CHANNELS.listModelProfiles) as Promise<ModelProfileRecord[]>,
  listModelProfileUsage: () =>
    ipcRenderer.invoke(IPC_CHANNELS.listModelProfileUsage) as Promise<ModelProfileUsageRecord[]>,
  saveModelProfile: (input: SaveModelProfileInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.saveModelProfile, input) as Promise<ModelProfileRecord>,
  deleteModelProfile: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.deleteModelProfile, { id }) as Promise<DeleteResult>,
  testModelProfile: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.testModelProfile, { id }) as Promise<ConnectionTestResult>,
  listMcpServers: () =>
    ipcRenderer.invoke(IPC_CHANNELS.listMcpServers) as Promise<McpServerRecord[]>,
  saveMcpServer: (input: SaveMcpServerInput) =>
    ipcRenderer.invoke(IPC_CHANNELS.saveMcpServer, input) as Promise<McpServerRecord>,
  deleteMcpServer: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.deleteMcpServer, { id }) as Promise<DeleteResult>,
  testMcpServer: (id) =>
    ipcRenderer.invoke(IPC_CHANNELS.testMcpServer, { id }) as Promise<McpConnectionTestResult>,
  listAuditLogs: (workspaceId, scanId) =>
    ipcRenderer.invoke(IPC_CHANNELS.listAuditLogs, {
      workspaceId,
      scanId
    }) as Promise<AuditLogRecord[]>,
  notifyRendererReady: () => {
    ipcRenderer.send(IPC_CHANNELS.rendererReady)
  }
}

contextBridge.exposeInMainWorld('agentGo', api)
