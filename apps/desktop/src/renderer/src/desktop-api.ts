import { LEGACY_V1_FAMILY_IDS } from '@agentgo/contracts'
import type {
  AgentGoDesktopApi,
  BootstrapState,
  DashboardSnapshot,
  PolicySelfCheckResult,
  WorkspaceRecord
} from '@agentgo/contracts'

const now = new Date().toISOString()
const previewWorkspace: WorkspaceRecord = {
  id: 'preview-workspace',
  name: 'Renderer 预览工作区',
  description: '仅用于浏览器预览，不写入本地数据库。',
  createdAt: now,
  updatedAt: now
}

const previewState: BootstrapState = {
  appVersion: '0.1.0-preview',
  milestone: 'V1',
  projectStatus: '四类漏洞闭环、真实模型路由与 MCP 配置/能力发现已接入',
  dataDirectory: 'Renderer preview memory',
  databaseReady: true,
  agents: ['planner', 'knowledge', 'strategy', 'analysis', 'verifier'],
  phases: [
    'intake',
    'passive-recon',
    'active-enum',
    'hypothesis',
    'validation',
    'verification',
    'report'
  ],
  vulnerabilityFamilies: [...LEGACY_V1_FAMILY_IDS],
  safeguards: [
    '所有主动动作经过确定性 SecurityPolicy',
    'L1 低影响探测允许，L2 逐次批准',
    'DROP/DELETE/持久化/越界等 L3 动作永久拒绝',
    'Confirmed 结论必须绑定规则和证据'
  ]
}

const previewSelfCheck: PolicySelfCheckResult = {
  safeProbe: {
    allowed: true,
    requiresApproval: false,
    code: 'allowed',
    reasons: ['动作位于授权范围内，且符合当前主动探测等级。'],
    normalizedTarget: 'https://lab.example.test/search?q=agentgo-marker'
  },
  destructiveProbe: {
    allowed: false,
    requiresApproval: false,
    code: 'destructive-action',
    reasons: ['检测到破坏性或数据写入动作。'],
    normalizedTarget: 'https://lab.example.test/api/query'
  },
  note: 'Renderer 预览模式使用静态策略结果，不发送网络请求。'
}

const previewDashboard: DashboardSnapshot = {
  workspaceCount: 1,
  targetCount: 0,
  activeScanCount: 0,
  confirmedFindingCount: 0,
  recentScans: [],
  recentFindings: []
}

const unavailable = async (): Promise<never> => {
  throw new Error('该操作需要在 Electron 桌面进程中运行。')
}

const previewApi: AgentGoDesktopApi = {
  getBootstrapState: async () => previewState,
  runPolicySelfCheck: async () => previewSelfCheck,
  getDashboard: async () => previewDashboard,
  listWorkspaces: async () => [previewWorkspace],
  createWorkspace: unavailable,
  deleteWorkspace: unavailable,
  listTargets: async () => [],
  getTargetDetail: unavailable,
  createTarget: unavailable,
  updateTarget: unavailable,
  deleteTarget: unavailable,
  saveIdentity: unavailable,
  deleteIdentity: unavailable,
  listScans: async () => [],
  createScan: unavailable,
  controlScan: unavailable,
  getScanDetail: unavailable,
  onScanEvent: () => () => undefined,
  searchKnowledge: async () => [],
  listKnowledgeImports: async () => [],
  getKnowledgeImport: unavailable,
  createKnowledgeImport: unavailable,
  extractKnowledgeImport: unavailable,
  updateKnowledgeCandidate: unavailable,
  reviewKnowledgeImport: unavailable,
  deleteKnowledgeImport: unavailable,
  listFindings: async () => [],
  listReports: async () => [],
  generateReport: unavailable,
  exportReport: unavailable,
  listModelProfiles: async () => [],
  listModelProfileUsage: async () => [],
  saveModelProfile: unavailable,
  deleteModelProfile: unavailable,
  testModelProfile: unavailable,
  listMcpServers: async () => [],
  saveMcpServer: unavailable,
  deleteMcpServer: unavailable,
  testMcpServer: unavailable,
  listAuditLogs: async () => [],
  notifyRendererReady: () => undefined
}

export function getDesktopApi(): AgentGoDesktopApi {
  if (window.agentGo) return window.agentGo
  if (import.meta.env.DEV) return previewApi
  throw new Error('AgentGo Preload bridge is unavailable.')
}
