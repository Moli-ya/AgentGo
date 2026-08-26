import { writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { app, BrowserWindow, dialog, ipcMain, safeStorage } from 'electron'
import {
  AgentGoApplicationService,
  AgentPromptCatalog,
  DefaultScanCoordinator,
  EphemeralRequestHashKeyProvider,
  EvidenceCapturePolicy,
  ExecutionAuthority,
  ExecutionService,
  InventoryService,
  LegacyV1RequestCompilerAdapter,
  PolicyBroker,
  PolicyExecutionGuard,
  ProtectedEvidenceRetentionScheduler,
  ReportService,
  createVulnerabilityPlatform
} from '@agentgo/application'
import { createDefaultScanPlan } from '@agentgo/agent-runtime'
import { PlaywrightBrowserRunner } from '@agentgo/browser-runner'
import {
  AuditFilterSchema,
  ControlScanInputSchema,
  CreateKnowledgeImportInputSchema,
  CreateScanInputSchema,
  CreateTargetInputSchema,
  CreateWorkspaceInputSchema,
  DeleteByIdInputSchema,
  DesktopOutputSchemas,
  ExportReportInputSchema,
  ExtractKnowledgeImportInputSchema,
  FindingFilterSchema,
  GenerateReportInputSchema,
  IPC_CHANNELS,
  KnowledgeSearchInputSchema,
  McpServerFilterSchema,
  ModelProfileFilterSchema,
  OptionalWorkspaceFilterSchema,
  ReportFilterSchema,
  ReviewKnowledgeImportInputSchema,
  SaveModelProfileInputSchema,
  SaveMcpServerInputSchema,
  SaveIdentityInputSchema,
  ScanFilterSchema,
  TargetFilterSchema,
  UpdateKnowledgeCandidateInputSchema,
  UpdateTargetInputSchema,
  WorkspaceFilterSchema,
  type BootstrapState,
  type PolicySelfCheckResult,
  type ProbeAction,
  type TargetScope
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  openAgentGoDatabase,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { UndiciHttpRunner } from '@agentgo/http-runner'
import { DefaultModelGateway } from '@agentgo/model-gateway'
import { evaluateProbe } from '@agentgo/security-policy'

const vulnerabilityPlatform = createVulnerabilityPlatform()
const plan = createDefaultScanPlan(vulnerabilityPlatform.defaultScanFamilies)
const isSmokeTest = process.env.AGENTGO_SMOKE_TEST === '1'
const mainDirectory = dirname(fileURLToPath(import.meta.url))

interface Parser<T> {
  parse(value: unknown): T
}

interface MainInfrastructure {
  database: AgentGoDatabase
  repository: AgentGoRepository
  applicationService: AgentGoApplicationService
  scanCoordinator: DefaultScanCoordinator
  retentionScheduler: ProtectedEvidenceRetentionScheduler
  requestHashKeyProvider: EphemeralRequestHashKeyProvider
  dataDirectory: string
}

let infrastructure: MainInfrastructure | undefined

function getBootstrapState(): BootstrapState {
  return {
    appVersion: app.getVersion(),
    milestone: 'V1',
    projectStatus: '四类漏洞闭环、真实模型路由与 MCP 配置/能力发现已接入',
    dataDirectory: infrastructure?.dataDirectory ?? '',
    databaseReady: Boolean(infrastructure),
    agents: ['planner', 'knowledge', 'strategy', 'analysis', 'verifier'],
    phases: plan.phases,
    vulnerabilityFamilies: plan.families,
    safeguards: [
      '所有主动动作经过确定性 SecurityPolicy',
      'L1 低影响探测允许，L2 逐次批准',
      'DROP/DELETE/持久化/越界等 L3 动作永久拒绝',
      'Confirmed 结论必须绑定规则和证据'
    ]
  }
}

function runPolicySelfCheck(): PolicySelfCheckResult {
  const scope: TargetScope = {
    id: 'desktop-self-check',
    allowedOrigins: ['https://lab.example.test'],
    allowedPathPrefixes: ['/'],
    deniedPathPrefixes: [],
    allowedPorts: [443],
    allowedIdentityIds: [],
    allowActiveProbing: true,
    allowSensitiveProbing: false,
    allowPrivateNetworkTargets: false,
    allowLoopbackTargets: false,
    networkEntries: [],
    maxRequestsPerMinute: 30,
    maxConcurrency: 2
  }

  const safeProbe: ProbeAction = {
    id: 'safe-probe',
    kind: 'http-request',
    targetUrl: 'https://lab.example.test/search?q=agentgo-marker',
    method: 'GET',
    probeLevel: 'active-safe',
    sideEffect: 'none',
    summary: '使用惰性标记比较授权靶场响应差异',
    expectedEvidence: '基线和测试响应摘要',
    requestedRequestsPerMinute: 5,
    requestedConcurrency: 1,
    maxRequests: 1,
    timeoutMs: 10_000,
    userApproved: false
  }

  const destructiveProbe: ProbeAction = {
    id: 'destructive-probe',
    kind: 'http-request',
    targetUrl: 'https://lab.example.test/api/query',
    method: 'POST',
    probeLevel: 'destructive',
    sideEffect: 'destructive',
    summary: '尝试执行破坏性数据库语句',
    payloadSummary: 'DROP TABLE users',
    expectedEvidence: '该动作不应执行',
    maxRequests: 1,
    timeoutMs: 10_000,
    userApproved: true
  }

  return {
    safeProbe: evaluateProbe(safeProbe, scope),
    destructiveProbe: evaluateProbe(destructiveProbe, scope),
    note: '自检只评估策略，不会向任何目标发送网络请求。'
  }
}

function handle<TInput, TResult>(
  channel: string,
  inputParser: Parser<TInput>,
  outputParser: Parser<TResult>,
  callback: (input: TInput) => TResult | Promise<TResult>
): void {
  ipcMain.handle(channel, async (_event, payload: unknown) =>
    outputParser.parse(await callback(inputParser.parse(payload)))
  )
}

function handleNoInput<TResult>(
  channel: string,
  outputParser: Parser<TResult>,
  callback: () => TResult | Promise<TResult>
): void {
  ipcMain.handle(channel, async () => outputParser.parse(await callback()))
}

function registerIpcHandlers(service: AgentGoApplicationService): void {
  handleNoInput(
    IPC_CHANNELS.getBootstrapState,
    DesktopOutputSchemas.bootstrapState,
    getBootstrapState
  )
  handleNoInput(
    IPC_CHANNELS.runPolicySelfCheck,
    DesktopOutputSchemas.policySelfCheck,
    runPolicySelfCheck
  )
  handleNoInput(
    IPC_CHANNELS.listWorkspaces,
    DesktopOutputSchemas.workspaces,
    () => service.listWorkspaces()
  )

  handle(
    IPC_CHANNELS.getDashboard,
    OptionalWorkspaceFilterSchema,
    DesktopOutputSchemas.dashboard,
    (input) => service.getDashboard(input.workspaceId)
  )
  handle(
    IPC_CHANNELS.createWorkspace,
    CreateWorkspaceInputSchema,
    DesktopOutputSchemas.workspace,
    (input) => service.createWorkspace(input)
  )
  handle(
    IPC_CHANNELS.deleteWorkspace,
    DeleteByIdInputSchema,
    DesktopOutputSchemas.deleteResult,
    (input) => service.deleteWorkspace(input.id)
  )
  handle(
    IPC_CHANNELS.listTargets,
    WorkspaceFilterSchema,
    DesktopOutputSchemas.targets,
    (input) => service.listTargets(input.workspaceId)
  )
  handle(
    IPC_CHANNELS.getTargetDetail,
    TargetFilterSchema,
    DesktopOutputSchemas.targetDetail,
    (input) => service.getTargetDetail(input.targetId)
  )
  handle(
    IPC_CHANNELS.createTarget,
    CreateTargetInputSchema,
    DesktopOutputSchemas.targetDetail,
    (input) => service.createTarget(input)
  )
  handle(
    IPC_CHANNELS.updateTarget,
    UpdateTargetInputSchema,
    DesktopOutputSchemas.targetDetail,
    (input) => service.updateTarget(input)
  )
  handle(
    IPC_CHANNELS.deleteTarget,
    DeleteByIdInputSchema,
    DesktopOutputSchemas.deleteResult,
    (input) => service.deleteTarget(input.id)
  )
  handle(
    IPC_CHANNELS.saveIdentity,
    SaveIdentityInputSchema,
    DesktopOutputSchemas.identity,
    (input) => service.saveIdentity(input)
  )
  handle(
    IPC_CHANNELS.deleteIdentity,
    DeleteByIdInputSchema,
    DesktopOutputSchemas.deleteResult,
    (input) => service.deleteIdentity(input.id)
  )
  handle(
    IPC_CHANNELS.listScans,
    OptionalWorkspaceFilterSchema,
    DesktopOutputSchemas.scans,
    (input) => service.listScans(input.workspaceId)
  )
  handle(
    IPC_CHANNELS.createScan,
    CreateScanInputSchema,
    DesktopOutputSchemas.scan,
    (input) => service.createScan(input)
  )
  handle(
    IPC_CHANNELS.controlScan,
    ControlScanInputSchema,
    DesktopOutputSchemas.scan,
    (input) => service.controlScan(input.scanId, input.action)
  )
  handle(
    IPC_CHANNELS.getScanDetail,
    ScanFilterSchema,
    DesktopOutputSchemas.scanDetail,
    (input) => service.getScanDetail(input.scanId)
  )
  handle(
    IPC_CHANNELS.searchKnowledge,
    KnowledgeSearchInputSchema,
    DesktopOutputSchemas.knowledgeEntries,
    (input) => service.searchKnowledge(input)
  )
  handleNoInput(
    IPC_CHANNELS.listKnowledgeImports,
    DesktopOutputSchemas.knowledgeImports,
    () => service.listKnowledgeImports()
  )
  handle(
    IPC_CHANNELS.getKnowledgeImport,
    DeleteByIdInputSchema,
    DesktopOutputSchemas.knowledgeImport,
    (input) => service.getKnowledgeImport(input.id)
  )
  handle(
    IPC_CHANNELS.createKnowledgeImport,
    CreateKnowledgeImportInputSchema,
    DesktopOutputSchemas.knowledgeImport,
    (input) => service.createKnowledgeImport(input)
  )
  handle(
    IPC_CHANNELS.extractKnowledgeImport,
    ExtractKnowledgeImportInputSchema,
    DesktopOutputSchemas.knowledgeImport,
    (input) => service.extractKnowledgeImport(input)
  )
  handle(
    IPC_CHANNELS.updateKnowledgeCandidate,
    UpdateKnowledgeCandidateInputSchema,
    DesktopOutputSchemas.knowledgeImport,
    (input) => service.updateKnowledgeCandidate(input)
  )
  handle(
    IPC_CHANNELS.reviewKnowledgeImport,
    ReviewKnowledgeImportInputSchema,
    DesktopOutputSchemas.knowledgeImport,
    (input) => service.reviewKnowledgeImport(input)
  )
  handle(
    IPC_CHANNELS.deleteKnowledgeImport,
    DeleteByIdInputSchema,
    DesktopOutputSchemas.deleteResult,
    (input) => service.deleteKnowledgeImport(input.id)
  )
  handle(
    IPC_CHANNELS.listFindings,
    FindingFilterSchema,
    DesktopOutputSchemas.findings,
    (input) => service.listFindings(input)
  )
  handle(
    IPC_CHANNELS.listReports,
    ReportFilterSchema,
    DesktopOutputSchemas.reports,
    (input) => service.listReports(input.scanId)
  )
  handle(
    IPC_CHANNELS.generateReport,
    GenerateReportInputSchema,
    DesktopOutputSchemas.report,
    (input) => service.generateReport(input)
  )
  handle(
    IPC_CHANNELS.exportReport,
    ExportReportInputSchema,
    DesktopOutputSchemas.exportReport,
    async (input) => {
      const report = await service.readReport(input.reportId)
      const safeName = report.report.title
        .replace(/[<>:"/\\|?*\u0000-\u001f]/g, '_')
        .slice(0, 120)
      const selection = await dialog.showSaveDialog({
        title: '导出脱敏安全验证报告',
        defaultPath: `${safeName}${report.extension}`,
        filters: [
          {
            name: report.report.format.toUpperCase(),
            extensions: [report.extension.slice(1)]
          }
        ]
      })
      if (selection.canceled || !selection.filePath) {
        return DesktopOutputSchemas.exportReport.parse({ exported: false })
      }
      await writeFile(selection.filePath, report.content, { flag: 'w', mode: 0o600 })
      await service.markReportExported(input.reportId, selection.filePath)
      return DesktopOutputSchemas.exportReport.parse({
        exported: true,
        filePath: selection.filePath
      })
    }
  )
  handleNoInput(
    IPC_CHANNELS.listModelProfiles,
    DesktopOutputSchemas.modelProfiles,
    () => service.listModelProfiles()
  )
  handleNoInput(
    IPC_CHANNELS.listModelProfileUsage,
    DesktopOutputSchemas.modelProfileUsage,
    () => service.listModelProfileUsage()
  )
  handle(
    IPC_CHANNELS.saveModelProfile,
    SaveModelProfileInputSchema,
    DesktopOutputSchemas.modelProfile,
    (input) => service.saveModelProfile(input)
  )
  handle(
    IPC_CHANNELS.deleteModelProfile,
    DeleteByIdInputSchema,
    DesktopOutputSchemas.deleteResult,
    (input) => service.deleteModelProfile(input.id)
  )
  handle(
    IPC_CHANNELS.testModelProfile,
    ModelProfileFilterSchema,
    DesktopOutputSchemas.connectionTest,
    (input) => service.testModelProfile(input.id)
  )
  handleNoInput(
    IPC_CHANNELS.listMcpServers,
    DesktopOutputSchemas.mcpServers,
    () => service.listMcpServers()
  )
  handle(
    IPC_CHANNELS.saveMcpServer,
    SaveMcpServerInputSchema,
    DesktopOutputSchemas.mcpServer,
    (input) => service.saveMcpServer(input)
  )
  handle(
    IPC_CHANNELS.deleteMcpServer,
    McpServerFilterSchema,
    DesktopOutputSchemas.deleteResult,
    (input) => service.deleteMcpServer(input.id)
  )
  handle(
    IPC_CHANNELS.testMcpServer,
    McpServerFilterSchema,
    DesktopOutputSchemas.mcpConnectionTest,
    (input) => service.testMcpServer(input.id)
  )
  handle(
    IPC_CHANNELS.listAuditLogs,
    AuditFilterSchema,
    DesktopOutputSchemas.auditLogs,
    (input) => infrastructure!.repository.listAuditLogs(input)
  )

  if (isSmokeTest) {
    const smokeTimeout = setTimeout(() => {
      console.error('AGENTGO_SMOKE_TEST_RENDERER_TIMEOUT')
      app.exit(1)
    }, 15_000)

    ipcMain.once(IPC_CHANNELS.rendererReady, () => {
      clearTimeout(smokeTimeout)
      const result = runPolicySelfCheck()
      const passed =
        result.safeProbe.allowed &&
        !result.destructiveProbe.allowed &&
        Boolean(infrastructure)
      console.log(passed ? 'AGENTGO_SMOKE_TEST_OK' : 'AGENTGO_SMOKE_TEST_FAILED')
      app.exit(passed ? 0 : 1)
    })
  }
}

function createInfrastructure(): MainInfrastructure {
  const dataDirectory = isSmokeTest ? ':memory:' : app.getPath('userData')
  const databasePath = isSmokeTest
    ? ':memory:'
    : join(dataDirectory, 'data', 'agentgo.sqlite')
  const database = openAgentGoDatabase(databasePath)
  const repository = new AgentGoRepository(database)
  const protector: SecretProtector = {
    isAvailable: () => safeStorage.isEncryptionAvailable(),
    protect: (value) => safeStorage.encryptString(value),
    unprotect: (value) => safeStorage.decryptString(value)
  }
  const credentialPath = isSmokeTest
    ? join(app.getPath('temp'), `agentgo-smoke-credentials-${process.pid}.json`)
    : join(dataDirectory, 'credentials', 'credentials.json')
  const credentialStore = new FileCredentialStore(credentialPath, protector)
  const artifactRoot = isSmokeTest
    ? join(app.getPath('temp'), `agentgo-smoke-artifacts-${process.pid}`)
    : join(dataDirectory, 'artifacts')
  const evidenceStore = new EvidenceStore(database, artifactRoot, {
    protector
  })
  const retentionScheduler = new ProtectedEvidenceRetentionScheduler(
    evidenceStore,
    {
      onError: () => {
        console.error('Protected Evidence retention sweep failed.')
      }
    }
  )
  const requestHashKeyProvider = new EphemeralRequestHashKeyProvider()
  const requestAdapter = new LegacyV1RequestCompilerAdapter({
    repository,
    credentialStore,
    hashKeyProvider: requestHashKeyProvider,
    hashKey: requestHashKeyProvider.reference
  })
  const authority = new ExecutionAuthority(repository, requestHashKeyProvider)
  const policyBroker = new PolicyBroker(repository)
  const executionGuard = new PolicyExecutionGuard(
    repository,
    requestHashKeyProvider,
    credentialStore
  )
  const evidenceCapturePolicy = new EvidenceCapturePolicy()
  const executionService = new ExecutionService({
    repository,
    evidenceStore,
    httpRunner: new UndiciHttpRunner(executionGuard),
    browserRunner: new PlaywrightBrowserRunner({ headless: true }),
    requestAdapter,
    authority,
    policyBroker,
    executionGuard,
    evidenceCapturePolicy,
    hashKeyProvider: requestHashKeyProvider
  })
  const reportService = new ReportService(repository, evidenceStore)
  const modelGateway = new DefaultModelGateway({
    profiles: repository,
    credentials: credentialStore,
    prompts: new AgentPromptCatalog(),
    invocations: repository
  })
  const inventoryService = new InventoryService(
    repository,
    vulnerabilityPlatform.capabilityCatalog
  )
  const applicationService = new AgentGoApplicationService({
    repository,
    credentialStore,
    evidenceStore,
    modelGateway,
    evidenceCapturePolicy,
    reportService,
    inventoryService,
    vulnerabilityPlatform,
    vulnerabilityExecutionEnvironment: 'authorized-real-target'
  })
  const scanCoordinator = new DefaultScanCoordinator({
    repository,
    evidenceStore,
    executionPort: executionService,
    modelGateway,
    reportService,
    inventoryService,
    vulnerabilityPlatform,
    vulnerabilityExecutionEnvironment: 'authorized-real-target',
    onEvent: (event) => {
      const validatedEvent = DesktopOutputSchemas.scanEvent.parse(event)
      for (const window of BrowserWindow.getAllWindows()) {
        if (!window.isDestroyed()) {
          window.webContents.send(IPC_CHANNELS.scanEvent, validatedEvent)
        }
      }
    }
  })
  applicationService.setScanCoordinator(scanCoordinator)
  return {
    database,
    repository,
    applicationService,
    scanCoordinator,
    retentionScheduler,
    requestHashKeyProvider,
    dataDirectory
  }
}

function createWindow(): void {
  const window = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 980,
    minHeight: 640,
    show: false,
    backgroundColor: '#f5f7fb',
    webPreferences: {
      preload: join(mainDirectory, '../preload/index.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      devTools: !app.isPackaged
    }
  })

  if (!isSmokeTest) {
    window.once('ready-to-show', () => window.show())
  }
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))

  const devUrl = process.env.ELECTRON_RENDERER_URL
  window.webContents.on('will-navigate', (event, url) => {
    const allowed = devUrl ? url.startsWith(devUrl) : url.startsWith('file://')
    if (!allowed) event.preventDefault()
  })

  if (isSmokeTest) {
    window.webContents.once('did-fail-load', (_event, code, description) => {
      console.error('AGENTGO_SMOKE_TEST_LOAD_FAILED', code, description)
      app.exit(1)
    })
  }

  if (devUrl) {
    void window.loadURL(devUrl)
  } else {
    void window.loadFile(join(mainDirectory, '../renderer/index.html'))
  }
}

app.whenReady().then(async () => {
  infrastructure = createInfrastructure()
  await infrastructure.applicationService.initialize()
  infrastructure.retentionScheduler.start()
  registerIpcHandlers(infrastructure.applicationService)
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

let shutdownStarted = false
app.on('before-quit', (event) => {
  if (!infrastructure || shutdownStarted) return
  event.preventDefault()
  shutdownStarted = true
  const current = infrastructure
  void Promise.allSettled([
    current.scanCoordinator.shutdown(),
    current.retentionScheduler.stop()
  ]).finally(() => {
    current.requestHashKeyProvider.dispose()
    current.database.close()
    infrastructure = undefined
    app.quit()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
