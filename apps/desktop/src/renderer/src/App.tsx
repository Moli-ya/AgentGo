import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  BookOpen,
  Bot,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Crosshair,
  Database,
  Download,
  FileSearch,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  Pause,
  Pencil,
  Play,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  Square,
  Trash2,
  Users,
  type LucideIcon
} from 'lucide-react'
import type {
  AgentRole,
  AuditLogRecord,
  BootstrapState,
  DashboardSnapshot,
  FindingRecord,
  IdentityAuthType,
  KnowledgeEntrySummary,
  ModelProfileRecord,
  PolicySelfCheckResult,
  ReportRecord,
  ScanControlAction,
  ScanDetail,
  ScanRecord,
  TargetDetail,
  TargetRecord,
  TargetScopeRecord,
  VulnerabilityFamily,
  WorkspaceRecord
} from '@agentgo/contracts'
import { getDesktopApi } from './desktop-api'

type ViewId =
  | 'dashboard'
  | 'targets'
  | 'scans'
  | 'findings'
  | 'audit'
  | 'knowledge'
  | 'settings'

interface ModelProfileForm {
  id: string
  name: string
  agentRole: ModelProfileRecord['agentRole']
  baseUrl: string
  model: string
  apiKey: string
  timeoutMs: number
  rpmLimit: number
  tpmLimit: number
  tokenBudget: number
  costBudget: number
}

interface ScanFormState {
  targetId: string
  name: string
  description: string
  families: VulnerabilityFamily[]
  identityIds: string[]
  callbackUrl: string
  modelProfileIds: Partial<Record<AgentRole, string>>
  maxRequests: number
  maxDurationMinutes: number
}

function createEmptyProfileForm(): ModelProfileForm {
  return {
    id: '',
    name: '',
    agentRole: 'planner',
    baseUrl: 'https://api.openai.com/v1/',
    model: '',
    apiKey: '',
    timeoutMs: 30_000,
    rpmLimit: 30,
    tpmLimit: 100_000,
    tokenBudget: 1_000_000,
    costBudget: 20
  }
}

const familyLabels: Record<VulnerabilityFamily, string> = {
  sqli: 'SQL 注入',
  xss: 'XSS',
  ssrf: 'SSRF',
  idor: '越权 / IDOR'
}

const agentRoles: AgentRole[] = [
  'planner',
  'knowledge',
  'strategy',
  'analysis',
  'verifier'
]

const agentRoleLabels: Record<AgentRole, string> = {
  planner: 'PlannerAgent',
  knowledge: 'KnowledgeAgent',
  strategy: 'StrategyAgent',
  analysis: 'AnalysisAgent',
  verifier: 'VerifierAgent'
}

const verdictLabels: Record<FindingRecord['verdict'], string> = {
  confirmed: 'Confirmed',
  'not-confirmed': 'Not Confirmed',
  inconclusive: 'Inconclusive'
}

const phaseLabels: Record<ScanRecord['phase'], string> = {
  intake: '授权与范围',
  'passive-recon': '被动信息整理',
  'active-enum': '安全主动枚举',
  hypothesis: '假设与知识检索',
  validation: '低影响验证',
  verification: '独立复核',
  report: '证据报告'
}

const navItems: Array<{ id: ViewId; label: string; icon: LucideIcon }> = [
  { id: 'dashboard', label: '工作台', icon: LayoutDashboard },
  { id: 'targets', label: '目标与身份', icon: Crosshair },
  { id: 'scans', label: '扫描与 Agent', icon: Radar },
  { id: 'findings', label: 'Findings 与报告', icon: FileSearch },
  { id: 'audit', label: '审计日志', icon: Activity },
  { id: 'knowledge', label: '知识库', icon: BookOpen },
  { id: 'settings', label: '模型设置', icon: Settings }
]

function splitValues(value: string): string[] {
  return value
    .split(/[\n,，]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function scopeInput(scope: TargetScopeRecord) {
  return {
    allowedOrigins: scope.allowedOrigins,
    allowedPathPrefixes: scope.allowedPathPrefixes,
    deniedPathPrefixes: scope.deniedPathPrefixes,
    allowedPorts: scope.allowedPorts,
    allowedIdentityIds: scope.allowedIdentityIds,
    allowActiveProbing: scope.allowActiveProbing,
    allowSensitiveProbing: scope.allowSensitiveProbing,
    allowPrivateNetworkTargets: scope.allowPrivateNetworkTargets,
    allowLoopbackTargets: scope.allowLoopbackTargets,
    maxRequestsPerMinute: scope.maxRequestsPerMinute,
    maxConcurrency: scope.maxConcurrency,
    ...(scope.authorizationReference
      ? { authorizationReference: scope.authorizationReference }
      : {}),
    ...(scope.validFrom ? { validFrom: scope.validFrom } : {}),
    ...(scope.validUntil ? { validUntil: scope.validUntil } : {})
  }
}

function errorText(reason: unknown): string {
  if (reason instanceof Error) return reason.message
  return typeof reason === 'string' ? reason : '操作失败。'
}

function ActionButton({
  icon: Icon,
  children,
  kind = 'secondary',
  busy = false,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  icon?: LucideIcon
  kind?: 'primary' | 'secondary' | 'danger' | 'quiet'
  busy?: boolean
}): React.JSX.Element {
  return (
    <button className={`action-button ${kind}`} {...props} disabled={props.disabled || busy}>
      {busy ? <LoaderCircle className="spin" size={16} /> : Icon ? <Icon size={16} /> : null}
      <span>{children}</span>
    </button>
  )
}

function StatusPill({ value }: { value: string }): React.JSX.Element {
  const normalized = value.toLowerCase().replaceAll(' ', '-')
  return <span className={`status-pill ${normalized}`}>{value}</span>
}

function EmptyState({ icon: Icon, children }: { icon: LucideIcon; children: string }): React.JSX.Element {
  return (
    <div className="empty-state">
      <Icon size={30} />
      <p>{children}</p>
    </div>
  )
}

export function App(): React.JSX.Element {
  const api = getDesktopApi()
  const [view, setView] = useState<ViewId>('dashboard')
  const [bootstrap, setBootstrap] = useState<BootstrapState>()
  const [workspaces, setWorkspaces] = useState<WorkspaceRecord[]>([])
  const [workspaceId, setWorkspaceId] = useState('')
  const [dashboard, setDashboard] = useState<DashboardSnapshot>()
  const [targets, setTargets] = useState<TargetRecord[]>([])
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [findings, setFindings] = useState<FindingRecord[]>([])
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([])
  const [profiles, setProfiles] = useState<ModelProfileRecord[]>([])
  const [selectedTarget, setSelectedTarget] = useState<TargetDetail>()
  const [selectedScan, setSelectedScan] = useState<ScanDetail>()
  const [reports, setReports] = useState<ReportRecord[]>([])
  const [knowledge, setKnowledge] = useState<KnowledgeEntrySummary[]>([])
  const [selfCheck, setSelfCheck] = useState<PolicySelfCheckResult>()
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  const [workspaceForm, setWorkspaceForm] = useState({ name: '', description: '' })
  const [targetForm, setTargetForm] = useState({
    name: '',
    baseUrl: 'http://127.0.0.1:3000/',
    description: '',
    authorizationReference: '',
    allowedOrigins: '',
    allowedPaths: '/',
    deniedPaths: '',
    allowLoopback: true,
    allowPrivate: false,
    maxRpm: 30,
    maxConcurrency: 1
  })
  const [identityForm, setIdentityForm] = useState({
    label: '',
    role: 'test-user',
    authType: 'bearer' as IdentityAuthType,
    headerName: '',
    secret: '',
    ownedResourceIds: '',
    includeInScope: true
  })
  const [scanForm, setScanForm] = useState<ScanFormState>({
    targetId: '',
    name: '',
    description: '',
    families: ['sqli', 'xss', 'ssrf', 'idor'] as VulnerabilityFamily[],
    identityIds: [] as string[],
    callbackUrl: '',
    modelProfileIds: {},
    maxRequests: 120,
    maxDurationMinutes: 30
  })
  const [knowledgeQuery, setKnowledgeQuery] = useState('')
  const [profileForm, setProfileForm] = useState<ModelProfileForm>(
    createEmptyProfileForm
  )

  const activeWorkspace = workspaces.find((workspace) => workspace.id === workspaceId)
  const runningScan = scans.some((scan) => ['queued', 'running'].includes(scan.status))

  const refreshWorkspace = useCallback(
    async (id: string): Promise<void> => {
      if (!id) return
      const [nextDashboard, nextTargets, nextScans, nextFindings, nextAuditLogs] =
        await Promise.all([
        api.getDashboard(id),
        api.listTargets(id),
        api.listScans(id),
        api.listFindings({ workspaceId: id }),
        api.listAuditLogs(id)
      ])
      setDashboard(nextDashboard)
      setTargets(nextTargets)
      setScans(nextScans)
      setFindings(nextFindings)
      setAuditLogs(nextAuditLogs)
      setScanForm((current) => ({
        ...current,
        targetId:
          current.targetId && nextTargets.some((target) => target.id === current.targetId)
            ? current.targetId
            : nextTargets[0]?.id ?? ''
      }))
    },
    [api]
  )

  const refreshScanDetail = useCallback(
    async (scanId: string): Promise<void> => {
      const [detail, nextReports] = await Promise.all([
        api.getScanDetail(scanId),
        api.listReports(scanId)
      ])
      setSelectedScan(detail)
      setReports(nextReports)
    },
    [api]
  )

  useEffect(() => {
    let active = true
    void Promise.all([
      api.getBootstrapState(),
      api.listWorkspaces(),
      api.listModelProfiles()
    ])
      .then(([state, nextWorkspaces, nextProfiles]) => {
        if (!active) return
        setBootstrap(state)
        setWorkspaces(nextWorkspaces)
        setProfiles(nextProfiles)
        setWorkspaceId(nextWorkspaces[0]?.id ?? '')
        api.notifyRendererReady()
      })
      .catch((reason: unknown) => active && setError(errorText(reason)))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [api])

  useEffect(() => {
    if (!workspaceId) return
    setError('')
    void refreshWorkspace(workspaceId).catch((reason: unknown) => setError(errorText(reason)))
  }, [refreshWorkspace, workspaceId])

  useEffect(() => {
    if (!profiles.length) return
    setScanForm((current) => {
      const modelProfileIds = { ...current.modelProfileIds }
      let changed = false
      for (const role of agentRoles) {
        const currentProfile = profiles.find(
          (profile) => profile.id === modelProfileIds[role] && profile.agentRole === role
        )
        if (currentProfile) continue
        const roleProfiles = profiles.filter((profile) => profile.agentRole === role)
        const preferred =
          roleProfiles.find((profile) => profile.provider === 'openai-compatible') ??
          roleProfiles[0]
        if (preferred) {
          modelProfileIds[role] = preferred.id
        } else {
          delete modelProfileIds[role]
        }
        changed = true
      }
      return changed ? { ...current, modelProfileIds } : current
    })
  }, [profiles])

  useEffect(() => {
    if (!scanForm.targetId) {
      setSelectedTarget(undefined)
      return
    }
    void api
      .getTargetDetail(scanForm.targetId)
      .then((detail) => {
        setSelectedTarget(detail)
        setScanForm((current) => ({
          ...current,
          identityIds: detail.identities
            .filter((identity) => detail.scope.allowedIdentityIds.includes(identity.id))
            .map((identity) => identity.id)
        }))
      })
      .catch((reason: unknown) => setError(errorText(reason)))
  }, [api, scanForm.targetId])

  useEffect(() => {
    const unsubscribe = api.onScanEvent((event) => {
      if (selectedScan?.scan.id === event.scanId) {
        void refreshScanDetail(event.scanId).catch(() => undefined)
      }
      if (workspaceId) void refreshWorkspace(workspaceId).catch(() => undefined)
    })
    return unsubscribe
  }, [api, refreshScanDetail, refreshWorkspace, selectedScan?.scan.id, workspaceId])

  useEffect(() => {
    if (!runningScan || !workspaceId) return
    const timer = window.setInterval(() => {
      void refreshWorkspace(workspaceId)
      if (selectedScan) void refreshScanDetail(selectedScan.scan.id)
    }, 2_000)
    return () => window.clearInterval(timer)
  }, [refreshScanDetail, refreshWorkspace, runningScan, selectedScan, workspaceId])

  async function runAction<T>(key: string, action: () => Promise<T>): Promise<T | undefined> {
    setBusy(key)
    setError('')
    try {
      return await action()
    } catch (reason) {
      setError(errorText(reason))
      return undefined
    } finally {
      setBusy('')
    }
  }

  async function createWorkspace(): Promise<void> {
    const created = await runAction('workspace-create', () =>
      api.createWorkspace(workspaceForm)
    )
    if (!created) return
    const next = await api.listWorkspaces()
    setWorkspaces(next)
    setWorkspaceId(created.id)
    setWorkspaceForm({ name: '', description: '' })
  }

  async function deleteWorkspace(): Promise<void> {
    if (!activeWorkspace) return
    if (!window.confirm(`删除工作区“${activeWorkspace.name}”及其目标、扫描、证据和测试身份凭据。是否继续？`)) return
    const result = await runAction('workspace-delete', () =>
      api.deleteWorkspace(activeWorkspace.id)
    )
    if (!result?.deleted) return
    const next = await api.listWorkspaces()
    setWorkspaces(next)
    setWorkspaceId(next[0]?.id ?? '')
    setDashboard(undefined)
    setTargets([])
    setScans([])
    setFindings([])
    setAuditLogs([])
    setSelectedTarget(undefined)
    setSelectedScan(undefined)
  }

  async function createTarget(): Promise<void> {
    if (!workspaceId) return
    const parsed = new URL(targetForm.baseUrl)
    const port = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80))
    const created = await runAction('target-create', () =>
      api.createTarget({
        workspaceId,
        name: targetForm.name,
        baseUrl: parsed.toString(),
        description: targetForm.description,
        authorizationReference: targetForm.authorizationReference,
        scope: {
          allowedOrigins: splitValues(targetForm.allowedOrigins || parsed.origin),
          allowedPathPrefixes: splitValues(targetForm.allowedPaths),
          deniedPathPrefixes: splitValues(targetForm.deniedPaths),
          allowedPorts: [port],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: targetForm.allowPrivate,
          allowLoopbackTargets: targetForm.allowLoopback,
          maxRequestsPerMinute: targetForm.maxRpm,
          maxConcurrency: targetForm.maxConcurrency,
          authorizationReference: targetForm.authorizationReference
        }
      })
    )
    if (!created) return
    await refreshWorkspace(workspaceId)
    setScanForm((current) => ({ ...current, targetId: created.target.id }))
    setSelectedTarget(created)
    setTargetForm((current) => ({
      ...current,
      name: '',
      description: '',
      authorizationReference: ''
    }))
  }

  async function selectTarget(targetId: string): Promise<void> {
    const detail = await runAction('target-detail', () => api.getTargetDetail(targetId))
    if (!detail) return
    setSelectedTarget(detail)
    setScanForm((current) => ({ ...current, targetId }))
  }

  async function saveIdentity(): Promise<void> {
    if (!selectedTarget) return
    const saved = await runAction('identity-save', () =>
      api.saveIdentity({
        targetId: selectedTarget.target.id,
        label: identityForm.label,
        role: identityForm.role,
        authType: identityForm.authType,
        ...(identityForm.authType === 'header' && identityForm.headerName
          ? { headerName: identityForm.headerName }
          : {}),
        ...(identityForm.authType !== 'none' ? { secret: identityForm.secret } : {}),
        isTestIdentity: true,
        ownedResourceIds: splitValues(identityForm.ownedResourceIds)
      })
    )
    if (!saved) return
    if (identityForm.includeInScope) {
      await api.updateTarget({
        id: selectedTarget.target.id,
        scope: {
          ...scopeInput(selectedTarget.scope),
          allowedIdentityIds: uniqueValues([
            ...selectedTarget.scope.allowedIdentityIds,
            saved.id
          ])
        }
      })
    }
    const detail = await api.getTargetDetail(selectedTarget.target.id)
    setSelectedTarget(detail)
    setIdentityForm((current) => ({
      ...current,
      label: '',
      secret: '',
      ownedResourceIds: ''
    }))
  }

  async function deleteIdentity(identityId: string): Promise<void> {
    if (!selectedTarget) return
    await runAction(`identity-delete-${identityId}`, async () => {
      if (selectedTarget.scope.allowedIdentityIds.includes(identityId)) {
        await api.updateTarget({
          id: selectedTarget.target.id,
          scope: {
            ...scopeInput(selectedTarget.scope),
            allowedIdentityIds: selectedTarget.scope.allowedIdentityIds.filter(
              (id) => id !== identityId
            )
          }
        })
      }
      await api.deleteIdentity(identityId)
      setSelectedTarget(await api.getTargetDetail(selectedTarget.target.id))
    })
  }

  async function deleteTarget(targetId: string): Promise<void> {
    if (!workspaceId) return
    if (!window.confirm('删除目标会同时删除其扫描、证据和测试身份凭据。是否继续？')) return
    await runAction(`target-delete-${targetId}`, () => api.deleteTarget(targetId))
    setSelectedTarget(undefined)
    await refreshWorkspace(workspaceId)
  }

  async function createScan(): Promise<void> {
    if (!scanForm.targetId) return
    const created = await runAction('scan-create', () =>
      api.createScan({
        targetId: scanForm.targetId,
        name: scanForm.name,
        description: scanForm.description,
        families: scanForm.families,
        identityIds: scanForm.identityIds,
        modelProfileIds: scanForm.modelProfileIds,
        ...(scanForm.callbackUrl ? { callbackUrl: scanForm.callbackUrl } : {}),
        budget: {
          maxRequests: scanForm.maxRequests,
          maxRequestsPerMinute: 30,
          maxConcurrency: 1,
          maxPlanRevisions: 3,
          maxDurationMinutes: scanForm.maxDurationMinutes,
          maxModelTokens: 80_000,
          maxEstimatedCost: 10
        }
      })
    )
    if (!created || !workspaceId) return
    await refreshWorkspace(workspaceId)
    await refreshScanDetail(created.id)
    setScanForm((current) => ({ ...current, name: '', description: '' }))
  }

  async function controlScan(scan: ScanRecord, action: ScanControlAction): Promise<void> {
    await runAction(`scan-${action}-${scan.id}`, () => api.controlScan(scan.id, action))
    if (workspaceId) await refreshWorkspace(workspaceId)
    await refreshScanDetail(scan.id)
  }

  async function selectScan(scanId: string): Promise<void> {
    await runAction('scan-detail', () => refreshScanDetail(scanId))
  }

  async function generateReport(format: 'markdown' | 'json' | 'html'): Promise<void> {
    if (!selectedScan) return
    await runAction(`report-${format}`, () =>
      api.generateReport({ scanId: selectedScan.scan.id, format, redacted: true })
    )
    setReports(await api.listReports(selectedScan.scan.id))
  }

  async function exportReport(reportId: string): Promise<void> {
    await runAction(`report-export-${reportId}`, () => api.exportReport({ reportId }))
    if (selectedScan) setReports(await api.listReports(selectedScan.scan.id))
  }

  async function searchKnowledge(): Promise<void> {
    const result = await runAction('knowledge-search', () =>
      api.searchKnowledge({ query: knowledgeQuery, families: [], limit: 50 })
    )
    if (result) setKnowledge(result)
  }

  async function saveProfile(): Promise<void> {
    const result = await runAction('profile-save', () =>
      api.saveModelProfile({
        ...(profileForm.id ? { id: profileForm.id } : {}),
        name: profileForm.name,
        agentRole: profileForm.agentRole,
        provider: 'openai-compatible',
        baseUrl: profileForm.baseUrl,
        model: profileForm.model,
        ...(profileForm.apiKey ? { apiKey: profileForm.apiKey } : {}),
        timeoutMs: profileForm.timeoutMs,
        rpmLimit: profileForm.rpmLimit,
        tpmLimit: profileForm.tpmLimit,
        tokenBudget: profileForm.tokenBudget,
        costBudget: profileForm.costBudget
      })
    )
    if (!result) return
    setProfiles(await api.listModelProfiles())
    setProfileForm(createEmptyProfileForm())
  }

  function editProfile(profile: ModelProfileRecord): void {
    if (profile.provider !== 'openai-compatible') return
    setProfileForm({
      id: profile.id,
      name: profile.name,
      agentRole: profile.agentRole,
      baseUrl: profile.baseUrl ?? 'https://api.openai.com/v1/',
      model: profile.model,
      apiKey: '',
      timeoutMs: profile.timeoutMs,
      rpmLimit: profile.rpmLimit,
      tpmLimit: profile.tpmLimit,
      tokenBudget: profile.tokenBudget,
      costBudget: profile.costBudget
    })
  }

  async function testProfile(id: string): Promise<void> {
    const result = await runAction(`profile-test-${id}`, () => api.testModelProfile(id))
    if (result) window.alert(result.message)
  }

  async function deleteProfile(id: string): Promise<void> {
    await runAction(`profile-delete-${id}`, () => api.deleteModelProfile(id))
    setProfiles(await api.listModelProfiles())
  }

  const viewTitle = navItems.find((item) => item.id === view)?.label ?? 'AgentGo'

  if (loading) {
    return (
      <div className="boot-screen">
        <LoaderCircle className="spin" />
        <span>正在初始化本地数据库与安全服务…</span>
      </div>
    )
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-icon"><ShieldCheck size={21} /></div>
          <div><strong>AgentGo</strong><span>授权漏洞验证工作台</span></div>
        </div>
        <nav className="main-nav">
          {navItems.map(({ id, label, icon: Icon }) => (
            <button key={id} className={view === id ? 'active' : ''} onClick={() => setView(id)}>
              <Icon size={18} /><span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-note">
          <ShieldCheck size={17} />
          <div><strong>确定性安全门禁</strong><span>仅限明确授权目标</span></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div><span>{activeWorkspace?.name ?? '未选择工作区'}</span><h1>{viewTitle}</h1></div>
          <div className="topbar-controls">
            <select value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)}>
              {workspaces.map((workspace) => <option key={workspace.id} value={workspace.id}>{workspace.name}</option>)}
            </select>
            <StatusPill value={bootstrap?.milestone ?? 'V1'} />
          </div>
        </header>

        <div className="page-content">
          {error ? <div className="alert error"><CircleAlert size={18} /><span>{error}</span><button onClick={() => setError('')}>关闭</button></div> : null}
          {view === 'dashboard' ? (
            <DashboardView
              dashboard={dashboard}
              scans={scans}
              findings={findings}
              bootstrap={bootstrap}
              selfCheck={selfCheck}
              busy={busy}
              workspaceForm={workspaceForm}
              setWorkspaceForm={setWorkspaceForm}
              createWorkspace={createWorkspace}
              deleteWorkspace={deleteWorkspace}
              activeWorkspace={activeWorkspace}
              runSelfCheck={async () => {
                const result = await runAction('self-check', () => api.runPolicySelfCheck())
                if (result) setSelfCheck(result)
              }}
              openScan={(id) => { setView('scans'); void selectScan(id) }}
            />
          ) : null}
          {view === 'targets' ? (
            <TargetsView
              targets={targets}
              selected={selectedTarget}
              form={targetForm}
              setForm={setTargetForm}
              identityForm={identityForm}
              setIdentityForm={setIdentityForm}
              busy={busy}
              createTarget={createTarget}
              selectTarget={selectTarget}
              deleteTarget={deleteTarget}
              saveIdentity={saveIdentity}
              deleteIdentity={deleteIdentity}
            />
          ) : null}
          {view === 'scans' ? (
            <ScansView
              targets={targets}
              scans={scans}
              profiles={profiles}
              selectedTarget={selectedTarget}
              selectedScan={selectedScan}
              reports={reports}
              form={scanForm}
              setForm={setScanForm}
              busy={busy}
              createScan={createScan}
              controlScan={controlScan}
              selectScan={selectScan}
              generateReport={generateReport}
              exportReport={exportReport}
            />
          ) : null}
          {view === 'findings' ? <FindingsView findings={findings} scans={scans} openScan={(id) => { setView('scans'); void selectScan(id) }} /> : null}
          {view === 'audit' ? <AuditView logs={auditLogs} scans={scans} /> : null}
          {view === 'knowledge' ? <KnowledgeView query={knowledgeQuery} setQuery={setKnowledgeQuery} entries={knowledge} search={searchKnowledge} busy={busy} /> : null}
          {view === 'settings' ? <SettingsView profiles={profiles} form={profileForm} setForm={setProfileForm} busy={busy} save={saveProfile} test={testProfile} edit={editProfile} remove={deleteProfile} reset={() => setProfileForm(createEmptyProfileForm())} /> : null}
        </div>
      </main>
    </div>
  )
}

function uniqueValues<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function DashboardView(props: {
  dashboard?: DashboardSnapshot
  scans: ScanRecord[]
  findings: FindingRecord[]
  bootstrap?: BootstrapState
  selfCheck?: PolicySelfCheckResult
  busy: string
  workspaceForm: { name: string; description: string }
  setWorkspaceForm: React.Dispatch<React.SetStateAction<{ name: string; description: string }>>
  createWorkspace: () => Promise<void>
  deleteWorkspace: () => Promise<void>
  activeWorkspace?: WorkspaceRecord
  runSelfCheck: () => Promise<void>
  openScan: (id: string) => void
}): React.JSX.Element {
  const cards = [
    ['目标', props.dashboard?.targetCount ?? 0, Crosshair],
    ['活动扫描', props.dashboard?.activeScanCount ?? 0, Activity],
    ['Confirmed', props.dashboard?.confirmedFindingCount ?? 0, CheckCircle2],
    ['本地工作区', props.dashboard?.workspaceCount ?? 0, Database]
  ] as const
  return (
    <>
      <section className="summary-grid">
        {cards.map(([label, value, Icon]) => <article className="metric-card" key={label}><Icon size={20} /><span>{label}</span><strong>{value}</strong></article>)}
      </section>
      <section className="two-column">
        <article className="panel">
          <div className="panel-header"><div><span className="eyebrow">CORE STATUS</span><h2>V1 核心闭环</h2></div><StatusPill value={props.bootstrap?.milestone ?? 'V1'} /></div>
          <p className="muted">{props.bootstrap?.projectStatus}</p>
          <div className="capability-list">
            {props.bootstrap?.vulnerabilityFamilies.map((family) => <div key={family}><strong>{familyLabels[family]}</strong><span>Signal → Validation → Verdict → Evidence → Report</span></div>)}
          </div>
        </article>
        <article className="panel">
          <div className="panel-header"><div><span className="eyebrow">SECURITY POLICY</span><h2>安全门禁自检</h2></div><ActionButton icon={RefreshCw} onClick={props.runSelfCheck} busy={props.busy === 'self-check'}>运行</ActionButton></div>
          {props.selfCheck ? <div className="policy-results"><div><StatusPill value={props.selfCheck.safeProbe.allowed ? 'allowed' : 'blocked'} /><p>{props.selfCheck.safeProbe.reasons.join('；')}</p></div><div><StatusPill value={props.selfCheck.destructiveProbe.allowed ? 'allowed' : 'blocked'} /><p>{props.selfCheck.destructiveProbe.reasons.join('；')}</p></div></div> : <EmptyState icon={ShieldCheck}>尚未运行策略自检。</EmptyState>}
        </article>
      </section>
      <section className="two-column">
        <article className="panel">
          <div className="panel-header"><div><span className="eyebrow">RECENT RUNS</span><h2>最近扫描</h2></div></div>
          {props.scans.length ? <div className="table-wrap"><table><thead><tr><th>任务</th><th>阶段</th><th>状态</th><th /></tr></thead><tbody>{props.scans.slice(0, 6).map((scan) => <tr key={scan.id}><td>{scan.name}</td><td>{phaseLabels[scan.phase]}</td><td><StatusPill value={scan.status} /></td><td><button className="icon-link" title="打开扫描" onClick={() => props.openScan(scan.id)}><ChevronRight size={17} /></button></td></tr>)}</tbody></table></div> : <EmptyState icon={Radar}>还没有扫描任务。</EmptyState>}
        </article>
        <article className="panel">
          <div className="panel-header"><div><span className="eyebrow">WORKSPACE</span><h2>新建工作区</h2></div></div>
          <div className="form-grid one"><label>名称<input value={props.workspaceForm.name} onChange={(event) => props.setWorkspaceForm((current) => ({ ...current, name: event.target.value }))} /></label><label>说明<textarea value={props.workspaceForm.description} onChange={(event) => props.setWorkspaceForm((current) => ({ ...current, description: event.target.value }))} /></label><ActionButton icon={Plus} kind="primary" onClick={props.createWorkspace} busy={props.busy === 'workspace-create'} disabled={!props.workspaceForm.name}>创建工作区</ActionButton>{props.activeWorkspace ? <ActionButton icon={Trash2} kind="danger" onClick={props.deleteWorkspace} busy={props.busy === 'workspace-delete'}>删除当前工作区及本地数据</ActionButton> : null}</div>
        </article>
      </section>
    </>
  )
}

function TargetsView(props: {
  targets: TargetRecord[]
  selected?: TargetDetail
  form: { name: string; baseUrl: string; description: string; authorizationReference: string; allowedOrigins: string; allowedPaths: string; deniedPaths: string; allowLoopback: boolean; allowPrivate: boolean; maxRpm: number; maxConcurrency: number }
  setForm: React.Dispatch<React.SetStateAction<TargetsViewProps['form']>>
  identityForm: { label: string; role: string; authType: IdentityAuthType; headerName: string; secret: string; ownedResourceIds: string; includeInScope: boolean }
  setIdentityForm: React.Dispatch<React.SetStateAction<TargetsViewProps['identityForm']>>
  busy: string
  createTarget: () => Promise<void>
  selectTarget: (id: string) => Promise<void>
  deleteTarget: (id: string) => Promise<void>
  saveIdentity: () => Promise<void>
  deleteIdentity: (id: string) => Promise<void>
}): React.JSX.Element {
  return (
    <div className="split-layout">
      <section className="panel list-panel">
        <div className="panel-header"><div><span className="eyebrow">AUTHORIZED TARGETS</span><h2>目标</h2></div><span className="count">{props.targets.length}</span></div>
        <div className="selection-list">{props.targets.map((target) => <button key={target.id} className={props.selected?.target.id === target.id ? 'selected' : ''} onClick={() => props.selectTarget(target.id)}><Crosshair size={17} /><div><strong>{target.name}</strong><span>{target.baseUrl}</span></div><ChevronRight size={16} /></button>)}</div>
        {!props.targets.length ? <EmptyState icon={Crosshair}>先创建一个明确授权的目标。</EmptyState> : null}
      </section>
      <div className="stack">
        <section className="panel">
          <div className="panel-header"><div><span className="eyebrow">SCOPE INTAKE</span><h2>新建授权目标</h2></div></div>
          <div className="form-grid two">
            <label>目标名称<input value={props.form.name} onChange={(event) => props.setForm((current) => ({ ...current, name: event.target.value }))} /></label>
            <label>Base URL<input value={props.form.baseUrl} onChange={(event) => props.setForm((current) => ({ ...current, baseUrl: event.target.value }))} /></label>
            <label className="span-2">授权依据<input placeholder="审批单、靶场所有权或书面授权引用" value={props.form.authorizationReference} onChange={(event) => props.setForm((current) => ({ ...current, authorizationReference: event.target.value }))} /></label>
            <label>允许 Origin（逗号分隔）<input placeholder="默认采用 Base URL Origin" value={props.form.allowedOrigins} onChange={(event) => props.setForm((current) => ({ ...current, allowedOrigins: event.target.value }))} /></label>
            <label>允许路径<input value={props.form.allowedPaths} onChange={(event) => props.setForm((current) => ({ ...current, allowedPaths: event.target.value }))} /></label>
            <label>拒绝路径<input value={props.form.deniedPaths} onChange={(event) => props.setForm((current) => ({ ...current, deniedPaths: event.target.value }))} /></label>
            <label>每分钟请求上限<input type="number" min="1" max="600" value={props.form.maxRpm} onChange={(event) => props.setForm((current) => ({ ...current, maxRpm: Number(event.target.value) }))} /></label>
            <label>最大并发<input type="number" min="1" max="10" value={props.form.maxConcurrency} onChange={(event) => props.setForm((current) => ({ ...current, maxConcurrency: Number(event.target.value) }))} /></label>
            <label className="check-row"><input type="checkbox" checked={props.form.allowLoopback} onChange={(event) => props.setForm((current) => ({ ...current, allowLoopback: event.target.checked }))} />显式授权回环目标</label>
            <label className="check-row"><input type="checkbox" checked={props.form.allowPrivate} onChange={(event) => props.setForm((current) => ({ ...current, allowPrivate: event.target.checked }))} />显式授权私网目标</label>
          </div>
          <div className="panel-actions"><ActionButton icon={Plus} kind="primary" onClick={props.createTarget} busy={props.busy === 'target-create'} disabled={!props.form.name || !props.form.authorizationReference}>创建目标与不可变 Scope 快照</ActionButton></div>
        </section>
        {props.selected ? <section className="panel"><div className="panel-header"><div><span className="eyebrow">TARGET DETAIL</span><h2>{props.selected.target.name}</h2></div><ActionButton icon={Trash2} kind="danger" onClick={() => props.deleteTarget(props.selected!.target.id)} busy={props.busy === `target-delete-${props.selected.target.id}`}>删除</ActionButton></div><div className="detail-grid"><div><span>Base URL</span><strong>{props.selected.target.baseUrl}</strong></div><div><span>Scope 快照</span><code>{props.selected.scope.id}</code></div><div><span>允许 Origin</span><strong>{props.selected.scope.allowedOrigins.join('、')}</strong></div><div><span>身份范围</span><strong>{props.selected.scope.allowedIdentityIds.length} 个测试身份</strong></div></div><hr /><h3>测试身份与资源归属</h3><div className="identity-list">{props.selected.identities.map((identity) => <div key={identity.id}><Users size={17} /><div><strong>{identity.label} · {identity.role}</strong><span>{identity.authType} · 资源 {identity.ownedResourceIds.join('、') || '未配置'} · {props.selected!.scope.allowedIdentityIds.includes(identity.id) ? '已在 Scope' : '未在 Scope'}</span></div><button className="icon-link danger" title="删除身份" onClick={() => props.deleteIdentity(identity.id)}><Trash2 size={16} /></button></div>)}</div><div className="form-grid two compact"><label>身份标签<input value={props.identityForm.label} onChange={(event) => props.setIdentityForm((current) => ({ ...current, label: event.target.value }))} /></label><label>角色<input value={props.identityForm.role} onChange={(event) => props.setIdentityForm((current) => ({ ...current, role: event.target.value }))} /></label><label>认证类型<select value={props.identityForm.authType} onChange={(event) => props.setIdentityForm((current) => ({ ...current, authType: event.target.value as IdentityAuthType }))}><option value="none">无</option><option value="bearer">Bearer</option><option value="cookie">Cookie</option><option value="basic">Basic</option><option value="header">自定义 Header</option></select></label>{props.identityForm.authType === 'header' ? <label>Header 名称<input value={props.identityForm.headerName} onChange={(event) => props.setIdentityForm((current) => ({ ...current, headerName: event.target.value }))} /></label> : null}{props.identityForm.authType !== 'none' ? <label>凭据（safeStorage）<input type="password" value={props.identityForm.secret} onChange={(event) => props.setIdentityForm((current) => ({ ...current, secret: event.target.value }))} /></label> : null}<label>已知归属测试资源 ID<input placeholder="IDOR 用，逗号分隔" value={props.identityForm.ownedResourceIds} onChange={(event) => props.setIdentityForm((current) => ({ ...current, ownedResourceIds: event.target.value }))} /></label><label className="check-row span-2"><input type="checkbox" checked={props.identityForm.includeInScope} onChange={(event) => props.setIdentityForm((current) => ({ ...current, includeInScope: event.target.checked }))} />同时创建新的 Scope 快照并纳入该身份</label></div><ActionButton icon={KeyRound} kind="primary" onClick={props.saveIdentity} busy={props.busy === 'identity-save'} disabled={!props.identityForm.label || (props.identityForm.authType !== 'none' && !props.identityForm.secret)}>保存测试身份</ActionButton></section> : null}
      </div>
    </div>
  )
}

type TargetsViewProps = Parameters<typeof TargetsView>[0]

function ScansView(props: {
  targets: TargetRecord[]
  scans: ScanRecord[]
  profiles: ModelProfileRecord[]
  selectedTarget?: TargetDetail
  selectedScan?: ScanDetail
  reports: ReportRecord[]
  form: ScanFormState
  setForm: React.Dispatch<React.SetStateAction<ScanFormState>>
  busy: string
  createScan: () => Promise<void>
  controlScan: (scan: ScanRecord, action: ScanControlAction) => Promise<void>
  selectScan: (id: string) => Promise<void>
  generateReport: (format: 'markdown' | 'json' | 'html') => Promise<void>
  exportReport: (id: string) => Promise<void>
}): React.JSX.Element {
  const selectedProfiles = agentRoles
    .map((role) =>
      props.profiles.find((profile) => profile.id === props.form.modelProfileIds[role])
    )
    .filter((profile): profile is ModelProfileRecord => Boolean(profile))
  const externalProfiles = selectedProfiles
    .filter((profile) => profile.provider === 'openai-compatible')
    .filter(
      (profile, index, values) =>
        values.findIndex((candidate) => candidate.id === profile.id) === index
    )
  const hasAllAgentProfiles = agentRoles.every((role) =>
    props.profiles.some(
      (profile) =>
        profile.id === props.form.modelProfileIds[role] && profile.agentRole === role
    )
  )

  const updateModelProfile = (role: AgentRole, profileId: string): void => {
    props.setForm((current) => {
      const modelProfileIds = { ...current.modelProfileIds }
      if (profileId) modelProfileIds[role] = profileId
      else delete modelProfileIds[role]
      return { ...current, modelProfileIds }
    })
  }

  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-header">
          <div><span className="eyebrow">NEW SCAN</span><h2>创建扫描任务</h2></div>
        </div>
        <div className="form-grid two">
          <label>
            目标
            <select value={props.form.targetId} onChange={(event) => props.setForm((current) => ({ ...current, targetId: event.target.value }))}>
              <option value="">选择目标</option>
              {props.targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}
            </select>
          </label>
          <label>
            任务名称
            <input value={props.form.name} onChange={(event) => props.setForm((current) => ({ ...current, name: event.target.value }))} />
          </label>
          <label className="span-2">
            任务与授权背景（发送给 PlannerAgent）
            <textarea
              rows={5}
              maxLength={4_000}
              placeholder="说明本次授权测试的业务背景、目标、已知限制、期望关注点和授权边界。不要填写 API Key、Cookie、Authorization、Token 或密码。"
              value={props.form.description}
              onChange={(event) => props.setForm((current) => ({ ...current, description: event.target.value }))}
            />
          </label>
          <fieldset>
            <legend>漏洞族</legend>
            <div className="check-group">
              {(Object.keys(familyLabels) as VulnerabilityFamily[]).map((family) => (
                <label key={family}>
                  <input
                    type="checkbox"
                    checked={props.form.families.includes(family)}
                    onChange={(event) => props.setForm((current) => ({
                      ...current,
                      families: event.target.checked
                        ? uniqueValues([...current.families, family])
                        : current.families.filter((item) => item !== family)
                    }))}
                  />
                  {familyLabels[family]}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend>授权测试身份</legend>
            <div className="check-group">
              {props.selectedTarget?.identities.map((identity) => (
                <label key={identity.id}>
                  <input
                    type="checkbox"
                    disabled={!props.selectedTarget?.scope.allowedIdentityIds.includes(identity.id)}
                    checked={props.form.identityIds.includes(identity.id)}
                    onChange={(event) => props.setForm((current) => ({
                      ...current,
                      identityIds: event.target.checked
                        ? uniqueValues([...current.identityIds, identity.id])
                        : current.identityIds.filter((id) => id !== identity.id)
                    }))}
                  />
                  {identity.label}
                </label>
              )) ?? <span className="muted">无身份</span>}
            </div>
          </fieldset>
          <fieldset className="span-2">
            <legend>扫描级 Multi-Agent 模型路由</legend>
            <div className="agent-profile-grid">
              {agentRoles.map((role) => (
                <label key={role}>
                  {agentRoleLabels[role]}
                  <select
                    value={props.form.modelProfileIds[role] ?? ''}
                    onChange={(event) => updateModelProfile(role, event.target.value)}
                  >
                    <option value="">未选择</option>
                    {props.profiles
                      .filter((profile) => profile.agentRole === role)
                      .map((profile) => (
                        <option key={profile.id} value={profile.id}>
                          {profile.name} · {profile.provider} · {profile.model} · {profile.baseUrl ?? '本地执行'}
                        </option>
                      ))}
                  </select>
                </label>
              ))}
            </div>
          </fieldset>
          <div className={`model-routing-note span-2 ${externalProfiles.length ? 'external' : 'local'}`}>
            <Bot size={17} />
            <div>
              <strong>{externalProfiles.length ? '将真实调用外部模型' : '当前不会调用外部大模型'}</strong>
              <span>
                {externalProfiles.length
                  ? `任务描述与结构化上下文会先脱敏，再发送至：${externalProfiles.map((profile) => `${profile.name}（${profile.baseUrl} / ${profile.model}）`).join('；')}。`
                  : '五个 Agent 当前全部选择本地确定性 Profile；可在“模型设置”添加并测试 OpenAI-compatible Profile。'}
              </span>
            </div>
          </div>
          <label>
            SSRF 受控回调 URL
            <input placeholder="必须也在当前 Scope 内" value={props.form.callbackUrl} onChange={(event) => props.setForm((current) => ({ ...current, callbackUrl: event.target.value }))} />
          </label>
          <label>
            最大请求数
            <input type="number" min="10" max="10000" value={props.form.maxRequests} onChange={(event) => props.setForm((current) => ({ ...current, maxRequests: Number(event.target.value) }))} />
          </label>
          <label>
            最长运行时间（分钟）
            <input type="number" min="1" max="1440" value={props.form.maxDurationMinutes} onChange={(event) => props.setForm((current) => ({ ...current, maxDurationMinutes: Number(event.target.value) }))} />
          </label>
        </div>
        <div className="panel-actions">
          <ActionButton
            icon={Plus}
            kind="primary"
            onClick={props.createScan}
            busy={props.busy === 'scan-create'}
            disabled={
              !props.form.targetId ||
              !props.form.name.trim() ||
              !props.form.description.trim() ||
              !props.form.families.length ||
              !hasAllAgentProfiles
            }
          >
            创建草稿并冻结 Agent 路由
          </ActionButton>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <div><span className="eyebrow">SCAN QUEUE</span><h2>任务列表</h2></div>
          <span className="count">{props.scans.length}</span>
        </div>
        {props.scans.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>任务</th><th>目标</th><th>阶段</th><th>进度</th><th>状态</th><th>控制</th></tr></thead>
              <tbody>
                {props.scans.map((scan) => (
                  <tr key={scan.id} className={props.selectedScan?.scan.id === scan.id ? 'selected-row' : ''}>
                    <td><button className="text-link" onClick={() => props.selectScan(scan.id)}>{scan.name}</button></td>
                    <td>{scan.targetName}</td>
                    <td>{phaseLabels[scan.phase]}</td>
                    <td>{scan.progress}% · {scan.requestCount}/{scan.budget.maxRequests}</td>
                    <td><StatusPill value={scan.status} /></td>
                    <td>
                      <div className="row-actions">
                        {scan.status === 'draft' ? <button title="启动" onClick={() => props.controlScan(scan, 'start')}><Play size={16} /></button> : null}
                        {scan.status === 'running' || scan.status === 'queued' ? <button title="暂停" onClick={() => props.controlScan(scan, 'pause')}><Pause size={16} /></button> : null}
                        {scan.status === 'paused' || scan.status === 'awaiting-user' ? <button title="恢复" onClick={() => props.controlScan(scan, 'resume')}><Play size={16} /></button> : null}
                        {!['completed', 'failed', 'cancelled'].includes(scan.status) ? <button title="取消" onClick={() => props.controlScan(scan, 'cancel')}><Square size={15} /></button> : null}
                        <button title="详情" onClick={() => props.selectScan(scan.id)}><ChevronRight size={16} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState icon={Radar}>没有扫描任务。</EmptyState>}
      </section>
      {props.selectedScan ? (
        <ScanConsole
          detail={props.selectedScan}
          profiles={props.profiles}
          reports={props.reports}
          busy={props.busy}
          generateReport={props.generateReport}
          exportReport={props.exportReport}
        />
      ) : null}
    </div>
  )
}

function ScanConsole(props: { detail: ScanDetail; profiles: ModelProfileRecord[]; reports: ReportRecord[]; busy: string; generateReport: (format: 'markdown' | 'json' | 'html') => Promise<void>; exportReport: (id: string) => Promise<void> }): React.JSX.Element {
  const { detail } = props
  return (
    <section className="panel">
      <div className="panel-header">
        <div><span className="eyebrow">AGENT CONSOLE</span><h2>{detail.scan.name}</h2></div>
        <div className="inline-status"><StatusPill value={detail.scan.status} /><span>{phaseLabels[detail.scan.phase]} · {detail.scan.progress}%</span></div>
      </div>
      {detail.scan.lastError ? <div className="alert error"><CircleAlert size={17} />{detail.scan.lastError}</div> : null}
      <div className="detail-grid scan-context-grid">
        <div className="span-2">
          <span>任务与授权背景</span>
          <strong className="scan-description">{detail.scan.description || '旧任务未记录描述'}</strong>
        </div>
        {agentRoles.map((role) => {
          const profileId = detail.scan.modelProfileIds[role]
          const profile = props.profiles.find((candidate) => candidate.id === profileId)
          return (
            <div key={role}>
              <span>{agentRoleLabels[role]}</span>
              <strong>{profile ? `${profile.name} · ${profile.provider} · ${profile.model}` : 'Profile 不可用或旧任务未记录'}</strong>
              {profileId ? <code>{profileId}</code> : null}
            </div>
          )
        })}
      </div>
      <hr />
      <div className="console-grid">
        <div>
          <h3>阶段事件</h3>
          <div className="event-list">{detail.events.slice(-80).reverse().map((event) => <div key={event.id} className={event.level}><span>{new Date(event.createdAt).toLocaleTimeString()}</span><strong>{event.message}</strong></div>)}</div>
        </div>
        <div>
          <h3>发现的接口</h3>
          <div className="endpoint-list">{detail.endpoints.map((endpoint) => <div key={endpoint.id}><code>{endpoint.method}</code><span>{endpoint.url}</span><small>{endpoint.parameters.map((parameter) => parameter.name).join('、') || '无参数'}</small></div>)}</div>
          <h3>证据与 Findings</h3>
          <div className="mini-stats"><div><strong>{detail.evidence.length}</strong><span>证据项</span></div><div><strong>{detail.findings.length}</strong><span>Findings</span></div><div><strong>{detail.findings.filter((item) => item.verdict === 'confirmed').length}</strong><span>Confirmed</span></div></div>
        </div>
      </div>
      <hr />
      <div className="panel-header">
        <div><h3>报告</h3><span className="muted">默认生成脱敏版本；HTML 带严格 CSP。</span></div>
        <div className="row-actions"><ActionButton onClick={() => props.generateReport('markdown')} busy={props.busy === 'report-markdown'}>Markdown</ActionButton><ActionButton onClick={() => props.generateReport('json')} busy={props.busy === 'report-json'}>JSON</ActionButton><ActionButton onClick={() => props.generateReport('html')} busy={props.busy === 'report-html'}>HTML</ActionButton></div>
      </div>
      <div className="report-list">{props.reports.map((report) => <div key={report.id}><FileSearch size={17} /><div><strong>{report.title}</strong><span>{report.format} · {report.redacted ? '已脱敏' : '原始'} · {new Date(report.createdAt).toLocaleString()}</span></div><ActionButton icon={Download} kind="quiet" onClick={() => props.exportReport(report.id)} busy={props.busy === `report-export-${report.id}`}>导出</ActionButton></div>)}</div>
    </section>
  )
}

function FindingsView(props: { findings: FindingRecord[]; scans: ScanRecord[]; openScan: (id: string) => void }): React.JSX.Element {
  const scanNames = new Map(props.scans.map((scan) => [scan.id, scan.name]))
  return <section className="panel"><div className="panel-header"><div><span className="eyebrow">EVIDENCE-BACKED RESULTS</span><h2>Findings</h2></div><span className="count">{props.findings.length}</span></div>{props.findings.length ? <div className="finding-list">{props.findings.map((finding) => <article key={finding.id}><div className="finding-title"><div><StatusPill value={verdictLabels[finding.verdict]} /><StatusPill value={finding.severity} /></div><button className="icon-link" title="打开所属扫描" onClick={() => props.openScan(finding.scanId)}><ChevronRight size={17} /></button></div><h3>{finding.title}</h3><p>{finding.reproducibility}</p><div className="finding-meta"><span>{scanNames.get(finding.scanId)}</span><span>{finding.endpointUrl}</span><span>{finding.parameterName}</span><code>{finding.confirmationRuleId}@{finding.confirmationRuleVersion}</code><span>{finding.evidenceRefs.length} 项证据</span></div><ul>{finding.remediation.map((item) => <li key={item}>{item}</li>)}</ul></article>)}</div> : <EmptyState icon={FileSearch}>尚无 Findings；未验证的假设不会显示为 Confirmed。</EmptyState>}</section>
}

function AuditView(props: { logs: AuditLogRecord[]; scans: ScanRecord[] }): React.JSX.Element {
  const scanNames = new Map(props.scans.map((scan) => [scan.id, scan.name]))
  return (
    <section className="panel">
      <div className="panel-header">
        <div><span className="eyebrow">IMMUTABLE ACTIVITY</span><h2>工作区审计日志</h2></div>
        <span className="count">{props.logs.length}</span>
      </div>
      {props.logs.length ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>时间</th><th>事件</th><th>执行者</th><th>扫描</th><th>详情</th></tr></thead>
            <tbody>
              {props.logs.map((entry) => (
                <tr key={entry.id}>
                  <td>{new Date(entry.createdAt).toLocaleString()}</td>
                  <td><code>{entry.event}</code></td>
                  <td>{entry.actor}</td>
                  <td>{entry.scanId ? scanNames.get(entry.scanId) ?? entry.scanId : '-'}</td>
                  <td><code>{JSON.stringify(entry.detail)}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <EmptyState icon={Activity}>当前工作区尚无审计事件。</EmptyState>}
    </section>
  )
}

function KnowledgeView(props: { query: string; setQuery: (value: string) => void; entries: KnowledgeEntrySummary[]; search: () => Promise<void>; busy: string }): React.JSX.Element {
  return <section className="panel"><div className="panel-header"><div><span className="eyebrow">CURATED KNOWLEDGE</span><h2>V1 知识条目</h2></div></div><div className="search-row"><Search size={18} /><input placeholder="检索适用性、信号或修复建议" value={props.query} onChange={(event) => props.setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void props.search() }} /><ActionButton onClick={props.search} busy={props.busy === 'knowledge-search'}>检索</ActionButton></div>{props.entries.length ? <div className="knowledge-grid">{props.entries.map((entry) => <article key={entry.id}><div><StatusPill value={entry.family} /><code>{entry.version}</code></div><h3>{entry.title}</h3><p>{entry.applicability.join('；')}</p><h4>确认规则</h4><ul>{entry.confirmationRules.map((item) => <li key={item}>{item}</li>)}</ul><h4>来源</h4><small>{entry.sourceTitles.join('、')}</small></article>)}</div> : <EmptyState icon={BookOpen}>输入关键词检索，或留空查看全部内置条目。</EmptyState>}</section>
}

function SettingsView(props: {
  profiles: ModelProfileRecord[]
  form: ModelProfileForm
  setForm: React.Dispatch<React.SetStateAction<ModelProfileForm>>
  busy: string
  save: () => Promise<void>
  test: (id: string) => Promise<void>
  edit: (profile: ModelProfileRecord) => void
  remove: (id: string) => Promise<void>
  reset: () => void
}): React.JSX.Element {
  const setNumber = (
    field: 'timeoutMs' | 'rpmLimit' | 'tpmLimit' | 'tokenBudget' | 'costBudget',
    value: string
  ): void => props.setForm((current) => ({ ...current, [field]: Number(value) }))

  return (
    <div className="two-column">
      <section className="panel">
        <div className="panel-header"><div><span className="eyebrow">MODEL GATEWAY</span><h2>模型 Profiles</h2></div></div>
        <div className="profile-list">
          {props.profiles.map((profile) => (
            <article key={profile.id}>
              <Bot size={19} />
              <div>
                <strong>{profile.name}</strong>
                <span>{profile.agentRole} · {profile.provider} · {profile.model}</span>
                <small>{profile.baseUrl ?? '本地确定性规则'} · Key {profile.credentialId ? '已安全保存' : '不需要'}</small>
                <small>{profile.timeoutMs / 1000}s · {profile.rpmLimit} RPM · {profile.tpmLimit} TPM · Token {profile.tokenBudget} · 费用 {profile.costBudget}</small>
              </div>
              <div className="row-actions">
                <button title="连接测试" onClick={() => props.test(profile.id)}><Gauge size={16} /></button>
                {profile.provider !== 'deterministic' ? (
                  <>
                    <button title="编辑" onClick={() => props.edit(profile)}><Pencil size={16} /></button>
                    <button title="删除" onClick={() => props.remove(profile.id)}><Trash2 size={16} /></button>
                  </>
                ) : null}
              </div>
            </article>
          ))}
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <div><span className="eyebrow">OPENAI-COMPATIBLE</span><h2>{props.form.id ? '编辑 Provider' : '添加 Provider'}</h2></div>
        </div>
        <p className="muted">API Key 仅写入 Electron safeStorage 加密凭据文件；编辑时留空会保留已有凭据。</p>
        <div className="form-grid two">
          <label>名称<input value={props.form.name} onChange={(event) => props.setForm((current) => ({ ...current, name: event.target.value }))} /></label>
          <label>Agent 角色<select value={props.form.agentRole} onChange={(event) => props.setForm((current) => ({ ...current, agentRole: event.target.value as ModelProfileRecord['agentRole'] }))}>{['planner', 'knowledge', 'strategy', 'analysis', 'verifier'].map((role) => <option key={role} value={role}>{role}</option>)}</select></label>
          <label className="span-2">Base URL<input value={props.form.baseUrl} onChange={(event) => props.setForm((current) => ({ ...current, baseUrl: event.target.value }))} /></label>
          <label>模型<input value={props.form.model} onChange={(event) => props.setForm((current) => ({ ...current, model: event.target.value }))} /></label>
          <label>API Key<input type="password" value={props.form.apiKey} onChange={(event) => props.setForm((current) => ({ ...current, apiKey: event.target.value }))} /></label>
          <label>超时（毫秒）<input type="number" min="1000" max="120000" value={props.form.timeoutMs} onChange={(event) => setNumber('timeoutMs', event.target.value)} /></label>
          <label>RPM 上限<input type="number" min="1" max="10000" value={props.form.rpmLimit} onChange={(event) => setNumber('rpmLimit', event.target.value)} /></label>
          <label>TPM 上限<input type="number" min="1" max="10000000" value={props.form.tpmLimit} onChange={(event) => setNumber('tpmLimit', event.target.value)} /></label>
          <label>Token 总预算<input type="number" min="1" value={props.form.tokenBudget} onChange={(event) => setNumber('tokenBudget', event.target.value)} /></label>
          <label>费用预算<input type="number" min="0" step="0.01" value={props.form.costBudget} onChange={(event) => setNumber('costBudget', event.target.value)} /></label>
        </div>
        <div className="panel-actions">
          {props.form.id ? <ActionButton onClick={props.reset}>取消编辑</ActionButton> : null}
          <ActionButton icon={props.form.id ? Pencil : Plus} kind="primary" onClick={props.save} busy={props.busy === 'profile-save'} disabled={!props.form.name || !props.form.model || (!props.form.id && !props.form.apiKey)}>保存 Profile</ActionButton>
        </div>
      </section>
    </div>
  )
}
