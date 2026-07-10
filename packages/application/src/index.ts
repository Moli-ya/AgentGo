import {
  V1_AGENT_ROLES,
  createDefaultScanPlan,
  createRuntimeState,
  transitionRuntime,
  type ScanRuntimeState
} from '@agentgo/agent-runtime'
import type {
  AgentModelProfileSelection,
  AgentRole,
  CreateScanInput,
  CreateTargetInput,
  CreateWorkspaceInput,
  DashboardSnapshot,
  DeleteResult,
  FindingRecord,
  GenerateReportInput,
  IdentityRecord,
  KnowledgeEntrySummary,
  KnowledgeSearchInput,
  ModelProfileRecord,
  ReportRecord,
  SaveModelProfileInput,
  SaveIdentityInput,
  ScanControlAction,
  ScanDetail,
  ScanRecord,
  TargetDetail,
  TargetRecord,
  UpdateTargetInput,
  WorkspaceRecord
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore
} from '@agentgo/db'
import {
  KNOWLEDGE_SOURCES,
  V1_KNOWLEDGE_ENTRIES
} from '@agentgo/knowledge-base'
import type { ModelGateway } from '@agentgo/model-gateway'
import { ReportService, type ReportContent } from './report-service'

export * from './execution-policy'
export * from './execution-service'
export * from './report-service'
export * from './agent-prompts'
export * from './scan-coordinator'
export * from './validation-engine'

export interface ScanCoordinator {
  control(scanId: string, action: ScanControlAction): Promise<ScanRecord>
}

export interface AgentGoApplicationDependencies {
  repository: AgentGoRepository
  credentialStore: FileCredentialStore
  evidenceStore?: EvidenceStore
  modelGateway?: ModelGateway
  reportService?: ReportService
  scanCoordinator?: ScanCoordinator
}

export class AgentGoApplicationService {
  private readonly repository: AgentGoRepository
  private readonly credentialStore: FileCredentialStore
  private readonly evidenceStore?: EvidenceStore
  private readonly modelGateway?: ModelGateway
  private readonly reportService?: ReportService
  private scanCoordinator?: ScanCoordinator

  constructor(dependencies: AgentGoApplicationDependencies) {
    this.repository = dependencies.repository
    this.credentialStore = dependencies.credentialStore
    this.evidenceStore = dependencies.evidenceStore
    this.modelGateway = dependencies.modelGateway
    this.reportService =
      dependencies.reportService ??
      (dependencies.evidenceStore
        ? new ReportService(dependencies.repository, dependencies.evidenceStore)
        : undefined)
    this.scanCoordinator = dependencies.scanCoordinator
  }

  setScanCoordinator(coordinator: ScanCoordinator): void {
    this.scanCoordinator = coordinator
  }

  async initialize(): Promise<void> {
    await this.repository.initializeDefaults()
    await this.ensureBuiltInKnowledgeIndex()
    await this.ensureDefaultModelProfiles()
    await this.recoverInterruptedScans()
  }

  getDashboard(workspaceId?: string): Promise<DashboardSnapshot> {
    return this.repository.getDashboardSnapshot(workspaceId)
  }

  listWorkspaces(): Promise<WorkspaceRecord[]> {
    return this.repository.listWorkspaces()
  }

  createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceRecord> {
    return this.repository.createWorkspace(input)
  }

  async deleteWorkspace(id: string): Promise<DeleteResult> {
    const targets = await this.repository.listTargets(id)
    const scans = (
      await Promise.all(targets.map((target) => this.repository.listScans({ targetId: target.id })))
    ).flat()
    if (scans.some((scan) => ['queued', 'running'].includes(scan.status))) {
      throw new Error('工作区包含正在运行的扫描，请先暂停或取消任务。')
    }
    const identities = (
      await Promise.all(targets.map((target) => this.repository.listIdentities(target.id)))
    ).flat()
    const deleted = await this.repository.deleteWorkspace(id)
    if (deleted) {
      for (const credentialId of new Set(
        identities
          .map((identity) => identity.credentialId)
          .filter((value): value is string => Boolean(value))
      )) {
        this.credentialStore.delete(credentialId)
      }
      this.evidenceStore?.deleteWorkspaceArtifacts(id)
    }
    return { deleted }
  }

  listTargets(workspaceId: string): Promise<TargetRecord[]> {
    return this.repository.listTargets(workspaceId)
  }

  async getTargetDetail(targetId: string): Promise<TargetDetail> {
    const target = await this.repository.getTarget(targetId)
    if (!target) throw new Error('目标不存在。')
    const scope = await this.repository.getLatestScope(targetId)
    if (!scope) throw new Error('目标缺少授权范围。')
    const identities = await this.repository.listIdentities(targetId)
    return { target, scope, identities }
  }

  async createTarget(input: CreateTargetInput): Promise<TargetDetail> {
    const created = await this.repository.createTarget(input)
    return { ...created, identities: [] }
  }

  async updateTarget(input: UpdateTargetInput): Promise<TargetDetail> {
    await this.repository.updateTarget(input)
    return this.getTargetDetail(input.id)
  }

  async deleteTarget(id: string): Promise<DeleteResult> {
    const target = await this.repository.getTarget(id)
    if (!target) return { deleted: false }
    const scans = await this.repository.listScans({ targetId: id })
    if (scans.some((scan) => ['queued', 'running'].includes(scan.status))) {
      throw new Error('目标包含正在运行的扫描，请先暂停或取消任务。')
    }
    const identities = await this.repository.listIdentities(id)
    const evidencePaths = this.evidenceStore
      ? (
          await Promise.all(
            scans.map(async (scan) =>
              (await this.evidenceStore!.list(scan.id)).map((item) => item.filePath)
            )
          )
        ).flat()
      : []
    const deleted = await this.repository.deleteTarget(id)
    if (deleted) {
      for (const credentialId of new Set(
        identities
          .map((identity) => identity.credentialId)
          .filter((value): value is string => Boolean(value))
      )) {
        this.credentialStore.delete(credentialId)
      }
      await this.evidenceStore?.deleteUnreferencedFiles(evidencePaths)
    }
    return { deleted }
  }

  async saveIdentity(input: SaveIdentityInput): Promise<IdentityRecord> {
    const existing = input.id
      ? await this.repository.getIdentity(input.id)
      : undefined
    let credentialId: string | null | undefined

    if (input.authType === 'none') {
      if (existing?.credentialId) this.credentialStore.delete(existing.credentialId)
      credentialId = null
    } else if (input.secret) {
      const metadata = this.credentialStore.save({
        ...(existing?.credentialId ? { id: existing.credentialId } : {}),
        kind: 'identity',
        label: `${input.label} (${input.role})`,
        secret: input.secret
      })
      credentialId = metadata.id
    }

    const sanitizedInput: SaveIdentityInput = {
      ...input,
      secret: undefined
    }
    return this.repository.saveIdentity(sanitizedInput, credentialId)
  }

  async deleteIdentity(id: string): Promise<DeleteResult> {
    const existing = await this.repository.getIdentity(id)
    const deleted = await this.repository.deleteIdentity(id)
    if (deleted && existing?.credentialId) {
      this.credentialStore.delete(existing.credentialId)
    }
    return { deleted }
  }

  listScans(workspaceId?: string): Promise<ScanRecord[]> {
    return this.repository.listScans({ workspaceId })
  }

  async getScanDetail(scanId: string): Promise<ScanDetail> {
    const scan = await this.repository.getScan(scanId)
    if (!scan) throw new Error('扫描不存在。')
    const row = await this.repository.getScanRow(scanId)
    if (!row) throw new Error('扫描运行状态不存在。')
    const target = await this.repository.getTarget(scan.targetId)
    if (!target) throw new Error('扫描目标不存在。')
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!scope) throw new Error('扫描 Scope 快照不存在。')
    const identityIds = new Set(row.configJson.identityIds)
    const identities = (await this.repository.listIdentities(scan.targetId)).filter(
      (identity) => identityIds.has(identity.id)
    )
    const endpoints = await this.repository.listInventoryEndpoints(scanId)
    const events = await this.repository.listScanEvents(scanId)
    const evidence = this.evidenceStore
      ? await this.evidenceStore.list(scanId)
      : []
    const findings = await this.repository.listFindings({ scanId })
    return { scan, target, scope, identities, endpoints, events, evidence, findings }
  }

  async createScan(input: CreateScanInput): Promise<ScanRecord> {
    const plan = createDefaultScanPlan()
    plan.families = input.families
    plan.budget = input.budget
    const runtime = createRuntimeState()
    const modelProfileIds = await this.resolveScanModelProfiles(input.modelProfileIds)
    return this.repository.createScan(
      {
        ...input,
        description: input.description.trim(),
        modelProfileIds
      },
      plan as unknown as Record<string, unknown>,
      runtime as unknown as Record<string, unknown>
    )
  }

  async controlScan(scanId: string, action: ScanControlAction): Promise<ScanRecord> {
    if (this.scanCoordinator) {
      return this.scanCoordinator.control(scanId, action)
    }

    const row = await this.repository.getScanRow(scanId)
    if (!row) throw new Error('扫描不存在。')
    const runtime = row.runtimeJson as unknown as ScanRuntimeState

    if (action === 'start') {
      if (row.status !== 'draft') throw new Error('只有草稿扫描可以启动。')
      return this.repository.updateScan(scanId, {
        status: 'queued',
        startedAt: Date.now(),
        runtimeJson: { ...runtime, status: 'running' }
      })
    }

    if (action === 'pause') {
      const next = transitionRuntime(runtime, { type: 'pause' })
      return this.repository.updateScan(scanId, {
        status: 'paused',
        runtimeJson: next as unknown as Record<string, unknown>
      })
    }

    if (action === 'resume') {
      const next = transitionRuntime(runtime, { type: 'resume' })
      return this.repository.updateScan(scanId, {
        status: 'queued',
        runtimeJson: next as unknown as Record<string, unknown>
      })
    }

    const next = transitionRuntime(runtime, { type: 'cancel' })
    return this.repository.updateScan(scanId, {
      status: 'cancelled',
      completedAt: Date.now(),
      runtimeJson: next as unknown as Record<string, unknown>
    })
  }

  async searchKnowledge(input: KnowledgeSearchInput): Promise<KnowledgeEntrySummary[]> {
    const entryIds = await this.repository.searchKnowledgeEntryIds(input)
    const entriesById = new Map(V1_KNOWLEDGE_ENTRIES.map((entry) => [entry.id, entry]))
    return entryIds
      .map((entryId) => entriesById.get(entryId))
      .filter((entry): entry is (typeof V1_KNOWLEDGE_ENTRIES)[number] => Boolean(entry))
      .map((entry) => ({
        id: entry.id,
        version: entry.version,
        family: entry.family,
        title: entry.title,
        applicability: entry.applicability,
        confirmationRules: entry.confirmationRules,
        remediationHints: entry.remediationHints,
        sourceTitles: entry.sourceRefs
          .map((sourceId) => KNOWLEDGE_SOURCES.find((source) => source.id === sourceId)?.title)
          .filter((title): title is string => Boolean(title))
      }))
  }

  listFindings(input?: {
    workspaceId?: string
    scanId?: string
    verdict?: FindingRecord['verdict']
    family?: FindingRecord['family']
  }): Promise<FindingRecord[]> {
    return this.repository.listFindings(input)
  }

  listReports(scanId: string): Promise<ReportRecord[]> {
    return this.requireReportService().list(scanId)
  }

  generateReport(input: GenerateReportInput): Promise<ReportRecord> {
    return this.requireReportService().generate(input)
  }

  readReport(reportId: string): Promise<ReportContent> {
    return this.requireReportService().read(reportId)
  }

  markReportExported(reportId: string, filePath: string): Promise<void> {
    return this.requireReportService().markExported(reportId, filePath)
  }

  listModelProfiles(): Promise<ModelProfileRecord[]> {
    return this.repository.listModelProfiles()
  }

  async saveModelProfile(input: SaveModelProfileInput): Promise<ModelProfileRecord> {
    const existing = input.id
      ? await this.repository.getModelProfile(input.id)
      : undefined
    let credentialId: string | null | undefined
    if (input.provider === 'deterministic') {
      if (existing?.credentialId) this.credentialStore.delete(existing.credentialId)
      credentialId = null
    } else if (input.apiKey) {
      const metadata = this.credentialStore.save({
        ...(existing?.credentialId ? { id: existing.credentialId } : {}),
        kind: 'model-api-key',
        label: `${input.name} (${input.model})`,
        secret: input.apiKey
      })
      credentialId = metadata.id
    } else if (!existing?.credentialId) {
      throw new Error('OpenAI-compatible Profile 缺少 API Key。')
    }
    const profile = await this.repository.saveModelProfile(
      { ...input, apiKey: undefined },
      credentialId
    )
    return profile
  }

  async deleteModelProfile(id: string): Promise<DeleteResult> {
    const existing = await this.repository.getModelProfile(id)
    if (!existing) return { deleted: false }
    const roleProfiles = (await this.repository.listModelProfiles()).filter(
      (profile) => profile.agentRole === existing.agentRole
    )
    if (roleProfiles.length <= 1) {
      throw new Error('每个 Agent 角色至少需要保留一个模型 Profile。')
    }
    const deleted = await this.repository.deleteModelProfile(id)
    if (deleted && existing.credentialId) {
      this.credentialStore.delete(existing.credentialId)
    }
    return { deleted }
  }

  async testModelProfile(id: string): Promise<{
    ok: boolean
    message: string
    provider?: string
    model?: string
    durationMs?: number
  }> {
    if (!this.modelGateway) throw new Error('ModelGateway 尚未初始化。')
    const profile = await this.repository.getModelProfile(id)
    if (!profile) throw new Error('模型 Profile 不存在。')
    const startedAt = Date.now()
    const result = await this.modelGateway.testConnection(id)
    return {
      ...result,
      provider: profile.provider,
      model: profile.model,
      durationMs: Date.now() - startedAt
    }
  }

  private requireReportService(): ReportService {
    if (!this.reportService) throw new Error('报告服务尚未初始化。')
    return this.reportService
  }

  private async resolveScanModelProfiles(
    requested: AgentModelProfileSelection | undefined
  ): Promise<Record<AgentRole, string>> {
    const resolved = {} as Record<AgentRole, string>
    for (const role of V1_AGENT_ROLES) {
      const requestedId = requested?.[role]
      const profile = requestedId
        ? await this.repository.getModelProfile(requestedId)
        : await this.repository.getPreferredModelProfile(role)
      if (!profile) {
        throw new Error(`Agent ${role} 没有可用模型 Profile。`)
      }
      if (profile.agentRole !== role) {
        throw new Error(`模型 Profile “${profile.name}” 不属于 ${role} Agent。`)
      }
      if (profile.provider === 'openai-compatible') {
        if (!profile.credentialId || !this.credentialStore.get(profile.credentialId)) {
          throw new Error(`外部模型 Profile “${profile.name}” 缺少可用 API Key。`)
        }
      }
      resolved[role] = profile.id
    }
    return resolved
  }

  private async ensureDefaultModelProfiles(): Promise<void> {
    const existing = await this.repository.listModelProfiles()
    const roles: ModelProfileRecord['agentRole'][] = [
      'planner',
      'knowledge',
      'strategy',
      'analysis',
      'verifier'
    ]
    for (const role of roles) {
      if (existing.some((profile) => profile.agentRole === role)) continue
      await this.repository.saveModelProfile({
        name: `本地确定性 ${role}`,
        agentRole: role,
        provider: 'deterministic',
        model: 'agentgo-rules-v1',
        timeoutMs: 10_000,
        rpmLimit: 120,
        tpmLimit: 100_000,
        tokenBudget: 5_000_000,
        costBudget: 0
      })
    }
  }

  private async ensureBuiltInKnowledgeIndex(): Promise<void> {
    const sourcesById = new Map(KNOWLEDGE_SOURCES.map((source) => [source.id, source]))
    await this.repository.upsertKnowledgeEntries(
      V1_KNOWLEDGE_ENTRIES.map((entry) => {
        const sources = entry.sourceRefs
          .map((sourceId) => sourcesById.get(sourceId))
          .filter((source): source is (typeof KNOWLEDGE_SOURCES)[number] => Boolean(source))
        return {
          id: entry.id,
          family: entry.family,
          title: entry.title,
          content: [
            `版本：${entry.version}`,
            `适用性：${entry.applicability.join('；')}`,
            `信号：${entry.signals.join('；')}`,
            `安全验证：${entry.safeProbePrinciples.join('；')}`,
            `确认规则：${entry.confirmationRules.join('；')}`,
            `误报模式：${entry.falsePositivePatterns.join('；')}`,
            `修复建议：${entry.remediationHints.join('；')}`,
            `禁止动作：${entry.forbiddenActions.join('；')}`,
            `来源：${sources.map((source) => source.title).join('；')}`
          ].join('\n'),
          tags: [entry.family, entry.id, entry.version, ...entry.sourceRefs],
          applicability: entry.applicability,
          ...(sources[0]?.url ? { sourceUrl: sources[0].url } : {}),
          ...(sources.length > 0
            ? { license: sources.map((source) => source.license).join('; ') }
            : {})
        }
      })
    )
  }

  private async recoverInterruptedScans(): Promise<void> {
    const interrupted = (await this.repository.listScans()).filter((scan) =>
      ['queued', 'running'].includes(scan.status)
    )
    for (const scan of interrupted) {
      const row = await this.repository.getScanRow(scan.id)
      if (!row) continue
      const runtime = row.runtimeJson as unknown as ScanRuntimeState
      const paused: ScanRuntimeState =
        runtime.status === 'running'
          ? transitionRuntime(runtime, { type: 'pause' })
          : { ...runtime, status: 'paused' }
      await this.repository.addCheckpoint({
        scanId: scan.id,
        phase: scan.phase,
        state: paused as unknown as Record<string, unknown>,
        reason: 'recovered-after-interruption'
      })
      await this.repository.updateScan(scan.id, {
        status: 'paused',
        runtimeJson: paused as unknown as Record<string, unknown>,
        lastError: null
      })
      await this.repository.addScanEvent({
        scanId: scan.id,
        type: 'status',
        level: 'warning',
        message: '检测到上次未正常结束的扫描，已安全恢复为暂停状态。',
        detail: { recoveredPhase: scan.phase }
      })
    }
  }
}
