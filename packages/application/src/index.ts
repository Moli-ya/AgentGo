import {
  V1_AGENT_ROLES,
  createDefaultScanPlan,
  createRuntimeState,
  transitionRuntime,
  type ScanRuntimeState
} from '@agentgo/agent-runtime'
import {
  CreateScanInputSchema,
  KnowledgeIntelligenceCandidateSchema
} from '@agentgo/contracts'
import type {
  EvidenceArtifactDraft,
  AgentModelProfileSelection,
  AgentRole,
  CreateKnowledgeImportInput,
  CreateScanInput,
  CreateTargetInput,
  CreateWorkspaceInput,
  DashboardSnapshot,
  DeleteResult,
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
  RequestVariantRecord,
  ReviewVariantInput,
  RetireVariantInput,
  ReviewKnowledgeImportInput,
  SaveModelProfileInput,
  SaveMcpServerInput,
  SaveIdentityInput,
  ScanControlAction,
  ScanDetail,
  ScanRecord,
  TargetDetail,
  TargetRecord,
  UpdateTargetInput,
  UpdateKnowledgeCandidateInput,
  UpsertInventoryInput,
  UpsertInventoryResult,
  ExtractKnowledgeImportInput,
  Environment,
  ExecutionLease,
  WorkspaceRecord
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  stableJson
} from '@agentgo/db'
import {
  KNOWLEDGE_SOURCES,
  V1_KNOWLEDGE_ENTRIES,
  inspectKnowledgeContent
} from '@agentgo/knowledge-base'
import {
  DefaultMcpHub,
  type McpConnectionSecrets,
  type McpHub
} from '@agentgo/mcp-hub'
import { redactSensitiveText, type ModelGateway } from '@agentgo/model-gateway'
import {
  KNOWLEDGE_INGESTION_PROMPTS,
  KnowledgeReviewerOutputSchema
} from './agent-prompts'
import { EvidenceCapturePolicy } from './evidence-capture-policy'
import { FindingAssembler } from './finding-assembler'
import { InventoryService } from './inventory-service'
import {
  ReportService,
  projectEvidenceSummary,
  type ReportContent
} from './report-service'
import {
  ProtectedEvidenceCaptureService,
  type PersistedProtectedEvidenceCapture,
  type ProtectedEvidenceCaptureInput
} from './protected-evidence-capture-service'
import {
  ScanModuleSnapshotError,
  buildScanModuleSnapshotDrafts,
  computeScanModuleSnapshotHash,
  requireSealedScanModuleSnapshotSet,
  verifyScanModuleSnapshots
} from './scan-module-snapshot'
import type { VulnerabilityPlatform } from './vulnerability-platform'

export * from './execution-policy'
export * from './execution-authority'
export * from './execution-port'
export * from './evidence-capture-policy'
export * from './execution-service'
export * from './inventory-service'
export * from './legacy-v1-request-compiler-adapter'
export * from './request-compiler'
export * from './request-hash-key-provider'
export * from './report-service'
export * from './protected-evidence-capture-service'
export * from './protected-evidence-retention-scheduler'
export * from './agent-prompts'
export * from './scan-coordinator'
export * from './scan-module-snapshot'
export * from './validation-engine'
export * from './vulnerability-bundles'
export * from './vulnerability-execution-gate'
export * from './vulnerability-platform'
export * from './qualification-record'
export * from './l2-protocol-service'
export * from './legacy-v1-qualification-records'
export * from './record-backed-activation-catalog'
export * from './identity-context-service'
export * from './session-vault'
export * from './csrf-binding-service'
export * from './authorization-matrix-service'
export * from './l2-binding-service'
export * from './approval-service'
export * from './l2-http-compiler'
export * from './l2-probe-orchestrator'
export * from './import-service'
export * from './discovery/static-discovery-service'
export * from './asset-manifest-service'
export * from './extraction-rule-service'
export * from './inventory-merge-service'
export * from './dependency-graph-service'
export * from './browser-recon-session'
export * from './browser-recon-service'
export * from './mediated-read-compiler'
export * from './validation-plan-compiler'
export * from './validation-plan-executor'
export * from './loopback-callback-collector'
export * from './retrieval-service'
export * from './legacy-validation-plans'
export * from './legacy-parity-adapters'
export * from './detector-service'
export * from './candidate-compiler'
export * from './finding-assembler'
export * from './sqli-mutation-gate'
export * from './sqli-response-normalizer'
export * from './idor-response-normalizer'
export * from './path-value-mutation'

export interface ScanCoordinator {
  control(scanId: string, action: ScanControlAction): Promise<ScanRecord>
}

function applicationErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '未知错误。'
}

function isRecoveredInterruptedLease(
  lease: ExecutionLease | undefined
): lease is ExecutionLease {
  return (
    lease?.state === 'failed' &&
    lease.terminalReason === 'interrupted' &&
    lease.deliveryState === 'unknown' &&
    lease.outcomeSummary?.executionState === 'interrupted' &&
    lease.outcomeSummary.verdictImpact === 'inconclusive'
  )
}

interface InterruptedScanRecoverySummary {
  leaseIds: string[]
  evidenceRefs: string[]
  evidenceUnavailableLeaseIds: string[]
}

export interface AgentGoApplicationDependencies {
  repository: AgentGoRepository
  credentialStore: FileCredentialStore
  evidenceStore?: EvidenceStore
  modelGateway?: ModelGateway
  mcpHub?: McpHub
  reportService?: ReportService
  evidenceCapturePolicy?: EvidenceCapturePolicy
  protectedEvidenceCaptureService?: ProtectedEvidenceCaptureService
  scanCoordinator?: ScanCoordinator
  inventoryService?: InventoryService
  vulnerabilityPlatform: VulnerabilityPlatform
  vulnerabilityExecutionEnvironment: Environment
}

export class AgentGoApplicationService {
  private readonly repository: AgentGoRepository
  private readonly credentialStore: FileCredentialStore
  private readonly evidenceStore?: EvidenceStore
  private readonly modelGateway?: ModelGateway
  private readonly mcpHub: McpHub
  private readonly reportService?: ReportService
  private readonly evidenceCapturePolicy: EvidenceCapturePolicy
  private readonly protectedEvidenceCaptureService?: ProtectedEvidenceCaptureService
  private readonly vulnerabilityPlatform: VulnerabilityPlatform
  private readonly vulnerabilityExecutionEnvironment: Environment
  private readonly inventoryService: InventoryService
  private scanCoordinator?: ScanCoordinator

  constructor(dependencies: AgentGoApplicationDependencies) {
    this.repository = dependencies.repository
    this.credentialStore = dependencies.credentialStore
    this.evidenceStore = dependencies.evidenceStore
    this.modelGateway = dependencies.modelGateway
    this.mcpHub = dependencies.mcpHub ?? new DefaultMcpHub()
    this.reportService =
      dependencies.reportService ??
      (dependencies.evidenceStore
        ? new ReportService(dependencies.repository, dependencies.evidenceStore, {
            familyDisplayNames: new FindingAssembler(
              dependencies.vulnerabilityPlatform.definitionRegistry
            ).familyDisplayNames()
          })
        : undefined)
    this.evidenceCapturePolicy =
      dependencies.evidenceCapturePolicy ?? new EvidenceCapturePolicy()
    this.protectedEvidenceCaptureService =
      dependencies.protectedEvidenceCaptureService ??
      (dependencies.evidenceStore
        ? new ProtectedEvidenceCaptureService(
            this.evidenceCapturePolicy,
            dependencies.evidenceStore
          )
        : undefined)
    this.scanCoordinator = dependencies.scanCoordinator
    this.vulnerabilityPlatform = dependencies.vulnerabilityPlatform
    this.vulnerabilityExecutionEnvironment = dependencies.vulnerabilityExecutionEnvironment
    this.inventoryService =
      dependencies.inventoryService ??
      new InventoryService(
        dependencies.repository,
        dependencies.vulnerabilityPlatform.capabilityCatalog
      )
  }

  setScanCoordinator(coordinator: ScanCoordinator): void {
    this.scanCoordinator = coordinator
  }

  captureProtectedEvidence(
    input: ProtectedEvidenceCaptureInput
  ): Promise<PersistedProtectedEvidenceCapture> {
    if (!this.protectedEvidenceCaptureService) {
      return Promise.reject(
        new Error('Protected Evidence persistence is unavailable.')
      )
    }
    return this.protectedEvidenceCaptureService.captureAndPersist(input)
  }

  async initialize(): Promise<void> {
    await this.repository.initializeDefaults()
    if (this.evidenceStore) {
      try {
        await this.evidenceStore.sweepExpiredProtectedOriginals()
      } catch {
        // Key erasure is transactional and ciphertext cleanup is retried on
        // the next startup. Initialization must not restore expired access.
      }
      try {
        await this.evidenceStore.sweepUnreferencedContentFiles()
      } catch {
        // Exact content-addressed candidates remain queued for a later
        // EvidenceStore mutation and are rediscovered on the next startup.
      }
    }
    await this.repository.expireIssuedExecutionLeases()
    const interruptedLeases =
      await this.repository.listClaimedExecutionLeasesForRecovery()
    const interruptedExecutions =
      await this.persistInterruptedLeaseEvidence(interruptedLeases)
    this.mergeInterruptedScanRecoveries(
      interruptedExecutions,
      await this.repository.listInterruptedExecutionLeasesForScanRecovery()
    )
    await this.ensureBuiltInKnowledgeIndex()
    await this.ensureDefaultModelProfiles()
    await this.recoverInterruptedScans(interruptedExecutions)
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
      await this.evidenceStore?.deleteWorkspaceArtifacts(id)
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
    const updated = await this.repository.updateTarget(input)
    const scope = updated.scope ?? (await this.repository.getLatestScope(input.id))
    if (!scope) throw new Error('目标缺少授权范围。')
    const identities = await this.repository.listIdentities(input.id)
    return { target: updated.target, scope, identities }
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

  upsertInventory(input: UpsertInventoryInput): Promise<UpsertInventoryResult> {
    return this.inventoryService.upsertInventory(input)
  }

  reviewVariant(input: ReviewVariantInput): Promise<RequestVariantRecord> {
    return this.inventoryService.reviewVariant(input)
  }

  retireVariant(input: RetireVariantInput): Promise<RequestVariantRecord> {
    return this.inventoryService.retireVariant(input)
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
      ? (await this.evidenceStore.list(scanId)).map(projectEvidenceSummary)
      : []
    const findings = await this.repository.listFindings({ scanId })
    return { scan, target, scope, identities, endpoints, events, evidence, findings }
  }

  async createScan(input: CreateScanInput): Promise<ScanRecord> {
    const parsedInput = CreateScanInputSchema.parse(input)
    const families = [
      ...(parsedInput.families ?? this.vulnerabilityPlatform.defaultScanFamilies)
    ]
    const moduleSnapshotDrafts = buildScanModuleSnapshotDrafts(
      families,
      this.vulnerabilityExecutionEnvironment,
      this.vulnerabilityPlatform
    )
    const plan = createDefaultScanPlan(families)
    plan.budget = parsedInput.budget
    const runtime = createRuntimeState()
    const modelProfileIds = await this.resolveScanModelProfiles(
      parsedInput.modelProfileIds
    )
    return this.repository.createScan(
      {
        ...parsedInput,
        families,
        description: parsedInput.description.trim(),
        modelProfileIds
      },
      plan as unknown as Record<string, unknown>,
      runtime as unknown as Record<string, unknown>,
      moduleSnapshotDrafts.map((draft) => ({
        draft,
        snapshotHash: computeScanModuleSnapshotHash(draft)
      }))
    )
  }

  async controlScan(scanId: string, action: ScanControlAction): Promise<ScanRecord> {
    const row = await this.repository.getScanRow(scanId)
    if (!row) throw new Error('扫描不存在。')
    if (action === 'resume') {
      const checkpoint = await this.repository.getLatestCheckpoint(scanId)
      if (checkpoint?.reason === 'execution-interrupted-unknown') {
        throw new Error(
          '上次执行在可能已发送后中断，结果为 Inconclusive；为避免自动重放，请创建新的扫描。'
        )
      }
    }
    if (action === 'start' || action === 'resume') {
      if (action === 'start' && row.status !== 'draft') {
        throw new Error('只有草稿扫描可以启动。')
      }
      if (
        action === 'resume' &&
        !['paused', 'awaiting-user'].includes(row.status)
      ) {
        throw new Error('只有暂停或等待用户的扫描可以恢复。')
      }
      const snapshots = await this.repository.listScanModuleSnapshots(scanId)
      try {
        requireSealedScanModuleSnapshotSet(row.moduleSnapshotsSealed)
        verifyScanModuleSnapshots(
          snapshots,
          scanId,
          row.configJson.families,
          this.vulnerabilityExecutionEnvironment,
          this.vulnerabilityPlatform
        )
      } catch (error) {
        if (!(error instanceof ScanModuleSnapshotError)) throw error
        const runtime = row.runtimeJson as unknown as ScanRuntimeState
        const awaiting = transitionRuntime(runtime, { type: 'await-user' })
        return this.repository.markScanAwaitingUser({
          scanId,
          phase: row.phase as ScanRecord['phase'],
          runtimeState: awaiting as unknown as Record<string, unknown>,
          reason: `module-snapshot-incompatible:${error.code}`,
          message:
            '扫描冻结的模块或能力版本无法精确恢复，已进入等待用户并按 Inconclusive 处理。',
          detail: {
            code: error.code,
            familyId: error.familyId,
            environment: this.vulnerabilityExecutionEnvironment,
            endState: 'inconclusive'
          }
        })
      }
      if (action === 'resume') {
        const pendingReviewVariantIds =
          await this.repository.listPendingActiveL1ReviewVariantIds(scanId)
        if (pendingReviewVariantIds.length > 0) {
          if (row.status === 'awaiting-user') {
            const current = await this.repository.getScan(scanId)
            if (!current) throw new Error('Scan disappeared while awaiting inventory review.')
            return current
          }
          const runtime = row.runtimeJson as unknown as ScanRuntimeState
          const awaiting = transitionRuntime(runtime, { type: 'await-user' })
          return this.repository.markScanAwaitingUser({
            scanId,
            phase: row.phase as ScanRecord['phase'],
            runtimeState: awaiting as unknown as Record<string, unknown>,
            reason: 'inventory-review-required',
            message: `${pendingReviewVariantIds.length} 个 L1 请求变体仍等待人工 review。`,
            detail: {
              reviewRequiredCount: pendingReviewVariantIds.length,
              endState: 'awaiting-user'
            }
          })
        }
      }
    }

    if (this.scanCoordinator) {
      return this.scanCoordinator.control(scanId, action)
    }

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
    const imported = await this.repository.listPublishedKnowledgeEntries(entryIds)
    const importedById = new Map(imported.map((entry) => [entry.chunkId, entry]))
    const results: KnowledgeEntrySummary[] = []
    for (const entryId of entryIds) {
      const builtIn = entriesById.get(entryId)
      if (builtIn) {
        results.push({
          id: builtIn.id,
          version: builtIn.version,
          family: builtIn.family,
          title: builtIn.title,
          applicability: builtIn.applicability,
          confirmationRules: builtIn.confirmationRules,
          remediationHints: builtIn.remediationHints,
          sourceTitles: builtIn.sourceRefs
            .map((sourceId) => KNOWLEDGE_SOURCES.find((source) => source.id === sourceId)?.title)
            .filter((title): title is string => Boolean(title)),
          sourceType: 'built-in-curated'
        })
        continue
      }
      const published = importedById.get(entryId)
      if (!published) continue
      results.push({
        id: published.chunkId,
        version: published.candidate.schemaVersion,
        ...(published.candidate.family ? { family: published.candidate.family } : {}),
        title: published.candidate.title,
        applicability: [
          ...published.candidate.affectedVersions,
          ...published.candidate.preconditions
        ],
        confirmationRules: published.candidate.confirmationRules,
        remediationHints: published.candidate.remediation,
        sourceTitles: [published.sourceTitle],
        vendor: published.candidate.vendor,
        product: published.candidate.product,
        sourceType: published.sourceType
      })
    }
    return results
  }

  listKnowledgeImports(): Promise<KnowledgeImportSummary[]> {
    return this.repository.listKnowledgeImports()
  }

  async getKnowledgeImport(id: string): Promise<KnowledgeImportDetail> {
    const record = await this.repository.getKnowledgeImport(id)
    if (!record) throw new Error('知识导入记录不存在。')
    return record
  }

  createKnowledgeImport(input: CreateKnowledgeImportInput): Promise<KnowledgeImportDetail> {
    const redactedContent = redactSensitiveText(input.rawContent)
    const inspection = inspectKnowledgeContent(redactedContent)
    const flags = [
      ...inspection.flags,
      ...(redactedContent !== input.rawContent ? ['sensitive-data-redacted'] : [])
    ]
    return this.repository.createKnowledgeImport(
      { ...input, rawContent: redactedContent },
      flags
    )
  }

  async extractKnowledgeImport(
    input: ExtractKnowledgeImportInput
  ): Promise<KnowledgeImportDetail> {
    if (!this.modelGateway) throw new Error('模型网关尚未初始化。')
    const record = await this.getKnowledgeImport(input.id)
    if (record.status === 'published') {
      throw new Error('已发布知识必须先重新打开审核，才能再次提取。')
    }
    const extractorProfile = await this.requireKnowledgeIngestionProfile(
      input.extractorProfileId,
      'knowledge'
    )
    const reviewerProfile = await this.requireKnowledgeIngestionProfile(
      input.reviewerProfileId,
      'verifier'
    )
    await this.repository.updateKnowledgeImportState({
      id: input.id,
      status: 'extracting',
      extractorProfileId: extractorProfile.id,
      reviewerProfileId: reviewerProfile.id,
      lastError: null
    })

    let activeRunId: string | undefined
    try {
      const hints = await this.repository.getKnowledgeImportHints(input.id)
      const extractorInput = {
        title: record.title,
        sourceType: record.sourceType,
        sourceUrl: record.sourceUrl,
        author: record.author,
        license: record.license,
        rawContent: record.rawContent,
        vendorHint: hints.vendorHint,
        productHint: hints.productHint
      }
      const extractorRun = await this.repository.createKnowledgeAgentRun({
        importId: input.id,
        role: 'intelligence-extractor',
        promptId: KNOWLEDGE_INGESTION_PROMPTS.extractor.id,
        promptVersion: KNOWLEDGE_INGESTION_PROMPTS.extractor.version,
        modelProfileId: extractorProfile.id,
        inputHashSource: stableJson(extractorInput)
      })
      activeRunId = extractorRun.id
      const extraction = await this.modelGateway.structuredCompletion({
        profileId: extractorProfile.id,
        systemPromptId: KNOWLEDGE_INGESTION_PROMPTS.extractor.id,
        systemPromptVersion: KNOWLEDGE_INGESTION_PROMPTS.extractor.version,
        input: extractorInput,
        schema: KnowledgeIntelligenceCandidateSchema,
        agentRunId: extractorRun.id,
        invocationSource: 'knowledge-extraction',
        invocationSink: {
          recordModelInvocation: (invocation) =>
            this.repository.recordKnowledgeModelInvocation({
              runId: invocation.agentRunId,
              profileId: invocation.profileId,
              provider: invocation.provider,
              model: invocation.model,
              outputHashSource: invocation.outputHashSource,
              promptTokens: invocation.promptTokens,
              completionTokens: invocation.completionTokens,
              durationMs: invocation.durationMs,
              source: 'knowledge-extraction'
            })
        }
      })
      await this.repository.finishKnowledgeAgentRun({
        id: extractorRun.id,
        status: 'completed',
        provider: extraction.provider,
        model: extraction.model,
        outputHashSource: stableJson(extraction.value),
        promptTokens: extraction.promptTokens,
        completionTokens: extraction.completionTokens,
        durationMs: extraction.durationMs
      })
      activeRunId = undefined

      const reviewerInput = {
        candidate: extraction.value,
        rawContent: record.rawContent.slice(0, 200_000),
        instructionFlags: record.instructionFlags
      }
      const reviewerRun = await this.repository.createKnowledgeAgentRun({
        importId: input.id,
        parentRunId: extractorRun.id,
        role: 'intelligence-reviewer',
        promptId: KNOWLEDGE_INGESTION_PROMPTS.reviewer.id,
        promptVersion: KNOWLEDGE_INGESTION_PROMPTS.reviewer.version,
        modelProfileId: reviewerProfile.id,
        inputHashSource: stableJson(reviewerInput)
      })
      activeRunId = reviewerRun.id
      const review = await this.modelGateway.structuredCompletion({
        profileId: reviewerProfile.id,
        systemPromptId: KNOWLEDGE_INGESTION_PROMPTS.reviewer.id,
        systemPromptVersion: KNOWLEDGE_INGESTION_PROMPTS.reviewer.version,
        input: reviewerInput,
        schema: KnowledgeReviewerOutputSchema,
        agentRunId: reviewerRun.id,
        invocationSource: 'knowledge-review',
        invocationSink: {
          recordModelInvocation: (invocation) =>
            this.repository.recordKnowledgeModelInvocation({
              runId: invocation.agentRunId,
              profileId: invocation.profileId,
              provider: invocation.provider,
              model: invocation.model,
              outputHashSource: invocation.outputHashSource,
              promptTokens: invocation.promptTokens,
              completionTokens: invocation.completionTokens,
              durationMs: invocation.durationMs,
              source: 'knowledge-review'
            })
        }
      })
      await this.repository.finishKnowledgeAgentRun({
        id: reviewerRun.id,
        status: 'completed',
        provider: review.provider,
        model: review.model,
        outputHashSource: stableJson(review.value),
        promptTokens: review.promptTokens,
        completionTokens: review.completionTokens,
        durationMs: review.durationMs
      })
      activeRunId = undefined
      return this.repository.saveKnowledgeCandidate(
        input.id,
        extraction.value,
        review.value.issues,
        review.value.decision
      )
    } catch (error) {
      if (activeRunId) {
        await this.repository.finishKnowledgeAgentRun({
          id: activeRunId,
          status: 'failed',
          error: applicationErrorMessage(error)
        })
      }
      await this.repository.updateKnowledgeImportState({
        id: input.id,
        status: 'failed',
        lastError: applicationErrorMessage(error)
      })
      throw error
    }
  }

  async updateKnowledgeCandidate(
    input: UpdateKnowledgeCandidateInput
  ): Promise<KnowledgeImportDetail> {
    const existing = await this.getKnowledgeImport(input.id)
    if (existing.status === 'published') {
      throw new Error('已发布知识必须先重新打开审核，才能修改。')
    }
    const candidate = KnowledgeIntelligenceCandidateSchema.parse(input.candidate)
    return this.repository.saveKnowledgeCandidate(
      input.id,
      candidate,
      [],
      'ready-for-review'
    )
  }

  reviewKnowledgeImport(input: ReviewKnowledgeImportInput): Promise<KnowledgeImportDetail> {
    return this.repository.reviewKnowledgeImport(input.id, input.action)
  }

  async deleteKnowledgeImport(id: string): Promise<DeleteResult> {
    return { deleted: await this.repository.deleteKnowledgeImport(id) }
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

  listModelProfileUsage(): Promise<ModelProfileUsageRecord[]> {
    return this.repository.listModelProfileUsage()
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
      { ...input, apiKey: undefined, costBudget: 0 },
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

  async testModelProfile(id: string) {
    if (!this.modelGateway) throw new Error('ModelGateway 尚未初始化。')
    const profile = await this.repository.getModelProfile(id)
    if (!profile) throw new Error('模型 Profile 不存在。')
    const startedAt = Date.now()
    const result = await this.modelGateway.testConnection(id)
    if ((result.promptTokens ?? 0) + (result.completionTokens ?? 0) > 0) {
      await this.repository.recordModelProfileUsage({
        profileId: id,
        source: 'connection-test',
        promptTokens: result.promptTokens ?? 0,
        completionTokens: result.completionTokens ?? 0
      })
    }
    return {
      ...result,
      provider: profile.provider,
      model: profile.model,
      durationMs: Date.now() - startedAt
    }
  }

  listMcpServers(): Promise<McpServerRecord[]> {
    return this.repository.listMcpServers()
  }

  async saveMcpServer(input: SaveMcpServerInput): Promise<McpServerRecord> {
    const existing = input.id
      ? await this.repository.getMcpServer(input.id)
      : undefined
    if (input.id && !existing) throw new Error('MCP Server 配置不存在。')
    const previousSecrets = this.readMcpSecrets(existing?.credentialId)
    const nextSecrets: McpConnectionSecrets = {}
    if (input.transport === 'stdio') {
      const environment = input.environment ?? previousSecrets.environment
      if (environment && Object.keys(environment).length > 0) {
        nextSecrets.environment = environment
      }
    } else {
      if (input.authType !== 'none') {
        const token = input.token ?? previousSecrets.token
        if (!token) throw new Error('远程 MCP Server 缺少鉴权 Token。')
        nextSecrets.token = token
      }
      const headers = input.headers ?? previousSecrets.headers
      if (headers && Object.keys(headers).length > 0) {
        nextSecrets.headers = headers
      }
    }

    const hasSecrets = Boolean(
      nextSecrets.token ||
      Object.keys(nextSecrets.environment ?? {}).length ||
      Object.keys(nextSecrets.headers ?? {}).length
    )
    let credentialId: string | null | undefined
    if (hasSecrets) {
      const metadata = this.credentialStore.save({
        ...(existing?.credentialId ? { id: existing.credentialId } : {}),
        kind: 'mcp-server-secret',
        label: `${input.name} MCP Server`,
        secret: JSON.stringify(nextSecrets)
      })
      credentialId = metadata.id
    } else if (existing?.credentialId) {
      credentialId = null
    }

    const riskLabels = new Set(input.riskLabels)
    riskLabels.add(
      input.transport === 'stdio' ? 'command-execution' : 'network-access'
    )
    if (input.roots.length > 0) riskLabels.add('file-access')
    const saved = await this.repository.saveMcpServer(
      {
        ...(input.id ? { id: input.id } : {}),
        name: input.name,
        transport: input.transport,
        enabled: input.enabled,
        ...(input.transport === 'stdio' && input.command
          ? { command: input.command }
          : {}),
        args: input.transport === 'stdio' ? input.args : [],
        ...(input.transport === 'stdio' && input.cwd ? { cwd: input.cwd } : {}),
        ...(input.transport === 'streamable-http' && input.url
          ? { url: input.url }
          : {}),
        authType: input.transport === 'streamable-http' ? input.authType : 'none',
        ...(input.transport === 'streamable-http' && input.authHeaderName
          ? { authHeaderName: input.authHeaderName }
          : {}),
        environmentKeys: Object.keys(nextSecrets.environment ?? {}).sort(),
        headerNames: Object.keys(nextSecrets.headers ?? {}).sort(),
        timeoutMs: input.timeoutMs,
        roots: [...new Set(input.roots)],
        allowedAgentRoles: [...new Set(input.allowedAgentRoles)],
        riskLabels: [...riskLabels]
      },
      credentialId
    )
    if (credentialId === null && existing?.credentialId) {
      this.credentialStore.delete(existing.credentialId)
    }
    return saved
  }

  async deleteMcpServer(id: string): Promise<DeleteResult> {
    const existing = await this.repository.getMcpServer(id)
    if (!existing) return { deleted: false }
    const deleted = await this.repository.deleteMcpServer(id)
    if (deleted && existing.credentialId) {
      this.credentialStore.delete(existing.credentialId)
    }
    return { deleted }
  }

  async testMcpServer(id: string): Promise<McpConnectionTestResult> {
    const server = await this.repository.getMcpServer(id)
    if (!server) throw new Error('MCP Server 配置不存在。')
    const result = await this.mcpHub.testConnection(
      server,
      this.readMcpSecrets(server.credentialId)
    )
    await this.repository.updateMcpServerTestResult(id, result)
    return result
  }

  private readMcpSecrets(credentialId?: string): McpConnectionSecrets {
    if (!credentialId) return {}
    const serialized = this.credentialStore.get(credentialId)
    if (!serialized) return {}
    let parsed: unknown
    try {
      parsed = JSON.parse(serialized)
    } catch {
      throw new Error('MCP Server 加密凭据格式无效。')
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('MCP Server 加密凭据格式无效。')
    }
    const value = parsed as Record<string, unknown>
    const result: McpConnectionSecrets = {}
    if (typeof value.token === 'string' && value.token) result.token = value.token
    for (const field of ['environment', 'headers'] as const) {
      const candidate = value[field]
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) continue
      const entries = Object.entries(candidate).filter(
        (entry): entry is [string, string] => typeof entry[1] === 'string'
      )
      if (entries.length > 0) result[field] = Object.fromEntries(entries)
    }
    return result
  }

  private requireReportService(): ReportService {
    if (!this.reportService) throw new Error('报告服务尚未初始化。')
    return this.reportService
  }

  private async requireKnowledgeIngestionProfile(
    id: string,
    role: 'knowledge' | 'verifier'
  ): Promise<ModelProfileRecord> {
    const profile = await this.repository.getModelProfile(id)
    if (!profile) throw new Error(`模型 Profile 不存在：${id}`)
    if (profile.agentRole !== role) {
      throw new Error(
        role === 'knowledge'
          ? '情报提取必须使用 KnowledgeAgent Profile。'
          : '情报复核必须使用 VerifierAgent Profile。'
      )
    }
    if (
      profile.provider === 'openai-compatible' &&
      (!profile.credentialId || !this.credentialStore.get(profile.credentialId))
    ) {
      throw new Error(`外部模型 Profile “${profile.name}” 缺少可用 API Key。`)
    }
    return profile
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

  private async persistInterruptedLeaseEvidence(
    contexts: Awaited<
      ReturnType<AgentGoRepository['listClaimedExecutionLeasesForRecovery']>
    >
  ): Promise<Map<string, InterruptedScanRecoverySummary>> {
    const byScan = new Map<string, InterruptedScanRecoverySummary>()
    for (const { lease, grant, captureDecision } of contexts) {
      const recovery = byScan.get(grant.scanId) ?? {
        leaseIds: [],
        evidenceRefs: [],
        evidenceUnavailableLeaseIds: []
      }
      recovery.leaseIds.push(lease.id)
      byScan.set(grant.scanId, recovery)

      let recoveredLease: ExecutionLease | undefined
      let savedEvidence:
        | Awaited<ReturnType<EvidenceStore['save']>>
        | undefined
      const discardedEvidencePaths: string[] = []
      let evidenceFailure: unknown =
        this.evidenceStore
          ? undefined
          : new Error('EvidenceStore is unavailable during recovery.')

      if (this.evidenceStore) {
        try {
          const scan = await this.repository.getScanRow(grant.scanId)
          const target = scan
            ? await this.repository.getTarget(scan.targetId)
            : undefined
          if (!scan || !target) {
            throw new Error(
              'Interrupted execution scan or target is unavailable.'
            )
          }
          const recoveredAtMs = Date.now()
          const validFromMs = Date.parse(captureDecision.validFrom)
          const occurredAtMs = Math.min(
            recoveredAtMs,
            Date.parse(lease.expiresAt),
            Date.parse(captureDecision.validUntil)
          )
          if (
            !Number.isSafeInteger(recoveredAtMs) ||
            !Number.isFinite(validFromMs) ||
            !Number.isFinite(occurredAtMs) ||
            occurredAtMs < validFromMs
          ) {
            throw new Error(
              'Interrupted execution recovery has no valid occurrence bound.'
            )
          }
          const summary = {
            schemaVersion: 'execution-interruption-summary.v2',
            grantId: grant.id,
            leaseId: lease.id,
            stepId: grant.stepId,
            adapterKind: grant.adapterKind,
            purpose: grant.purpose,
            executionState: 'interrupted',
            lastKnownDeliveryState: lease.deliveryState,
            deliveryState: 'unknown',
            verdictImpact: 'inconclusive',
            terminalReason: 'interrupted',
            interruptionTime: 'unknown',
            occurredAtSemantics: 'authorization-window-upper-bound',
            recoveredAt: new Date(recoveredAtMs).toISOString()
          } as const
          const content = Buffer.from(stableJson(summary), 'utf8')
          const capture = this.evidenceCapturePolicy.capture({
            kind: 'bytes',
            context: {
              scanId: grant.scanId,
              policyDecisionId: grant.policyDecisionId,
              techniqueId: grant.techniqueId,
              techniqueVersion: grant.techniqueVersion,
              stepId: grant.stepId,
              executionState: 'interrupted',
              source: 'execution-interruption-summary',
              role: 'interruption-summary',
              occurredAt: new Date(occurredAtMs).toISOString(),
              content: {
                mediaType: 'application/json',
                charset: 'utf-8',
                contentEncoding: 'identity',
                declaredSizeBytes: content.byteLength
              }
            },
            decision: captureDecision,
            content,
            completeness: 'complete',
            knownTotalBytes: content.byteLength
          })
          if (
            capture.state !== 'hash-only' ||
            capture.artifacts.length !== 1
          ) {
            throw new Error(
              'Interrupted execution recovery did not produce one hash-only artifact.'
            )
          }
          const artifact = capture.artifacts[0] as EvidenceArtifactDraft
          savedEvidence = await this.evidenceStore.save({
            workspaceId: target.workspaceId,
            scanId: grant.scanId,
            policyDecisionId: grant.policyDecisionId,
            type: artifact.type,
            mimeType: artifact.mimeType,
            content: stableJson(artifact),
            source: artifact.source,
            createdBy: 'application-service',
            captureTool: 'evidence-capture-policy',
            captureToolVersion: '2.0.0',
            redactionState: 'redacted'
          })
          const recovered =
            await this.repository.recoverInterruptedExecutionLeaseWithCleanup({
              leaseId: lease.id,
              evidenceId: savedEvidence.id,
              discardUnboundStagedEvidence: true
            })
          recoveredLease = recovered.lease
          discardedEvidencePaths.push(
            ...recovered.discardedEvidence.map(({ filePath }) => filePath)
          )
        } catch (error) {
          evidenceFailure = error
          try {
            const current = await this.repository.getExecutionLease(lease.id)
            if (isRecoveredInterruptedLease(current)) {
              recoveredLease = current
              evidenceFailure = undefined
            }
          } catch {
            // The fallback below is the authoritative fail-closed path.
          }
        }
      }

      if (!recoveredLease) {
        try {
          const recovered =
            await this.repository.recoverInterruptedExecutionLeaseWithCleanup({
              leaseId: lease.id,
              discardUnboundStagedEvidence: Boolean(this.evidenceStore),
              ...(savedEvidence
                ? { discardUnboundEvidenceId: savedEvidence.id }
                : {})
            })
          recoveredLease = recovered.lease
          discardedEvidencePaths.push(
            ...recovered.discardedEvidence.map(({ filePath }) => filePath)
          )
        } catch (fallbackError) {
          try {
            const current = await this.repository.getExecutionLease(lease.id)
            if (isRecoveredInterruptedLease(current)) {
              recoveredLease = current
            }
          } catch {
            // Preserve the recovery failure below.
          }
          if (!recoveredLease) {
            let cleanupError: unknown
            if (savedEvidence && this.evidenceStore) {
              try {
                await this.evidenceStore.discardUnboundEvidence(savedEvidence)
              } catch (error) {
                cleanupError = error
              }
            }
            throw new AggregateError(
              [
                ...(evidenceFailure ? [evidenceFailure] : []),
                fallbackError,
                ...(cleanupError ? [cleanupError] : [])
              ],
              `Interrupted execution lease ${lease.id} could not be terminalized.`
            )
          }
        }

        recovery.evidenceUnavailableLeaseIds.push(lease.id)
        try {
          const scan = await this.repository.getScanRow(grant.scanId)
          if (scan) {
            await this.repository.addScanEvent({
              scanId: grant.scanId,
              type: 'error',
              level: 'error',
              message:
                '中断执行的最小恢复证据无法持久化；扫描仍保持 Inconclusive 且禁止自动重放。',
              detail: {
                leaseId: lease.id,
                endState: 'inconclusive',
                evidenceState: 'unavailable'
              }
            })
          }
        } catch {
          // recoverInterruptedScans persists the authoritative checkpoint next.
        }
      }

      if (this.evidenceStore && discardedEvidencePaths.length > 0) {
        try {
          await this.evidenceStore.deleteUnreferencedFiles(
            discardedEvidencePaths
          )
        } catch {
          // The database rows were atomically discarded with terminalization.
          // A file cleanup failure must not resurrect or replay the lease.
        }
      }

      for (const evidenceRef of recoveredLease.evidenceRefs) {
        if (!recovery.evidenceRefs.includes(evidenceRef)) {
          recovery.evidenceRefs.push(evidenceRef)
        }
      }
    }
    return byScan
  }

  private mergeInterruptedScanRecoveries(
    byScan: Map<string, InterruptedScanRecoverySummary>,
    contexts: Awaited<
      ReturnType<
        AgentGoRepository['listInterruptedExecutionLeasesForScanRecovery']
      >
    >
  ): void {
    for (const { lease, grant, interruptionEvidenceId } of contexts) {
      const recovery = byScan.get(grant.scanId) ?? {
        leaseIds: [],
        evidenceRefs: [],
        evidenceUnavailableLeaseIds: []
      }
      if (!recovery.leaseIds.includes(lease.id)) {
        recovery.leaseIds.push(lease.id)
      }
      for (const evidenceRef of lease.evidenceRefs) {
        if (!recovery.evidenceRefs.includes(evidenceRef)) {
          recovery.evidenceRefs.push(evidenceRef)
        }
      }
      if (
        !interruptionEvidenceId &&
        !recovery.evidenceUnavailableLeaseIds.includes(lease.id)
      ) {
        recovery.evidenceUnavailableLeaseIds.push(lease.id)
      }
      byScan.set(grant.scanId, recovery)
    }
  }

  private async recoverInterruptedScans(
    interruptedExecutions: ReadonlyMap<
      string,
      {
        leaseIds: readonly string[]
        evidenceRefs: readonly string[]
        evidenceUnavailableLeaseIds: readonly string[]
      }
    >
  ): Promise<void> {
    const interrupted = (await this.repository.listScans()).filter((scan) =>
      ['queued', 'running'].includes(scan.status)
    )
    for (const scan of interrupted) {
      const row = await this.repository.getScanRow(scan.id)
      if (!row) continue
      const runtime = row.runtimeJson as unknown as ScanRuntimeState
      const executionRecovery = interruptedExecutions.get(scan.id)
      if (executionRecovery) {
        const awaiting = transitionRuntime(runtime, {
          type: 'await-user'
        })
        await this.repository.markScanAwaitingUser({
          scanId: scan.id,
          phase: scan.phase,
          runtimeState: awaiting as unknown as Record<string, unknown>,
          reason: 'execution-interrupted-unknown',
          message:
            '检测到可能已经发送但未确定结束的执行；已标记为 Inconclusive，禁止自动重放。',
          detail: {
            recoveredPhase: scan.phase,
            executionState: 'interrupted',
            deliveryState: 'unknown',
            verdictImpact: 'inconclusive',
            leaseIds: executionRecovery.leaseIds,
            evidenceRefs: executionRecovery.evidenceRefs,
            evidenceState:
              executionRecovery.evidenceUnavailableLeaseIds.length > 0
                ? 'partially-unavailable'
                : 'captured',
            evidenceUnavailableLeaseIds:
              executionRecovery.evidenceUnavailableLeaseIds
          }
        })
        continue
      }
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
