import {
  registerActionResult,
  transitionRuntime,
  type ScanRuntimeState
} from '@agentgo/agent-runtime'
import {
  isLegacyV1VulnerabilityFamily,
  type AgentRole,
  type Candidate,
  type CandidateAttempt,
  type CapabilityId,
  type Environment,
  type InventoryEndpoint,
  type InventoryValueType,
  type LegacyV1VulnerabilityFamily,
  type ScanControlAction,
  type ScanEvent,
  type ScanRecord,
  type SelectorRef,
  type TargetScopeRecord,
  type VulnerabilityFamily
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  ImportDiscoveryRepository,
  sha256Text,
  type CandidateAttemptRepository,
  type StoredSignalRecord,
  type ValidationPlanRepository
} from '@agentgo/db'
import type { ModelGateway, StructuredSchema } from '@agentgo/model-gateway'
import { evaluateProbe } from '@agentgo/security-policy'
import {
  AGENT_PROMPT_VERSIONS,
  AnalysisOutputSchema,
  KnowledgeAgentOutputSchema,
  PlannerOutputSchema,
  StrategyOutputSchema,
  VerifierOutputSchema,
  type PlannerOutput
} from './agent-prompts'
import { CandidateCompiler } from './candidate-compiler'
import { controlledCallbackInventoryUrl } from './controlled-callback-inventory'
import {
  DetectorService,
  schemaHintsFromImportOperations,
  type DetectorSchemaHint,
  type DetectorSinkHint
} from './detector-service'
import type { AuthorizationMatrixService } from './authorization-matrix-service'
import { resolveFrozenAssetHtml } from './asset-manifest-service'
import type { SessionVault } from './session-vault'
import type {
  BrowserFormView,
  BrowserOfflineExecutionStepInput,
  ExecutionPort,
  HttpExecutionStepInput
} from './execution-port'
import { FindingAssembler } from './finding-assembler'
import { InventoryService } from './inventory-service'
import { compileLegacyParityPlan } from './legacy-parity-adapters'
import { RetrievalService } from './retrieval-service'
import { ReportService } from './report-service'
import {
  ScanModuleSnapshotError,
  requireSealedScanModuleSnapshotSet,
  verifyScanModuleSnapshots
} from './scan-module-snapshot'
import type { VulnerabilityPlatform } from './vulnerability-platform'
import {
  type BrowserObservation,
  type HttpObservation,
  type ValidationAssessment
} from './validation-engine'
import {
  ValidationPlanExecutor,
  type CallbackCollectorPort
} from './validation-plan-executor'
import {
  ensureAttestedFixtureCallbackListen,
  LoopbackCallbackCollector,
  type LoopbackCallbackHttpServer
} from './loopback-callback-collector'

interface CoordinatorRuntimeState extends ScanRuntimeState {
  plannerRunId?: string
  plannerPlan?: PlannerOutput
  strategyRunId?: string
  candidates?: Candidate[]
  phaseOutputRefs?: Record<string, string[]>
  runStartedAt?: number
}

export interface PhaseOutcome {
  readonly kind: 'completed' | 'awaiting-user' | 'paused' | 'failed'
  readonly reason?: string
  readonly patch?: Partial<CoordinatorRuntimeState>
}

export interface ScanCoordinatorDependencies {
  repository: AgentGoRepository
  evidenceStore: EvidenceStore
  executionPort: ExecutionPort
  modelGateway: ModelGateway
  reportService: ReportService
  vulnerabilityPlatform: VulnerabilityPlatform
  vulnerabilityExecutionEnvironment: Environment
  inventoryService?: InventoryService
  retrievalService?: RetrievalService
  detectorService?: DetectorService
  candidateCompiler?: CandidateCompiler
  validationPlans?: ValidationPlanRepository
  candidateAttempts?: CandidateAttemptRepository
  authorizationMatrixService?: AuthorizationMatrixService
  sessionVault?: SessionVault
  importDiscoveryRepository?: ImportDiscoveryRepository
  callbackCollector?: CallbackCollectorPort
  onEvent?: (event: ScanEvent) => void
}

const phaseProgress: Record<ScanRecord['phase'], number> = {
  intake: 8,
  'passive-recon': 18,
  'active-enum': 38,
  hypothesis: 52,
  validation: 78,
  verification: 92,
  report: 100
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function compactAttemptReason(value: string): string {
  const compact = value
    .replace(/[\u0000-\u001f\u007f]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim()
  return compact.slice(0, 2_048) || 'Candidate attempt updated.'
}

function candidateEndpointId(candidate: Candidate): string | undefined {
  return candidate.subjectRefs.find((ref) => ref.kind === 'endpoint')?.id
}

function candidateFingerprint(candidate: Candidate): string {
  return `${candidate.techniqueId}:${candidateEndpointId(candidate) ?? 'none'}:${candidate.parameterId ?? 'none'}`
}

function attemptStatusForDecision(
  decision: CandidateAttempt['decision']
): CandidateAttempt['status'] {
  if (decision === 'awaiting-user') return 'awaiting-input'
  if (decision === 'executable') return 'planned'
  return 'rejected'
}

function responseRef(observation: HttpObservation): string {
  const reference = observation.evidenceRefs.at(-1)
  if (!reference) {
    throw new Error('ExecutionPort omitted the terminal response Evidence reference.')
  }
  return reference
}

function terminalTraceId(values: readonly string[], label: string): string {
  const value = values.at(-1)
  if (!value) {
    throw new Error(`ExecutionPort omitted the terminal ${label}.`)
  }
  return value
}

function safeBodyText(observation: HttpObservation): string {
  return observation.result.responseBody
    ? Buffer.from(observation.result.responseBody).toString('utf8')
    : ''
}

function contentTypeOf(observation: HttpObservation): string {
  return observation.result.responseHeaders['content-type'] ?? ''
}

function isHtml(observation: HttpObservation): boolean {
  const type = contentTypeOf(observation).toLowerCase()
  const body = safeBodyText(observation).trimStart().toLowerCase()
  return type.includes('text/html') || body.startsWith('<!doctype html') || body.startsWith('<html')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown scan error.'
}

function deriveSinkHint(
  parameter: { readonly name: string; readonly location: string },
  contentType?: string,
  extras: { readonly csp?: string; readonly encoding?: string } = {}
): DetectorSinkHint {
  const type = (contentType ?? '').toLowerCase()
  const encoding = extras.encoding
  const csp = extras.csp
  if (parameter.location === 'json' || type.includes('application/json')) {
    return {
      context: 'json',
      source: 'content-type',
      ...(encoding ? { encoding } : {}),
      ...(csp ? { csp } : {})
    }
  }
  if (/hash|fragment|sink|dom/i.test(parameter.name)) {
    return {
      context: 'dom',
      source: 'parameter-name',
      ...(encoding ? { encoding } : {}),
      ...(csp ? { csp } : {})
    }
  }
  if (type.includes('text/plain')) {
    return {
      context: 'text',
      encoding: encoding ?? 'plain',
      source: 'content-type',
      ...(csp ? { csp } : {})
    }
  }
  if (parameter.location === 'form' || type.includes('text/html')) {
    return {
      context: 'html',
      source: 'content-type',
      ...(encoding ? { encoding } : {}),
      ...(csp ? { csp } : {})
    }
  }
  return {
    context: 'html',
    source: 'inventory',
    ...(encoding ? { encoding } : {}),
    ...(csp ? { csp } : {})
  }
}

function cspFromHtml(html: string): string | undefined {
  const equivContent = html.match(
    /http-equiv=["']content-security-policy["'][^>]*content=["']([^"']+)/iu
  )
  if (equivContent?.[1]) return equivContent[1]
  const contentEquiv = html.match(
    /content=["']([^"']+)["'][^>]*http-equiv=["']content-security-policy["']/iu
  )
  return contentEquiv?.[1]
}

function dataTypeSchemaHints(
  endpoint: InventoryEndpoint
): Readonly<Record<string, DetectorSchemaHint>> {
  return Object.fromEntries(
    endpoint.parameters
      .filter((parameter) => parameter.dataType)
      .map((parameter) => [
        parameter.id,
        {
          format: parameter.dataType,
          operation: 'read' as const
        }
      ])
  )
}

export class DefaultScanCoordinator {
  private readonly repository: AgentGoRepository
  private readonly evidenceStore: EvidenceStore
  private readonly executionPort: ExecutionPort
  private readonly modelGateway: ModelGateway
  private readonly reportService: ReportService
  private readonly vulnerabilityPlatform: VulnerabilityPlatform
  private readonly vulnerabilityExecutionEnvironment: Environment
  private readonly inventoryService: InventoryService
  private readonly retrievalService: RetrievalService
  private readonly detectorService: DetectorService
  private readonly candidateCompiler: CandidateCompiler
  private readonly findingAssembler: FindingAssembler
  private readonly validationPlans: ValidationPlanRepository
  private readonly candidateAttempts: CandidateAttemptRepository
  private readonly authorizationMatrixService?: AuthorizationMatrixService
  private readonly sessionVault?: SessionVault
  private readonly importDiscoveryRepository?: ImportDiscoveryRepository
  private readonly callbackCollector?: CallbackCollectorPort
  private callbackCollectorListen?: LoopbackCallbackHttpServer
  private readonly inventoryHttpByEndpoint = new Map<string, HttpObservation>()
  private readonly onEvent?: (event: ScanEvent) => void
  private readonly controllers = new Map<string, AbortController>()
  private readonly tasks = new Map<string, Promise<void>>()

  constructor(dependencies: ScanCoordinatorDependencies) {
    this.repository = dependencies.repository
    this.evidenceStore = dependencies.evidenceStore
    this.executionPort = dependencies.executionPort
    this.modelGateway = dependencies.modelGateway
    this.reportService = dependencies.reportService
    this.vulnerabilityPlatform = dependencies.vulnerabilityPlatform
    this.vulnerabilityExecutionEnvironment =
      dependencies.vulnerabilityExecutionEnvironment
    this.inventoryService =
      dependencies.inventoryService ??
      new InventoryService(
        dependencies.repository,
        dependencies.vulnerabilityPlatform.capabilityCatalog
      )
    this.retrievalService =
      dependencies.retrievalService ?? new RetrievalService(dependencies.repository)
    this.detectorService = dependencies.detectorService ?? new DetectorService()
    this.candidateCompiler = dependencies.candidateCompiler ?? new CandidateCompiler()
    this.findingAssembler = new FindingAssembler(
      dependencies.vulnerabilityPlatform.definitionRegistry
    )
    this.validationPlans =
      dependencies.validationPlans ??
      dependencies.repository.createValidationPlanRepository()
    this.candidateAttempts =
      dependencies.candidateAttempts ??
      dependencies.repository.createCandidateAttemptRepository()
    this.authorizationMatrixService = dependencies.authorizationMatrixService
    this.sessionVault = dependencies.sessionVault
    this.importDiscoveryRepository = dependencies.importDiscoveryRepository
    this.callbackCollector =
      dependencies.callbackCollector ??
      (dependencies.vulnerabilityExecutionEnvironment === 'attested-fixture'
        ? new LoopbackCallbackCollector()
        : undefined)
    this.onEvent = dependencies.onEvent
  }

  async control(scanId: string, action: ScanControlAction): Promise<ScanRecord> {
    const row = await this.repository.getScanRow(scanId)
    if (!row) throw new Error('扫描不存在。')
    const runtime = row.runtimeJson as unknown as CoordinatorRuntimeState

    if (action === 'start') {
      if (row.status !== 'draft') throw new Error('只有草稿扫描可以启动。')
      const incompatible = await this.awaitOnIncompatibleModuleSnapshot(
        scanId,
        row.phase as ScanRecord['phase'],
        runtime,
        row.configJson.families,
        row.moduleSnapshotsSealed
      )
      if (incompatible) return incompatible
      await this.upsertEntryInventory(scanId)
      const awaitingReview = await this.awaitOnPendingInventoryReview(
        scanId,
        row.phase as ScanRecord['phase'],
        runtime,
        row.status as ScanRecord['status']
      )
      if (awaitingReview) return awaitingReview
      const nextRuntime: CoordinatorRuntimeState = {
        ...runtime,
        status: 'running',
        runStartedAt: runtime.runStartedAt ?? Date.now()
      }
      const scan = await this.repository.updateScan(scanId, {
        status: 'running',
        phase: runtime.phase,
        startedAt: Date.now(),
        completedAt: null,
        lastError: null,
        runtimeJson: nextRuntime as unknown as Record<string, unknown>
      })
      await this.emit({
        scanId,
        type: 'status',
        level: 'info',
        message: '扫描已启动，正在执行授权范围和预算检查。',
        detail: { action: 'start' }
      })
      this.launch(scanId)
      return scan
    }

    if (action === 'pause') {
      if (!['running', 'queued'].includes(row.status)) {
        throw new Error('只有运行中的扫描可以暂停。')
      }
      this.controllers.get(scanId)?.abort()
      const next = transitionRuntime(runtime, { type: 'pause' }) as CoordinatorRuntimeState
      await this.repository.addCheckpoint({
        scanId,
        phase: row.phase as ScanRecord['phase'],
        state: next as unknown as Record<string, unknown>,
        reason: 'user-paused'
      })
      const scan = await this.repository.updateScan(scanId, {
        status: 'paused',
        runtimeJson: next as unknown as Record<string, unknown>
      })
      await this.emit({
        scanId,
        type: 'status',
        level: 'info',
        message: '扫描已暂停，当前检查点已保存。',
        detail: { action: 'pause', phase: row.phase }
      })
      return scan
    }

    if (action === 'resume') {
      if (!['paused', 'awaiting-user'].includes(row.status)) {
        throw new Error('只有暂停或等待用户的扫描可以恢复。')
      }
      const latestCheckpoint = await this.repository.getLatestCheckpoint(scanId)
      if (latestCheckpoint?.reason === 'execution-interrupted-unknown') {
        throw new Error(
          'The latest execution may already have been sent and has an unknown terminal state; automatic resume is forbidden.'
        )
      }
      const cleanupPending = (await this.candidateAttempts.listByScan(scanId)).filter(
        (attempt) => attempt.status === 'cleanup-pending'
      )
      if (cleanupPending.length > 0) {
        throw new Error(
          'Cleanup is still pending for a previous candidate; automatic resume is forbidden.'
        )
      }
      const incompatible = await this.awaitOnIncompatibleModuleSnapshot(
        scanId,
        row.phase as ScanRecord['phase'],
        runtime,
        row.configJson.families,
        row.moduleSnapshotsSealed
      )
      if (incompatible) return incompatible
      await this.upsertEntryInventory(scanId)
      const awaitingReview = await this.awaitOnPendingInventoryReview(
        scanId,
        row.phase as ScanRecord['phase'],
        runtime,
        row.status as ScanRecord['status']
      )
      if (awaitingReview) return awaitingReview
      const next = transitionRuntime(runtime, { type: 'resume' }) as CoordinatorRuntimeState
      const scan = await this.repository.updateScan(scanId, {
        status: 'running',
        runtimeJson: next as unknown as Record<string, unknown>,
        lastError: null,
        ...(row.startedAt === null ? { startedAt: Date.now() } : {})
      })
      await this.emit({
        scanId,
        type: 'status',
        level: 'info',
        message: '扫描已从最近检查点恢复；授权、会话和预算将在继续前重新校验。',
        detail: { action: 'resume', phase: row.phase }
      })
      this.launch(scanId)
      return scan
    }

    if (['completed', 'failed', 'cancelled'].includes(row.status)) {
      return (await this.repository.getScan(scanId))!
    }
    this.controllers.get(scanId)?.abort()
    const next = transitionRuntime(runtime, { type: 'cancel' }) as CoordinatorRuntimeState
    const scan = await this.repository.updateScan(scanId, {
      status: 'cancelled',
      completedAt: Date.now(),
      runtimeJson: next as unknown as Record<string, unknown>
    })
    await this.emit({
      scanId,
      type: 'status',
      level: 'warning',
      message: '扫描已取消，已保存的证据和审计记录不会删除。',
      detail: { action: 'cancel', phase: row.phase }
    })
    return scan
  }

  async waitForScan(scanId: string): Promise<ScanRecord> {
    await this.tasks.get(scanId)
    const scan = await this.repository.getScan(scanId)
    if (!scan) throw new Error('扫描不存在。')
    return scan
  }

  async shutdown(): Promise<void> {
    for (const scanId of this.controllers.keys()) {
      const row = await this.repository.getScanRow(scanId)
      if (row?.status === 'running') {
        const runtime = row.runtimeJson as unknown as CoordinatorRuntimeState
        const paused = transitionRuntime(runtime, { type: 'pause' }) as CoordinatorRuntimeState
        await this.repository.addCheckpoint({
          scanId,
          phase: row.phase as ScanRecord['phase'],
          state: paused as unknown as Record<string, unknown>,
          reason: 'application-shutdown'
        })
        await this.repository.updateScan(scanId, {
          status: 'paused',
          runtimeJson: paused as unknown as Record<string, unknown>
        })
      }
    }
    for (const controller of this.controllers.values()) controller.abort()
    await Promise.allSettled(this.tasks.values())
  }

  private launch(scanId: string): void {
    if (this.tasks.has(scanId)) return
    const controller = new AbortController()
    this.controllers.set(scanId, controller)
    const task = this.run(scanId, controller.signal)
      .catch(async (error: unknown) => {
        const current = await this.repository.getScanRow(scanId)
        if (!current || ['paused', 'cancelled'].includes(current.status)) return
        const runtime = current.runtimeJson as unknown as CoordinatorRuntimeState
        const failedRuntime =
          runtime.status === 'running'
            ? ({ ...runtime, status: 'failed' } as CoordinatorRuntimeState)
            : runtime
        await this.repository.updateScan(scanId, {
          status: 'failed',
          completedAt: Date.now(),
          lastError: errorMessage(error),
          runtimeJson: failedRuntime as unknown as Record<string, unknown>
        })
        await this.emit({
          scanId,
          type: 'error',
          level: 'error',
          message: `扫描失败：${errorMessage(error)}`,
          detail: { phase: current.phase }
        })
      })
      .finally(() => {
        if (this.controllers.get(scanId) === controller) this.controllers.delete(scanId)
        this.tasks.delete(scanId)
      })
    this.tasks.set(scanId, task)
  }

  private async run(scanId: string, signal: AbortSignal): Promise<void> {
    while (true) {
      this.assertNotAborted(signal)
      const row = await this.repository.getScanRow(scanId)
      if (!row || row.status !== 'running') return
      const runtime = row.runtimeJson as unknown as CoordinatorRuntimeState
      await this.assertBudget(scanId, runtime)
      if (row.phase === 'active-enum') {
        await this.upsertEntryInventory(scanId)
        const awaitingReview = await this.awaitOnPendingInventoryReview(
          scanId,
          row.phase as ScanRecord['phase'],
          runtime,
          row.status as ScanRecord['status']
        )
        if (awaitingReview) return
      }
      const outcome = await this.runPhase(
        scanId,
        row.phase as ScanRecord['phase'],
        runtime,
        signal
      )
      this.assertNotAborted(signal)
      const patch = outcome.patch ?? {}
      const stateAfterPhase = {
        ...runtime,
        ...patch,
        phaseOutputRefs: {
          ...(runtime.phaseOutputRefs ?? {}),
          ...(patch.phaseOutputRefs ?? {})
        }
      }
      if (outcome.kind === 'awaiting-user') {
        const next = transitionRuntime(stateAfterPhase, {
          type: 'await-user'
        }) as CoordinatorRuntimeState
        const checkpointId = await this.repository.addCheckpoint({
          scanId,
          phase: row.phase as ScanRecord['phase'],
          state: next as unknown as Record<string, unknown>,
          reason: outcome.reason ?? 'awaiting-user'
        })
        await this.repository.updateScan(scanId, {
          status: 'awaiting-user',
          phase: row.phase as ScanRecord['phase'],
          progress: phaseProgress[row.phase as ScanRecord['phase']],
          runtimeJson: next as unknown as Record<string, unknown>
        })
        await this.emit({
          scanId,
          type: 'status',
          level: 'warning',
          message: outcome.reason ?? '扫描等待用户确认后才能继续。',
          detail: {
            phase: row.phase,
            checkpointId
          }
        })
        return
      }
      if (outcome.kind === 'failed') {
        const next = transitionRuntime(stateAfterPhase, { type: 'fail' }) as CoordinatorRuntimeState
        await this.repository.updateScan(scanId, {
          status: 'failed',
          completedAt: Date.now(),
          lastError: outcome.reason ?? '阶段失败。',
          runtimeJson: next as unknown as Record<string, unknown>
        })
        return
      }
      if (outcome.kind === 'paused') {
        const next = transitionRuntime(stateAfterPhase, { type: 'pause' }) as CoordinatorRuntimeState
        await this.repository.updateScan(scanId, {
          status: 'paused',
          runtimeJson: next as unknown as Record<string, unknown>
        })
        return
      }
      const next = transitionRuntime(stateAfterPhase, {
        type: 'phase-completed',
        checkpointRef: `${row.phase}:${Date.now()}`
      }) as CoordinatorRuntimeState
      const checkpointId = await this.repository.addCheckpoint({
        scanId,
        phase: row.phase as ScanRecord['phase'],
        state: next as unknown as Record<string, unknown>,
        reason: `phase-completed:${row.phase}`
      })
      const completed = next.status === 'completed'
      await this.repository.updateScan(scanId, {
        status: completed ? 'completed' : 'running',
        phase: next.phase,
        progress: phaseProgress[row.phase as ScanRecord['phase']],
        completedAt: completed ? Date.now() : null,
        runtimeJson: next as unknown as Record<string, unknown>
      })
      await this.emit({
        scanId,
        type: 'phase',
        level: 'info',
        message: completed
          ? '扫描已完成，报告和证据链已归档。'
          : `阶段 ${row.phase} 已完成，进入 ${next.phase}。`,
        detail: { completedPhase: row.phase, nextPhase: next.phase, checkpointId }
      })
      if (completed) return
    }
  }

  private async runPhase(
    scanId: string,
    phase: ScanRecord['phase'],
    runtime: CoordinatorRuntimeState,
    signal: AbortSignal
  ): Promise<PhaseOutcome> {
    switch (phase) {
      case 'intake':
        return { kind: 'completed', patch: await this.runIntake(scanId, signal) }
      case 'passive-recon':
        return { kind: 'completed', patch: await this.runPassiveRecon(scanId) }
      case 'active-enum':
        return this.runEnumeration(scanId, runtime, signal)
      case 'hypothesis':
        return this.runHypothesis(scanId, runtime, signal)
      case 'validation':
        return this.runValidation(scanId, runtime, signal)
      case 'verification':
        await this.runVerificationAudit(scanId)
        return { kind: 'completed' }
      case 'report':
        await this.runReport(scanId)
        return { kind: 'completed' }
    }
  }

  private async runIntake(
    scanId: string,
    signal: AbortSignal
  ): Promise<Partial<CoordinatorRuntimeState>> {
    const context = await this.loadContext(scanId)
    this.assertNotAborted(signal)
    if (!context.target.authorizationReference.trim()) {
      throw new Error('目标缺少明确授权依据。')
    }
    const now = Date.now()
    if (context.scope.validFrom && Date.parse(context.scope.validFrom) > now) {
      throw new Error('Scope 尚未生效。')
    }
    if (context.scope.validUntil && Date.parse(context.scope.validUntil) <= now) {
      throw new Error('Scope 已过期。')
    }
    const planner = await this.runAgent({
      scanId,
      role: 'planner',
      schema: PlannerOutputSchema,
      input: {
        engagement: {
          name: context.scan.name,
          description: context.scan.description
        },
        target: {
          name: context.target.name,
          baseUrl: context.target.baseUrl,
          description: context.target.description,
          authorizationReference: context.target.authorizationReference
        },
        scope: {
          id: context.scope.id,
          allowedOrigins: context.scope.allowedOrigins,
          allowedPathPrefixes: context.scope.allowedPathPrefixes,
          deniedPathPrefixes: context.scope.deniedPathPrefixes
        },
        families: context.scan.families,
        budget: context.scan.budget,
        stopConditions: [
          '获得满足确认规则的最小证据',
          '离开授权范围',
          '出现非预期副作用',
          '达到请求、时间或模型 Token 预算',
          '连续重复且无新证据'
        ]
      }
    })
    return {
      plannerRunId: planner.runId,
      plannerPlan: planner.value,
      phaseOutputRefs: { intake: [planner.outputRef] },
      runStartedAt: Date.now()
    }
  }

  private async runPassiveRecon(scanId: string): Promise<Partial<CoordinatorRuntimeState>> {
    const context = await this.loadContext(scanId)
    const evidence = await this.saveJsonEvidence(
      scanId,
      'passive-recon-summary',
      {
        target: context.target.baseUrl,
        authorizationReference: context.target.authorizationReference,
        scopeSnapshotId: context.scope.id,
        allowedOrigins: context.scope.allowedOrigins,
        allowedPaths: context.scope.allowedPathPrefixes,
        deniedPaths: context.scope.deniedPathPrefixes,
        identities: context.identities.map((identity) => ({
          id: identity.id,
          label: identity.label,
          role: identity.role,
          authType: identity.authType,
          isTestIdentity: identity.isTestIdentity,
          ownedResourceCount: identity.ownedResourceIds.length
        })),
        note: '本阶段仅整理用户提供的目标、授权和身份信息，不产生漏洞结论。'
      },
      'planner'
    )
    return { phaseOutputRefs: { 'passive-recon': [evidence.id] } }
  }

  private async runEnumeration(
    scanId: string,
    runtime: CoordinatorRuntimeState,
    signal: AbortSignal
  ): Promise<PhaseOutcome> {
    const existingPages = await this.repository.listPages(scanId)
    const seedFetched = existingPages.some(
      (page) => page.depth === 0 && (page.status === 'fetched' || page.status === 'inspected')
    )
    if (!seedFetched) {
      await this.runEnumerationFetch(scanId, runtime, signal)
    }
    const pendingReviewVariantIds =
      await this.repository.listPendingActiveL1ReviewVariantIds(scanId)
    if (pendingReviewVariantIds.length > 0) {
      return {
        kind: 'awaiting-user',
        reason: 'inventory-review-required'
      }
    }
    return { kind: 'completed' }
  }

  private async runEnumerationFetch(
    scanId: string,
    runtime: CoordinatorRuntimeState,
    signal: AbortSignal
  ): Promise<void> {
    const context = await this.loadContext(scanId)
    const agentRunId =
      runtime.plannerRunId ??
      (
        await this.createControlAgentRun(
          scanId,
          'planner',
          'agentgo.safe-enumeration.v1',
          '1.0.0'
        )
      ).id
    const primaryIdentity = context.identities[0]
    const inventoryReadFamily = await this.executionFamilyForCapability(
      scanId,
      'http.reviewed-read'
    )
    const browserOfflineFamily = await this.executionFamilyForCapability(
      scanId,
      'browser.offline-replay',
      false
    )
    const queue: Array<{ url: string; depth: number; discoveredFrom?: string }> = [
      { url: context.target.baseUrl, depth: 0 }
    ]
    const visited = new Set<string>()
    const remainingBudget = Math.max(0, context.scan.budget.maxRequests - context.scan.requestCount)
    const maximumPages = Math.max(1, Math.min(12, Math.floor(remainingBudget / 2) || 1))

    while (queue.length > 0 && visited.size < maximumPages) {
      this.assertNotAborted(signal)
      const next = queue.shift()!
      const normalized = new URL(next.url)
      normalized.hash = ''
      const url = normalized.toString()
      if (visited.has(url) || !this.urlAllowed(url, context.scope, primaryIdentity?.id)) continue
      visited.add(url)
      const inventory = await this.upsertReadInventory({
        scanId,
        url,
        sourceType: next.discoveredFrom ? 'link' : 'target-base',
        ...(next.discoveredFrom
          ? { pageId: next.discoveredFrom, initiator: next.discoveredFrom }
          : {})
      })
      const endpointId = inventory.endpoint.id
      // The exact user-configured target base is the bounded enumeration seed.
      // Page-derived URLs are inventoried below but never fetched before review.
      if (next.discoveredFrom) continue
      const http = await this.executeHttpProbe({
        scanId,
        agentRunId,
        familyId: inventoryReadFamily,
        stepId: 'inventory.target-base.read',
        purpose: 'read',
        endpointId,
        desiredUrl: url,
        ...(primaryIdentity ? { identityId: primaryIdentity.id } : {}),
        summary: '低速读取页面并建立接口与参数基线。',
        expectedEvidence: '页面响应摘要、响应体和内容哈希',
        signal
      })
      this.inventoryHttpByEndpoint.set(endpointId, http)
      if (http.result.status !== 'succeeded' || !isHtml(http)) continue
      const page = await this.repository.upsertPage({
        scanId,
        url: inventory.requestVariant.redactedPreview.url,
        depth: next.depth,
        ...(next.discoveredFrom ? { discoveredFrom: next.discoveredFrom } : {}),
        stateHash: http.result.responseBodySha256,
        status: 'fetched'
      })
      if (!browserOfflineFamily) continue
      const browser = await this.executeBrowserProbe({
        scanId,
        agentRunId,
        familyId: browserOfflineFamily,
        stepId: 'inventory.target-base.offline-inspect',
        purpose: 'read',
        baseUrl: url,
        summary: '在断网隔离浏览器中提取页面链接与表单。',
        expectedEvidence: 'DOM 摘要、链接和表单清单',
        html: safeBodyText(http),
        action: 'inspect-dom',
        ...(http.result.responseHeaders['content-security-policy']
          ? { contentSecurityPolicy: http.result.responseHeaders['content-security-policy'] }
          : {}),
        signal
      })
      if (browser.result.pageTitle) {
        await this.repository.upsertPage({
          scanId,
          url: inventory.requestVariant.redactedPreview.url,
          title: browser.result.pageTitle,
          depth: next.depth,
          ...(next.discoveredFrom ? { discoveredFrom: next.discoveredFrom } : {}),
          status: 'inspected'
        })
      }
      for (const link of browser.result.links) {
        if (!this.urlAllowed(link, context.scope, primaryIdentity?.id)) continue
        await this.upsertReadInventory({
          scanId,
          pageId: page.id,
          url: link,
          sourceType: 'link',
          initiator: page.id
        })
      }
      for (const form of browser.result.forms) {
        await this.persistForm(scanId, page.id, form)
      }
    }

    await this.emit({
      scanId,
      type: 'phase',
      level: 'info',
      message: `安全主动枚举完成：访问 ${visited.size} 个页面。`,
      detail: {
        pages: visited.size,
        endpointCount: (await this.repository.listInventoryEndpoints(scanId)).length
      }
    })
  }

  private async runHypothesis(
    scanId: string,
    runtime: CoordinatorRuntimeState,
    signal: AbortSignal
  ): Promise<PhaseOutcome> {
    const context = await this.loadContext(scanId)
    const endpoints = await this.repository.listLegacyV1ExecutionEndpoints(scanId)
    const endpointParameterNames = unique(
      endpoints.flatMap((endpoint) => endpoint.parameters.map((parameter) => parameter.name))
    )
    // Retrieval may use stable endpoint semantics, but never raw query values
    // or credentials.  This gives KnowledgeAgent useful context for routes
    // such as /search, /redirect and /resource without exporting user data.
    const endpointPathTerms = unique(
      endpoints.flatMap((endpoint) =>
        new URL(endpoint.url).pathname
          .split(/[/. _-]+/)
          .map((term) => term.trim())
          .filter((term) => term.length >= 2)
      )
    )
    const knowledgeOutput = (
      await this.retrievalService.retrieveForScan({
        families: context.scan.families,
        signalTerms: unique([...endpointParameterNames, ...endpointPathTerms])
      })
    ).coordinatorOutput
    const knowledge = await this.runAgent({
      scanId,
      role: 'knowledge',
      schema: KnowledgeAgentOutputSchema,
      parentRunId: runtime.plannerRunId,
      inputRefs: runtime.phaseOutputRefs?.intake ?? [],
      input: {
        engagementDescription: context.scan.description,
        plannerPlan: runtime.plannerPlan,
        families: context.scan.families,
        endpointParameterNames,
        knowledgeOutput
      }
    })
    this.assertNotAborted(signal)
    const strategy = await this.runAgent({
      scanId,
      role: 'strategy',
      schema: StrategyOutputSchema,
      parentRunId: knowledge.runId,
      inputRefs: [
        ...(runtime.phaseOutputRefs?.intake ?? []),
        knowledge.outputRef
      ],
      input: {
        engagementDescription: context.scan.description,
        plannerPlan: runtime.plannerPlan,
        families: context.scan.families,
        endpoints: endpoints.map((endpoint) => ({
          id: endpoint.id,
          method: endpoint.method,
          url: endpoint.url,
          parameters: endpoint.parameters.map((parameter) => ({
            id: parameter.id,
            name: parameter.name,
            location: parameter.location
          }))
        })),
        knowledgePack: knowledge.value,
        policyCapabilities: {
          readOnly: true,
          activeSafe: context.scope.allowActiveProbing,
          sensitive: false,
          destructive: false
        }
      }
    })
    const surfaces = await Promise.all(
      endpoints.map(async (endpoint) => {
        const binding = await this.repository.getLegacyV1ExecutionBinding(scanId, endpoint.id)
        return {
          endpoint,
          variantIds: binding ? [binding.requestVariant.id] : [],
          method: endpoint.method,
          reviewStatus: binding?.requestVariant.reviewStatus,
          executionClass: binding?.requestVariant.executionClass,
          codec: binding?.requestVariant.codec,
          contentType: endpoint.contentType
        }
      })
    )
    const matrix = await this.resolveAuthorizationMatrix(context)
    const importOperations = this.importDiscoveryRepository
      ? (
          await this.importDiscoveryRepository.listCommittedImportPreviews(scanId)
        ).flatMap((preview) => preview.operations)
      : []
    const frozenManifests = this.importDiscoveryRepository
      ? await this.importDiscoveryRepository.listFrozenAssetManifests(scanId)
      : []
    const seeds = this.detectorService.detect({
      families: context.scan.families,
      surfaces: await Promise.all(
        surfaces.map(async (surface) => {
          const frozenHtml =
            frozenManifests.length > 0
              ? await resolveFrozenAssetHtml({
                  manifests: frozenManifests,
                  url: surface.endpoint.url,
                  readArtifact: async (artifactRef) => {
                    const read = await this.evidenceStore.read(artifactRef)
                    return { content: read.content }
                  }
                })
              : undefined
          const csp = frozenHtml ? cspFromHtml(frozenHtml) : undefined
          return {
            ...surface,
            sinkHints: Object.fromEntries(
              surface.endpoint.parameters.map((parameter) => [
                parameter.id,
                deriveSinkHint(parameter, surface.contentType, {
                  ...(csp ? { csp } : {})
                })
              ])
            ),
            schemaHints: {
              ...dataTypeSchemaHints(surface.endpoint),
              ...schemaHintsFromImportOperations(surface.endpoint, importOperations)
            }
          }
        })
      ),
      registry: this.vulnerabilityPlatform.definitionRegistry,
      identities: context.identities.map((identity) => ({
        id: identity.id,
        role: identity.role,
        isTestIdentity: identity.isTestIdentity,
        ownedResourceIds: identity.ownedResourceIds
      })),
      ...(matrix ? { matrixId: matrix.matrixId } : {})
    })
    const compiled = this.candidateCompiler.compile({
      seeds,
      suggestions: strategy.value.candidates,
      registry: this.vulnerabilityPlatform.definitionRegistry,
      surfaces: surfaces.map((surface) => ({
        endpointId: surface.endpoint.id,
        method: surface.method,
        ...(surface.variantIds[0] ? { variantId: surface.variantIds[0] } : {}),
        variantIds: surface.variantIds,
        ...(surface.reviewStatus ? { reviewStatus: surface.reviewStatus } : {}),
        ...(surface.executionClass ? { executionClass: surface.executionClass } : {}),
        ...(surface.codec ? { codec: surface.codec } : {}),
        parameters: surface.endpoint.parameters.map((parameter) => ({
          id: parameter.id,
          location: parameter.location
        }))
      })),
      environment: this.vulnerabilityExecutionEnvironment
    })
    const now = new Date().toISOString()
    for (const record of compiled) {
      await this.candidateAttempts.save({
        attemptId: record.candidate.candidateId,
        scanId,
        candidateId: record.candidate.candidateId,
        candidate: record.candidate,
        status: attemptStatusForDecision(record.decision),
        decision: record.decision,
        grantRefs: [],
        evidenceRefs: [],
        reason: record.reason,
        createdAt: now,
        updatedAt: now
      })
    }
    const executable = compiled
      .filter((record) => record.decision === 'executable')
      .map((record) => record.candidate)
    const awaitingUser = compiled.filter((record) => record.decision === 'awaiting-user')
    await this.emit({
      scanId,
      type: 'agent',
      level: 'info',
      message: `Detector 与 Strategy 形成 ${executable.length} 个可执行验证候选。`,
      detail: {
        candidateCount: executable.length,
        seedCount: seeds.length,
        skippedReasons: strategy.value.skippedReasons
      }
    })
    const patch: Partial<CoordinatorRuntimeState> = {
      strategyRunId: strategy.runId,
      candidates: executable,
      phaseOutputRefs: {
        hypothesis: [knowledge.outputRef, strategy.outputRef]
      }
    }
    if (awaitingUser.length > 0 && executable.length === 0) {
      return {
        kind: 'awaiting-user',
        reason: awaitingUser[0]?.reason ?? 'Candidate compilation is waiting for user input.',
        patch
      }
    }
    return { kind: 'completed', patch }
  }

  private async runValidation(
    scanId: string,
    runtime: CoordinatorRuntimeState,
    signal: AbortSignal
  ): Promise<PhaseOutcome> {
    const candidates = runtime.candidates ?? []
    let nextRuntime = runtime
    const attempts = await this.candidateAttempts.listByScan(scanId)
    let agentRunId = runtime.strategyRunId
    for (const candidate of candidates) {
      this.assertNotAborted(signal)
      this.vulnerabilityPlatform.executionGate.requireExecutableFamily(
        candidate.familyId,
        this.vulnerabilityExecutionEnvironment
      )
      if (!agentRunId) {
        agentRunId = (
          await this.createControlAgentRun(
            scanId,
            'strategy',
            'agentgo.strategy-recovery.v1',
            '1.0.0'
          )
        ).id
      }
      const fingerprint = candidateFingerprint(candidate)
      if (nextRuntime.actionFingerprints.includes(fingerprint)) continue
      const endpointId = candidateEndpointId(candidate)
      const endpoint = (await this.repository.listLegacyV1ExecutionEndpoints(scanId)).find(
        (item) => item.id === endpointId
      )
      if (!endpoint || endpoint.method.toUpperCase() !== 'GET') {
        nextRuntime = registerActionResult(nextRuntime, fingerprint, false)
          .state as CoordinatorRuntimeState
        continue
      }
      const attempt = attempts.find((item) => item.candidateId === candidate.candidateId)
      try {
        const outcome = await this.executeCompiledCandidate({
          scanId,
          agentRunId,
          candidate,
          endpoint,
          attempt,
          signal
        })
        if (outcome.kind === 'awaiting-user') {
          return {
            kind: 'awaiting-user',
            reason: outcome.reason,
            patch: nextRuntime
          }
        }
        nextRuntime = registerActionResult(nextRuntime, fingerprint, outcome.executed)
          .state as CoordinatorRuntimeState
      } catch (error) {
        if (signal.aborted) throw error
        await this.emit({
          scanId,
          type: 'error',
          level: 'error',
          message: `${this.findingAssembler.displayName(candidate.familyId)} 候选未完成：${errorMessage(error)}`,
          detail: { fingerprint }
        })
        nextRuntime = registerActionResult(nextRuntime, fingerprint, false)
          .state as CoordinatorRuntimeState
        await this.markAttempt(attempt, {
          status: 'failed',
          reason: errorMessage(error)
        })
      }
      await this.repository.addCheckpoint({
        scanId,
        phase: 'validation',
        state: nextRuntime as unknown as Record<string, unknown>,
        reason: `candidate-completed:${fingerprint}`
      })
      await this.assertBudget(scanId, nextRuntime)
    }
    return { kind: 'completed', patch: nextRuntime }
  }

  private async executeCompiledCandidate(input: {
    scanId: string
    agentRunId: string
    candidate: Candidate
    endpoint: InventoryEndpoint
    attempt: CandidateAttempt | undefined
    signal: AbortSignal
  }): Promise<{
    kind: 'completed' | 'awaiting-user'
    executed: boolean
    reason?: string
  }> {
    const context = await this.loadContext(input.scanId)
    await this.markAttempt(input.attempt, { status: 'running' })
    const matrix = await this.resolveAuthorizationMatrix(context)
    const frozenAssetHtml = this.importDiscoveryRepository
      ? await resolveFrozenAssetHtml({
          manifests: await this.importDiscoveryRepository.listFrozenAssetManifests(
            input.scanId
          ),
          url: input.endpoint.url,
          readArtifact: async (artifactRef) => {
            const read = await this.evidenceStore.read(artifactRef)
            return { content: read.content }
          }
        })
      : undefined
    const callbackCollectorListenUrl = await this.resolveCallbackCollectorListenUrl()
    const compiled = await compileLegacyParityPlan({
      scanId: input.scanId,
      candidate: input.candidate,
      endpoint: input.endpoint,
      identities: context.identities,
      allowedIdentityIds: context.scope.allowedIdentityIds,
      environment: this.vulnerabilityExecutionEnvironment,
      ...(context.row.configJson.callbackUrl
        ? { callbackUrl: context.row.configJson.callbackUrl }
        : {}),
      ...(matrix ? { authorizationMatrix: matrix } : {}),
      ...(frozenAssetHtml ? { frozenAssetHtml } : {}),
      ...(this.inventoryHttpByEndpoint.get(input.endpoint.id)?.result.responseHeaders
        ? {
            existingResponseHeaders:
              this.inventoryHttpByEndpoint.get(input.endpoint.id)!.result
                .responseHeaders
          }
        : {}),
      ...(this.callbackCollector ? { callbackCollectorAvailable: true } : {}),
      ...(callbackCollectorListenUrl
        ? { callbackCollectorListenUrl }
        : {}),
      upsertReadInventory: async (inventory) => {
        const result = await this.upsertReadInventory({
          scanId: input.scanId,
          url: inventory.url,
          sourceType: inventory.sourceType
        })
        return {
          endpoint: {
            id: result.endpoint.id,
            method: result.endpoint.method,
            url: inventory.url,
            source: inventory.sourceType,
            parameters: []
          },
          requestVariant: {
            reviewStatus: result.requestVariant.reviewStatus
          }
        }
      }
    })
    if (compiled.kind !== 'plan') {
      const status =
        compiled.kind === 'awaiting-user' ? 'awaiting-input' : 'rejected'
      await this.markAttempt(input.attempt, {
        status,
        decision: compiled.kind === 'forbidden' ? 'forbidden' : compiled.kind,
        reason: compiled.reason
      })
      if (compiled.kind === 'awaiting-user') {
        return { kind: 'awaiting-user', executed: false, reason: compiled.reason }
      }
      return { kind: 'completed', executed: false, reason: compiled.reason }
    }
    const executor = new ValidationPlanExecutor({
      plans: this.validationPlans,
      execution: this.executionPort,
      agentRunId: input.agentRunId,
      ...(this.sessionVault ? { sessionVault: this.sessionVault } : {}),
      ...(this.callbackCollector ? { callbackCollector: this.callbackCollector } : {}),
      repository: this.repository
    })
    const execution = await executor.execute(compiled.draft, {
      signal: input.signal,
      ...(frozenAssetHtml
        ? { htmlSeeds: { 'xss.dom.capture': frozenAssetHtml } }
        : {})
    })
    const hasHttpSteps = compiled.draft.steps.some((step) => step.kind === 'http-request')
    const inventoryHttp = this.inventoryHttpByEndpoint.get(input.endpoint.id)
    const baseline =
      execution.httpByStep.get(compiled.observations.baselineStepId) ??
      (!hasHttpSteps ? inventoryHttp : undefined)
    const primary =
      execution.httpByStep.get(compiled.observations.primaryStepId) ??
      (!hasHttpSteps ? inventoryHttp : undefined)
    const negative = compiled.observations.negativeStepId
      ? execution.httpByStep.get(compiled.observations.negativeStepId)
      : undefined
    if (!baseline || !primary || execution.run.status !== 'succeeded') {
      await this.markAttempt(input.attempt, {
        status: 'failed',
        planId: execution.plan.planId,
        planHash: execution.plan.planHash,
        planRunId: execution.run.runId,
        reason: execution.run.stopReason ?? 'Validation plan did not complete.'
      })
      return { kind: 'completed', executed: false }
    }
    const assessment = compiled.assess(execution)
    const evidenceRefs = unique([
      ...[...execution.httpByStep.values()].flatMap((item) => item.evidenceRefs),
      ...[...execution.browserByStep.values()].flatMap((item) => item.evidenceRefs)
    ])
    const analysisResult = await this.createSignalFromAssessment({
      scanId: input.scanId,
      parentRunId: input.agentRunId,
      endpoint: input.endpoint,
      ...(input.candidate.parameterId
        ? { parameterId: input.candidate.parameterId }
        : {}),
      identityId: context.identities[0]?.id,
      primary,
      assessment,
      evidenceRefs
    })
    const verdict = await this.verifyAssessment({
      scanId: input.scanId,
      parentRunId: analysisResult.runId,
      inputRefs: [analysisResult.outputRef, ...evidenceRefs],
      signal: analysisResult.signal,
      assessment,
      evidenceRefs
    })
    const familyRule = this.findingAssembler.confirmationRule(assessment.family)
    if (
      familyRule &&
      (familyRule.id !== assessment.confirmationRuleId ||
        familyRule.version !== assessment.confirmationRuleVersion)
    ) {
      await this.repository.ensureConfirmationRule({
        id: familyRule.id,
        version: familyRule.version,
        family: familyRule.family,
        rule: familyRule.rule,
        requiredChecks: familyRule.requiredChecks,
        sourceRefs: familyRule.sourceRefs
      })
    }
    await this.repository.ensureConfirmationRule({
      id: assessment.confirmationRuleId,
      version: assessment.confirmationRuleVersion,
      family: assessment.family,
      rule: familyRule?.id === assessment.confirmationRuleId
        ? familyRule.rule
        : { techniqueId: input.candidate.techniqueId },
      requiredChecks:
        familyRule?.id === assessment.confirmationRuleId
          ? familyRule.requiredChecks
          : [
              ...assessment.completedChecks,
              ...assessment.failedChecks,
              ...assessment.missingChecks
            ],
      sourceRefs:
        familyRule?.id === assessment.confirmationRuleId
          ? familyRule.sourceRefs
          : ['registry']
    })
    const parameter = input.endpoint.parameters.find(
      (item) => item.id === input.candidate.parameterId
    )
    const assembled = this.findingAssembler.assemble({
      familyId: input.candidate.familyId,
      techniqueId: input.candidate.techniqueId,
      moduleVersion: input.candidate.moduleVersion,
      pathname: new URL(input.endpoint.url).pathname,
      ...(parameter ? { parameterName: parameter.name } : {}),
      assessment
    })
    await this.repository.createValidationRun({
      signalId: analysisResult.signal.id,
      confirmationRuleId: assembled.confirmationRuleId,
      confirmationRuleVersion: assembled.confirmationRuleVersion,
      probeProposalId: primary.proposalId,
      policyDecisionId: primary.policyDecisionId,
      toolCallId: primary.toolCallId,
      baselineRef: responseRef(baseline),
      testRef: responseRef(primary),
      ...(negative ? { negativeControlRef: responseRef(negative) } : {}),
      completedChecks: assessment.completedChecks,
      failedChecks: assessment.failedChecks,
      missingChecks: assessment.missingChecks,
      cleanupStatus: 'not-needed',
      result: verdict.verdict
    })
    const finding = await this.repository.createFinding({
      scanId: input.scanId,
      family: input.candidate.familyId,
      title: assembled.title,
      verdict: verdict.verdict,
      severity: verdict.verdict === 'confirmed' ? assembled.severity : 'info',
      confidence:
        verdict.verdict === assessment.verdict
          ? assessment.confidence
          : Math.min(assessment.confidence, 0.5),
      endpointId: input.endpoint.id,
      ...(input.candidate.parameterId
        ? { parameterId: input.candidate.parameterId }
        : {}),
      ...(context.identities[0] ? { identityId: context.identities[0].id } : {}),
      ...(compiled.affectedResource
        ? { affectedResource: compiled.affectedResource }
        : {}),
      cwe: assembled.cwe,
      owasp: assembled.owasp,
      confirmationRuleId: assembled.confirmationRuleId,
      confirmationRuleVersion: assembled.confirmationRuleVersion,
      reproducibility: verdict.explanation,
      remediation: assembled.remediation,
      evidenceRefs
    })
    await this.emit({
      scanId: input.scanId,
      type: 'finding',
      level: finding.verdict === 'confirmed' ? 'warning' : 'info',
      message: `${finding.title} -> ${finding.verdict}`,
      detail: {
        findingId: finding.id,
        signalId: analysisResult.signal.id,
        rule: `${assembled.confirmationRuleId}@${assembled.confirmationRuleVersion}`,
        evidenceCount: evidenceRefs.length
      }
    })
    await this.markAttempt(input.attempt, {
      status: verdict.verdict === 'inconclusive' ? 'inconclusive' : 'completed',
      planId: execution.plan.planId,
      planHash: execution.plan.planHash,
      planRunId: execution.run.runId,
      evidenceRefs,
      reason: verdict.explanation.slice(0, 2_048)
    })
    return { kind: 'completed', executed: evidenceRefs.length > 0 }
  }

  private async markAttempt(
    attempt: CandidateAttempt | undefined,
    patch: {
      status: CandidateAttempt['status']
      decision?: CandidateAttempt['decision']
      planId?: string
      planHash?: string
      planRunId?: string
      evidenceRefs?: readonly string[]
      reason?: string
    }
  ): Promise<void> {
    if (!attempt) return
    const now = new Date().toISOString()
    const terminal =
      patch.status === 'completed' ||
      patch.status === 'failed' ||
      patch.status === 'inconclusive' ||
      patch.status === 'rejected' ||
      patch.status === 'cancelled'
    await this.candidateAttempts.update({
      ...attempt,
      status: patch.status,
      decision: patch.decision ?? attempt.decision,
      ...(patch.planId ? { planId: patch.planId } : {}),
      ...(patch.planHash ? { planHash: patch.planHash } : {}),
      ...(patch.planRunId ? { planRunId: patch.planRunId } : {}),
      evidenceRefs: patch.evidenceRefs ? [...patch.evidenceRefs] : attempt.evidenceRefs,
      ...(patch.reason ? { reason: compactAttemptReason(patch.reason) } : {}),
      updatedAt: now,
      ...(terminal ? { completedAt: now } : {})
    })
  }

  private async createSignalFromAssessment(input: {
    scanId: string
    parentRunId: string
    endpoint: InventoryEndpoint
    parameterId?: string
    identityId?: string
    primary: HttpObservation
    assessment: ValidationAssessment
    evidenceRefs: string[]
  }): Promise<{
    signal: StoredSignalRecord
    runId: string
    outputRef: string
  }> {
    const analysis = await this.runAgent({
      scanId: input.scanId,
      role: 'analysis',
      schema: AnalysisOutputSchema,
      parentRunId: input.parentRunId,
      inputRefs: input.evidenceRefs,
      input: {
        family: input.assessment.family,
        endpointId: input.endpoint.id,
        parameterId: input.parameterId,
        summary: input.assessment.signalSummary,
        confidenceHint: input.assessment.confidence,
        observedChecks: [
          ...input.assessment.completedChecks,
          ...input.assessment.failedChecks.map((check) => `failed:${check}`)
        ]
      }
    })
    const signal = await this.repository.createSignal({
      scanId: input.scanId,
      ...(input.primary.interactionId
        ? { interactionId: input.primary.interactionId }
        : {}),
      family: input.assessment.family,
      endpointId: input.endpoint.id,
      ...(input.parameterId ? { parameterId: input.parameterId } : {}),
      ...(input.identityId ? { identityId: input.identityId } : {}),
      hypothesis: `${this.findingAssembler.displayName(input.assessment.family)} 候选需要按版本化规则验证。`,
      observedDifference: analysis.value.summary,
      confidenceHint: analysis.value.confidenceHint,
      evidenceRefs: input.evidenceRefs,
      status: input.assessment.verdict === 'confirmed' ? 'validated' : 'reviewed'
    })
    return { signal, runId: analysis.runId, outputRef: analysis.outputRef }
  }

  private async verifyAssessment(input: {
    scanId: string
    parentRunId: string
    inputRefs: string[]
    signal: StoredSignalRecord
    assessment: ValidationAssessment
    evidenceRefs: string[]
  }): Promise<{ verdict: ValidationAssessment['verdict']; explanation: string }> {
    const verification = await this.runAgent({
      scanId: input.scanId,
      role: 'verifier',
      schema: VerifierOutputSchema,
      parentRunId: input.parentRunId,
      inputRefs: input.inputRefs,
      input: {
        signalId: input.signal.id,
        deterministicVerdict: input.assessment.verdict,
        explanation: input.assessment.explanation,
        completedChecks: input.assessment.completedChecks,
        failedChecks: input.assessment.failedChecks,
        missingChecks: input.assessment.missingChecks,
        evidenceRefs: input.evidenceRefs,
        confirmationRule: `${input.assessment.confirmationRuleId}@${input.assessment.confirmationRuleVersion}`
      }
    })
    let verdict = verification.value.verdict
    if (verdict === 'confirmed' && input.assessment.verdict !== 'confirmed') {
      verdict = input.assessment.verdict
    }
    if (verdict === 'confirmed' && input.evidenceRefs.length < 2) {
      verdict = 'inconclusive'
    }
    return { verdict, explanation: verification.value.explanation }
  }

  private async runVerificationAudit(scanId: string): Promise<void> {
    const findings = await this.repository.listFindings({ scanId })
    const invalidConfirmed = findings.filter(
      (finding) =>
        finding.verdict === 'confirmed' &&
        (!finding.confirmationRuleId ||
          !finding.confirmationRuleVersion ||
          finding.evidenceRefs.length < 2 ||
          !finding.reproducibility)
    )
    if (invalidConfirmed.length > 0) {
      throw new Error('存在缺少规则、复现说明或最小证据的 Confirmed Finding。')
    }
    await this.saveJsonEvidence(
      scanId,
      'verification-audit',
      {
        findingCount: findings.length,
        confirmedCount: findings.filter((item) => item.verdict === 'confirmed').length,
        invalidConfirmedCount: invalidConfirmed.length,
        checkedAt: new Date().toISOString()
      },
      'verifier'
    )
  }

  private async runReport(scanId: string): Promise<void> {
    const existing = await this.reportService.list(scanId)
    if (!existing.some((report) => report.format === 'markdown' && report.redacted)) {
      await this.reportService.generate({ scanId, format: 'markdown', redacted: true })
    }
  }

  private async executeHttpProbe(
    input: Omit<
      HttpExecutionStepInput,
      'adapterKind' | 'timeoutMs' | 'maxResponseBytes' | 'maxRedirects'
    >
  ): Promise<HttpObservation> {
    if (input.signal) this.assertNotAborted(input.signal)
    const execution = await this.executionPort.execute({
      ...input,
      adapterKind: 'http',
      timeoutMs: 10_000,
      maxResponseBytes: 2 * 1024 * 1024,
      maxRedirects: 5
    })
    const toolCallId = terminalTraceId(execution.toolCallIds, 'tool call')
    const proposalId = terminalTraceId(execution.proposalIds, 'proposal')
    const policyDecisionId = terminalTraceId(
      execution.policyDecisionIds,
      'policy decision'
    )
    terminalTraceId(execution.grantIds, 'execution grant')
    terminalTraceId(execution.leaseIds, 'execution lease')
    const interactionId = execution.interactionIds.at(-1)
    return {
      result: execution.result,
      evidenceRefs: [...execution.evidenceRefs],
      ...(interactionId ? { interactionId } : {}),
      toolCallId,
      proposalId,
      policyDecisionId
    }
  }

  private async executeBrowserProbe(
    input: Omit<
      BrowserOfflineExecutionStepInput,
      'adapterKind' | 'timeoutMs' | 'maxDomBytes'
    >
  ): Promise<BrowserObservation> {
    if (input.signal) this.assertNotAborted(input.signal)
    const execution = await this.executionPort.execute({
      ...input,
      adapterKind: 'browser-offline',
      timeoutMs: 10_000,
      maxDomBytes: 1024 * 1024
    })
    const toolCallId = terminalTraceId(execution.toolCallIds, 'tool call')
    const proposalId = terminalTraceId(execution.proposalIds, 'proposal')
    const policyDecisionId = terminalTraceId(
      execution.policyDecisionIds,
      'policy decision'
    )
    terminalTraceId(execution.grantIds, 'execution grant')
    terminalTraceId(execution.leaseIds, 'execution lease')
    return {
      result: execution.result,
      evidenceRefs: [...execution.evidenceRefs],
      toolCallId,
      proposalId,
      policyDecisionId
    }
  }

  private async runAgent<TResult>(input: {
    scanId: string
    role: AgentRole
    schema: StructuredSchema<TResult>
    input: unknown
    parentRunId?: string
    inputRefs?: string[]
  }): Promise<{ value: TResult; runId: string; outputRef: string }> {
    const profile = await this.resolveModelProfile(input.scanId, input.role)
    const prompt = AGENT_PROMPT_VERSIONS[input.role]
    const run = await this.repository.createAgentRun({
      scanId: input.scanId,
      ...(input.parentRunId ? { parentRunId: input.parentRunId } : {}),
      role: input.role,
      promptId: prompt.id,
      promptVersion: prompt.version,
      promptHash: sha256Text(`${prompt.id}@${prompt.version}`),
      modelProfileId: profile.id,
      inputRefs: input.inputRefs ?? []
    })
    try {
      const completion = await this.modelGateway.structuredCompletion({
        profileId: profile.id,
        systemPromptId: prompt.id,
        systemPromptVersion: prompt.version,
        input: input.input,
        schema: input.schema,
        agentRunId: run.id,
        scanId: input.scanId
      })
      const output = await this.saveJsonEvidence(
        input.scanId,
        `agent-output-${input.role}`,
        {
          role: input.role,
          promptId: prompt.id,
          promptVersion: prompt.version,
          modelProfileId: profile.id,
          provider: completion.provider,
          model: completion.model,
          value: completion.value
        },
        input.role
      )
      await this.repository.finishAgentRun({
        id: run.id,
        status: 'completed',
        outputRefs: [output.id]
      })
      await this.repository.incrementScanUsage({
        scanId: input.scanId,
        modelTokens: completion.promptTokens + completion.completionTokens,
        estimatedCostMicros: Math.round(completion.estimatedCost * 1_000_000)
      })
      await this.emit({
        scanId: input.scanId,
        type: 'agent',
        level: 'info',
        message: `${input.role} Agent 完成结构化输出。`,
        detail: {
          agentRunId: run.id,
          promptVersion: prompt.version,
          modelProfileId: profile.id,
          provider: completion.provider,
          model: completion.model,
          outputRef: output.id
        }
      })
      return { value: completion.value, runId: run.id, outputRef: output.id }
    } catch (error) {
      await this.repository.finishAgentRun({
        id: run.id,
        status: 'failed',
        error: errorMessage(error)
      })
      throw error
    }
  }

  private async resolveModelProfile(scanId: string, role: AgentRole) {
    const row = await this.repository.getScanRow(scanId)
    if (!row) throw new Error('扫描不存在。')
    const configuredProfileId = row.configJson.modelProfileIds?.[role]
    const profile = configuredProfileId
      ? await this.repository.getModelProfile(configuredProfileId)
      : await this.repository.getPreferredModelProfile(role)
    if (!profile) {
      throw new Error(
        configuredProfileId
          ? `扫描冻结的 ${role} Agent 模型 Profile 已不存在：${configuredProfileId}。`
          : `Agent ${role} 没有可用模型 Profile。`
      )
    }
    if (profile.agentRole !== role) {
      throw new Error(`扫描配置的模型 Profile “${profile.name}” 不属于 ${role} Agent。`)
    }
    return profile
  }

  private async createControlAgentRun(
    scanId: string,
    role: AgentRole,
    promptId: string,
    promptVersion: string
  ) {
    const profile = await this.resolveModelProfile(scanId, role)
    const run = await this.repository.createAgentRun({
      scanId,
      role,
      promptId,
      promptVersion,
      promptHash: sha256Text(`${promptId}@${promptVersion}`),
      modelProfileId: profile.id
    })
    return this.repository.finishAgentRun({
      id: run.id,
      status: 'completed',
      outputRefs: []
    })
  }

  private executionFamilyForCapability(
    scanId: string,
    capabilityId: CapabilityId
  ): Promise<LegacyV1VulnerabilityFamily>
  private executionFamilyForCapability(
    scanId: string,
    capabilityId: CapabilityId,
    required: false
  ): Promise<LegacyV1VulnerabilityFamily | undefined>

  private async executionFamilyForCapability(
    scanId: string,
    capabilityId: CapabilityId,
    required = true
  ): Promise<LegacyV1VulnerabilityFamily | undefined> {
    const row = await this.repository.getScanRow(scanId)
    if (!row) throw new Error('扫描不存在。')
    const snapshots = await this.repository.listScanModuleSnapshots(scanId)
    const configuredFamilies = new Set(row.configJson.families)

    if (snapshots.some((snapshot) => !configuredFamilies.has(snapshot.familyId))) {
      throw new Error('Scan module snapshots contain an unconfigured family.')
    }

    const orderedSnapshots = row.configJson.families.map((familyId) => {
      const matches = snapshots.filter(
        (snapshot) => snapshot.familyId === familyId
      )
      if (matches.length !== 1) {
        throw new Error(
          `Scan family ${familyId} must have exactly one module snapshot.`
        )
      }
      return { familyId, snapshot: matches[0]! }
    })

    for (const { familyId, snapshot } of orderedSnapshots) {
      if (
        !snapshot.capabilityDescriptors.some(
          (descriptor) => descriptor.id === capabilityId
        )
      ) {
        continue
      }
      if (!isLegacyV1VulnerabilityFamily(familyId)) {
        throw new Error(
          `Capability ${capabilityId} is not bound to a legacy V1 execution family.`
        )
      }
      return familyId
    }

    if (required) {
      throw new Error(
        `No configured scan family snapshot authorizes capability ${capabilityId}.`
      )
    }
    return undefined
  }

  private querySelectors(urlValue: string): SelectorRef[] {
    const grouped = new Map<string, InventoryValueType>()
    for (const [name, value] of new URL(urlValue).searchParams) {
      const valueType: InventoryValueType = /^-?\d+(?:\.\d+)?$/u.test(value)
        ? 'number'
        : 'string'
      const existing = grouped.get(name)
      grouped.set(name, existing && existing !== valueType ? 'unknown' : valueType)
    }
    return [...grouped.entries()]
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([name, valueType]) => ({
        kind: 'query',
        name,
        valueType,
        required: true
      }))
  }

  private inventoryDiscoveryHash(input: {
    type: string
    url: string
    pageId?: string
    fields?: readonly { name: string; type: string; required: boolean }[]
  }): string {
    const url = new URL(input.url)
    return sha256Text(
      JSON.stringify({
        type: input.type,
        route: `${url.origin}${url.pathname}`,
        queryNames: [...url.searchParams.keys()].sort(),
        pageId: input.pageId ?? null,
        fields: (input.fields ?? [])
          .map(({ name, type, required }) => ({ name, type, required }))
          .sort((left, right) =>
            `${left.name}\u0000${left.type}` < `${right.name}\u0000${right.type}`
              ? -1
              : `${left.name}\u0000${left.type}` > `${right.name}\u0000${right.type}`
                ? 1
                : 0
          )
      })
    )
  }

  private upsertReadInventory(input: {
    scanId: string
    pageId?: string
    url: string
    sourceType: 'target-base' | 'link' | 'controlled-callback'
    initiator?: string
  }) {
    return this.inventoryService.upsertInventory({
      scanId: input.scanId,
      ...(input.pageId ? { pageId: input.pageId } : {}),
      method: 'GET',
      url: input.url,
      bodyShape: { rootType: 'none', fields: [] },
      codec: 'none',
      transport: 'standard-http',
      allowedHeaders: [
        { name: 'accept', valueType: 'string', required: true },
        { name: 'user-agent', valueType: 'string', required: true }
      ],
      templateVersion: '1.0.0',
      requiredCapabilityIds: ['http.reviewed-read'],
      selectors: this.querySelectors(input.url),
      preview: { url: input.url },
      source: {
        type: input.sourceType,
        sourceHash: this.inventoryDiscoveryHash({
          type: input.sourceType,
          url: input.url,
          ...(input.pageId ? { pageId: input.pageId } : {})
        }),
        ...(input.pageId ? { pageId: input.pageId } : {}),
        ...(input.initiator ? { initiator: input.initiator } : {}),
        confidence: 1
      }
    })
  }

  private async upsertEntryInventory(scanId: string): Promise<void> {
    const context = await this.loadContext(scanId)
    await this.resolveCallbackCollectorListenUrl()
    await this.upsertReadInventory({
      scanId,
      url: context.target.baseUrl,
      sourceType: 'target-base'
    })
    if (context.row.configJson.callbackUrl) {
      await this.upsertReadInventory({
        scanId,
        url: controlledCallbackInventoryUrl(context.row.configJson.callbackUrl),
        sourceType: 'controlled-callback'
      })
    }
  }

  private async persistForm(scanId: string, pageId: string, form: BrowserFormView): Promise<void> {
    const method = form.method.toUpperCase()
    const url = new URL(form.action)
    if (method === 'GET') {
      for (const field of form.fields) {
        if (!url.searchParams.has(field.name)) url.searchParams.set(field.name, '')
      }
    }
    const fields = new Map<
      string,
      { name: string; valueType: InventoryValueType; required: boolean }
    >()
    for (const field of form.fields) {
      const name = field.name.trim()
      if (!name) continue
      const valueType: InventoryValueType =
        field.type === 'number' || field.type === 'range'
          ? 'number'
          : field.type === 'checkbox' || field.type === 'radio'
            ? 'boolean'
            : field.type === 'file'
              ? 'binary'
              : 'string'
      const existing = fields.get(name)
      fields.set(name, {
        name,
        valueType:
          existing && existing.valueType !== valueType
            ? 'unknown'
            : valueType,
        required: Boolean(existing?.required || field.required)
      })
    }
    const fieldList = [...fields.values()]
    await this.inventoryService.upsertInventory({
      scanId,
      pageId,
      method,
      url: url.toString(),
      ...(method === 'GET'
        ? {}
        : { contentType: 'application/x-www-form-urlencoded' }),
      bodyShape:
        method === 'GET'
          ? { rootType: 'none', fields: [] }
          : {
              rootType: 'object',
              fields: fieldList.map((field) => ({
                path: `/${field.name.replaceAll('~', '~0').replaceAll('/', '~1')}`,
                valueType: field.valueType,
                required: field.required
              }))
            },
      codec: method === 'GET' ? 'none' : 'form',
      transport: 'standard-http',
      allowedHeaders:
        method === 'GET'
          ? []
          : [{ name: 'content-type', valueType: 'string', required: true }],
      templateVersion: '1.0.0',
      requiredCapabilityIds: [
        method === 'GET' ? 'http.reviewed-read' : 'http.test-object-write'
      ],
      selectors: fieldList.map((field) => ({
        kind: method === 'GET' ? 'query' : 'form',
        name: field.name,
        valueType: field.valueType,
        required: field.required
      })),
      preview: { url: url.toString() },
      source: {
        type: 'form',
        sourceHash: this.inventoryDiscoveryHash({
          type: 'form',
          url: url.toString(),
          pageId,
          fields: form.fields
        }),
        pageId,
        initiator: pageId,
        confidence: 1
      }
    })
  }

  private urlAllowed(
    url: string,
    scope: TargetScopeRecord,
    identityId?: string
  ): boolean {
    return evaluateProbe(
      {
        id: 'enumeration-precheck',
        kind: 'http-request',
        targetUrl: url,
        method: 'GET',
        ...(identityId ? { identityId } : {}),
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: '枚举候选预检查',
        expectedEvidence: '无，仅用于本地 Scope 过滤',
        maxRequests: 1,
        timeoutMs: 10_000,
        userApproved: false
      },
      scope
    ).allowed
  }

  private async saveJsonEvidence(
    scanId: string,
    type: string,
    value: unknown,
    createdBy: string
  ) {
    const scan = await this.repository.getScan(scanId)
    if (!scan) throw new Error('扫描不存在。')
    const target = await this.repository.getTarget(scan.targetId)
    if (!target) throw new Error('扫描目标不存在。')
    return this.evidenceStore.save({
      workspaceId: target.workspaceId,
      scanId,
      type,
      mimeType: 'application/json',
      content: JSON.stringify(value, null, 2),
      source: 'agent-runtime',
      createdBy,
      captureTool: 'agentgo-coordinator',
      captureToolVersion: '1.0.0',
      redactionState: 'redacted'
    })
  }

  private async loadContext(scanId: string) {
    const scan = await this.repository.getScan(scanId)
    const row = await this.repository.getScanRow(scanId)
    if (!scan || !row) throw new Error('扫描不存在。')
    const target = await this.repository.getTarget(scan.targetId)
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!target || !scope) throw new Error('扫描目标或 Scope 快照不存在。')
    const selected = new Set(row.configJson.identityIds)
    const identities = (await this.repository.listIdentities(scan.targetId)).filter(
      (identity) => selected.has(identity.id)
    )
    return { scan, row, target, scope, identities }
  }

  private async resolveAuthorizationMatrix(context: {
    readonly target: { readonly id: string }
    readonly scope: { readonly id: string }
    readonly identities: readonly {
      readonly id: string
      readonly role: string
      readonly isTestIdentity: boolean
      readonly ownedResourceIds: readonly string[]
    }[]
  }) {
    if (!this.authorizationMatrixService) return undefined
    const current = await this.authorizationMatrixService.getCurrentMatrix(
      context.target.id,
      context.scope.id
    )
    if (current) return current
    if (this.vulnerabilityExecutionEnvironment !== 'attested-fixture') {
      return undefined
    }
    return this.authorizationMatrixService.ensureOwnedResourceReadMatrix({
      targetId: context.target.id,
      scopeSnapshotId: context.scope.id,
      identities: context.identities
    })
  }

  async ensureCallbackCollectorListenUrl(): Promise<string | undefined> {
    return this.resolveCallbackCollectorListenUrl()
  }

  private async resolveCallbackCollectorListenUrl(): Promise<string | undefined> {
    const server = await ensureAttestedFixtureCallbackListen({
      environment: this.vulnerabilityExecutionEnvironment,
      collector: this.callbackCollector,
      ...(this.callbackCollectorListen ? { existing: this.callbackCollectorListen } : {})
    })
    if (!server) return undefined
    this.callbackCollectorListen = server
    return server.baseUrl
  }

  private async awaitOnIncompatibleModuleSnapshot(
    scanId: string,
    phase: ScanRecord['phase'],
    runtime: CoordinatorRuntimeState,
    families: readonly VulnerabilityFamily[],
    snapshotSetSealed: boolean
  ): Promise<ScanRecord | undefined> {
    try {
      requireSealedScanModuleSnapshotSet(snapshotSetSealed)
      verifyScanModuleSnapshots(
        await this.repository.listScanModuleSnapshots(scanId),
        scanId,
        families,
        this.vulnerabilityExecutionEnvironment,
        this.vulnerabilityPlatform
      )
      return undefined
    } catch (error) {
      if (!(error instanceof ScanModuleSnapshotError)) throw error
      const awaiting = transitionRuntime(runtime, {
        type: 'await-user'
      }) as CoordinatorRuntimeState
      return this.repository.markScanAwaitingUser({
        scanId,
        phase,
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
  }

  private async assertBudget(
    scanId: string,
    runtime: CoordinatorRuntimeState
  ): Promise<void> {
    const scan = await this.repository.getScan(scanId)
    if (!scan) throw new Error('扫描不存在。')
    if (scan.requestCount >= scan.budget.maxRequests) {
      throw new Error('扫描请求预算已耗尽。')
    }
    if (scan.modelTokens >= scan.budget.maxModelTokens) {
      throw new Error('扫描模型 Token 预算已耗尽。')
    }
    const startedAt = runtime.runStartedAt ?? Date.parse(scan.startedAt ?? scan.createdAt)
    if (Date.now() - startedAt > scan.budget.maxDurationMinutes * 60_000) {
      throw new Error('扫描时间预算已耗尽。')
    }
  }

  private assertNotAborted(signal: AbortSignal): void {
    if (signal.aborted) throw new Error('扫描执行已暂停或取消。')
  }

  private async emit(input: Omit<ScanEvent, 'id' | 'createdAt'>): Promise<ScanEvent> {
    const event = await this.repository.addScanEvent(input)
    this.onEvent?.(event)
    return event
  }

  private async awaitOnPendingInventoryReview(
    scanId: string,
    phase: ScanRecord['phase'],
    runtime: CoordinatorRuntimeState,
    scanStatus: ScanRecord['status']
  ): Promise<ScanRecord | undefined> {
    const pendingReviewVariantIds =
      await this.repository.listPendingActiveL1ReviewVariantIds(scanId)
    if (pendingReviewVariantIds.length === 0) return undefined
    if (scanStatus === 'awaiting-user') {
      const current = await this.repository.getScan(scanId)
      if (!current) throw new Error('Scan disappeared while awaiting inventory review.')
      return current
    }
    const awaiting = transitionRuntime(runtime, {
      type: 'await-user'
    }) as CoordinatorRuntimeState
    return this.repository.markScanAwaitingUser({
      scanId,
      phase,
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
