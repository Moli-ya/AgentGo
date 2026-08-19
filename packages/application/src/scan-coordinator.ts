import { randomBytes } from 'node:crypto'
import {
  registerActionResult,
  transitionRuntime,
  type ScanRuntimeState
} from '@agentgo/agent-runtime'
import {
  isLegacyV1VulnerabilityFamily,
  type LegacyV1VulnerabilityFamily,
  type VulnerabilityFamily,
  type AgentRole,
  type Environment,
  type InventoryEndpoint,
  type InventoryValueType,
  type ScanControlAction,
  type ScanEvent,
  type CapabilityId,
  type ScanRecord,
  type SelectorRef,
  type TargetScopeRecord
} from '@agentgo/contracts'
import { buildInertXssMarkerPayload } from '@agentgo/domain'
import {
  AgentGoRepository,
  EvidenceStore,
  sha256Text,
  type StoredSignalRecord
} from '@agentgo/db'
import { V1_KNOWLEDGE_ENTRIES } from '@agentgo/knowledge-base'
import type { ModelGateway, StructuredSchema } from '@agentgo/model-gateway'
import { evaluateProbe } from '@agentgo/security-policy'
import {
  AGENT_PROMPT_VERSIONS,
  AnalysisOutputSchema,
  KnowledgeAgentOutputSchema,
  PlannerOutputSchema,
  StrategyOutputSchema,
  VerifierOutputSchema,
  type KnowledgeAgentOutput,
  type PlannerOutput,
  type StrategyOutput
} from './agent-prompts'
import type {
  BrowserFormView,
  BrowserOfflineExecutionStepInput,
  ExecutionPort,
  HttpExecutionStepInput,
  QueryValueMutation
} from './execution-port'
import { InventoryService } from './inventory-service'
import { ReportService } from './report-service'
import {
  ScanModuleSnapshotError,
  requireSealedScanModuleSnapshotSet,
  verifyScanModuleSnapshots
} from './scan-module-snapshot'
import type { Day2VulnerabilityPlatform } from './vulnerability-platform'
import {
  V1_CONFIRMATION_RULES,
  assessIdor,
  assessSqli,
  assessSsrf,
  assessXss,
  type BrowserObservation,
  type HttpObservation,
  type ValidationAssessment
} from './validation-engine'

interface CoordinatorRuntimeState extends ScanRuntimeState {
  plannerRunId?: string
  plannerPlan?: PlannerOutput
  strategyRunId?: string
  candidates?: StrategyOutput['candidates']
  phaseOutputRefs?: Record<string, string[]>
  runStartedAt?: number
}

export interface ScanCoordinatorDependencies {
  repository: AgentGoRepository
  evidenceStore: EvidenceStore
  executionPort: ExecutionPort
  modelGateway: ModelGateway
  reportService: ReportService
  vulnerabilityPlatform: Day2VulnerabilityPlatform
  vulnerabilityExecutionEnvironment: Environment
  inventoryService?: InventoryService
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

const legacyFamilyLabels: Record<LegacyV1VulnerabilityFamily, string> = {
  sqli: 'SQL 注入',
  xss: 'XSS',
  ssrf: 'SSRF',
  idor: 'IDOR / 对象级越权'
}

function familyLabel(familyId: VulnerabilityFamily): string {
  return isLegacyV1VulnerabilityFamily(familyId)
    ? legacyFamilyLabels[familyId]
    : familyId
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function responseRef(observation: HttpObservation): string {
  const reference = observation.evidenceRefs.at(-1)
  if (!reference) {
    throw new Error('ExecutionPort omitted the terminal response Evidence reference.')
  }
  return reference
}

const CALLBACK_TOKEN_PARAMETER = 'agentgo_token'
const CALLBACK_REVIEW_PLACEHOLDER = 'agentgo-callback-review-placeholder'

function queryValueMutation(
  urlValue: string,
  name: string,
  value: string
): { desiredUrl: string; mutation: QueryValueMutation } {
  const url = new URL(urlValue)
  const entries = [...url.searchParams.entries()]
  let mutated = false
  url.search = ''
  for (const [entryName, entryValue] of entries) {
    if (!mutated && entryName === name) {
      url.searchParams.append(entryName, value)
      mutated = true
      continue
    }
    url.searchParams.append(entryName, entryValue)
  }
  if (!mutated) {
    throw new Error(`Reviewed query selector ${name} is absent from the endpoint URL.`)
  }
  return {
    desiredUrl: url.toString(),
    mutation: {
      kind: 'query',
      name,
      occurrence: 0,
      value
    }
  }
}

function controlledCallbackInventoryUrl(urlValue: string): string {
  const url = new URL(urlValue)
  url.searchParams.set(CALLBACK_TOKEN_PARAMETER, CALLBACK_REVIEW_PLACEHOLDER)
  return url.toString()
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

function marker(): string {
  return `agx_${randomBytes(16).toString('hex')}`
}

function callbackToken(): string {
  return randomBytes(12).toString('hex')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown scan error.'
}

export class DefaultScanCoordinator {
  private readonly repository: AgentGoRepository
  private readonly evidenceStore: EvidenceStore
  private readonly executionPort: ExecutionPort
  private readonly modelGateway: ModelGateway
  private readonly reportService: ReportService
  private readonly vulnerabilityPlatform: Day2VulnerabilityPlatform
  private readonly vulnerabilityExecutionEnvironment: Environment
  private readonly inventoryService: InventoryService
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
      const patch = await this.runPhase(scanId, row.phase as ScanRecord['phase'], runtime, signal)
      this.assertNotAborted(signal)
      const stateAfterPhase = {
        ...runtime,
        ...patch,
        phaseOutputRefs: {
          ...(runtime.phaseOutputRefs ?? {}),
          ...(patch.phaseOutputRefs ?? {})
        }
      }
      let next = transitionRuntime(stateAfterPhase, {
        type: 'phase-completed',
        checkpointRef: `${row.phase}:${Date.now()}`
      }) as CoordinatorRuntimeState
      const pendingReviewVariantIds =
        row.phase === 'active-enum'
          ? await this.repository.listPendingActiveL1ReviewVariantIds(scanId)
          : []
      if (pendingReviewVariantIds.length > 0) {
        next = transitionRuntime(next, {
          type: 'await-user'
        }) as CoordinatorRuntimeState
      }
      const checkpointId = await this.repository.addCheckpoint({
        scanId,
        phase: row.phase as ScanRecord['phase'],
        state: next as unknown as Record<string, unknown>,
        reason:
          pendingReviewVariantIds.length > 0
            ? 'inventory-review-required'
            : `phase-completed:${row.phase}`
      })
      const completed = next.status === 'completed'
      await this.repository.updateScan(scanId, {
        status: completed
          ? 'completed'
          : pendingReviewVariantIds.length > 0
            ? 'awaiting-user'
            : 'running',
        phase: next.phase,
        progress: phaseProgress[row.phase as ScanRecord['phase']],
        completedAt: completed ? Date.now() : null,
        runtimeJson: next as unknown as Record<string, unknown>
      })
      if (pendingReviewVariantIds.length > 0) {
        await this.emit({
          scanId,
          type: 'status',
          level: 'warning',
          message: `枚举已完成；${pendingReviewVariantIds.length} 个 L1 请求变体等待人工 review。`,
          detail: {
            completedPhase: row.phase,
            nextPhase: next.phase,
            checkpointId,
            reviewRequiredCount: pendingReviewVariantIds.length
          }
        })
        return
      }
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
  ): Promise<Partial<CoordinatorRuntimeState>> {
    switch (phase) {
      case 'intake':
        return this.runIntake(scanId, signal)
      case 'passive-recon':
        return this.runPassiveRecon(scanId)
      case 'active-enum':
        await this.runEnumeration(scanId, runtime, signal)
        return {}
      case 'hypothesis':
        return this.runHypothesis(scanId, runtime, signal)
      case 'validation':
        return this.runValidation(scanId, runtime, signal)
      case 'verification':
        await this.runVerificationAudit(scanId)
        return {}
      case 'report':
        await this.runReport(scanId)
        return {}
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
  ): Promise<Partial<CoordinatorRuntimeState>> {
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
    const knowledgeOutput = await this.buildKnowledgeOutput(
      context.scan.families,
      unique([...endpointParameterNames, ...endpointPathTerms])
    )
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
    const parameterIdsByEndpoint = new Map(
      endpoints.map((endpoint) => [
        endpoint.id,
        new Set(endpoint.parameters.map((parameter) => parameter.id))
      ])
    )
    const candidates = strategy.value.candidates.filter(
      (candidate) =>
        context.scan.families.includes(candidate.family) &&
        parameterIdsByEndpoint
          .get(candidate.endpointId)
          ?.has(candidate.parameterId) === true
    )
    await this.emit({
      scanId,
      type: 'agent',
      level: 'info',
      message: `StrategyAgent 形成 ${candidates.length} 个低影响验证候选。`,
      detail: {
        candidateCount: candidates.length,
        skippedReasons: strategy.value.skippedReasons
      }
    })
    return {
      strategyRunId: strategy.runId,
      candidates,
      phaseOutputRefs: {
        hypothesis: [knowledge.outputRef, strategy.outputRef]
      }
    }
  }

  private async runValidation(
    scanId: string,
    runtime: CoordinatorRuntimeState,
    signal: AbortSignal
  ): Promise<Partial<CoordinatorRuntimeState>> {
    const candidates = runtime.candidates ?? []
    let nextRuntime = runtime
    for (const candidate of candidates) {
      this.assertNotAborted(signal)
      this.vulnerabilityPlatform.executionGate.requireExecutableFamily(
        candidate.family,
        this.vulnerabilityExecutionEnvironment
      )
      const fingerprint = `${candidate.family}:${candidate.endpointId}:${candidate.parameterId}`
      if (nextRuntime.actionFingerprints.includes(fingerprint)) continue
      const endpoint = (await this.repository.listLegacyV1ExecutionEndpoints(scanId))
        .find((item) => item.id === candidate.endpointId)
      const parameter = endpoint?.parameters.find((item) => item.id === candidate.parameterId)
      if (!endpoint || !parameter || endpoint.method.toUpperCase() !== 'GET') continue
      try {
        const outcome = await this.validateCandidate({
          scanId,
          agentRunId:
            runtime.strategyRunId ??
            (
              await this.createControlAgentRun(
                scanId,
                'strategy',
                'agentgo.strategy-recovery.v1',
                '1.0.0'
              )
            ).id,
          family: candidate.family,
          endpoint,
          parameter,
          signal
        })
        nextRuntime = registerActionResult(nextRuntime, fingerprint, outcome).state as CoordinatorRuntimeState
      } catch (error) {
        if (signal.aborted) throw error
        await this.emit({
          scanId,
          type: 'error',
          level: 'error',
          message: `${familyLabel(candidate.family)} 候选未完成：${errorMessage(error)}`,
          detail: { fingerprint }
        })
        nextRuntime = registerActionResult(nextRuntime, fingerprint, false).state as CoordinatorRuntimeState
      }
      await this.repository.addCheckpoint({
        scanId,
        phase: 'validation',
        state: nextRuntime as unknown as Record<string, unknown>,
        reason: `candidate-completed:${fingerprint}`
      })
      await this.assertBudget(scanId, nextRuntime)
    }
    return nextRuntime
  }

  private async validateCandidate(input: {
    scanId: string
    agentRunId: string
    family: VulnerabilityFamily
    endpoint: InventoryEndpoint
    parameter: InventoryEndpoint['parameters'][number]
    signal: AbortSignal
  }): Promise<boolean> {
    const executable = this.vulnerabilityPlatform.executionGate.requireExecutableFamily(
      input.family,
      this.vulnerabilityExecutionEnvironment
    )
    const family = executable.familyId
    const context = await this.loadContext(input.scanId)
    let assessment: ValidationAssessment
    let primary: HttpObservation
    let baseline: HttpObservation
    let negative: HttpObservation | undefined
    let evidenceRefs: string[]
    let affectedResource: string | undefined
    const identity = context.identities[0]

    if (family === 'sqli') {
      const redactedValue =
        new URL(input.endpoint.url).searchParams.get(input.parameter.name) ?? ''
      const numeric =
        input.parameter.dataType === 'number' ||
        input.parameter.dataType === 'integer' ||
        /^-?\d+(?:\.\d+)?$/u.test(redactedValue)
      const original = numeric ? '1' : 'agentgo'
      const trueValue = numeric ? `${original} AND 1=1` : `${original}' AND '1'='1`
      const falseValue = numeric ? `${original} AND 1=2` : `${original}' AND '1'='2`
      const trueMutation = queryValueMutation(
        input.endpoint.url,
        input.parameter.name,
        trueValue
      )
      const falseMutation = queryValueMutation(
        input.endpoint.url,
        input.parameter.name,
        falseValue
      )
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'sqli.baseline',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: input.endpoint.url,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'SQLi 只读差异验证：获取基线响应。',
        expectedEvidence: '基线响应摘要和内容哈希',
        signal: input.signal
      })
      const trueFirst = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'sqli.true',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: trueMutation.desiredUrl,
        mutation: trueMutation.mutation,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'SQLi 只读布尔真条件差异验证。',
        payloadSummary: '非写入式布尔真条件；不读取业务数据。',
        expectedEvidence: '测试响应摘要和内容哈希',
        signal: input.signal
      })
      const falseControl = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'sqli.false',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: falseMutation.desiredUrl,
        mutation: falseMutation.mutation,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'SQLi 只读布尔负对照。',
        payloadSummary: '非写入式布尔假条件；不读取业务数据。',
        expectedEvidence: '负对照响应摘要和内容哈希',
        signal: input.signal
      })
      const trueRepeat = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'sqli.repeat',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: trueMutation.desiredUrl,
        mutation: trueMutation.mutation,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'SQLi 只读布尔真条件重复验证。',
        payloadSummary: '重复非写入式布尔真条件。',
        expectedEvidence: '重复测试响应摘要和内容哈希',
        signal: input.signal
      })
      assessment = assessSqli({ baseline, trueFirst, falseControl, trueRepeat })
      primary = trueFirst
      negative = falseControl
      evidenceRefs = unique(
        [baseline, trueFirst, falseControl, trueRepeat].flatMap((item) => item.evidenceRefs)
      )
    } else if (family === 'xss') {
      const xssMarker = marker()
      const payload = buildInertXssMarkerPayload(xssMarker)
      const reflectionMutation = queryValueMutation(
        input.endpoint.url,
        input.parameter.name,
        payload
      )
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'xss.baseline',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: input.endpoint.url,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'XSS 验证：获取未注入标记的基线响应。',
        expectedEvidence: '基线响应摘要和 DOM 输入',
        signal: input.signal
      })
      primary = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'xss.reflection',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: reflectionMutation.desiredUrl,
        mutation: reflectionMutation.mutation,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'XSS 随机惰性标记反射验证。',
        payloadSummary: `无外传能力的隔离执行标记 ${xssMarker}。`,
        expectedEvidence: 'HTTP 反射、DOM 快照和隔离浏览器截图',
        signal: input.signal
      })
      let browser: BrowserObservation | undefined
      if (primary.result.status === 'succeeded' && isHtml(primary)) {
        browser = await this.executeBrowserProbe({
          scanId: input.scanId,
          agentRunId: input.agentRunId,
          familyId: family,
          stepId: 'xss.offline-verify',
          purpose: 'read',
          baseUrl: reflectionMutation.desiredUrl,
          summary: '在断网隔离浏览器中验证随机惰性 XSS 标记。',
          payloadSummary: `仅设置本地 DOM 属性的标记 ${xssMarker}。`,
          expectedEvidence: '标记执行状态、DOM 快照和截图',
          html: safeBodyText(primary),
          action: 'verify-xss',
          marker: xssMarker,
          ...(primary.result.responseHeaders['content-security-policy']
            ? { contentSecurityPolicy: primary.result.responseHeaders['content-security-policy'] }
            : {}),
          signal: input.signal
        })
      }
      assessment = assessXss({ marker: xssMarker, http: primary, ...(browser ? { browser } : {}) })
      evidenceRefs = unique([
        ...baseline.evidenceRefs,
        ...primary.evidenceRefs,
        ...(browser?.evidenceRefs ?? [])
      ])
    } else if (family === 'ssrf') {
      const callbackUrl = context.row.configJson.callbackUrl
      if (!callbackUrl) {
        throw new Error('扫描未配置受控回调 URL，SSRF 只能标记为未具备验证条件。')
      }
      const callbackTemplateUrl = controlledCallbackInventoryUrl(callbackUrl)
      const callbackInventory = await this.upsertReadInventory({
        scanId: input.scanId,
        url: callbackTemplateUrl,
        sourceType: 'controlled-callback'
      })
      if (callbackInventory.requestVariant.reviewStatus !== 'reviewed') {
        throw new Error(
          'The controlled SSRF callback request variant must be inventoried and reviewed before execution.'
        )
      }
      const callbackMutation = queryValueMutation(
        callbackTemplateUrl,
        CALLBACK_TOKEN_PARAMETER,
        callbackToken()
      )
      const primaryMutation = queryValueMutation(
        input.endpoint.url,
        input.parameter.name,
        callbackMutation.desiredUrl
      )
      const negativeMutation = queryValueMutation(
        input.endpoint.url,
        input.parameter.name,
        'agentgo-invalid-url'
      )
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'ssrf.callback-read',
        purpose: 'read',
        endpointId: callbackInventory.endpoint.id,
        desiredUrl: callbackMutation.desiredUrl,
        mutation: callbackMutation.mutation,
        summary: '读取明确授权的受控 SSRF 回调证明。',
        expectedEvidence: '唯一回调证明响应',
        signal: input.signal
      })
      primary = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'ssrf.primary',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: primaryMutation.desiredUrl,
        mutation: primaryMutation.mutation,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'SSRF 受控回调 URL 只读验证。',
        payloadSummary: '仅访问已列入 Scope 的项目控制回调端点。',
        expectedEvidence: '目标响应中的唯一受控证明',
        signal: input.signal
      })
      negative = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'ssrf.negative',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: negativeMutation.desiredUrl,
        mutation: negativeMutation.mutation,
        ...(identity ? { identityId: identity.id } : {}),
        summary: 'SSRF 非 URL 负对照。',
        payloadSummary: '不触发网络访问的无效 URL 文本。',
        expectedEvidence: '不包含受控证明的负对照响应',
        signal: input.signal
      })
      assessment = assessSsrf({
        callbackBaseline: baseline,
        targetProbe: primary,
        negativeControl: negative
      })
      evidenceRefs = unique(
        [baseline, primary, negative].flatMap((item) => item.evidenceRefs)
      )
    } else if (family === 'idor') {
      if (context.identities.length < 2) {
        throw new Error('IDOR 只读对照至少需要两个授权测试身份。')
      }
      const owner = context.identities.find((item) => item.ownedResourceIds.length > 0)
      const second = context.identities.find(
        (item) => item.id !== owner?.id && item.ownedResourceIds.length > 0
      )
      if (!owner || !second) {
        throw new Error('两个测试身份都必须配置已知归属资源 ID。')
      }
      const ownerResourceId = owner.ownedResourceIds[0]!
      const secondResourceId = second.ownedResourceIds[0]!
      const ownerMutation = queryValueMutation(
        input.endpoint.url,
        input.parameter.name,
        ownerResourceId
      )
      const secondMutation = queryValueMutation(
        input.endpoint.url,
        input.parameter.name,
        secondResourceId
      )
      affectedResource = ownerResourceId
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'idor.owner',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: ownerMutation.desiredUrl,
        mutation: ownerMutation.mutation,
        identityId: owner.id,
        summary: 'IDOR 对照：资源所有者只读访问自己的测试资源。',
        expectedEvidence: '所有者基线响应摘要',
        signal: input.signal
      })
      const secondOwn = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'idor.second-own',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: secondMutation.desiredUrl,
        mutation: secondMutation.mutation,
        identityId: second.id,
        summary: 'IDOR 负对照：第二身份只读访问自己的测试资源。',
        expectedEvidence: '第二身份合法资源响应摘要',
        signal: input.signal
      })
      primary = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        familyId: family,
        stepId: 'idor.cross-read',
        purpose: 'read',
        endpointId: input.endpoint.id,
        desiredUrl: ownerMutation.desiredUrl,
        mutation: ownerMutation.mutation,
        identityId: second.id,
        summary: 'IDOR 对照：第二身份只读访问第一身份的已知测试资源。',
        expectedEvidence: '跨身份只读响应对照',
        signal: input.signal
      })
      negative = secondOwn
      assessment = assessIdor({
        ownerResourceId,
        secondIdentityResourceId: secondResourceId,
        ownerRead: baseline,
        secondIdentityOwnRead: secondOwn,
        secondIdentityOwnerRead: primary,
        identitiesAuthorized:
          owner.isTestIdentity &&
          second.isTestIdentity &&
          context.scope.allowedIdentityIds.includes(owner.id) &&
          context.scope.allowedIdentityIds.includes(second.id)
      })
      evidenceRefs = unique([baseline, secondOwn, primary].flatMap((item) => item.evidenceRefs))
    } else {
      throw new Error(`当前运行时没有漏洞族 ${family} 的候选执行器。`)
    }

    const analysisResult = await this.createSignalFromAssessment({
      scanId: input.scanId,
      parentRunId: input.agentRunId,
      endpoint: input.endpoint,
      parameterId: input.parameter.id,
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
    const rule = V1_CONFIRMATION_RULES[family]
    await this.repository.ensureConfirmationRule(rule)
    await this.repository.createValidationRun({
      signalId: analysisResult.signal.id,
      confirmationRuleId: rule.id,
      confirmationRuleVersion: rule.version,
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
    const location = new URL(input.endpoint.url)
    const finding = await this.repository.createFinding({
      scanId: input.scanId,
      family,
      title: `${familyLabel(family)}：${location.pathname} 参数 ${input.parameter.name}`,
      verdict: verdict.verdict,
      severity: verdict.verdict === 'confirmed' ? assessment.severity : 'info',
      confidence:
        verdict.verdict === assessment.verdict
          ? assessment.confidence
          : Math.min(assessment.confidence, 0.5),
      endpointId: input.endpoint.id,
      parameterId: input.parameter.id,
      ...(context.identities[0] ? { identityId: context.identities[0].id } : {}),
      ...(affectedResource ? { affectedResource } : {}),
      cwe: assessment.cwe,
      owasp: assessment.owasp,
      confirmationRuleId: rule.id,
      confirmationRuleVersion: rule.version,
      reproducibility: verdict.explanation,
      remediation: assessment.remediation,
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
        rule: `${rule.id}@${rule.version}`,
        evidenceCount: evidenceRefs.length
      }
    })
    return evidenceRefs.length > 0
  }

  private async createSignalFromAssessment(input: {
    scanId: string
    parentRunId: string
    endpoint: InventoryEndpoint
    parameterId: string
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
      parameterId: input.parameterId,
      ...(input.identityId ? { identityId: input.identityId } : {}),
      hypothesis: `${familyLabel(input.assessment.family)} 候选需要按版本化规则验证。`,
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
    await this.upsertReadInventory({
      scanId,
      url: context.target.baseUrl,
      sourceType: 'target-base'
    })
    if (
      context.row.configJson.families.includes('ssrf') &&
      context.row.configJson.callbackUrl
    ) {
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

  private async buildKnowledgeOutput(
    families: VulnerabilityFamily[],
    signalTerms: string[]
  ): Promise<KnowledgeAgentOutput> {
    const entryById = new Map(V1_KNOWLEDGE_ENTRIES.map((entry) => [entry.id, entry]))
    // Every enabled V1 family receives its vetted built-in safety and
    // confirmation baseline even when endpoint naming gives the search index
    // no useful lexical match.  Search results can add reviewed imported
    // intelligence, but cannot replace this policy baseline.
    const baselineIds = families.flatMap((family) =>
      V1_KNOWLEDGE_ENTRIES.filter((entry) => entry.family === family).map((entry) => entry.id)
    )
    const matchedIds = unique([
      ...baselineIds,
      ...families.flatMap((family) =>
        this.repository.searchKnowledgeEntryIds({
          query: signalTerms.join(' '),
          families: [family],
          limit: 5
        })
      )
    ])
    const entries = matchedIds
      .map((entryId) => entryById.get(entryId))
      .filter((entry): entry is (typeof V1_KNOWLEDGE_ENTRIES)[number] => Boolean(entry))
    const importedEntries = (await this.repository.listPublishedKnowledgeEntries(matchedIds))
      .filter((entry) => entry.candidate.family !== undefined)
    return {
      matchedEntryIds: [
        ...entries.map((entry) => entry.id),
        ...importedEntries.map((entry) => entry.chunkId)
      ],
      guidance: [
        ...entries.map((entry) => ({
          family: entry.family,
          applicability: entry.applicability,
          safeProbePrinciples: entry.safeProbePrinciples,
          confirmationRules: entry.confirmationRules,
          falsePositivePatterns: entry.falsePositivePatterns,
          remediationHints: entry.remediationHints
        })),
        ...importedEntries.map((entry) => ({
          family: entry.candidate.family!,
          applicability: [
            ...entry.candidate.affectedVersions,
            ...entry.candidate.preconditions
          ],
          safeProbePrinciples: [
            '导入请求模板仅用于形成假设，执行前必须重新经过 SecurityPolicy。',
            '不得直接执行原始 PoC，必须使用低影响、带负对照的验证动作。'
          ],
          confirmationRules: entry.candidate.confirmationRules,
          falsePositivePatterns: [],
          remediationHints: entry.candidate.remediation
        }))
      ],
      sourceRefs: unique([
        ...entries.flatMap((entry) => entry.sourceRefs),
        ...importedEntries.map((entry) => entry.chunkId)
      ]),
      policyConstraints: unique([
        ...entries.flatMap((entry) => entry.forbiddenActions),
        ...importedEntries.flatMap((entry) => entry.candidate.forbiddenActions)
      ]),
      ...(entries.length === 0 && importedEntries.length === 0
        ? {
            sourceRefs: [],
            policyConstraints: [
              '知识检索未命中时不得扩大测试范围或生成未经规则审查的动作。'
            ]
          }
        : {})
    }
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
