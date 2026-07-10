import { randomBytes } from 'node:crypto'
import {
  buildInertXssMarkerPayload,
  type BrowserFormSummary
} from '@agentgo/browser-runner'
import {
  registerActionResult,
  transitionRuntime,
  type ScanRuntimeState
} from '@agentgo/agent-runtime'
import type {
  AgentRole,
  IdentityRecord,
  InventoryEndpoint,
  ScanControlAction,
  ScanEvent,
  ScanRecord,
  TargetScopeRecord,
  VulnerabilityFamily
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
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
import { ExecutionService } from './execution-service'
import { PolicyBroker } from './execution-policy'
import { ReportService } from './report-service'
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
  credentialStore: FileCredentialStore
  evidenceStore: EvidenceStore
  executionService: ExecutionService
  policyBroker: PolicyBroker
  modelGateway: ModelGateway
  reportService: ReportService
  onEvent?: (event: ScanEvent) => void
}

class PolicyDeniedError extends Error {}

const phaseProgress: Record<ScanRecord['phase'], number> = {
  intake: 8,
  'passive-recon': 18,
  'active-enum': 38,
  hypothesis: 52,
  validation: 78,
  verification: 92,
  report: 100
}

const familyLabels: Record<VulnerabilityFamily, string> = {
  sqli: 'SQL 注入',
  xss: 'XSS',
  ssrf: 'SSRF',
  idor: 'IDOR / 对象级越权'
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function responseRef(observation: HttpObservation): string {
  return observation.evidenceRefs[2] ?? observation.evidenceRefs[1] ?? observation.evidenceRefs[0]!
}

function replaceQueryParameter(urlValue: string, name: string, value: string): string {
  const url = new URL(urlValue)
  url.searchParams.set(name, value)
  return url.toString()
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
  private readonly credentialStore: FileCredentialStore
  private readonly evidenceStore: EvidenceStore
  private readonly executionService: ExecutionService
  private readonly policyBroker: PolicyBroker
  private readonly modelGateway: ModelGateway
  private readonly reportService: ReportService
  private readonly onEvent?: (event: ScanEvent) => void
  private readonly controllers = new Map<string, AbortController>()
  private readonly tasks = new Map<string, Promise<void>>()

  constructor(dependencies: ScanCoordinatorDependencies) {
    this.repository = dependencies.repository
    this.credentialStore = dependencies.credentialStore
    this.evidenceStore = dependencies.evidenceStore
    this.executionService = dependencies.executionService
    this.policyBroker = dependencies.policyBroker
    this.modelGateway = dependencies.modelGateway
    this.reportService = dependencies.reportService
    this.onEvent = dependencies.onEvent
  }

  async control(scanId: string, action: ScanControlAction): Promise<ScanRecord> {
    const row = await this.repository.getScanRow(scanId)
    if (!row) throw new Error('扫描不存在。')
    const runtime = row.runtimeJson as unknown as CoordinatorRuntimeState

    if (action === 'start') {
      if (row.status !== 'draft') throw new Error('只有草稿扫描可以启动。')
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
      const next = transitionRuntime(runtime, { type: 'resume' }) as CoordinatorRuntimeState
      const scan = await this.repository.updateScan(scanId, {
        status: 'running',
        runtimeJson: next as unknown as Record<string, unknown>,
        lastError: null
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
          '达到请求、时间或费用预算',
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
      const endpoint = await this.repository.upsertEndpoint({
        scanId,
        method: 'GET',
        url,
        source: next.discoveredFrom ? 'link' : 'target-base',
        status: 'enumerating'
      })
      await this.persistQueryParameters(endpoint.id, endpoint.url)
      const http = await this.executeHttpProbe({
        scanId,
        agentRunId,
        endpointId: endpoint.id,
        targetUrl: endpoint.url,
        identity: primaryIdentity,
        summary: '低速读取页面并建立接口与参数基线。',
        expectedEvidence: '页面响应摘要、响应体和内容哈希',
        signal
      })
      if (http.result.status !== 'succeeded' || !isHtml(http)) continue
      const page = await this.repository.upsertPage({
        scanId,
        url: endpoint.url,
        depth: next.depth,
        ...(next.discoveredFrom ? { discoveredFrom: next.discoveredFrom } : {}),
        stateHash: http.result.responseBodySha256,
        status: 'fetched'
      })
      const browser = await this.executeBrowserProbe({
        scanId,
        agentRunId,
        targetUrl: endpoint.url,
        summary: '在断网隔离浏览器中提取页面链接与表单。',
        expectedEvidence: 'DOM 摘要、链接和表单清单',
        html: safeBodyText(http),
        action: 'inspect-dom',
        contentSecurityPolicy: http.result.responseHeaders['content-security-policy'],
        signal
      })
      if (browser.result.pageTitle) {
        await this.repository.upsertPage({
          scanId,
          url: endpoint.url,
          title: browser.result.pageTitle,
          depth: next.depth,
          ...(next.discoveredFrom ? { discoveredFrom: next.discoveredFrom } : {}),
          status: 'inspected'
        })
      }
      for (const link of browser.result.links) {
        if (!this.urlAllowed(link, context.scope, primaryIdentity?.id)) continue
        const linkEndpoint = await this.repository.upsertEndpoint({
          scanId,
          pageId: page.id,
          method: 'GET',
          url: link,
          source: 'link'
        })
        await this.persistQueryParameters(linkEndpoint.id, linkEndpoint.url)
        if (next.depth < 1 && !visited.has(linkEndpoint.url)) {
          queue.push({ url: linkEndpoint.url, depth: next.depth + 1, discoveredFrom: page.id })
        }
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
    const endpoints = await this.repository.listInventoryEndpoints(scanId)
    const endpointParameterNames = unique(
      endpoints.flatMap((endpoint) => endpoint.parameters.map((parameter) => parameter.name))
    )
    const knowledgeOutput = this.buildKnowledgeOutput(
      context.scan.families,
      endpointParameterNames
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
    const endpointIds = new Set(endpoints.map((endpoint) => endpoint.id))
    const parameterIds = new Set(endpoints.flatMap((endpoint) => endpoint.parameters.map((item) => item.id)))
    const candidates = strategy.value.candidates.filter(
      (candidate) =>
        context.scan.families.includes(candidate.family) &&
        endpointIds.has(candidate.endpointId) &&
        parameterIds.has(candidate.parameterId)
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
    const endpoints = await this.repository.listInventoryEndpoints(scanId)
    const byEndpoint = new Map(endpoints.map((endpoint) => [endpoint.id, endpoint]))
    const candidates = runtime.candidates ?? []
    let nextRuntime = runtime
    for (const candidate of candidates) {
      this.assertNotAborted(signal)
      const fingerprint = `${candidate.family}:${candidate.endpointId}:${candidate.parameterId}`
      if (nextRuntime.actionFingerprints.includes(fingerprint)) continue
      const endpoint = byEndpoint.get(candidate.endpointId)
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
          level: error instanceof PolicyDeniedError ? 'warning' : 'error',
          message: `${familyLabels[candidate.family]} 候选未完成：${errorMessage(error)}`,
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
    const context = await this.loadContext(input.scanId)
    let assessment: ValidationAssessment
    let primary: HttpObservation
    let baseline: HttpObservation
    let negative: HttpObservation | undefined
    let evidenceRefs: string[]
    let affectedResource: string | undefined
    const identity = context.identities[0]

    if (input.family === 'sqli') {
      const original = new URL(input.endpoint.url).searchParams.get(input.parameter.name) || '1'
      const numeric = /^-?\d+(?:\.\d+)?$/.test(original)
      const trueValue = numeric ? `${original} AND 1=1` : `${original}' AND '1'='1`
      const falseValue = numeric ? `${original} AND 1=2` : `${original}' AND '1'='2`
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: input.endpoint.url,
        identity,
        summary: 'SQLi 只读差异验证：获取基线响应。',
        expectedEvidence: '基线响应摘要和内容哈希',
        signal: input.signal
      })
      const trueFirst = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, trueValue),
        identity,
        summary: 'SQLi 只读布尔真条件差异验证。',
        payloadSummary: '非写入式布尔真条件；不读取业务数据。',
        expectedEvidence: '测试响应摘要和内容哈希',
        signal: input.signal
      })
      const falseControl = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, falseValue),
        identity,
        summary: 'SQLi 只读布尔负对照。',
        payloadSummary: '非写入式布尔假条件；不读取业务数据。',
        expectedEvidence: '负对照响应摘要和内容哈希',
        signal: input.signal
      })
      const trueRepeat = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, trueValue),
        identity,
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
    } else if (input.family === 'xss') {
      const xssMarker = marker()
      const payload = buildInertXssMarkerPayload(xssMarker)
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: input.endpoint.url,
        identity,
        summary: 'XSS 验证：获取未注入标记的基线响应。',
        expectedEvidence: '基线响应摘要和 DOM 输入',
        signal: input.signal
      })
      primary = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, payload),
        identity,
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
          targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, payload),
          summary: '在断网隔离浏览器中验证随机惰性 XSS 标记。',
          payloadSummary: `仅设置本地 DOM 属性的标记 ${xssMarker}。`,
          expectedEvidence: '标记执行状态、DOM 快照和截图',
          html: safeBodyText(primary),
          action: 'verify-xss',
          marker: xssMarker,
          contentSecurityPolicy: primary.result.responseHeaders['content-security-policy'],
          signal: input.signal
        })
      }
      assessment = assessXss({ marker: xssMarker, http: primary, ...(browser ? { browser } : {}) })
      evidenceRefs = unique([
        ...baseline.evidenceRefs,
        ...primary.evidenceRefs,
        ...(browser?.evidenceRefs ?? [])
      ])
    } else if (input.family === 'ssrf') {
      const callbackUrl = context.row.configJson.callbackUrl
      if (!callbackUrl) {
        throw new Error('扫描未配置受控回调 URL，SSRF 只能标记为未具备验证条件。')
      }
      const callback = new URL(callbackUrl)
      callback.searchParams.set('agentgo_token', callbackToken())
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        targetUrl: callback.toString(),
        summary: '读取明确授权的受控 SSRF 回调证明。',
        expectedEvidence: '唯一回调证明响应',
        signal: input.signal
      })
      primary = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(
          input.endpoint.url,
          input.parameter.name,
          callback.toString()
        ),
        identity,
        summary: 'SSRF 受控回调 URL 只读验证。',
        payloadSummary: '仅访问已列入 Scope 的项目控制回调端点。',
        expectedEvidence: '目标响应中的唯一受控证明',
        signal: input.signal
      })
      negative = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(
          input.endpoint.url,
          input.parameter.name,
          'agentgo-invalid-url'
        ),
        identity,
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
    } else {
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
      affectedResource = ownerResourceId
      baseline = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, ownerResourceId),
        identity: owner,
        summary: 'IDOR 对照：资源所有者只读访问自己的测试资源。',
        expectedEvidence: '所有者基线响应摘要',
        signal: input.signal
      })
      const secondOwn = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, secondResourceId),
        identity: second,
        summary: 'IDOR 负对照：第二身份只读访问自己的测试资源。',
        expectedEvidence: '第二身份合法资源响应摘要',
        signal: input.signal
      })
      primary = await this.executeHttpProbe({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        endpointId: input.endpoint.id,
        targetUrl: replaceQueryParameter(input.endpoint.url, input.parameter.name, ownerResourceId),
        identity: second,
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
    const rule = V1_CONFIRMATION_RULES[input.family]
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
      family: input.family,
      title: `${familyLabels[input.family]}：${location.pathname} 参数 ${input.parameter.name}`,
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
      hypothesis: `${familyLabels[input.assessment.family]} 候选需要按版本化规则验证。`,
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

  private async executeHttpProbe(input: {
    scanId: string
    agentRunId: string
    endpointId?: string
    targetUrl: string
    identity?: IdentityRecord
    summary: string
    payloadSummary?: string
    expectedEvidence: string
    signal: AbortSignal
  }): Promise<HttpObservation> {
    this.assertNotAborted(input.signal)
    const context = await this.loadContext(input.scanId)
    const policy = await this.policyBroker.evaluate({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action: {
        kind: 'http-request',
        targetUrl: input.targetUrl,
        method: 'GET',
        ...(input.identity ? { identityId: input.identity.id } : {}),
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: input.summary,
        ...(input.payloadSummary ? { payloadSummary: input.payloadSummary } : {}),
        expectedEvidence: input.expectedEvidence,
        requestedRequestsPerMinute: Math.min(
          context.scope.maxRequestsPerMinute,
          context.scan.budget.maxRequestsPerMinute
        ),
        requestedConcurrency: 1,
        maxRequests: 1,
        timeoutMs: 10_000,
        userApproved: false
      },
      stopConditions: ['取得当前最小证据后停止', '出现阻断、越界或副作用立即停止']
    })
    if (!policy.decision.allowed || policy.decision.requiresApproval) {
      throw new PolicyDeniedError(policy.decision.reasons.join('；'))
    }
    const execution = await this.executionService.executeHttp({
      scanId: input.scanId,
      policyDecisionId: policy.decision.id,
      ...(input.endpointId ? { endpointId: input.endpointId } : {}),
      signal: input.signal,
      request: {
        targetUrl: input.targetUrl,
        method: 'GET',
        headers: this.headersForIdentity(input.identity),
        timeoutMs: 10_000,
        maxResponseBytes: 2 * 1024 * 1024,
        maxRedirects: 5
      }
    })
    return {
      result: execution.result,
      evidenceRefs: execution.evidenceRefs,
      ...(execution.interactionId ? { interactionId: execution.interactionId } : {}),
      toolCallId: execution.toolCallId,
      proposalId: policy.proposal.id,
      policyDecisionId: policy.decision.id
    }
  }

  private async executeBrowserProbe(input: {
    scanId: string
    agentRunId: string
    targetUrl: string
    summary: string
    payloadSummary?: string
    expectedEvidence: string
    html: string
    action: 'inspect-dom' | 'verify-xss' | 'capture-evidence'
    marker?: string
    contentSecurityPolicy?: string
    signal: AbortSignal
  }): Promise<BrowserObservation> {
    const policy = await this.policyBroker.evaluate({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action: {
        kind: 'browser-action',
        targetUrl: input.targetUrl,
        method: 'GET',
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: input.summary,
        ...(input.payloadSummary ? { payloadSummary: input.payloadSummary } : {}),
        expectedEvidence: input.expectedEvidence,
        maxRequests: 1,
        timeoutMs: 10_000,
        userApproved: false
      },
      stopConditions: ['完成本地隔离渲染后立即关闭浏览器上下文']
    })
    if (!policy.decision.allowed || policy.decision.requiresApproval) {
      throw new PolicyDeniedError(policy.decision.reasons.join('；'))
    }
    const execution = await this.executionService.executeBrowser({
      scanId: input.scanId,
      policyDecisionId: policy.decision.id,
      signal: input.signal,
      request: {
        baseUrl: input.targetUrl,
        html: input.html,
        action: input.action,
        ...(input.marker ? { marker: input.marker } : {}),
        ...(input.contentSecurityPolicy
          ? { contentSecurityPolicy: input.contentSecurityPolicy }
          : {}),
        timeoutMs: 10_000,
        maxDomBytes: 1024 * 1024
      }
    })
    return {
      result: execution.result,
      evidenceRefs: execution.evidenceRefs,
      toolCallId: execution.toolCallId,
      proposalId: policy.proposal.id,
      policyDecisionId: policy.decision.id
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

  private async persistQueryParameters(endpointId: string, urlValue: string): Promise<void> {
    const url = new URL(urlValue)
    for (const [name, value] of url.searchParams) {
      await this.repository.upsertParameter({
        endpointId,
        name,
        location: 'query',
        dataType: /^-?\d+(?:\.\d+)?$/.test(value) ? 'number' : 'string',
        required: true,
        exampleMasked: value ? '[provided]' : '[empty]'
      })
    }
  }

  private async persistForm(scanId: string, pageId: string, form: BrowserFormSummary): Promise<void> {
    const method = form.method.toUpperCase()
    const url = new URL(form.action)
    if (method === 'GET') {
      for (const field of form.fields) {
        if (!url.searchParams.has(field.name)) url.searchParams.set(field.name, '')
      }
    }
    const endpoint = await this.repository.upsertEndpoint({
      scanId,
      pageId,
      method,
      url: url.toString(),
      source: 'form'
    })
    for (const field of form.fields) {
      await this.repository.upsertParameter({
        endpointId: endpoint.id,
        name: field.name,
        location: method === 'GET' ? 'query' : 'form',
        dataType: field.type,
        required: field.required,
        exampleMasked: '[form-field]'
      })
    }
  }

  private headersForIdentity(identity?: IdentityRecord): Record<string, string> {
    const headers: Record<string, string> = {
      'User-Agent': 'AgentGo/0.1 Authorized Security Validation',
      Accept: 'text/html,application/json;q=0.9,*/*;q=0.8'
    }
    if (!identity || identity.authType === 'none') return headers
    if (!identity.credentialId) throw new Error(`身份 ${identity.label} 缺少凭据引用。`)
    const secret = this.credentialStore.get(identity.credentialId)
    if (!secret) throw new Error(`身份 ${identity.label} 的凭据不可用。`)
    if (identity.authType === 'bearer') headers.Authorization = `Bearer ${secret}`
    else if (identity.authType === 'cookie') headers.Cookie = secret
    else if (identity.authType === 'basic') {
      headers.Authorization = `Basic ${Buffer.from(secret).toString('base64')}`
    } else if (identity.authType === 'header') {
      if (!identity.headerName) throw new Error(`身份 ${identity.label} 缺少 Header 名称。`)
      headers[identity.headerName] = secret
    }
    return headers
  }

  private buildKnowledgeOutput(
    families: VulnerabilityFamily[],
    signalTerms: string[]
  ): KnowledgeAgentOutput {
    const matchedIds = unique(
      families.flatMap((family) =>
        this.repository.searchKnowledgeEntryIds({
          query: signalTerms.join(' '),
          families: [family],
          limit: 5
        })
      )
    )
    const entryById = new Map(V1_KNOWLEDGE_ENTRIES.map((entry) => [entry.id, entry]))
    const entries = matchedIds
      .map((entryId) => entryById.get(entryId))
      .filter((entry): entry is (typeof V1_KNOWLEDGE_ENTRIES)[number] => Boolean(entry))
    return {
      matchedEntryIds: entries.map((entry) => entry.id),
      guidance: entries.map((entry) => ({
        family: entry.family,
        applicability: entry.applicability,
        safeProbePrinciples: entry.safeProbePrinciples,
        confirmationRules: entry.confirmationRules,
        falsePositivePatterns: entry.falsePositivePatterns,
        remediationHints: entry.remediationHints
      })),
      sourceRefs: unique(entries.flatMap((entry) => entry.sourceRefs)),
      policyConstraints: unique(entries.flatMap((entry) => entry.forbiddenActions)),
      ...(entries.length === 0
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
    if (
      scan.estimatedCost > 0 &&
      scan.estimatedCost >= scan.budget.maxEstimatedCost
    ) {
      throw new Error('扫描模型费用预算已耗尽。')
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
}
