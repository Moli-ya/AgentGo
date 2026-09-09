import { randomUUID } from 'node:crypto'
import type {
  LegacyV1VulnerabilityFamily,
  ValidationEvidenceBinding,
  ValidationObservation,
  ValidationPlan,
  ValidationPlanRun,
  ValidationStep,
  ValidationStepRun
} from '@agentgo/contracts'
import { isLegacyV1VulnerabilityFamily } from '@agentgo/contracts'
import { AgentGoRepository, ValidationPlanRepository } from '@agentgo/db'
import { hashIdentitySessionValue } from '@agentgo/domain'
import type { SessionVault } from './session-vault'
import type {
  BrowserExecutionResultView,
  BrowserOfflineExecutionStepInput,
  ExecutionPort,
  HttpExecutionResultView,
  HttpExecutionStepInput,
  RequestSelectorMutation,
  StoredExecutionResult
} from './execution-port'
import {
  compileValidationPlan,
  type ValidationPlanDraft
} from './validation-plan-compiler'
import type { BrowserObservation, HttpObservation } from './validation-engine'

export interface CallbackCollectorPort {
  register(token: string): Promise<{ collectorId: string }>
  poll(
    collectorId: string,
    timeoutMs: number
  ): Promise<{
    received: boolean
    sourceKind?: string
    staleOrReplay?: boolean
    clientOrBrokerOrHealth?: boolean
  }>
  consume(collectorId: string): Promise<{
    observation?: string
    sourceKind?: string
    staleOrReplay?: boolean
    clientOrBrokerOrHealth?: boolean
  }>
  bind?(input: {
    readonly collectorId: string
    readonly scanId?: string
    readonly candidateId?: string
    readonly stepId?: string
    readonly targetRef?: string
    readonly tenantId?: string
  }): void
}

export interface CallbackStepObservation {
  readonly received?: boolean
  readonly observation?: string
  readonly collectorId?: string
  readonly sourceKind?: string
  readonly staleOrReplay?: boolean
  readonly clientOrBrokerOrHealth?: boolean
}

export interface ValidationPlanExecutorDependencies {
  readonly plans: ValidationPlanRepository
  readonly execution: ExecutionPort
  readonly callbackCollector?: CallbackCollectorPort
  readonly agentRunId: string
  readonly sessionVault?: SessionVault
  readonly repository?: AgentGoRepository
}

export interface ValidationPlanExecuteOptions {
  readonly signal?: AbortSignal
  readonly htmlSeeds?: Readonly<Record<string, string>>
}

export interface ValidationPlanExecution {
  readonly run: ValidationPlanRun
  readonly plan: ValidationPlan
  readonly httpByStep: ReadonlyMap<string, HttpObservation>
  readonly browserByStep: ReadonlyMap<string, BrowserObservation>
  readonly callbackByStep: ReadonlyMap<string, CallbackStepObservation>
  readonly requestCount: number
}

interface ExecutorState {
  identityId?: string
  sessionId?: string
  sessionGeneration?: number
  frozenHtmlByStep: Map<string, string>
  observations: Map<string, ValidationObservation>
  collectors: Map<string, string>
  htmlByStep: Map<string, string>
  headersByStep: Map<string, Readonly<Record<string, string>>>
  httpByStep: Map<string, HttpObservation>
  browserByStep: Map<string, BrowserObservation>
  callbackByStep: Map<string, CallbackStepObservation>
  statusByStep: Map<string, number>
  hashByStep: Map<string, string>
  usedRequests: number
  usedBytes: number
  tracesByStep: Map<string, { policyDecisionId?: string; leaseId?: string }>
  outcomesByStep: Map<string, ValidationStepRun['status']>
}

function terminalTraceId(values: readonly string[], label: string): string {
  const value = values.at(-1)
  if (!value) {
    throw new Error(`ExecutionPort omitted the terminal ${label}.`)
  }
  return value
}

function httpObservationFrom(
  executed: StoredExecutionResult<HttpExecutionResultView>
): HttpObservation {
  const toolCallId = terminalTraceId(executed.toolCallIds, 'tool call')
  const proposalId = terminalTraceId(executed.proposalIds, 'proposal')
  const policyDecisionId = terminalTraceId(
    executed.policyDecisionIds,
    'policy decision'
  )
  terminalTraceId(executed.grantIds, 'execution grant')
  terminalTraceId(executed.leaseIds, 'execution lease')
  const interactionId = executed.interactionIds.at(-1)
  return {
    result: executed.result,
    evidenceRefs: [...executed.evidenceRefs],
    ...(interactionId ? { interactionId } : {}),
    toolCallId,
    proposalId,
    policyDecisionId
  }
}

function browserObservationFrom(
  executed: StoredExecutionResult<BrowserExecutionResultView>
): BrowserObservation {
  const toolCallId = terminalTraceId(executed.toolCallIds, 'tool call')
  const proposalId = terminalTraceId(executed.proposalIds, 'proposal')
  const policyDecisionId = terminalTraceId(
    executed.policyDecisionIds,
    'policy decision'
  )
  terminalTraceId(executed.grantIds, 'execution grant')
  terminalTraceId(executed.leaseIds, 'execution lease')
  return {
    result: executed.result,
    evidenceRefs: [...executed.evidenceRefs],
    toolCallId,
    proposalId,
    policyDecisionId,
    ...(executed.reviewableDomOrScreenshotEvidence
      ? { reviewableDomOrScreenshotEvidence: true }
      : {})
  }
}

function executionFamily(familyId: string): LegacyV1VulnerabilityFamily {
  if (!isLegacyV1VulnerabilityFamily(familyId)) {
    throw new Error(`Validation plan family ${familyId} is not a legacy execution family.`)
  }
  return familyId
}

export class ValidationPlanExecutor {
  constructor(private readonly dependencies: ValidationPlanExecutorDependencies) {}

  async run(draft: ValidationPlanDraft): Promise<ValidationPlanRun> {
    return (await this.execute(draft)).run
  }

  async execute(
    draft: ValidationPlanDraft,
    options: ValidationPlanExecuteOptions = {}
  ): Promise<ValidationPlanExecution> {
    const plan = compileValidationPlan(draft)
    const now = new Date().toISOString()
    let run: ValidationPlanRun = {
      runId: randomUUID(),
      scanId: plan.scanId,
      planId: plan.planId,
      planHash: plan.planHash,
      status: 'running',
      createdAt: now
    }
    await this.dependencies.plans.savePlanRun(run)
    const state: ExecutorState = {
      frozenHtmlByStep: new Map(Object.entries(options.htmlSeeds ?? {})),
      observations: new Map(),
      collectors: new Map(),
      htmlByStep: new Map(),
      headersByStep: new Map(),
      httpByStep: new Map(),
      browserByStep: new Map(),
      callbackByStep: new Map(),
      statusByStep: new Map(),
      hashByStep: new Map(),
      usedRequests: 0,
      usedBytes: 0,
      tracesByStep: new Map(),
      outcomesByStep: new Map()
    }
    const deadline = AbortSignal.timeout(plan.budget.maxDurationMs)
    const signal = options.signal ? AbortSignal.any([options.signal, deadline]) : deadline
    const grouped = new Set(
      plan.steps
        .filter((step) => step.kind === 'bounded-parallel-group')
        .flatMap((step) =>
          step.kind === 'bounded-parallel-group'
            ? step.childStepIds
            : []
        )
    )
    let hadFailure = false
    try {
      for (const [ordinal, step] of plan.steps.entries()) {
        if (signal.aborted) {
          run = await this.finish(run, 'fail-closed', 'validation-interrupted-or-timed-out')
          return this.snapshot(plan, run, state)
        }
        if (grouped.has(step.stepId)) continue
        const outcome = await this.runStep(plan, run, step, state, ordinal, signal)
        if (outcome === 'fail-closed' || outcome === 'failed') {
          hadFailure = true
          const stop =
            outcome === 'fail-closed' ||
            step.stopConditions.includes('on-step-failure') ||
            plan.stopConditions.includes('on-step-failure')
          if (stop) {
            run = await this.finish(run, outcome, `Stopped after ${step.stepId}`)
            return this.snapshot(plan, run, state)
          }
        }
      }
      run = await this.finish(run, hadFailure ? 'failed' : 'succeeded')
      return this.snapshot(plan, run, state)
    } catch {
      run = await this.finish(run, 'fail-closed', 'validation-execution-failed')
      return this.snapshot(plan, run, state)
    }
  }

  private snapshot(
    plan: ValidationPlan,
    run: ValidationPlanRun,
    state: ExecutorState
  ): ValidationPlanExecution {
    return {
      run,
      plan,
      httpByStep: new Map(state.httpByStep),
      browserByStep: new Map(state.browserByStep),
      callbackByStep: new Map(state.callbackByStep),
      requestCount: state.usedRequests
    }
  }

  private async runStep(
    plan: ValidationPlan,
    run: ValidationPlanRun,
    step: ValidationStep,
    state: ExecutorState,
    ordinal: number,
    signal: AbortSignal | undefined
  ): Promise<ValidationStepRun['status']> {
    const started: ValidationStepRun = {
      stepRunId: randomUUID(),
      runId: run.runId,
      stepId: step.stepId,
      kind: step.kind,
      status: 'running',
      ordinal,
      createdAt: new Date().toISOString()
    }
    await this.dependencies.plans.saveStepRun(started)
    let status: ValidationStepRun['status'] = 'succeeded'
    let errorCode: string | undefined
    try {
      if (signal?.aborted) {
        status = 'fail-closed'
        errorCode = 'validation-interrupted-or-timed-out'
      } else if (state.usedRequests + step.budget.maxRequests > plan.budget.maxRequests) {
        status = 'fail-closed'
        errorCode = 'budget-exhausted'
      } else {
        status = await this.dispatch(plan, run, step, state, signal)
        if (signal?.aborted || state.usedBytes > plan.budget.maxBytes) {
          status = 'fail-closed'
          errorCode = signal?.aborted ? 'validation-interrupted-or-timed-out' : 'budget-exhausted'
        }
      }
    } catch {
      status = 'fail-closed'
      errorCode = 'validation-step-failed'
    }
    state.outcomesByStep.set(step.stepId, status)
    const trace = state.tracesByStep.get(step.stepId)
    await this.dependencies.plans.updateStepRun({
      ...started,
      status,
      ...(errorCode ? { errorCode } : {}),
      ...(trace?.policyDecisionId
        ? { policyDecisionId: trace.policyDecisionId }
        : {}),
      ...(trace?.leaseId ? { leaseId: trace.leaseId } : {}),
      completedAt: new Date().toISOString()
    })
    return status
  }

  private async dispatch(
    plan: ValidationPlan,
    run: ValidationPlanRun,
    step: ValidationStep,
    state: ExecutorState,
    signal: AbortSignal | undefined
  ): Promise<ValidationStepRun['status']> {
    switch (step.kind) {
      case 'passive-analysis':
        await this.observe(run, step, 'passive', { analyzed: true })
        return 'succeeded'
      case 'identity-switch': {
        state.identityId = step.identityId
        const vault = this.dependencies.sessionVault
        const repository = this.dependencies.repository
        if (vault && repository) {
          const scan = await repository.getScan(plan.scanId)
          if (!scan) return 'fail-closed'
          try {
            const session = await vault.establishSession({
              identityId: step.identityId,
              scopeSnapshotId: scan.scopeSnapshotId
            })
            state.sessionId = session.sessionId
            state.sessionGeneration = session.generation
            await this.observe(run, step, 'identity', {
              identityId: step.identityId,
              sessionGeneration: session.generation,
              sessionHash: hashIdentitySessionValue({
                sessionId: session.sessionId,
                identityId: step.identityId,
                generation: session.generation
              })
            })
            return 'succeeded'
          } catch {
            return 'fail-closed'
          }
        }
        await this.observe(run, step, 'identity', { identityId: step.identityId })
        return 'succeeded'
      }
      case 'http-request': {
        if (step.budget.maxRequests < 1) return 'fail-closed'
        if (state.identityId && step.identityId && state.identityId !== step.identityId) return 'fail-closed'
        const mutation: RequestSelectorMutation | undefined =
          step.mutationName !== undefined && step.mutationValue !== undefined
            ? step.mutationKind === 'path'
              ? {
                  kind: 'path',
                  name: step.mutationName,
                  segmentIndex: step.mutationSegmentIndex ?? 0,
                  value: step.mutationValue
                }
              : {
                  kind: 'query',
                  name: step.mutationName,
                  occurrence: 0,
                  value: step.mutationValue
                }
            : undefined
        const input: HttpExecutionStepInput = {
          scanId: plan.scanId,
          agentRunId: this.dependencies.agentRunId,
          familyId: executionFamily(plan.familyId),
          stepId: step.stepId,
          purpose: step.purpose,
          summary: step.summary ?? `Validation plan ${step.stepId}`,
          expectedEvidence: 'HTTP observation',
          adapterKind: 'http',
          endpointId: step.endpointId,
          desiredUrl: step.desiredUrl,
          timeoutMs: step.budget.timeoutMs,
          maxResponseBytes: step.budget.maxResponseBytes,
          maxRedirects: step.maxRedirects ?? 0,
          ...(state.identityId ?? step.identityId
            ? { identityId: state.identityId ?? step.identityId }
            : {}),
          ...(state.sessionId ? { sessionId: state.sessionId } : {}),
          ...(mutation ? { mutation } : {}),
          ...(step.payloadSummary ? { payloadSummary: step.payloadSummary } : {}),
          ...(signal ? { signal } : {})
        }
        state.usedRequests += 1
        const executed = await this.dependencies.execution.execute(input)
        this.recordTrace(state, step.stepId, executed)
        const observation = httpObservationFrom(executed)
        state.httpByStep.set(step.stepId, observation)
        state.usedRequests += executed.result.redirectChain.length
        state.usedBytes += executed.result.responseBytes
        state.statusByStep.set(step.stepId, executed.result.statusCode ?? 0)
        if (executed.result.responseBodySha256) {
          state.hashByStep.set(step.stepId, executed.result.responseBodySha256)
        }
        if (executed.result.responseBody) {
          state.htmlByStep.set(
            step.stepId,
            Buffer.from(executed.result.responseBody).toString('utf8')
          )
        }
        state.headersByStep.set(step.stepId, executed.result.responseHeaders)
        await this.observe(run, step, 'http', {
          statusCode: executed.result.statusCode ?? 0,
          evidenceRefs: [...executed.evidenceRefs],
          responseBodySha256: executed.result.responseBodySha256
        })
        await this.bindEvidence(run, step, executed.evidenceRefs)
        if (executed.result.responseBytes > step.budget.maxResponseBytes || state.usedRequests > plan.budget.maxRequests) return 'fail-closed'
        return executed.result.status === 'succeeded' ? 'succeeded' : 'failed'
      }
      case 'browser-offline-replay': {
        const html =
          state.frozenHtmlByStep.get(step.htmlFromObservationId) ??
          state.htmlByStep.get(step.htmlFromObservationId)
        if (!html) return 'fail-closed'
        const sourceHeaders = state.headersByStep.get(step.htmlFromObservationId)
        const input: BrowserOfflineExecutionStepInput = {
          scanId: plan.scanId,
          agentRunId: this.dependencies.agentRunId,
          familyId: executionFamily(plan.familyId),
          stepId: step.stepId,
          purpose: 'read',
          summary: step.summary ?? `Validation plan ${step.stepId}`,
          expectedEvidence: 'offline browser observation',
          adapterKind: 'browser-offline',
          baseUrl: step.baseUrl ?? 'http://127.0.0.1/',
          html,
          action: step.action,
          timeoutMs: step.budget.timeoutMs,
          maxDomBytes: step.budget.maxResponseBytes,
          ...(step.marker ? { marker: step.marker } : {}),
          ...(step.payloadSummary ? { payloadSummary: step.payloadSummary } : {}),
          ...(sourceHeaders?.['content-security-policy']
            ? { contentSecurityPolicy: sourceHeaders['content-security-policy'] }
            : {}),
          ...(signal ? { signal } : {})
        }
        const executed = await this.dependencies.execution.execute(input)
        this.recordTrace(state, step.stepId, executed)
        state.usedBytes += executed.result.resultBytes
        const observation = browserObservationFrom(executed)
        state.browserByStep.set(step.stepId, observation)
        await this.observe(run, step, 'browser-offline', {
          evidenceRefs: [...executed.evidenceRefs],
          markerExecuted: executed.result.markerExecuted === true
        })
        await this.bindEvidence(run, step, executed.evidenceRefs)
        return executed.result.status === 'succeeded' ? 'succeeded' : 'failed'
      }
      case 'browser-mediated-read': {
        if (step.budget.maxRequests < 1) return 'fail-closed'
        state.usedRequests += 1
        const executed = await this.dependencies.execution.executeMediatedHttp({
          scanId: plan.scanId,
          agentRunId: this.dependencies.agentRunId,
          familyId: executionFamily(plan.familyId),
          stepId: step.stepId,
          purpose: 'read',
          summary: `Validation plan ${step.stepId}`,
          expectedEvidence: 'mediated read observation',
          adapterKind: 'http',
          method: 'GET',
          endpointId: step.endpointId,
          requestVariantId: step.requestVariantId,
          desiredUrl: step.desiredUrl,
          ...(state.identityId ? { identityId: state.identityId } : {}),
          ...(state.sessionId ? { sessionId: state.sessionId } : {}),
          ...(signal ? { signal } : {}),
          ...(step.expectedContentHash
            ? { expectedContentHash: step.expectedContentHash }
            : {}),
          timeoutMs: step.budget.timeoutMs,
          maxResponseBytes: step.budget.maxResponseBytes
        })
        this.recordTrace(state, step.stepId, executed)
        state.usedRequests += executed.result.redirectChain.length
        state.usedBytes += executed.result.responseBytes
        state.httpByStep.set(step.stepId, httpObservationFrom(executed))
        state.statusByStep.set(step.stepId, executed.result.statusCode ?? 0)
        if (executed.result.responseBodySha256) state.hashByStep.set(step.stepId, executed.result.responseBodySha256)
        await this.observe(run, step, 'mediated-read', {
          evidenceRefs: [...executed.evidenceRefs]
        })
        await this.bindEvidence(run, step, executed.evidenceRefs)
        if (executed.result.responseBytes > step.budget.maxResponseBytes || state.usedRequests > plan.budget.maxRequests) return 'fail-closed'
        return executed.result.status === 'succeeded' ? 'succeeded' : 'failed'
      }
      case 'extract-value':
      case 'state-observe':
        // No reviewed extraction/state oracle is bound to this runtime yet.
        return 'fail-closed'
      case 'callback-register':
      case 'callback-poll':
      case 'callback-consume': {
        const collector = this.dependencies.callbackCollector
        if (!collector) return 'fail-closed'
        if (step.kind === 'callback-register') {
          const registered = await collector.register(step.tokenSlot)
          state.collectors.set(step.stepId, registered.collectorId)
          collector.bind?.({
            collectorId: registered.collectorId,
            scanId: plan.scanId,
            stepId: step.stepId
          })
          state.callbackByStep.set(step.stepId, {
            collectorId: registered.collectorId
          })
          await this.observe(run, step, 'callback', registered)
          return 'succeeded'
        }
        const collectorId = state.collectors.get(step.collectorFromStepId)
        if (!collectorId) return 'fail-closed'
        if (step.kind === 'callback-poll') {
          const polled = await collector.poll(collectorId, step.budget.timeoutMs)
          state.callbackByStep.set(step.stepId, {
            collectorId,
            received: polled.received,
            ...(polled.sourceKind ? { sourceKind: polled.sourceKind } : {}),
            ...(polled.staleOrReplay !== undefined
              ? { staleOrReplay: polled.staleOrReplay }
              : {}),
            ...(polled.clientOrBrokerOrHealth !== undefined
              ? { clientOrBrokerOrHealth: polled.clientOrBrokerOrHealth }
              : {})
          })
          await this.observe(run, step, 'callback-poll', polled)
          return 'succeeded'
        }
        const consumed = await collector.consume(collectorId)
        state.callbackByStep.set(step.stepId, {
          collectorId,
          ...(consumed.observation ? { observation: consumed.observation } : {}),
          ...(consumed.sourceKind ? { sourceKind: consumed.sourceKind } : {}),
          ...(consumed.staleOrReplay !== undefined
            ? { staleOrReplay: consumed.staleOrReplay }
            : {}),
          ...(consumed.clientOrBrokerOrHealth !== undefined
            ? { clientOrBrokerOrHealth: consumed.clientOrBrokerOrHealth }
            : {})
        })
        await this.observe(run, step, 'callback-consume', {
          collectorId,
          ...(consumed.observation ? { observation: consumed.observation } : {}),
          ...(consumed.sourceKind ? { sourceKind: consumed.sourceKind } : {})
        })
        return 'succeeded'
      }
      case 'bounded-parallel-group': {
        const children = plan.steps.filter((candidate) =>
          step.childStepIds.includes(candidate.stepId)
        )
        const fanOut = Math.min(step.maxFanOut, plan.budget.maxFanOut)
        for (let index = 0; index < children.length; index += fanOut) {
          const batch = children.slice(index, index + fanOut)
          const results = await Promise.all(
            batch.map((child) =>
              this.runStep(plan, run, child, state, plan.steps.indexOf(child), signal)
            )
          )
          if (results.some((result) => result === 'failed' || result === 'fail-closed')) {
            return 'failed'
          }
        }
        return 'succeeded'
      }
      case 'compare': {
        if (state.outcomesByStep.get(step.leftStepId) !== 'succeeded' || state.outcomesByStep.get(step.rightStepId) !== 'succeeded') return 'fail-closed'
        const left = state.statusByStep.get(step.leftStepId)
        const right = state.statusByStep.get(step.rightStepId)
        if (step.comparator === 'body-hash-diff') {
          if (!state.hashByStep.has(step.leftStepId) || !state.hashByStep.has(step.rightStepId)) return 'fail-closed'
        } else if (left === undefined || right === undefined) return 'fail-closed'
        const different =
          step.comparator === 'body-hash-diff'
            ? state.hashByStep.get(step.leftStepId) !==
              state.hashByStep.get(step.rightStepId)
            : left !== right
        await this.observe(run, step, 'compare', { different, left, right })
        return 'succeeded'
      }
      case 'aggregate':
        if (step.childStepIds.some((id) => state.outcomesByStep.get(id) !== 'succeeded')) return 'fail-closed'
        await this.observe(run, step, 'aggregate', { childStepIds: [...step.childStepIds] })
        return 'succeeded'
      case 'cleanup':
      case 'cleanup-verify':
        return 'fail-closed'
      default:
        return 'fail-closed'
    }
  }

  private recordTrace(
    state: ExecutorState,
    stepId: string,
    executed: {
      readonly policyDecisionIds: readonly string[]
      readonly leaseIds: readonly string[]
    }
  ): void {
    state.tracesByStep.set(stepId, {
      policyDecisionId: executed.policyDecisionIds.at(-1),
      leaseId: executed.leaseIds.at(-1)
    })
  }

  private async observe(
    run: ValidationPlanRun,
    step: ValidationStep,
    kind: string,
    payload: Record<string, unknown>
  ): Promise<void> {
    const observation: ValidationObservation = {
      observationId: randomUUID(),
      runId: run.runId,
      stepId: step.stepId,
      kind,
      payloadJson: payload,
      createdAt: new Date().toISOString()
    }
    await this.dependencies.plans.saveObservation(observation)
  }

  private async bindEvidence(
    run: ValidationPlanRun,
    step: ValidationStep,
    evidenceRefs: readonly string[]
  ): Promise<void> {
    let ordinal = 0
    for (const role of step.evidenceRoles) {
      const evidenceRef = evidenceRefs[ordinal]
      if (!evidenceRef) continue
      const binding: ValidationEvidenceBinding = {
        bindingId: randomUUID(),
        runId: run.runId,
        stepId: step.stepId,
        evidenceRef,
        role,
        ordinal,
        profileId: 'legacy.v1.evidence',
        profileVersion: step.moduleVersion
      }
      await this.dependencies.plans.saveEvidenceBinding(binding)
      ordinal += 1
    }
  }

  private async finish(
    run: ValidationPlanRun,
    status: ValidationPlanRun['status'],
    stopReason?: string
  ): Promise<ValidationPlanRun> {
    const completed: ValidationPlanRun = {
      ...run,
      status,
      ...(stopReason ? { stopReason } : {}),
      completedAt: new Date().toISOString()
    }
    return this.dependencies.plans.updatePlanRun(completed)
  }
}
