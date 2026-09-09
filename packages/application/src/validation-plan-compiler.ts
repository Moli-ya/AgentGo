import {
  ValidationPlanSchema,
  ValidationStepKindSchema,
  type CapabilityId,
  type ValidationPlan,
  type ValidationStep
} from '@agentgo/contracts'
import { stableInventoryHash } from '@agentgo/domain'
import { DEFAULT_PROBE_CAPABILITY_CATALOG } from '@agentgo/security-policy'
import { randomUUID } from 'node:crypto'

export class ValidationPlanCompileError extends Error {
  constructor(
    readonly code:
      | 'unknown-step'
      | 'unknown-capability'
      | 'budget-exceeded'
      | 'dangling-ref'
      | 'environment-mismatch'
      | 'invalid-plan',
    message: string
  ) {
    super(message)
    this.name = 'ValidationPlanCompileError'
  }
}

export type ValidationPlanDraft = Omit<
  ValidationPlan,
  'planHash' | 'planId' | 'createdAt' | 'schemaVersion'
> & {
  readonly planId?: string
  readonly createdAt?: string
}

export function compileValidationPlan(draft: ValidationPlanDraft): ValidationPlan {
  const planId = inputPlanId(draft.planId)
  const createdAt = draft.createdAt ?? new Date().toISOString()
  const unsigned = {
    schemaVersion: 'agentgo.validation-plan.v1' as const,
    planId,
    scanId: draft.scanId,
    familyId: draft.familyId,
    techniqueId: draft.techniqueId,
    moduleVersion: draft.moduleVersion,
    strategyVersion: draft.strategyVersion,
    environment: draft.environment,
    steps: draft.steps,
    stopConditions: draft.stopConditions,
    budget: draft.budget,
    createdAt
  }
  assertKnownSteps(unsigned.steps)
  assertCapabilities(unsigned.steps)
  assertBudget(unsigned)
  const parsed = ValidationPlanSchema.safeParse({
    ...unsigned,
    planHash: stableInventoryHash(unsigned)
  })
  if (!parsed.success) {
    throw new ValidationPlanCompileError(
      'invalid-plan',
      parsed.error.issues[0]?.message ?? 'Validation plan is invalid.'
    )
  }
  assertExecutionGraph(parsed.data)
  return parsed.data
}

/** Validate execution ownership before any step can acquire authority. */
function assertExecutionGraph(plan: ValidationPlan): void {
  const byId = new Map(plan.steps.map((step) => [step.stepId, step]))
  const positionById = new Map(plan.steps.map((step, index) => [step.stepId, index]))
  const owners = new Map<string, string>()
  for (const step of plan.steps) {
    if (
      step.familyId !== plan.familyId ||
      step.techniqueId !== plan.techniqueId ||
      step.moduleVersion !== plan.moduleVersion ||
      step.strategyVersion !== plan.strategyVersion
    ) {
      throw new ValidationPlanCompileError(
        'invalid-plan',
        'Step family and definition versions must match the plan.'
      )
    }
    if (step.kind !== 'bounded-parallel-group') continue
    if (step.fixtureOnly && plan.environment !== 'attested-fixture') {
      throw new ValidationPlanCompileError('environment-mismatch', 'Fixture-only parallel groups require an attested fixture.')
    }
    for (const childId of step.childStepIds) {
      const child = byId.get(childId)
      if (!child || childId === step.stepId || owners.has(childId)) {
        throw new ValidationPlanCompileError('invalid-plan', 'Parallel children must have exactly one execution owner.')
      }
      if ((positionById.get(childId) ?? -1) <= (positionById.get(step.stepId) ?? -1)) {
        throw new ValidationPlanCompileError(
          'dangling-ref',
          'Parallel group children must be declared after their execution owner.'
        )
      }
      // Stateful switches or nested groups cannot share mutable session state.
      if (!['http-request', 'browser-mediated-read', 'passive-analysis'].includes(child.kind)) {
        throw new ValidationPlanCompileError('invalid-plan', 'Parallel groups accept independent read or passive steps only.')
      }
      owners.set(childId, step.stepId)
    }
  }
  const completed = new Set<string>()
  for (const step of plan.steps) {
    if (owners.has(step.stepId)) continue
    const required: string[] = []
    if (step.kind === 'compare') required.push(step.leftStepId, step.rightStepId)
    if (step.kind === 'aggregate') required.push(...step.childStepIds)
    if (step.kind === 'extract-value' || step.kind === 'state-observe') required.push(step.observationStepId)
    if (step.kind === 'callback-poll' || step.kind === 'callback-consume') {
      required.push(step.collectorFromStepId)
      if (byId.get(step.collectorFromStepId)?.kind !== 'callback-register') {
        throw new ValidationPlanCompileError('dangling-ref', 'Callback steps require a callback-register source.')
      }
    }
    if (step.kind === 'cleanup-verify') {
      required.push(step.cleanupStepId)
      if (byId.get(step.cleanupStepId)?.kind !== 'cleanup') {
        throw new ValidationPlanCompileError('dangling-ref', 'Cleanup verification requires a cleanup source.')
      }
    }
    if (required.some((id) => !completed.has(id))) {
      throw new ValidationPlanCompileError('dangling-ref', 'Step dependencies must have completed earlier in the plan.')
    }
    if (step.kind === 'bounded-parallel-group') {
      for (const id of step.childStepIds) completed.add(id)
    }
    completed.add(step.stepId)
  }
}

function inputPlanId(value: string | undefined): string {
  return value ?? randomUUID()
}

function assertKnownSteps(steps: readonly ValidationStep[]): void {
  const ids = new Set(steps.map((step) => step.stepId))
  for (const step of steps) {
    if (!ValidationStepKindSchema.safeParse(step.kind).success) {
      throw new ValidationPlanCompileError(
        'unknown-step',
        'Validation step kind is not in the sealed registry.'
      )
    }
    if (step.kind === 'compare') {
      if (!ids.has(step.leftStepId) || !ids.has(step.rightStepId)) {
        throw new ValidationPlanCompileError(
          'dangling-ref',
          'Compare step references a missing step.'
        )
      }
    }
    if (step.kind === 'extract-value' || step.kind === 'state-observe') {
      if (!ids.has(step.observationStepId) && step.kind === 'state-observe') {
        throw new ValidationPlanCompileError(
          'dangling-ref',
          'State-observe step references a missing observation.'
        )
      }
      if (step.kind === 'extract-value' && !ids.has(step.observationStepId)) {
        throw new ValidationPlanCompileError(
          'dangling-ref',
          'Extract-value step references a missing observation.'
        )
      }
    }
    if (
      (step.kind === 'callback-poll' || step.kind === 'callback-consume') &&
      !ids.has(step.collectorFromStepId)
    ) {
      throw new ValidationPlanCompileError(
        'dangling-ref',
        'Callback step references a missing collector.'
      )
    }
    if (step.kind === 'cleanup-verify' && !ids.has(step.cleanupStepId)) {
      throw new ValidationPlanCompileError(
        'dangling-ref',
        'Cleanup-verify step references a missing cleanup step.'
      )
    }
    if (step.environment !== steps[0]?.environment) {
      throw new ValidationPlanCompileError(
        'environment-mismatch',
        'Validation steps must share one environment.'
      )
    }
  }
}

function assertCapabilities(steps: readonly ValidationStep[]): void {
  const known = new Set(
    DEFAULT_PROBE_CAPABILITY_CATALOG.list().map((descriptor) => descriptor.id)
  )
  for (const step of steps) {
    for (const capabilityId of step.capabilityIds) {
      if (!known.has(capabilityId as CapabilityId)) {
        throw new ValidationPlanCompileError(
          'unknown-capability',
          'Validation step capability is not in the sealed catalog.'
        )
      }
    }
  }
}

function assertBudget(plan: {
  readonly budget: ValidationPlan['budget']
  readonly steps: readonly ValidationStep[]
}): void {
  let requests = 0
  let bytes = 0
  for (const step of plan.steps) {
    requests += step.budget.maxRequests
    bytes += step.budget.maxResponseBytes
    if (
      step.kind === 'http-request' &&
      step.budget.maxRequests < (step.maxRedirects ?? 0) + 1
    ) {
      throw new ValidationPlanCompileError(
        'budget-exceeded',
        'HTTP request budget must include the initial request and every permitted redirect hop.'
      )
    }
    if (step.kind === 'bounded-parallel-group' && step.maxFanOut > plan.budget.maxFanOut) {
      throw new ValidationPlanCompileError(
        'budget-exceeded',
        'Parallel fan-out exceeds the plan maximum.'
      )
    }
  }
  if (requests > plan.budget.maxRequests || bytes > plan.budget.maxBytes) {
    throw new ValidationPlanCompileError(
      'budget-exceeded',
      'Step budgets exceed the compiled plan totals.'
    )
  }
}
