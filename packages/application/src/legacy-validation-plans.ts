import type { SystemIssuedOpaqueId, ValidationPlan } from '@agentgo/contracts'
import { compileValidationPlan, type ValidationPlanDraft } from './validation-plan-compiler'

const STEP_BUDGET = {
  maxRequests: 1,
  maxResponseBytes: 2 * 1024 * 1024,
  timeoutMs: 10_000
} as const

const STOP = ['on-step-failure', 'on-budget-exhausted', 'on-policy-deny'] as const

function base(input: {
  readonly scanId: SystemIssuedOpaqueId
  readonly familyId: 'sqli' | 'xss' | 'ssrf' | 'idor'
  readonly techniqueId: string
}): Pick<
  ValidationPlanDraft,
  | 'scanId'
  | 'familyId'
  | 'techniqueId'
  | 'moduleVersion'
  | 'strategyVersion'
  | 'environment'
  | 'stopConditions'
  | 'budget'
> {
  return {
    scanId: input.scanId,
    familyId: input.familyId,
    techniqueId: input.techniqueId,
    moduleVersion: '1.0.0',
    strategyVersion: '1.0.0',
    environment: 'attested-fixture',
    stopConditions: [...STOP],
    budget: {
      maxRequests: 8,
      maxBytes: 16 * 1024 * 1024,
      maxDurationMs: 60_000,
      maxFanOut: 2
    }
  }
}

function httpStep(input: {
  readonly stepId: string
  readonly familyId: 'sqli' | 'xss' | 'ssrf' | 'idor'
  readonly techniqueId: string
  readonly endpointId: SystemIssuedOpaqueId
  readonly desiredUrl: string
  readonly evidenceRoles: readonly string[]
  readonly identityId?: SystemIssuedOpaqueId
  readonly mutationName?: string
  readonly mutationValue?: string
}): ValidationPlanDraft['steps'][number] {
  return {
    stepId: input.stepId,
    kind: 'http-request',
    familyId: input.familyId,
    techniqueId: input.techniqueId,
    moduleVersion: '1.0.0',
    strategyVersion: '1.0.0',
    subjectRefs: [{ kind: 'endpoint', id: input.endpointId }],
    capabilityIds: ['http.reviewed-read'],
    environment: 'attested-fixture',
    evidenceRoles: [...input.evidenceRoles],
    budget: STEP_BUDGET,
    stopConditions: [...STOP],
    endpointId: input.endpointId,
    desiredUrl: input.desiredUrl,
    purpose: 'read',
    maxRedirects: 0,
    ...(input.identityId ? { identityId: input.identityId } : {}),
    ...(input.mutationName ? { mutationName: input.mutationName } : {}),
    ...(input.mutationValue ? { mutationValue: input.mutationValue } : {})
  }
}

export function compileLegacySqliPlan(input: {
  readonly scanId: SystemIssuedOpaqueId
  readonly endpointId: SystemIssuedOpaqueId
  readonly desiredUrl: string
}): ValidationPlan {
  const familyId = 'sqli' as const
  const techniqueId = 'sqli.boolean-differential'
  return compileValidationPlan({
    ...base({ scanId: input.scanId, familyId, techniqueId }),
    steps: [
      httpStep({
        stepId: 'sqli.baseline',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['baseline']
      }),
      httpStep({
        stepId: 'sqli.true',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['test'],
        mutationName: 'q',
        mutationValue: 'true'
      }),
      httpStep({
        stepId: 'sqli.false',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['negative-control'],
        mutationName: 'q',
        mutationValue: 'false'
      }),
      {
        stepId: 'sqli.compare',
        kind: 'compare',
        familyId,
        techniqueId,
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [],
        capabilityIds: [],
        environment: 'attested-fixture',
        evidenceRoles: [],
        budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
        stopConditions: [...STOP],
        leftStepId: 'sqli.true',
        rightStepId: 'sqli.false',
        comparator: 'body-hash-diff'
      }
    ]
  })
}

export function compileLegacyXssPlan(input: {
  readonly scanId: SystemIssuedOpaqueId
  readonly endpointId: SystemIssuedOpaqueId
  readonly desiredUrl: string
}): ValidationPlan {
  const familyId = 'xss' as const
  const techniqueId = 'xss.reflected-inert-marker'
  return compileValidationPlan({
    ...base({ scanId: input.scanId, familyId, techniqueId }),
    steps: [
      httpStep({
        stepId: 'xss.baseline',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['baseline']
      }),
      httpStep({
        stepId: 'xss.reflection',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['test']
      }),
      {
        stepId: 'xss.offline-verify',
        kind: 'browser-offline-replay',
        familyId,
        techniqueId,
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [{ kind: 'endpoint', id: input.endpointId }],
        capabilityIds: ['browser.offline-replay'],
        environment: 'attested-fixture',
        evidenceRoles: ['browser-observation'],
        budget: STEP_BUDGET,
        stopConditions: [...STOP],
        htmlFromObservationId: 'xss.reflection',
        action: 'verify-xss'
      }
    ]
  })
}

export function compileLegacySsrfPlan(input: {
  readonly scanId: SystemIssuedOpaqueId
  readonly endpointId: SystemIssuedOpaqueId
  readonly desiredUrl: string
}): ValidationPlan {
  const familyId = 'ssrf' as const
  const techniqueId = 'ssrf.controlled-proof-response'
  return compileValidationPlan({
    ...base({ scanId: input.scanId, familyId, techniqueId }),
    steps: [
      {
        stepId: 'ssrf.callback-register',
        kind: 'callback-register',
        familyId,
        techniqueId,
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [],
        capabilityIds: ['oob.controlled-observe'],
        environment: 'attested-fixture',
        evidenceRoles: ['callback-proof'],
        budget: STEP_BUDGET,
        stopConditions: [...STOP],
        tokenSlot: 'ssrf.token'
      },
      httpStep({
        stepId: 'ssrf.primary',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['test']
      }),
      httpStep({
        stepId: 'ssrf.negative',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['negative-control']
      }),
      {
        stepId: 'ssrf.callback-poll',
        kind: 'callback-poll',
        familyId,
        techniqueId,
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [],
        capabilityIds: ['oob.controlled-observe'],
        environment: 'attested-fixture',
        evidenceRoles: ['callback-proof'],
        budget: STEP_BUDGET,
        stopConditions: [...STOP],
        collectorFromStepId: 'ssrf.callback-register'
      }
    ]
  })
}

export function compileLegacyIdorPlan(input: {
  readonly scanId: SystemIssuedOpaqueId
  readonly endpointId: SystemIssuedOpaqueId
  readonly desiredUrl: string
  readonly ownerId: SystemIssuedOpaqueId
  readonly otherId: SystemIssuedOpaqueId
}): ValidationPlan {
  const familyId = 'idor' as const
  const techniqueId = 'idor.two-test-identities-readonly'
  return compileValidationPlan({
    ...base({ scanId: input.scanId, familyId, techniqueId }),
    steps: [
      {
        stepId: 'idor.switch-owner',
        kind: 'identity-switch',
        familyId,
        techniqueId,
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [{ kind: 'identity', id: input.ownerId }],
        capabilityIds: ['http.identity-read-compare'],
        environment: 'attested-fixture',
        evidenceRoles: [],
        budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
        stopConditions: [...STOP],
        identityId: input.ownerId
      },
      httpStep({
        stepId: 'idor.owner',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['owner-baseline'],
        identityId: input.ownerId
      }),
      httpStep({
        stepId: 'idor.second-own',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['second-own-baseline'],
        identityId: input.ownerId
      }),
      {
        stepId: 'idor.switch-other',
        kind: 'identity-switch',
        familyId,
        techniqueId,
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [{ kind: 'identity', id: input.otherId }],
        capabilityIds: ['http.identity-read-compare'],
        environment: 'attested-fixture',
        evidenceRoles: [],
        budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
        stopConditions: [...STOP],
        identityId: input.otherId
      },
      httpStep({
        stepId: 'idor.cross-read',
        familyId,
        techniqueId,
        endpointId: input.endpointId,
        desiredUrl: input.desiredUrl,
        evidenceRoles: ['cross-identity-test'],
        identityId: input.otherId
      }),
      {
        stepId: 'idor.compare',
        kind: 'compare',
        familyId,
        techniqueId,
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [],
        capabilityIds: [],
        environment: 'attested-fixture',
        evidenceRoles: [],
        budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
        stopConditions: [...STOP],
        leftStepId: 'idor.owner',
        rightStepId: 'idor.cross-read',
        comparator: 'identity-visibility'
      }
    ]
  })
}
