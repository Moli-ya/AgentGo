import { randomBytes } from 'node:crypto'
import { issueLoopbackCallbackToken } from './loopback-callback-collector'
import type {
  AuthorizationMatrix,
  Candidate,
  Environment,
  IdentityRecord,
  InventoryEndpoint,
  InventoryReviewStatus
} from '@agentgo/contracts'
import {
  buildInertXssMarkerPayload,
  hashIdentitySessionValue,
  lookupAuthorizationExpectation,
  xssMarkerContextFromParameter
} from '@agentgo/domain'
import { queryValueMutation } from './query-value-mutation'
import { pathValueMutation } from './path-value-mutation'
import { assertNonDestructiveSqliMutation } from './sqli-mutation-gate'
import {
  IDOR_V2_TECHNIQUE_IDS,
  LEGACY_V1_MODULE_VERSIONS,
  LEGACY_V1_TECHNIQUE_IDS,
  SECURITY_HEADERS_MODULE_VERSION,
  SECURITY_HEADERS_TECHNIQUE_IDS,
  SQLI_V2_TECHNIQUE_IDS,
  SSRF_V2_TECHNIQUE_IDS,
  XSS_V2_TECHNIQUE_IDS
} from './vulnerability-bundles'
import {
  controlledCallbackInventoryUrl,
  controlledCallbackTokenParameter
} from './controlled-callback-inventory'
import type { ValidationPlanDraft as CompilerDraft } from './validation-plan-compiler'
import type { ValidationPlanExecution } from './validation-plan-executor'
import {
  assessBola,
  assessIdor,
  assessSecurityHeaders,
  assessSqli,
  assessSqliBoundedTime,
  assessSqliErrorSignal,
  assessSsrf,
  assessSsrfOob,
  assessSsrfReflected,
  assessXss,
  assessXssDomOffline,
  assessXssStored,
  type HttpObservation,
  type ValidationAssessment
} from './validation-engine'

export type { CompilerDraft }

const STOP = ['on-step-failure', 'on-budget-exhausted', 'on-policy-deny'] as const
const HTTP_BUDGET = {
  // One initial request plus up to five independently authorized redirect hops.
  maxRequests: 6,
  maxResponseBytes: 2 * 1024 * 1024,
  timeoutMs: 10_000
} as const
const BROWSER_BUDGET = {
  maxRequests: 1,
  maxResponseBytes: 1024 * 1024,
  timeoutMs: 10_000
} as const
const PLAN_BUDGET = {
  // BOLA can compile eight reviewed reads. Each read reserves its complete
  // redirect chain before any authority is acquired.
  maxRequests: 48,
  maxBytes: 20 * 1024 * 1024,
  maxDurationMs: 60_000,
  maxFanOut: 2
} as const

export interface LegacyParityInventoryUpsert {
  (input: {
    url: string
    sourceType: 'controlled-callback'
  }): Promise<{
    endpoint: InventoryEndpoint
    requestVariant: { reviewStatus: InventoryReviewStatus }
  }>
}

export interface LegacyParityCompileInput {
  readonly scanId: string
  readonly candidate: Candidate
  readonly endpoint: InventoryEndpoint
  readonly identities: readonly IdentityRecord[]
  readonly allowedIdentityIds: readonly string[]
  readonly environment: Environment
  readonly callbackUrl?: string
  readonly upsertReadInventory: LegacyParityInventoryUpsert
  readonly authorizationMatrix?: AuthorizationMatrix
  readonly frozenAssetHtml?: string
  readonly existingResponseHeaders?: Readonly<Record<string, string>>
  readonly callbackCollectorAvailable?: boolean
  readonly callbackCollectorListenUrl?: string
}

export type LegacyParityHold =
  | {
      readonly kind: 'awaiting-user'
      readonly waitFor: 'input' | 'session' | 'approval'
      readonly reason: string
    }
  | { readonly kind: 'inventory-only'; readonly reason: string }
  | { readonly kind: 'forbidden'; readonly reason: string }

export interface LegacyParityObservationRefs {
  readonly baselineStepId: string
  readonly primaryStepId: string
  readonly negativeStepId?: string
}

export interface LegacyParityCompiledPlan {
  readonly kind: 'plan'
  readonly draft: CompilerDraft
  readonly assess: (execution: ValidationPlanExecution) => ValidationAssessment
  readonly observations: LegacyParityObservationRefs
  readonly parameterId?: string
  readonly affectedResource?: string
}

export type LegacyParityCompileResult = LegacyParityCompiledPlan | LegacyParityHold

type HttpFamily = 'sqli' | 'xss' | 'ssrf' | 'idor'

function requireHttp(
  execution: ValidationPlanExecution,
  stepId: string
): HttpObservation {
  const observation = execution.httpByStep.get(stepId)
  if (!observation) {
    throw new Error(`Validation plan omitted HTTP observation ${stepId}.`)
  }
  return observation
}

function httpStep(input: {
  readonly stepId: string
  readonly familyId: HttpFamily
  readonly techniqueId: string
  readonly moduleVersion: string
  readonly environment: Environment
  readonly endpointId: string
  readonly desiredUrl: string
  readonly evidenceRoles: readonly string[]
  readonly identityId?: string
  readonly mutationName?: string
  readonly mutationValue?: string
  readonly mutationKind?: 'query' | 'path'
  readonly mutationSegmentIndex?: number
  readonly summary: string
  readonly payloadSummary?: string
}): CompilerDraft['steps'][number] {
  return {
    stepId: input.stepId,
    kind: 'http-request',
    familyId: input.familyId,
    techniqueId: input.techniqueId,
    moduleVersion: input.moduleVersion,
    strategyVersion: input.moduleVersion,
    subjectRefs: [{ kind: 'endpoint', id: input.endpointId }],
    capabilityIds: ['http.reviewed-read'],
    environment: input.environment,
    evidenceRoles: [...input.evidenceRoles],
    budget: HTTP_BUDGET,
    stopConditions: [...STOP],
    endpointId: input.endpointId,
    desiredUrl: input.desiredUrl,
    purpose: 'read',
    maxRedirects: 5,
    summary: input.summary,
    ...(input.identityId ? { identityId: input.identityId } : {}),
    ...(input.mutationName ? { mutationName: input.mutationName } : {}),
    ...(input.mutationValue !== undefined ? { mutationValue: input.mutationValue } : {}),
    ...(input.mutationKind ? { mutationKind: input.mutationKind } : {}),
    ...(input.mutationSegmentIndex !== undefined
      ? { mutationSegmentIndex: input.mutationSegmentIndex }
      : {}),
    ...(input.payloadSummary ? { payloadSummary: input.payloadSummary } : {})
  }
}

function identityEvidenceSummary(identity: IdentityRecord): string {
  return `identityLabel=${identity.label}; identityHash=${hashIdentitySessionValue({
    identityId: identity.id,
    label: identity.label,
    role: identity.role
  })}`
}

function identitySwitchStep(input: {
  readonly stepId: string
  readonly familyId: HttpFamily
  readonly techniqueId: string
  readonly moduleVersion: string
  readonly environment: Environment
  readonly identity: IdentityRecord
}): CompilerDraft['steps'][number] {
  return {
    stepId: input.stepId,
    kind: 'identity-switch',
    familyId: input.familyId,
    techniqueId: input.techniqueId,
    moduleVersion: input.moduleVersion,
    strategyVersion: input.moduleVersion,
    subjectRefs: [{ kind: 'identity', id: input.identity.id }],
    capabilityIds: ['http.identity-read-compare'],
    environment: input.environment,
    evidenceRoles: [],
    budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
    stopConditions: [...STOP],
    identityId: input.identity.id
  }
}

function requireParameter(input: LegacyParityCompileInput): InventoryEndpoint['parameters'][number] {
  const parameterId = input.candidate.parameterId
  const parameter = input.endpoint.parameters.find((item) => item.id === parameterId)
  if (!parameter) {
    throw new Error('Legacy parity adapter requires a reviewed parameter.')
  }
  return parameter
}

function selectorSampleValue(
  parameter: InventoryEndpoint['parameters'][number],
  endpointUrl: string
): string {
  const url = new URL(endpointUrl)
  if (parameter.location === 'query') {
    return url.searchParams.get(parameter.name) ?? ''
  }
  if (parameter.location === 'path') {
    const parts = url.pathname.split('/').filter(Boolean)
    try {
      return decodeURIComponent(parts.at(-1) ?? '')
    } catch {
      return parts.at(-1) ?? ''
    }
  }
  return ''
}

function sqliBooleanValues(parameter: InventoryEndpoint['parameters'][number], endpointUrl: string) {
  const redactedValue = selectorSampleValue(parameter, endpointUrl)
  const numeric =
    parameter.dataType === 'number' ||
    parameter.dataType === 'integer' ||
    /^-?\d+(?:\.\d+)?$/u.test(redactedValue)
  const original = numeric ? '1' : 'agentgo'
  const trueValue = numeric ? `${original} AND 1=1` : `${original}' AND '1'='1`
  const falseValue = numeric ? `${original} AND 1=2` : `${original}' AND '1'='2`
  assertNonDestructiveSqliMutation(trueValue)
  assertNonDestructiveSqliMutation(falseValue)
  return { trueValue, falseValue }
}

function compileSqliBooleanPlan(
  input: LegacyParityCompileInput,
  parameter: InventoryEndpoint['parameters'][number],
  trueMutation: { desiredUrl: string },
  falseMutation: { desiredUrl: string },
  trueValue: string,
  falseValue: string,
  mutationKind: 'query' | 'path',
  mutationSegmentIndex?: number
): LegacyParityCompiledPlan {
  const familyId = 'sqli' as const
  const techniqueId = SQLI_V2_TECHNIQUE_IDS.booleanDifferential
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.sqli
  const identityId = input.identities[0]?.id
  const mutationFields = {
    mutationName: parameter.name,
    mutationKind,
    ...(mutationSegmentIndex !== undefined ? { mutationSegmentIndex } : {})
  } as const
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'sqli.baseline',
      primaryStepId: 'sqli.true',
      negativeStepId: 'sqli.false'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        httpStep({
          stepId: 'sqli.baseline',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: input.endpoint.url,
          evidenceRoles: ['baseline'],
          summary: 'SQLi 只读差异验证：获取基线响应。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.true',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: trueMutation.desiredUrl,
          evidenceRoles: ['test'],
          ...mutationFields,
          mutationValue: trueValue,
          summary: 'SQLi 只读布尔真条件差异验证。',
          payloadSummary: '非写入式布尔真条件；不读取业务数据。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.false',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: falseMutation.desiredUrl,
          evidenceRoles: ['negative-control'],
          ...mutationFields,
          mutationValue: falseValue,
          summary: 'SQLi 只读布尔负对照。',
          payloadSummary: '非写入式布尔假条件；不读取业务数据。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.repeat',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: trueMutation.desiredUrl,
          evidenceRoles: ['repeat'],
          ...mutationFields,
          mutationValue: trueValue,
          summary: 'SQLi 只读布尔真条件重复验证。',
          payloadSummary: '重复非写入式布尔真条件。',
          ...(identityId ? { identityId } : {})
        })
      ]
    },
    assess: (execution) =>
      assessSqli({
        baseline: requireHttp(execution, 'sqli.baseline'),
        trueFirst: requireHttp(execution, 'sqli.true'),
        falseControl: requireHttp(execution, 'sqli.false'),
        trueRepeat: requireHttp(execution, 'sqli.repeat')
      })
  }
}

function compileSqli(input: LegacyParityCompileInput): LegacyParityCompileResult {
  const parameter = requireParameter(input)
  if (parameter.location === 'header' || parameter.location === 'cookie') {
    return {
      kind: 'inventory-only',
      reason: 'Header and cookie selectors remain inventory-only for SQLi V2.'
    }
  }
  if (parameter.location === 'form' || parameter.location === 'json') {
    return {
      kind: 'awaiting-user',
      waitFor: 'approval',
      reason: 'Form and JSON Pointer SQLi requires an approved L2 test object.'
    }
  }
  const { trueValue, falseValue } = sqliBooleanValues(parameter, input.endpoint.url)
  if (parameter.location === 'path') {
    const trueMutation = pathValueMutation(input.endpoint.url, parameter.name, trueValue)
    const falseMutation = pathValueMutation(input.endpoint.url, parameter.name, falseValue)
    return compileSqliBooleanPlan(
      input,
      parameter,
      trueMutation,
      falseMutation,
      trueValue,
      falseValue,
      'path',
      trueMutation.mutation.segmentIndex
    )
  }
  const trueMutation = queryValueMutation(input.endpoint.url, parameter.name, trueValue)
  const falseMutation = queryValueMutation(input.endpoint.url, parameter.name, falseValue)
  return compileSqliBooleanPlan(
    input,
    parameter,
    trueMutation,
    falseMutation,
    trueValue,
    falseValue,
    'query'
  )
}

function compileSqliErrorSignal(input: LegacyParityCompileInput): LegacyParityCompileResult {
  const parameter = requireParameter(input)
  if (parameter.location !== 'query' && parameter.location !== 'path') {
    return {
      kind: 'inventory-only',
      reason: 'Error-signal SQLi only executes reviewed query/path selectors.'
    }
  }
  const errorValue = "1'"
  const negativeValue = '1'
  assertNonDestructiveSqliMutation(errorValue)
  assertNonDestructiveSqliMutation(negativeValue)
  const errorMutation =
    parameter.location === 'path'
      ? pathValueMutation(input.endpoint.url, parameter.name, errorValue)
      : queryValueMutation(input.endpoint.url, parameter.name, errorValue)
  const negativeMutation =
    parameter.location === 'path'
      ? pathValueMutation(input.endpoint.url, parameter.name, negativeValue)
      : queryValueMutation(input.endpoint.url, parameter.name, negativeValue)
  const familyId = 'sqli' as const
  const techniqueId = SQLI_V2_TECHNIQUE_IDS.errorSignal
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.sqli
  const identityId = input.identities[0]?.id
  const mutationKind = parameter.location === 'path' ? 'path' : 'query'
  const mutationSegmentIndex =
    errorMutation.mutation.kind === 'path' ? errorMutation.mutation.segmentIndex : undefined
  const mutationFields = {
    mutationName: parameter.name,
    mutationKind,
    ...(mutationSegmentIndex !== undefined ? { mutationSegmentIndex } : {})
  } as const
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'sqli.error.baseline',
      primaryStepId: 'sqli.error.test',
      negativeStepId: 'sqli.error.negative'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        httpStep({
          stepId: 'sqli.error.baseline',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: input.endpoint.url,
          evidenceRoles: ['baseline'],
          summary: 'SQLi 错误信号：获取基线响应。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.error.test',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: errorMutation.desiredUrl,
          evidenceRoles: ['test'],
          ...mutationFields,
          mutationValue: errorValue,
          summary: 'SQLi 受限错误信号探测。',
          payloadSummary: '非写入式引号破裂；不读取业务数据。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.error.negative',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: negativeMutation.desiredUrl,
          evidenceRoles: ['negative-control'],
          ...mutationFields,
          mutationValue: negativeValue,
          summary: 'SQLi 错误信号负对照。',
          payloadSummary: '无引号破裂的对照值。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.error.repeat',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: errorMutation.desiredUrl,
          evidenceRoles: ['repeat'],
          ...mutationFields,
          mutationValue: errorValue,
          summary: 'SQLi 错误信号重复验证。',
          payloadSummary: '重复非写入式引号破裂。',
          ...(identityId ? { identityId } : {})
        })
      ]
    },
    assess: (execution) =>
      assessSqliErrorSignal({
        baseline: requireHttp(execution, 'sqli.error.baseline'),
        errorFirst: requireHttp(execution, 'sqli.error.test'),
        negativeControl: requireHttp(execution, 'sqli.error.negative'),
        errorRepeat: requireHttp(execution, 'sqli.error.repeat')
      })
  }
}

function compileSqliBoundedTime(input: LegacyParityCompileInput): LegacyParityCompileResult {
  if (input.environment !== 'attested-fixture') {
    return {
      kind: 'forbidden',
      reason: 'Bounded-time SQLi is fixture-only for the current window.'
    }
  }
  const parameter = requireParameter(input)
  if (parameter.location !== 'query') {
    return {
      kind: 'inventory-only',
      reason: 'Bounded-time SQLi only executes reviewed query selectors.'
    }
  }
  const delayedValue = '1 AND SLEEP(2)'
  const negativeValue = '1 AND SLEEP(0)'
  assertNonDestructiveSqliMutation(delayedValue)
  assertNonDestructiveSqliMutation(negativeValue)
  const delayedMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    delayedValue
  )
  const negativeMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    negativeValue
  )
  const familyId = 'sqli' as const
  const techniqueId = SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.sqli
  const identityId = input.identities[0]?.id
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'sqli.time.baseline',
      primaryStepId: 'sqli.time.test',
      negativeStepId: 'sqli.time.negative'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        httpStep({
          stepId: 'sqli.time.baseline',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: input.endpoint.url,
          evidenceRoles: ['baseline'],
          summary: 'SQLi 有界时间差异：获取基线响应。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.time.test',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: delayedMutation.desiredUrl,
          evidenceRoles: ['test'],
          mutationName: parameter.name,
          mutationValue: delayedValue,
          summary: 'SQLi 有界 SLEEP 真条件。',
          payloadSummary: '非写入式有界 SLEEP(2)；不读取业务数据。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.time.negative',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: negativeMutation.desiredUrl,
          evidenceRoles: ['negative-control'],
          mutationName: parameter.name,
          mutationValue: negativeValue,
          summary: 'SQLi 有界时间负对照。',
          payloadSummary: '非写入式 SLEEP(0) 负对照。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'sqli.time.repeat',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: delayedMutation.desiredUrl,
          evidenceRoles: ['repeat'],
          mutationName: parameter.name,
          mutationValue: delayedValue,
          summary: 'SQLi 有界时间重复验证。',
          payloadSummary: '重复非写入式有界 SLEEP(2)。',
          ...(identityId ? { identityId } : {})
        })
      ]
    },
    assess: (execution) =>
      assessSqliBoundedTime({
        baseline: requireHttp(execution, 'sqli.time.baseline'),
        delayedFirst: requireHttp(execution, 'sqli.time.test'),
        negativeControl: requireHttp(execution, 'sqli.time.negative'),
        delayedRepeat: requireHttp(execution, 'sqli.time.repeat')
      })
  }
}

function encodedXssControl(payload: string): string {
  return payload
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function compileXss(input: LegacyParityCompileInput): LegacyParityCompileResult {
  const parameter = requireParameter(input)
  if (parameter.location === 'header' || parameter.location === 'cookie') {
    return {
      kind: 'inventory-only',
      reason: 'Header and cookie XSS selectors remain inventory-only.'
    }
  }
  if (parameter.location === 'form' || parameter.location === 'json') {
    return {
      kind: 'awaiting-user',
      waitFor: 'approval',
      reason: 'Stored XSS requires an approved L2 test object and cleanup.'
    }
  }
  const familyId = 'xss' as const
  const techniqueId = LEGACY_V1_TECHNIQUE_IDS.xss
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.xss
  const identity = input.identities[0]
  const xssMarker = `agx_${randomBytes(16).toString('hex')}`
  const context = xssMarkerContextFromParameter(parameter.name)
  const payload = buildInertXssMarkerPayload(xssMarker, context)
  const encodedPayload = encodedXssControl(payload)
  const reflection =
    parameter.location === 'path'
      ? pathValueMutation(input.endpoint.url, parameter.name, payload)
      : queryValueMutation(input.endpoint.url, parameter.name, payload)
  const encoded =
    parameter.location === 'path'
      ? pathValueMutation(input.endpoint.url, parameter.name, encodedPayload)
      : queryValueMutation(input.endpoint.url, parameter.name, encodedPayload)
  const mutationKind = parameter.location === 'path' ? 'path' : 'query'
  const reflectionSegment =
    reflection.mutation.kind === 'path' ? reflection.mutation.segmentIndex : undefined
  const identityId = identity?.id
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'xss.baseline',
      primaryStepId: 'xss.reflection',
      negativeStepId: 'xss.encoded-negative'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        httpStep({
          stepId: 'xss.baseline',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: input.endpoint.url,
          evidenceRoles: ['baseline'],
          summary: 'XSS 验证：获取未注入标记的基线响应。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'xss.reflection',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: reflection.desiredUrl,
          evidenceRoles: ['test'],
          mutationName: parameter.name,
          mutationValue: payload,
          mutationKind,
          ...(reflectionSegment !== undefined
            ? { mutationSegmentIndex: reflectionSegment }
            : {}),
          summary: 'XSS 随机惰性标记反射验证。',
          payloadSummary: `无外传能力的隔离执行标记 ${xssMarker}。`,
          ...(identityId ? { identityId } : {})
        }),
        {
          stepId: 'xss.offline-verify',
          kind: 'browser-offline-replay',
          familyId,
          techniqueId,
          moduleVersion,
          strategyVersion: moduleVersion,
          subjectRefs: [{ kind: 'endpoint', id: input.endpoint.id }],
          capabilityIds: ['browser.offline-replay'],
          environment: input.environment,
          evidenceRoles: ['browser-observation'],
          budget: BROWSER_BUDGET,
          stopConditions: [...STOP],
          htmlFromObservationId: 'xss.reflection',
          action: 'verify-xss',
          marker: xssMarker,
          baseUrl: reflection.desiredUrl,
          summary: '在断网隔离浏览器中验证随机惰性 XSS 标记。',
          payloadSummary: `仅设置本地 DOM 属性的标记 ${xssMarker}。`
        },
        httpStep({
          stepId: 'xss.encoded-negative',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: encoded.desiredUrl,
          evidenceRoles: ['negative-control'],
          mutationName: parameter.name,
          mutationValue: encodedPayload,
          mutationKind,
          ...(reflectionSegment !== undefined
            ? { mutationSegmentIndex: reflectionSegment }
            : {}),
          summary: 'XSS 正确编码负对照。',
          payloadSummary: '上下文编码后的惰性标记，不得作为执行证明。',
          ...(identityId ? { identityId } : {})
        })
      ]
    },
    assess: (execution) => {
      const http = requireHttp(execution, 'xss.reflection')
      const browser = execution.browserByStep.get('xss.offline-verify')
      return assessXss({
        marker: xssMarker,
        http,
        ...(browser ? { browser } : {})
      })
    }
  }
}

async function compileSsrf(
  input: LegacyParityCompileInput
): Promise<LegacyParityCompileResult> {
  const parameter = requireParameter(input)
  const callbackUrl = input.callbackUrl
  if (!callbackUrl) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: '扫描未配置受控回调 URL，SSRF 只能标记为未具备验证条件。'
    }
  }
  const familyId = 'ssrf' as const
  const techniqueId = LEGACY_V1_TECHNIQUE_IDS.ssrf
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.ssrf
  const identity = input.identities[0]
  const callbackTemplateUrl = controlledCallbackInventoryUrl(callbackUrl)
  const callbackInventory = await input.upsertReadInventory({
    url: callbackTemplateUrl,
    sourceType: 'controlled-callback'
  })
  if (callbackInventory.requestVariant.reviewStatus !== 'reviewed') {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason:
        'The controlled SSRF callback request variant must be inventoried and reviewed before execution.'
    }
  }
  const token = randomBytes(12).toString('hex')
  const tokenParameter = controlledCallbackTokenParameter()
  const callbackMutation = queryValueMutation(callbackTemplateUrl, tokenParameter, token)
  const primaryMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    callbackMutation.desiredUrl
  )
  const negativeMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    'agentgo-invalid-url'
  )
  const identityId = identity?.id
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'ssrf.callback-read',
      primaryStepId: 'ssrf.primary',
      negativeStepId: 'ssrf.negative'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        httpStep({
          stepId: 'ssrf.callback-read',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: callbackInventory.endpoint.id,
          desiredUrl: callbackMutation.desiredUrl,
          evidenceRoles: ['callback-proof'],
          mutationName: tokenParameter,
          mutationValue: token,
          summary: '读取明确授权的受控 SSRF 回调证明。'
        }),
        httpStep({
          stepId: 'ssrf.primary',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: primaryMutation.desiredUrl,
          evidenceRoles: ['test'],
          mutationName: parameter.name,
          mutationValue: callbackMutation.desiredUrl,
          summary: 'SSRF 受控回调 URL 只读验证。',
          payloadSummary: '仅访问已列入 Scope 的项目控制回调端点。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'ssrf.negative',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: negativeMutation.desiredUrl,
          evidenceRoles: ['negative-control'],
          mutationName: parameter.name,
          mutationValue: 'agentgo-invalid-url',
          summary: 'SSRF 非 URL 负对照。',
          payloadSummary: '不触发网络访问的无效 URL 文本。',
          ...(identityId ? { identityId } : {})
        })
      ]
    },
    assess: (execution) =>
      assessSsrf({
        callbackBaseline: requireHttp(execution, 'ssrf.callback-read'),
        targetProbe: requireHttp(execution, 'ssrf.primary'),
        negativeControl: requireHttp(execution, 'ssrf.negative')
      })
  }
}

async function compileSsrfReflected(
  input: LegacyParityCompileInput
): Promise<LegacyParityCompileResult> {
  const parameter = requireParameter(input)
  const callbackUrl = input.callbackUrl
  if (!callbackUrl) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: '扫描未配置受控回调 URL，SSRF 回显只能标记为未具备验证条件。'
    }
  }
  const familyId = 'ssrf' as const
  const techniqueId = SSRF_V2_TECHNIQUE_IDS.reflectedProof
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.ssrf
  const identity = input.identities[0]
  const callbackTemplateUrl = controlledCallbackInventoryUrl(callbackUrl)
  const callbackInventory = await input.upsertReadInventory({
    url: callbackTemplateUrl,
    sourceType: 'controlled-callback'
  })
  if (callbackInventory.requestVariant.reviewStatus !== 'reviewed') {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason:
        'The controlled SSRF callback request variant must be inventoried and reviewed before execution.'
    }
  }
  const token = randomBytes(12).toString('hex')
  const tokenParameter = controlledCallbackTokenParameter()
  const callbackMutation = queryValueMutation(callbackTemplateUrl, tokenParameter, token)
  const baselineMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    'agentgo-invalid-url'
  )
  const primaryMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    callbackMutation.desiredUrl
  )
  const negativeMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    'agentgo-invalid-url'
  )
  const identityId = identity?.id
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'ssrf.reflected.baseline',
      primaryStepId: 'ssrf.reflected.primary',
      negativeStepId: 'ssrf.reflected.negative'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        httpStep({
          stepId: 'ssrf.reflected.baseline',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: baselineMutation.desiredUrl,
          evidenceRoles: ['baseline'],
          mutationName: parameter.name,
          mutationValue: 'agentgo-invalid-url',
          summary: 'SSRF 回显基线，不触发受控目的地。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'ssrf.reflected.primary',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: primaryMutation.desiredUrl,
          evidenceRoles: ['test'],
          mutationName: parameter.name,
          mutationValue: callbackMutation.desiredUrl,
          summary: 'SSRF 回显受控目的地只读验证。',
          payloadSummary: '仅访问已列入 Scope 的项目控制回调端点。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'ssrf.reflected.negative',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: negativeMutation.desiredUrl,
          evidenceRoles: ['negative-control'],
          mutationName: parameter.name,
          mutationValue: 'agentgo-invalid-url',
          summary: 'SSRF 回显负对照。',
          ...(identityId ? { identityId } : {})
        })
      ]
    },
    assess: (execution) => {
      const targetProbe = requireHttp(execution, 'ssrf.reflected.primary')
      const policyError = targetProbe.result.errorCode ?? ''
      return assessSsrfReflected({
        baseline: requireHttp(execution, 'ssrf.reflected.baseline'),
        targetProbe,
        negativeControl: requireHttp(execution, 'ssrf.reflected.negative'),
        destinationInScope: !/network-address-blocked|network-target-not-authorized|out-of-scope|url-canonicalization/i.test(
          policyError
        ),
        redirectPolicyEnforced: !/redirect-follow|dns-rebinding/i.test(policyError)
      })
    }
  }
}

function compileSsrfOob(input: LegacyParityCompileInput): LegacyParityCompileResult {
  if (input.environment !== 'attested-fixture' || !input.callbackCollectorAvailable) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason:
        'OOB SSRF 需要 loopback Collector。远程生产 Collector 协议已定义但状态为 not-run，不得用 mock 冒充。'
    }
  }
  const listenUrl = input.callbackCollectorListenUrl
  if (!listenUrl) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: 'OOB SSRF 需要已监听的 loopback Collector URL，不能用 fixture /callback 冒充 Collector 事件。'
    }
  }
  const parameter = requireParameter(input)
  const familyId = 'ssrf' as const
  const techniqueId = SSRF_V2_TECHNIQUE_IDS.oobCallback
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.ssrf
  const token = issueLoopbackCallbackToken()
  const tokenParameter = controlledCallbackTokenParameter()
  const collectorCallbackUrl = new URL('/callback', listenUrl).toString()
  const destination = queryValueMutation(
    controlledCallbackInventoryUrl(collectorCallbackUrl),
    tokenParameter,
    token
  )
  const primaryMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    destination.desiredUrl
  )
  const negativeMutation = queryValueMutation(
    input.endpoint.url,
    parameter.name,
    'agentgo-invalid-url'
  )
  const identityId = input.identities[0]?.id
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'ssrf.oob.primary',
      primaryStepId: 'ssrf.oob.primary',
      negativeStepId: 'ssrf.oob.negative'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        {
          stepId: 'ssrf.oob.register',
          kind: 'callback-register' as const,
          familyId,
          techniqueId,
          moduleVersion,
          strategyVersion: moduleVersion,
          subjectRefs: [{ kind: 'endpoint' as const, id: input.endpoint.id }],
          capabilityIds: [],
          environment: input.environment,
          evidenceRoles: ['callback-proof'],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
          stopConditions: [...STOP],
          tokenSlot: token
        },
        httpStep({
          stepId: 'ssrf.oob.primary',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: primaryMutation.desiredUrl,
          evidenceRoles: ['test'],
          mutationName: parameter.name,
          mutationValue: destination.desiredUrl,
          summary: '向目标注入 loopback Collector URL。',
          payloadSummary: '仅访问项目控制的 loopback Collector。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'ssrf.oob.negative',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: negativeMutation.desiredUrl,
          evidenceRoles: ['negative-control'],
          mutationName: parameter.name,
          mutationValue: 'agentgo-invalid-url',
          summary: 'OOB 负对照，不触发回连。',
          ...(identityId ? { identityId } : {})
        }),
        {
          stepId: 'ssrf.oob.poll',
          kind: 'callback-poll' as const,
          familyId,
          techniqueId,
          moduleVersion,
          strategyVersion: moduleVersion,
          subjectRefs: [{ kind: 'endpoint' as const, id: input.endpoint.id }],
          capabilityIds: [],
          environment: input.environment,
          evidenceRoles: ['callback-proof'],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 3_000 },
          stopConditions: [...STOP],
          collectorFromStepId: 'ssrf.oob.register'
        },
        {
          stepId: 'ssrf.oob.consume',
          kind: 'callback-consume' as const,
          familyId,
          techniqueId,
          moduleVersion,
          strategyVersion: moduleVersion,
          subjectRefs: [{ kind: 'endpoint' as const, id: input.endpoint.id }],
          capabilityIds: [],
          environment: input.environment,
          evidenceRoles: ['callback-proof'],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
          stopConditions: [...STOP],
          collectorFromStepId: 'ssrf.oob.register'
        }
      ]
    },
    assess: (execution) => {
      const consumed = execution.callbackByStep.get('ssrf.oob.consume')
      const polled = execution.callbackByStep.get('ssrf.oob.poll')
      const primary = requireHttp(execution, 'ssrf.oob.primary')
      const sourceKind = consumed?.sourceKind ?? polled?.sourceKind
      const primaryBody = Buffer.from(primary.result.responseBody ?? []).toString('utf8')
      const collectorUnreachable =
        primary.result.status !== 'succeeded' ||
        primary.result.statusCode === 504 ||
        /waf|timeout/i.test(primary.result.errorCode ?? '') ||
        /collector down/i.test(primaryBody)
      return assessSsrfOob({
        serverSideEvent: Boolean(consumed?.observation) && sourceKind !== 'browser',
        clientOrBrokerOrHealth:
          sourceKind === 'browser' ||
          sourceKind === 'broker' ||
          sourceKind === 'health-check' ||
          Boolean(polled?.clientOrBrokerOrHealth) ||
          Boolean(consumed?.clientOrBrokerOrHealth),
        staleOrReplay:
          sourceKind === 'replay' ||
          sourceKind === 'expired' ||
          Boolean(polled?.staleOrReplay) ||
          Boolean(consumed?.staleOrReplay),
        tokenBound: Boolean(consumed?.observation),
        negativeHasEvent: false,
        collectorAvailable: true,
        timedOutOrWaf: collectorUnreachable && !consumed?.observation
      })
    }
  }
}

function compileSecurityHeaders(
  input: LegacyParityCompileInput
): LegacyParityCompileResult {
  const headers = input.existingResponseHeaders
  if (!headers || Object.keys(headers).length === 0) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: '没有既有响应头可供 security.headers.baseline 分析，不能新增网络请求。'
    }
  }
  const familyId = 'security.headers'
  const techniqueId = SECURITY_HEADERS_TECHNIQUE_IDS.baseline
  const moduleVersion = SECURITY_HEADERS_MODULE_VERSION
  let https = false
  try {
    https = new URL(input.endpoint.url).protocol === 'https:'
  } catch {
    https = false
  }
  return {
    kind: 'plan',
    observations: {
      baselineStepId: 'headers.baseline.analyze',
      primaryStepId: 'headers.baseline.analyze'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: {
        maxRequests: 0,
        maxBytes: 1,
        maxDurationMs: 5_000,
        maxFanOut: 1
      },
      steps: [
        {
          stepId: 'headers.baseline.analyze',
          kind: 'passive-analysis' as const,
          familyId,
          techniqueId,
          moduleVersion,
          strategyVersion: moduleVersion,
          subjectRefs: [{ kind: 'endpoint' as const, id: input.endpoint.id }],
          capabilityIds: [],
          environment: input.environment,
          evidenceRoles: ['response-headers'],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
          stopConditions: [...STOP]
        }
      ]
    },
    assess: (execution) =>
      assessSecurityHeaders({
        headers,
        newRequestCount: execution.requestCount,
        https
      })
  }
}

function compileIdor(input: LegacyParityCompileInput): LegacyParityCompileResult {
  const parameter = requireParameter(input)
  if (parameter.location === 'header' || parameter.location === 'cookie') {
    return {
      kind: 'inventory-only',
      reason: 'Header and cookie IDOR selectors remain inventory-only.'
    }
  }
  if (parameter.location === 'form' || parameter.location === 'json') {
    return {
      kind: 'awaiting-user',
      waitFor: 'approval',
      reason: 'Write-style IDOR remains signal or L2 fixture-only and is not executed as L1.'
    }
  }
  if (input.identities.length < 2) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: 'IDOR 只读对照至少需要两个授权测试身份。'
    }
  }
  const owner = input.identities.find((item) => item.ownedResourceIds.length > 0)
  const second = input.identities.find(
    (item) => item.id !== owner?.id && item.ownedResourceIds.length > 0
  )
  if (!owner || !second) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: '两个测试身份都必须配置已知归属资源 ID。'
    }
  }
  const ownerResourceId = owner.ownedResourceIds[0]!
  const secondResourceId = second.ownedResourceIds[0]!
  const ownerMutation =
    parameter.location === 'path'
      ? pathValueMutation(input.endpoint.url, parameter.name, ownerResourceId)
      : queryValueMutation(input.endpoint.url, parameter.name, ownerResourceId)
  const secondMutation =
    parameter.location === 'path'
      ? pathValueMutation(input.endpoint.url, parameter.name, secondResourceId)
      : queryValueMutation(input.endpoint.url, parameter.name, secondResourceId)
  const familyId = 'idor' as const
  const techniqueId = LEGACY_V1_TECHNIQUE_IDS.idor
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.idor
  const mutationKind = parameter.location === 'path' ? 'path' : 'query'
  const ownerSegment =
    ownerMutation.mutation.kind === 'path' ? ownerMutation.mutation.segmentIndex : undefined
  return {
    kind: 'plan',
    parameterId: parameter.id,
    affectedResource: ownerResourceId,
    observations: {
      baselineStepId: 'idor.owner',
      primaryStepId: 'idor.cross-read',
      negativeStepId: 'idor.second-own'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        identitySwitchStep({
          stepId: 'idor.switch-owner',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          identity: owner
        }),
        httpStep({
          stepId: 'idor.owner',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: ownerMutation.desiredUrl,
          evidenceRoles: ['owner-baseline'],
          mutationName: parameter.name,
          mutationValue: ownerResourceId,
          mutationKind,
          ...(ownerSegment !== undefined ? { mutationSegmentIndex: ownerSegment } : {}),
          identityId: owner.id,
          summary: 'IDOR 对照：资源所有者只读访问自己的测试资源。',
          payloadSummary: identityEvidenceSummary(owner)
        }),
        identitySwitchStep({
          stepId: 'idor.switch-second',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          identity: second
        }),
        httpStep({
          stepId: 'idor.second-own',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: secondMutation.desiredUrl,
          evidenceRoles: ['second-own-baseline'],
          mutationName: parameter.name,
          mutationValue: secondResourceId,
          mutationKind,
          ...(ownerSegment !== undefined ? { mutationSegmentIndex: ownerSegment } : {}),
          identityId: second.id,
          summary: 'IDOR 负对照：第二身份只读访问自己的测试资源。',
          payloadSummary: identityEvidenceSummary(second)
        }),
        httpStep({
          stepId: 'idor.cross-read',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: ownerMutation.desiredUrl,
          evidenceRoles: ['cross-identity-test'],
          mutationName: parameter.name,
          mutationValue: ownerResourceId,
          mutationKind,
          ...(ownerSegment !== undefined ? { mutationSegmentIndex: ownerSegment } : {}),
          identityId: second.id,
          summary: 'IDOR 对照：第二身份只读访问第一身份的已知测试资源。',
          payloadSummary: identityEvidenceSummary(second)
        })
      ]
    },
    assess: (execution) =>
      assessIdor({
        ownerResourceId,
        secondIdentityResourceId: secondResourceId,
        ownerRead: requireHttp(execution, 'idor.owner'),
        secondIdentityOwnRead: requireHttp(execution, 'idor.second-own'),
        secondIdentityOwnerRead: requireHttp(execution, 'idor.cross-read'),
        identitiesAuthorized:
          owner.isTestIdentity &&
          second.isTestIdentity &&
          input.allowedIdentityIds.includes(owner.id) &&
          input.allowedIdentityIds.includes(second.id)
      })
  }
}

function mutateResourceUrl(
  endpointUrl: string,
  parameter: InventoryEndpoint['parameters'][number],
  value: string
) {
  return parameter.location === 'path'
    ? pathValueMutation(endpointUrl, parameter.name, value)
    : queryValueMutation(endpointUrl, parameter.name, value)
}

function compileBola(input: LegacyParityCompileInput): LegacyParityCompileResult {
  const parameter = requireParameter(input)
  if (parameter.location === 'header' || parameter.location === 'cookie') {
    return {
      kind: 'inventory-only',
      reason: 'Header and cookie BOLA selectors remain inventory-only.'
    }
  }
  if (parameter.location === 'form' || parameter.location === 'json') {
    return {
      kind: 'awaiting-user',
      waitFor: 'approval',
      reason: 'Write-style BOLA remains signal or dedicated fixture L2.'
    }
  }
  if (input.identities.length < 2) {
    return {
      kind: 'awaiting-user',
      waitFor: 'session',
      reason: 'BOLA 只读矩阵至少需要两个授权测试身份。'
    }
  }
  const owner = input.identities.find((item) => item.ownedResourceIds.length > 0)
  const second = input.identities.find(
    (item) => item.id !== owner?.id && item.ownedResourceIds.length > 0
  )
  if (!owner || !second) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: '未知归属：两个测试身份都必须配置已知归属资源 ID。'
    }
  }
  const matrix = input.authorizationMatrix
  if (!matrix) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: 'AuthorizationMatrix is required before BOLA read-differential execution.'
    }
  }
  const ownerResourceId = owner.ownedResourceIds[0]!
  const secondResourceId = second.ownedResourceIds[0]!
  const crossEntry = lookupAuthorizationExpectation(matrix, {
    subjectIdentityId: second.id,
    resourceRef: ownerResourceId,
    operation: 'read'
  })
  if (!crossEntry) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: 'The authorization matrix has no entry for this subject, resource, and operation.'
    }
  }
  const familyId = 'idor' as const
  const techniqueId = IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.idor
  const ownerMutation = mutateResourceUrl(input.endpoint.url, parameter, ownerResourceId)
  const secondMutation = mutateResourceUrl(input.endpoint.url, parameter, secondResourceId)
  const mutationKind = parameter.location === 'path' ? 'path' : 'query'
  const segmentIndex =
    ownerMutation.mutation.kind === 'path' ? ownerMutation.mutation.segmentIndex : undefined
  const publicIdentity = input.identities.find((item) => item.role === 'public')
  const sharedIdentity = input.identities.find((item) => item.role === 'shared')
  const adminIdentity = input.identities.find((item) => item.role === 'admin')
  const tenantIdentity = input.identities.find((item) => item.role === 'tenant-b')
  const parentResourceId = owner.ownedResourceIds[1]
  const steps: CompilerDraft['steps'] = [
    identitySwitchStep({
      stepId: 'bola.switch-owner',
      familyId,
      techniqueId,
      moduleVersion,
      environment: input.environment,
      identity: owner
    }),
    httpStep({
      stepId: 'bola.owner',
      familyId,
      techniqueId,
      moduleVersion,
      environment: input.environment,
      endpointId: input.endpoint.id,
      desiredUrl: ownerMutation.desiredUrl,
      evidenceRoles: ['owner-baseline'],
      mutationName: parameter.name,
      mutationValue: ownerResourceId,
      mutationKind,
      ...(segmentIndex !== undefined ? { mutationSegmentIndex: segmentIndex } : {}),
      identityId: owner.id,
      summary: 'BOLA：所有者读取已知测试对象。',
      payloadSummary: identityEvidenceSummary(owner)
    }),
    identitySwitchStep({
      stepId: 'bola.switch-second',
      familyId,
      techniqueId,
      moduleVersion,
      environment: input.environment,
      identity: second
    }),
    httpStep({
      stepId: 'bola.second-own',
      familyId,
      techniqueId,
      moduleVersion,
      environment: input.environment,
      endpointId: input.endpoint.id,
      desiredUrl: secondMutation.desiredUrl,
      evidenceRoles: ['second-own-baseline'],
      mutationName: parameter.name,
      mutationValue: secondResourceId,
      mutationKind,
      ...(segmentIndex !== undefined ? { mutationSegmentIndex: segmentIndex } : {}),
      identityId: second.id,
      summary: 'BOLA：第二身份读取自己的测试对象。',
      payloadSummary: identityEvidenceSummary(second)
    }),
    httpStep({
      stepId: 'bola.cross-read',
      familyId,
      techniqueId,
      moduleVersion,
      environment: input.environment,
      endpointId: input.endpoint.id,
      desiredUrl: ownerMutation.desiredUrl,
      evidenceRoles: ['cross-identity-test'],
      mutationName: parameter.name,
      mutationValue: ownerResourceId,
      mutationKind,
      ...(segmentIndex !== undefined ? { mutationSegmentIndex: segmentIndex } : {}),
      identityId: second.id,
      summary: 'BOLA：第二身份读取所有者测试对象。',
      payloadSummary: identityEvidenceSummary(second)
    })
  ]
  const addControl = (
    stepId: string,
    role: 'public-control' | 'shared-control' | 'admin-control',
    identity: IdentityRecord
  ) => {
    steps.push(
      identitySwitchStep({
        stepId: `${stepId}.switch`,
        familyId,
        techniqueId,
        moduleVersion,
        environment: input.environment,
        identity
      }),
      httpStep({
        stepId,
        familyId,
        techniqueId,
        moduleVersion,
        environment: input.environment,
        endpointId: input.endpoint.id,
        desiredUrl: ownerMutation.desiredUrl,
        evidenceRoles: [role],
        mutationName: parameter.name,
        mutationValue: ownerResourceId,
        mutationKind,
        ...(segmentIndex !== undefined ? { mutationSegmentIndex: segmentIndex } : {}),
        identityId: identity.id,
        summary: `BOLA control：${role}`,
        payloadSummary: identityEvidenceSummary(identity)
      })
    )
  }
  if (publicIdentity) addControl('bola.public', 'public-control', publicIdentity)
  if (sharedIdentity) addControl('bola.shared', 'shared-control', sharedIdentity)
  if (adminIdentity) addControl('bola.admin', 'admin-control', adminIdentity)
  if (tenantIdentity) {
    addControl('bola.tenant', 'admin-control', tenantIdentity)
  }
  if (parentResourceId) {
    const parentMutation = mutateResourceUrl(input.endpoint.url, parameter, parentResourceId)
    steps.push(
      httpStep({
        stepId: 'bola.parent',
        familyId,
        techniqueId,
        moduleVersion,
        environment: input.environment,
        endpointId: input.endpoint.id,
        desiredUrl: parentMutation.desiredUrl,
        evidenceRoles: ['admin-control'],
        mutationName: parameter.name,
        mutationValue: parentResourceId,
        mutationKind,
        ...(segmentIndex !== undefined ? { mutationSegmentIndex: segmentIndex } : {}),
        identityId: second.id,
        summary: 'BOLA parent-child control。',
        payloadSummary: identityEvidenceSummary(second)
      })
    )
  }
  return {
    kind: 'plan',
    parameterId: parameter.id,
    affectedResource: ownerResourceId,
    observations: {
      baselineStepId: 'bola.owner',
      primaryStepId: 'bola.cross-read',
      negativeStepId: 'bola.second-own'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps
    },
    assess: (execution) =>
      assessBola({
        ownerResourceId,
        secondIdentityResourceId: secondResourceId,
        ownerRead: requireHttp(execution, 'bola.owner'),
        secondIdentityOwnRead: requireHttp(execution, 'bola.second-own'),
        secondIdentityOwnerRead: requireHttp(execution, 'bola.cross-read'),
        identitiesAuthorized:
          owner.isTestIdentity &&
          second.isTestIdentity &&
          input.allowedIdentityIds.includes(owner.id) &&
          input.allowedIdentityIds.includes(second.id),
        matrixCrossExpected:
          crossEntry.expected === 'visible' || crossEntry.expected === 'state-allowed'
            ? 'visible'
            : 'not-visible',
        crossIdentityRole: second.role,
        ...(publicIdentity && execution.httpByStep.has('bola.public')
          ? { publicControl: requireHttp(execution, 'bola.public') }
          : {}),
        ...(sharedIdentity && execution.httpByStep.has('bola.shared')
          ? { sharedControl: requireHttp(execution, 'bola.shared') }
          : {}),
        ...(adminIdentity && execution.httpByStep.has('bola.admin')
          ? { adminControl: requireHttp(execution, 'bola.admin') }
          : {}),
        ...(tenantIdentity && execution.httpByStep.has('bola.tenant')
          ? { tenantControl: requireHttp(execution, 'bola.tenant') }
          : {}),
        ...(parentResourceId && execution.httpByStep.has('bola.parent')
          ? { parentControl: requireHttp(execution, 'bola.parent') }
          : {})
      })
  }
}

function compileXssDomOffline(input: LegacyParityCompileInput): LegacyParityCompileResult {
  const parameter = requireParameter(input)
  if (input.environment === 'authorized-real-target' && !input.frozenAssetHtml) {
    return {
      kind: 'awaiting-user',
      waitFor: 'input',
      reason: 'DOM XSS replay requires a frozen AssetManifest or Broker-captured bundle.'
    }
  }
  if (parameter.location === 'form' || parameter.location === 'json') {
    return {
      kind: 'awaiting-user',
      waitFor: 'approval',
      reason: 'Stored XSS requires an approved L2 test object and cleanup.'
    }
  }
  const familyId = 'xss' as const
  const techniqueId = XSS_V2_TECHNIQUE_IDS.domOfflineReplay
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.xss
  const identity = input.identities[0]
  const xssMarker = `agx_${randomBytes(16).toString('hex')}`
  const payload = buildInertXssMarkerPayload(xssMarker, 'dom')
  const replayUrl = `${input.endpoint.url.split('#')[0]}#${xssMarker}`
  const identityId = identity?.id
  const frozenSource = Boolean(input.frozenAssetHtml) || input.environment === 'attested-fixture'
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'xss.dom.baseline',
      primaryStepId: 'xss.dom.capture'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps: [
        httpStep({
          stepId: 'xss.dom.baseline',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: input.endpoint.url,
          evidenceRoles: ['baseline'],
          summary: 'XSS DOM：读取冻结或已盘点页面，不注入外传 payload。',
          ...(identityId ? { identityId } : {})
        }),
        httpStep({
          stepId: 'xss.dom.capture',
          familyId,
          techniqueId,
          moduleVersion,
          environment: input.environment,
          endpointId: input.endpoint.id,
          desiredUrl: replayUrl,
          evidenceRoles: ['test'],
          summary: 'XSS DOM：在已盘点 URL 上附加 fragment marker，供断网重放。',
          payloadSummary: `fragment-only inert marker ${xssMarker}`,
          ...(identityId ? { identityId } : {})
        }),
        {
          stepId: 'xss.dom.offline-verify',
          kind: 'browser-offline-replay',
          familyId,
          techniqueId,
          moduleVersion,
          strategyVersion: moduleVersion,
          subjectRefs: [{ kind: 'endpoint', id: input.endpoint.id }],
          capabilityIds: ['browser.offline-replay'],
          environment: input.environment,
          evidenceRoles: ['browser-observation'],
          budget: BROWSER_BUDGET,
          stopConditions: [...STOP],
          htmlFromObservationId: 'xss.dom.capture',
          action: 'verify-xss',
          marker: xssMarker,
          baseUrl: replayUrl,
          summary: '断网重放冻结 DOM，验证 hash/sink 执行上下文。',
          payloadSummary: payload
        }
      ]
    },
    assess: (execution) => {
      const http = requireHttp(execution, 'xss.dom.capture')
      const browser = execution.browserByStep.get('xss.dom.offline-verify')
      return assessXssDomOffline({
        marker: xssMarker,
        http,
        frozenSource,
        ...(browser ? { browser } : {})
      })
    }
  }
}

function compileXssStored(input: LegacyParityCompileInput): LegacyParityCompileResult {
  if (input.environment !== 'attested-fixture') {
    return {
      kind: 'awaiting-user',
      waitFor: 'approval',
      reason:
        'Stored XSS requires a trusted L2 approval, disposable test object, and cleanup; product L2 remains disabled.'
    }
  }
  const parameter = requireParameter(input)
  const familyId = 'xss' as const
  const techniqueId = XSS_V2_TECHNIQUE_IDS.storedTestObject
  const moduleVersion = LEGACY_V1_MODULE_VERSIONS.xss
  const identity = input.identities[0]
  const xssMarker = `agx_${randomBytes(16).toString('hex')}`
  const payload = buildInertXssMarkerPayload(xssMarker, 'html')
  const identityId = identity?.id
  const testObject = input.candidate.testObjectRefs[0]
  const steps: CompilerDraft['steps'] = [
    httpStep({
      stepId: 'xss.stored.pre-read',
      familyId,
      techniqueId,
      moduleVersion,
      environment: input.environment,
      endpointId: input.endpoint.id,
      desiredUrl: input.endpoint.url,
      evidenceRoles: ['baseline'],
      summary: '存储型 XSS：写入前只读基线。',
      ...(identityId ? { identityId } : {})
    }),
    httpStep({
      stepId: 'xss.stored.isolated-read',
      familyId,
      techniqueId,
      moduleVersion,
      environment: input.environment,
      endpointId: input.endpoint.id,
      desiredUrl: input.endpoint.url,
      evidenceRoles: ['test'],
      summary: '存储型 XSS：隔离读取测试对象回显。',
      payloadSummary: `inert stored marker ${xssMarker}`,
      ...(identityId ? { identityId } : {})
    }),
    {
      stepId: 'xss.stored.offline-verify',
      kind: 'browser-offline-replay',
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      subjectRefs: [{ kind: 'endpoint', id: input.endpoint.id }],
      capabilityIds: ['browser.offline-replay'],
      environment: input.environment,
      evidenceRoles: ['browser-observation'],
      budget: BROWSER_BUDGET,
      stopConditions: [...STOP],
      htmlFromObservationId: 'xss.stored.isolated-read',
      action: 'verify-xss',
      marker: xssMarker,
      baseUrl: input.endpoint.url,
      summary: '断网重放存储回显，验证执行上下文。',
      payloadSummary: payload
    }
  ]
  if (testObject) {
    steps.push(
      {
        stepId: 'xss.stored.cleanup',
        kind: 'cleanup',
        familyId,
        techniqueId,
        moduleVersion,
        strategyVersion: moduleVersion,
        subjectRefs: [{ kind: 'test-object', id: testObject.id }],
        capabilityIds: [],
        environment: input.environment,
        evidenceRoles: ['cleanup-receipt'],
        budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
        stopConditions: [...STOP],
        testObjectRef: testObject,
        approvalBundleRef: input.candidate.candidateId
      },
      {
        stepId: 'xss.stored.cleanup-verify',
        kind: 'cleanup-verify',
        familyId,
        techniqueId,
        moduleVersion,
        strategyVersion: moduleVersion,
        subjectRefs: [{ kind: 'test-object', id: testObject.id }],
        capabilityIds: [],
        environment: input.environment,
        evidenceRoles: ['cleanup-receipt'],
        budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
        stopConditions: [...STOP],
        testObjectRef: testObject,
        cleanupStepId: 'xss.stored.cleanup'
      }
    )
  }
  return {
    kind: 'plan',
    parameterId: parameter.id,
    observations: {
      baselineStepId: 'xss.stored.pre-read',
      primaryStepId: 'xss.stored.isolated-read'
    },
    draft: {
      scanId: input.scanId,
      familyId,
      techniqueId,
      moduleVersion,
      strategyVersion: moduleVersion,
      environment: input.environment,
      stopConditions: [...STOP],
      budget: PLAN_BUDGET,
      steps
    },
    assess: (execution) => {
      const http = requireHttp(execution, 'xss.stored.isolated-read')
      const browser = execution.browserByStep.get('xss.stored.offline-verify')
      return assessXssStored({
        marker: xssMarker,
        http,
        ...(browser ? { browser } : {}),
        approved: Boolean(testObject),
        cleanupVerified: Boolean(testObject) && execution.run.status === 'succeeded'
      })
    }
  }
}

const compilers = new Map<
  string,
  (
    input: LegacyParityCompileInput
  ) => LegacyParityCompileResult | Promise<LegacyParityCompileResult>
>([
  [SQLI_V2_TECHNIQUE_IDS.booleanDifferential, compileSqli],
  [SQLI_V2_TECHNIQUE_IDS.errorSignal, compileSqliErrorSignal],
  [SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential, compileSqliBoundedTime],
  [LEGACY_V1_TECHNIQUE_IDS.xss, compileXss],
  [XSS_V2_TECHNIQUE_IDS.domOfflineReplay, compileXssDomOffline],
  [XSS_V2_TECHNIQUE_IDS.storedTestObject, compileXssStored],
  [LEGACY_V1_TECHNIQUE_IDS.ssrf, compileSsrf],
  [SSRF_V2_TECHNIQUE_IDS.reflectedProof, compileSsrfReflected],
  [SSRF_V2_TECHNIQUE_IDS.oobCallback, compileSsrfOob],
  [LEGACY_V1_TECHNIQUE_IDS.idor, compileIdor],
  [IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential, compileBola],
  [SECURITY_HEADERS_TECHNIQUE_IDS.baseline, compileSecurityHeaders]
])

export function hasLegacyParityAdapter(techniqueId: string): boolean {
  return compilers.has(techniqueId)
}

export async function compileLegacyParityPlan(
  input: LegacyParityCompileInput
): Promise<LegacyParityCompileResult> {
  const compiler = compilers.get(input.candidate.techniqueId)
  if (!compiler) {
    return {
      kind: 'forbidden',
      reason: `No legacy-parity adapter is registered for ${input.candidate.techniqueId}.`
    }
  }
  return compiler(input)
}
