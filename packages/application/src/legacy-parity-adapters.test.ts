import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  compileLegacyParityPlan,
  type LegacyParityCompileInput
} from './legacy-parity-adapters'
import {
  assessIdor,
  assessSqli,
  assessSsrf,
  type HttpObservation,
  type ValidationAssessment
} from './validation-engine'
import type { ValidationPlanExecution } from './validation-plan-executor'
import type { Candidate, IdentityRecord, InventoryEndpoint } from '@agentgo/contracts'

const endpointId = randomUUID()
const parameterId = randomUUID()
const ownerId = randomUUID()
const secondId = randomUUID()

function candidate(techniqueId: string, familyId: string): Candidate {
  return {
    candidateId: randomUUID(),
    familyId,
    techniqueId,
    moduleVersion: '1.1.0',
    subjectRefs: [{ kind: 'endpoint', id: endpointId }],
    variantRefs: [],
    dependencyRefs: [],
    identityRefs: [],
    testObjectRefs: [],
    matrixRefs: [],
    parameterId,
    reason: 'Golden parity candidate.',
    expectedSignal: techniqueId,
    suggestedStrategy: `${familyId}.legacy.strategy`
  }
}

function endpoint(url: string, name: string): InventoryEndpoint {
  return {
    id: endpointId,
    method: 'GET',
    url,
    source: 'link',
    parameters: [
      {
        id: parameterId,
        name,
        location: 'query',
        required: true
      }
    ]
  }
}

function identity(
  id: string,
  ownedResourceIds: string[]
): IdentityRecord {
  return {
    id,
    targetId: randomUUID(),
    label: id,
    role: 'member',
    authType: 'bearer',
    isTestIdentity: true,
    ownedResourceIds,
    createdAt: '2026-09-02T00:00:00.000Z',
    updatedAt: '2026-09-02T00:00:00.000Z'
  }
}

function http(body: string, statusCode = 200): HttpObservation {
  return {
    result: {
      status: 'succeeded',
      statusCode,
      responseBody: Buffer.from(body),
      responseBodySha256: 'ab'.repeat(32),
      responseBytes: Buffer.byteLength(body),
      durationMs: 10,
      responseHeaders: { 'content-type': 'text/plain' }
    },
    evidenceRefs: [randomUUID()],
    toolCallId: randomUUID(),
    proposalId: randomUUID(),
    policyDecisionId: randomUUID()
  }
}

function executionFrom(
  steps: Record<string, HttpObservation>
): ValidationPlanExecution {
  return {
    run: {
      runId: randomUUID(),
      scanId: randomUUID(),
      planId: randomUUID(),
      planHash: 'ab'.repeat(32),
      status: 'succeeded',
      createdAt: '2026-09-02T00:00:00.000Z'
    },
    plan: {
      schemaVersion: 'agentgo.validation-plan.v1',
      planId: randomUUID(),
      planHash: 'ab'.repeat(32),
      scanId: randomUUID(),
      familyId: 'sqli',
      techniqueId: 'sqli.boolean-differential',
      moduleVersion: '1.0.0',
      strategyVersion: '1.0.0',
      environment: 'attested-fixture',
      steps: [],
      stopConditions: ['on-step-failure'],
      budget: {
        maxRequests: 8,
        maxBytes: 16 * 1024 * 1024,
        maxDurationMs: 60_000,
        maxFanOut: 2
      },
      createdAt: '2026-09-02T00:00:00.000Z'
    },
    httpByStep: new Map(Object.entries(steps)),
    browserByStep: new Map(),
    callbackByStep: new Map(),
    requestCount: Object.keys(steps).length
  }
}

function baseInput(
  familyId: string,
  techniqueId: string,
  url: string,
  name: string
): LegacyParityCompileInput {
  return {
    scanId: randomUUID(),
    candidate: candidate(techniqueId, familyId),
    endpoint: endpoint(url, name),
    identities: [
      identity(ownerId, ['resource-a']),
      identity(secondId, ['resource-b'])
    ],
    allowedIdentityIds: [ownerId, secondId],
    environment: 'attested-fixture',
    upsertReadInventory: async () => {
      throw new Error('upsert should not run for this family.')
    }
  }
}

function sameAssessment(left: ValidationAssessment, right: ValidationAssessment): void {
  expect(left.verdict).toBe(right.verdict)
  expect(left.completedChecks).toEqual(right.completedChecks)
  expect(left.failedChecks).toEqual(right.failedChecks)
  expect(left.missingChecks).toEqual(right.missingChecks)
  expect(left.confirmationRuleId).toBe(right.confirmationRuleId)
}

describe('legacy parity adapters', () => {
  it('compiles SQLi step order and assesses identically to assessSqli', async () => {
    const compiled = await compileLegacyParityPlan(
      baseInput(
        'sqli',
        'sqli.boolean-differential',
        'https://fixture.agentgo.test/items?id=1',
        'id'
      )
    )
    if (compiled.kind !== 'plan') throw new Error('SQLi adapter must compile a plan.')
    expect(compiled.draft.steps.map((step) => step.stepId)).toEqual([
      'sqli.baseline',
      'sqli.true',
      'sqli.false',
      'sqli.repeat'
    ])
    const baseline = http('product: visible')
    const trueFirst = http('product: visible')
    const falseControl = http('no rows')
    const trueRepeat = http('product: visible')
    sameAssessment(
      compiled.assess(
        executionFrom({
          'sqli.baseline': baseline,
          'sqli.true': trueFirst,
          'sqli.false': falseControl,
          'sqli.repeat': trueRepeat
        })
      ),
      assessSqli({ baseline, trueFirst, falseControl, trueRepeat })
    )
  })

  it('compiles XSS HTTP then offline browser without a second network path', async () => {
    const compiled = await compileLegacyParityPlan(
      baseInput(
        'xss',
        'xss.reflected-inert-marker',
        'https://fixture.agentgo.test/search?q=hello',
        'q'
      )
    )
    if (compiled.kind !== 'plan') throw new Error('XSS adapter must compile a plan.')
    expect(compiled.draft.steps.map((step) => step.stepId)).toEqual([
      'xss.baseline',
      'xss.reflection',
      'xss.offline-verify',
      'xss.encoded-negative'
    ])
    const assessed = compiled.assess(
      executionFrom({
        'xss.baseline': http('baseline'),
        'xss.reflection': http('<p>no marker</p>')
      })
    )
    expect(assessed.family).toBe('xss')
    expect(assessed.verdict).toBe('inconclusive')
  })

  it('compiles SSRF callback-read/primary/negative and matches assessSsrf', async () => {
    const callbackEndpoint = endpoint(
      'https://fixture.agentgo.test/callback?agentgo_token=agentgo-callback-review-placeholder',
      'agentgo_token'
    )
    const compiled = await compileLegacyParityPlan({
      ...baseInput(
        'ssrf',
        'ssrf.controlled-proof-response',
        'https://fixture.agentgo.test/fetch?url=none',
        'url'
      ),
      callbackUrl: 'https://fixture.agentgo.test/callback?tenant=fixture',
      upsertReadInventory: async () => ({
        endpoint: callbackEndpoint,
        requestVariant: { reviewStatus: 'reviewed' }
      })
    })
    if (compiled.kind !== 'plan') throw new Error('SSRF adapter must compile a plan.')
    expect(compiled.draft.steps.map((step) => step.stepId)).toEqual([
      'ssrf.callback-read',
      'ssrf.primary',
      'ssrf.negative'
    ])
    const callbackBaseline = http('AGENTGO_CALLBACK_PROOF_token')
    const targetProbe = http('AGENTGO_CALLBACK_PROOF_token')
    const negativeControl = http('invalid url')
    sameAssessment(
      compiled.assess(
        executionFrom({
          'ssrf.callback-read': callbackBaseline,
          'ssrf.primary': targetProbe,
          'ssrf.negative': negativeControl
        })
      ),
      assessSsrf({ callbackBaseline, targetProbe, negativeControl })
    )
  })

  it('compiles IDOR owner/second-own/cross-read and matches assessIdor', async () => {
    const compiled = await compileLegacyParityPlan(
      baseInput(
        'idor',
        'idor.two-test-identities-readonly',
        'https://fixture.agentgo.test/resource?resource_id=resource-a',
        'resource_id'
      )
    )
    if (compiled.kind !== 'plan') throw new Error('IDOR adapter must compile a plan.')
    expect(compiled.draft.steps.map((step) => step.stepId)).toEqual([
      'idor.switch-owner',
      'idor.owner',
      'idor.switch-second',
      'idor.second-own',
      'idor.cross-read'
    ])
    const ownerRead = http('{"id":"resource-a"}')
    const secondIdentityOwnRead = http('{"id":"resource-b"}')
    const secondIdentityOwnerRead = http('{"id":"resource-a"}')
    sameAssessment(
      compiled.assess(
        executionFrom({
          'idor.owner': ownerRead,
          'idor.second-own': secondIdentityOwnRead,
          'idor.cross-read': secondIdentityOwnerRead
        })
      ),
      assessIdor({
        ownerResourceId: 'resource-a',
        secondIdentityResourceId: 'resource-b',
        ownerRead,
        secondIdentityOwnRead,
        secondIdentityOwnerRead,
        identitiesAuthorized: true
      })
    )
  })
})
