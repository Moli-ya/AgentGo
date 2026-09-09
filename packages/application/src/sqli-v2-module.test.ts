import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Candidate, IdentityRecord, InventoryEndpoint } from '@agentgo/contracts'
import {
  compileLegacyParityPlan,
  type LegacyParityCompileInput
} from './legacy-parity-adapters'
import {
  assessSqliBoundedTime,
  assessSqliErrorSignal,
  type HttpObservation
} from './validation-engine'
import { isDestructiveSqliMutation } from './sqli-mutation-gate'
import { SQLI_NORMALIZER_VERSION } from './sqli-response-normalizer'
import { SQLI_V2_TECHNIQUE_IDS } from './vulnerability-bundles'
import { createVulnerabilityPlatform } from './vulnerability-platform'

const endpointId = randomUUID()
const parameterId = randomUUID()
const identityId = randomUUID()

function candidate(techniqueId: string): Candidate {
  return {
    candidateId: randomUUID(),
    familyId: 'sqli',
    techniqueId,
    moduleVersion: '1.1.0',
    subjectRefs: [{ kind: 'endpoint', id: endpointId }],
    variantRefs: [],
    dependencyRefs: [],
    identityRefs: [],
    testObjectRefs: [],
    matrixRefs: [],
    parameterId,
    reason: 'SQLi V2 module candidate.',
    expectedSignal: techniqueId,
    suggestedStrategy: 'sqli.legacy.strategy'
  }
}

function identity(): IdentityRecord {
  return {
    id: identityId,
    targetId: randomUUID(),
    label: 'test',
    role: 'member',
    authType: 'bearer',
    isTestIdentity: true,
    ownedResourceIds: [],
    createdAt: '2026-09-02T00:00:00.000Z',
    updatedAt: '2026-09-02T00:00:00.000Z'
  }
}

function endpoint(
  url: string,
  name: string,
  location: InventoryEndpoint['parameters'][number]['location'] = 'query',
  dataType?: string
): InventoryEndpoint {
  return {
    id: endpointId,
    method: location === 'form' || location === 'json' ? 'POST' : 'GET',
    url,
    source: 'link',
    parameters: [
      {
        id: parameterId,
        name,
        location,
        ...(dataType ? { dataType } : {}),
        required: true
      }
    ]
  }
}

function input(
  techniqueId: string,
  url: string,
  name: string,
  location: InventoryEndpoint['parameters'][number]['location'] = 'query',
  dataType?: string
): LegacyParityCompileInput {
  return {
    scanId: randomUUID(),
    candidate: candidate(techniqueId),
    endpoint: endpoint(url, name, location, dataType),
    identities: [identity()],
    allowedIdentityIds: [identityId],
    environment: 'attested-fixture',
    upsertReadInventory: async () => {
      throw new Error('SQLi V2 tests must not perform a second I/O path.')
    }
  }
}

function http(
  body: string,
  extras: { statusCode?: number; durationMs?: number } = {}
): HttpObservation {
  return {
    result: {
      status: 'succeeded',
      statusCode: extras.statusCode ?? 200,
      responseBody: Buffer.from(body),
      responseBodySha256: 'ab'.repeat(32),
      responseBytes: Buffer.byteLength(body),
      durationMs: extras.durationMs ?? 10,
      responseHeaders: { 'content-type': 'text/plain', 'cache-control': 'no-store' }
    },
    evidenceRefs: [],
    toolCallId: randomUUID(),
    proposalId: randomUUID(),
    policyDecisionId: randomUUID()
  }
}

describe('SQLi V2 reference module', () => {
  it('declares independent techniques, environments and confirmation rules', () => {
    const platform = createVulnerabilityPlatform()
    const bundle = platform.definitionRegistry.getBundle('sqli.legacy-v1', '1.2.0')
    expect(bundle?.bundle.manifest.techniques.map((item) => item.techniqueId).sort()).toEqual(
      [
        SQLI_V2_TECHNIQUE_IDS.booleanDifferential,
        SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential,
        SQLI_V2_TECHNIQUE_IDS.errorSignal
      ].sort()
    )
    const time = bundle?.bundle.manifest.techniques.find(
      (item) => item.techniqueId === SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential
    )
    expect(time?.allowedEnvironments).toEqual(['attested-fixture'])
    expect(time?.confirmationRuleRefs[0]?.id).toBe('sqli-bounded-time-differential')
    const error = bundle?.bundle.manifest.techniques.find(
      (item) => item.techniqueId === SQLI_V2_TECHNIQUE_IDS.errorSignal
    )
    expect(error?.allowedEnvironments).toContain('authorized-real-target')
    expect(bundle?.bundle.remediations[0]?.remediation).toContain('不能把 WAF 当作根因修复')
    expect(SQLI_NORMALIZER_VERSION).toBe('sqli.normalize@1.1.0')
  })

  it('keeps Day 15 boolean query mutations and compiles path through RequestCompiler fields', async () => {
    const query = await compileLegacyParityPlan(
      input(
        SQLI_V2_TECHNIQUE_IDS.booleanDifferential,
        'https://fixture.agentgo.test/items?id=1',
        'id',
        'query',
        'number'
      )
    )
    expect(query.kind).toBe('plan')
    if (query.kind !== 'plan') return
    const trueStep = query.draft.steps.find((step) => step.stepId === 'sqli.true')
    expect(trueStep).toMatchObject({
      mutationName: 'id',
      mutationValue: '1 AND 1=1',
      mutationKind: 'query'
    })
    expect(isDestructiveSqliMutation('1 AND 1=1')).toBe(false)

    const path = await compileLegacyParityPlan(
      input(
        SQLI_V2_TECHNIQUE_IDS.booleanDifferential,
        'https://fixture.agentgo.test/items/1',
        'id',
        'path'
      )
    )
    expect(path.kind).toBe('plan')
    if (path.kind !== 'plan') return
    const pathTrue = path.draft.steps.find((step) => step.stepId === 'sqli.true')
    expect(pathTrue).toMatchObject({
      mutationKind: 'path',
      mutationName: 'id',
      mutationValue: '1 AND 1=1'
    })
    expect(pathTrue && 'desiredUrl' in pathTrue ? pathTrue.desiredUrl : '').toContain(
      '1%20AND%201%3D1'
    )
  })

  it('compiles error-signal and fixture-only time plans without a second I/O path', async () => {
    const error = await compileLegacyParityPlan(
      input(
        SQLI_V2_TECHNIQUE_IDS.errorSignal,
        'https://fixture.agentgo.test/research/sqli/error/query/positive?msg=1',
        'msg'
      )
    )
    expect(error.kind).toBe('plan')
    if (error.kind === 'plan') {
      expect(
        error.draft.steps.some(
          (step) => step.kind === 'http-request' && step.mutationValue === "1'"
        )
      ).toBe(true)
    }

    const time = await compileLegacyParityPlan(
      input(
        SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential,
        'https://fixture.agentgo.test/research/sqli/time/query/positive?wait=1',
        'wait'
      )
    )
    expect(time.kind).toBe('plan')
    if (time.kind === 'plan') {
      expect(
        time.draft.steps.some(
          (step) => step.kind === 'http-request' && step.mutationValue === '1 AND SLEEP(2)'
        )
      ).toBe(true)
    }

    const realTarget = await compileLegacyParityPlan({
      ...input(
        SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential,
        'https://fixture.agentgo.test/research/sqli/time/query/positive?wait=1',
        'wait'
      ),
      environment: 'authorized-real-target'
    })
    expect(realTarget).toMatchObject({ kind: 'forbidden' })
  })

  it('does not emit form/JSON or header requests', async () => {
    const form = await compileLegacyParityPlan(
      input(
        SQLI_V2_TECHNIQUE_IDS.booleanDifferential,
        'https://fixture.agentgo.test/research/sqli/form/positive',
        'title',
        'form'
      )
    )
    expect(form).toMatchObject({ kind: 'awaiting-user', waitFor: 'approval' })

    const json = await compileLegacyParityPlan(
      input(
        SQLI_V2_TECHNIQUE_IDS.booleanDifferential,
        'https://fixture.agentgo.test/research/sqli/json/positive',
        'filter',
        'json'
      )
    )
    expect(json).toMatchObject({ kind: 'awaiting-user', waitFor: 'approval' })

    const header = await compileLegacyParityPlan(
      input(
        SQLI_V2_TECHNIQUE_IDS.booleanDifferential,
        'https://fixture.agentgo.test/items',
        'x-id',
        'header'
      )
    )
    expect(header).toMatchObject({ kind: 'inventory-only' })
  })

  it('does not confirm generic 500 or WAF, and confirms repeatable SQL fingerprints', () => {
    const sqlError =
      "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    const confirmed = assessSqliErrorSignal({
      baseline: http('message stored'),
      errorFirst: http(sqlError),
      negativeControl: http('message stored'),
      errorRepeat: http(sqlError)
    })
    expect(confirmed.verdict).toBe('confirmed')
    expect(confirmed.confirmationRuleId).toBe('sqli-error-signal')

    const generic = assessSqliErrorSignal({
      baseline: http('ok'),
      errorFirst: http('Internal Server Error', { statusCode: 500 }),
      negativeControl: http('ok'),
      errorRepeat: http('Internal Server Error', { statusCode: 500 })
    })
    expect(generic.verdict).toBe('inconclusive')

    const waf = assessSqliErrorSignal({
      baseline: http('ok'),
      errorFirst: http('request blocked by web application firewall', { statusCode: 403 }),
      negativeControl: http('ok'),
      errorRepeat: http('request blocked by web application firewall', { statusCode: 403 })
    })
    expect(waf.verdict).toBe('inconclusive')
  })

  it('confirms bounded time only when delay is repeatable and negative stays fast', () => {
    const confirmed = assessSqliBoundedTime({
      baseline: http('ready', { durationMs: 12 }),
      delayedFirst: http('ready', { durationMs: 2_010 }),
      negativeControl: http('ready', { durationMs: 11 }),
      delayedRepeat: http('ready', { durationMs: 2_020 })
    })
    expect(confirmed.verdict).toBe('confirmed')

    const noDelay = assessSqliBoundedTime({
      baseline: http('ready', { durationMs: 12 }),
      delayedFirst: http('ready', { durationMs: 14 }),
      negativeControl: http('ready', { durationMs: 11 }),
      delayedRepeat: http('ready', { durationMs: 13 })
    })
    expect(noDelay.verdict).toBe('not-confirmed')

    const jitter = assessSqliBoundedTime({
      baseline: http('ready', { durationMs: 12 }),
      delayedFirst: http('ready', { durationMs: 400 }),
      negativeControl: http('ready', { durationMs: 350 }),
      delayedRepeat: http('ready', { durationMs: 1_800 })
    })
    expect(jitter.verdict).toBe('not-confirmed')

    const blocked = assessSqliBoundedTime({
      baseline: http('ready', { durationMs: 12 }),
      delayedFirst: http('request blocked by web application firewall', {
        statusCode: 403,
        durationMs: 15
      }),
      negativeControl: http('ready', { durationMs: 11 }),
      delayedRepeat: http('request blocked by web application firewall', {
        statusCode: 403,
        durationMs: 14
      })
    })
    expect(blocked.verdict).toBe('inconclusive')
  })

  it('rejects destructive SQL at the compiler gate with zero requests', () => {
    expect(isDestructiveSqliMutation('1 UNION SELECT password FROM users')).toBe(true)
    expect(isDestructiveSqliMutation('1; DROP TABLE users')).toBe(true)
    expect(isDestructiveSqliMutation('1 AND SLEEP(2)')).toBe(false)
  })
})
