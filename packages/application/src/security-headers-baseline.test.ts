import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Candidate, InventoryEndpoint } from '@agentgo/contracts'
import {
  compileLegacyParityPlan,
  type LegacyParityCompileInput
} from './legacy-parity-adapters'
import { assessSecurityHeaders } from './validation-engine'
import { SECURITY_HEADERS_TECHNIQUE_IDS } from './vulnerability-bundles'
import { createVulnerabilityPlatform } from './vulnerability-platform'
import { FindingAssembler } from './finding-assembler'

const endpointId = randomUUID()

function candidate(): Candidate {
  return {
    candidateId: randomUUID(),
    familyId: 'security.headers',
    techniqueId: SECURITY_HEADERS_TECHNIQUE_IDS.baseline,
    moduleVersion: '0.2.0',
    subjectRefs: [{ kind: 'endpoint', id: endpointId }],
    variantRefs: [],
    dependencyRefs: [],
    identityRefs: [],
    testObjectRefs: [],
    matrixRefs: [],
    reason: 'passive headers',
    expectedSignal: SECURITY_HEADERS_TECHNIQUE_IDS.baseline,
    suggestedStrategy: 'security.headers.baseline.strategy'
  }
}

function endpoint(): InventoryEndpoint {
  return {
    id: endpointId,
    method: 'GET',
    url: 'https://fixture.agentgo.test/research/headers/missing',
    source: 'link',
    parameters: []
  }
}

function input(
  extras: Partial<LegacyParityCompileInput> = {}
): LegacyParityCompileInput {
  return {
    scanId: randomUUID(),
    candidate: candidate(),
    endpoint: endpoint(),
    identities: [],
    allowedIdentityIds: [],
    environment: 'attested-fixture',
    upsertReadInventory: async () => {
      throw new Error('security.headers.baseline must not create inventory I/O.')
    },
    ...extras
  }
}

describe('security.headers.baseline', () => {
  it('compiles a zero-request passive plan and reads labels from the registry', async () => {
    const missing = await compileLegacyParityPlan(input())
    expect(missing).toMatchObject({ kind: 'awaiting-user', waitFor: 'input' })

    const compiled = await compileLegacyParityPlan(
      input({
        existingResponseHeaders: {
          'content-type': 'text/html',
          'x-content-type-options': 'nosniff'
        }
      })
    )
    expect(compiled.kind).toBe('plan')
    if (compiled.kind === 'plan') {
      expect(compiled.draft.steps).toEqual([
        expect.objectContaining({
          kind: 'passive-analysis',
          stepId: 'headers.baseline.analyze',
          capabilityIds: []
        })
      ])
      expect(compiled.draft.budget.maxRequests).toBe(0)
      const assessment = compiled.assess({
        run: {
          runId: randomUUID(),
          scanId: compiled.draft.scanId,
          planId: randomUUID(),
          planHash: 'ab'.repeat(32),
          status: 'succeeded',
          createdAt: '2026-09-06T00:00:00.000Z'
        },
        plan: {
          schemaVersion: 'agentgo.validation-plan.v1',
          planId: randomUUID(),
          planHash: 'ab'.repeat(32),
          scanId: compiled.draft.scanId,
          familyId: 'security.headers',
          techniqueId: SECURITY_HEADERS_TECHNIQUE_IDS.baseline,
          moduleVersion: '0.2.0',
          strategyVersion: '0.2.0',
          environment: 'attested-fixture',
          steps: [],
          stopConditions: ['on-step-failure'],
          budget: compiled.draft.budget,
          createdAt: '2026-09-06T00:00:00.000Z'
        },
        httpByStep: new Map(),
        browserByStep: new Map(),
        callbackByStep: new Map(),
        requestCount: 0
      })
      expect(assessment.family).toBe('security.headers')
      expect(assessment.verdict).toBe('confirmed')
      expect(assessment.signalSummary).toMatch(/hsts|csp|frame/i)
    }

    const platform = createVulnerabilityPlatform()
    const assembler = new FindingAssembler(platform.definitionRegistry)
    expect(assembler.displayName('security.headers')).toBe('HTTP 安全响应头')
  })

  it('treats complete headers as not-confirmed and new requests as inconclusive', () => {
    expect(
      assessSecurityHeaders({
        headers: {
          'strict-transport-security': 'max-age=63072000',
          'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer'
        },
        newRequestCount: 0,
        https: true
      }).verdict
    ).toBe('not-confirmed')
    expect(
      assessSecurityHeaders({
        headers: { 'content-type': 'text/html' },
        newRequestCount: 1,
        https: true
      }).verdict
    ).toBe('inconclusive')
    expect(
      assessSecurityHeaders({
        headers: {},
        newRequestCount: 0,
        https: false
      }).verdict
    ).toBe('inconclusive')
  })
})
