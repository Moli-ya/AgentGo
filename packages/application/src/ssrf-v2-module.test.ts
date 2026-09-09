import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Candidate, IdentityRecord, InventoryEndpoint } from '@agentgo/contracts'
import { REMOTE_CALLBACK_COLLECTOR_PROTOCOL } from '@agentgo/contracts'
import {
  compileLegacyParityPlan,
  type LegacyParityCompileInput
} from './legacy-parity-adapters'
import { compileValidationPlan } from './validation-plan-compiler'
import {
  assessSsrfOob,
  assessSsrfReflected,
  type HttpObservation
} from './validation-engine'
import { SSRF_V2_TECHNIQUE_IDS } from './vulnerability-bundles'
import { createVulnerabilityPlatform } from './vulnerability-platform'
import { selectSsrfTechnique } from './detector-service'
import {
  LoopbackCallbackCollector,
  ensureAttestedFixtureCallbackListen
} from './loopback-callback-collector'

const endpointId = randomUUID()
const parameterId = randomUUID()
const identityId = randomUUID()

function candidate(techniqueId: string): Candidate {
  return {
    candidateId: randomUUID(),
    familyId: 'ssrf',
    techniqueId,
    moduleVersion: '1.1.0',
    subjectRefs: [{ kind: 'endpoint', id: endpointId }],
    variantRefs: [],
    dependencyRefs: [],
    identityRefs: [],
    testObjectRefs: [],
    matrixRefs: [],
    parameterId,
    reason: 'SSRF V2 module candidate.',
    expectedSignal: techniqueId,
    suggestedStrategy: 'ssrf.legacy.strategy'
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
    createdAt: '2026-09-06T00:00:00.000Z',
    updatedAt: '2026-09-06T00:00:00.000Z'
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
    parameters: [{ id: parameterId, name, location, required: true }]
  }
}

function input(
  techniqueId: string,
  url: string,
  name: string,
  extras: Partial<LegacyParityCompileInput> = {}
): LegacyParityCompileInput {
  return {
    scanId: randomUUID(),
    candidate: candidate(techniqueId),
    endpoint: endpoint(url, name),
    identities: [identity()],
    allowedIdentityIds: [identityId],
    environment: 'attested-fixture',
    callbackUrl: 'https://fixture.agentgo.test/callback?tenant=fixture',
    upsertReadInventory: async () => ({
      endpoint: endpoint(
        'https://fixture.agentgo.test/callback?agentgo_token=agentgo-callback-review-placeholder',
        'agentgo_token'
      ),
      requestVariant: { reviewStatus: 'reviewed' }
    }),
    ...extras
  }
}

function http(body: string): HttpObservation {
  return {
    result: {
      status: 'succeeded',
      statusCode: 200,
      responseBody: Buffer.from(body),
      responseBodySha256: 'cd'.repeat(32),
      responseBytes: Buffer.byteLength(body),
      durationMs: 10,
      responseHeaders: { 'content-type': 'text/plain' }
    },
    evidenceRefs: [],
    toolCallId: randomUUID(),
    proposalId: randomUUID(),
    policyDecisionId: randomUUID()
  }
}

describe('SSRF V2 reference module', () => {
  it('keeps the qualified 40-case technique first and adds reflected/OOB on the same bundle', () => {
    const platform = createVulnerabilityPlatform()
    const bundle = platform.definitionRegistry.getBundle('ssrf.legacy-v1', '1.2.0')
    expect(bundle?.bundle.manifest.techniques[0]?.techniqueId).toBe(
      SSRF_V2_TECHNIQUE_IDS.controlledProofResponse
    )
    expect(
      new Set(bundle?.bundle.manifest.techniques.map((item) => item.techniqueId))
    ).toEqual(
      new Set([
        SSRF_V2_TECHNIQUE_IDS.controlledProofResponse,
        SSRF_V2_TECHNIQUE_IDS.reflectedProof,
        SSRF_V2_TECHNIQUE_IDS.oobCallback
      ])
    )
    expect(REMOTE_CALLBACK_COLLECTOR_PROTOCOL.status).toBe('not-run')
  })

  it('selects frozen query url onto the qualified technique and ignores client navigation fields', () => {
    expect(
      selectSsrfTechnique({
        parameter: { id: parameterId, name: 'url', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(SSRF_V2_TECHNIQUE_IDS.controlledProofResponse)
    expect(
      selectSsrfTechnique({
        parameter: { id: parameterId, name: 'callback', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(SSRF_V2_TECHNIQUE_IDS.oobCallback)
    expect(
      selectSsrfTechnique({
        parameter: { id: parameterId, name: 'target', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(SSRF_V2_TECHNIQUE_IDS.reflectedProof)
    expect(
      selectSsrfTechnique({
        parameter: { id: parameterId, name: 'next', location: 'query', required: true },
        method: 'GET'
      })
    ).toBeUndefined()
  })

  it('compiles reflected proof and keeps product OOB awaiting a real collector', async () => {
    const reflected = await compileLegacyParityPlan(
      input(
        SSRF_V2_TECHNIQUE_IDS.reflectedProof,
        'https://fixture.agentgo.test/research/ssrf/reflected/positive?target=none',
        'target'
      )
    )
    expect(reflected.kind).toBe('plan')
    if (reflected.kind === 'plan') {
      expect(reflected.draft.steps.map((step) => step.stepId)).toEqual([
        'ssrf.reflected.baseline',
        'ssrf.reflected.primary',
        'ssrf.reflected.negative'
      ])
      const negative = reflected.draft.steps.find(
        (step) => step.stepId === 'ssrf.reflected.negative'
      )
      expect(negative && 'mutationValue' in negative ? negative.mutationValue : undefined).toBe(
        'agentgo-invalid-url'
      )
    }

    const productOob = await compileLegacyParityPlan(
      input(
        SSRF_V2_TECHNIQUE_IDS.oobCallback,
        'https://app.example/hook?callback=none',
        'callback',
        { environment: 'authorized-real-target', callbackCollectorAvailable: false }
      )
    )
    expect(productOob).toMatchObject({ kind: 'awaiting-user', waitFor: 'input' })

    const fixtureOob = await compileLegacyParityPlan(
      input(
        SSRF_V2_TECHNIQUE_IDS.oobCallback,
        'https://fixture.agentgo.test/research/ssrf/oob/positive?callback=none',
        'callback',
        {
          callbackCollectorAvailable: true,
          callbackCollectorListenUrl: 'http://127.0.0.1:9'
        }
      )
    )
    expect(fixtureOob.kind).toBe('plan')
    if (fixtureOob.kind === 'plan') {
      expect(fixtureOob.draft.steps.map((step) => step.stepId)).toEqual([
        'ssrf.oob.register',
        'ssrf.oob.primary',
        'ssrf.oob.negative',
        'ssrf.oob.poll',
        'ssrf.oob.consume'
      ])
      const primary = fixtureOob.draft.steps.find((step) => step.stepId === 'ssrf.oob.primary')
      expect(primary && 'mutationValue' in primary ? String(primary.mutationValue) : '').toContain(
        'http://127.0.0.1:9/callback'
      )
      expect(() => compileValidationPlan(fixtureOob.draft)).not.toThrow()
    }

    const missingListen = await compileLegacyParityPlan(
      input(
        SSRF_V2_TECHNIQUE_IDS.oobCallback,
        'https://fixture.agentgo.test/research/ssrf/oob/positive?callback=none',
        'callback',
        { callbackCollectorAvailable: true }
      )
    )
    expect(missingListen).toMatchObject({ kind: 'awaiting-user', waitFor: 'input' })
  })

  it('compiles OOB against a live loopback listen URL the coordinator must pass', async () => {
    const collector = new LoopbackCallbackCollector()
    const server = await ensureAttestedFixtureCallbackListen({
      environment: 'attested-fixture',
      collector
    })
    expect(server).toBeDefined()
    try {
      const compiled = await compileLegacyParityPlan(
        input(
          SSRF_V2_TECHNIQUE_IDS.oobCallback,
          'https://fixture.agentgo.test/research/ssrf/oob/positive?callback=none',
          'callback',
          {
            callbackCollectorAvailable: true,
            callbackCollectorListenUrl: server!.baseUrl
          }
        )
      )
      expect(compiled.kind).toBe('plan')
      if (compiled.kind === 'plan') {
        const primary = compiled.draft.steps.find((step) => step.stepId === 'ssrf.oob.primary')
        expect(primary && 'mutationValue' in primary ? String(primary.mutationValue) : '').toContain(
          `${server!.baseUrl}/callback`
        )
        expect(() => compileValidationPlan(compiled.draft)).not.toThrow()
      }
    } finally {
      await server?.close()
    }
  })

  it('confirms reflected proof and excludes client/replay OOB events', () => {
    const proof = 'AGENTGO_CALLBACK_PROOF_fixture01'
    expect(
      assessSsrfReflected({
        baseline: http('ok'),
        targetProbe: http(proof),
        negativeControl: http('invalid'),
        destinationInScope: true,
        redirectPolicyEnforced: true
      }).verdict
    ).toBe('confirmed')
    expect(
      assessSsrfOob({
        serverSideEvent: true,
        clientOrBrokerOrHealth: true,
        staleOrReplay: false,
        tokenBound: true,
        negativeHasEvent: false,
        collectorAvailable: true,
        timedOutOrWaf: false
      }).verdict
    ).toBe('not-confirmed')
    expect(
      assessSsrfOob({
        serverSideEvent: false,
        clientOrBrokerOrHealth: false,
        staleOrReplay: false,
        tokenBound: false,
        negativeHasEvent: false,
        collectorAvailable: true,
        timedOutOrWaf: false
      }).verdict
    ).toBe('not-confirmed')
    expect(
      assessSsrfOob({
        serverSideEvent: false,
        clientOrBrokerOrHealth: false,
        staleOrReplay: false,
        tokenBound: false,
        negativeHasEvent: false,
        collectorAvailable: false,
        timedOutOrWaf: true
      }).verdict
    ).toBe('inconclusive')
    expect(
      assessSsrfReflected({
        baseline: http('ok'),
        targetProbe: {
          ...http('blocked'),
          result: {
            ...http('blocked').result,
            status: 'failed',
            errorCode: 'network-address-blocked'
          }
        },
        negativeControl: http('invalid'),
        destinationInScope: false,
        redirectPolicyEnforced: true
      }).verdict
    ).toBe('inconclusive')
    expect(
      assessSsrfReflected({
        baseline: http('ok'),
        targetProbe: {
          ...http('redirect'),
          result: {
            ...http('redirect').result,
            statusCode: 302
          }
        },
        negativeControl: http('invalid'),
        destinationInScope: true,
        redirectPolicyEnforced: true
      }).verdict
    ).toBe('inconclusive')
  })
})
