import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { CandidateCompiler } from './candidate-compiler'
import { createVulnerabilityPlatform } from './vulnerability-platform'
import { IDOR_V2_TECHNIQUE_IDS, LEGACY_V1_MODULE_VERSIONS } from './vulnerability-bundles'
import type { CandidateSeed } from '@agentgo/contracts'

const endpointId = randomUUID()
const parameterId = randomUUID()
const variantId = randomUUID()

function seed(overrides: Partial<CandidateSeed> = {}): CandidateSeed {
  return {
    familyId: 'sqli',
    techniqueId: 'sqli.boolean-differential',
    moduleVersion: LEGACY_V1_MODULE_VERSIONS.sqli,
    detectorId: 'sqli.legacy.detector',
    subjectRefs: [{ kind: 'endpoint', id: endpointId }],
    variantRefs: [variantId],
    dependencyRefs: [],
    identityRefs: [],
    testObjectRefs: [],
    matrixRefs: [],
    parameterId,
    reason: 'Query id matches SQLi detector hints.',
    expectedSignal: 'sqli.boolean-differential',
    suggestedStrategy: 'sqli.legacy.strategy',
    confidenceHint: 0.7,
    ...overrides
  }
}

describe('CandidateCompiler', () => {
  const platform = createVulnerabilityPlatform()
  const compiler = new CandidateCompiler()
  const surface = {
    endpointId,
    method: 'GET',
    variantId,
    variantIds: [variantId],
    reviewStatus: 'reviewed',
    executionClass: 'active-l1',
    parameters: [{ id: parameterId, location: 'query' as const }]
  }

  it('ranks detector seeds and rejects unmatched agent suggestions', () => {
    const compiled = compiler.compile({
      seeds: [seed()],
      suggestions: [
        {
          family: 'sqli',
          endpointId,
          parameterId,
          reason: 'Agent rank hint for the detector seed.'
        },
        {
          family: 'sqli',
          endpointId,
          parameterId: randomUUID(),
          reason: 'Agent invented an unknown parameter.'
        }
      ],
      registry: platform.definitionRegistry,
      surfaces: [surface],
      environment: 'attested-fixture'
    })
    const executable = compiled.filter((item) => item.decision === 'executable')
    const rejected = compiled.filter((item) => item.decision === 'rejected')
    expect(executable).toHaveLength(1)
    expect(executable[0]?.candidate.reason).toContain('Agent rank hint')
    expect(rejected.some((item) => item.reason.includes('not backed by a Detector seed'))).toBe(
      true
    )
  })

  it('keeps non-GET and signal-only techniques inventory-only', () => {
    const compiled = compiler.compile({
      seeds: [
        seed(),
        seed({
          familyId: 'security.headers',
          techniqueId: 'security.headers.existing-response-audit',
          moduleVersion: '0.2.0',
          detectorId: 'security.headers.detector',
          suggestedStrategy: 'security.headers.existing-response-strategy',
          parameterId: undefined,
          reason: 'Passive header audit from frozen inventory.'
        })
      ],
      suggestions: [],
      registry: platform.definitionRegistry,
      surfaces: [{ ...surface, method: 'POST' }],
      environment: 'attested-fixture'
    })
    expect(compiled.every((item) => item.decision === 'inventory-only')).toBe(true)
  })

  it('keeps header and cookie SQLi inventory-only and form/JSON awaiting approval', () => {
    const headerParameter = randomUUID()
    const formParameter = randomUUID()
    const compiled = compiler.compile({
      seeds: [
        seed({
          parameterId: headerParameter,
          reason: 'Header selector is inventory-only.'
        }),
        seed({
          parameterId: formParameter,
          reason: 'Form selector needs L2 approval.'
        })
      ],
      suggestions: [],
      registry: platform.definitionRegistry,
      surfaces: [
        {
          ...surface,
          parameters: [
            { id: headerParameter, location: 'header' },
            { id: formParameter, location: 'form' }
          ]
        }
      ],
      environment: 'attested-fixture'
    })
    expect(compiled.find((item) => item.candidate.parameterId === headerParameter)?.decision).toBe(
      'inventory-only'
    )
    const form = compiled.find((item) => item.candidate.parameterId === formParameter)
    expect(form?.decision).toBe('awaiting-user')
    expect(form?.waitFor).toBe('approval')
  })

  it('keeps non-none codec selectors inventory-only', () => {
    const compiled = compiler.compile({
      seeds: [seed()],
      suggestions: [],
      registry: platform.definitionRegistry,
      surfaces: [{ ...surface, codec: 'base64url' }],
      environment: 'attested-fixture'
    })
    expect(compiled[0]?.decision).toBe('inventory-only')
  })

  it('forbids bounded-time SQLi outside attested-fixture', () => {
    const compiled = compiler.compile({
      seeds: [
        seed({
          techniqueId: 'sqli.bounded-time-differential',
          detectorId: 'sqli.bounded-time.detector',
          expectedSignal: 'sqli.bounded-time-differential',
          suggestedStrategy: 'sqli.bounded-time.strategy'
        })
      ],
      suggestions: [],
      registry: platform.definitionRegistry,
      surfaces: [surface],
      environment: 'authorized-real-target'
    })
    expect(compiled[0]?.decision).toBe('forbidden')
  })

  it('rejects seeds whose family, detector, strategy, parameter, or variants drift from frozen definitions', () => {
    const inputs = [
      { seed: seed({ familyId: 'xss' }), expected: 'family' },
      { seed: seed({ detectorId: 'sqli.unlinked.detector' }), expected: 'detector' },
      { seed: seed({ suggestedStrategy: 'sqli.unlinked.strategy' }), expected: 'strategy' },
      { seed: seed({ parameterId: randomUUID() }), expected: 'parameter' },
      { seed: seed({ variantRefs: [randomUUID()] }), expected: 'variants' }
    ]
    for (const input of inputs) {
      const [compiled] = compiler.compile({
        seeds: [input.seed],
        suggestions: [],
        registry: platform.definitionRegistry,
        surfaces: [surface],
        environment: 'attested-fixture'
      })
      expect(compiled?.decision).toBe('rejected')
      expect(compiled?.reason).toContain(input.expected)
    }
  })

  it('returns awaiting-user for unreviewed variants', () => {
    const compiled = compiler.compile({
      seeds: [seed()],
      suggestions: [],
      registry: platform.definitionRegistry,
      surfaces: [{ ...surface, reviewStatus: 'unreviewed' }],
      environment: 'attested-fixture'
    })
    expect(compiled[0]?.decision).toBe('awaiting-user')
    expect(compiled[0]?.waitFor).toBe('input')
  })

  it('keeps BOLA read-differential awaiting a matrix instead of executing it', () => {
    const compiled = compiler.compile({
      seeds: [
        seed({
          familyId: 'idor',
          techniqueId: IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
          moduleVersion: '1.2.0',
          detectorId: 'idor.bola.detector',
          expectedSignal: IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
          suggestedStrategy: 'idor.bola.strategy',
          reason: 'Query item_id matches BOLA detector hints.'
        })
      ],
      suggestions: [],
      registry: platform.definitionRegistry,
      surfaces: [surface],
      environment: 'attested-fixture'
    })
    expect(compiled[0]?.decision).toBe('awaiting-user')
    expect(compiled[0]?.waitFor).toBe('input')
    expect(compiled[0]?.reason).toContain('AuthorizationMatrix')
  })

  it('executes BOLA when Detector attached a human-confirmed matrix ref', () => {
    const compiled = compiler.compile({
      seeds: [
        seed({
          familyId: 'idor',
          techniqueId: IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
          moduleVersion: '1.2.0',
          detectorId: 'idor.bola.detector',
          expectedSignal: IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
          suggestedStrategy: 'idor.bola.strategy',
          reason: 'Query item_id matches BOLA detector hints.',
          matrixRefs: [randomUUID()]
        })
      ],
      suggestions: [],
      registry: platform.definitionRegistry,
      surfaces: [surface],
      environment: 'attested-fixture'
    })
    expect(compiled[0]?.decision).toBe('executable')
  })
})
