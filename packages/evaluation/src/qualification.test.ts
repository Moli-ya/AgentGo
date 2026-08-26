import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  LEGACY_V1_FAMILY_IDS
} from '@agentgo/contracts'
import {
  LEGACY_V1_QUALIFICATION_PINS,
  LEGACY_V1_TECHNIQUE_IDS,
  computeLegacyV1PolicyHash,
  createVulnerabilityPlatform,
  createPinnedLegacyV1QualificationRecords
} from '@agentgo/application'
import { createFrozenBenchmarkSuiteRegistry } from './benchmark-registry'
import {
  BenchmarkScoringError,
  BenchmarkPredictionSchema,
  type BenchmarkPrediction
} from './index'
import {
  createEvaluationCoreMetaSuite,
  createLegacyV1BenchmarkSuites,
  loadCheckedInLegacyV1Manifest
} from './legacy-v1-suites'
import { localFixtureAttestationHash } from './local-fixture'
import {
  createQualificationRecordForBinding,
  hashBenchmarkSuite,
  scoreTechniqueSuite
} from './qualification-service'

function completedPrediction(
  caseId: string,
  actualVerdict: BenchmarkPrediction['actualVerdict'],
  extras: Record<string, unknown> = {}
): BenchmarkPrediction {
  return BenchmarkPredictionSchema.parse({
    caseId,
    actualVerdict,
    evidenceRefs: actualVerdict === 'confirmed' ? ['evidence'] : [],
    confirmationRuleId: actualVerdict === 'confirmed' ? 'rule' : undefined,
    evidenceRoles:
      actualVerdict === 'confirmed'
        ? ['baseline', 'test', 'negative-control', 'repeat']
        : [],
    durationMs: 1,
    requestCount: 1,
    modelTokens: 0,
    estimatedCost: 0,
    runStatus: 'completed',
    ...extras
  })
}

describe('Qualification evaluation core', () => {
  it('discovers the legacy-v1 suites from the registry rather than a family enum', () => {
    const suites = createLegacyV1BenchmarkSuites()
    const registry = createFrozenBenchmarkSuiteRegistry(suites)

    expect(registry.list().map((suite) => suite.familyId).sort()).toEqual(
      [...LEGACY_V1_FAMILY_IDS].sort()
    )
    expect(registry.listLegacyV1()).toHaveLength(4)
    expect(
      registry.list().flatMap((suite) => suite.cases).map((item) => item.caseId)
    ).toHaveLength(40)
    expect(
      loadCheckedInLegacyV1Manifest().cases.map((item) => item.caseId)
    ).toEqual(
      JSON.parse(
        readFileSync(
          new URL('../../../benchmarks/v1-ground-truth.json', import.meta.url),
          'utf8'
        )
      ).cases.map((item: { caseId: string }) => item.caseId)
    )
  })

  it('pins suite, fixture and definition hashes used by production records', () => {
    const platform = createVulnerabilityPlatform()
    const suites = createLegacyV1BenchmarkSuites()
    const policyCatalogHash = computeLegacyV1PolicyHash(platform.capabilityCatalog)

    expect(localFixtureAttestationHash()).toBe(
      LEGACY_V1_QUALIFICATION_PINS.fixtureAttestationHash
    )
    expect(platform.definitionSnapshot.snapshotHash).toBe(
      LEGACY_V1_QUALIFICATION_PINS.definitionSnapshotHash
    )
    expect(policyCatalogHash).toBe(LEGACY_V1_QUALIFICATION_PINS.policyCatalogHash)

    const generated = suites.map((suite) => {
      const binding = platform.executionGate.requireExecutableFamily(
        suite.familyId,
        'attested-fixture'
      )
      return createQualificationRecordForBinding({
        binding,
        suite,
        definitionSnapshotHash: platform.definitionSnapshot.snapshotHash,
        policyCatalogHash,
        fixtureAttestationHash: localFixtureAttestationHash()
      })
    })
    const pinned = createPinnedLegacyV1QualificationRecords({
      definitionSnapshotHash: platform.definitionSnapshot.snapshotHash,
      policyCatalogHash
    })

    expect(generated.map((item) => item.recordHash)).toEqual(
      pinned.map((item) => item.recordHash)
    )
    for (const suite of suites) {
      expect(hashBenchmarkSuite(suite)).toBe(
        LEGACY_V1_QUALIFICATION_PINS.suiteHashes[
          suite.familyId as keyof typeof LEGACY_V1_QUALIFICATION_PINS.suiteHashes
        ]
      )
    }
  })

  it('invalidates a qualification hash when any bound input changes', () => {
    const platform = createVulnerabilityPlatform()
    const suite = createLegacyV1BenchmarkSuites().find(
      (item) => item.familyId === 'sqli'
    )!
    const binding = platform.executionGate.requireExecutableFamily(
      'sqli',
      'attested-fixture'
    )
    const baseline = createQualificationRecordForBinding({
      binding,
      suite,
      definitionSnapshotHash: platform.definitionSnapshot.snapshotHash,
      policyCatalogHash: computeLegacyV1PolicyHash(platform.capabilityCatalog)
    })
    const mutated = createQualificationRecordForBinding({
      binding,
      suite,
      definitionSnapshotHash: '0'.repeat(64),
      policyCatalogHash: computeLegacyV1PolicyHash(platform.capabilityCatalog)
    })
    expect(mutated.recordHash).not.toBe(baseline.recordHash)
    expect(mutated.definitionSnapshotHash).not.toBe(baseline.definitionSnapshotHash)
  })

  it('fails closed for missing predictions, unknown techniques, version mismatch and missing evidence roles', () => {
    const suite = createLegacyV1BenchmarkSuites().find(
      (item) => item.familyId === 'sqli'
    )!
    const predictions = suite.cases.map((item) =>
      completedPrediction(
        item.caseId,
        item.expectedVerdict === 'confirmed' ? 'confirmed' : 'not-confirmed'
      )
    )

    expect(() =>
      scoreTechniqueSuite({
        suite,
        predictions: predictions.slice(1)
      })
    ).toThrow(BenchmarkScoringError)
    expect(() =>
      scoreTechniqueSuite({
        suite,
        predictions: [
          ...predictions,
          completedPrediction('unknown-case', 'not-confirmed')
        ]
      })
    ).toThrow(/Unknown predictions/)
    expect(() =>
      scoreTechniqueSuite({
        suite,
        predictions,
        knownTechniqueIds: ['idor.two-test-identities-readonly']
      })
    ).toThrow(/Unknown technique/)
    expect(() =>
      scoreTechniqueSuite({
        suite,
        predictions,
        fixtureVersion: 'agentgo-local-fixture/9.9.9'
      })
    ).toThrow(/does not match/)
    expect(() =>
      scoreTechniqueSuite({
        suite,
        predictions: predictions.map((item) =>
          item.actualVerdict === 'confirmed'
            ? { ...item, evidenceRoles: ['baseline'] }
            : item
        )
      })
    ).toThrow(/missing evidence roles/)
  })

  it('scores each qualification case category and refuses to execute cleanup-failure', () => {
    const suite = createEvaluationCoreMetaSuite()
    const predictions: BenchmarkPrediction[] = [
      completedPrediction('meta-positive', 'confirmed'),
      completedPrediction('meta-negative', 'not-confirmed', { evidenceRoles: [] }),
      completedPrediction('meta-inconclusive', 'inconclusive', { evidenceRoles: [] }),
      {
        ...completedPrediction('meta-policy-denied', 'inconclusive', {
          evidenceRoles: []
        }),
        runStatus: 'policy-denied'
      },
      {
        ...completedPrediction('meta-version-mismatch', 'inconclusive', {
          evidenceRoles: []
        }),
        runStatus: 'version-mismatch'
      },
      {
        ...completedPrediction('meta-cleanup-failure', 'inconclusive', {
          evidenceRoles: []
        }),
        runStatus: 'cleanup-failure'
      }
    ]

    expect(() => scoreTechniqueSuite({ suite, predictions })).not.toThrow()
    expect(() =>
      scoreTechniqueSuite({
        suite,
        predictions: predictions.map((item) =>
          item.caseId === 'meta-cleanup-failure'
            ? { ...item, runStatus: 'completed', actualVerdict: 'not-confirmed' }
            : item
        )
      })
    ).toThrow(/cannot be executed or scored as success/)
    expect(LEGACY_V1_TECHNIQUE_IDS.sqli).toBe(suite.techniqueId)
  })

  it('is stable across three identical suite hashes', () => {
    const first = createLegacyV1BenchmarkSuites().map(hashBenchmarkSuite)
    const second = createLegacyV1BenchmarkSuites().map(hashBenchmarkSuite)
    const third = createLegacyV1BenchmarkSuites().map(hashBenchmarkSuite)
    expect(second).toEqual(first)
    expect(third).toEqual(first)
  })
})
