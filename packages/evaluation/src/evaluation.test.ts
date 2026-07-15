import { readFileSync } from 'node:fs'
import { LEGACY_V1_FAMILY_IDS } from '@agentgo/contracts'
import { describe, expect, it } from 'vitest'
import {
  GroundTruthManifestSchema,
  buildBenchmarkSummary,
  renderBenchmarkMarkdown,
  type BenchmarkPrediction,
  type GroundTruthCase
} from './index'

const families: GroundTruthCase['family'][] = [...LEGACY_V1_FAMILY_IDS]

function cases(): GroundTruthCase[] {
  return families.flatMap((family) =>
    Array.from({ length: 10 }, (_, index) => ({
      caseId: `${family}-${index + 1}`,
      name: `${family} case ${index + 1}`,
      targetVersion: 'agentgo-local-fixture/1.0.0',
      family,
      endpoint: `/${family}/${index + 1}`,
      parameter: family === 'xss' ? 'q' : family === 'ssrf' ? 'url' : 'id',
      identityPlan: {},
      expectedVerdict: index < 5 ? 'confirmed' : 'not-confirmed',
      confirmationRule: `${family}-rule@1.0.0`,
      requiredEvidence: ['baseline', 'test', 'negative-control'],
      resetProcedure: 'stateless local fixture',
      forbiddenActions: ['destructive writes', 'out-of-scope access'],
      source: 'AgentGo self-built fixture',
      license: 'project-internal-test-data',
      reviewer: 'project-team'
    }))
  )
}

describe('benchmark metrics', () => {
  it('validates the checked-in 40-case V1 ground-truth manifest', () => {
    const manifest = GroundTruthManifestSchema.parse(
      JSON.parse(
        readFileSync(
          new URL('../../../benchmarks/v1-ground-truth.json', import.meta.url),
          'utf8'
        )
      )
    )

    expect(manifest.cases).toHaveLength(40)
    expect(new Set(manifest.cases.map((item) => item.caseId)).size).toBe(40)
  })

  it('calculates four-family metrics for the required 40-case minimum', () => {
    const groundTruth = cases()
    const predictions: BenchmarkPrediction[] = groundTruth.map((item, index) => ({
      caseId: item.caseId,
      actualVerdict:
        index === 0
          ? 'inconclusive'
          : item.expectedVerdict,
      evidenceRefs: ['evidence'],
      confirmationRuleId: `${item.family}-rule`,
      durationMs: 100 + index,
      requestCount: 4,
      modelTokens: 50,
      estimatedCost: 0,
      planRevisions: 0,
      duplicateRequests: 0,
      recoveredFromCrash: false
    }))
    const summary = buildBenchmarkSummary({
      cases: groundTruth,
      predictions,
      safetyCounters: {
        outOfScopeRequests: 0,
        destructiveL3Executions: 0,
        unapprovedL2Executions: 0,
        plaintextSecretsInLogsOrReports: 0,
        confirmedWithoutEvidenceOrRule: 0,
        continuedAfterCleanupFailure: 0
      }
    })

    expect(summary.overall.total).toBe(40)
    expect(summary.overall.inconclusive).toBe(1)
    expect(summary.overall.precision).toBe(1)
    expect(summary.overall.recall).toBe(19 / 20)
    expect(summary.safety.passed).toBe(true)
    expect(renderBenchmarkMarkdown(summary)).toContain('Safety Gates: PASS')
  })

  it('keeps V1 coverage requirements anchored to the explicit legacy family set', () => {
    const manifest = {
      schemaVersion: 'agentgo-ground-truth/1.0' as const,
      targetVersion: 'agentgo-local-fixture/1.0.0',
      note: 'An open family ID cannot replace one of the four V1 coverage groups.',
      cases: cases().map((item) =>
        item.caseId === 'idor-10'
          ? { ...item, family: 'security.headers' }
          : item
      )
    }

    const result = GroundTruthManifestSchema.safeParse(manifest)

    expect(result.success).toBe(false)
    expect(result.error?.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          message: 'idor/not-confirmed requires at least five cases.'
        })
      ])
    )
  })
})
