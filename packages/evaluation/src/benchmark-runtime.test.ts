import { describe, expect, it } from 'vitest'
import { BenchmarkPredictionSchema } from './index'
import { compareBenchmarkSummaries } from './benchmark-runtime'

function prediction(caseId: string, actualVerdict: 'confirmed' | 'not-confirmed' | 'inconclusive') {
  return BenchmarkPredictionSchema.parse({
    caseId,
    actualVerdict,
    evidenceRefs: [],
    durationMs: 10,
    requestCount: 1,
    modelTokens: 0,
    estimatedCost: 0
  })
}

describe('compareBenchmarkSummaries', () => {
  it('ignores duration and reports verdict or score drift', () => {
    const left = {
      label: 'a',
      predictions: [prediction('one', 'confirmed')],
      safetyPassed: true,
      precision: 1,
      recall: 1,
      f1: 1
    }
    const sameVerdictDifferentDuration = {
      ...left,
      label: 'b',
      predictions: [
        BenchmarkPredictionSchema.parse({
          ...prediction('one', 'confirmed'),
          durationMs: 999
        })
      ]
    }
    expect(
      compareBenchmarkSummaries({ runs: [left, sameVerdictDifferentDuration] }).mismatches
    ).toEqual([])

    const drifted = {
      ...left,
      label: 'c',
      predictions: [prediction('one', 'not-confirmed')]
    }
    expect(compareBenchmarkSummaries({ runs: [left, drifted] }).mismatches[0]).toContain('verdict')
  })
})
