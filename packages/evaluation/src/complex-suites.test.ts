import { COMPLEX_SUITE_ID, LOCAL_FIXTURE_VERSION } from '@agentgo/contracts'
import { describe, expect, it } from 'vitest'
import {
  COMPLEX_SUITE_VERSION,
  createComplexBenchmarkSuites,
  listComplexRunnerCases
} from './complex-suites'

describe('complex-v1 suites', () => {
  it('covers four families with at least 4/4/2 plus safety cases', () => {
    const suites = createComplexBenchmarkSuites()
    expect(suites).toHaveLength(4)
    expect(new Set(suites.map((suite) => suite.suiteId))).toEqual(new Set([COMPLEX_SUITE_ID]))
    expect(suites.every((suite) => suite.suiteVersion === COMPLEX_SUITE_VERSION)).toBe(true)
    expect(suites.every((suite) => suite.fixtureVersion === LOCAL_FIXTURE_VERSION)).toBe(true)

    for (const family of ['sqli', 'xss', 'ssrf', 'idor'] as const) {
      const cases = suites
        .filter((suite) => suite.familyId === family)
        .flatMap((suite) => suite.cases)
      expect(cases.filter((item) => item.category === 'positive').length, family).toBeGreaterThanOrEqual(4)
      expect(cases.filter((item) => item.category === 'negative').length, family).toBeGreaterThanOrEqual(4)
      expect(
        cases.filter((item) => item.category === 'inconclusive').length,
        family
      ).toBeGreaterThanOrEqual(2)
    }

    const all = listComplexRunnerCases()
    expect(all.some((item) => item.category === 'policy-denied')).toBe(true)
    expect(all.some((item) => item.category === 'cleanup-failure' && item.executable === false)).toBe(
      true
    )
    expect(all.some((item) => item.caseId.includes('secret-isolation'))).toBe(true)
    expect(all.every((item) => item.endpoint.startsWith('/research/'))).toBe(true)
  })
})
