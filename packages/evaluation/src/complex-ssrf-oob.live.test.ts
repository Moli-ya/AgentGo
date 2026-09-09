import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { BenchmarkSuiteManifestSchema } from '@agentgo/contracts'
import { AgentGoRepository, openAgentGoDatabase } from '@agentgo/db'
import { runExtendedBenchmark } from './benchmark-runtime'
import { createComplexBenchmarkSuites, listComplexRunnerCases } from './complex-suites'
import { startLocalBenchmarkFixture } from './local-fixture'

async function listAttemptReasons(outputDirectory: string) {
  const database = openAgentGoDatabase(join(outputDirectory, 'data', 'agentgo.sqlite'))
  try {
    const repository = new AgentGoRepository(database)
    const attempts = repository.createCandidateAttemptRepository()
    const scans = await repository.listScans({ limit: 32 })
    const rows = []
    for (const scan of scans) {
      for (const attempt of await attempts.listByScan(scan.id)) {
        rows.push({
          scanName: scan.name,
          techniqueId: attempt.candidate.techniqueId,
          status: attempt.status,
          decision: attempt.decision,
          reason: attempt.reason,
          requestCount: scan.requestCount
        })
      }
    }
    return rows
  } finally {
    database.close()
  }
}

describe('complex SSRF OOB live compile path', () => {
  it('executes OOB positives against the loopback collector and research fixtures', async () => {
    const outputDirectory = mkdtempSync(join(tmpdir(), 'agentgo-oob-live-'))
    const oobCaseIds = new Set([
      'complex-v1-ssrf-oob-callback-positive',
      'complex-v1-ssrf-oob-webhook-positive'
    ])
    const cases = listComplexRunnerCases().filter((item) => oobCaseIds.has(item.caseId))
    const ssrf = createComplexBenchmarkSuites().find((suite) => suite.familyId === 'ssrf')
    expect(cases).toHaveLength(2)
    expect(ssrf).toBeDefined()
    const suites = [
      BenchmarkSuiteManifestSchema.parse({
        ...ssrf,
        requiredCaseCategories: ['positive'],
        cases: ssrf!.cases.filter((item) => oobCaseIds.has(item.caseId))
      })
    ]
    const result = await runExtendedBenchmark({
      outputDirectory,
      workspaceName: 'OOB live path',
      resultClass: 'self-built-fixture',
      fixtureVersion: 'agentgo-local-fixture/1.0.0',
      throwOnAwaitingUser: false,
      cases,
      suites,
      startFixture: startLocalBenchmarkFixture
    })
    const attempts = await listAttemptReasons(outputDirectory)
    expect(
      result.predictions.map((item) => ({
        caseId: item.caseId,
        verdict: item.actualVerdict,
        requestCount: item.requestCount,
        evidence: item.evidenceRefs.length,
        runStatus: item.runStatus
      })),
      JSON.stringify({ attempts }, null, 2)
    ).toEqual([
      {
        caseId: 'complex-v1-ssrf-oob-callback-positive',
        verdict: 'confirmed',
        requestCount: expect.any(Number),
        evidence: expect.any(Number),
        runStatus: 'completed'
      },
      {
        caseId: 'complex-v1-ssrf-oob-webhook-positive',
        verdict: 'confirmed',
        requestCount: expect.any(Number),
        evidence: expect.any(Number),
        runStatus: 'completed'
      }
    ])
    for (const prediction of result.predictions) {
      expect(prediction.requestCount, prediction.caseId).toBeGreaterThan(1)
      expect(prediction.evidenceRefs.length, prediction.caseId).toBeGreaterThan(0)
    }
  }, 120_000)

  it('classifies completed no-callback as not-confirmed and collector-down as inconclusive', async () => {
    const outputDirectory = mkdtempSync(join(tmpdir(), 'agentgo-oob-neg-'))
    const oobCaseIds = new Set([
      'complex-v1-ssrf-old-token-negative',
      'complex-v1-ssrf-collector-down'
    ])
    const cases = listComplexRunnerCases().filter((item) => oobCaseIds.has(item.caseId))
    const ssrf = createComplexBenchmarkSuites().find((suite) => suite.familyId === 'ssrf')
    expect(cases).toHaveLength(2)
    expect(ssrf).toBeDefined()
    const suites = [
      BenchmarkSuiteManifestSchema.parse({
        ...ssrf,
        requiredCaseCategories: ['negative', 'inconclusive'],
        cases: ssrf!.cases.filter((item) => oobCaseIds.has(item.caseId))
      })
    ]
    const result = await runExtendedBenchmark({
      outputDirectory,
      workspaceName: 'OOB classify path',
      resultClass: 'self-built-fixture',
      fixtureVersion: 'agentgo-local-fixture/1.0.0',
      throwOnAwaitingUser: false,
      cases,
      suites,
      startFixture: startLocalBenchmarkFixture
    })
    const attempts = await listAttemptReasons(outputDirectory)
    expect(
      result.predictions.map((item) => ({
        caseId: item.caseId,
        verdict: item.actualVerdict
      })),
      JSON.stringify({ attempts }, null, 2)
    ).toEqual([
      {
        caseId: 'complex-v1-ssrf-old-token-negative',
        verdict: 'not-confirmed'
      },
      {
        caseId: 'complex-v1-ssrf-collector-down',
        verdict: 'inconclusive'
      }
    ])
  }, 120_000)
})
