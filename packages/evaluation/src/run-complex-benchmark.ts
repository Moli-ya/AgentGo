import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createComplexBenchmarkSuites, listComplexRunnerCases } from './complex-suites'
import { parseOutputOption, runExtendedBenchmark } from './benchmark-runtime'
import { startLocalBenchmarkFixture } from './local-fixture'

function timestampId(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const outputDirectory = resolve(
  parseOutputOption(
    process.argv,
    join(repositoryRoot, 'benchmark-results', `day20-complex-${timestampId()}`)
  )
)

const result = await runExtendedBenchmark({
  outputDirectory,
  workspaceName: `AgentGo complex benchmark ${new Date().toISOString()}`,
  resultClass: 'self-built-fixture',
  fixtureVersion: 'agentgo-local-fixture/1.0.0',
  throwOnAwaitingUser: false,
  cases: listComplexRunnerCases(),
  suites: createComplexBenchmarkSuites(),
  startFixture: startLocalBenchmarkFixture,
  extraMetadata: {
    suiteId: 'complex-v1',
    suiteVersion: '1.0.0'
  }
})

if (!result.summary.safety.passed) {
  process.exitCode = 1
}
