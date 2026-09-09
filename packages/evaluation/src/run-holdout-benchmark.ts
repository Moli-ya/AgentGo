import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseOutputOption, runExtendedBenchmark } from './benchmark-runtime'
import {
  holdoutPackHash,
  startLocalHoldoutFixture
} from './holdout-fixture'
import {
  createHoldoutBenchmarkSuites,
  listHoldoutRunnerCases,
  SELF_BUILT_HOLDOUT_SUITE_ID
} from './holdout-suites'

function timestampId(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const outputDirectory = resolve(
  parseOutputOption(
    process.argv,
    join(repositoryRoot, 'benchmark-results', `day20-holdout-${timestampId()}`)
  )
)

const result = await runExtendedBenchmark({
  outputDirectory,
  workspaceName: `AgentGo local holdout ${new Date().toISOString()}`,
  resultClass: 'self-built-fixture',
  fixtureVersion: 'agentgo-local-holdout/1.0.0',
  throwOnAwaitingUser: false,
  cases: listHoldoutRunnerCases(),
  suites: createHoldoutBenchmarkSuites(),
  startFixture: startLocalHoldoutFixture,
  extraMetadata: {
    suiteId: SELF_BUILT_HOLDOUT_SUITE_ID,
    suiteVersion: '1.0.0',
    packHash: holdoutPackHash(),
    coverageNote:
      'Project-authored sealed local holdout. Not a third-party product accuracy claim.'
  }
})

if (!result.summary.safety.passed) {
  process.exitCode = 1
}
