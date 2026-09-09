import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')

/**
 * Day20 item 10 executable gate. Reuses existing compiler/architecture/evidence
 * tests. There is no fast-check fuzzer in-tree; these files are the property
 * and boundary suite.
 */
const CHECKS = [
  {
    id: 'parser-compiler',
    title: 'parser/compiler property suite',
    files: [
      'packages/application/src/request-compiler.test.ts',
      'packages/application/src/candidate-compiler.test.ts',
      'packages/application/src/legacy-v1-request-compiler-adapter.test.ts'
    ]
  },
  {
    id: 'module-dependency-boundary',
    title: 'module dependency boundary',
    files: [
      'packages/application/src/execution-boundary.architecture.test.ts',
      'packages/application/src/l2-boundary.architecture.test.ts',
      'packages/application/src/import-discovery.architecture.test.ts',
      'packages/application/src/qualification-boundary.architecture.test.ts'
    ]
  },
  {
    id: 'registry-canonical-snapshot',
    title: 'Registry canonical snapshot / lockfile hashes',
    files: [
      'packages/domain/src/vulnerabilities/registry.test.ts',
      'packages/application/src/vulnerability-platform.test.ts',
      'packages/security-policy/src/probe-capability-catalog.test.ts'
    ]
  },
  {
    id: 'evidence-crypto-lifecycle',
    title: 'Evidence 加密/轮换/保留期/配额',
    files: [
      'packages/db/src/protected-evidence-store.test.ts',
      'packages/db/src/protected-evidence-migration-hardening.test.ts',
      'packages/application/src/protected-evidence-capture-service.test.ts'
    ]
  },
  {
    id: 'hmac-approval-keys',
    title: 'HMAC / 审批签名密钥生命周期合同',
    files: [
      'packages/contracts/src/security.test.ts',
      'packages/application/src/approval-service.test.ts',
      'packages/application/src/evidence-capture-policy.test.ts'
    ]
  }
] as const

const files = [...new Set(CHECKS.flatMap((item) => item.files))]

console.log(
  JSON.stringify(
    {
      schemaVersion: 'agentgo-day20-fuzz-gates/1.0',
      note:
        'No standalone generative fuzzer is vendored. This CLI runs the in-tree property, compiler, boundary, snapshot, evidence, and HMAC suites.',
      checks: CHECKS
    },
    null,
    2
  )
)

const result = spawnSync(
  'pnpm',
  ['vitest', 'run', ...files],
  { cwd: ROOT, stdio: 'inherit', shell: true }
)

if (result.status !== 0) {
  process.exit(result.status ?? 1)
}

console.log(JSON.stringify({ status: 'passed', checks: CHECKS.map((item) => item.id) }))
