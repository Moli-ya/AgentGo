import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')

/**
 * Day20 item 3 executable playbook. Reuses existing tests; does not invent a
 * second recovery framework.
 */
const CHECKS = [
  {
    id: 'synthetic-migration',
    title: '旧库 -> V2 合成迁移',
    files: [
      'packages/db/src/database.test.ts',
      'scripts/v1-database-baseline.test.ts'
    ]
  },
  {
    id: 'repeat-migration',
    title: '重复迁移恰好一次',
    files: ['packages/db/src/database.test.ts']
  },
  {
    id: 'scan-module-snapshot',
    title: 'Scan module snapshot 不可变/封存',
    files: [
      'packages/application/src/scan-module-snapshot.test.ts',
      'packages/application/src/scan-module-snapshot.integration.test.ts'
    ]
  },
  {
    id: 'pause-resume',
    title: '暂停/恢复',
    files: [
      'packages/application/src/application-service.test.ts',
      'packages/application/src/vulnerability-execution-gate.integration.test.ts'
    ]
  },
  {
    id: 'missing-historical-module',
    title: 'missing historical module 失败封闭',
    files: ['packages/application/src/vulnerability-execution-gate.integration.test.ts']
  },
  {
    id: 'claimed-lease-crash',
    title: 'claimed lease crash / 无伪造 Evidence',
    files: [
      'packages/application/src/execution-service.runtime.test.ts',
      'packages/db/src/execution-repository.test.ts'
    ]
  },
  {
    id: 'cleanup-pending-resume',
    title: 'cleanup pending 恢复被阻断',
    files: ['packages/application/src/scan-coordinator.test.ts']
  }
] as const

const files = [...new Set(CHECKS.flatMap((item) => item.files))]
const packageFiles = files.filter((file) => file.startsWith('packages/'))
const scriptFiles = files.filter((file) => file.startsWith('scripts/'))

console.log(
  JSON.stringify(
    {
      schemaVersion: 'agentgo-day20-recovery-playbook/1.0',
      note: 'Runs existing migration/recovery tests. Not a new recovery engine.',
      checks: CHECKS
    },
    null,
    2
  )
)

const packageResult = spawnSync(
  'pnpm',
  ['vitest', 'run', ...packageFiles],
  { cwd: ROOT, stdio: 'inherit', shell: true }
)
if (packageResult.status !== 0) {
  process.exit(packageResult.status ?? 1)
}

if (scriptFiles.length > 0) {
  const scriptResult = spawnSync(
    'pnpm',
    ['vitest', 'run', '--config', 'scripts/vitest.config.ts', ...scriptFiles],
    { cwd: ROOT, stdio: 'inherit', shell: true }
  )
  if (scriptResult.status !== 0) {
    process.exit(scriptResult.status ?? 1)
  }
}

console.log(
  JSON.stringify({
    status: 'passed',
    checks: CHECKS.map((item) => item.id)
  })
)
