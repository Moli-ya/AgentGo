import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { spawnSync } from 'node:child_process'

const ROOT = resolve(import.meta.dirname, '..')

export interface ConfirmedFindingRow {
  readonly id: string
  readonly scanId: string
  readonly family: string
  readonly verdict: string
  readonly confirmationRuleId: string
  readonly confirmationRuleVersion: string
  readonly reproducibility: string
  readonly remediationJson: string
  readonly evidenceCount: number
  readonly ruleHashPresent: boolean
  readonly negativeControlPresent: boolean
  readonly moduleVersion: string | null
}

export interface FindingAuditFailure {
  readonly findingId: string
  readonly scanId: string
  readonly reason: string
}

const DEFAULT_RUNS = [
  'benchmark-results/day20-legacy-run1',
  'benchmark-results/day20-legacy-run2',
  'benchmark-results/day20-legacy-run3',
  'benchmark-results/day20-complex-pass1',
  'benchmark-results/day20-complex-pass2',
  'benchmark-results/day20-complex-pass3',
  'benchmark-results/day20-external-holdout-official'
]

export function parseAuditInputs(argv: string[], fallback: string[]): string[] {
  const inputs: string[] = []
  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index]
    if (value === '--inputs' || value === '--input') {
      if (!argv[index + 1] || argv[index + 1]!.startsWith('--')) {
        throw new Error(`Missing directory after ${value}.`)
      }
      while (argv[index + 1] && !argv[index + 1]!.startsWith('--')) {
        inputs.push(
          ...argv[index + 1]!
            .split(',')
            .map((item) => item.trim())
            .filter(Boolean)
        )
        index += 1
      }
      continue
    }
    throw new Error(`Unknown or incomplete argument: ${value ?? ''}`)
  }
  return inputs.length > 0 ? inputs : fallback
}

export function findMissingAuditRuns(directories: readonly string[]): string[] {
  return directories.filter(
    (directory) => !existsSync(resolve(directory, 'data', 'agentgo.sqlite'))
  )
}

export function auditConfirmedFinding(row: ConfirmedFindingRow): FindingAuditFailure[] {
  const failures: FindingAuditFailure[] = []
  const missing = (reason: string): void => {
    failures.push({ findingId: row.id, scanId: row.scanId, reason })
  }
  if (row.verdict !== 'confirmed') return failures
  if (!row.confirmationRuleId) missing('missing confirmation_rule_id')
  if (!row.confirmationRuleVersion) missing('missing confirmation_rule_version')
  if (!row.ruleHashPresent) missing('confirmation rule record missing')
  if (row.evidenceCount < 2) missing(`evidence count ${row.evidenceCount} < 2`)
  if (!row.reproducibility.trim()) missing('missing reproducibility')
  if (!row.remediationJson.trim() || row.remediationJson === '[]') {
    missing('missing remediation')
  }
  if (!row.negativeControlPresent) missing('missing negative-control validation run')
  if (!row.moduleVersion?.trim()) missing('missing scan module version')
  return failures
}

function loadConfirmedFindings(databasePath: string): ConfirmedFindingRow[] {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return database
      .prepare(
        `SELECT
           f.id,
           f.scan_id AS scanId,
           f.family,
           f.verdict,
           f.confirmation_rule_id AS confirmationRuleId,
           f.confirmation_rule_version AS confirmationRuleVersion,
           f.reproducibility,
           f.remediation_json AS remediationJson,
           (
             SELECT count(*) FROM finding_evidence fe WHERE fe.finding_id = f.id
           ) AS evidenceCount,
           EXISTS(
             SELECT 1 FROM confirmation_rules cr
             WHERE cr.id = f.confirmation_rule_id
               AND cr.version = f.confirmation_rule_version
               AND length(cr.rule_json) > 0
           ) AS ruleHashPresent,
           EXISTS(
             SELECT 1 FROM validation_runs vr
             WHERE vr.signal_id IN (
               SELECT s.id FROM signals s WHERE s.scan_id = f.scan_id
             )
               AND vr.confirmation_rule_id = f.confirmation_rule_id
               AND vr.result = 'confirmed'
               AND length(coalesce(vr.negative_control_ref, '')) > 0
           ) AS negativeControlPresent,
           (
             SELECT sms.module_version
             FROM scan_module_snapshots sms
             WHERE sms.scan_id = f.scan_id
               AND sms.family_id = f.family
             LIMIT 1
           ) AS moduleVersion
         FROM findings f
         WHERE f.verdict = 'confirmed'`
      )
      .all() as unknown as ConfirmedFindingRow[]
  } finally {
    database.close()
  }
}

function main(): void {
  const directories = parseAuditInputs(process.argv, DEFAULT_RUNS).map((item) =>
    resolve(ROOT, item)
  )
  const missingRuns = findMissingAuditRuns(directories)
  if (missingRuns.length > 0) {
    console.log(
      JSON.stringify(
        {
          schemaVersion: 'agentgo-findings-audit/1.0',
          note: 'Audit aborted because every requested benchmark database is required.',
          missingRuns,
          reports: [],
          failureCount: 0
        },
        null,
        2
      )
    )
    process.exitCode = 1
    return
  }
  const noElevate = spawnSync(
    'pnpm',
    [
      'vitest',
      'run',
      'packages/application/src/finding-assembler.test.ts',
      'packages/application/src/scan-coordinator.test.ts'
    ],
    { cwd: ROOT, stdio: 'inherit', shell: true }
  )
  if (noElevate.status !== 0) {
    throw new Error('Static no-elevate / assembler tests failed.')
  }

  const reports: Array<{
    directory: string
    confirmed: number
    failures: FindingAuditFailure[]
  }> = []
  for (const directory of directories) {
    const databasePath = resolve(directory, 'data', 'agentgo.sqlite')
    const rows = loadConfirmedFindings(databasePath)
    reports.push({
      directory,
      confirmed: rows.length,
      failures: rows.flatMap(auditConfirmedFinding)
    })
  }

  const failures = reports.flatMap((item) => item.failures)
  const result = {
    schemaVersion: 'agentgo-findings-audit/1.0',
    note:
      'Audits persisted Confirmed findings from benchmark DBs. Extra post-confirm probes are enforced by ValidationPlan stop conditions; this CLI checks rule/version/evidence/remediation/negative-control/module version. Verifier cannot elevate a non-confirmed assessment.',
    missingRuns,
    reports,
    failureCount: failures.length
  }
  console.log(JSON.stringify(result, null, 2))
  if (failures.length > 0 || missingRuns.length > 0 || reports.length === 0) {
    process.exitCode = 1
  }
}

const invoked = process.argv[1]?.replaceAll('\\', '/').endsWith('scripts/findings-audit.ts')
if (invoked) {
  main()
}
