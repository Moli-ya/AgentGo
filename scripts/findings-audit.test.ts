import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, expect, it } from 'vitest'
import {
  auditConfirmedFinding,
  findMissingAuditRuns,
  parseAuditInputs
} from './findings-audit'

const valid = {
  id: 'finding-1',
  scanId: 'scan-1',
  family: 'sqli',
  verdict: 'confirmed',
  confirmationRuleId: 'sqli-boolean-differential',
  confirmationRuleVersion: '1.0.0',
  reproducibility: 'repeatable boolean differential',
  remediationJson: '["parameterize queries"]',
  evidenceCount: 2,
  ruleHashPresent: true,
  negativeControlPresent: true,
  moduleVersion: '1.1.0'
}

describe('findings-audit', () => {
  it('parses --inputs directories', () => {
    expect(
      parseAuditInputs(
        ['node', 'findings-audit.ts', '--inputs', 'a', 'b'],
        ['fallback']
      )
    ).toEqual(['a', 'b'])
    expect(parseAuditInputs(['node', 'findings-audit.ts'], ['fallback'])).toEqual([
      'fallback'
    ])
    expect(parseAuditInputs(['node', 'findings-audit.ts', '--input', 'run with spaces'], [])).toEqual(['run with spaces'])
    expect(() => parseAuditInputs(['node', 'findings-audit.ts', '--input'], ['fallback'])).toThrow('Missing directory')
  })

  it('requires rule, evidence, negative control, remediation, and module version', () => {
    expect(auditConfirmedFinding(valid)).toEqual([])
    expect(
      auditConfirmedFinding({ ...valid, evidenceCount: 1 }).map((item) => item.reason)
    ).toContain('evidence count 1 < 2')
    expect(
      auditConfirmedFinding({ ...valid, ruleHashPresent: false }).map((item) => item.reason)
    ).toContain('confirmation rule record missing')
    expect(
      auditConfirmedFinding({ ...valid, negativeControlPresent: false }).map(
        (item) => item.reason
      )
    ).toContain('missing negative-control validation run')
    expect(
      auditConfirmedFinding({ ...valid, moduleVersion: null }).map((item) => item.reason)
    ).toContain('missing scan module version')
    expect(auditConfirmedFinding({ ...valid, verdict: 'not-confirmed' })).toEqual([])
  })

  it('treats every requested missing benchmark database as a hard failure', () => {
    const missingRun = join(tmpdir(), 'agentgo-findings-audit-missing-run')
    expect(findMissingAuditRuns([missingRun])).toEqual([missingRun])
  })
})
