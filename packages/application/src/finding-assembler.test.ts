import { describe, expect, it } from 'vitest'
import { FindingAssembler } from './finding-assembler'
import { createVulnerabilityPlatform } from './vulnerability-platform'
import type { ValidationAssessment } from './validation-engine'

describe('FindingAssembler', () => {
  const platform = createVulnerabilityPlatform()
  const assembler = new FindingAssembler(platform.definitionRegistry)

  it('reads display names from the frozen registry', () => {
    const names = assembler.familyDisplayNames()
    expect(names.sqli).toBe('SQL 注入')
    expect(names.xss).toBe('跨站脚本')
    expect(names['security.headers']).toBe('HTTP 安全响应头')
    expect(assembler.displayName('unknown.family')).toBe('unknown.family')
  })

  it('assembles titles and remediations without a closed family table', () => {
    const assessment: ValidationAssessment = {
      family: 'sqli',
      verdict: 'confirmed',
      signalSummary: 'boolean differential',
      explanation: 'repeatable',
      confidence: 0.96,
      severity: 'high',
      completedChecks: ['all-requests-succeeded'],
      failedChecks: [],
      missingChecks: [],
      confirmationRuleId: 'sqli-boolean-differential',
      confirmationRuleVersion: '1.0.0',
      cwe: 'CWE-89',
      owasp: 'A03:2021 Injection',
      remediation: ['fallback']
    }
    const assembled = assembler.assemble({
      familyId: 'sqli',
      techniqueId: 'sqli.boolean-differential',
      moduleVersion: '1.1.0',
      pathname: '/items',
      parameterName: 'id',
      assessment
    })
    expect(assembled.title).toBe('SQL 注入：/items 参数 id')
    expect(assembled.displayName).toBe('SQL 注入')
    expect(assembled.remediation.length).toBeGreaterThan(0)
    expect(assembled.confirmationRuleId).toBe('sqli-boolean-differential')
  })
})
