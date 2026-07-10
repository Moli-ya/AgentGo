import type { Finding } from '@agentgo/domain'

export interface ReportOutline {
  confirmed: Finding[]
  inconclusive: Finding[]
  notConfirmed: Finding[]
  safetyStatement: string
}

export function buildReportOutline(findings: Finding[]): ReportOutline {
  return {
    confirmed: findings.filter((finding) => finding.verdict === 'confirmed'),
    inconclusive: findings.filter((finding) => finding.verdict === 'inconclusive'),
    notConfirmed: findings.filter((finding) => finding.verdict === 'not-confirmed'),
    safetyStatement:
      '本报告仅记录授权范围内的低影响验证，未执行破坏性数据操作。'
  }
}
