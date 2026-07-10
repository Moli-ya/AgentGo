import type { Verdict, VulnerabilityFamily } from '@agentgo/contracts'

export interface Target {
  id: string
  workspaceId: string
  name: string
  baseUrl: string
  scopeSnapshotId: string
}

export interface Signal {
  id: string
  scanId: string
  family: VulnerabilityFamily
  endpointId: string
  parameterId?: string
  identityId?: string
  hypothesis: string
  observedDifference: string
  evidenceRefs: string[]
}

export interface ValidationRecord {
  id: string
  signalId: string
  confirmationRuleId: string
  confirmationRuleVersion: string
  policyDecisionId: string
  baselineRef: string
  testRef: string
  negativeControlRef?: string
  cleanupStatus: 'not-needed' | 'completed' | 'failed'
}

export interface Finding {
  id: string
  scanId: string
  family: VulnerabilityFamily
  title: string
  verdict: Verdict
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  evidenceRefs: string[]
  confirmationRuleId: string
  confirmationRuleVersion: string
  reproducibility: string
  remediation: string[]
}

export function isEvidenceBacked(finding: Finding): boolean {
  return (
    finding.verdict !== 'confirmed' ||
    (finding.evidenceRefs.length > 0 &&
      finding.confirmationRuleId.length > 0 &&
      finding.reproducibility.length > 0)
  )
}
