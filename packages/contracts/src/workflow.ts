import { z } from 'zod'

export const VulnerabilityFamilySchema = z.enum([
  'sqli',
  'xss',
  'ssrf',
  'idor'
])

export type VulnerabilityFamily = z.infer<typeof VulnerabilityFamilySchema>

export const VerdictSchema = z.enum([
  'confirmed',
  'not-confirmed',
  'inconclusive'
])

export type Verdict = z.infer<typeof VerdictSchema>

export const ScanPhaseSchema = z.enum([
  'intake',
  'passive-recon',
  'active-enum',
  'hypothesis',
  'validation',
  'verification',
  'report'
])

export type ScanPhase = z.infer<typeof ScanPhaseSchema>

export const AgentRoleSchema = z.enum([
  'planner',
  'knowledge',
  'strategy',
  'analysis',
  'verifier'
])

export type AgentRole = z.infer<typeof AgentRoleSchema>

export interface AgentEnvelope<T> {
  schemaVersion: string
  messageId: string
  scanId: string
  runId: string
  parentRunId?: string
  source: AgentRole
  destination: AgentRole
  createdAt: string
  promptVersion: string
  modelProfileId: string
  scopeSnapshotId: string
  inputRefs: string[]
  payload: T
}

export interface ScanBudget {
  maxRequests: number
  maxRequestsPerMinute: number
  maxConcurrency: number
  maxPlanRevisions: number
  maxDurationMinutes: number
  maxModelTokens: number
  maxEstimatedCost: number
}
