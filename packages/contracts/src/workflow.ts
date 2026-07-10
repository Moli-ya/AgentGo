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

export const ScanStatusSchema = z.enum([
  'draft',
  'queued',
  'running',
  'paused',
  'awaiting-user',
  'completed',
  'failed',
  'cancelled'
])

export type ScanStatus = z.infer<typeof ScanStatusSchema>

export const ScanControlActionSchema = z.enum(['start', 'pause', 'resume', 'cancel'])

export type ScanControlAction = z.infer<typeof ScanControlActionSchema>

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

export const ScanBudgetSchema = z.object({
  maxRequests: z.number().int().positive().max(10_000),
  maxRequestsPerMinute: z.number().int().positive().max(600),
  maxConcurrency: z.number().int().positive().max(32),
  maxPlanRevisions: z.number().int().nonnegative().max(20),
  maxDurationMinutes: z.number().int().positive().max(1_440),
  maxModelTokens: z.number().int().nonnegative().max(10_000_000),
  maxEstimatedCost: z.number().nonnegative().max(100_000)
})
