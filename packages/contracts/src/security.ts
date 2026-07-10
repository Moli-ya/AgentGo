import { z } from 'zod'

export const ProbeLevelSchema = z.enum([
  'passive',
  'active-safe',
  'active-sensitive',
  'destructive'
])

export type ProbeLevel = z.infer<typeof ProbeLevelSchema>

export const SideEffectSchema = z.enum([
  'none',
  'reversible',
  'destructive',
  'unknown'
])

export type SideEffect = z.infer<typeof SideEffectSchema>

export const TargetScopeSchema = z.object({
  id: z.string().min(1),
  allowedOrigins: z.array(z.string().min(1)).min(1),
  allowedPathPrefixes: z.array(z.string().min(1)).default(['/']),
  allowActiveProbing: z.boolean().default(true),
  allowSensitiveProbing: z.boolean().default(false),
  maxRequestsPerMinute: z.number().int().positive().max(600),
  maxConcurrency: z.number().int().positive().max(32),
  validUntil: z.string().datetime().optional()
})

export type TargetScope = z.infer<typeof TargetScopeSchema>

export const ProbeActionSchema = z.object({
  id: z.string().min(1),
  kind: z.enum(['http-request', 'browser-action', 'tool-call']),
  targetUrl: z.string().url(),
  method: z.string().min(1).default('GET'),
  probeLevel: ProbeLevelSchema,
  sideEffect: SideEffectSchema,
  summary: z.string().min(1),
  payloadSummary: z.string().optional(),
  expectedEvidence: z.string().min(1),
  cleanupPlan: z.string().optional(),
  requestedRequestsPerMinute: z.number().int().positive().optional(),
  requestedConcurrency: z.number().int().positive().optional(),
  userApproved: z.boolean().default(false)
})

export type ProbeAction = z.infer<typeof ProbeActionSchema>

export const PolicyCodeSchema = z.enum([
  'allowed',
  'invalid-target',
  'scope-expired',
  'out-of-scope',
  'active-probing-disabled',
  'sensitive-probing-disabled',
  'approval-required',
  'destructive-action',
  'unknown-side-effect',
  'http-method-blocked',
  'mutating-method-requires-l2',
  'rate-limit-exceeded',
  'concurrency-limit-exceeded'
])

export type PolicyCode = z.infer<typeof PolicyCodeSchema>

export interface PolicyDecision {
  allowed: boolean
  requiresApproval: boolean
  code: PolicyCode
  reasons: string[]
  normalizedTarget?: string
}
