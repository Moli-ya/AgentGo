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
  deniedPathPrefixes: z.array(z.string().min(1)).default([]),
  allowedPorts: z.array(z.number().int().positive().max(65_535)).default([]),
  allowedIdentityIds: z.array(z.string().min(1)).default([]),
  allowActiveProbing: z.boolean().default(true),
  allowSensitiveProbing: z.boolean().default(false),
  allowPrivateNetworkTargets: z.boolean().default(false),
  allowLoopbackTargets: z.boolean().default(false),
  maxRequestsPerMinute: z.number().int().positive().max(600),
  maxConcurrency: z.number().int().positive().max(32),
  authorizationReference: z.string().max(500).optional(),
  validFrom: z.string().datetime().optional(),
  validUntil: z.string().datetime().optional()
})

export type TargetScope = z.infer<typeof TargetScopeSchema>

export const ProbeActionSchema = z.object({
  id: z.string().min(1),
  kind: z.enum(['http-request', 'browser-action', 'tool-call']),
  targetUrl: z.string().url(),
  method: z.string().min(1).default('GET'),
  identityId: z.string().min(1).optional(),
  scopeSnapshotId: z.string().min(1).optional(),
  probeLevel: ProbeLevelSchema,
  sideEffect: SideEffectSchema,
  summary: z.string().min(1),
  payloadSummary: z.string().optional(),
  expectedEvidence: z.string().min(1),
  cleanupPlan: z.string().optional(),
  requestedRequestsPerMinute: z.number().int().positive().optional(),
  requestedConcurrency: z.number().int().positive().optional(),
  maxRequests: z.number().int().positive().max(100).default(1),
  timeoutMs: z.number().int().positive().max(120_000).default(15_000),
  userApproved: z.boolean().default(false)
})

export type ProbeAction = z.infer<typeof ProbeActionSchema>

export const PolicyCodeSchema = z.enum([
  'allowed',
  'invalid-target',
  'scope-expired',
  'scope-not-yet-valid',
  'out-of-scope',
  'identity-out-of-scope',
  'network-address-blocked',
  'redirect-out-of-scope',
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

export const PolicyDecisionSchema = z.object({
  allowed: z.boolean(),
  requiresApproval: z.boolean(),
  code: PolicyCodeSchema,
  reasons: z.array(z.string()),
  normalizedTarget: z.string().url().optional()
})

export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>
