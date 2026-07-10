import type { AgentRole } from '@agentgo/contracts'

export interface ModelProfile {
  id: string
  agentRole: AgentRole
  provider: string
  baseUrl: string
  model: string
  credentialId: string
  timeoutMs: number
  rpmLimit: number
  tpmLimit: number
  tokenBudget: number
  costBudget: number
}

export interface StructuredModelRequest<TSchema> {
  profileId: string
  systemPromptId: string
  systemPromptVersion: string
  input: unknown
  schema: TSchema
}

export interface StructuredModelResponse<T> {
  value: T
  provider: string
  model: string
  promptTokens: number
  completionTokens: number
  durationMs: number
  estimatedCost: number
}

export interface ModelGateway {
  testConnection(profileId: string): Promise<{ ok: boolean; message: string }>
  structuredCompletion<TSchema, TResult>(
    request: StructuredModelRequest<TSchema>
  ): Promise<StructuredModelResponse<TResult>>
}

const sensitivePatterns = [
  /Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi,
  /(api[_-]?key\s*[:=]\s*)[^\s,;]+/gi,
  /(cookie\s*[:=]\s*)[^\r\n]+/gi,
  /(password\s*[:=]\s*)[^\s,;]+/gi
]

export function redactSensitiveText(value: string): string {
  return sensitivePatterns.reduce(
    (redacted, pattern) => redacted.replace(pattern, '$1[REDACTED]'),
    value
  )
}
