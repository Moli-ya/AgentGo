export interface HttpExecutionRequest {
  policyDecisionId: string
  targetUrl: string
  method: string
  headers: Record<string, string>
  body?: string
  timeoutMs: number
}

export interface HttpExecutionResult {
  requestId: string
  status: 'succeeded' | 'failed' | 'cancelled'
  statusCode?: number
  responseHeaders: Record<string, string>
  responseBodyRef?: string
  durationMs: number
  evidenceRefs: string[]
}

export interface HttpRunner {
  execute(request: HttpExecutionRequest): Promise<HttpExecutionResult>
  cancel(requestId: string): Promise<void>
}
