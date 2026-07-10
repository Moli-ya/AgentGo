export interface BrowserExecutionRequest {
  policyDecisionId: string
  targetUrl: string
  identityId?: string
  action: 'navigate' | 'inspect-dom' | 'submit-test-form' | 'capture-evidence'
  timeoutMs: number
}

export interface BrowserExecutionResult {
  requestId: string
  status: 'succeeded' | 'failed' | 'cancelled'
  finalUrl: string
  evidenceRefs: string[]
  durationMs: number
}

export interface BrowserRunner {
  execute(request: BrowserExecutionRequest): Promise<BrowserExecutionResult>
  cancel(requestId: string): Promise<void>
}
