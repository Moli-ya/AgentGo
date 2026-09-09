import type {
  ExecutionAdapterKind,
  ExecutionPurpose,
  LegacyV1VulnerabilityFamily,
  TestObjectRef
} from '@agentgo/contracts'

export interface ExecutionWireHeader {
  readonly name: string
  readonly value: string
}

export interface HttpRedirectObservation {
  readonly hop: number
  readonly from: string
  readonly to: string
  readonly statusCode: number
  readonly policyDecisionId: string
  readonly grantId: string
  readonly leaseId: string
}

/**
 * Application-owned view of an HTTP execution. The opaque runner claim token
 * is deliberately absent and response bytes remain process-local/ephemeral.
 */
export interface HttpExecutionResultView {
  readonly requestId: string
  readonly status: 'succeeded' | 'failed' | 'cancelled'
  readonly finalUrl: string
  readonly method: string
  readonly statusCode?: number
  readonly requestHeaders: readonly ExecutionWireHeader[]
  readonly responseHeaders: Readonly<Record<string, string>>
  readonly responseBody?: Uint8Array
  readonly requestBodySha256?: string
  readonly responseBodySha256?: string
  readonly responseBytes: number
  readonly durationMs: number
  readonly resolvedAddresses: readonly string[]
  readonly redirectChain: readonly HttpRedirectObservation[]
  readonly errorCode?: string
  readonly errorMessage?: string
}

export interface BrowserFormFieldView {
  readonly name: string
  readonly type: string
  readonly required: boolean
}

export interface BrowserFormView {
  readonly action: string
  readonly method: string
  readonly fields: readonly BrowserFormFieldView[]
}

export interface BrowserExecutionResultView {
  readonly requestId: string
  readonly status: 'succeeded' | 'failed' | 'cancelled'
  readonly finalUrl: string
  readonly pageTitle?: string
  readonly links: readonly string[]
  readonly forms: readonly BrowserFormView[]
  readonly domSnapshot?: string
  readonly markerExecuted?: boolean
  readonly screenshot?: Uint8Array
  readonly networkRequestsBlocked: number
  readonly resultBytes: number
  readonly durationMs: number
  readonly errorCode?: string
  readonly errorMessage?: string
}

export interface StoredExecutionResult<TResult> {
  readonly result: TResult
  readonly interactionId?: string
  readonly interactionIds: readonly string[]
  readonly evidenceRefs: readonly string[]
  readonly toolCallId: string
  readonly toolCallIds: readonly string[]
  readonly proposalIds: readonly string[]
  readonly policyDecisionIds: readonly string[]
  readonly grantIds: readonly string[]
  readonly leaseIds: readonly string[]
  readonly reviewableDomOrScreenshotEvidence?: boolean
}

export interface QueryValueMutation {
  readonly kind: 'query'
  readonly name: string
  readonly occurrence: number
  readonly value: string
}

export interface PathValueMutation {
  readonly kind: 'path'
  readonly name: string
  readonly segmentIndex: number
  readonly value: string
}

export type RequestSelectorMutation = QueryValueMutation | PathValueMutation

interface ExecutionStepInput {
  readonly scanId: string
  readonly agentRunId: string
  readonly familyId: LegacyV1VulnerabilityFamily
  readonly stepId: string
  readonly purpose: ExecutionPurpose
  readonly summary: string
  readonly payloadSummary?: string
  readonly expectedEvidence: string
  readonly signal?: AbortSignal
}

export interface HttpExecutionStepInput extends ExecutionStepInput {
  readonly adapterKind: 'http'
  readonly endpointId: string
  readonly desiredUrl: string
  readonly identityId?: string
  readonly sessionId?: string
  readonly mutation?: RequestSelectorMutation
  readonly timeoutMs: number
  readonly maxResponseBytes: number
  readonly maxRedirects: number
}

export interface BrowserOfflineExecutionStepInput extends ExecutionStepInput {
  readonly adapterKind: 'browser-offline'
  readonly baseUrl: string
  readonly html: string
  readonly action: 'inspect-dom' | 'verify-xss' | 'capture-evidence'
  readonly marker?: string
  readonly contentSecurityPolicy?: string
  readonly timeoutMs: number
  readonly maxDomBytes: number
}

export interface UnsupportedExecutionStepInput extends ExecutionStepInput {
  readonly adapterKind: Exclude<
    ExecutionAdapterKind,
    'http' | 'browser-offline'
  >
}

export interface L2HttpExecutionStepInput extends ExecutionStepInput {
  readonly adapterKind: 'http'
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  readonly desiredUrl: string
  readonly identityId: string
  readonly sessionId: string
  readonly csrfBindingHash?: string
  readonly jsonBody?: Readonly<Record<string, string | number | boolean | null>>
  readonly testObjectRef: TestObjectRef
  readonly approvalBundleRef?: string
  readonly timeoutMs: number
  readonly maxResponseBytes: number
  readonly probeLevel: 'active-safe' | 'active-sensitive'
  readonly sideEffect: 'none' | 'reversible'
  readonly cleanupPlan?: string
}

export interface MediatedHttpExecutionStepInput extends ExecutionStepInput {
  readonly adapterKind: 'http'
  readonly method: 'GET' | 'HEAD'
  readonly endpointId: string
  readonly requestVariantId: string
  readonly desiredUrl: string
  readonly identityId?: string
  readonly sessionId?: string
  readonly expectedContentHash?: string
  readonly timeoutMs: number
  readonly maxResponseBytes: number
}

export type ExecutionPortInput =
  | HttpExecutionStepInput
  | BrowserOfflineExecutionStepInput
  | UnsupportedExecutionStepInput

export interface ExecutionPort {
  execute(
    input: HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>>
  execute(
    input: BrowserOfflineExecutionStepInput
  ): Promise<StoredExecutionResult<BrowserExecutionResultView>>
  execute(input: UnsupportedExecutionStepInput): Promise<never>
  executeL2Http(
    input: L2HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>>
  executeMediatedHttp(
    input: MediatedHttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>>
}
