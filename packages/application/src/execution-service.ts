import { createHash, randomUUID } from 'node:crypto'
import type {
  BrowserExecutionResult,
  BrowserRunner
} from '@agentgo/browser-runner'
import {
  DefinitionIdSchema,
  ExecutionPurposeSchema,
  LegacyV1VulnerabilityFamilySchema,
  RESOLVED_INTENT_HASH_DOMAIN,
  ResolvedIntentHashSchema,
  TEMPLATE_INTENT_HASH_DOMAIN,
  TemplateIntentHashSchema,
  type EvidenceArtifactDraft,
  type EvidenceCaptureDecision,
  type EvidenceCaptureExecutionState,
  type ExecutionPurpose,
  type IdentityRef,
  type LegacyV1VulnerabilityFamily,
  type ProtectedOriginalEvidenceCaptureDecision
} from '@agentgo/contracts'
import {
  canonicalJson,
  canonicalizeInventoryUrl,
  redactInventoryText,
  redactInventoryUrlPreview,
  sha256Text
} from '@agentgo/domain'
import {
  canonicalizeTargetUrl,
  DEFAULT_PROBE_CAPABILITY_CATALOG
} from '@agentgo/security-policy'
import type {
  HttpExecutionResult,
  HttpRunner
} from '@agentgo/http-runner'
import {
  AgentGoRepository,
  EvidenceStore,
  type EvidenceItemRecord
} from '@agentgo/db'
import { EvidenceCapturePolicy } from './evidence-capture-policy'
import {
  ExecutionAuthority,
  type ExecutionEvidenceCaptureDecisionSet,
  type IssuedExecutionAuthority
} from './execution-authority'
import {
  PolicyBroker,
  PolicyExecutionGuard,
  createBrowserOfflineExactWire,
  type ExecutionClaimToken,
  type ExecutionFailureCode,
  type ExecutionInteractionAuditInput
} from './execution-policy'
import type {
  BrowserExecutionResultView,
  BrowserOfflineExecutionStepInput,
  ExecutionPort,
  ExecutionPortInput,
  HttpExecutionResultView,
  HttpExecutionStepInput,
  HttpRedirectObservation,
  L2HttpExecutionStepInput,
  MediatedHttpExecutionStepInput,
  StoredExecutionResult,
  UnsupportedExecutionStepInput
} from './execution-port'
import {
  claimTokenFromRunnerOutputError,
  validateBrowserRunnerOutput,
  validateHttpRunnerOutput
} from './execution-result-validation'
import { LegacyV1RequestCompilerAdapter } from './legacy-v1-request-compiler-adapter'
import type { EphemeralRequestHashKeyProvider } from './request-hash-key-provider'
import {
  CompiledWireRequest,
  computeWireRequestHmac,
  type CompiledProbeRequest,
  type MaterializedWireRequest,
  type WireRequestAuthorizationContext
} from './request-compiler'
import { compileL2HttpRequest, l2JsonBodyFields } from './l2-http-compiler'
import { compileMediatedRead } from './mediated-read-compiler'
import type { CsrfBindingService } from './csrf-binding-service'
import { InventoryService } from './inventory-service'
import { SessionVault } from './session-vault'
import { ProtectedEvidenceCaptureService } from './protected-evidence-capture-service'

const HTTP_TOOL_VERSION = '2.0.0'
const BROWSER_TOOL_VERSION = '2.0.0'
const EXECUTION_SERVICE_VERSION = '2.0.0'
const CAPTURE_GRACE_MS = 30_000
const MAX_GRANT_WINDOW_MS = 5 * 60_000
const MAX_BROWSER_HTML_BYTES = 1024 * 1024
const BROWSER_CAPABILITY = 'browser.offline-replay' as const
const CREDENTIAL_BEARING_HTTP_HEADER_NAMES = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  'x-api-key',
  'x-auth-token'
])

function sha256Bytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

export interface ExecutionServiceDependencies {
  readonly repository: AgentGoRepository
  readonly evidenceStore: EvidenceStore
  readonly httpRunner: HttpRunner<ExecutionClaimToken>
  readonly browserRunner: BrowserRunner
  readonly requestAdapter: LegacyV1RequestCompilerAdapter
  readonly authority: ExecutionAuthority
  readonly policyBroker: PolicyBroker
  readonly executionGuard: PolicyExecutionGuard
  readonly evidenceCapturePolicy: EvidenceCapturePolicy
  readonly hashKeyProvider: EphemeralRequestHashKeyProvider
  /**
   * Optional Day 9 vault. Only grants that carry an active sessionRef get a
   * private Set-Cookie sink; ordinary L1 executions are untouched. L2 HTTP
   * requires the full vault so cookie secret-refs can be compiled.
   */
  readonly sessionVault?: SessionVault
  readonly csrfBindingService?: CsrfBindingService
  readonly clock?: () => number
}

/** Minimal vault capability used by the execution path. */
export interface SessionCookieSink {
  ingestSetCookie(
    sessionId: string,
    headerValue: string,
    requestUrl: string
  ): Promise<unknown>
}

interface ExecutionTrace {
  readonly interactionIds: string[]
  readonly evidenceRefs: string[]
  readonly toolCallIds: string[]
  readonly proposalIds: string[]
  readonly policyDecisionIds: string[]
  readonly grantIds: string[]
  readonly leaseIds: string[]
}

interface SafeCaptureSummary {
  readonly source:
    | 'http-request-summary'
    | 'http-response-summary'
    | 'browser-request-summary'
    | 'browser-result-summary'
  readonly value: Readonly<Record<string, unknown>>
}

interface PersistCaptureInput {
  readonly issued: IssuedExecutionAuthority
  readonly workspaceId: string
  readonly executionState: EvidenceCaptureExecutionState
  readonly summaries: readonly [SafeCaptureSummary, SafeCaptureSummary]
}

interface PersistedCapture {
  readonly requestEvidenceId: string
  readonly resultEvidenceId: string
  readonly evidenceRefs: readonly string[]
  readonly hashOnlyEvidenceRefs: readonly string[]
  readonly evidenceLinks: ExecutionInteractionAuditInput['evidenceLinks']
  readonly requestInteractionSummary: Readonly<Record<string, unknown>>
  readonly resultInteractionSummary: Readonly<Record<string, unknown>>
  readonly reviewableDomOrScreenshotEvidence?: boolean
}

type EvidenceCleanupRecord = Pick<
  EvidenceItemRecord,
  'id' | 'filePath' | 'sha256'
>

interface IssuanceWindow {
  readonly grantValidUntil: string
  readonly leaseExpiresAt: string
}

function newTrace(): ExecutionTrace {
  return {
    interactionIds: [],
    evidenceRefs: [],
    toolCallIds: [],
    proposalIds: [],
    policyDecisionIds: [],
    grantIds: [],
    leaseIds: []
  }
}

function freezeStoredResult<TResult>(
  result: TResult,
  trace: ExecutionTrace,
  extras: { readonly reviewableDomOrScreenshotEvidence?: boolean } = {}
): StoredExecutionResult<TResult> {
  return Object.freeze({
    result,
    ...(trace.interactionIds.at(-1)
      ? { interactionId: trace.interactionIds.at(-1) }
      : {}),
    interactionIds: Object.freeze([...trace.interactionIds]),
    evidenceRefs: Object.freeze([...trace.evidenceRefs]),
    toolCallId: requiredLast(trace.toolCallIds, 'tool call'),
    toolCallIds: Object.freeze([...trace.toolCallIds]),
    proposalIds: Object.freeze([...trace.proposalIds]),
    policyDecisionIds: Object.freeze([...trace.policyDecisionIds]),
    grantIds: Object.freeze([...trace.grantIds]),
    leaseIds: Object.freeze([...trace.leaseIds]),
    ...(extras.reviewableDomOrScreenshotEvidence
      ? { reviewableDomOrScreenshotEvidence: true }
      : {})
  })
}

function requiredLast(values: readonly string[], label: string): string {
  const value = values.at(-1)
  if (!value) throw new Error(`Execution ${label} trace is missing.`)
  return value
}

function canonicalNow(clock: () => number): number {
  const now = clock()
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new Error('Execution service clock is invalid.')
  }
  return now
}

function safeText(value: string, maximum = 2_048): string {
  return redactInventoryText(value, maximum)
}

function safeUrl(value: string): string {
  try {
    return redactInventoryUrlPreview(value)
  } catch {
    return 'https://redacted.invalid/'
  }
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false
      }
      index += 1
      continue
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      return false
    }
  }
  return true
}

function assertPositiveInteger(
  value: number,
  label: string,
  maximum: number
): number {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > maximum
  ) {
    throw new Error(`${label} is outside the supported execution limit.`)
  }
  return value
}

function assertNonNegativeInteger(
  value: number,
  label: string,
  maximum: number
): number {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new Error(`${label} is outside the supported execution limit.`)
  }
  return value
}

function assertCanonicalHttpUrl(value: string, label: string): string {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error(`${label} is invalid.`)
  }
  if (
    !['http:', 'https:'].includes(parsed.protocol) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== '' ||
    parsed.toString() !== value
  ) {
    throw new Error(`${label} is not a canonical HTTP URL.`)
  }
  return value
}

function assertCredentialModeMatchesWire(
  wire: MaterializedWireRequest,
  credentialMode: 'include' | 'omit'
): void {
  if (
    credentialMode === 'omit' &&
    wire.headers.some(({ name }) =>
      CREDENTIAL_BEARING_HTTP_HEADER_NAMES.has(name.toLowerCase())
    )
  ) {
    throw new Error(
      'Credential-omitted HTTP request contains a credential-bearing header.'
    )
  }
}

function executionStateForHttp(
  result: HttpExecutionResult<ExecutionClaimToken>
): EvidenceCaptureExecutionState {
  if (result.status === 'succeeded') return 'succeeded'
  if (result.status === 'cancelled' || result.errorCode === 'cancelled') {
    return 'cancelled'
  }
  return result.errorCode === 'timeout' ? 'timed-out' : 'failed'
}

function executionStateForBrowser(
  result: BrowserExecutionResult
): EvidenceCaptureExecutionState {
  if (result.status === 'succeeded') return 'succeeded'
  if (result.status === 'cancelled' || result.errorCode === 'cancelled') {
    return 'cancelled'
  }
  return result.errorCode === 'timeout' ? 'timed-out' : 'failed'
}

function failureCodeForHttp(
  result: HttpExecutionResult<ExecutionClaimToken>
): ExecutionFailureCode {
  switch (result.errorCode) {
    case 'cancelled':
      return 'cancelled'
    case 'timeout':
      return 'timeout'
    case 'response-too-large':
      return 'response-too-large'
    case 'response-header-too-large':
      return 'response-header-too-large'
    case 'response-decompressed-too-large':
      return 'response-decompressed-too-large'
    case 'response-compression-bomb':
      return 'response-compression-bomb'
    case 'response-decompression-failed':
      return 'response-decompression-failed'
    case 'response-slow-read':
      return 'response-slow-read'
    case 'address-rejected':
      return 'address-rejected'
    case 'runner-output-invalid':
      return 'runner-output-invalid'
    case 'dispatch-mark-failed':
      return 'dispatch-mark-failed'
    case 'response-start-mark-failed':
      return 'response-start-mark-failed'
    default:
      return 'network-error'
  }
}

function failureCodeForBrowser(
  result: BrowserExecutionResult
): ExecutionFailureCode {
  if (result.errorCode === 'cancelled') return 'cancelled'
  if (result.errorCode === 'timeout') return 'timeout'
  if (result.errorCode === 'result-too-large') return 'response-too-large'
  if (result.errorCode === 'dispatch-mark-failed') {
    return 'dispatch-mark-failed'
  }
  if (result.errorCode === 'response-start-mark-failed') {
    return 'response-start-mark-failed'
  }
  if (result.errorCode === 'runner-output-invalid') {
    return 'runner-output-invalid'
  }
  return 'network-error'
}

function responseBytesForBrowser(result: BrowserExecutionResult): number {
  return result.resultBytes
}

function browserServiceFailureResult(
  requestId: string,
  baseUrl: string,
  errorCode:
    | 'cancelled'
    | 'dispatch-mark-failed'
    | 'response-start-mark-failed'
    | 'runner-output-invalid'
): BrowserExecutionResult {
  const errorMessage = {
    cancelled: 'The offline browser execution was cancelled.',
    'dispatch-mark-failed':
      'The offline browser dispatch could not be persisted.',
    'response-start-mark-failed':
      'The offline browser response could not be persisted.',
    'runner-output-invalid':
      'The offline browser runner returned an invalid result.'
  }[errorCode]
  return Object.freeze({
    requestId,
    status: errorCode === 'cancelled' ? 'cancelled' : 'failed',
    finalUrl: baseUrl,
    links: Object.freeze([]),
    forms: Object.freeze([]),
    networkRequestsBlocked: 0,
    resultBytes: 0,
    durationMs: 0,
    errorCode,
    errorMessage
  })
}

function mergeReviewableCapture(
  capture: PersistedCapture,
  reviewable: {
    readonly evidenceRefs: readonly string[]
    readonly reviewable: boolean
  }
): PersistedCapture {
  if (reviewable.evidenceRefs.length === 0) return capture
  return Object.freeze({
    ...capture,
    evidenceRefs: Object.freeze([
      ...capture.evidenceRefs,
      ...reviewable.evidenceRefs
    ]),
    hashOnlyEvidenceRefs: capture.hashOnlyEvidenceRefs,
    reviewableDomOrScreenshotEvidence: reviewable.reviewable
  })
}

function asProtectedOriginalDecision(
  decision: EvidenceCaptureDecision,
  source: 'dom-snapshot' | 'browser-screenshot'
): ProtectedOriginalEvidenceCaptureDecision | undefined {
  if (
    decision.action !== 'protected-original' ||
    decision.protectedOriginalPlan === undefined
  ) {
    return undefined
  }
  const {
    oobCommitmentKeyRef: _oobCommitmentKeyRef,
    oobCommitmentKeyVersion: _oobCommitmentKeyVersion,
    ...rest
  } = decision
  return {
    ...rest,
    action: 'protected-original',
    source,
    protectedOriginalPlan: decision.protectedOriginalPlan
  }
}

function reviewableDecisionFor(
  decisions: ExecutionEvidenceCaptureDecisionSet,
  source: 'dom-snapshot' | 'browser-screenshot',
  executionState: EvidenceCaptureExecutionState
): EvidenceCaptureDecision | undefined {
  if (!(source in decisions)) return undefined
  const byState = (
    decisions as unknown as Readonly<
      Record<
        'dom-snapshot' | 'browser-screenshot',
        Readonly<Record<EvidenceCaptureExecutionState, EvidenceCaptureDecision>>
      >
    >
  )[source]
  return byState?.[executionState]
}

function decisionFor(
  decisions: ExecutionEvidenceCaptureDecisionSet,
  source: SafeCaptureSummary['source'],
  executionState: EvidenceCaptureExecutionState
): EvidenceCaptureDecision {
  if (!(source in decisions)) {
    throw new Error('Execution capture source is not authorized by the grant.')
  }
  const byState = (
    decisions as unknown as Readonly<
      Record<
        SafeCaptureSummary['source'],
        Readonly<Record<EvidenceCaptureExecutionState, EvidenceCaptureDecision>>
      >
    >
  )[source]
  const decision = byState?.[executionState]
  if (!decision) {
    throw new Error('Execution capture state is not authorized by the grant.')
  }
  return decision
}

function flattenDecisionSet(
  decisions: ExecutionEvidenceCaptureDecisionSet
): readonly EvidenceCaptureDecision[] {
  return Object.values(decisions).flatMap((byState) =>
    Object.values(byState)
  )
}

function materializedWire(
  compiled: CompiledProbeRequest
): MaterializedWireRequest {
  return compiled.request.materialize()
}

function browserResultView(
  result: BrowserExecutionResult
): BrowserExecutionResultView {
  return Object.freeze({
    requestId: result.requestId,
    status: result.status,
    finalUrl: result.finalUrl,
    ...(result.pageTitle !== undefined ? { pageTitle: result.pageTitle } : {}),
    links: Object.freeze([...result.links]),
    forms: Object.freeze(
      result.forms.map((form) =>
        Object.freeze({
          action: form.action,
          method: form.method,
          fields: Object.freeze(
            form.fields.map((field) => Object.freeze({ ...field }))
          )
        })
      )
    ),
    ...(result.domSnapshot !== undefined
      ? { domSnapshot: result.domSnapshot }
      : {}),
    ...(result.markerExecuted !== undefined
      ? { markerExecuted: result.markerExecuted }
      : {}),
    ...(result.screenshot !== undefined
      ? { screenshot: Uint8Array.from(result.screenshot) }
      : {}),
    networkRequestsBlocked: result.networkRequestsBlocked,
    resultBytes: result.resultBytes,
    durationMs: result.durationMs,
    ...(result.errorCode !== undefined ? { errorCode: result.errorCode } : {}),
    ...(result.errorMessage !== undefined
      ? { errorMessage: safeText(result.errorMessage) }
      : {})
  })
}

function httpResultView(
  result: HttpExecutionResult<ExecutionClaimToken>,
  redirects: readonly HttpRedirectObservation[]
): HttpExecutionResultView {
  return Object.freeze({
    requestId: result.requestId,
    status: result.status,
    finalUrl: result.finalUrl,
    method: result.method,
    ...(result.statusCode !== undefined
      ? { statusCode: result.statusCode }
      : {}),
    requestHeaders: Object.freeze(
      result.requestHeaders.map((header) => Object.freeze({ ...header }))
    ),
    responseHeaders: Object.freeze({ ...result.responseHeaders }),
    ...(result.responseBody !== undefined
      ? { responseBody: Uint8Array.from(result.responseBody) }
      : {}),
    ...(result.requestBodySha256 !== undefined
      ? { requestBodySha256: result.requestBodySha256 }
      : {}),
    ...(result.responseBodySha256 !== undefined
      ? { responseBodySha256: result.responseBodySha256 }
      : {}),
    responseBytes: result.responseBytes,
    durationMs: result.durationMs,
    resolvedAddresses: Object.freeze([...result.resolvedAddresses]),
    redirectChain: Object.freeze([...redirects]),
    ...(result.errorCode !== undefined ? { errorCode: result.errorCode } : {}),
    ...(result.errorMessage !== undefined
      ? { errorMessage: safeText(result.errorMessage) }
      : {})
  })
}

class RedirectAuthorizationError extends Error {
  constructor(
    readonly code:
      | 'redirect-protocol-downgraded'
      | 'url-canonicalization-failed'
      | 'invalid-target',
    message: string
  ) {
    super(message)
    this.name = 'RedirectAuthorizationError'
  }
}

function ssrfTargetUrlForHttpStep(
  input: HttpExecutionStepInput,
  wireUrl: string,
  hop: number
): string | undefined {
  if (input.familyId !== 'ssrf') return undefined
  if (input.stepId === 'ssrf.callback-read') return wireUrl
  if (hop !== 0) return undefined
  const mutationValue =
    input.mutation && input.mutation.kind !== 'path'
      ? input.mutation.value
      : undefined
  if (
    typeof mutationValue === 'string' &&
    canonicalizeTargetUrl(mutationValue).ok
  ) {
    return mutationValue
  }
  return undefined
}

export class ExecutionService implements ExecutionPort {
  readonly #repository: AgentGoRepository
  readonly #evidenceStore: EvidenceStore
  readonly #httpRunner: HttpRunner<ExecutionClaimToken>
  readonly #browserRunner: BrowserRunner
  readonly #requestAdapter: LegacyV1RequestCompilerAdapter
  readonly #authority: ExecutionAuthority
  readonly #policyBroker: PolicyBroker
  readonly #executionGuard: PolicyExecutionGuard
  readonly #evidenceCapturePolicy: EvidenceCapturePolicy
  readonly #hashKeyProvider: EphemeralRequestHashKeyProvider
  readonly #sessionVault?: SessionVault
  readonly #csrfBindingService?: CsrfBindingService
  readonly #protectedEvidence: ProtectedEvidenceCaptureService
  readonly #clock: () => number

  constructor(dependencies: ExecutionServiceDependencies) {
    this.#repository = dependencies.repository
    this.#evidenceStore = dependencies.evidenceStore
    this.#httpRunner = dependencies.httpRunner
    this.#browserRunner = dependencies.browserRunner
    this.#requestAdapter = dependencies.requestAdapter
    this.#authority = dependencies.authority
    this.#policyBroker = dependencies.policyBroker
    this.#executionGuard = dependencies.executionGuard
    this.#evidenceCapturePolicy = dependencies.evidenceCapturePolicy
    this.#hashKeyProvider = dependencies.hashKeyProvider
    this.#sessionVault = dependencies.sessionVault
    this.#csrfBindingService = dependencies.csrfBindingService
    this.#protectedEvidence = new ProtectedEvidenceCaptureService(
      dependencies.evidenceCapturePolicy,
      dependencies.evidenceStore
    )
    this.#clock = dependencies.clock ?? Date.now
  }

  execute(
    input: HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>>
  execute(
    input: BrowserOfflineExecutionStepInput
  ): Promise<StoredExecutionResult<BrowserExecutionResultView>>
  execute(input: UnsupportedExecutionStepInput): Promise<never>
  execute(
    input: ExecutionPortInput
  ): Promise<
    | StoredExecutionResult<HttpExecutionResultView>
    | StoredExecutionResult<BrowserExecutionResultView>
  > {
    if (input.adapterKind === 'http') return this.#executeHttp(input)
    if (input.adapterKind === 'browser-offline') {
      return this.#executeBrowserOffline(input)
    }
    return this.#rejectUnsupported(input)
  }

  async executeL2Http(
    input: L2HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>> {
    const familyId = this.#prepareCommonInput(input)
    if (!this.#sessionVault) {
      throw new Error('L2 HTTP execution requires an active SessionVault.')
    }
    const mutating = input.method !== 'GET'
    if (mutating && input.approvalBundleRef === undefined) {
      throw new Error('L2 mutating HTTP requires a bound approval record.')
    }
    if (mutating && !this.#csrfBindingService) {
      throw new Error('L2 mutating HTTP requires a CSRF binding service.')
    }
    const timeoutMs = assertPositiveInteger(input.timeoutMs, 'HTTP timeout', 120_000)
    const maxResponseBytes = assertPositiveInteger(
      input.maxResponseBytes,
      'HTTP response budget',
      16_777_216
    )
    const desiredUrl = assertCanonicalHttpUrl(input.desiredUrl, 'HTTP desired URL')
    const identity = await this.#repository.getIdentity(input.identityId)
    if (!identity || !identity.isTestIdentity) {
      throw new Error('L2 HTTP identity is missing or is not a test identity.')
    }
    const identityRef: IdentityRef = {
      id: identity.id,
      version: Date.parse(identity.updatedAt),
      ownerRef: identity.targetId,
      scopeSnapshotId: input.testObjectRef.scopeSnapshotId,
      statusSummary: 'active'
    }
    const sessionRef = await this.#sessionVault.sessionGenerationRef(input.sessionId)
    const compiled = await compileL2HttpRequest({
      scanId: input.scanId,
      method: input.method,
      url: desiredUrl,
      identityRef,
      sessionRef,
      testObjectRef: input.testObjectRef,
      ownerRef: identity.targetId,
      scopeSnapshotId: input.testObjectRef.scopeSnapshotId,
      sessionId: input.sessionId,
      ...(input.csrfBindingHash ? { csrfBindingHash: input.csrfBindingHash } : {}),
      ...(input.jsonBody ? { jsonBody: input.jsonBody } : {}),
      hashKey: this.#hashKeyProvider.reference,
      hashKeyProvider: this.#hashKeyProvider,
      sessionVault: this.#sessionVault,
      ...(this.#csrfBindingService
        ? { csrfBindingService: this.#csrfBindingService }
        : {}),
      executionBinding: {
        stepId: input.stepId,
        purpose: input.purpose,
        adapterKind: 'http'
      }
    })
    const ownerRef = compiled.authorizationContext.ownerRef
    if (!ownerRef) {
      throw new Error('Compiled L2 request lacks owner binding.')
    }
    const endpointId = await this.#ensureL2InventoryEndpoint(input, desiredUrl)
    const wire = materializedWire(compiled)
    const policy = await this.#policyBroker.evaluate({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action: {
        kind: 'http-request',
        targetUrl: wire.url,
        method: wire.method,
        identityId: identity.id,
        probeLevel: input.probeLevel,
        sideEffect: input.sideEffect,
        summary: safeText(input.summary),
        ...(input.payloadSummary
          ? { payloadSummary: safeText(input.payloadSummary) }
          : {}),
        expectedEvidence: safeText(input.expectedEvidence),
        maxRequests: 1,
        timeoutMs,
        maxResponseBytes,
        maxRedirects: 0,
        maxRepeats: 0,
        userApproved: false,
        ...(input.cleanupPlan ? { cleanupPlan: safeText(input.cleanupPlan) } : {})
      },
      stopConditions: ['Stop after this single reviewed L2 execution step.'],
      authorizedWireRequestHmac: compiled.wireRequestHmac,
      ...(input.approvalBundleRef ? { backendTrustedApproval: true } : {})
    })
    const trace = newTrace()
    trace.proposalIds.push(policy.proposal.id)
    trace.policyDecisionIds.push(policy.decision.id)
    if (!policy.decision.allowed || policy.decision.requiresApproval) {
      throw new Error('Security policy rejected the compiled L2 HTTP request.')
    }
    const decidedTimeoutMs = policy.executionLimits?.timeoutMs ?? timeoutMs
    const decidedMaxResponseBytes =
      policy.executionLimits?.maxResponseBytes ?? maxResponseBytes
    const context = await this.#requireDecisionContext(input.scanId, policy.decision.id)
    const window = this.#issuanceWindow(
      policy.decision.validUntil,
      context.scope.validUntil,
      decidedTimeoutMs,
      0,
      undefined
    )
    const issued = await this.#authority.issue({
      scanId: input.scanId,
      familyId,
      policyDecisionId: policy.decision.id,
      stepId: input.stepId,
      compiled,
      capabilityIds: compiled.enabledCapabilityIds,
      ownerRef,
      credentialRef: compiled.authorizationContext.credentialRef,
      ...(compiled.authorizationContext.identityRef
        ? { identityRef: compiled.authorizationContext.identityRef }
        : {}),
      ...(compiled.authorizationContext.sessionRef
        ? { sessionRef: compiled.authorizationContext.sessionRef }
        : {}),
      testObjectRef: input.testObjectRef,
      ...(input.approvalBundleRef
        ? { approvalBundleRef: input.approvalBundleRef }
        : {}),
      purpose: input.purpose,
      adapterKind: 'http',
      retryClass: 'never',
      limits: {
        timeoutMs: decidedTimeoutMs,
        maxResponseBytes: decidedMaxResponseBytes,
        maxRedirects: 0
      },
      ...window
    })
    trace.grantIds.push(issued.grant.id)
    trace.leaseIds.push(issued.lease.id)
    const toolCallId = await this.#recordToolCall(issued, 'http-runner', HTTP_TOOL_VERSION)
    trace.toolCallIds.push(toolCallId)

    const requestId = randomUUID()
    const abort = (): void => {
      void this.#httpRunner.cancel(requestId)
    }
    input.signal?.addEventListener('abort', abort, { once: true })
    let rawResult: unknown
    const sessionRefIssued = issued.grant.sessionRef
    const vault = this.#sessionVault
    const pendingCookies: Array<{ readonly cookie: string; readonly url: string }> = []
    try {
      rawResult = await this.#httpRunner.execute({
        requestId,
        leaseId: issued.lease.id,
        wire,
        timeoutMs: decidedTimeoutMs,
        maxResponseBytes: decidedMaxResponseBytes,
        ...(input.signal ? { signal: input.signal } : {}),
        ...(vault && sessionRefIssued
          ? {
              setCookieSink: (cookies: readonly string[], requestUrl: string) => {
                for (const cookie of cookies) {
                  pendingCookies.push({ cookie, url: requestUrl })
                }
              }
            }
          : {})
      })
    } finally {
      input.signal?.removeEventListener('abort', abort)
    }
    if (vault && sessionRefIssued) {
      for (const pending of pendingCookies) {
        try {
          await vault.ingestSetCookie(sessionRefIssued.id, pending.cookie, pending.url)
        } catch {
          // Vault-side rejection must not fail an already authorized request.
        }
      }
    }
    let result
    try {
      result = validateHttpRunnerOutput<ExecutionClaimToken>(rawResult, {
        requestId,
        wire,
        timeoutMs: decidedTimeoutMs,
        maxResponseBytes: decidedMaxResponseBytes
      })
    } catch (error) {
      const claimToken = claimTokenFromRunnerOutputError<ExecutionClaimToken>(error)
      try {
        await this.#executionGuard.rejectInvalidRunnerOutput(issued.lease.id, claimToken)
      } catch {
        // Recovered as interrupted.
      }
      throw new Error('HTTP runner output failed closed validation.')
    }
    const redirects: HttpRedirectObservation[] = []
    const claimToken = result.claimToken
    if (!claimToken) {
      await this.#executionGuard.revoke(issued.lease.id, 'guard-rejected')
      return freezeStoredResult(httpResultView(result, redirects), trace)
    }
    const redirectRejected = Boolean(result.status === 'succeeded' && result.redirectLocation)
    const executionState = redirectRejected ? 'failed' : executionStateForHttp(result)
    const interactionId = randomUUID()
    const summaries = this.#httpCaptureSummaries(
      issued,
      wire,
      result,
      redirectRejected ? 'redirect-rejected' : undefined
    )
    let capture: PersistedCapture
    const unboundEvidence: EvidenceCleanupRecord[] = []
    let auditStage: 'evidence' | 'interaction' = 'evidence'
    try {
      capture = await this.#persistCaptures(
        {
          issued,
          workspaceId: context.workspaceId,
          executionState,
          summaries
        },
        unboundEvidence
      )
      auditStage = 'interaction'
      const persistedInteractionId = await this.#executionGuard.recordInteractionAudit(
        claimToken,
        {
          interaction: {
            id: interactionId,
            scanId: input.scanId,
            endpointId,
            identityId: identity.id,
            policyDecisionId: policy.decision.id,
            requestRef: capture.requestEvidenceId,
            responseRef: capture.resultEvidenceId,
            requestSummary: capture.requestInteractionSummary,
            responseSummary: capture.resultInteractionSummary,
            ...(result.statusCode !== undefined ? { statusCode: result.statusCode } : {}),
            durationMs: result.durationMs
          },
          evidenceLinks: capture.evidenceLinks
        }
      )
      if (persistedInteractionId !== interactionId) {
        throw new Error('Execution interaction identity changed during audit persistence.')
      }
      trace.interactionIds.push(interactionId)
      trace.evidenceRefs.push(...capture.evidenceRefs)
    } catch (error) {
      const retainedEvidenceRefs = await this.#discardUnboundCaptures(unboundEvidence)
      await this.#finalizeAuditFailure(claimToken, result.responseBytes, retainedEvidenceRefs)
      throw new Error(`HTTP execution ${auditStage} persistence failed.`, {
        cause: error
      })
    }

    if (redirectRejected) {
      await this.#executionGuard.finalizeFailed(claimToken, {
        code: 'redirect-rejected',
        responseBytes: result.responseBytes,
        evidenceRefs: capture.evidenceRefs
      })
      return freezeStoredResult(
        Object.freeze({
          ...httpResultView(result, redirects),
          status: 'failed' as const,
          errorCode: 'redirect-rejected',
          errorMessage: 'The HTTP redirect target was rejected.'
        }),
        trace
      )
    }
    if (result.status === 'succeeded') {
      await this.#executionGuard.finalizeSucceeded(claimToken, {
        responseBytes: result.responseBytes,
        evidenceRefs: capture.evidenceRefs
      })
    } else {
      await this.#executionGuard.finalizeFailed(claimToken, {
        code: failureCodeForHttp(result),
        responseBytes: result.responseBytes,
        evidenceRefs: capture.evidenceRefs
      })
    }
    return freezeStoredResult(httpResultView(result, redirects), trace)
  }

  async executeMediatedHttp(
    input: MediatedHttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>> {
    const familyId = this.#prepareCommonInput(input)
    if (input.method !== 'GET' && input.method !== 'HEAD') {
      throw new Error('Mediated HTTP only allows GET or HEAD.')
    }
    const timeoutMs = assertPositiveInteger(input.timeoutMs, 'HTTP timeout', 120_000)
    const maxResponseBytes = assertPositiveInteger(
      input.maxResponseBytes,
      'HTTP response budget',
      16_777_216
    )
    const desiredUrl = assertCanonicalHttpUrl(input.desiredUrl, 'HTTP desired URL')
    const scan = await this.#repository.getScan(input.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    const target = await this.#repository.getTarget(scan.targetId)
    if (!target) throw new Error('Scan target does not exist.')
    let identityRef: IdentityRef | undefined
    if (input.identityId) {
      const identity = await this.#repository.getIdentity(input.identityId)
      if (!identity) throw new Error('Mediated HTTP identity is missing.')
      identityRef = {
        id: identity.id,
        version: Date.parse(identity.updatedAt),
        ownerRef: identity.targetId,
        scopeSnapshotId: scan.scopeSnapshotId,
        statusSummary: 'active'
      }
    }
    const sessionRef =
      input.sessionId && this.#sessionVault
        ? await this.#sessionVault.sessionGenerationRef(input.sessionId)
        : undefined
    const compiled = await compileMediatedRead(this.#repository, {
      scanId: input.scanId,
      endpointId: input.endpointId,
      requestVariantId: input.requestVariantId,
      desiredUrl,
      method: input.method,
      ownerRef: target.id,
      scopeSnapshotId: scan.scopeSnapshotId,
      hashKey: this.#hashKeyProvider.reference,
      hashKeyProvider: this.#hashKeyProvider,
      executionBinding: {
        stepId: input.stepId,
        purpose: input.purpose,
        adapterKind: 'http'
      },
      ...(identityRef ? { identityRef } : {}),
      ...(sessionRef ? { sessionRef } : {}),
      ...(input.sessionId ? { sessionId: input.sessionId } : {}),
      ...(this.#sessionVault ? { sessionVault: this.#sessionVault } : {})
    })
    const ownerRef = compiled.authorizationContext.ownerRef
    if (!ownerRef) {
      throw new Error('Compiled mediated request lacks owner binding.')
    }
    const wire = materializedWire(compiled)
    const policy = await this.#policyBroker.evaluate({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action: {
        kind: 'http-request',
        targetUrl: wire.url,
        method: wire.method,
        ...(identityRef ? { identityId: identityRef.id } : {}),
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: safeText(input.summary),
        ...(input.payloadSummary
          ? { payloadSummary: safeText(input.payloadSummary) }
          : {}),
        expectedEvidence: safeText(input.expectedEvidence),
        maxRequests: 1,
        timeoutMs,
        maxResponseBytes,
        maxRedirects: 0,
        maxRepeats: 0,
        userApproved: false
      },
      stopConditions: ['Stop after this single reviewed mediated-read step.'],
      authorizedWireRequestHmac: compiled.wireRequestHmac
    })
    const trace = newTrace()
    trace.proposalIds.push(policy.proposal.id)
    trace.policyDecisionIds.push(policy.decision.id)
    if (!policy.decision.allowed || policy.decision.requiresApproval) {
      throw new Error('Security policy rejected the compiled mediated HTTP request.')
    }
    const decidedTimeoutMs = policy.executionLimits?.timeoutMs ?? timeoutMs
    const decidedMaxResponseBytes =
      policy.executionLimits?.maxResponseBytes ?? maxResponseBytes
    const context = await this.#requireDecisionContext(input.scanId, policy.decision.id)
    const window = this.#issuanceWindow(
      policy.decision.validUntil,
      context.scope.validUntil,
      decidedTimeoutMs,
      0,
      undefined
    )
    const issued = await this.#authority.issue({
      scanId: input.scanId,
      familyId,
      policyDecisionId: policy.decision.id,
      stepId: input.stepId,
      compiled,
      capabilityIds: compiled.enabledCapabilityIds,
      ownerRef,
      credentialRef: compiled.authorizationContext.credentialRef,
      ...(compiled.authorizationContext.identityRef
        ? { identityRef: compiled.authorizationContext.identityRef }
        : {}),
      ...(compiled.authorizationContext.sessionRef
        ? { sessionRef: compiled.authorizationContext.sessionRef }
        : {}),
      purpose: input.purpose,
      adapterKind: 'http',
      retryClass: 'deterministic-readonly',
      limits: {
        timeoutMs: decidedTimeoutMs,
        maxResponseBytes: decidedMaxResponseBytes,
        maxRedirects: 0
      },
      ...window
    })
    trace.grantIds.push(issued.grant.id)
    trace.leaseIds.push(issued.lease.id)
    const toolCallId = await this.#recordToolCall(issued, 'http-runner', HTTP_TOOL_VERSION)
    trace.toolCallIds.push(toolCallId)

    const requestId = randomUUID()
    const abort = (): void => {
      void this.#httpRunner.cancel(requestId)
    }
    input.signal?.addEventListener('abort', abort, { once: true })
    let rawResult: unknown
    const sessionRefIssued = issued.grant.sessionRef
    const vault = this.#sessionVault
    const pendingCookies: Array<{ readonly cookie: string; readonly url: string }> = []
    try {
      rawResult = await this.#httpRunner.execute({
        requestId,
        leaseId: issued.lease.id,
        wire,
        timeoutMs: decidedTimeoutMs,
        maxResponseBytes: decidedMaxResponseBytes,
        ...(input.signal ? { signal: input.signal } : {}),
        ...(vault && sessionRefIssued
          ? {
              setCookieSink: (cookies: readonly string[], requestUrl: string) => {
                for (const cookie of cookies) {
                  pendingCookies.push({ cookie, url: requestUrl })
                }
              }
            }
          : {})
      })
    } finally {
      input.signal?.removeEventListener('abort', abort)
    }
    if (vault && sessionRefIssued) {
      for (const pending of pendingCookies) {
        try {
          await vault.ingestSetCookie(sessionRefIssued.id, pending.cookie, pending.url)
        } catch {
          // Vault-side rejection must not fail an already authorized request.
        }
      }
    }
    let result
    try {
      result = validateHttpRunnerOutput<ExecutionClaimToken>(rawResult, {
        requestId,
        wire,
        timeoutMs: decidedTimeoutMs,
        maxResponseBytes: decidedMaxResponseBytes
      })
    } catch (error) {
      const claimToken = claimTokenFromRunnerOutputError<ExecutionClaimToken>(error)
      try {
        await this.#executionGuard.rejectInvalidRunnerOutput(issued.lease.id, claimToken)
      } catch {
        // Recovered as interrupted.
      }
      throw new Error('HTTP runner output failed closed validation.')
    }
    const redirects: HttpRedirectObservation[] = []
    const claimToken = result.claimToken
    if (!claimToken) {
      await this.#executionGuard.revoke(issued.lease.id, 'guard-rejected')
      return freezeStoredResult(httpResultView(result, redirects), trace)
    }
    const hashRejected = Boolean(
      input.expectedContentHash &&
        result.status === 'succeeded' &&
        result.responseBody !== undefined &&
        sha256Bytes(result.responseBody) !== input.expectedContentHash
    )
    const redirectRejected = Boolean(result.status === 'succeeded' && result.redirectLocation)
    const executionState =
      redirectRejected || hashRejected ? 'failed' : executionStateForHttp(result)
    const interactionId = randomUUID()
    const summaries = this.#httpCaptureSummaries(
      issued,
      wire,
      result,
      redirectRejected ? 'redirect-rejected' : hashRejected ? 'runner-output-invalid' : undefined
    )
    let capture: PersistedCapture
    const unboundEvidence: EvidenceCleanupRecord[] = []
    let auditStage: 'evidence' | 'interaction' = 'evidence'
    try {
      capture = await this.#persistCaptures(
        {
          issued,
          workspaceId: context.workspaceId,
          executionState,
          summaries
        },
        unboundEvidence
      )
      auditStage = 'interaction'
      const persistedInteractionId = await this.#executionGuard.recordInteractionAudit(
        claimToken,
        {
          interaction: {
            id: interactionId,
            scanId: input.scanId,
            endpointId: input.endpointId,
            ...(identityRef ? { identityId: identityRef.id } : {}),
            policyDecisionId: policy.decision.id,
            requestRef: capture.requestEvidenceId,
            responseRef: capture.resultEvidenceId,
            requestSummary: capture.requestInteractionSummary,
            responseSummary: capture.resultInteractionSummary,
            ...(result.statusCode !== undefined ? { statusCode: result.statusCode } : {}),
            durationMs: result.durationMs
          },
          evidenceLinks: capture.evidenceLinks
        }
      )
      if (persistedInteractionId !== interactionId) {
        throw new Error('Execution interaction identity changed during audit persistence.')
      }
      trace.interactionIds.push(interactionId)
      trace.evidenceRefs.push(...capture.evidenceRefs)
    } catch (error) {
      const retainedEvidenceRefs = await this.#discardUnboundCaptures(unboundEvidence)
      await this.#finalizeAuditFailure(claimToken, result.responseBytes, retainedEvidenceRefs)
      throw new Error(`HTTP execution ${auditStage} persistence failed.`, {
        cause: error
      })
    }

    if (redirectRejected || hashRejected) {
      await this.#executionGuard.finalizeFailed(claimToken, {
        code: redirectRejected ? 'redirect-rejected' : 'runner-output-invalid',
        responseBytes: result.responseBytes,
        evidenceRefs: capture.evidenceRefs
      })
      return freezeStoredResult(
        Object.freeze({
          ...httpResultView(result, redirects),
          status: 'failed' as const,
          errorCode: redirectRejected ? 'redirect-rejected' : 'runner-output-invalid',
          errorMessage: redirectRejected
            ? 'The HTTP redirect target was rejected.'
            : 'The mediated response hash does not match the frozen AssetManifest.'
        }),
        trace
      )
    }
    if (result.status === 'succeeded') {
      await this.#executionGuard.finalizeSucceeded(claimToken, {
        responseBytes: result.responseBytes,
        evidenceRefs: capture.evidenceRefs
      })
    } else {
      await this.#executionGuard.finalizeFailed(claimToken, {
        code: failureCodeForHttp(result),
        responseBytes: result.responseBytes,
        evidenceRefs: capture.evidenceRefs
      })
    }
    return freezeStoredResult(httpResultView(result, redirects), trace)
  }

  async #ensureL2InventoryEndpoint(
    input: L2HttpExecutionStepInput,
    desiredUrl: string
  ): Promise<string> {
    const mutating = input.method !== 'GET'
    const inventory = new InventoryService(
      this.#repository,
      DEFAULT_PROBE_CAPABILITY_CATALOG
    )
    const persisted = await inventory.upsertInventory({
      scanId: input.scanId,
      method: input.method,
      url: desiredUrl,
      ...(mutating ? { contentType: 'application/json' } : {}),
      bodyShape: mutating
        ? { rootType: 'object', fields: l2JsonBodyFields(input.jsonBody) }
        : { rootType: 'none', fields: [] },
      codec: mutating ? 'json' : 'none',
      transport: 'standard-http',
      allowedHeaders: mutating
        ? [{ name: 'x-csrf-token', valueType: 'string', required: true }]
        : [],
      selectors: [
        { kind: 'cookie', name: 'sid', valueType: 'string', required: true },
        ...(mutating
          ? [
              {
                kind: 'header' as const,
                name: 'x-csrf-token',
                valueType: 'string' as const,
                required: true
              }
            ]
          : [])
      ],
      templateVersion: '1.0.0',
      requiredCapabilityIds: mutating
        ? ['http.reviewed-read', 'http.test-object-write']
        : ['http.reviewed-read'],
      preview: { url: desiredUrl },
      source: {
        type: 'l2.execution',
        sourceHash: sha256Text(
          canonicalJson({
            scanId: input.scanId,
            method: input.method,
            url: desiredUrl
          })
        ),
        confidence: 1
      }
    })
    return persisted.endpoint.id
  }

  async #rejectUnsupported(
    input: UnsupportedExecutionStepInput
  ): Promise<never> {
    if (
      typeof input !== 'object' ||
      input === null ||
      typeof input.adapterKind !== 'string'
    ) {
      throw new Error('Execution adapter input is invalid.')
    }
    throw new Error(
      `Execution adapter ${safeText(input.adapterKind, 128)} is not implemented.`
    )
  }

  async #executeHttp(
    input: HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>> {
    const familyId = this.#prepareCommonInput(input)
    const timeoutMs = assertPositiveInteger(
      input.timeoutMs,
      'HTTP timeout',
      120_000
    )
    const maxResponseBytes = assertPositiveInteger(
      input.maxResponseBytes,
      'HTTP response budget',
      16_777_216
    )
    const maxRedirects = assertNonNegativeInteger(
      input.maxRedirects,
      'HTTP redirect budget',
      10
    )
    let desiredUrl = assertCanonicalHttpUrl(
      input.desiredUrl,
      'HTTP desired URL'
    )
    let endpointId = input.endpointId
    let credentialMode: 'include' | 'omit' =
      input.identityId === undefined ? 'omit' : 'include'
    let credentialOrigin = new URL(desiredUrl).origin
    let parent: IssuedExecutionAuthority | undefined
    let finalResult: HttpExecutionResult<ExecutionClaimToken> | undefined
    const redirects: HttpRedirectObservation[] = []
    const trace = newTrace()

    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      if (input.signal?.aborted) {
        throw new Error('HTTP execution was cancelled before issuance.')
      }
      const compiled = await this.#requestAdapter.compile({
        scanId: input.scanId,
        endpointId,
        desiredTargetUrl: desiredUrl,
        familyId,
        ...(input.identityId ? { identityId: input.identityId } : {}),
        credentialMode,
        ...(hop === 0 && input.mutation
          ? input.mutation.kind === 'path'
            ? {
                pathMutation: {
                  selectorName: input.mutation.name,
                  segmentIndex: input.mutation.segmentIndex,
                  value: input.mutation.value
                }
              }
            : {
                queryMutation: {
                  kind: 'query' as const,
                  name: input.mutation.name,
                  occurrence: input.mutation.occurrence,
                  value: input.mutation.value
                }
              }
          : {}),
        executionBinding: {
          stepId: input.stepId,
          purpose: input.purpose,
          adapterKind: 'http'
        }
      })
      if (
        compiled.ownerRef === undefined ||
        compiled.scopeSnapshotId.length === 0
      ) {
        throw new Error('Compiled HTTP request lacks owner or scope binding.')
      }
      const wire = materializedWire(compiled.compiledRequest)
      assertCredentialModeMatchesWire(wire, credentialMode)
      const ssrfTargetUrl = ssrfTargetUrlForHttpStep(input, wire.url, hop)
      const policy = await this.#policyBroker.evaluate({
        scanId: input.scanId,
        agentRunId: input.agentRunId,
        action: {
          kind: 'http-request',
          targetUrl: wire.url,
          method: wire.method,
          ...(compiled.identityRef
            ? { identityId: compiled.identityRef.id }
            : {}),
          probeLevel: 'active-safe',
          sideEffect: 'none',
          summary: safeText(input.summary),
          ...(input.payloadSummary
            ? { payloadSummary: safeText(input.payloadSummary) }
            : {}),
          expectedEvidence: safeText(input.expectedEvidence),
          maxRequests: 1,
          timeoutMs,
          maxResponseBytes,
          maxRedirects,
          maxRepeats: 0,
          userApproved: false
        },
        stopConditions: ['Stop after this single reviewed execution step.'],
        authorizedWireRequestHmac:
          compiled.compiledRequest.wireRequestHmac,
        ...(ssrfTargetUrl ? { ssrfTargetUrl } : {})
      })
      trace.proposalIds.push(policy.proposal.id)
      trace.policyDecisionIds.push(policy.decision.id)
      if (!policy.decision.allowed || policy.decision.requiresApproval) {
        throw new Error('Security policy rejected the compiled HTTP request.')
      }
      const decidedTimeoutMs =
        policy.executionLimits?.timeoutMs ?? timeoutMs
      const decidedMaxResponseBytes =
        policy.executionLimits?.maxResponseBytes ?? maxResponseBytes
      const decidedMaxRedirects =
        policy.executionLimits?.maxRedirects ?? maxRedirects
      const context = await this.#requireDecisionContext(
        input.scanId,
        policy.decision.id
      )
      const window = this.#issuanceWindow(
        policy.decision.validUntil,
        context.scope.validUntil,
        decidedTimeoutMs,
        decidedMaxRedirects,
        parent?.grant.validUntil
      )
      const pinnedSessionRef =
        !parent && input.sessionId && this.#sessionVault
          ? await this.#sessionVault.sessionGenerationRef(input.sessionId)
          : undefined
      const issued = parent
        ? await this.#authority.issueRedirectChild({
            parentGrantId: parent.grant.id,
            parentLeaseId: parent.lease.id,
            policyDecisionId: policy.decision.id,
            stepId: parent.grant.stepId,
            compiled: compiled.compiledRequest,
            credentialRef: compiled.credentialRef,
            limits: {
              timeoutMs: decidedTimeoutMs,
              maxResponseBytes: decidedMaxResponseBytes,
              maxRedirects: decidedMaxRedirects
            },
            ...window
          })
        : await this.#authority.issue({
            scanId: input.scanId,
            familyId,
            policyDecisionId: policy.decision.id,
            stepId: input.stepId,
            compiled: compiled.compiledRequest,
            capabilityIds: compiled.capabilityIds,
            ownerRef: compiled.ownerRef,
            credentialRef: compiled.credentialRef,
            ...(compiled.identityRef
              ? { identityRef: compiled.identityRef }
              : {}),
            ...(pinnedSessionRef ? { sessionRef: pinnedSessionRef } : {}),
            purpose: input.purpose,
            adapterKind: 'http',
            retryClass:
              input.purpose === 'read'
                ? 'deterministic-readonly'
                : 'never',
            limits: {
              timeoutMs: decidedTimeoutMs,
              maxResponseBytes: decidedMaxResponseBytes,
              maxRedirects: decidedMaxRedirects
            },
            ...window
          })
      trace.grantIds.push(issued.grant.id)
      trace.leaseIds.push(issued.lease.id)
      const toolCallId = await this.#recordToolCall(
        issued,
        'http-runner',
        HTTP_TOOL_VERSION
      )
      trace.toolCallIds.push(toolCallId)

      const requestId = randomUUID()
      const abort = (): void => {
        void this.#httpRunner.cancel(requestId)
      }
      input.signal?.addEventListener('abort', abort, { once: true })
      let rawResult: unknown
      const sessionRef = issued.grant.sessionRef
      const vault = this.#sessionVault
      const pendingCookies: Array<{ readonly cookie: string; readonly url: string }> =
        []
      try {
        rawResult = await this.#httpRunner.execute({
          requestId,
          leaseId: issued.lease.id,
          wire,
          timeoutMs: decidedTimeoutMs,
          maxResponseBytes: decidedMaxResponseBytes,
          ...(input.signal ? { signal: input.signal } : {}),
          ...(vault && sessionRef
            ? {
                setCookieSink: (cookies: readonly string[], requestUrl: string) => {
                  for (const cookie of cookies) {
                    pendingCookies.push({ cookie, url: requestUrl })
                  }
                }
              }
            : {})
        })
      } finally {
        input.signal?.removeEventListener('abort', abort)
      }
      if (vault && sessionRef) {
        for (const pending of pendingCookies) {
          try {
            await vault.ingestSetCookie(sessionRef.id, pending.cookie, pending.url)
          } catch {
            // Vault-side rejection must not fail an already authorized request.
          }
        }
      }
      let result: HttpExecutionResult<ExecutionClaimToken>
      try {
        result = validateHttpRunnerOutput<ExecutionClaimToken>(rawResult, {
          requestId,
          wire,
          timeoutMs: decidedTimeoutMs,
          maxResponseBytes: decidedMaxResponseBytes
        })
      } catch (error) {
        const claimToken =
          claimTokenFromRunnerOutputError<ExecutionClaimToken>(error)
        try {
          await this.#executionGuard.rejectInvalidRunnerOutput(
            issued.lease.id,
            claimToken
          )
        } catch {
          // A claimed-but-unknown or concurrently terminal lease is recovered
          // as interrupted. A token for another lease is never consumed here.
        }
        throw new Error('HTTP runner output failed closed validation.')
      }
      finalResult = result
      const claimToken = result.claimToken
      if (!claimToken) {
        await this.#executionGuard.revoke(
          issued.lease.id,
          'guard-rejected'
        )
        return freezeStoredResult(httpResultView(result, redirects), trace)
      }
      let redirectTarget:
        | Readonly<{
            url: string
            endpointId: string
            credentialMode: 'include' | 'omit'
            credentialOrigin: string
          }>
        | undefined
      let redirectRejected = false
      if (result.status === 'succeeded' && result.redirectLocation) {
        if (hop >= maxRedirects) {
          redirectRejected = true
        } else {
          try {
            const redirectMethod = this.#redirectMethod(
              wire.method,
              result.statusCode
            )
            const nextUrl = this.#resolveRedirect(
              desiredUrl,
              result.redirectLocation
            )
            const nextOrigin = new URL(nextUrl).origin
            const nextCredentialMode =
              nextOrigin === credentialOrigin ? credentialMode : 'omit'
            redirectTarget = Object.freeze({
              url: nextUrl,
              endpointId: await this.#reviewedRedirectEndpoint(
                input.scanId,
                nextUrl,
                redirectMethod
              ),
              credentialMode: nextCredentialMode,
              credentialOrigin:
                nextCredentialMode === 'omit' ? nextOrigin : credentialOrigin
            })
          } catch (error) {
            if (error instanceof RedirectAuthorizationError) {
              await this.#repository.incrementScanSecurityCounter(
                input.scanId,
                error.code
              )
            }
            redirectRejected = true
          }
        }
      }
      const executionState = redirectRejected
        ? 'failed'
        : executionStateForHttp(result)
      const interactionId = randomUUID()
      const summaries = this.#httpCaptureSummaries(
        issued,
        wire,
        result,
        redirectRejected ? 'redirect-rejected' : undefined
      )
      let capture: PersistedCapture
      const unboundEvidence: EvidenceCleanupRecord[] = []
      let auditStage: 'evidence' | 'interaction' = 'evidence'
      try {
        capture = await this.#persistCaptures({
          issued,
          workspaceId: context.workspaceId,
          executionState,
          summaries
        }, unboundEvidence)
        auditStage = 'interaction'
        const persistedInteractionId =
          await this.#executionGuard.recordInteractionAudit(claimToken, {
            interaction: {
              id: interactionId,
              scanId: input.scanId,
              endpointId,
              ...(compiled.identityRef
                ? { identityId: compiled.identityRef.id }
                : {}),
              policyDecisionId: policy.decision.id,
              requestRef: capture.requestEvidenceId,
              responseRef: capture.resultEvidenceId,
              requestSummary: capture.requestInteractionSummary,
              responseSummary: capture.resultInteractionSummary,
              ...(result.statusCode !== undefined
                ? { statusCode: result.statusCode }
                : {}),
              durationMs: result.durationMs
            },
            evidenceLinks: capture.evidenceLinks
          })
        if (persistedInteractionId !== interactionId) {
          throw new Error(
            'Execution interaction identity changed during audit persistence.'
          )
        }
        trace.interactionIds.push(interactionId)
        trace.evidenceRefs.push(...capture.evidenceRefs)
      } catch {
        const retainedEvidenceRefs =
          await this.#discardUnboundCaptures(unboundEvidence)
        await this.#finalizeAuditFailure(
          claimToken,
          result.responseBytes,
          retainedEvidenceRefs
        )
        throw new Error(`HTTP execution ${auditStage} persistence failed.`)
      }

      if (redirectRejected) {
        await this.#executionGuard.finalizeFailed(claimToken, {
          code: 'redirect-rejected',
          responseBytes: result.responseBytes,
          evidenceRefs: capture.evidenceRefs
        })
      } else if (result.status === 'succeeded') {
        await this.#executionGuard.finalizeSucceeded(claimToken, {
          responseBytes: result.responseBytes,
          evidenceRefs: capture.evidenceRefs
        })
      } else {
        await this.#executionGuard.finalizeFailed(claimToken, {
          code: failureCodeForHttp(result),
          responseBytes: result.responseBytes,
          evidenceRefs: capture.evidenceRefs
        })
        return freezeStoredResult(httpResultView(result, redirects), trace)
      }

      if (redirectRejected) {
        return freezeStoredResult(
          Object.freeze({
            ...httpResultView(result, redirects),
            status: 'failed' as const,
            errorCode: 'redirect-rejected',
            errorMessage: 'The HTTP redirect target was rejected.'
          }),
          trace
        )
      }
      if (!redirectTarget) {
        return freezeStoredResult(httpResultView(result, redirects), trace)
      }
      redirects.push(
        Object.freeze({
          hop: hop + 1,
          from: safeUrl(desiredUrl),
          to: safeUrl(redirectTarget.url),
          statusCode: result.statusCode ?? 0,
          policyDecisionId: policy.decision.id,
          grantId: issued.grant.id,
          leaseId: issued.lease.id
        })
      )
      desiredUrl = redirectTarget.url
      endpointId = redirectTarget.endpointId
      credentialMode = redirectTarget.credentialMode
      credentialOrigin = redirectTarget.credentialOrigin
      parent = issued
    }

    if (!finalResult) throw new Error('HTTP execution produced no result.')
    return freezeStoredResult(httpResultView(finalResult, redirects), trace)
  }

  async #executeBrowserOffline(
    input: BrowserOfflineExecutionStepInput
  ): Promise<StoredExecutionResult<BrowserExecutionResultView>> {
    const familyId = this.#prepareCommonInput(input)
    const timeoutMs = assertPositiveInteger(
      input.timeoutMs,
      'Browser timeout',
      120_000
    )
    const maxDomBytes = assertPositiveInteger(
      input.maxDomBytes,
      'Browser result budget',
      16_777_216
    )
    const baseUrl = assertCanonicalHttpUrl(
      input.baseUrl,
      'Browser base URL'
    )
    if (
      typeof input.html !== 'string' ||
      !isWellFormedUnicode(input.html) ||
      Buffer.byteLength(input.html, 'utf8') > MAX_BROWSER_HTML_BYTES
    ) {
      throw new Error('Browser HTML input is invalid.')
    }
    if (input.marker !== undefined && input.marker.length > 512) {
      throw new Error('Browser marker exceeds its supported limit.')
    }
    if (input.contentSecurityPolicy !== undefined && input.contentSecurityPolicy.length > 8_192) {
      throw new Error('Browser content security policy exceeds its supported limit.')
    }
    if (input.signal?.aborted) {
      throw new Error('Browser execution was cancelled before issuance.')
    }
    const scan = await this.#repository.getScanRow(input.scanId)
    if (!scan) throw new Error('Browser execution scan is missing.')
    const compiled = this.#compileBrowserOffline(
      input,
      scan.targetId,
      scan.scopeSnapshotId
    )
    const wire = materializedWire(compiled)
    const policy = await this.#policyBroker.evaluate({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action: {
        kind: 'browser-action',
        targetUrl: baseUrl,
        method: 'GET',
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: safeText(input.summary),
        ...(input.payloadSummary
          ? { payloadSummary: safeText(input.payloadSummary) }
          : {}),
        expectedEvidence: safeText(input.expectedEvidence),
        maxRequests: 1,
        timeoutMs,
        maxResponseBytes: maxDomBytes,
        maxRedirects: 0,
        maxRepeats: 0,
        userApproved: false
      },
      stopConditions: ['Stop after this isolated offline browser action.'],
      authorizedWireRequestHmac: compiled.wireRequestHmac
    })
    if (!policy.decision.allowed || policy.decision.requiresApproval) {
      throw new Error('Security policy rejected the offline browser action.')
    }
    const context = await this.#requireDecisionContext(
      input.scanId,
      policy.decision.id
    )
    const window = this.#issuanceWindow(
      policy.decision.validUntil,
      context.scope.validUntil,
      timeoutMs,
      0
    )
    const issued = await this.#authority.issue({
      scanId: input.scanId,
      familyId,
      policyDecisionId: policy.decision.id,
      stepId: input.stepId,
      compiled,
      capabilityIds: [BROWSER_CAPABILITY],
      ownerRef: scan.targetId,
      credentialRef: null,
      purpose: input.purpose,
      adapterKind: 'browser-offline',
      retryClass:
        input.purpose === 'read' ? 'deterministic-readonly' : 'never',
      limits: {
        timeoutMs,
        maxResponseBytes: maxDomBytes,
        maxRedirects: 0
      },
      ...window
    })
    const trace = newTrace()
    trace.proposalIds.push(policy.proposal.id)
    trace.policyDecisionIds.push(policy.decision.id)
    trace.grantIds.push(issued.grant.id)
    trace.leaseIds.push(issued.lease.id)
    const toolCallId = await this.#recordToolCall(
      issued,
      'browser-runner',
      BROWSER_TOOL_VERSION
    )
    trace.toolCallIds.push(toolCallId)

    let claimToken: ExecutionClaimToken
    const requestId = randomUUID()
    try {
      claimToken = await this.#executionGuard.claimOffline({
        leaseId: issued.lease.id,
        wire,
        limits: {
          timeoutMs,
          maxResponseBytes: maxDomBytes
        }
      })
    } catch {
      await this.#executionGuard.revoke(
        issued.lease.id,
        'guard-rejected'
      )
      throw new Error('Offline browser execution guard rejected the lease.')
    }

    const runnerRequest = Object.freeze({
      requestId,
      baseUrl,
      html: input.html,
      action: input.action,
      ...(input.marker !== undefined ? { marker: input.marker } : {}),
      ...(input.contentSecurityPolicy !== undefined
        ? { contentSecurityPolicy: input.contentSecurityPolicy }
        : {}),
      timeoutMs,
      maxDomBytes,
      ...(input.signal ? { signal: input.signal } : {})
    })
    let result: BrowserExecutionResult | undefined
    if (input.signal?.aborted) {
      result = browserServiceFailureResult(requestId, baseUrl, 'cancelled')
    } else {
      try {
        await this.#executionGuard.markDispatched(claimToken)
      } catch {
        result = browserServiceFailureResult(
          requestId,
          baseUrl,
          'dispatch-mark-failed'
        )
      }
    }

    if (result === undefined) {
      const abort = (): void => {
        void this.#browserRunner.cancel(requestId)
      }
      input.signal?.addEventListener('abort', abort, { once: true })
      let rawResult: unknown
      try {
        rawResult = await this.#browserRunner.execute(runnerRequest)
      } catch {
        await this.#executionGuard.finalizeFailed(claimToken, {
          code: 'network-error',
          responseBytes: 0,
          evidenceRefs: []
        })
        throw new Error('Offline browser runner failed.')
      } finally {
        input.signal?.removeEventListener('abort', abort)
      }
      try {
        result = validateBrowserRunnerOutput(rawResult, {
          request: runnerRequest,
          maxResultBytes: maxDomBytes
        })
      } catch {
        await this.#executionGuard.finalizeFailed(claimToken, {
          code: 'runner-output-invalid',
          responseBytes: 0,
          evidenceRefs: []
        })
        throw new Error('Offline browser runner output failed closed validation.')
      }
      try {
        await this.#executionGuard.markResponseStarted(claimToken)
      } catch {
        result = browserServiceFailureResult(
          requestId,
          baseUrl,
          'response-start-mark-failed'
        )
      }
    }

    const executionState = executionStateForBrowser(result)
    const responseBytes = responseBytesForBrowser(result)
    const interactionId = randomUUID()
    const summaries = this.#browserCaptureSummaries(issued, input, result)
    let capture: PersistedCapture | undefined
    const unboundEvidence: EvidenceCleanupRecord[] = []
    let auditStage: 'evidence' | 'interaction' = 'evidence'
    try {
      capture = await this.#persistCaptures({
        issued,
        workspaceId: context.workspaceId,
        executionState,
        summaries
      }, unboundEvidence)
      const reviewable = await this.#persistReviewableBrowserEvidence({
        issued,
        executionState,
        result,
        unboundEvidence
      })
      capture = mergeReviewableCapture(capture, reviewable)
      auditStage = 'interaction'
      const persistedInteractionId =
        await this.#executionGuard.recordInteractionAudit(claimToken, {
          interaction: {
            id: interactionId,
            scanId: input.scanId,
            policyDecisionId: policy.decision.id,
            requestRef: capture.requestEvidenceId,
            responseRef: capture.resultEvidenceId,
            requestSummary: capture.requestInteractionSummary,
            responseSummary: capture.resultInteractionSummary,
            durationMs: result.durationMs
          },
          evidenceLinks: capture.evidenceLinks
        })
      if (persistedInteractionId !== interactionId) {
        throw new Error(
          'Execution interaction identity changed during audit persistence.'
        )
      }
      trace.interactionIds.push(interactionId)
      trace.evidenceRefs.push(...capture.evidenceRefs)
    } catch {
      const retainedEvidenceRefs =
        await this.#discardUnboundCaptures(unboundEvidence)
      const hashOnlyRefs = capture?.hashOnlyEvidenceRefs
      const finalizeRefs = hashOnlyRefs
        ? retainedEvidenceRefs.filter((id) => hashOnlyRefs.includes(id))
        : retainedEvidenceRefs
      await this.#finalizeAuditFailure(
        claimToken,
        responseBytes,
        finalizeRefs
      )
      throw new Error(`Browser execution ${auditStage} persistence failed.`)
    }
    if (!capture) {
      throw new Error('Browser execution capture is missing after audit.')
    }

    if (result.status === 'succeeded') {
      await this.#executionGuard.finalizeSucceeded(claimToken, {
        responseBytes,
        evidenceRefs: capture.hashOnlyEvidenceRefs
      })
    } else {
      await this.#executionGuard.finalizeFailed(claimToken, {
        code: failureCodeForBrowser(result),
        responseBytes,
        evidenceRefs: capture.hashOnlyEvidenceRefs
      })
    }
    return freezeStoredResult(browserResultView(result), trace, {
      ...(capture.reviewableDomOrScreenshotEvidence
        ? { reviewableDomOrScreenshotEvidence: true }
        : {})
    })
  }

  #prepareCommonInput(
    input:
      | HttpExecutionStepInput
      | BrowserOfflineExecutionStepInput
      | L2HttpExecutionStepInput
      | MediatedHttpExecutionStepInput
  ): LegacyV1VulnerabilityFamily {
    if (!input || typeof input !== 'object') {
      throw new Error('Execution step input is invalid.')
    }
    const familyId = LegacyV1VulnerabilityFamilySchema.parse(input.familyId)
    DefinitionIdSchema.parse(input.stepId)
    ExecutionPurposeSchema.parse(input.purpose)
    if (
      typeof input.scanId !== 'string' ||
      input.scanId.length === 0 ||
      typeof input.agentRunId !== 'string' ||
      input.agentRunId.length === 0 ||
      typeof input.summary !== 'string' ||
      input.summary.length === 0 ||
      typeof input.expectedEvidence !== 'string' ||
      input.expectedEvidence.length === 0
    ) {
      throw new Error('Execution step binding is invalid.')
    }
    return familyId
  }

  async #requireDecisionContext(
    scanId: string,
    policyDecisionId: string
  ): Promise<
    NonNullable<
      Awaited<ReturnType<AgentGoRepository['getExecutionDecision']>>
    >
  > {
    const context = await this.#repository.getExecutionDecision(
      policyDecisionId
    )
    if (
      !context ||
      context.scanId !== scanId ||
      context.decision.id !== policyDecisionId
    ) {
      throw new Error('Execution policy context is missing or mismatched.')
    }
    return context
  }

  #issuanceWindow(
    policyValidUntil: string | undefined,
    scopeValidUntil: string | undefined,
    timeoutMs: number,
    maxRedirects: number,
    parentValidUntil?: string
  ): IssuanceWindow {
    const now = canonicalNow(this.#clock)
    const candidates = [
      policyValidUntil,
      scopeValidUntil,
      parentValidUntil
    ]
      .filter((value): value is string => value !== undefined)
      .map(Date.parse)
    if (
      candidates.length === 0 ||
      candidates.some((value) => !Number.isFinite(value))
    ) {
      throw new Error('Execution authorization has no canonical expiry.')
    }
    const externalExpiry = Math.min(...candidates)
    const hopWindowMs = timeoutMs + CAPTURE_GRACE_MS
    const requiredWindowMs =
      (parentValidUntil === undefined ? maxRedirects + 1 : 1) * hopWindowMs
    if (requiredWindowMs > MAX_GRANT_WINDOW_MS) {
      throw new Error('Execution redirect chain exceeds the grant window limit.')
    }
    const requiredUntil = now + requiredWindowMs
    if (externalExpiry < requiredUntil) {
      throw new Error(
        'Execution authorization does not cover timeout and capture grace.'
      )
    }
    const grantValidUntil =
      parentValidUntil === undefined
        ? Math.min(externalExpiry, requiredUntil)
        : externalExpiry
    const leaseExpiresAt = Math.min(
      grantValidUntil,
      now + hopWindowMs
    )
    return Object.freeze({
      grantValidUntil: new Date(grantValidUntil).toISOString(),
      leaseExpiresAt: new Date(leaseExpiresAt).toISOString()
    })
  }

  async #recordToolCall(
    issued: IssuedExecutionAuthority,
    toolName: string,
    toolVersion: string
  ): Promise<string> {
    return this.#repository.recordToolCall({
      scanId: issued.grant.scanId,
      policyDecisionId: issued.grant.policyDecisionId,
      executionLeaseId: issued.lease.id,
      toolName,
      toolVersion,
      argumentHash: sha256Text(
        canonicalJson({
          domain: 'agentgo.execution-tool-call.v1',
          adapterKind: issued.grant.adapterKind,
          grantId: issued.grant.id,
          leaseId: issued.lease.id,
          stepId: issued.grant.stepId,
          wireRequestHmacDigest: issued.grant.wireRequestHmac.digest
        })
      ),
      status: 'running'
    })
  }

  #httpCaptureSummaries(
    issued: IssuedExecutionAuthority,
    wire: MaterializedWireRequest,
    result: HttpExecutionResult<ExecutionClaimToken>,
    outcomeErrorCode?: 'redirect-rejected' | 'runner-output-invalid'
  ): readonly [SafeCaptureSummary, SafeCaptureSummary] {
    return Object.freeze([
      Object.freeze({
        source: 'http-request-summary',
        value: Object.freeze({
          schemaVersion: 'execution-http-request-summary.v1',
          requestId: result.requestId,
          grantId: issued.grant.id,
          leaseId: issued.lease.id,
          method: wire.method,
          target: safeUrl(wire.url),
          targetHash: sha256Text(wire.url),
          headerNames: Object.freeze(
            wire.headers.map(({ name }) => name)
          ),
          requestBodySha256: result.requestBodySha256 ?? null,
          wireRequestHmacDigest: issued.grant.wireRequestHmac.digest
        })
      }),
      Object.freeze({
        source: 'http-response-summary',
        value: Object.freeze({
          schemaVersion: 'execution-http-response-summary.v1',
          requestId: result.requestId,
          status: outcomeErrorCode ? 'failed' : result.status,
          statusCode: result.statusCode ?? null,
          responseHeaderNames: Object.freeze(
            Object.keys(result.responseHeaders).sort()
          ),
          responseBodySha256: result.responseBodySha256 ?? null,
          responseBytes: result.responseBytes,
          durationMs: result.durationMs,
          resolvedAddressCount: result.resolvedAddresses.length,
          redirectObserved: result.redirectLocation !== undefined,
          errorCode: outcomeErrorCode ?? result.errorCode ?? null
        })
      })
    ])
  }

  #browserCaptureSummaries(
    issued: IssuedExecutionAuthority,
    input: BrowserOfflineExecutionStepInput,
    result: BrowserExecutionResult
  ): readonly [SafeCaptureSummary, SafeCaptureSummary] {
    return Object.freeze([
      Object.freeze({
        source: 'browser-request-summary',
        value: Object.freeze({
          schemaVersion: 'execution-browser-request-summary.v1',
          requestId: result.requestId,
          grantId: issued.grant.id,
          leaseId: issued.lease.id,
          baseUrl: safeUrl(input.baseUrl),
          baseUrlHash: sha256Text(input.baseUrl),
          htmlSha256: sha256Text(input.html),
          action: input.action,
          markerPresent: input.marker !== undefined,
          contentSecurityPolicyPresent:
            input.contentSecurityPolicy !== undefined,
          wireRequestHmacDigest: issued.grant.wireRequestHmac.digest
        })
      }),
      Object.freeze({
        source: 'browser-result-summary',
        value: Object.freeze({
          schemaVersion: 'execution-browser-result-summary.v1',
          requestId: result.requestId,
          status: result.status,
          finalUrl: safeUrl(result.finalUrl),
          finalUrlHash: sha256Text(result.finalUrl),
          linkCount: result.links.length,
          formCount: result.forms.length,
          domSha256:
            result.domSnapshot === undefined
              ? null
              : sha256Text(result.domSnapshot),
          screenshotSha256:
            result.screenshot === undefined
              ? null
              : sha256Bytes(result.screenshot),
          markerExecuted: result.markerExecuted ?? null,
          networkRequestsBlocked: result.networkRequestsBlocked,
          durationMs: result.durationMs,
          errorCode: result.errorCode ?? null
        })
      })
    ])
  }

  async #persistCaptures(
    input: PersistCaptureInput,
    unboundEvidence: EvidenceCleanupRecord[]
  ): Promise<PersistedCapture> {
    const persisted: Array<{
      readonly evidenceId: string
      readonly captureDecisionId: string
      readonly role: string
      readonly source: SafeCaptureSummary['source']
    }> = []
    for (const summary of input.summaries) {
      const decision = decisionFor(
        input.issued.evidenceCaptureDecisions,
        summary.source,
        input.executionState
      )
      const content = Buffer.from(canonicalJson(summary.value), 'utf8')
      const result = this.#evidenceCapturePolicy.capture({
        kind: 'bytes',
        context: {
          scanId: input.issued.grant.scanId,
          policyDecisionId: input.issued.grant.policyDecisionId,
          techniqueId: input.issued.grant.techniqueId,
          techniqueVersion: input.issued.grant.techniqueVersion,
          stepId: input.issued.grant.stepId,
          executionState: input.executionState,
          source: summary.source,
          role: decision.role,
          occurredAt: new Date(canonicalNow(this.#clock)).toISOString(),
          content: {
            mediaType: 'application/json',
            charset: 'utf-8',
            contentEncoding: 'identity',
            declaredSizeBytes: content.byteLength
          }
        },
        decision,
        content,
        completeness: 'complete',
        knownTotalBytes: content.byteLength
      })
      if (
        result.state !== 'hash-only' ||
        result.artifacts.length !== 1
      ) {
        throw new Error('Execution summary capture did not produce one hash-only artifact.')
      }
      const artifact = result.artifacts[0] as EvidenceArtifactDraft
      const evidence = await this.#evidenceStore.save({
        workspaceId: input.workspaceId,
        scanId: input.issued.grant.scanId,
        policyDecisionId: input.issued.grant.policyDecisionId,
        type: artifact.type,
        mimeType: artifact.mimeType,
        content: canonicalJson(artifact),
        source: artifact.source,
        createdBy: 'execution-service',
        captureTool: 'evidence-capture-policy',
        captureToolVersion: EXECUTION_SERVICE_VERSION,
        redactionState: 'redacted'
      })
      unboundEvidence.push({
        id: evidence.id,
        filePath: evidence.filePath,
        sha256: evidence.sha256
      })
      persisted.push({
        evidenceId: evidence.id,
        captureDecisionId: decision.id,
        role: artifact.role,
        source: summary.source
      })
    }
    const requestCapture = persisted[0]
    const resultCapture = persisted[1]
    if (!requestCapture || !resultCapture || persisted.length !== 2) {
      throw new Error('Execution capture trace is incomplete.')
    }
    const interactionSummary = (
      capture: typeof requestCapture
    ): Readonly<Record<string, unknown>> =>
      Object.freeze({
        schemaVersion: 'execution-interaction-capture-ref.v1',
        captureState: 'hash-only',
        source: capture.source,
        evidenceRef: capture.evidenceId,
        captureDecisionId: capture.captureDecisionId,
        role: capture.role,
        executionState: input.executionState
      })
    const evidenceLinks: ExecutionInteractionAuditInput['evidenceLinks'] =
      Object.freeze([
        Object.freeze({
          evidenceId: requestCapture.evidenceId,
          captureDecisionId: requestCapture.captureDecisionId,
          role: requestCapture.role,
          ordinal: 0
        }),
        Object.freeze({
          evidenceId: resultCapture.evidenceId,
          captureDecisionId: resultCapture.captureDecisionId,
          role: resultCapture.role,
          ordinal: 0
        })
      ])
    const hashOnlyEvidenceRefs = Object.freeze([
      requestCapture.evidenceId,
      resultCapture.evidenceId
    ])
    return Object.freeze({
      requestEvidenceId: requestCapture.evidenceId,
      resultEvidenceId: resultCapture.evidenceId,
      evidenceRefs: hashOnlyEvidenceRefs,
      hashOnlyEvidenceRefs,
      evidenceLinks,
      requestInteractionSummary: interactionSummary(requestCapture),
      resultInteractionSummary: interactionSummary(resultCapture)
    })
  }

  async #discardUnboundCaptures(
    evidence: readonly EvidenceCleanupRecord[]
  ): Promise<readonly string[]> {
    const retainedEvidenceRefs: string[] = []
    for (const item of evidence) {
      try {
        const discarded =
          await this.#evidenceStore.discardUnboundEvidence(item)
        if (!discarded) retainedEvidenceRefs.push(item.id)
      } catch {
        // A failed/ambiguous cleanup must be bound to the failed lease instead
        // of being silently abandoned as an untraceable Evidence row.
        retainedEvidenceRefs.push(item.id)
      }
    }
    return Object.freeze(retainedEvidenceRefs)
  }

  async #persistReviewableBrowserEvidence(input: {
    readonly issued: IssuedExecutionAuthority
    readonly executionState: EvidenceCaptureExecutionState
    readonly result: BrowserExecutionResult
    readonly unboundEvidence: EvidenceCleanupRecord[]
  }): Promise<{
    readonly evidenceRefs: readonly string[]
    readonly reviewable: boolean
  }> {
    const empty = {
      evidenceRefs: Object.freeze([]) as readonly string[],
      reviewable: false
    }
    const candidates: Array<{
      readonly source: 'dom-snapshot' | 'browser-screenshot'
      readonly role: 'dom-snapshot' | 'screenshot'
      readonly mediaType: string
      readonly content: Uint8Array
    }> = []
    if (input.result.domSnapshot && input.result.domSnapshot.length > 0) {
      candidates.push({
        source: 'dom-snapshot',
        role: 'dom-snapshot',
        mediaType: 'text/html',
        content: Uint8Array.from(Buffer.from(input.result.domSnapshot, 'utf8'))
      })
    }
    if (input.result.screenshot && input.result.screenshot.byteLength > 0) {
      candidates.push({
        source: 'browser-screenshot',
        role: 'screenshot',
        mediaType: 'image/png',
        content: Uint8Array.from(input.result.screenshot)
      })
    }
    if (candidates.length === 0) return empty
    const occurredAt = new Date(canonicalNow(this.#clock)).toISOString()
    const evidenceRefs: string[] = []
    for (const candidate of candidates) {
      const rawDecision = reviewableDecisionFor(
        input.issued.evidenceCaptureDecisions,
        candidate.source,
        input.executionState
      )
      if (!rawDecision) continue
      const decision = asProtectedOriginalDecision(
        rawDecision,
        candidate.source
      )
      if (!decision) continue
      try {
        const persisted = await this.#protectedEvidence.captureAndPersist({
          context: {
            scanId: input.issued.grant.scanId,
            policyDecisionId: input.issued.grant.policyDecisionId,
            techniqueId: input.issued.grant.techniqueId,
            techniqueVersion: input.issued.grant.techniqueVersion,
            stepId: input.issued.grant.stepId,
            executionState: input.executionState,
            source: candidate.source,
            role: candidate.role,
            occurredAt,
            response: {
              mediaType: candidate.mediaType,
              charset: candidate.source === 'dom-snapshot' ? 'utf-8' : 'not-applicable',
              contentEncoding: 'identity',
              declaredSizeBytes: candidate.content.byteLength
            }
          },
          decision,
          content: candidate.content,
          knownTotalBytes: candidate.content.byteLength
        })
        evidenceRefs.push(persisted.evidence.original.id)
        if (persisted.evidence.derivative) {
          evidenceRefs.push(persisted.evidence.derivative.id)
        }
        input.unboundEvidence.push({
          id: persisted.evidence.original.id,
          filePath: persisted.evidence.original.filePath,
          sha256: persisted.evidence.original.sha256
        })
      } catch {
        // Missing protector or quota fails closed to hash-only; XSS stays Inconclusive.
      }
    }
    return Object.freeze({
      evidenceRefs: Object.freeze(evidenceRefs),
      reviewable: evidenceRefs.length > 0
    })
  }

  async #finalizeAuditFailure(
    claimToken: ExecutionClaimToken,
    responseBytes: number,
    evidenceRefs: readonly string[]
  ): Promise<void> {
    try {
      await this.#executionGuard.finalizeFailed(claimToken, {
        code: 'audit-persistence-failed',
        responseBytes,
        evidenceRefs
      })
    } catch {
      // Recovery owns claimed-but-unknown leases when audit finalization itself fails.
    }
  }

  #resolveRedirect(from: string, location: string): string {
    let fromUrl: URL
    let resolved: URL
    try {
      fromUrl = new URL(from)
      resolved = new URL(location, from)
    } catch {
      throw new RedirectAuthorizationError(
        'invalid-target',
        'HTTP redirect location is invalid.'
      )
    }
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
      throw new RedirectAuthorizationError(
        'invalid-target',
        'HTTP redirect target is not HTTP or HTTPS.'
      )
    }
    if (fromUrl.protocol === 'https:' && resolved.protocol === 'http:') {
      throw new RedirectAuthorizationError(
        'redirect-protocol-downgraded',
        'HTTP redirect protocol was downgraded.'
      )
    }
    resolved.hash = ''
    const canonical = canonicalizeTargetUrl(resolved.toString())
    if (!canonical.ok) {
      throw new RedirectAuthorizationError(
        'url-canonicalization-failed',
        'HTTP redirect target failed canonicalization.'
      )
    }
    return assertCanonicalHttpUrl(
      canonical.value.href,
      'HTTP redirect target'
    )
  }

  #redirectMethod(method: string, statusCode: number | undefined): string {
    if (statusCode === 303) {
      return method === 'HEAD' ? 'HEAD' : 'GET'
    }
    if (
      (statusCode === 301 || statusCode === 302) &&
      (method === 'GET' || method === 'HEAD')
    ) {
      return method
    }
    if (
      (statusCode === 307 || statusCode === 308) &&
      (method === 'GET' || method === 'HEAD')
    ) {
      return method
    }
    throw new Error('HTTP redirect method semantics are not safely supported.')
  }

  async #reviewedRedirectEndpoint(
    scanId: string,
    desiredUrl: string,
    method: string
  ): Promise<string> {
    const route = canonicalizeInventoryUrl(desiredUrl)
    const endpoints =
      await this.#repository.listLegacyV1ExecutionEndpoints(scanId)
    const matches = endpoints.filter(
      (endpoint) =>
        endpoint.method === method &&
        canonicalizeInventoryUrl(endpoint.url) === route
    )
    if (matches.length !== 1) {
      throw new Error(
        'HTTP redirect target has no unique reviewed request variant.'
      )
    }
    return matches[0]!.id
  }

  #compileBrowserOffline(
    input: BrowserOfflineExecutionStepInput,
    ownerRef: string,
    scopeSnapshotId: string
  ): CompiledProbeRequest {
    const wire = createBrowserOfflineExactWire({
      baseUrl: input.baseUrl,
      html: input.html,
      action: input.action,
      ...(input.marker !== undefined ? { marker: input.marker } : {}),
      ...(input.contentSecurityPolicy !== undefined
        ? { contentSecurityPolicy: input.contentSecurityPolicy }
        : {})
    })
    const templateIntentHash = TemplateIntentHashSchema.parse({
      domain: TEMPLATE_INTENT_HASH_DOMAIN,
      algorithm: 'sha256',
      digest: sha256Text(
        canonicalJson({
          domain: TEMPLATE_INTENT_HASH_DOMAIN,
          adapterKind: 'browser-offline',
          scanId: input.scanId,
          baseUrl: input.baseUrl,
          action: input.action,
          markerPresent: input.marker !== undefined,
          contentSecurityPolicyPresent:
            input.contentSecurityPolicy !== undefined
        })
      )
    })
    const reference = this.#hashKeyProvider.reference
    const resolvedIntentHash = ResolvedIntentHashSchema.parse({
      domain: RESOLVED_INTENT_HASH_DOMAIN,
      algorithm: 'sha256',
      commitmentKeyRef: reference.keyRef,
      commitmentKeyVersion: reference.keyVersion,
      digest: sha256Text(
        canonicalJson({
          domain: RESOLVED_INTENT_HASH_DOMAIN,
          templateIntentDigest: templateIntentHash.digest,
          commitmentKeyRef: reference.keyRef,
          commitmentKeyVersion: reference.keyVersion,
          ownerRef,
          scopeSnapshotId,
          wireDigest: sha256Text(
            canonicalJson({
              method: wire.method,
              url: wire.url,
              headers: wire.headers,
              bodySha256:
                wire.bodyBytes === undefined
                  ? null
                  : sha256Text(
                      Buffer.from(wire.bodyBytes).toString('base64')
                    )
            })
          )
        })
      )
    })
    const authorizationContext: WireRequestAuthorizationContext =
      Object.freeze({
        templateIntentHash,
        enabledCapabilityIds: Object.freeze([BROWSER_CAPABILITY]),
        ownerRef,
        scopeSnapshotId,
        identityRef: null,
        credentialRef: null,
        sessionRef: null,
        testObjectRef: null,
        executionBinding: Object.freeze({
          stepId: input.stepId,
          purpose: input.purpose as ExecutionPurpose,
          adapterKind: 'browser-offline'
        })
      })
    const wireRequestHmac = computeWireRequestHmac(
      {
        hashKey: reference,
        resolvedIntentHash,
        authorizationContext,
        request: wire
      },
      this.#hashKeyProvider
    )
    return Object.freeze({
      request: new CompiledWireRequest(wire),
      templateIntentHash,
      resolvedIntentHash,
      wireRequestHmac,
      authorizationContext,
      enabledCapabilityIds: Object.freeze([BROWSER_CAPABILITY])
    })
  }
}

export function executionCaptureDecisions(
  issued: IssuedExecutionAuthority
): readonly EvidenceCaptureDecision[] {
  return flattenDecisionSet(issued.evidenceCaptureDecisions)
}
