import { lookup } from 'node:dns/promises'
import { randomUUID } from 'node:crypto'
import { isIP } from 'node:net'
import type {
  ExecutionGrant,
  ExecutionLease,
  ExecutionLeaseDeliveryState,
  ProbeAction,
  PolicyDecision,
  WireRequestHmac
} from '@agentgo/contracts'
import type {
  HttpExactWireRequest,
  HttpExecutionClaimInput,
  HttpExecutionGuard,
  HttpExecutionLimits,
  ResolvedAddress
} from '@agentgo/http-runner'
import { canonicalJson, redactInventoryUrlPreview } from '@agentgo/domain'
import {
  executionClaimBindingForGrant,
  executionGrantIntegrityBindingForGrant,
  verifyExecutionGrantIntegrity,
  type CredentialMetadata,
  type AgentGoRepository,
  type ExecutionGrantIntegrityKey,
  type RecordExecutionInteractionAuditInput,
  type ProbeProposalRecord,
  type StoredPolicyDecision
} from '@agentgo/db'
import {
  canonicalizeTargetUrl,
  evaluateExecutionAddresses,
  evaluateProbe,
  evaluateSsrfTargetAddresses
} from '@agentgo/security-policy'
import {
  createWireRequestAuthorizationContext,
  verifyWireRequestHmac,
  type MaterializedWireRequest,
  type RequestHashKeyProvider
} from './request-compiler'
import {
  snapshotSecureBytes,
  zeroizeSecureBytes
} from './secure-byte-snapshot'

export interface PolicyDecidedExecutionLimits {
  readonly timeoutMs: number
  readonly maxRequestBytes: number
  readonly maxResponseBytes: number
  readonly maxRedirects: number
  readonly maxRepeats: number
}

export interface PolicyBrokerResult {
  proposal: ProbeProposalRecord
  decision: StoredPolicyDecision
  executionLimits: PolicyDecidedExecutionLimits
}

const DEFAULT_PER_REQUEST_MAX_RESPONSE_BYTES = 5 * 1024 * 1024
const DEFAULT_PER_REQUEST_MAX_REDIRECTS = 5
const SSRF_CALLBACK_STEP_ID = 'ssrf.callback-read'

function denyDecision(
  decision: PolicyDecision,
  code: PolicyDecision['code'],
  reason: string
): PolicyDecision {
  return {
    allowed: false,
    requiresApproval: false,
    code,
    reasons: [reason],
    ...(decision.normalizedTarget
      ? { normalizedTarget: decision.normalizedTarget }
      : {})
  }
}

export class PolicyBroker {
  constructor(private readonly repository: AgentGoRepository) {}

  async evaluate(input: {
    scanId: string
    agentRunId: string
    action: Omit<ProbeAction, 'id'> & { id?: string }
    stopConditions: string[]
    approvedBy?: string
    /** Exact compiled-wire proof. Omission preserves legacy read compatibility only. */
    authorizedWireRequestHmac?: WireRequestHmac
    ssrfTargetUrl?: string
    /**
     * Backend-only. Set only after ApprovalService verified a live approval
     * record. Renderer/Agent `userApproved` must never populate this.
     */
    backendTrustedApproval?: boolean
  }): Promise<PolicyBrokerResult> {
    const scan = await this.repository.getScanRow(input.scanId)
    if (!scan) throw new Error('Cannot evaluate a proposal for a missing scan.')
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!scope) throw new Error('The scan scope snapshot is missing.')
    const action: ProbeAction = {
      ...input.action,
      id: input.action.id ?? randomUUID(),
      scopeSnapshotId: scope.id
    }
    const persistedAction: ProbeAction = {
      ...action,
      targetUrl: redactInventoryUrlPreview(action.targetUrl)
    }
    const proposal = await this.repository.createProbeProposal({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action: persistedAction,
      stopConditions: input.stopConditions
    })
    const capped = this.#applyScanBudgetCaps(
      evaluateProbe(
        action,
        scope,
        input.backendTrustedApproval === true
          ? { backendTrustedApproval: true }
          : undefined
      ),
      action,
      scope,
      scan
    )
    let evaluated: PolicyDecision = capped.decision
    if (evaluated.allowed && input.ssrfTargetUrl) {
      evaluated = await this.#authorizeSsrfTarget(
        evaluated,
        input.ssrfTargetUrl,
        scope
      )
    }
    const persistedDecision: PolicyDecision = {
      ...evaluated,
      ...(evaluated.normalizedTarget
        ? {
            normalizedTarget: redactInventoryUrlPreview(
              evaluated.normalizedTarget
            )
          }
        : {})
    }
    const decision = await this.repository.recordPolicyDecision({
      proposalId: proposal.id,
      scopeSnapshotId: scope.id,
      decision: persistedDecision,
      ...(input.approvedBy ? { approvedBy: input.approvedBy } : {}),
      ...(input.authorizedWireRequestHmac
        ? { authorizedWireRequestHmac: input.authorizedWireRequestHmac }
        : {})
    })
    await this.repository.addScanEvent({
      scanId: input.scanId,
      type: 'policy',
      level: decision.allowed ? 'info' : 'warning',
      message: decision.allowed
        ? 'SecurityPolicy approved: ' + action.summary
        : 'SecurityPolicy rejected: ' + decision.reasons.join('; '),
      detail: {
        proposalId: proposal.id,
        policyDecisionId: decision.id,
        code: decision.code,
        targetUrl: decision.normalizedTarget ?? persistedAction.targetUrl
      }
    })
    if (!decision.allowed) {
      await this.repository.incrementScanSecurityCounter(
        input.scanId,
        decision.code
      )
    }
    return { proposal, decision, executionLimits: capped.limits }
  }

  async #authorizeSsrfTarget(
    decision: PolicyDecision,
    ssrfTargetUrl: string,
    scope: Parameters<typeof evaluateSsrfTargetAddresses>[1]
  ): Promise<PolicyDecision> {
    const canonical = canonicalizeTargetUrl(ssrfTargetUrl)
    if (!canonical.ok) {
      return denyDecision(
        decision,
        'url-canonicalization-failed',
        canonical.reason
      )
    }
    // WHATWG URL keeps IPv6 literals bracketed; isIP/lookup need the bare form.
    const hostname = canonical.value.hostname.replace(/^\[|\]$/g, '')
    const port = canonical.value.port
    let addresses: string[]
    if (isIP(hostname) !== 0) {
      addresses = [hostname]
    } else {
      try {
        const resolved = await lookup(hostname, { all: true, verbatim: true })
        addresses = resolved.map((item) => item.address)
      } catch {
        return denyDecision(
          decision,
          'invalid-target',
          'SSRF 目标主机未解析到可验证地址。'
        )
      }
    }
    const ssrfDecision = evaluateSsrfTargetAddresses(
      { hostname, port, addresses },
      scope
    )
    if (ssrfDecision.allowed) return decision
    return {
      ...ssrfDecision,
      ...(decision.normalizedTarget
        ? { normalizedTarget: decision.normalizedTarget }
        : {})
    }
  }

  #applyScanBudgetCaps(
    decision: PolicyDecision,
    action: ProbeAction,
    scope: { maxRequestsPerMinute: number; maxConcurrency: number },
    scan: {
      budgetJson: {
        maxRequestsPerMinute: number
        maxConcurrency: number
        maxDurationMinutes: number
        maxRequestBytes: number
        maxResponseBytes: number
      }
      startedAt: number | null
    }
  ): { decision: PolicyDecision; limits: PolicyDecidedExecutionLimits } {
    const limits: PolicyDecidedExecutionLimits = {
      timeoutMs: action.timeoutMs,
      maxRequestBytes: action.maxRequestBytes ?? 1_146_880,
      maxResponseBytes:
        action.maxResponseBytes ??
        Math.min(
          scan.budgetJson.maxResponseBytes,
          DEFAULT_PER_REQUEST_MAX_RESPONSE_BYTES
        ),
      maxRedirects: action.maxRedirects ?? DEFAULT_PER_REQUEST_MAX_REDIRECTS,
      maxRepeats: action.maxRepeats ?? 0
    }
    if (!decision.allowed) return { decision, limits }
    const rpmCap = Math.min(
      scope.maxRequestsPerMinute,
      scan.budgetJson.maxRequestsPerMinute
    )
    const concurrencyCap = Math.min(
      scope.maxConcurrency,
      scan.budgetJson.maxConcurrency
    )
    if (
      action.requestedRequestsPerMinute &&
      action.requestedRequestsPerMinute > rpmCap
    ) {
      return {
        decision: denyDecision(
          decision,
          'budget-exhausted-rpm',
          '请求速率超过 Scope 与 Scan 的较小 RPM 上限。'
        ),
        limits
      }
    }
    if (
      action.requestedConcurrency &&
      action.requestedConcurrency > concurrencyCap
    ) {
      return {
        decision: denyDecision(
          decision,
          'budget-exhausted-concurrency',
          '请求并发超过 Scope 与 Scan 的较小并发上限。'
        ),
        limits
      }
    }
    if (limits.maxRequestBytes > scan.budgetJson.maxRequestBytes) {
      return {
        decision: denyDecision(
          decision,
          'budget-exhausted-bytes',
          '请求字节上限超过 Scan 发送字节预算。'
        ),
        limits
      }
    }
    if (limits.maxResponseBytes > scan.budgetJson.maxResponseBytes) {
      return {
        decision: denyDecision(
          decision,
          'budget-exhausted-bytes',
          '响应字节上限超过 Scan 接收字节预算。'
        ),
        limits
      }
    }
    if (
      scan.startedAt !== null &&
      Date.now() - scan.startedAt >=
        scan.budgetJson.maxDurationMinutes * 60 * 1000
    ) {
      return {
        decision: denyDecision(
          decision,
          'budget-exhausted-duration',
          '扫描已超过计划时长预算。'
        ),
        limits
      }
    }
    return { decision, limits }
  }
}

const claimTokenBrand: unique symbol = Symbol('agentgo.execution-claim')

/** Empty, identity-only capability. Its raw database token lives only in a WeakMap. */
export type ExecutionClaimToken = object & {
  readonly [claimTokenBrand]: true
}

export interface BrowserOfflineWireInput {
  readonly baseUrl: string
  readonly html: string
  readonly action: 'inspect-dom' | 'verify-xss' | 'capture-evidence'
  readonly marker?: string
  readonly contentSecurityPolicy?: string
}

export interface BrowserOfflineExecutionClaimInput {
  readonly leaseId: string
  readonly wire: HttpExactWireRequest
  readonly limits: HttpExecutionLimits
}

export interface ExecutionSuccessInput {
  readonly responseBytes?: number
  readonly evidenceRefs?: readonly string[]
}
type BoundExecutionLeaseEvidenceLink = Omit<
  RecordExecutionInteractionAuditInput['evidenceLinks'][number],
  'leaseId'
>

export interface ExecutionInteractionAuditInput {
  readonly interaction: RecordExecutionInteractionAuditInput['interaction']
  readonly evidenceLinks: readonly [
    BoundExecutionLeaseEvidenceLink,
    BoundExecutionLeaseEvidenceLink
  ]
}

export type ExecutionFailureCode =
  | 'dispatch-mark-failed'
  | 'address-rejected'
  | 'response-start-mark-failed'
  | 'timeout'
  | 'response-too-large'
  | 'response-header-too-large'
  | 'response-decompressed-too-large'
  | 'response-compression-bomb'
  | 'response-decompression-failed'
  | 'response-slow-read'
  | 'network-error'
  | 'cancelled'
  | 'audit-persistence-failed'
  | 'runner-output-invalid'
  | 'redirect-rejected'

export interface ExecutionFailureInput {
  readonly code: ExecutionFailureCode
  readonly responseBytes?: number
  readonly evidenceRefs?: readonly string[]
}

interface LegacyAuthorizationInput {
  readonly policyDecisionId: string
  readonly url?: string
  readonly baseUrl?: string
  readonly method?: string
  readonly redirectFrom?: string
  readonly addresses?: readonly ResolvedAddress[]
}

interface ActiveClaim {
  readonly leaseId: string
  readonly grant: ExecutionGrant
  readonly requestBytes: number
  readonly maxResponseBytes: number
  readonly adapterKind: 'http' | 'browser-offline'
  readonly targetUrl: string
  resolvedAddressesAuthorized: boolean
  rawClaimToken: string
  deliveryState: Extract<
    ExecutionLeaseDeliveryState,
    'not-dispatched' | 'possibly-sent' | 'response-started'
  >
}

interface PreparedClaimInput {
  readonly leaseId: string
  readonly wire: HttpExactWireRequest
  readonly limits: HttpExecutionLimits
  readonly adapterKind: 'http' | 'browser-offline'
  readonly actionKind: 'http-request' | 'browser-action'
}

function parseExecutionTarget(value: string): { hostname: string; port: number } {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('Execution target URL is invalid.')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Execution target URL is invalid.')
  }
  const port = Number(
    parsed.port || (parsed.protocol === 'https:' ? '443' : '80')
  )
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('Execution target URL is invalid.')
  }
  return { hostname: parsed.hostname, port }
}

function exactObjectKeys(
  value: object,
  expected: readonly string[]
): boolean {
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    return false
  }
  const keys = Reflect.ownKeys(value)
  if (
    keys.some((key) => typeof key !== 'string') ||
    keys.length !== expected.length
  ) {
    return false
  }
  for (const key of keys) {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    ) {
      return false
    }
  }

  return canonicalJson(Object.keys(value).sort()) === canonicalJson(expected)
}

function snapshotResolvedAddresses(
  addresses: readonly ResolvedAddress[]
): readonly ResolvedAddress[] {
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.length > 64) {
    throw new Error('Resolved execution addresses are invalid.')
  }
  const seen = new Set<string>()
  return Object.freeze(
    addresses.map((entry) => {
      if (
        !entry ||
        typeof entry !== 'object' ||
        Array.isArray(entry) ||
        !exactObjectKeys(entry, ['address', 'family']) ||
        typeof entry.address !== 'string' ||
        (entry.family !== 4 && entry.family !== 6) ||
        isIP(entry.address) !== entry.family ||
        seen.has(`${entry.family}:${entry.address}`)
      ) {
        throw new Error('Resolved execution addresses are invalid.')
      }
      seen.add(`${entry.family}:${entry.address}`)
      return Object.freeze({
        address: entry.address,
        family: entry.family
      })
    })
  )
}

function snapshotExactWire(input: HttpExactWireRequest): MaterializedWireRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Execution wire request is invalid.')
  }
  const bodyPresent = Object.prototype.hasOwnProperty.call(input, 'bodyBytes')
  if (
    !exactObjectKeys(
      input,
      bodyPresent
        ? ['bodyBytes', 'headers', 'method', 'url']
        : ['headers', 'method', 'url']
    ) ||
    typeof input.method !== 'string' ||
    typeof input.url !== 'string' ||
    !Array.isArray(input.headers)
  ) {
    throw new Error('Execution wire request is invalid.')
  }
  let previousHeaderName: string | undefined
  const headers = input.headers.map((header) => {
    if (
      !header ||
      typeof header !== 'object' ||
      Array.isArray(header) ||
      !exactObjectKeys(header, ['name', 'value']) ||
      typeof header.name !== 'string' ||
      typeof header.value !== 'string' ||
      (previousHeaderName !== undefined && previousHeaderName > header.name)
    ) {
      throw new Error('Execution wire headers are not canonical.')
    }
    previousHeaderName = header.name
    return Object.freeze({ name: header.name, value: header.value })
  })
  let bodyBytes: readonly number[] | undefined
  if (bodyPresent) {
    if (
      !Array.isArray(input.bodyBytes) ||
      input.bodyBytes.some(
        (byte) => !Number.isInteger(byte) || byte < 0 || byte > 255
      )
    ) {
      throw new Error('Execution wire body is invalid.')
    }
    bodyBytes = Object.freeze([...input.bodyBytes])
  }
  return Object.freeze({
    method: input.method,
    url: input.url,
    headers: Object.freeze(headers),
    ...(bodyBytes !== undefined ? { bodyBytes } : {})
  })
}

function exactWireByteLength(wire: MaterializedWireRequest): number {
  return (
    Buffer.byteLength(wire.method, 'utf8') +
    Buffer.byteLength(wire.url, 'utf8') +
    wire.headers.reduce(
      (total, header) =>
        total +
        Buffer.byteLength(header.name, 'ascii') +
        Buffer.byteLength(header.value, 'ascii') +
        4,
      0
    ) +
    (wire.bodyBytes?.length ?? 0)
  )
}

function assertExecutionLimits(
  limits: HttpExecutionLimits,
  grant: ExecutionGrant
): void {
  if (
    !limits ||
    !Number.isSafeInteger(limits.timeoutMs) ||
    limits.timeoutMs <= 0 ||
    limits.timeoutMs > grant.budget.timeoutMs ||
    !Number.isSafeInteger(limits.maxResponseBytes) ||
    limits.maxResponseBytes < 0 ||
    limits.maxResponseBytes > grant.budget.maxResponseBytes
  ) {
    throw new Error('Execution limits exceed the immutable grant.')
  }
}

function assertResponseBytes(value: number, maximum?: number): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    (maximum !== undefined && value > maximum)
  ) {
    throw new Error('Execution response byte count is invalid.')
  }
}

function failureMapping(input: ExecutionFailureCode): {
  terminalReason:
    | 'guard-rejected'
    | 'cancelled'
    | 'timed-out'
    | 'network-failed'
    | 'response-read-failed'
    | 'redirect-rejected'
  executionState: 'failed' | 'cancelled' | 'timed-out'
  errorCode: string
} {
  switch (input) {
    case 'address-rejected':
      return {
        terminalReason: 'guard-rejected',
        executionState: 'failed',
        errorCode: 'execution.address-rejected'
      }
    case 'dispatch-mark-failed':
      return {
        terminalReason: 'guard-rejected',
        executionState: 'failed',
        errorCode: 'execution.dispatch-mark-failed'
      }
    case 'response-start-mark-failed':
    case 'response-too-large':
    case 'response-header-too-large':
    case 'response-decompressed-too-large':
    case 'response-compression-bomb':
    case 'response-decompression-failed':
    case 'response-slow-read':
      return {
        terminalReason: 'response-read-failed',
        executionState: 'failed',
        errorCode: `execution.${input}`
      }
    case 'timeout':
      return {
        terminalReason: 'timed-out',
        executionState: 'timed-out',
        errorCode: 'execution.timed-out'
      }
    case 'network-error':
      return {
        terminalReason: 'network-failed',
        executionState: 'failed',
        errorCode: 'execution.network-failed'
      }
    case 'cancelled':
      return {
        terminalReason: 'cancelled',
        executionState: 'cancelled',
        errorCode: 'execution.cancelled'
      }
    case 'audit-persistence-failed':
      return {
        terminalReason: 'response-read-failed',
        executionState: 'failed',
        errorCode: 'execution.audit-persistence-failed'
      }
    case 'runner-output-invalid':
      return {
        terminalReason: 'response-read-failed',
        executionState: 'failed',
        errorCode: 'execution.runner-output-invalid'
      }
    case 'redirect-rejected':
      return {
        terminalReason: 'redirect-rejected',
        executionState: 'failed',
        errorCode: 'execution.redirect-rejected'
      }
  }

  throw new Error('Unsupported execution failure code.')
}

export function createBrowserOfflineExactWire(
  input: BrowserOfflineWireInput
): HttpExactWireRequest {
  let url: URL
  try {
    url = new URL(input.baseUrl)
  } catch {
    throw new Error('Offline browser base URL is invalid.')
  }
  if (
    url.username !== '' ||
    url.password !== '' ||
    !['http:', 'https:'].includes(url.protocol) ||
    url.hash !== '' ||
    url.toString() !== input.baseUrl
  ) {
    throw new Error('Offline browser base URL is not canonical.')
  }
  const headers = [
    ...(input.contentSecurityPolicy
      ? [
          {
            name: 'content-security-policy',
            value: input.contentSecurityPolicy
          }
        ]
      : []),
    { name: 'x-agentgo-browser-action', value: input.action },
    ...(input.marker
      ? [{ name: 'x-agentgo-browser-marker', value: input.marker }]
      : [])
  ].sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0
  )
  return Object.freeze({
    method: 'BROWSER-OFFLINE',
    url: input.baseUrl,
    headers: Object.freeze(
      headers.map((header) => Object.freeze({ ...header }))
    ),
    bodyBytes: Object.freeze([...Buffer.from(input.html, 'utf8')])
  })
}

export interface CredentialMetadataAuthority {
  isAvailable(): boolean
  list(): readonly CredentialMetadata[]
}

/**
 * Authoritative session-generation checker consulted at the dispatch edge.
 * A grant carrying a sessionRef can only dispatch while the vault confirms
 * the pinned generation.
 */
export interface SessionGenerationAuthority {
  assertActiveGeneration(sessionId: string, generation: number): Promise<void>
}

export class PolicyExecutionGuard
  implements HttpExecutionGuard<ExecutionClaimToken>
{
  readonly #claims = new WeakMap<ExecutionClaimToken, ActiveClaim>()
  readonly #repository: AgentGoRepository
  readonly #hashKeyProvider: RequestHashKeyProvider | undefined
  readonly #credentialMetadataAuthority: CredentialMetadataAuthority | undefined
  readonly #sessionAuthority: SessionGenerationAuthority | undefined
  readonly #runnerInstanceId: string

  constructor(
    repository: AgentGoRepository,
    hashKeyProvider?: RequestHashKeyProvider,
    credentialMetadataAuthority?: CredentialMetadataAuthority,
    sessionAuthority?: SessionGenerationAuthority,
    runnerInstanceId: string = randomUUID()
  ) {
    this.#repository = repository
    this.#hashKeyProvider = hashKeyProvider
    this.#credentialMetadataAuthority = credentialMetadataAuthority
    this.#sessionAuthority = sessionAuthority
    this.#runnerInstanceId = runnerInstanceId
  }

  claim(input: HttpExecutionClaimInput): Promise<ExecutionClaimToken> {
    return this.#claimPrepared({
      ...input,
      adapterKind: 'http',
      actionKind: 'http-request'
    })
  }

  claimOffline(
    input: BrowserOfflineExecutionClaimInput
  ): Promise<ExecutionClaimToken> {
    const wire = snapshotExactWire(input.wire)
    if (input.wire.method !== 'BROWSER-OFFLINE') {
      throw new Error('Offline browser execution requires its synthetic method.')
    }
    return this.#claimPrepared({
      ...input,
      wire,
      adapterKind: 'browser-offline',
      actionKind: 'browser-action'
    })
  }

  async validateResolvedAddresses(
    claimToken: ExecutionClaimToken,
    addresses: readonly ResolvedAddress[]
  ): Promise<void> {
    const claim = this.#requireClaim(claimToken)
    if (
      claim.adapterKind !== 'http' ||
      claim.deliveryState !== 'not-dispatched' ||
      claim.resolvedAddressesAuthorized
    ) {
      throw new Error('Execution address authorization state is invalid.')
    }
    const snapshot = snapshotResolvedAddresses(addresses)
    const context = await this.#repository.getExecutionDecision(
      claim.grant.policyDecisionId
    )
    if (
      !context ||
      context.scanId !== claim.grant.scanId ||
      context.decision.id !== claim.grant.policyDecisionId ||
      context.decision.scopeSnapshotId !== claim.grant.scopeSnapshotId ||
      context.scope.id !== claim.grant.scopeSnapshotId ||
      context.scope.targetId !== context.targetId ||
      context.scope.snapshotHash !== claim.grant.scopeSnapshotHash
    ) {
      throw new Error('Execution address authorization context is invalid.')
    }
    const parsedTarget = parseExecutionTarget(claim.targetUrl)
    const hop = {
      hostname: parsedTarget.hostname,
      port: parsedTarget.port,
      addresses: snapshot.map((address) => address.address)
    }
    const networkDecision = evaluateExecutionAddresses(hop, context.scope)
    if (!networkDecision.allowed) {
      await this.#repository.incrementScanSecurityCounter(
        claim.grant.scanId,
        networkDecision.code
      )
      throw new Error('Resolved execution addresses are outside scope.')
    }
    if (claim.grant.stepId === SSRF_CALLBACK_STEP_ID) {
      const ssrfDecision = evaluateSsrfTargetAddresses(hop, context.scope)
      if (!ssrfDecision.allowed) {
        await this.#repository.incrementScanSecurityCounter(
          claim.grant.scanId,
          ssrfDecision.code
        )
        throw new Error('Resolved SSRF target addresses are outside scope.')
      }
    }
    const current = this.#requireClaim(claimToken)
    if (
      current !== claim ||
      current.deliveryState !== 'not-dispatched' ||
      current.resolvedAddressesAuthorized
    ) {
      throw new Error('Execution address authorization state changed.')
    }
    current.resolvedAddressesAuthorized = true
  }

  async markDispatched(claimToken: ExecutionClaimToken): Promise<void> {
    const claim = this.#requireClaim(claimToken)
    if (claim.adapterKind === 'http' && !claim.resolvedAddressesAuthorized) {
      throw new Error('HTTP dispatch requires authorized resolved addresses.')
    }
    this.#assertCredentialAvailable(claim.grant.credentialRef)
    await this.#assertSessionGenerationCurrent(claim.grant.sessionRef)
    await this.#markDelivery(claimToken, 'possibly-sent')
    this.#assertCredentialAvailable(claim.grant.credentialRef)
    await this.#assertSessionGenerationCurrent(claim.grant.sessionRef)
  }

  async #assertSessionGenerationCurrent(
    sessionRef: ExecutionGrant['sessionRef']
  ): Promise<void> {
    if (!sessionRef) return
    if (!this.#sessionAuthority) {
      throw new Error('Execution session references require an authoritative session service.')
    }
    await this.#sessionAuthority.assertActiveGeneration(
      sessionRef.id,
      sessionRef.generation
    )
  }

  markResponseStarted(claimToken: ExecutionClaimToken): Promise<void> {
    return this.#markDelivery(claimToken, 'response-started')
  }

  async recordInteractionAudit(
    claimToken: ExecutionClaimToken,
    input: ExecutionInteractionAuditInput
  ): Promise<string> {
    const claim = this.#requireClaim(claimToken)
    const [firstEvidence, secondEvidence] = input.evidenceLinks
    return this.#repository.recordExecutionInteractionAudit({
      leaseId: claim.leaseId,
      claimToken: claim.rawClaimToken,
      interaction: input.interaction,
      evidenceLinks: [
        {
          ...firstEvidence,
          leaseId: claim.leaseId
        },
        {
          ...secondEvidence,
          leaseId: claim.leaseId
        }
      ]
    })
  }

  async finalizeSucceeded(
    claimToken: ExecutionClaimToken,
    input: ExecutionSuccessInput = {}
  ): Promise<ExecutionLease> {
    const claim = this.#requireClaim(claimToken)
    if (claim.deliveryState !== 'response-started') {
      throw new Error('Successful execution requires a persisted response start.')
    }
    const responseBytes = input.responseBytes ?? 0
    assertResponseBytes(responseBytes, claim.maxResponseBytes)
    const lease = await this.#repository.finalizeExecutionLease({
      leaseId: claim.leaseId,
      claimToken: claim.rawClaimToken,
      state: 'completed',
      terminalReason: 'completed',
      deliveryState: 'completed',
      outcomeSummary: {
        executionState: 'succeeded',
        deliveryState: 'completed',
        verdictImpact: 'none',
        wireRequestHmacDigest: claim.grant.wireRequestHmac.digest,
        requestBytes: claim.requestBytes,
        responseBytes
      },
      evidenceRefs: [...(input.evidenceRefs ?? [])]
    })
    this.#forgetClaim(claimToken, claim)
    return lease
  }

  async finalizeFailed(
    claimToken: ExecutionClaimToken,
    input: ExecutionFailureInput
  ): Promise<ExecutionLease> {
    const claim = this.#requireClaim(claimToken)
    const mapping = failureMapping(input.code)
    const responseBytes = input.responseBytes ?? 0
    assertResponseBytes(responseBytes)
    const persistedResponseBytes = Math.min(
      responseBytes,
      claim.maxResponseBytes
    )
    const lease = await this.#repository.finalizeExecutionLease({
      leaseId: claim.leaseId,
      claimToken: claim.rawClaimToken,
      state: 'failed',
      terminalReason: mapping.terminalReason,
      deliveryState: claim.deliveryState,
      outcomeSummary: {
        executionState: mapping.executionState,
        deliveryState: claim.deliveryState,
        verdictImpact:
          claim.deliveryState === 'not-dispatched' ? 'none' : 'inconclusive',
        wireRequestHmacDigest: claim.grant.wireRequestHmac.digest,
        requestBytes: claim.requestBytes,
        responseBytes: persistedResponseBytes,
        errorCode: mapping.errorCode
      },
      evidenceRefs: [...(input.evidenceRefs ?? [])]
    })
    this.#forgetClaim(claimToken, claim)
    return lease
  }

  async rejectInvalidRunnerOutput(
    leaseId: string,
    claimToken: ExecutionClaimToken | undefined
  ): Promise<ExecutionLease> {
    const claim =
      claimToken === undefined ? undefined : this.#claims.get(claimToken)
    if (claim?.leaseId === leaseId && claimToken !== undefined) {
      return this.finalizeFailed(claimToken, {
        code: 'runner-output-invalid',
        responseBytes: 0,
        evidenceRefs: []
      })
    }
    return this.revoke(leaseId, 'guard-rejected')
  }

  revoke(
    leaseId: string,
    reason: 'revoked' | 'guard-rejected' | 'unsupported-adapter'
  ): Promise<ExecutionLease> {
    return this.#repository.revokeExecutionLease({ leaseId, reason })
  }

  /**
   * @deprecated Legacy diagnostic read compatibility only. It never mints an
   * execution capability and has no production caller. Remove after
   * the unified ExecutionPort/Runner boundary regression remains green.
   */
  async authorize(input: LegacyAuthorizationInput): Promise<void> {
    const context = await this.#repository.getExecutionDecision(
      input.policyDecisionId
    )
    if (!context) throw new Error('Policy decision does not exist.')
    if (!context.decision.allowed || context.decision.requiresApproval) {
      throw new Error('Policy decision does not authorize execution.')
    }
    if (
      context.decision.validUntil &&
      Date.parse(context.decision.validUntil) <= Date.now()
    ) {
      throw new Error('Policy decision expired before execution.')
    }
    if (context.scanStatus !== 'running') {
      throw new Error(
        'Scan status ' + context.scanStatus + ' does not allow execution.'
      )
    }
    if (context.requestCount >= context.scanBudget.maxRequests) {
      throw new Error('Scan request budget is exhausted.')
    }
    const url = input.url ?? input.baseUrl
    if (!url) throw new Error('Execution URL is missing.')
    const method = input.method ?? context.proposal.action.method
    const revalidation = evaluateProbe(
      {
        ...context.proposal.action,
        targetUrl: url,
        method,
        scopeSnapshotId: context.scope.id
      },
      context.scope
    )
    if (!revalidation.allowed) {
      throw new Error(
        (input.redirectFrom ? 'Redirect' : 'Execution') +
          ' revalidation failed: ' +
          revalidation.reasons.join('; ')
      )
    }
    if (input.addresses) {
      const parsedTarget = parseExecutionTarget(url)
      const networkDecision = evaluateExecutionAddresses(
        {
          hostname: parsedTarget.hostname,
          port: parsedTarget.port,
          addresses: input.addresses.map((address) => address.address)
        },
        context.scope
      )
      if (!networkDecision.allowed) {
        throw new Error(networkDecision.reasons.join('; '))
      }
    }
  }

  async #claimPrepared(
    input: PreparedClaimInput
  ): Promise<ExecutionClaimToken> {
    const hashKeyProvider = this.#hashKeyProvider
    if (!hashKeyProvider) {
      throw new Error('Execution proof key provider is unavailable.')
    }
    const wire = snapshotExactWire(input.wire)
    const lease = await this.#repository.getExecutionLease(input.leaseId)
    if (!lease || lease.state !== 'issued') {
      throw new Error('Execution lease is not claimable.')
    }
    const grant = await this.#repository.getExecutionGrant(lease.grantId)
    if (
      !grant ||
      grant.id !== lease.grantId ||
      grant.adapterKind !== input.adapterKind
    ) {
      throw new Error('Execution adapter is not authorized by the grant.')
    }
    const context = await this.#repository.getExecutionDecision(
      grant.policyDecisionId
    )
    const decisionValidUntil = context?.decision.validUntil
      ? Date.parse(context.decision.validUntil)
      : Number.NaN
    if (
      !context ||
      context.scanId !== grant.scanId ||
      context.proposal.scanId !== grant.scanId ||
      context.decision.id !== grant.policyDecisionId ||
      context.decision.proposalId !== context.proposal.id ||
      context.decision.scopeSnapshotId !== grant.scopeSnapshotId ||
      context.proposal.action.scopeSnapshotId !== grant.scopeSnapshotId ||
      context.scope.id !== grant.scopeSnapshotId ||
      context.scope.targetId !== context.targetId ||
      context.scope.snapshotHash !== grant.scopeSnapshotHash ||
      context.proposal.action.kind !== input.actionKind ||
      !context.decision.allowed ||
      context.decision.requiresApproval ||
      !Number.isFinite(decisionValidUntil) ||
      decisionValidUntil <= Date.now() ||
      context.decision.authorizedWireRequestHmac === undefined ||
      canonicalJson(context.decision.authorizedWireRequestHmac) !==
        canonicalJson(grant.wireRequestHmac) ||
      context.scanStatus !== 'running' ||
      context.requestCount + grant.budget.requestUnits >
        context.scanBudget.maxRequests
    ) {
      throw new Error('Execution policy binding is no longer valid.')
    }
    if (
      input.adapterKind === 'http' &&
      wire.method !== context.proposal.action.method.toUpperCase()
    ) {
      throw new Error('Execution method differs from the policy proposal.')
    }
    const actionIdentityId = context.proposal.action.identityId
    const grantIdentityRef = grant.identityRef
    const grantIdentityId = grantIdentityRef?.id
    if (actionIdentityId !== grantIdentityId) {
      throw new Error('Execution identity differs from the policy proposal.')
    }
    if (grant.credentialRef !== null && !grantIdentityRef) {
      throw new Error(
        'Execution credential metadata has no authoritative identity.'
      )
    }
    if (grantIdentityRef) {
      const authorizedIdentityId = grantIdentityRef.id
      const [identity, scan] = await Promise.all([
        this.#repository.getIdentity(authorizedIdentityId),
        this.#repository.getScanRow(grant.scanId)
      ])
      if (
        !identity ||
        !scan ||
        scan.targetId !== context.targetId ||
        !scan.configJson.identityIds.includes(authorizedIdentityId) ||
        identity.targetId !== context.targetId ||
        !identity.isTestIdentity ||
        !context.scope.allowedIdentityIds.includes(authorizedIdentityId) ||
        grantIdentityRef.ownerRef !== context.targetId ||
        grantIdentityRef.scopeSnapshotId !== grant.scopeSnapshotId ||
        grantIdentityRef.statusSummary !== 'active' ||
        grantIdentityRef.version !== Date.parse(identity.updatedAt) ||
        (grant.credentialRef !== null &&
          (identity.credentialId !== grant.credentialRef.id ||
            identity.authType === 'none'))
      ) {
        throw new Error('Execution identity is not an authorized test identity.')
      }
    }
    const authorizationContext = createWireRequestAuthorizationContext({
      templateIntentHash: grant.templateIntentHash,
      enabledCapabilityIds: grant.capabilityIds,
      ...(grant.ownerRef ? { ownerRef: grant.ownerRef } : {}),
      scopeSnapshotId: grant.scopeSnapshotId,
      ...(grant.identityRef
        ? { identityRef: grant.identityRef }
        : {}),
      ...(grant.credentialRef
        ? { credentialRef: grant.credentialRef }
        : {}),
      ...(grant.sessionRef
        ? { sessionRef: grant.sessionRef }
        : {}),
      ...(grant.testObjectRef
        ? { testObjectRef: grant.testObjectRef }
        : {}),
      executionBinding: {
        stepId: grant.stepId,
        purpose: grant.purpose,
        adapterKind: grant.adapterKind
      }
    })
    if (
      !verifyWireRequestHmac(
        {
          hashKey: {
            keyRef: grant.wireRequestHmac.keyRef,
            keyVersion: grant.wireRequestHmac.keyVersion
          },
          resolvedIntentHash: grant.resolvedIntentHash,
          authorizationContext,
          request: wire
        },
        grant.wireRequestHmac,
        hashKeyProvider
      )
    ) {
      throw new Error('Execution wire proof verification failed.')
    }
    const requestBytes = exactWireByteLength(wire)
    if (requestBytes !== grant.budget.requestBytes) {
      throw new Error('Execution request byte count differs from the grant.')
    }
    assertExecutionLimits(input.limits, grant)
    const revalidation = evaluateProbe(
      {
        ...context.proposal.action,
        targetUrl: wire.url,
        method:
          input.adapterKind === 'http'
            ? wire.method
            : context.proposal.action.method,
        scopeSnapshotId: context.scope.id
      },
      context.scope,
      grant.approvalBundleRef ? { backendTrustedApproval: true } : undefined
    )
    if (!revalidation.allowed) {
      throw new Error(
        'Execution revalidation failed: ' + revalidation.reasons.join('; ')
      )
    }

    let keyMaterial: Uint8Array<ArrayBuffer>
    try {
      keyMaterial = snapshotSecureBytes(
        hashKeyProvider.resolveKey({
          keyRef: grant.integrityHmac.keyRef,
          keyVersion: grant.integrityHmac.keyVersion
        }),
        {
          minimumBytes: 32,
          maximumBytes: 4_096
        }
      )
    } catch {
      throw new Error('Execution integrity key is invalid.')
    }
    const integrityKey: ExecutionGrantIntegrityKey = {
      keyRef: grant.integrityHmac.keyRef,
      keyVersion: grant.integrityHmac.keyVersion,
      keyMaterial
    }
    try {
      if (
        !verifyExecutionGrantIntegrity(
          executionGrantIntegrityBindingForGrant(grant),
          grant.integrityHmac,
          integrityKey
        )
      ) {
        throw new Error('Execution grant integrity verification failed.')
      }
      this.#assertCredentialAvailable(grant.credentialRef)
      const claimed = await this.#repository.claimExecutionLease({
        leaseId: lease.id,
        runnerInstanceId: this.#runnerInstanceId,
        binding: executionClaimBindingForGrant(grant),
        integrityKey
      })
      try {
        this.#assertCredentialAvailable(grant.credentialRef)
      } catch {
        try {
          await this.#repository.finalizeExecutionLease({
            leaseId: lease.id,
            claimToken: claimed.claimToken,
            state: 'failed',
            terminalReason: 'guard-rejected',
            deliveryState: 'not-dispatched',
            outcomeSummary: {
              executionState: 'failed',
              deliveryState: 'not-dispatched',
              verdictImpact: 'none',
              wireRequestHmacDigest: grant.wireRequestHmac.digest,
              requestBytes,
              responseBytes: 0,
              errorCode: 'execution.credential-generation-changed'
            },
            evidenceRefs: []
          })
        } catch {
          throw new Error(
            'Execution credential changed after claim and the lease could not be closed safely.'
          )
        }
        throw new Error('Execution credential changed while claiming the lease.')
      }
      const claimToken = Object.freeze(
        Object.create(null)
      ) as ExecutionClaimToken
      this.#claims.set(claimToken, {
        leaseId: lease.id,
        grant,
        requestBytes,
        maxResponseBytes: input.limits.maxResponseBytes,
        adapterKind: input.adapterKind,
        targetUrl: wire.url,
        resolvedAddressesAuthorized: input.adapterKind === 'browser-offline',
        rawClaimToken: claimed.claimToken,
        deliveryState: 'not-dispatched'
      })
      return claimToken
    } finally {
      zeroizeSecureBytes(keyMaterial)
    }
  }

  #assertCredentialAvailable(
    credentialRef: ExecutionGrant['credentialRef']
  ): void {
    if (credentialRef === null) return
    const authority = this.#credentialMetadataAuthority
    if (!authority) {
      throw new Error('Execution credential metadata authority is unavailable.')
    }
    let availableBefore: boolean
    let entries: readonly CredentialMetadata[]
    let availableAfter: boolean
    try {
      availableBefore = authority.isAvailable()
      entries = authority.list()
      availableAfter = authority.isAvailable()
    } catch {
      throw new Error('Execution credential metadata is unavailable.')
    }
    if (!availableBefore || !availableAfter || !Array.isArray(entries)) {
      throw new Error('Execution credential metadata is unavailable.')
    }
    const matches = entries.filter((entry) => {
      if (
        !entry ||
        typeof entry !== 'object' ||
        Array.isArray(entry) ||
        (Object.getPrototypeOf(entry) !== Object.prototype &&
          Object.getPrototypeOf(entry) !== null)
      ) {
        return false
      }
      const id = Reflect.getOwnPropertyDescriptor(entry, 'id')
      return Boolean(
        id?.enumerable &&
        Object.prototype.hasOwnProperty.call(id, 'value') &&
        id.value === credentialRef.id
      )
    })
    const metadata = matches[0]
    const kind = metadata
      ? Reflect.getOwnPropertyDescriptor(metadata, 'kind')
      : undefined
    const generation = metadata
      ? Reflect.getOwnPropertyDescriptor(metadata, 'generation')
      : undefined
    if (
      matches.length !== 1 ||
      !metadata ||
      !kind?.enumerable ||
      !Object.prototype.hasOwnProperty.call(kind, 'value') ||
      kind.value !== credentialRef.kind ||
      !generation?.enumerable ||
      !Object.prototype.hasOwnProperty.call(generation, 'value') ||
      !Number.isSafeInteger(generation.value) ||
      generation.value !== credentialRef.generation
    ) {
      throw new Error('Execution credential generation is no longer exact.')
    }
  }

  async #markDelivery(
    claimToken: ExecutionClaimToken,
    deliveryState: 'possibly-sent' | 'response-started'
  ): Promise<void> {
    const claim = this.#requireClaim(claimToken)
    const expected =
      deliveryState === 'possibly-sent'
        ? 'not-dispatched'
        : 'possibly-sent'
    if (claim.deliveryState !== expected) {
      throw new Error('Execution delivery transition is invalid.')
    }
    await this.#repository.markExecutionLeaseDelivery({
      leaseId: claim.leaseId,
      claimToken: claim.rawClaimToken,
      deliveryState
    })
    claim.deliveryState = deliveryState
  }

  #requireClaim(claimToken: ExecutionClaimToken): ActiveClaim {
    if (
      !claimToken ||
      (typeof claimToken !== 'object' && typeof claimToken !== 'function')
    ) {
      throw new Error('Execution claim token is unknown.')
    }
    const claim = this.#claims.get(claimToken)
    if (!claim) throw new Error('Execution claim token is unknown.')
    return claim
  }

  #forgetClaim(
    claimToken: ExecutionClaimToken,
    claim: ActiveClaim
  ): void {
    claim.rawClaimToken = ''
    this.#claims.delete(claimToken)
  }
}
