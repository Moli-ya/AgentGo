import { createHash } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { BrowserRunner } from '@agentgo/browser-runner'
import {
  EvidenceCaptureDecisionSchema,
  type EvidenceCaptureDecision,
  type EvidenceCaptureExecutionState,
  type ExecutionCredentialRef,
  type IdentityRef
} from '@agentgo/contracts'
import type {
  AgentGoRepository,
  EvidenceStore
} from '@agentgo/db'
import type {
  HttpExecutionGuard,
  HttpExecutionRequest,
  HttpExecutionResult,
  HttpRunner,
  ResolvedAddress
} from '@agentgo/http-runner'
import { EvidenceCapturePolicy } from './evidence-capture-policy'
import type {
  ExecutionEvidenceCaptureDecisionSet,
  IssueRedirectChildExecutionInput,
  IssueRootExecutionInput,
  IssuedExecutionAuthority
} from './execution-authority'
import type {
  ExecutionClaimToken,
  ExecutionInteractionAuditInput,
  PolicyBroker,
  PolicyExecutionGuard
} from './execution-policy'
import type { HttpExecutionStepInput } from './execution-port'
import {
  ExecutionService,
  type ExecutionServiceDependencies
} from './execution-service'
import type {
  LegacyV1RequestCompilerAdapter,
  LegacyV1RequestCompilerAdapterInput,
  LegacyV1RequestCompilerAdapterOutput
} from './legacy-v1-request-compiler-adapter'
import { EphemeralRequestHashKeyProvider } from './request-hash-key-provider'
import {
  CompiledWireRequest,
  computeWireRequestHmac,
  createWireRequestAuthorizationContext,
  type CompiledProbeRequest,
  type MaterializedWireRequest
} from './request-compiler'

const NOW = '2026-07-28T00:00:00.000Z'
const NOW_MS = Date.parse(NOW)
const VALID_UNTIL = '2099-01-01T00:00:00.000Z'
const ROOT_URL = 'https://origin.example.test/start'
const CHILD_URL = 'https://redirect.example.test/final'
const AUTHORIZATION_SECRET = 'Bearer redirect-secret-must-not-leak'

const ids = {
  scan: '51000000-0000-4000-8000-000000000001',
  agentRun: '51000000-0000-4000-8000-000000000002',
  target: '51000000-0000-4000-8000-000000000003',
  scope: '51000000-0000-4000-8000-000000000004',
  workspace: '51000000-0000-4000-8000-000000000005',
  identity: '51000000-0000-4000-8000-000000000006',
  credential: '51000000-0000-4000-8000-000000000007',
  rootEndpoint: '51000000-0000-4000-8000-000000000008',
  childEndpoint: '51000000-0000-4000-8000-000000000009',
  rootProposal: '51000000-0000-4000-8000-00000000000a',
  childProposal: '51000000-0000-4000-8000-00000000000b',
  rootDecision: '51000000-0000-4000-8000-00000000000c',
  childDecision: '51000000-0000-4000-8000-00000000000d',
  rootGrant: '51000000-0000-4000-8000-00000000000e',
  childGrant: '51000000-0000-4000-8000-00000000000f',
  rootLease: '51000000-0000-4000-8000-000000000010',
  childLease: '51000000-0000-4000-8000-000000000011'
} as const

const providers: EphemeralRequestHashKeyProvider[] = []

afterEach(() => {
  for (const provider of providers.splice(0)) provider.dispose()
})

function digest(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function sequentialId(prefix: string, index: number): string {
  return `${prefix}-0000-4000-8000-${String(index).padStart(12, '0')}`
}

function captureDecision(
  id: string,
  policyDecisionId: string,
  source: EvidenceCaptureDecision['source'],
  role: EvidenceCaptureDecision['role'],
  executionState: EvidenceCaptureExecutionState,
  validUntil: string
): EvidenceCaptureDecision {
  return EvidenceCaptureDecisionSchema.parse({
    id,
    scanId: ids.scan,
    policyDecisionId,
    capturePolicyId: 'evidence-summary-v1',
    capturePolicyVersion: '1.0.0',
    techniqueId: 'ssrf.redirect',
    techniqueVersion: '1.0.0',
    stepId: 'ssrf.redirect.follow',
    executionState,
    source,
    role,
    action: 'hash-only',
    validFrom: NOW,
    validUntil,
    maxSourceBytes: 65_536,
    maxExcerptBytes: 32,
    jsonPointers: [],
    oobMetadataFields: []
  })
}

function normalCaptureDecisions(
  startIndex: number,
  policyDecisionId: string,
  source: 'http-request-summary' | 'http-response-summary',
  role: 'request-summary' | 'response-summary',
  validUntil: string
) {
  const id = (offset: number) =>
    sequentialId('52000000', startIndex + offset)
  return Object.freeze({
    succeeded: captureDecision(
      id(0),
      policyDecisionId,
      source,
      role,
      'succeeded',
      validUntil
    ),
    failed: captureDecision(
      id(1),
      policyDecisionId,
      source,
      role,
      'failed',
      validUntil
    ),
    cancelled: captureDecision(
      id(2),
      policyDecisionId,
      source,
      role,
      'cancelled',
      validUntil
    ),
    'timed-out': captureDecision(
      id(3),
      policyDecisionId,
      source,
      role,
      'timed-out',
      validUntil
    )
  })
}

function captureDecisions(
  hop: number,
  policyDecisionId: string,
  validUntil: string
): ExecutionEvidenceCaptureDecisionSet {
  const offset = hop * 20
  return Object.freeze({
    'execution-interruption-summary': Object.freeze({
      interrupted: captureDecision(
        sequentialId('52000000', offset + 9),
        policyDecisionId,
        'execution-interruption-summary',
        'interruption-summary',
        'interrupted',
        validUntil
      )
    }),
    'http-request-summary': normalCaptureDecisions(
      offset + 1,
      policyDecisionId,
      'http-request-summary',
      'request-summary',
      validUntil
    ),
    'http-response-summary': normalCaptureDecisions(
      offset + 5,
      policyDecisionId,
      'http-response-summary',
      'response-summary',
      validUntil
    )
  })
}

const identityRef: IdentityRef = Object.freeze({
  id: ids.identity,
  version: NOW_MS,
  ownerRef: ids.target,
  scopeSnapshotId: ids.scope,
  statusSummary: 'active'
})

const credentialRef: ExecutionCredentialRef = Object.freeze({
  id: ids.credential,
  kind: 'identity',
  generation: 7
})

function compiledRequest(
  provider: EphemeralRequestHashKeyProvider,
  wire: MaterializedWireRequest,
  includeCredential: boolean
): CompiledProbeRequest {
  const templateIntentHash = Object.freeze({
    domain: 'agentgo.template-intent.v1' as const,
    algorithm: 'sha256' as const,
    digest: 'a'.repeat(64)
  })
  const resolvedIntentHash = Object.freeze({
    domain: 'agentgo.resolved-intent.v1' as const,
    algorithm: 'sha256' as const,
    commitmentKeyRef: provider.reference.keyRef,
    commitmentKeyVersion: provider.reference.keyVersion,
    digest: 'b'.repeat(64)
  })
  const authorizationContext = createWireRequestAuthorizationContext({
    templateIntentHash,
    enabledCapabilityIds: ['http.reviewed-read'],
    ownerRef: ids.target,
    scopeSnapshotId: ids.scope,
    identityRef,
    ...(includeCredential ? { credentialRef } : {}),
    executionBinding: {
      stepId: 'ssrf.redirect.follow',
      purpose: 'read',
      adapterKind: 'http'
    }
  })
  const wireRequestHmac = computeWireRequestHmac(
    {
      hashKey: provider.reference,
      resolvedIntentHash,
      authorizationContext,
      request: wire
    },
    provider
  )
  return Object.freeze({
    request: new CompiledWireRequest(wire),
    templateIntentHash,
    resolvedIntentHash,
    authorizationContext,
    wireRequestHmac,
    enabledCapabilityIds: Object.freeze(['http.reviewed-read'])
  })
}

function attachClaimToken(
  result: HttpExecutionResult<ExecutionClaimToken>,
  claimToken: ExecutionClaimToken
): HttpExecutionResult<ExecutionClaimToken> {
  Object.defineProperty(result, 'claimToken', {
    value: claimToken,
    enumerable: false,
    configurable: false,
    writable: false
  })
  return result
}

function redactedRequestHeaders(
  wire: MaterializedWireRequest
): readonly Readonly<{ name: string; value: string }>[] {
  return wire.headers.map(({ name }) =>
    Object.freeze({ name: name.toLowerCase(), value: '[REDACTED]' })
  )
}

interface RedirectFixtureOptions {
  readonly childUrl?: string
  readonly childAddress?: string
  readonly policyRejectedUrls?: ReadonlySet<string>
  readonly rejectResolvedAddresses?: ReadonlySet<string>
  readonly leakAuthorizationOnOmit?: boolean
}

function createRedirectFixture(
  options: RedirectFixtureOptions = {}
) {
  const childUrl = options.childUrl ?? CHILD_URL
  const childAddress = options.childAddress ?? '203.0.113.11'
  const provider = new EphemeralRequestHashKeyProvider()
  providers.push(provider)
  const adapterCalls: LegacyV1RequestCompilerAdapterInput[] = []
  const compile = vi.fn(
    async (
      input: LegacyV1RequestCompilerAdapterInput
    ): Promise<LegacyV1RequestCompilerAdapterOutput> => {
      adapterCalls.push(input)
      const includeCredential = input.credentialMode !== 'omit'
      const leakCredential =
        !includeCredential && options.leakAuthorizationOnOmit === true
      const wire: MaterializedWireRequest = Object.freeze({
        method: 'GET',
        url: input.desiredTargetUrl,
        headers: Object.freeze([
          Object.freeze({ name: 'accept', value: 'text/plain' }),
          ...(includeCredential || leakCredential
            ? [
                Object.freeze({
                  name: 'authorization',
                  value: AUTHORIZATION_SECRET
                })
              ]
            : [])
        ])
      })
      const compiled = compiledRequest(
        provider,
        wire,
        includeCredential
      )
      return {
        endpoint: Object.freeze({ id: input.endpointId }),
        requestVariant: Object.freeze({ id: input.endpointId }),
        compiledRequest: compiled,
        capabilityIds: Object.freeze(['http.reviewed-read']),
        scopeSnapshotId: ids.scope,
        ownerRef: ids.target,
        identityRef,
        credentialRef: includeCredential ? credentialRef : null,
        requestBytes:
          Buffer.byteLength(wire.method, 'utf8') +
          Buffer.byteLength(wire.url, 'utf8') +
          wire.headers.reduce(
            (total, header) =>
              total +
              Buffer.byteLength(header.name, 'ascii') +
              Buffer.byteLength(header.value, 'ascii') +
              4,
            0
          )
      } as unknown as LegacyV1RequestCompilerAdapterOutput
    }
  )
  const requestAdapter = {
    compile
  } as unknown as LegacyV1RequestCompilerAdapter

  let policyIndex = 0
  const decisionIds = [ids.rootDecision, ids.childDecision] as const
  const proposalIds = [ids.rootProposal, ids.childProposal] as const
  const policyEvaluate = vi.fn(
    async (input: Parameters<PolicyBroker['evaluate']>[0]) => {
      const index = policyIndex++
      const decisionId = decisionIds[index]
      const proposalId = proposalIds[index]
      if (!decisionId || !proposalId) {
        throw new Error('Unexpected extra policy evaluation.')
      }
      const allowed =
        !options.policyRejectedUrls?.has(input.action.targetUrl)
      return {
        proposal: {
          id: proposalId
        },
        decision: {
          id: decisionId,
          allowed,
          requiresApproval: false,
          validUntil: VALID_UNTIL
        }
      }
    }
  )
  const policyBroker = {
    evaluate: policyEvaluate
  } as unknown as PolicyBroker

  const getExecutionDecision = vi.fn(async (decisionId: string) => ({
    scanId: ids.scan,
    workspaceId: ids.workspace,
    decision: {
      id: decisionId
    },
    scope: {
      validUntil: VALID_UNTIL
    }
  }))
  let toolCallIndex = 0
  const recordToolCall = vi.fn(async () =>
    sequentialId('53000000', ++toolCallIndex)
  )
  const listLegacyV1ExecutionEndpoints = vi.fn(async () => [
    {
      id: ids.rootEndpoint,
      method: 'GET',
      url: ROOT_URL
    },
    {
      id: ids.childEndpoint,
      method: 'GET',
      url: childUrl
    }
  ])
  const repository = {
    getExecutionDecision,
    recordToolCall,
    listLegacyV1ExecutionEndpoints
  } as unknown as AgentGoRepository

  let evidenceIndex = 0
  const evidenceSave = vi.fn(async () => ({
    id: sequentialId('54000000', ++evidenceIndex)
  }))
  const evidenceStore = {
    save: evidenceSave
  } as unknown as EvidenceStore

  const issued = (
    hop: 0 | 1,
    policyDecisionId: string,
    compiled: CompiledProbeRequest,
    validUntil: string
  ): IssuedExecutionAuthority =>
    ({
      grant: {
        id: hop === 0 ? ids.rootGrant : ids.childGrant,
        scanId: ids.scan,
        policyDecisionId,
        techniqueId: 'ssrf.redirect',
        techniqueVersion: '1.0.0',
        stepId: 'ssrf.redirect.follow',
        adapterKind: 'http',
        wireRequestHmac: compiled.wireRequestHmac,
        validUntil
      },
      lease: {
        id: hop === 0 ? ids.rootLease : ids.childLease
      },
      evidenceCaptureDecisions: captureDecisions(
        hop,
        policyDecisionId,
        validUntil
      )
    }) as unknown as IssuedExecutionAuthority

  const authorityIssue = vi.fn(
    async (input: IssueRootExecutionInput) =>
      issued(
        0,
        input.policyDecisionId,
        input.compiled,
        input.grantValidUntil
      )
  )
  const authorityIssueRedirectChild = vi.fn(
    async (input: IssueRedirectChildExecutionInput) =>
      issued(
        1,
        input.policyDecisionId,
        input.compiled,
        input.grantValidUntil
      )
  )
  const authority = {
    issue: authorityIssue,
    issueRedirectChild: authorityIssueRedirectChild
  } as unknown as ExecutionServiceDependencies['authority']

  const claimTokens = new Map<string, ExecutionClaimToken>([
    [
      ids.rootLease,
      Object.freeze(Object.create(null)) as ExecutionClaimToken
    ],
    [
      ids.childLease,
      Object.freeze(Object.create(null)) as ExecutionClaimToken
    ]
  ])
  const claim = vi.fn(
    async (input: {
      readonly leaseId: string
    }): Promise<ExecutionClaimToken> => {
      const token = claimTokens.get(input.leaseId)
      if (!token) throw new Error('Unknown test lease.')
      return token
    }
  )
  const validateResolvedAddresses = vi.fn(
    async (
      _token: ExecutionClaimToken,
      addresses: readonly ResolvedAddress[]
    ) => {
      if (
        addresses.some((address) =>
          options.rejectResolvedAddresses?.has(address.address)
        )
      ) {
        throw new Error('Resolved execution addresses are outside scope.')
      }
    }
  )
  const markDispatched = vi.fn(async () => undefined)
  const markResponseStarted = vi.fn(async () => undefined)
  const recordInteractionAudit = vi.fn(
    async (
      _token: ExecutionClaimToken,
      input: ExecutionInteractionAuditInput
    ) => input.interaction.id
  )
  const finalizeSucceeded = vi.fn(async () => ({}))
  const finalizeFailed = vi.fn(
    async (
      _token: ExecutionClaimToken,
      _input: Readonly<{
        code: string
        responseBytes: number
        evidenceRefs: readonly string[]
      }>
    ) => ({})
  )
  const revoke = vi.fn(
    async (
      _leaseId: string,
      _reason: 'revoked' | 'guard-rejected' | 'unsupported-adapter'
    ) => ({})
  )
  const rejectInvalidRunnerOutput = vi.fn(
    async (
      leaseId: string,
      token: ExecutionClaimToken | undefined
    ) => {
      if (
        token !== undefined &&
        token === claimTokens.get(leaseId)
      ) {
        return finalizeFailed(token, {
          code: 'runner-output-invalid',
          responseBytes: 0,
          evidenceRefs: []
        })
      }
      return revoke(leaseId, 'guard-rejected')
    }
  )
  const guard = {
    claim,
    validateResolvedAddresses,
    markDispatched,
    markResponseStarted,
    recordInteractionAudit,
    finalizeSucceeded,
    finalizeFailed,
    rejectInvalidRunnerOutput,
    revoke
  }
  const executionGuard = guard as unknown as PolicyExecutionGuard
  const httpExecutionGuard =
    guard as unknown as HttpExecutionGuard<ExecutionClaimToken>

  const networkSend = vi.fn((_url: string) => undefined)
  const runnerExecute = vi.fn(
    async (
      request: HttpExecutionRequest
    ): Promise<HttpExecutionResult<ExecutionClaimToken>> => {
      const token = await httpExecutionGuard.claim({
        leaseId: request.leaseId,
        wire: request.wire,
        limits: {
          timeoutMs: request.timeoutMs,
          maxResponseBytes: request.maxResponseBytes ?? 5 * 1024 * 1024
        }
      })
      const address =
        request.wire.url === ROOT_URL
          ? '203.0.113.10'
          : childAddress
      const addresses = Object.freeze([
        Object.freeze({ address, family: 4 as const })
      ])
      try {
        await httpExecutionGuard.validateResolvedAddresses(
          token,
          addresses
        )
      } catch {
        return attachClaimToken(
          {
            requestId: request.requestId,
            status: 'failed',
            finalUrl: request.wire.url,
            method: request.wire.method,
            requestHeaders: redactedRequestHeaders(request.wire),
            responseHeaders: {},
            responseBytes: 0,
            durationMs: 1,
            resolvedAddresses: [address],
            errorCode: 'address-rejected',
            errorMessage:
              'The resolved target addresses were rejected.'
          },
          token
        )
      }
      await httpExecutionGuard.markDispatched(token)
      networkSend(request.wire.url)
      await httpExecutionGuard.markResponseStarted(token)
      const isRoot = request.wire.url === ROOT_URL
      const body = Uint8Array.from(
        Buffer.from(isRoot ? 'redirect' : 'complete', 'utf8')
      )
      return attachClaimToken(
        {
          requestId: request.requestId,
          status: 'succeeded',
          finalUrl: request.wire.url,
          method: request.wire.method,
          statusCode: isRoot ? 302 : 200,
          ...(isRoot ? { redirectLocation: childUrl } : {}),
          requestHeaders: redactedRequestHeaders(request.wire),
          responseHeaders: {
            'content-type': 'text/plain'
          },
          responseBody: body,
          responseBodySha256: digest(body),
          responseBytes: body.byteLength,
          durationMs: 1,
          resolvedAddresses: [address]
        },
        token
      )
    }
  )
  const httpRunner = {
    execute: runnerExecute,
    cancel: vi.fn(async () => undefined)
  } as unknown as HttpRunner<ExecutionClaimToken>
  const browserRunner = {
    execute: vi.fn(async () => {
      throw new Error('Browser runner is outside this HTTP fixture.')
    }),
    cancel: vi.fn(async () => undefined)
  } as unknown as BrowserRunner

  const service = new ExecutionService({
    repository,
    evidenceStore,
    httpRunner,
    browserRunner,
    requestAdapter,
    authority,
    policyBroker,
    executionGuard,
    evidenceCapturePolicy: new EvidenceCapturePolicy(),
    hashKeyProvider: provider,
    clock: () => NOW_MS
  })
  const input: HttpExecutionStepInput = {
    adapterKind: 'http',
    scanId: ids.scan,
    agentRunId: ids.agentRun,
    familyId: 'ssrf',
    stepId: 'ssrf.redirect.follow',
    purpose: 'read',
    summary: 'Follow one reviewed redirect through a fresh grant.',
    expectedEvidence: 'Hash-only request and response summaries.',
    endpointId: ids.rootEndpoint,
    desiredUrl: ROOT_URL,
    identityId: ids.identity,
    timeoutMs: 1_000,
    maxResponseBytes: 16_384,
    maxRedirects: 1
  }

  return {
    service,
    input,
    childUrl,
    adapterCalls,
    compile,
    policyEvaluate,
    authorityIssue,
    authorityIssueRedirectChild,
    evidenceSave,
    recordToolCall,
    claim,
    validateResolvedAddresses,
    markDispatched,
    markResponseStarted,
    recordInteractionAudit,
    finalizeSucceeded,
    finalizeFailed,
    rejectInvalidRunnerOutput,
    revoke,
    runnerExecute,
    networkSend
  }
}

describe('ExecutionService V2 HTTP redirect boundary', () => {
  it('revokes an issued lease when malformed output carries a forged claim token', async () => {
    const fixture = createRedirectFixture()
    const forgedClaimToken = Object.freeze(Object.create(null))
    fixture.runnerExecute.mockImplementationOnce(async (request) => {
      const malformed = {
        requestId: request.requestId,
        status: 'succeeded',
        finalUrl: 'https://different.example.test/',
        method: request.wire.method,
        requestHeaders: redactedRequestHeaders(request.wire),
        responseHeaders: {},
        responseBytes: 0,
        durationMs: 1,
        resolvedAddresses: []
      } as unknown as HttpExecutionResult<ExecutionClaimToken>
      return attachClaimToken(malformed, forgedClaimToken)
    })
    await expect(
      fixture.service.execute(fixture.input)
    ).rejects.toThrow('HTTP runner output failed closed validation.')

    expect(
      fixture.rejectInvalidRunnerOutput
    ).toHaveBeenCalledExactlyOnceWith(
      ids.rootLease,
      forgedClaimToken
    )
    expect(fixture.finalizeFailed).not.toHaveBeenCalled()
    expect(fixture.revoke).toHaveBeenCalledExactlyOnceWith(
      ids.rootLease,
      'guard-rejected'
    )
    expect(fixture.claim).not.toHaveBeenCalled()
    expect(fixture.networkSend).not.toHaveBeenCalled()
  })

  it('uses a fresh policy decision, child grant, lease and DNS guard for a cross-origin hop', async () => {
    const fixture = createRedirectFixture()

    const stored = await fixture.service.execute(fixture.input)

    expect(stored.result.status).toBe('succeeded')
    expect(stored.result.finalUrl).toBe(CHILD_URL)
    expect(stored.policyDecisionIds).toEqual([
      ids.rootDecision,
      ids.childDecision
    ])
    expect(stored.grantIds).toEqual([
      ids.rootGrant,
      ids.childGrant
    ])
    expect(stored.leaseIds).toEqual([
      ids.rootLease,
      ids.childLease
    ])
    expect(stored.toolCallIds).toHaveLength(2)
    expect(stored.interactionIds).toHaveLength(2)
    expect(stored.evidenceRefs).toHaveLength(4)
    expect(stored.result.redirectChain).toEqual([
      {
        hop: 1,
        from: ROOT_URL,
        to: CHILD_URL,
        statusCode: 302,
        policyDecisionId: ids.rootDecision,
        grantId: ids.rootGrant,
        leaseId: ids.rootLease
      }
    ])

    expect(fixture.compile).toHaveBeenCalledTimes(2)
    expect(
      fixture.adapterCalls.map(
        ({ desiredTargetUrl, credentialMode }) => ({
          desiredTargetUrl,
          credentialMode
        })
      )
    ).toEqual([
      {
        desiredTargetUrl: ROOT_URL,
        credentialMode: 'include'
      },
      {
        desiredTargetUrl: CHILD_URL,
        credentialMode: 'omit'
      }
    ])
    const rootWire = fixture.runnerExecute.mock.calls[0]?.[0].wire
    const childWire = fixture.runnerExecute.mock.calls[1]?.[0].wire
    expect(rootWire?.headers.map(({ name }) => name)).toContain(
      'authorization'
    )
    expect(childWire?.headers.map(({ name }) => name)).not.toContain(
      'authorization'
    )

    expect(fixture.policyEvaluate).toHaveBeenCalledTimes(2)
    expect(fixture.authorityIssue).toHaveBeenCalledOnce()
    expect(
      fixture.authorityIssueRedirectChild
    ).toHaveBeenCalledOnce()
    expect(
      fixture.authorityIssueRedirectChild.mock.calls[0]?.[0]
    ).toMatchObject({
      parentGrantId: ids.rootGrant,
      parentLeaseId: ids.rootLease,
      policyDecisionId: ids.childDecision,
      credentialRef: null
    })
    expect(fixture.runnerExecute).toHaveBeenCalledTimes(2)
    expect(fixture.runnerExecute.mock.calls[0]?.[0]).not.toHaveProperty(
      'followRedirects'
    )
    expect(fixture.runnerExecute.mock.calls[0]?.[0]).not.toHaveProperty(
      'maxRedirects'
    )
    expect(fixture.claim.mock.calls.map(([input]) => input.leaseId)).toEqual([
      ids.rootLease,
      ids.childLease
    ])
    expect(fixture.validateResolvedAddresses).toHaveBeenCalledTimes(2)
    expect(fixture.networkSend.mock.calls.map(([url]) => url)).toEqual([
      ROOT_URL,
      CHILD_URL
    ])
    expect(
      fixture.finalizeSucceeded.mock.invocationCallOrder[0]!
    ).toBeLessThan(
      fixture.authorityIssueRedirectChild.mock.invocationCallOrder[0]!
    )
  })

  it('rejects an out-of-scope redirect in the fresh policy evaluation before child issuance or send', async () => {
    const outsideUrl = 'https://outside.example.test/final'
    const fixture = createRedirectFixture({
      childUrl: outsideUrl,
      policyRejectedUrls: new Set([outsideUrl])
    })

    await expect(
      fixture.service.execute(fixture.input)
    ).rejects.toThrow(
      'Security policy rejected the compiled HTTP request.'
    )

    expect(fixture.compile).toHaveBeenCalledTimes(2)
    expect(fixture.policyEvaluate).toHaveBeenCalledTimes(2)
    expect(fixture.authorityIssue).toHaveBeenCalledOnce()
    expect(
      fixture.authorityIssueRedirectChild
    ).not.toHaveBeenCalled()
    expect(fixture.runnerExecute).toHaveBeenCalledOnce()
    expect(fixture.validateResolvedAddresses).toHaveBeenCalledOnce()
    expect(fixture.networkSend).toHaveBeenCalledExactlyOnceWith(
      ROOT_URL
    )
  })

  it.each([
    ['private', '10.0.0.8'],
    ['metadata', '169.254.169.254']
  ])(
    'rejects a %s redirect address through the fresh DNS guard before the child network send',
    async (_kind, rejectedAddress) => {
      const childUrl = `https://${_kind}.example.test/final`
      const fixture = createRedirectFixture({
        childUrl,
        childAddress: rejectedAddress,
        rejectResolvedAddresses: new Set([rejectedAddress])
      })

      const stored = await fixture.service.execute(fixture.input)

      expect(stored.result).toMatchObject({
        status: 'failed',
        finalUrl: childUrl,
        errorCode: 'address-rejected',
        resolvedAddresses: [rejectedAddress]
      })
      expect(stored.policyDecisionIds).toEqual([
        ids.rootDecision,
        ids.childDecision
      ])
      expect(stored.grantIds).toEqual([
        ids.rootGrant,
        ids.childGrant
      ])
      expect(stored.leaseIds).toEqual([
        ids.rootLease,
        ids.childLease
      ])
      expect(fixture.validateResolvedAddresses).toHaveBeenCalledTimes(2)
      expect(fixture.markDispatched).toHaveBeenCalledOnce()
      expect(fixture.networkSend).toHaveBeenCalledExactlyOnceWith(
        ROOT_URL
      )
      expect(fixture.finalizeFailed).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          code: 'address-rejected'
        })
      )
    }
  )

  it('fails closed before fresh policy, child issuance or send when an omit-mode adapter retains Authorization', async () => {
    const fixture = createRedirectFixture({
      leakAuthorizationOnOmit: true
    })

    const error = await fixture.service.execute(fixture.input).then(
      () => undefined,
      (reason: unknown) => reason
    )

    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toBe(
      'Credential-omitted HTTP request contains a credential-bearing header.'
    )
    expect((error as Error).message).not.toContain(
      AUTHORIZATION_SECRET
    )
    expect(fixture.compile).toHaveBeenCalledTimes(2)
    expect(fixture.policyEvaluate).toHaveBeenCalledOnce()
    expect(fixture.authorityIssue).toHaveBeenCalledOnce()
    expect(
      fixture.authorityIssueRedirectChild
    ).not.toHaveBeenCalled()
    expect(fixture.runnerExecute).toHaveBeenCalledOnce()
    expect(fixture.networkSend).toHaveBeenCalledExactlyOnceWith(
      ROOT_URL
    )
    const persisted = JSON.stringify({
      evidence: fixture.evidenceSave.mock.calls,
      interactions: fixture.recordInteractionAudit.mock.calls,
      toolCalls: fixture.recordToolCall.mock.calls
    })
    expect(persisted).not.toContain(AUTHORIZATION_SECRET)
  })
})
