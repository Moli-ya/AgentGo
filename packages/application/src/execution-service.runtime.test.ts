import { afterEach, describe, expect, it, vi } from 'vitest'
import type {
  BrowserExecutionRequest,
  BrowserExecutionResult,
  BrowserRunner
} from '@agentgo/browser-runner'
import {
  EvidenceCaptureDecisionSchema,
  MAX_PROTECTED_EVIDENCE_RETENTION_SECONDS,
  PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
  PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
  PROTECTED_EVIDENCE_POLICY_VERSION,
  PROTECTED_EVIDENCE_PROTECTION_SCHEME,
  type EvidenceCaptureDecision,
  type EvidenceCaptureExecutionState
} from '@agentgo/contracts'
import type {
  AgentGoRepository,
  EvidenceStore
} from '@agentgo/db'
import type { HttpRunner } from '@agentgo/http-runner'
import { EvidenceCapturePolicy } from './evidence-capture-policy'
import type {
  ExecutionEvidenceCaptureDecisionSet,
  IssueRootExecutionInput,
  IssuedExecutionAuthority
} from './execution-authority'
import type {
  ExecutionClaimToken,
  ExecutionInteractionAuditInput,
  PolicyBroker,
  PolicyExecutionGuard
} from './execution-policy'
import type { BrowserOfflineExecutionStepInput } from './execution-port'
import {
  ExecutionService,
  type ExecutionServiceDependencies
} from './execution-service'
import type { LegacyV1RequestCompilerAdapter } from './legacy-v1-request-compiler-adapter'
import { EphemeralRequestHashKeyProvider } from './request-hash-key-provider'

const NOW = '2026-07-28T00:00:00.000Z'
const NOW_MS = Date.parse(NOW)
const POLICY_VALID_UNTIL = '2099-01-01T00:00:00.000Z'
const HTML_SECRET = 'HTML_SECRET_must_remain_process_local'
const MARKER_SECRET = 'MARKER_SECRET_must_remain_process_local'

const ids = {
  scan: '20000000-0000-4000-8000-000000000001',
  agentRun: '20000000-0000-4000-8000-000000000002',
  target: '20000000-0000-4000-8000-000000000003',
  scope: '20000000-0000-4000-8000-000000000004',
  workspace: '20000000-0000-4000-8000-000000000005',
  proposal: '20000000-0000-4000-8000-000000000006',
  decision: '20000000-0000-4000-8000-000000000007',
  grant: '20000000-0000-4000-8000-000000000008',
  lease: '20000000-0000-4000-8000-000000000009',
  toolCall: '20000000-0000-4000-8000-00000000000a',
  requestEvidence: '20000000-0000-4000-8000-00000000000b',
  resultEvidence: '20000000-0000-4000-8000-00000000000c',
  domEvidence: '20000000-0000-4000-8000-00000000000e',
  screenshotEvidence: '20000000-0000-4000-8000-00000000000f'
} as const

const providers: EphemeralRequestHashKeyProvider[] = []

afterEach(() => {
  for (const provider of providers.splice(0)) {
    provider.dispose()
  }
})

type BrowserResultFactory = (
  request: BrowserExecutionRequest
) => BrowserExecutionResult | object

interface FixtureOptions {
  readonly abortController?: AbortController
  readonly abortOnIssue?: boolean
  readonly resultFactory?: BrowserResultFactory
  readonly persistReviewable?: boolean
  readonly evidenceSaveFailureAt?: number
  readonly interactionAuditFailure?: boolean
  readonly interactionAuditIdentityChange?: boolean
  readonly discardUnboundResult?: boolean
}

function captureDecisionId(index: number): string {
  return `30000000-0000-4000-8000-${String(index).padStart(12, '0')}`
}

function captureDecision(
  index: number,
  validUntil: string,
  source: EvidenceCaptureDecision['source'],
  role: EvidenceCaptureDecision['role'],
  executionState: EvidenceCaptureExecutionState
): EvidenceCaptureDecision {
  return EvidenceCaptureDecisionSchema.parse({
    id: captureDecisionId(index),
    scanId: ids.scan,
    policyDecisionId: ids.decision,
    capturePolicyId: 'evidence-summary-v1',
    capturePolicyVersion: '1.0.0',
    techniqueId: 'xss.reflected',
    techniqueVersion: '1.0.0',
    stepId: 'xss.reflected.offline',
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
  validUntil: string,
  source: 'browser-request-summary' | 'browser-result-summary',
  role: 'request-summary' | 'result-summary'
) {
  return Object.freeze({
    succeeded: captureDecision(
      startIndex,
      validUntil,
      source,
      role,
      'succeeded'
    ),
    failed: captureDecision(
      startIndex + 1,
      validUntil,
      source,
      role,
      'failed'
    ),
    cancelled: captureDecision(
      startIndex + 2,
      validUntil,
      source,
      role,
      'cancelled'
    ),
    'timed-out': captureDecision(
      startIndex + 3,
      validUntil,
      source,
      role,
      'timed-out'
    )
  })
}

function reviewableCaptureDecision(
  index: number,
  validUntil: string,
  source: 'dom-snapshot' | 'browser-screenshot',
  role: 'dom-snapshot' | 'screenshot',
  executionState: EvidenceCaptureExecutionState
): EvidenceCaptureDecision {
  return EvidenceCaptureDecisionSchema.parse({
    id: captureDecisionId(index),
    scanId: ids.scan,
    policyDecisionId: ids.decision,
    capturePolicyId: 'evidence-summary-v1',
    capturePolicyVersion: '1.0.0',
    techniqueId: 'xss.reflected',
    techniqueVersion: '1.0.0',
    stepId: 'xss.reflected.offline',
    executionState,
    source,
    role,
    action: 'protected-original',
    validFrom: NOW,
    validUntil,
    maxSourceBytes: 16_777_216,
    maxExcerptBytes: 32,
    jsonPointers: [],
    oobMetadataFields: [],
    protectedOriginalPlan: {
      protectionScheme: PROTECTED_EVIDENCE_PROTECTION_SCHEME,
      accessPolicyId: PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
      accessPolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
      derivativePolicyId: PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
      derivativePolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
      retentionSeconds: Math.min(
        7 * 24 * 60 * 60,
        MAX_PROTECTED_EVIDENCE_RETENTION_SECONDS
      ),
      maxScanPlaintextBytes: 16_777_216,
      maxWorkspacePlaintextBytes: 16_777_216
    }
  })
}

function reviewableCaptureDecisions(
  startIndex: number,
  validUntil: string,
  source: 'dom-snapshot' | 'browser-screenshot',
  role: 'dom-snapshot' | 'screenshot'
) {
  return Object.freeze({
    succeeded: reviewableCaptureDecision(
      startIndex,
      validUntil,
      source,
      role,
      'succeeded'
    ),
    failed: reviewableCaptureDecision(
      startIndex + 1,
      validUntil,
      source,
      role,
      'failed'
    ),
    cancelled: reviewableCaptureDecision(
      startIndex + 2,
      validUntil,
      source,
      role,
      'cancelled'
    ),
    'timed-out': reviewableCaptureDecision(
      startIndex + 3,
      validUntil,
      source,
      role,
      'timed-out'
    )
  })
}

function captureDecisions(
  validUntil: string
): ExecutionEvidenceCaptureDecisionSet {
  return Object.freeze({
    'execution-interruption-summary': Object.freeze({
      interrupted: captureDecision(
        9,
        validUntil,
        'execution-interruption-summary',
        'interruption-summary',
        'interrupted'
      )
    }),
    'browser-request-summary': normalCaptureDecisions(
      1,
      validUntil,
      'browser-request-summary',
      'request-summary'
    ),
    'browser-result-summary': normalCaptureDecisions(
      5,
      validUntil,
      'browser-result-summary',
      'result-summary'
    ),
    'dom-snapshot': reviewableCaptureDecisions(
      10,
      validUntil,
      'dom-snapshot',
      'dom-snapshot'
    ),
    'browser-screenshot': reviewableCaptureDecisions(
      14,
      validUntil,
      'browser-screenshot',
      'screenshot'
    )
  })
}

function successResult(
  request: BrowserExecutionRequest
): BrowserExecutionResult {
  const pageTitle = 'Offline fixture'
  const links: string[] = []
  const forms: BrowserExecutionResult['forms'] = []
  const domSnapshot = '<main>sanitized fixture</main>'
  const markerExecuted =
    request.marker === undefined ? undefined : true
  const metadataBytes = Buffer.byteLength(
    JSON.stringify({
      title: pageTitle,
      links,
      forms,
      markerExecuted
    }),
    'utf8'
  )
  return {
    requestId: request.requestId,
    status: 'succeeded',
    finalUrl: request.baseUrl,
    pageTitle,
    links,
    forms,
    domSnapshot,
    ...(markerExecuted !== undefined ? { markerExecuted } : {}),
    networkRequestsBlocked: 0,
    resultBytes:
      metadataBytes + Buffer.byteLength(domSnapshot, 'utf8'),
    durationMs: 1
  }
}

function failedResult(
  request: BrowserExecutionRequest
): BrowserExecutionResult {
  return {
    requestId: request.requestId,
    status: 'failed',
    finalUrl: request.baseUrl,
    links: [],
    forms: [],
    networkRequestsBlocked: 0,
    resultBytes: 0,
    durationMs: 1,
    errorCode: 'render-error',
    errorMessage:
      'The offline browser could not render the supplied document.'
  }
}

function createFixture(options: FixtureOptions = {}) {
  const provider = new EphemeralRequestHashKeyProvider()
  providers.push(provider)
  const claimToken = Object.freeze(
    Object.create(null)
  ) as ExecutionClaimToken
  const evidenceIds = [
    ids.requestEvidence,
    ids.resultEvidence
  ] as const
  let evidenceIndex = 0

  const getScanRow = vi.fn(async () => ({
    id: ids.scan,
    targetId: ids.target,
    scopeSnapshotId: ids.scope
  }))
  const getExecutionDecision = vi.fn(async () => ({
    scanId: ids.scan,
    workspaceId: ids.workspace,
    decision: {
      id: ids.decision
    },
    scope: {
      validUntil: POLICY_VALID_UNTIL
    }
  }))
  const recordToolCall = vi.fn(async () => ids.toolCall)
  const repository = {
    getScanRow,
    getExecutionDecision,
    recordToolCall
  } as unknown as AgentGoRepository

  const evidenceSave = vi.fn(async (_input: unknown) => {
    if (options.evidenceSaveFailureAt === evidenceIndex + 1) {
      throw new Error('Injected Evidence persistence failure.')
    }
    const id = evidenceIds[evidenceIndex]
    if (!id) throw new Error('Unexpected extra evidence save.')
    evidenceIndex += 1
    return {
      id,
      filePath: `fixture/${id}.json`,
      sha256: id.replaceAll('-', '').padEnd(64, '0').slice(0, 64)
    }
  })
  const discardUnboundEvidence = vi.fn(async (_evidence: unknown) =>
    options.discardUnboundResult ?? true
  )
  const saveProtectedOriginal = vi.fn(async (input: { artifact?: { source?: string } }) => {
    const source = input.artifact?.source
    const id =
      source === 'browser-screenshot' ? ids.screenshotEvidence : ids.domEvidence
    return {
      original: {
        id,
        filePath: `fixture/${id}.bin`,
        sha256: id.replaceAll('-', '').padEnd(64, '0').slice(0, 64)
      }
    }
  })
  const evidenceStore = {
    save: evidenceSave,
    discardUnboundEvidence,
    ...(options.persistReviewable
      ? { saveProtectedOriginalWithDerivative: saveProtectedOriginal }
      : {})
  } as unknown as EvidenceStore

  const policyEvaluate = vi.fn(async () => ({
    proposal: {
      id: ids.proposal
    },
    decision: {
      id: ids.decision,
      allowed: true,
      requiresApproval: false,
      validUntil: POLICY_VALID_UNTIL
    }
  }))
  const policyBroker = {
    evaluate: policyEvaluate
  } as unknown as PolicyBroker

  const authorityIssue = vi.fn(
    async (input: IssueRootExecutionInput) => {
      if (options.abortOnIssue) {
        options.abortController?.abort()
      }
      return {
        grant: {
          id: ids.grant,
          scanId: ids.scan,
          policyDecisionId: ids.decision,
          techniqueId: 'xss.reflected',
          techniqueVersion: '1.0.0',
          stepId: 'xss.reflected.offline',
          adapterKind: 'browser-offline',
          wireRequestHmac: input.compiled.wireRequestHmac
        },
        lease: {
          id: ids.lease
        },
        evidenceCaptureDecisions: captureDecisions(
          input.grantValidUntil
        )
      } as unknown as IssuedExecutionAuthority
    }
  )
  const authority = {
    issue: authorityIssue
  } as unknown as ExecutionServiceDependencies['authority']

  const claimOffline = vi.fn(async () => claimToken)
  const markDispatched = vi.fn(async () => undefined)
  const markResponseStarted = vi.fn(async () => undefined)
  const recordInteractionAudit = vi.fn(
    async (
      _token: ExecutionClaimToken,
      input: ExecutionInteractionAuditInput
    ) => {
      if (options.interactionAuditFailure) {
        throw new Error('Injected interaction audit failure.')
      }
      return options.interactionAuditIdentityChange
        ? '20000000-0000-4000-8000-00000000000d'
        : input.interaction.id
    }
  )
  const finalizeSucceeded = vi.fn(async () => ({}))
  const finalizeFailed = vi.fn(async () => ({}))
  const revoke = vi.fn(async () => ({}))
  const executionGuard = {
    claimOffline,
    markDispatched,
    markResponseStarted,
    recordInteractionAudit,
    finalizeSucceeded,
    finalizeFailed,
    revoke
  } as unknown as PolicyExecutionGuard

  const browserExecute = vi.fn(
    async (request: BrowserExecutionRequest) =>
      options.resultFactory?.(request) ?? successResult(request)
  )
  const browserCancel = vi.fn(async () => undefined)
  const browserRunner = {
    execute: browserExecute,
    cancel: browserCancel
  } as unknown as BrowserRunner
  const httpRunner = {
    execute: vi.fn(async () => {
      throw new Error('HTTP runner is not used by this fixture.')
    }),
    cancel: vi.fn(async () => undefined)
  } as unknown as HttpRunner<ExecutionClaimToken>
  const requestAdapter = {
    compile: vi.fn(async () => {
      throw new Error('HTTP adapter is not used by this fixture.')
    })
  } as unknown as LegacyV1RequestCompilerAdapter

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
  const input: BrowserOfflineExecutionStepInput = {
    adapterKind: 'browser-offline',
    scanId: ids.scan,
    agentRunId: ids.agentRun,
    familyId: 'xss',
    stepId: 'xss.reflected.offline',
    purpose: 'read',
    summary: 'Inspect a supplied document in the offline browser.',
    expectedEvidence: 'Hash-only request and result summaries.',
    baseUrl: 'https://fixture.example.test/offline',
    html: `<main data-value="${HTML_SECRET}">fixture</main>`,
    action: 'inspect-dom',
    marker: MARKER_SECRET,
    timeoutMs: 1_000,
    maxDomBytes: 16_384,
    ...(options.abortController
      ? { signal: options.abortController.signal }
      : {})
  }

  return {
    service,
    input,
    claimToken,
    evidenceSave,
    discardUnboundEvidence,
    recordToolCall,
    authorityIssue,
    claimOffline,
    markDispatched,
    markResponseStarted,
    recordInteractionAudit,
    finalizeSucceeded,
    finalizeFailed,
    revoke,
    browserExecute,
    browserCancel,
    saveProtectedOriginal
  }
}

describe('ExecutionService offline audit boundary', () => {
  it('persists only hash-only artifacts before atomic audit and successful finalization', async () => {
    const fixture = createFixture()

    const stored = await fixture.service.execute(fixture.input)

    expect(stored.result.status).toBe('succeeded')
    expect(stored.toolCallId).toBe(ids.toolCall)
    expect(stored.grantIds).toEqual([ids.grant])
    expect(stored.leaseIds).toEqual([ids.lease])
    expect(stored.evidenceRefs).toEqual([
      ids.requestEvidence,
      ids.resultEvidence
    ])
    expect(stored.interactionIds).toHaveLength(1)

    expect(fixture.evidenceSave).toHaveBeenCalledTimes(2)
    const saveInputs = fixture.evidenceSave.mock.calls.map(
      ([input]) =>
        input as {
          type: string
          content: string
          redactionState: string
        }
    )
    expect(saveInputs.map(({ type }) => type)).toEqual([
      'evidence-capture-hash-only',
      'evidence-capture-hash-only'
    ])
    expect(
      saveInputs.every(
        ({ redactionState }) => redactionState === 'redacted'
      )
    ).toBe(true)

    expect(fixture.recordInteractionAudit).toHaveBeenCalledOnce()
    const audit =
      fixture.recordInteractionAudit.mock.calls[0]?.[1]
    expect(audit?.evidenceLinks).toEqual([
      {
        evidenceId: ids.requestEvidence,
        captureDecisionId: expect.any(String),
        role: 'request-summary',
        ordinal: 0
      },
      {
        evidenceId: ids.resultEvidence,
        captureDecisionId: expect.any(String),
        role: 'result-summary',
        ordinal: 0
      }
    ])
    expect(audit?.interaction.requestSummary).toMatchObject({
      captureState: 'hash-only',
      source: 'browser-request-summary',
      evidenceRef: ids.requestEvidence
    })
    expect(audit?.interaction.responseSummary).toMatchObject({
      captureState: 'hash-only',
      source: 'browser-result-summary',
      evidenceRef: ids.resultEvidence
    })

    const persistedBoundary = JSON.stringify({
      evidence: fixture.evidenceSave.mock.calls,
      audit: fixture.recordInteractionAudit.mock.calls,
      tool: fixture.recordToolCall.mock.calls
    })
    expect(persistedBoundary).not.toContain(HTML_SECRET)
    expect(persistedBoundary).not.toContain(MARKER_SECRET)

    expect(fixture.finalizeSucceeded).toHaveBeenCalledWith(
      fixture.claimToken,
      {
        responseBytes: stored.result.resultBytes,
        evidenceRefs: [
          ids.requestEvidence,
          ids.resultEvidence
        ]
      }
    )
    expect(
      fixture.claimOffline.mock.invocationCallOrder[0]!
    ).toBeLessThan(
      fixture.markDispatched.mock.invocationCallOrder[0]!
    )
    expect(
      fixture.markDispatched.mock.invocationCallOrder[0]!
    ).toBeLessThan(
      fixture.browserExecute.mock.invocationCallOrder[0]!
    )
    expect(
      fixture.recordInteractionAudit.mock.invocationCallOrder[0]!
    ).toBeLessThan(
      fixture.finalizeSucceeded.mock.invocationCallOrder[0]!
    )
  })

  it('closes a claimed lease as runner-output-invalid without auditing malformed output', async () => {
    const fixture = createFixture({
      resultFactory: (request) => ({
        ...successResult(request),
        finalUrl: 'https://different.example.test/'
      })
    })

    const error = await fixture.service.execute(fixture.input).then(
      () => undefined,
      (reason: unknown) => reason
    )

    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).not.toContain(HTML_SECRET)
    expect((error as Error).message).not.toContain(MARKER_SECRET)
    expect(fixture.finalizeFailed).toHaveBeenCalledWith(
      fixture.claimToken,
      {
        code: 'runner-output-invalid',
        responseBytes: 0,
        evidenceRefs: []
      }
    )
    expect(fixture.evidenceSave).not.toHaveBeenCalled()
    expect(fixture.recordInteractionAudit).not.toHaveBeenCalled()
    expect(fixture.revoke).not.toHaveBeenCalled()
  })

  it('discards the first unbound artifact before terminalizing a second-save failure', async () => {
    const fixture = createFixture({
      evidenceSaveFailureAt: 2
    })

    await expect(fixture.service.execute(fixture.input)).rejects.toThrow(
      'Browser execution evidence persistence failed.'
    )

    expect(fixture.evidenceSave).toHaveBeenCalledTimes(2)
    expect(fixture.recordInteractionAudit).not.toHaveBeenCalled()
    expect(fixture.discardUnboundEvidence).toHaveBeenCalledOnce()
    expect(fixture.discardUnboundEvidence).toHaveBeenCalledWith(
      expect.objectContaining({ id: ids.requestEvidence })
    )
    expect(fixture.finalizeFailed).toHaveBeenCalledWith(
      fixture.claimToken,
      {
        code: 'audit-persistence-failed',
        responseBytes: successResult(
          fixture.browserExecute.mock.calls[0]![0]
        ).resultBytes,
        evidenceRefs: []
      }
    )
    expect(
      fixture.discardUnboundEvidence.mock.invocationCallOrder[0]!
    ).toBeLessThan(
      fixture.finalizeFailed.mock.invocationCallOrder[0]!
    )
  })

  it('discards both unbound artifacts after an atomic interaction audit rollback', async () => {
    const fixture = createFixture({
      interactionAuditFailure: true
    })

    await expect(fixture.service.execute(fixture.input)).rejects.toThrow(
      'Browser execution interaction persistence failed.'
    )

    expect(fixture.discardUnboundEvidence).toHaveBeenCalledTimes(2)
    expect(
      fixture.discardUnboundEvidence.mock.calls.map(
        ([evidence]) => (evidence as { id: string }).id
      )
    ).toEqual([ids.requestEvidence, ids.resultEvidence])
    expect(fixture.finalizeFailed).toHaveBeenCalledWith(
      fixture.claimToken,
      expect.objectContaining({
        code: 'audit-persistence-failed',
        evidenceRefs: []
      })
    )
  })

  it('retains and terminally binds artifacts already attached by a committed audit', async () => {
    const fixture = createFixture({
      interactionAuditIdentityChange: true,
      discardUnboundResult: false
    })

    await expect(fixture.service.execute(fixture.input)).rejects.toThrow(
      'Browser execution interaction persistence failed.'
    )

    expect(fixture.discardUnboundEvidence).toHaveBeenCalledTimes(2)
    expect(fixture.finalizeFailed).toHaveBeenCalledWith(
      fixture.claimToken,
      expect.objectContaining({
        code: 'audit-persistence-failed',
        evidenceRefs: [
          ids.requestEvidence,
          ids.resultEvidence
        ]
      })
    )
  })

  it('claims but does not dispatch when cancellation arrives after issuance', async () => {
    const abortController = new AbortController()
    const fixture = createFixture({
      abortController,
      abortOnIssue: true
    })

    const stored = await fixture.service.execute(fixture.input)

    expect(stored.result).toMatchObject({
      status: 'cancelled',
      errorCode: 'cancelled',
      resultBytes: 0
    })
    expect(fixture.authorityIssue).toHaveBeenCalledOnce()
    expect(fixture.claimOffline).toHaveBeenCalledOnce()
    expect(fixture.markDispatched).not.toHaveBeenCalled()
    expect(fixture.markResponseStarted).not.toHaveBeenCalled()
    expect(fixture.browserExecute).not.toHaveBeenCalled()
    expect(fixture.browserCancel).not.toHaveBeenCalled()
    expect(fixture.recordInteractionAudit).toHaveBeenCalledOnce()
    expect(fixture.evidenceSave).toHaveBeenCalledTimes(2)
    expect(fixture.finalizeFailed).toHaveBeenCalledWith(
      fixture.claimToken,
      {
        code: 'cancelled',
        responseBytes: 0,
        evidenceRefs: [
          ids.requestEvidence,
          ids.resultEvidence
        ]
      }
    )
    const audit =
      fixture.recordInteractionAudit.mock.calls[0]?.[1]
    expect(audit?.interaction.requestSummary).toMatchObject({
      executionState: 'cancelled'
    })
    expect(audit?.interaction.responseSummary).toMatchObject({
      executionState: 'cancelled'
    })
  })

  it('audits a valid failed result and finalizes it with a deterministic code', async () => {
    const fixture = createFixture({
      resultFactory: failedResult
    })

    const stored = await fixture.service.execute(fixture.input)

    expect(stored.result).toMatchObject({
      status: 'failed',
      errorCode: 'render-error',
      resultBytes: 0
    })
    expect(fixture.recordInteractionAudit).toHaveBeenCalledOnce()
    expect(fixture.evidenceSave).toHaveBeenCalledTimes(2)
    expect(fixture.finalizeSucceeded).not.toHaveBeenCalled()
    expect(fixture.finalizeFailed).toHaveBeenCalledWith(
      fixture.claimToken,
      {
        code: 'network-error',
        responseBytes: 0,
        evidenceRefs: [
          ids.requestEvidence,
          ids.resultEvidence
        ]
      }
    )
  })

  it('persists grant-bound DOM originals when the protector path is available', async () => {
    const fixture = createFixture({
      persistReviewable: true
    })

    const stored = await fixture.service.execute(fixture.input)

    expect(stored.reviewableDomOrScreenshotEvidence).toBe(true)
    expect(stored.evidenceRefs).toEqual([
      ids.requestEvidence,
      ids.resultEvidence,
      ids.domEvidence
    ])
    expect(fixture.saveProtectedOriginal).toHaveBeenCalledTimes(1)
    expect(fixture.finalizeSucceeded).toHaveBeenCalledWith(
      fixture.claimToken,
      {
        responseBytes: stored.result.resultBytes,
        evidenceRefs: [
          ids.requestEvidence,
          ids.resultEvidence
        ]
      }
    )
  })
})
