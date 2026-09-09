import { randomUUID } from 'node:crypto'
import {
  L2_CLEANUP_CAPABILITY_ID,
  type ActorContext,
  type ApprovalRecordView,
  type CleanupReceipt,
  type RequestExecutionState,
  type TestObjectRef
} from '@agentgo/contracts'
import { canonicalJson, evaluateCleanupCapability, sha256Text } from '@agentgo/domain'
import type { ExecutionPort, HttpExecutionResultView } from './execution-port'
import {
  ApprovalError,
  ApprovalService
} from './approval-service'
import type { L2BindingService } from './l2-binding-service'
import {
  L2ProtocolError,
  L2ProtocolService,
  type L2BundleView
} from './l2-protocol-service'

export type L2OrchestratorFault =
  | 'crash-before-primary'
  | 'drop-primary-response'
  | 'fail-cleanup'

export interface L2ProbeRunInput {
  readonly bundleId: string
  readonly bundleVersion: number
  readonly actor: ActorContext
  readonly agentRunId: string
  readonly sessionId: string
  readonly csrfBindingHash: string
  readonly identityId: string
  readonly cookieName?: string
  readonly fault?: L2OrchestratorFault
}

export interface L2ProbeRunResult {
  readonly view: L2BundleView
  readonly approval: ApprovalRecordView
  readonly approvalMode: 'fixture-only' | 'trusted-backend'
  readonly primaryRequestCount: number
  readonly receipt?: CleanupReceipt
  readonly evidenceHashes: {
    readonly preRead: string
    readonly primary?: string
    readonly postRead?: string
    readonly cleanup?: string
    readonly cleanupVerify?: string
    readonly terminalRead?: string
  }
}

export class L2ProbeOrchestrator {
  readonly #l2: L2ProtocolService
  readonly #approvals: ApprovalService
  readonly #bindings: L2BindingService
  readonly #execution: ExecutionPort

  constructor(dependencies: {
    readonly l2ProtocolService: L2ProtocolService
    readonly approvalService: ApprovalService
    readonly bindingService: L2BindingService
    readonly executionPort: ExecutionPort
  }) {
    this.#l2 = dependencies.l2ProtocolService
    this.#approvals = dependencies.approvalService
    this.#bindings = dependencies.bindingService
    this.#execution = dependencies.executionPort
  }

  async run(input: L2ProbeRunInput): Promise<L2ProbeRunResult> {
    let view = await this.#requireView(input.bundleId, input.bundleVersion)
    const freshness = await this.#bindings.assertBindingsFresh(view.bundle)
    if (freshness !== 'ok') {
      throw new L2ProtocolError(freshness)
    }
    const proposal = await this.#approvals.createProposal(
      view.bundle.bundleId,
      view.bundle.bundleVersion
    )
    const approved = await this.#approvals.approve({
      actor: input.actor,
      proposalId: proposal.proposalId
    })
    if (!approved.ok) {
      throw new ApprovalError(approved.reasonCode, approved.message)
    }
    view = await this.#requireView(input.bundleId, input.bundleVersion)

    const readUrl = resourceUrl(view, 'GET')
    const writeUrl = resourceUrl(view, 'POST')
    const testObjectRef = objectRef(view)
    const evidenceHashes: {
      preRead: string
      primary?: string
      postRead?: string
      cleanup?: string
      cleanupVerify?: string
      terminalRead?: string
    } = {
      preRead: ''
    }
    let primaryRequestCount = 0
    let primaryExecutionState: RequestExecutionState = 'sent-known-complete'
    let primaryResponseMissing = false

    view = await this.#transition(view, 'start-pre-read', true)
    const preRead = await this.#read(input, view, readUrl, testObjectRef, 'l2.pre-read')
    evidenceHashes.preRead = hashEvidence(preRead.result)
    view = await this.#transition(view, 'complete-pre-read', true)

    if (input.fault === 'crash-before-primary') {
      throw new Error('Injected crash before primary send.')
    }

    view = await this.#transition(view, 'start-primary', true)
    const consumed = await this.#approvals.consumeForPrimary(approved.view.record.approvalId)
    try {
      const primary = await this.#write(input, view, writeUrl, testObjectRef, {
        stepId: 'l2.primary',
        purpose: 'primary',
        body: { status: 'submitted' },
        approvalId: consumed.record.approvalId,
        summary: 'L2 primary state change on the disposable TestObject.'
      })
      primaryRequestCount = 1
      if (input.fault === 'drop-primary-response') {
        view = await this.#transition(view, 'mark-primary-unknown', true)
        primaryExecutionState = 'response-missing'
        primaryResponseMissing = true
      } else if (primary.result.status !== 'succeeded') {
        view = await this.#transition(view, 'mark-primary-unknown', true)
        throw new L2ProtocolError('request-execution-state-unknown')
      } else {
        evidenceHashes.primary = hashEvidence(primary.result)
        view = await this.#transition(view, 'complete-primary', true)
      }
    } catch (error) {
      if (error instanceof L2ProtocolError) throw error
      view = await this.#transition(view, 'mark-primary-unknown', true)
      throw error
    }

    if (!primaryResponseMissing) {
      view = await this.#transition(view, 'start-post-read', true)
    }
    const postRead = await this.#read(input, view, readUrl, testObjectRef, 'l2.post-read')
    evidenceHashes.postRead = hashEvidence(postRead.result)
    const postStatus = jsonObjectStatus(postRead.result)
    const expectedPostStatus = expectedStatusConstraint(view, 'new')
    if (postStatus === undefined || postStatus !== expectedPostStatus) {
      throw new L2ProtocolError(
        'unknown-side-effect',
        'Post-read did not observe the expected TestObject state change.'
      )
    }
    if (!primaryResponseMissing) {
      view = await this.#transition(view, 'complete-post-read', true)
    }

    const cleanupStep = view.bundle.steps.find((step) => step.kind === 'cleanup')
    if (cleanupStep?.kind !== 'cleanup') {
      throw new L2ProtocolError('missing-cleanup-protocol')
    }
    const cleanupGate = evaluateCleanupCapability({
      protocol: cleanupStep.cleanupProtocol,
      testObject: view.testObject,
      bundle: view.bundle,
      requestedMethod: cleanupStep.cleanupProtocol.method,
      requestedPath: cleanupStep.cleanupProtocol.path,
      requestedResourceId: view.testObject.canonicalResource.resourceId,
      requestedBundleHash: view.bundle.bundleHash
    })
    if (cleanupGate !== 'ok') {
      throw new L2ProtocolError(cleanupGate)
    }
    if ((cleanupStep.cleanupProtocol.method as string) === 'DELETE') {
      throw new L2ProtocolError('generic-http-delete-forbidden')
    }

    view = await this.#transition(view, 'start-cleanup', true)
    try {
      const cleanup = await this.#write(input, view, writeUrl, testObjectRef, {
        stepId: 'l2.cleanup',
        purpose: 'cleanup',
        body: { action: 'reset' },
        approvalId: consumed.record.approvalId,
        summary: 'Declared TestObject cleanup reset.',
        cleanupPlan: 'reset disposable fixture TestObject to baseline draft'
      })
      evidenceHashes.cleanup = hashEvidence(cleanup.result)
      if (input.fault === 'fail-cleanup' || cleanup.result.status !== 'succeeded') {
        await this.#freezeCleanupFailure(view, 'Cleanup execution did not complete successfully.')
      }
    } catch (error) {
      if (error instanceof L2ProtocolError) throw error
      await this.#freezeCleanupFailure(view, 'Cleanup execution failed before a safe terminal state was observed.')
    }
    view = await this.#transition(view, 'complete-cleanup', true)

    view = await this.#transition(view, 'start-cleanup-verify', true)
    const expectedTerminal = view.testObject.cleanupProtocol.expectedTerminalState
    try {
      const verify = await this.#read(input, view, readUrl, testObjectRef, 'l2.cleanup-verify')
      evidenceHashes.cleanupVerify = hashEvidence(verify.result)
      const verifyStatus = jsonObjectStatus(verify.result)
      if (verifyStatus === undefined || verifyStatus !== expectedTerminal) {
        await this.#freezeCleanupFailure(
          view,
          'Cleanup verify did not return JSON with the declared terminal TestObject state.'
        )
      }
    } catch (error) {
      if (error instanceof L2ProtocolError) throw error
      await this.#freezeCleanupFailure(view, 'Cleanup verify failed before the terminal state was proven.')
    }
    view = await this.#transition(view, 'complete-cleanup-verify', true)
    view = await this.#transition(view, 'start-terminal-read', true)
    try {
      const terminal = await this.#read(input, view, readUrl, testObjectRef, 'l2.terminal-read')
      evidenceHashes.terminalRead = hashEvidence(terminal.result)
      const terminalStatus = jsonObjectStatus(terminal.result)
      if (terminalStatus === undefined || terminalStatus !== expectedTerminal) {
        await this.#freezeCleanupFailure(
          view,
          'Terminal read did not return JSON with the declared terminal TestObject state.'
        )
      }
    } catch (error) {
      if (error instanceof L2ProtocolError) throw error
      await this.#freezeCleanupFailure(view, 'Terminal read failed before the terminal state was proven.')
    }
    view = await this.#transition(view, 'complete-clean', true)

    const receipt = await this.#l2.issueCleanupReceipt({
      receiptId: randomUUID(),
      kind: 'cleanup-completed',
      bundleId: view.bundle.bundleId,
      bundleHash: view.bundle.bundleHash,
      testObjectId: view.testObject.testObjectId,
      testObjectVersion: view.testObject.objectVersion,
      testObjectHash: view.testObject.objectHash,
      stepEvidenceHashes: {
        preRead: evidenceHashes.preRead,
        primary: evidenceHashes.primary,
        postRead: evidenceHashes.postRead!,
        cleanup: evidenceHashes.cleanup,
        cleanupVerify: evidenceHashes.cleanupVerify!,
        terminalRead: evidenceHashes.terminalRead!
      },
      actorSlot: {
        status: 'resolved',
        actorId: approved.view.record.actorId,
        approvalRecordHash: approved.view.record.approvalHash
      },
      issuedAt: new Date().toISOString(),
      terminalResourceState: view.testObject.cleanupProtocol.expectedTerminalState,
      cleanupCapabilityId: L2_CLEANUP_CAPABILITY_ID,
      requestExecutionState: primaryExecutionState
    })

    return {
      view,
      approval: consumed,
      approvalMode: approved.view.record.approvalMode,
      primaryRequestCount,
      receipt,
      evidenceHashes
    }
  }

  async #read(
    input: L2ProbeRunInput,
    view: L2BundleView,
    url: string,
    testObjectRef: TestObjectRef,
    stepId: string
  ) {
    return this.#execution.executeL2Http({
      scanId: view.bundle.scanId,
      agentRunId: input.agentRunId,
      familyId: 'sqli',
      stepId,
      purpose: 'read',
      summary: `L2 ${stepId} observation of the disposable TestObject.`,
      expectedEvidence: 'JSON TestObject state',
      adapterKind: 'http',
      method: 'GET',
      desiredUrl: url,
      identityId: input.identityId,
      sessionId: input.sessionId,
      testObjectRef,
      timeoutMs: 5_000,
      maxResponseBytes: 65_536,
      probeLevel: 'active-safe',
      sideEffect: 'none'
    })
  }

  async #write(
    input: L2ProbeRunInput,
    view: L2BundleView,
    url: string,
    testObjectRef: TestObjectRef,
    step: {
      readonly stepId: string
      readonly purpose: 'primary' | 'cleanup'
      readonly body: Readonly<Record<string, string>>
      readonly approvalId: string
      readonly summary: string
      readonly cleanupPlan?: string
    }
  ) {
    return this.#execution.executeL2Http({
      scanId: view.bundle.scanId,
      agentRunId: input.agentRunId,
      familyId: 'sqli',
      stepId: step.stepId,
      purpose: step.purpose,
      summary: step.summary,
      expectedEvidence: 'JSON TestObject mutation result',
      adapterKind: 'http',
      method: 'POST',
      desiredUrl: url,
      identityId: input.identityId,
      sessionId: input.sessionId,
      csrfBindingHash: input.csrfBindingHash,
      jsonBody: step.body,
      testObjectRef,
      approvalBundleRef: step.approvalId,
      timeoutMs: 5_000,
      maxResponseBytes: 65_536,
      probeLevel: 'active-sensitive',
      sideEffect: 'reversible',
      ...(step.cleanupPlan ? { cleanupPlan: step.cleanupPlan } : {
        cleanupPlan: 'reset disposable fixture TestObject to baseline draft'
      })
    })
  }

  async #transition(
    view: L2BundleView,
    event: Parameters<L2ProtocolService['applyEvent']>[0]['event'],
    trustedApprovalPresent: boolean
  ): Promise<L2BundleView> {
    return this.#l2.applyEvent({
      bundleId: view.bundle.bundleId,
      bundleVersion: view.bundle.bundleVersion,
      event,
      expectedRowVersion: view.runtime.rowVersion,
      trustedApprovalPresent
    })
  }

  async #freezeCleanupFailure(view: L2BundleView, message: string): Promise<never> {
    await this.#transition(view, 'fail-cleanup', false)
    throw new L2ProtocolError('cleanup-failed-frozen', message)
  }

  async #requireView(bundleId: string, bundleVersion: number): Promise<L2BundleView> {
    const view = await this.#l2.getBundleView(bundleId, bundleVersion)
    if (!view) throw new L2ProtocolError('missing-test-object')
    return view
  }
}

function resourceUrl(view: L2BundleView, _method: 'GET' | 'POST'): string {
  const resource = view.testObject.canonicalResource
  return `${resource.origin}${resource.path}`
}

function objectRef(view: L2BundleView): TestObjectRef {
  return {
    id: view.testObject.testObjectId,
    version: view.testObject.objectVersion,
    ownerRef: view.testObject.targetId,
    scopeSnapshotId: view.testObject.scopeSnapshotId,
    statusSummary: 'in-use'
  }
}

function hashEvidence(result: HttpExecutionResultView): string {
  if (result.responseBodySha256 && /^[a-f0-9]{64}$/u.test(result.responseBodySha256)) {
    return result.responseBodySha256
  }
  return sha256Text(canonicalJson({
    status: result.status,
    statusCode: result.statusCode ?? null,
    bytes: result.responseBytes
  }))
}

function jsonObjectStatus(result: HttpExecutionResultView): string | undefined {
  if (!result.responseBody || result.responseBody.byteLength === 0) return undefined
  try {
    const parsed = JSON.parse(new TextDecoder().decode(result.responseBody)) as {
      status?: unknown
    }
    return typeof parsed.status === 'string' ? parsed.status : undefined
  } catch {
    return undefined
  }
}

function expectedStatusConstraint(
  view: L2BundleView,
  phase: 'old' | 'new'
): string | undefined {
  const constraint = view.bundle.sideEffectEnvelope.fieldWrites.find(
    (field) => field.fieldPath === 'status'
  )
  return phase === 'old' ? constraint?.oldValueConstraint : constraint?.newValueConstraint
}
