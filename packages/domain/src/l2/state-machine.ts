import type {
  ExecutionPurpose,
  L2ActionBundle,
  L2BundleEventType,
  L2BundleState,
  L2ProtocolReasonCode,
  TestObject
} from '@agentgo/contracts'
import { evaluateCleanupCapability } from './cleanup-policy'
import {
  bundleMatchesTestObject,
  sessionBindingsResolved,
  sideEffectEnvelopeEligibility,
  testObjectL2Eligibility
} from './eligibility'

export interface L2TransitionContext {
  readonly now: Date
  readonly bundle: L2ActionBundle
  readonly testObject: TestObject
  readonly trustedApprovalPresent: boolean
  readonly expectedRowVersion: number
  readonly actualRowVersion: number
  readonly primaryAlreadyStarted: boolean
  readonly primarySentProof: 'not-sent' | 'sent' | 'unknown'
  readonly freezeActive: boolean
  readonly isRecoveryProposal: boolean
}

export interface L2TransitionSuccess {
  readonly ok: true
  readonly nextState: L2BundleState
  readonly reasonCode: 'ok'
  readonly allowedGrantPurpose: ExecutionPurpose | null
  readonly activateFreeze: boolean
  readonly primaryStarted: boolean
}

export interface L2TransitionFailure {
  readonly ok: false
  readonly nextState: L2BundleState
  readonly reasonCode: L2ProtocolReasonCode
  readonly allowedGrantPurpose: ExecutionPurpose | null
  readonly activateFreeze: false
  readonly primaryStarted: boolean
}

export type L2TransitionResult = L2TransitionSuccess | L2TransitionFailure

const TERMINAL: ReadonlySet<L2BundleState> = new Set([
  'clean',
  'expired',
  'revoked',
  'interrupted',
  'inconclusive'
])

function grantPurposeFor(state: L2BundleState): ExecutionPurpose | null {
  switch (state) {
    case 'running-pre-read':
    case 'running-post-read':
    case 'cleanup-verifying':
    case 'primary-unknown':
      return 'read'
    case 'running-primary':
      return 'primary'
    case 'cleanup-running':
      return 'cleanup'
    default:
      return null
  }
}

function fail(
  state: L2BundleState,
  reasonCode: L2ProtocolReasonCode,
  primaryStarted: boolean
): L2TransitionFailure {
  return {
    ok: false,
    nextState: state,
    reasonCode,
    allowedGrantPurpose: grantPurposeFor(state),
    activateFreeze: false,
    primaryStarted
  }
}

function succeed(
  nextState: L2BundleState,
  primaryStarted: boolean,
  activateFreeze = false
): L2TransitionSuccess {
  return {
    ok: true,
    nextState,
    reasonCode: 'ok',
    allowedGrantPurpose: grantPurposeFor(nextState),
    activateFreeze,
    primaryStarted
  }
}

function nextFromTable(
  state: L2BundleState,
  event: L2BundleEventType
): L2BundleState | undefined {
  const table: Partial<Record<L2BundleEventType, Partial<Record<L2BundleState, L2BundleState>>>> =
    {
      'mark-ineligible': { draft: 'ineligible' },
      'submit-for-approval': { draft: 'pending-approval' },
      approve: { 'pending-approval': 'approved' },
      reject: { 'pending-approval': 'revoked' },
      'start-pre-read': { approved: 'running-pre-read' },
      'complete-pre-read': { 'running-pre-read': 'running-primary' },
      'start-primary': { 'running-primary': 'running-primary' },
      'complete-primary': { 'running-primary': 'running-post-read' },
      'mark-primary-unknown': { 'running-primary': 'primary-unknown' },
      'observe-primary-unsent': { 'primary-unknown': 'revoked' },
      'start-post-read': { 'running-post-read': 'running-post-read' },
      'complete-post-read': { 'running-post-read': 'cleanup-pending' },
      'start-cleanup': {
        'cleanup-pending': 'cleanup-running',
        'primary-unknown': 'cleanup-running'
      },
      'complete-cleanup': { 'cleanup-running': 'cleanup-verifying' },
      'fail-cleanup': {
        'cleanup-running': 'cleanup-failed',
        'cleanup-verifying': 'cleanup-failed'
      },
      'start-cleanup-verify': {
        'cleanup-verifying': 'cleanup-verifying',
        'cleanup-pending': 'cleanup-verifying'
      },
      'complete-cleanup-verify': { 'cleanup-verifying': 'cleanup-verifying' },
      'start-terminal-read': { 'cleanup-verifying': 'cleanup-verifying' },
      'complete-clean': { 'cleanup-verifying': 'clean' },
      expire: {
        draft: 'expired',
        ineligible: 'expired',
        'pending-approval': 'expired',
        approved: 'expired'
      },
      revoke: {
        draft: 'revoked',
        ineligible: 'revoked',
        'pending-approval': 'revoked',
        approved: 'revoked',
        'primary-unknown': 'revoked'
      },
      interrupt: {
        'running-pre-read': 'interrupted',
        'running-primary': 'primary-unknown',
        'running-post-read': 'interrupted',
        'cleanup-running': 'interrupted',
        'cleanup-verifying': 'interrupted'
      },
      'mark-inconclusive': {
        'running-pre-read': 'inconclusive',
        'running-post-read': 'inconclusive',
        'primary-unknown': 'inconclusive',
        interrupted: 'inconclusive'
      },
      'propose-recovery': {
        'cleanup-failed': 'cleanup-failed',
        'primary-unknown': 'primary-unknown'
      }
    }
  return table[event]?.[state]
}

export function transitionL2(input: {
  state: L2BundleState
  event: L2BundleEventType
  context: L2TransitionContext
}): L2TransitionResult {
  const { context } = input
  if (context.expectedRowVersion !== context.actualRowVersion) {
    return fail(input.state, 'concurrent-version-conflict', context.primaryAlreadyStarted)
  }

  const objectMatch = bundleMatchesTestObject(context.bundle, context.testObject)
  if (objectMatch !== 'ok') {
    return fail(input.state, objectMatch, context.primaryAlreadyStarted)
  }
  const objectEligible = testObjectL2Eligibility(context.testObject, context.now)
  if (objectEligible !== 'ok' && input.event !== 'expire' && input.event !== 'mark-ineligible') {
    return fail(input.state, objectEligible, context.primaryAlreadyStarted)
  }
  const envelopeEligible = sideEffectEnvelopeEligibility(context.bundle.sideEffectEnvelope)
  if (envelopeEligible !== 'ok' && input.event !== 'mark-ineligible') {
    return fail(input.state, envelopeEligible, context.primaryAlreadyStarted)
  }

  const freezeBlockedEvents = new Set<L2BundleEventType>([
    'submit-for-approval',
    'approve',
    'start-pre-read',
    'complete-pre-read',
    'start-primary',
    'complete-primary',
    'start-post-read',
    'complete-post-read',
    'start-cleanup-verify',
    'complete-cleanup-verify',
    'start-terminal-read',
    'complete-clean'
  ])
  if (
    context.freezeActive &&
    freezeBlockedEvents.has(input.event) &&
    !context.isRecoveryProposal
  ) {
    return fail(input.state, 'cleanup-failed-frozen', context.primaryAlreadyStarted)
  }

  if (input.event === 'submit-for-approval' && !sessionBindingsResolved(context.bundle)) {
    return fail(input.state, 'session-binding-unresolved', context.primaryAlreadyStarted)
  }
  if (
    (input.event === 'approve' ||
      input.event === 'start-pre-read' ||
      input.event === 'start-primary' ||
      input.event === 'start-cleanup') &&
    !context.trustedApprovalPresent
  ) {
    return fail(input.state, 'trusted-approval-missing', context.primaryAlreadyStarted)
  }

  if (input.event === 'start-primary' && context.primaryAlreadyStarted) {
    return fail(input.state, 'repeat-primary-forbidden', true)
  }
  if (input.event === 'observe-primary-unsent') {
    if (context.primarySentProof !== 'not-sent') {
      return fail(input.state, 'primary-unknown-no-replay', context.primaryAlreadyStarted)
    }
  }
  if (input.event === 'start-cleanup') {
    const cleanupStep = context.bundle.steps.find((step) => step.kind === 'cleanup')
    if (cleanupStep?.kind !== 'cleanup') {
      return fail(input.state, 'illegal-transition', context.primaryAlreadyStarted)
    }
    const cleanup = evaluateCleanupCapability({
      protocol: cleanupStep.cleanupProtocol,
      testObject: context.testObject,
      bundle: context.bundle
    })
    if (cleanup !== 'ok') {
      return fail(input.state, cleanup, context.primaryAlreadyStarted)
    }
  }
  if (input.event === 'propose-recovery' && !context.isRecoveryProposal) {
    return fail(input.state, 'cleanup-failed-frozen', context.primaryAlreadyStarted)
  }
  if (TERMINAL.has(input.state) && input.event !== 'propose-recovery') {
    return fail(input.state, 'illegal-transition', context.primaryAlreadyStarted)
  }

  const next = nextFromTable(input.state, input.event)
  if (!next) {
    return fail(input.state, 'illegal-transition', context.primaryAlreadyStarted)
  }

  const primaryStarted =
    input.event === 'start-primary' ||
    (input.event === 'interrupt' && input.state === 'running-primary') ||
    (input.event !== 'observe-primary-unsent' && context.primaryAlreadyStarted)
  const activateFreeze = input.event === 'fail-cleanup'
  return succeed(next, primaryStarted, activateFreeze)
}
