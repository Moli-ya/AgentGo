import type {
  CleanupReceiptPayload,
  L2ProtocolReasonCode
} from '@agentgo/contracts'

export function cleanupReceiptEligibility(
  payload: CleanupReceiptPayload
): L2ProtocolReasonCode | 'ok' {
  const hashes = payload.stepEvidenceHashes
  if (!hashes.preRead || !hashes.postRead || !hashes.terminalRead || !hashes.cleanupVerify) {
    return 'receipt-evidence-incomplete'
  }
  if (payload.kind === 'not-needed-no-state-change') {
    if (payload.requestExecutionState !== 'sent-known-complete') {
      return 'request-execution-state-unknown'
    }
    if (
      hashes.preRead !== hashes.postRead ||
      hashes.postRead !== hashes.terminalRead
    ) {
      return 'not-needed-requires-consistent-evidence'
    }
  }
  if (payload.kind === 'cleanup-completed' && !hashes.cleanup) {
    return 'receipt-evidence-incomplete'
  }
  return 'ok'
}
