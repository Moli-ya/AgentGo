import type {
  EvidenceCaptureResult,
  ProtectedOriginalEvidenceCaptureContext,
  ProtectedOriginalEvidenceCaptureDecision
} from '@agentgo/contracts'
import {
  EvidenceStore,
  type ProtectedEvidenceWriteResult
} from '@agentgo/db'
import {
  EvidenceCapturePolicy,
  type EvidenceByteCaptureInput
} from './evidence-capture-policy'
import {
  snapshotSecureBytes,
  zeroizeSecureBytes
} from './secure-byte-snapshot'

const MAX_PROTECTED_CAPTURE_BYTES = 16_777_216

export interface ProtectedEvidenceCaptureInput {
  readonly context: ProtectedOriginalEvidenceCaptureContext
  readonly decision: ProtectedOriginalEvidenceCaptureDecision
  readonly content: Uint8Array
  readonly knownTotalBytes?: number
}

export interface PersistedProtectedEvidenceCapture {
  readonly capture: EvidenceCaptureResult
  readonly evidence: ProtectedEvidenceWriteResult
}

/**
 * Trusted backend-only composition boundary for protected originals.
 * It snapshots the source once, lets the pure policy seal the persistence
 * artifact, persists that exact artifact with the same bytes, and clears the
 * shared snapshot. It is intentionally not exposed through Renderer IPC.
 */
export class ProtectedEvidenceCaptureService {
  constructor(
    private readonly policy: EvidenceCapturePolicy,
    private readonly store: EvidenceStore
  ) {}

  async captureAndPersist(
    input: ProtectedEvidenceCaptureInput
  ): Promise<PersistedProtectedEvidenceCapture> {
    const content = snapshotSecureBytes(input.content, {
      minimumBytes: 1,
      maximumBytes: MAX_PROTECTED_CAPTURE_BYTES
    })
    try {
      const policyInput: EvidenceByteCaptureInput = {
        kind: 'bytes',
        context: input.context,
        decision: input.decision,
        content,
        completeness: 'complete',
        ...(input.knownTotalBytes === undefined
          ? {}
          : { knownTotalBytes: input.knownTotalBytes })
      }
      const capture = this.policy.capture(policyInput)
      const artifact = capture.artifacts[0]
      if (
        capture.state !== 'captured' ||
        capture.reason !== 'protected-original-authorized' ||
        capture.artifacts.length !== 1 ||
        artifact?.type !== 'evidence-capture-protected-original'
      ) {
        throw new Error(
          'Protected Evidence policy did not authorize original persistence.'
        )
      }
      const evidence = await this.store.saveProtectedOriginalWithDerivative({
        artifact,
        content
      })
      return Object.freeze({
        capture,
        evidence: Object.freeze(evidence)
      })
    } finally {
      zeroizeSecureBytes(content)
    }
  }
}
