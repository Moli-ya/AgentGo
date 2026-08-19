import type {
  EvidenceStore,
  ProtectedEvidenceSweepResult
} from '@agentgo/db'

const DEFAULT_PROTECTED_EVIDENCE_SWEEP_INTERVAL_MS = 60_000

export interface ProtectedEvidenceRetentionSchedulerOptions {
  intervalMs?: number
  onError?: (error: unknown) => void
}

/**
 * Keeps protected-original retention enforceable in a long-running process.
 *
 * The application startup sweep remains the crash-recovery boundary. This
 * scheduler adds a non-overlapping periodic sweep and never restores erased
 * key material after a failed physical-file cleanup.
 */
export class ProtectedEvidenceRetentionScheduler {
  readonly #evidenceStore: Pick<
    EvidenceStore,
    'sweepExpiredProtectedOriginals'
  >
  readonly #intervalMs: number
  readonly #onError?: (error: unknown) => void
  #timer?: ReturnType<typeof setInterval>
  #inFlight?: Promise<ProtectedEvidenceSweepResult | undefined>

  constructor(
    evidenceStore: Pick<EvidenceStore, 'sweepExpiredProtectedOriginals'>,
    options: ProtectedEvidenceRetentionSchedulerOptions = {}
  ) {
    const intervalMs =
      options.intervalMs ?? DEFAULT_PROTECTED_EVIDENCE_SWEEP_INTERVAL_MS
    if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) {
      throw new Error(
        'Protected Evidence retention interval must be a positive safe integer.'
      )
    }
    this.#evidenceStore = evidenceStore
    this.#intervalMs = intervalMs
    this.#onError = options.onError
  }

  start(): void {
    if (this.#timer !== undefined) return
    this.#timer = setInterval(() => {
      this.#triggerSweep()
    }, this.#intervalMs)
    this.#timer.unref?.()
  }

  async stop(): Promise<void> {
    const timer = this.#timer
    this.#timer = undefined
    if (timer !== undefined) clearInterval(timer)
    await this.#inFlight
  }

  #triggerSweep(): void {
    if (this.#timer === undefined || this.#inFlight !== undefined) return
    const sweep = this.#evidenceStore
      .sweepExpiredProtectedOriginals()
      .catch((error: unknown) => {
        this.#onError?.(error)
        return undefined
      })
      .finally(() => {
        if (this.#inFlight === sweep) this.#inFlight = undefined
      })
    this.#inFlight = sweep
  }
}
