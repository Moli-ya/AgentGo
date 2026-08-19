import { randomBytes, randomUUID } from 'node:crypto'
import type {
  RequestHashKeyProvider,
  RequestHashKeyRef
} from './request-compiler'

const REQUEST_HMAC_KEY_BYTES = 32

/**
 * Process-local request proof key.
 *
 * The key is intentionally not persisted. Grants left behind by a crashed
 * process therefore fail closed after restart instead of becoming replayable.
 * Callers receive copies only; the provider-owned bytes are cleared on dispose.
 */
export class EphemeralRequestHashKeyProvider
  implements RequestHashKeyProvider
{
  readonly reference: Readonly<RequestHashKeyRef>
  #key: Uint8Array | undefined

  constructor() {
    this.reference = Object.freeze({
      keyRef: randomUUID(),
      keyVersion: 0
    })
    this.#key = Uint8Array.from(randomBytes(REQUEST_HMAC_KEY_BYTES))
  }

  resolveKey(input: RequestHashKeyRef): Uint8Array {
    const key = this.#key
    if (
      !key ||
      input.keyRef !== this.reference.keyRef ||
      input.keyVersion !== this.reference.keyVersion
    ) {
      throw new Error('The request proof key is unavailable.')
    }
    return Uint8Array.from(key)
  }

  dispose(): void {
    this.#key?.fill(0)
    this.#key = undefined
  }
}
