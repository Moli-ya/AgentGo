import { describe, expect, it } from 'vitest'
import {
  snapshotSecureBytes,
  zeroizeSecureBytes
} from './secure-byte-snapshot'

describe('secure byte snapshot', () => {
  it('uses native TypedArray length instead of an overridden budget value', () => {
    class ForgedKey extends Uint8Array {
      override get byteLength(): number {
        return 32
      }

      override fill(): this {
        return this
      }

      override [Symbol.iterator](): ArrayIterator<number> {
        return new Uint8Array(40).fill(7).values()
      }
    }

    expect(() =>
      snapshotSecureBytes(new ForgedKey(1), {
        minimumBytes: 32,
        maximumBytes: 64
      })
    ).toThrow('Secure byte input failed closed validation.')
  })

  it('copies native bytes without invoking an overridden iterator', () => {
    class IteratorTrap extends Uint8Array {
      override [Symbol.iterator](): ArrayIterator<number> {
        throw new Error('iterator must not execute')
      }
    }
    const source = new IteratorTrap(32)
    source[0] = 91

    const snapshot = snapshotSecureBytes(source, {
      minimumBytes: 32,
      maximumBytes: 64
    })

    expect(snapshot).toHaveLength(32)
    expect(snapshot[0]).toBe(91)
    expect(Object.getPrototypeOf(snapshot)).toBe(Uint8Array.prototype)
    zeroizeSecureBytes(snapshot)
    expect([...snapshot]).toEqual(new Array(32).fill(0))
  })

  it('rejects SharedArrayBuffer-backed inputs', () => {
    if (typeof SharedArrayBuffer === 'undefined') return
    expect(() =>
      snapshotSecureBytes(
        new Uint8Array(new SharedArrayBuffer(32)),
        {
          minimumBytes: 32,
          maximumBytes: 64
        }
      )
    ).toThrow('Secure byte input failed closed validation.')
  })
})
