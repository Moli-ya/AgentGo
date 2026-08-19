const typedArrayPrototype = Object.getPrototypeOf(
  Uint8Array.prototype
) as object
const typedArrayByteLengthGetter =
  Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    'byteLength'
  )?.get
const typedArrayBufferGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer')?.get
const typedArraySet = Uint8Array.prototype.set
const typedArrayFill = Uint8Array.prototype.fill

export interface SecureByteSnapshotLimits {
  readonly minimumBytes?: number
  readonly maximumBytes: number
}

export function snapshotSecureBytes(
  value: unknown,
  limits: SecureByteSnapshotLimits
): Uint8Array<ArrayBuffer> {
  if (
    !(value instanceof Uint8Array) ||
    typedArrayByteLengthGetter === undefined ||
    typedArrayBufferGetter === undefined ||
    !Number.isSafeInteger(limits.minimumBytes ?? 0) ||
    (limits.minimumBytes ?? 0) < 0 ||
    !Number.isSafeInteger(limits.maximumBytes) ||
    limits.maximumBytes < (limits.minimumBytes ?? 0)
  ) {
    throw new Error('Secure byte input failed closed validation.')
  }
  let byteLength: unknown
  let buffer: unknown
  try {
    byteLength = Reflect.apply(typedArrayByteLengthGetter, value, [])
    buffer = Reflect.apply(typedArrayBufferGetter, value, [])
  } catch {
    throw new Error('Secure byte input failed closed validation.')
  }
  if (
    typeof byteLength !== 'number' ||
    !Number.isSafeInteger(byteLength) ||
    byteLength < (limits.minimumBytes ?? 0) ||
    byteLength > limits.maximumBytes ||
    (typeof SharedArrayBuffer !== 'undefined' &&
      buffer instanceof SharedArrayBuffer)
  ) {
    throw new Error('Secure byte input failed closed validation.')
  }
  const snapshot = new Uint8Array(new ArrayBuffer(byteLength))
  try {
    Reflect.apply(typedArraySet, snapshot, [value])
  } catch {
    zeroizeSecureBytes(snapshot)
    throw new Error('Secure byte input failed closed validation.')
  }
  return snapshot
}

export function zeroizeSecureBytes(
  value: Uint8Array<ArrayBufferLike>
): void {
  Reflect.apply(typedArrayFill, value, [0])
}
