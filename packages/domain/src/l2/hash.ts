import {
  CleanupReceiptPayloadSchema,
  CleanupReceiptSchema,
  L2ActionBundlePayloadSchema,
  L2ActionBundleSchema,
  TestObjectPayloadSchema,
  TestObjectSchema,
  type CleanupReceipt,
  type CleanupReceiptPayload,
  type L2ActionBundle,
  type L2ActionBundlePayload,
  type TestObject,
  type TestObjectPayload
} from '@agentgo/contracts'
import { canonicalJson, sha256Text } from '../vulnerabilities/canonical'

export function hashL2Value(value: unknown): string {
  return sha256Text(canonicalJson(value))
}

function jsonCanonicalize<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

export function unsignedTestObject(object: TestObject): TestObjectPayload {
  const { objectHash, ...payload } = object
  void objectHash
  return TestObjectPayloadSchema.parse(payload)
}

export function unsignedL2ActionBundle(bundle: L2ActionBundle): L2ActionBundlePayload {
  const { bundleHash, ...payload } = bundle
  void bundleHash
  return L2ActionBundlePayloadSchema.parse(payload)
}

export function unsignedCleanupReceipt(receipt: CleanupReceipt): CleanupReceiptPayload {
  const { receiptHash, ...payload } = receipt
  void receiptHash
  return CleanupReceiptPayloadSchema.parse(payload)
}

export function sealTestObject(payload: TestObjectPayload): TestObject {
  const parsed = TestObjectPayloadSchema.parse(jsonCanonicalize(payload))
  return TestObjectSchema.parse({
    ...parsed,
    objectHash: hashL2Value(parsed)
  })
}

export function sealL2ActionBundle(payload: L2ActionBundlePayload): L2ActionBundle {
  const parsed = L2ActionBundlePayloadSchema.parse(jsonCanonicalize(payload))
  return L2ActionBundleSchema.parse({
    ...parsed,
    bundleHash: hashL2Value(parsed)
  })
}

export function sealCleanupReceipt(payload: CleanupReceiptPayload): CleanupReceipt {
  const parsed = CleanupReceiptPayloadSchema.parse(jsonCanonicalize(payload))
  return CleanupReceiptSchema.parse({
    ...parsed,
    receiptHash: hashL2Value(parsed)
  })
}
