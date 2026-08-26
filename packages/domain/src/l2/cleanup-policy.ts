import {
  L2_CLEANUP_CAPABILITY_ID,
  type DeclaredCleanupProtocol,
  type L2ActionBundle,
  type L2ProtocolReasonCode,
  type TestObjectPayload
} from '@agentgo/contracts'

const GENERIC_DELETE_METHODS = new Set(['DELETE'])

export function evaluateCleanupCapability(input: {
  protocol: DeclaredCleanupProtocol
  testObject: TestObjectPayload
  bundle: L2ActionBundle
  requestedMethod?: string
  requestedPath?: string
  requestedResourceId?: string
  requestedBundleHash?: string
}): L2ProtocolReasonCode | 'ok' {
  const { protocol, testObject, bundle } = input
  if (!testObject.creationAttestation.createdByAgentGo) {
    return 'non-agentgo-object-forbidden'
  }
  if (testObject.disposable !== true) return 'real-business-object-forbidden'
  if (protocol.capabilityId !== L2_CLEANUP_CAPABILITY_ID) {
    return 'missing-cleanup-protocol'
  }
  if (!protocol.declaredByTarget) return 'missing-cleanup-protocol'
  if (GENERIC_DELETE_METHODS.has((input.requestedMethod ?? '').toUpperCase())) {
    return 'generic-http-delete-forbidden'
  }
  if (
    input.requestedMethod &&
    input.requestedMethod !== protocol.method
  ) {
    return 'generic-http-delete-forbidden'
  }
  if (input.requestedPath && input.requestedPath !== protocol.path) {
    return 'imprecise-resource-forbidden'
  }
  if (
    input.requestedResourceId &&
    input.requestedResourceId !== testObject.canonicalResource.resourceId
  ) {
    return 'imprecise-resource-forbidden'
  }
  if (protocol.path !== testObject.canonicalResource.path) {
    return 'imprecise-resource-forbidden'
  }
  if (
    input.requestedBundleHash &&
    input.requestedBundleHash !== bundle.bundleHash
  ) {
    return 'cross-bundle-cleanup-forbidden'
  }
  const cleanupStep = bundle.steps.find((step) => step.kind === 'cleanup')
  if (cleanupStep && cleanupStep.kind === 'cleanup') {
    if (cleanupStep.cleanupProtocol.capabilityId !== protocol.capabilityId) {
      return 'cross-bundle-cleanup-forbidden'
    }
  }
  return 'ok'
}
