import {
  L2_CLEANUP_CAPABILITY_ID,
  type L2ActionBundlePayload,
  type L2BindingSlot,
  type L2ProtocolReasonCode,
  type SideEffectEnvelope,
  type TestObjectPayload
} from '@agentgo/contracts'

export function bindingSlotResolved(slot: L2BindingSlot): boolean {
  return slot.status === 'resolved'
}

export function sessionBindingsResolved(bundle: L2ActionBundlePayload): boolean {
  return (
    bindingSlotResolved(bundle.identityContextVersion) &&
    bindingSlotResolved(bundle.sessionGeneration) &&
    bindingSlotResolved(bundle.csrfBindingVersion) &&
    bindingSlotResolved(bundle.authorizationMatrixVersion)
  )
}

export function sideEffectEnvelopeEligibility(
  envelope: SideEffectEnvelope
): L2ProtocolReasonCode | 'ok' {
  if (envelope.unknownSideEffects.length > 0) return 'unknown-side-effect'
  if (envelope.unobservableSideEffects.length > 0) return 'unobservable-side-effect'
  if (envelope.irreversibleItems.length > 0) return 'irreversible-side-effect'
  if (envelope.maxImpactScope !== 'single-test-object-fields') {
    return 'broad-resource-forbidden'
  }
  return 'ok'
}

export function testObjectL2Eligibility(
  object: TestObjectPayload,
  now: Date
): L2ProtocolReasonCode | 'ok' {
  if (!object.creationAttestation.createdByAgentGo) {
    return 'missing-agentgo-creation-attestation'
  }
  if (object.creationAttestation.source !== 'agentgo-application') {
    return 'missing-agentgo-creation-attestation'
  }
  if (object.disposable !== true) return 'not-disposable'
  if (!object.canonicalResource.resourceId) return 'imprecise-resource-forbidden'
  if (!object.cleanupProtocol || !object.cleanupProtocol.declaredByTarget) {
    return 'missing-cleanup-protocol'
  }
  if (object.cleanupProtocol.capabilityId !== L2_CLEANUP_CAPABILITY_ID) {
    return 'missing-cleanup-protocol'
  }
  if (Date.parse(object.expiresAt) <= now.getTime()) return 'expired'
  return 'ok'
}

export function bundleMatchesTestObject(
  bundle: L2ActionBundlePayload,
  object: TestObjectPayload
): L2ProtocolReasonCode | 'ok' {
  if (bundle.testObjectId !== object.testObjectId) return 'missing-test-object'
  if (bundle.testObjectVersion !== object.objectVersion) return 'version-mismatch'
  if (bundle.scanId !== object.scanId) return 'ownership-or-tenant-mismatch'
  if (bundle.targetId !== object.targetId) return 'ownership-or-tenant-mismatch'
  if (bundle.identityId !== object.identityId) return 'identity-mismatch'
  if ((bundle.tenantRef ?? null) !== (object.tenantRef ?? null)) {
    return 'ownership-or-tenant-mismatch'
  }
  if (bundle.scopeSnapshotId !== object.scopeSnapshotId) {
    return 'ownership-or-tenant-mismatch'
  }
  if (bundle.sideEffectEnvelope.writableResourceId !== object.canonicalResource.resourceId) {
    return 'imprecise-resource-forbidden'
  }
  const allowedFields = new Set(object.allowedFields)
  for (const write of bundle.sideEffectEnvelope.fieldWrites) {
    if (!allowedFields.has(write.fieldPath)) return 'broad-resource-forbidden'
  }
  return 'ok'
}
