import {
  ActorContextPayloadSchema,
  ActorContextSchema,
  ApprovalProposalPayloadSchema,
  ApprovalProposalSchema,
  ApprovalRecordPayloadSchema,
  ApprovalRecordSchema,
  AuthorizationMatrixPayloadSchema,
  AuthorizationMatrixSchema,
  CsrfBindingPayloadSchema,
  CsrfBindingSchema,
  IdentityContextPayloadSchema,
  IdentityContextSchema,
  type ActorContext,
  type ActorContextPayload,
  type ActorProofHandle,
  type ApprovalProposal,
  type ApprovalProposalPayload,
  type ApprovalRecord,
  type ApprovalRecordPayload,
  type AuthorizationMatrix,
  type AuthorizationMatrixPayload,
  type CsrfBinding,
  type CsrfBindingPayload,
  type IdentityContext,
  type IdentityContextPayload
} from '@agentgo/contracts'
import { canonicalJson, sha256Text } from '../vulnerabilities/canonical'

export function hashIdentitySessionValue(value: unknown): string {
  return sha256Text(canonicalJson(value))
}

function jsonCanonicalize<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

export function unsignedIdentityContext(context: IdentityContext): IdentityContextPayload {
  const { contextHash, ...payload } = context
  void contextHash
  return IdentityContextPayloadSchema.parse(jsonCanonicalize(payload))
}

export function unsignedCsrfBinding(binding: CsrfBinding): CsrfBindingPayload {
  const { bindingHash, ...payload } = binding
  void bindingHash
  return CsrfBindingPayloadSchema.parse(jsonCanonicalize(payload))
}

export function unsignedAuthorizationMatrix(
  matrix: AuthorizationMatrix
): AuthorizationMatrixPayload {
  const { matrixHash, ...payload } = matrix
  void matrixHash
  return AuthorizationMatrixPayloadSchema.parse(jsonCanonicalize(payload))
}

export function unsignedApprovalProposal(
  proposal: ApprovalProposal
): ApprovalProposalPayload {
  const { proposalHash, ...payload } = proposal
  void proposalHash
  return ApprovalProposalPayloadSchema.parse(jsonCanonicalize(payload))
}

export function unsignedApprovalRecord(record: ApprovalRecord): ApprovalRecordPayload {
  const { approvalHash, ...payload } = record
  void approvalHash
  return ApprovalRecordPayloadSchema.parse(jsonCanonicalize(payload))
}

export function sealIdentityContext(payload: IdentityContextPayload): IdentityContext {
  const parsed = IdentityContextPayloadSchema.parse(jsonCanonicalize(payload))
  return IdentityContextSchema.parse({
    ...parsed,
    contextHash: hashIdentitySessionValue(parsed)
  })
}

export function sealCsrfBinding(payload: CsrfBindingPayload): CsrfBinding {
  const parsed = CsrfBindingPayloadSchema.parse(jsonCanonicalize(payload))
  return CsrfBindingSchema.parse({
    ...parsed,
    bindingHash: hashIdentitySessionValue(parsed)
  })
}

export function sealAuthorizationMatrix(
  payload: AuthorizationMatrixPayload
): AuthorizationMatrix {
  const parsed = AuthorizationMatrixPayloadSchema.parse(jsonCanonicalize(payload))
  return AuthorizationMatrixSchema.parse({
    ...parsed,
    matrixHash: hashIdentitySessionValue(parsed)
  })
}

export function sealApprovalProposal(
  payload: ApprovalProposalPayload
): ApprovalProposal {
  const parsed = ApprovalProposalPayloadSchema.parse(jsonCanonicalize(payload))
  return ApprovalProposalSchema.parse({
    ...parsed,
    proposalHash: hashIdentitySessionValue(parsed)
  })
}

export function sealApprovalRecord(payload: ApprovalRecordPayload): ApprovalRecord {
  const parsed = ApprovalRecordPayloadSchema.parse(jsonCanonicalize(payload))
  return ApprovalRecordSchema.parse({
    ...parsed,
    approvalHash: hashIdentitySessionValue(parsed)
  })
}

/**
 * Hashes the canonical actor payload. The trusted backend attaches the proof
 * handle afterwards; this digest is what the handle's HMAC signs.
 */
export function actorContextPayloadHash(payload: ActorContextPayload): string {
  const parsed = ActorContextPayloadSchema.parse(jsonCanonicalize(payload))
  return hashIdentitySessionValue(parsed)
}

export function attachActorProofHandle(
  payload: ActorContextPayload,
  handle: ActorProofHandle
): ActorContext {
  const parsed = ActorContextPayloadSchema.parse(jsonCanonicalize(payload))
  return ActorContextSchema.parse({
    ...parsed,
    contextHash: hashIdentitySessionValue(parsed),
    handle
  })
}

export function unsignedActorContext(context: ActorContext): ActorContextPayload {
  const { contextHash, handle, ...payload } = context
  void contextHash
  void handle
  return ActorContextPayloadSchema.parse(jsonCanonicalize(payload))
}
