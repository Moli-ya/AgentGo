import type {
  AuthorizationMatrix,
  AuthorizationMatrixEntry,
  AuthorizationOperation
} from '@agentgo/contracts'

/**
 * Deterministic AuthorizationMatrix reads. An HTTP 200, page text, model
 * judgement, or identity naming is never an authorization oracle: lookups
 * are exact subject/resource/operation matches against a human-confirmed,
 * versioned matrix, and absence of an entry fails closed.
 */

export interface AuthorizationMatrixQuery {
  readonly subjectIdentityId: string
  readonly resourceRef: string
  readonly operation: AuthorizationOperation
  readonly tenantRef?: string
}

export function lookupAuthorizationExpectation(
  matrix: AuthorizationMatrix,
  query: AuthorizationMatrixQuery
): AuthorizationMatrixEntry | undefined {
  return matrix.entries.find(
    (entry) =>
      entry.subjectIdentityId === query.subjectIdentityId &&
      entry.resourceRef === query.resourceRef &&
      entry.operation === query.operation &&
      (entry.tenantRef ?? null) === (query.tenantRef ?? null)
  )
}

export function authorizationMatrixFreshness(input: {
  readonly matrix: AuthorizationMatrix
  readonly expectedMatrixId: string
  readonly expectedVersion: number
  readonly targetId: string
  readonly scopeSnapshotId: string
  readonly now: number
}): 'ok' | 'version-mismatch' | 'expired' {
  const { matrix } = input
  if (
    matrix.matrixId !== input.expectedMatrixId ||
    matrix.matrixVersion !== input.expectedVersion ||
    matrix.targetId !== input.targetId ||
    matrix.scopeSnapshotId !== input.scopeSnapshotId
  ) {
    return 'version-mismatch'
  }
  if (Date.parse(matrix.expiresAt) <= input.now) return 'expired'
  return 'ok'
}
