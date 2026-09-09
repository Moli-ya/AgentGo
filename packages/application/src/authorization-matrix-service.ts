import { randomUUID } from 'node:crypto'
import {
  AuthorizationMatrixSchema,
  type AuthorizationMatrix,
  type AuthorizationMatrixEntry,
  type AuthorizationOperation
} from '@agentgo/contracts'
import {
  authorizationMatrixFreshness,
  lookupAuthorizationExpectation,
  sealAuthorizationMatrix
} from '@agentgo/domain'
import type { AgentGoRepository, IdentitySessionRepository } from '@agentgo/db'

export class AuthorizationMatrixError extends Error {
  readonly code:
    | 'identity-missing'
    | 'identity-target-mismatch'
    | 'matrix-missing'
    | 'matrix-incomplete'
    | 'version-mismatch'
    | 'matrix-expired'

  constructor(code: AuthorizationMatrixError['code'], message: string) {
    super(message)
    this.name = 'AuthorizationMatrixError'
    this.code = code
  }
}

export interface ConfirmAuthorizationMatrixInput {
  readonly targetId: string
  readonly scopeSnapshotId: string
  readonly entries: readonly Omit<AuthorizationMatrixEntry, 'tenantRef'>[] |
    readonly AuthorizationMatrixEntry[]
  readonly humanAttestationRef: string
  readonly ttlMs: number
  /** Reissue a matrix chain with a bumped version. */
  readonly matrixId?: string
}

/**
 * Human-confirmed authorization expectations. IDOR/BOLA/BFLA and business
 * privilege checks read only this matrix; HTTP 200s, page text, model
 * judgement, or identity naming are never an oracle. An incomplete matrix
 * yields a missing-entry failure, never an implicit permission.
 */
const FIXTURE_OWNED_RESOURCE_ATTESTATION_REF =
  '17000000-0000-4000-8000-000000000017'

export class AuthorizationMatrixService {
  readonly #repository: AgentGoRepository
  readonly #identitySessions: IdentitySessionRepository
  readonly #now: () => Date

  constructor(dependencies: {
    readonly repository: AgentGoRepository
    readonly identitySessionRepository: IdentitySessionRepository
    readonly now?: () => Date
  }) {
    this.#repository = dependencies.repository
    this.#identitySessions = dependencies.identitySessionRepository
    this.#now = dependencies.now ?? (() => new Date())
  }

  async confirmMatrix(
    input: ConfirmAuthorizationMatrixInput
  ): Promise<AuthorizationMatrix> {
    const identityIds = new Set<string>()
    for (const entry of input.entries) {
      identityIds.add(entry.subjectIdentityId)
      identityIds.add(entry.resourceOwnerIdentityId)
    }
    for (const identityId of identityIds) {
      const identity = await this.#repository.getIdentity(identityId)
      if (!identity) {
        throw new AuthorizationMatrixError(
          'identity-missing',
          `Matrix identity does not exist: ${identityId}`
        )
      }
      if (identity.targetId !== input.targetId) {
        throw new AuthorizationMatrixError(
          'identity-target-mismatch',
          'Matrix identities must belong to the matrix target.'
        )
      }
    }

    let matrixId = input.matrixId ?? randomUUID()
    let version = 1
    if (input.matrixId) {
      const latest = await this.#identitySessions.getLatestAuthorizationMatrixVersion(
        input.matrixId
      )
      if (latest === undefined) {
        throw new AuthorizationMatrixError(
          'matrix-missing',
          'Cannot reissue an authorization matrix that does not exist.'
        )
      }
      version = latest + 1
      matrixId = input.matrixId
    }

    const issuedAtDate = this.#now()
    const sealed = sealAuthorizationMatrix({
      schemaVersion: 'agentgo-identity-session/1.0',
      matrixId,
      matrixVersion: version,
      targetId: input.targetId,
      scopeSnapshotId: input.scopeSnapshotId,
      entries: input.entries.map((entry) => ({ ...entry })),
      humanAttestationRef: input.humanAttestationRef,
      issuedAt: issuedAtDate.toISOString(),
      expiresAt: new Date(issuedAtDate.getTime() + input.ttlMs).toISOString()
    })
    AuthorizationMatrixSchema.parse(sealed)
    return this.#identitySessions.insertAuthorizationMatrix(sealed)
  }

  async getCurrentMatrix(
    targetId: string,
    scopeSnapshotId: string
  ): Promise<AuthorizationMatrix | undefined> {
    return this.#identitySessions.getCurrentAuthorizationMatrix(targetId, scopeSnapshotId)
  }

  /**
   * Fixture-only matrix from user-supplied ownedResourceIds. Never infers
   * visibility from HTTP, page text, model output, or identity labels.
   * Real-target scans must call confirmMatrix with a human attestation.
   */
  async ensureOwnedResourceReadMatrix(input: {
    readonly targetId: string
    readonly scopeSnapshotId: string
    readonly identities: readonly {
      readonly id: string
      readonly role: string
      readonly isTestIdentity: boolean
      readonly ownedResourceIds: readonly string[]
    }[]
  }): Promise<AuthorizationMatrix | undefined> {
    const existing = await this.getCurrentMatrix(input.targetId, input.scopeSnapshotId)
    if (existing) return existing
    const owners = input.identities.filter(
      (item) => item.isTestIdentity && item.ownedResourceIds.length > 0
    )
    if (owners.length < 2) return undefined
    const entries: AuthorizationMatrixEntry[] = []
    for (const owner of owners) {
      for (const resourceRef of owner.ownedResourceIds) {
        for (const subject of owners) {
          entries.push({
            subjectIdentityId: subject.id,
            resourceOwnerIdentityId: owner.id,
            role: subject.role,
            operation: 'read',
            resourceRef,
            expected: subject.id === owner.id ? 'visible' : 'not-visible',
            humanSource: 'attested-fixture owned-resource inventory'
          })
        }
      }
    }
    if (entries.length === 0 || entries.length > 64) return undefined
    return this.confirmMatrix({
      targetId: input.targetId,
      scopeSnapshotId: input.scopeSnapshotId,
      entries,
      humanAttestationRef: FIXTURE_OWNED_RESOURCE_ATTESTATION_REF,
      ttlMs: 24 * 60 * 60 * 1000
    })
  }

  /**
   * Deterministic matrix read. Missing entries fail closed with
   * `matrix-incomplete`; the caller must surface `awaiting-user` instead of
   * inferring permission from responses or model output.
   */
  async requireExpectation(query: {
    readonly matrix: AuthorizationMatrix
    readonly subjectIdentityId: string
    readonly resourceRef: string
    readonly operation: AuthorizationOperation
    readonly tenantRef?: string
  }): Promise<AuthorizationMatrixEntry> {
    const entry = lookupAuthorizationExpectation(query.matrix, {
      subjectIdentityId: query.subjectIdentityId,
      resourceRef: query.resourceRef,
      operation: query.operation,
      ...(query.tenantRef ? { tenantRef: query.tenantRef } : {})
    })
    if (!entry) {
      throw new AuthorizationMatrixError(
        'matrix-incomplete',
        'The authorization matrix has no entry for this subject, resource, and operation.'
      )
    }
    return entry
  }

  /** Freshness check used before bundle submission, approval, and steps. */
  async assertMatrixCurrent(
    targetId: string,
    scopeSnapshotId: string,
    expected: { readonly matrixId: string; readonly version: number }
  ): Promise<AuthorizationMatrix> {
    const current = await this.getCurrentMatrix(targetId, scopeSnapshotId)
    if (!current) {
      throw new AuthorizationMatrixError(
        'matrix-missing',
        'No active authorization matrix exists for this scope.'
      )
    }
    const freshness = authorizationMatrixFreshness({
      matrix: current,
      expectedMatrixId: expected.matrixId,
      expectedVersion: expected.version,
      targetId,
      scopeSnapshotId,
      now: this.#now().getTime()
    })
    if (freshness === 'version-mismatch') {
      throw new AuthorizationMatrixError(
        'version-mismatch',
        'The authorization matrix version is no longer current.'
      )
    }
    if (freshness === 'expired') {
      throw new AuthorizationMatrixError(
        'matrix-expired',
        'The authorization matrix has expired.'
      )
    }
    return current
  }
}

/** Stable slot encoding for L2 bundles: the monotonically increasing version. */
export function authorizationMatrixSlotVersion(matrix: AuthorizationMatrix): string {
  return String(matrix.matrixVersion)
}
