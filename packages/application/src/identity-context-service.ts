import { randomUUID } from 'node:crypto'
import {
  IdentityContextSchema,
  type IdentityContext,
  type IdentityContextOperation,
  type IdentityContextPayload,
  type IdentityRecord
} from '@agentgo/contracts'
import { hashIdentitySessionValue, sealIdentityContext } from '@agentgo/domain'
import type {
  AgentGoRepository,
  FileCredentialStore,
  IdentitySessionRepository
} from '@agentgo/db'

export class IdentityContextError extends Error {
  readonly code:
    | 'identity-missing'
    | 'identity-not-test'
    | 'identity-target-mismatch'
    | 'contrast-identity-invalid'
    | 'context-expired'
    | 'context-missing'
    | 'version-mismatch'

  constructor(code: IdentityContextError['code'], message: string) {
    super(message)
    this.name = 'IdentityContextError'
    this.code = code
  }
}

export interface IssueIdentityContextInput {
  readonly identityId: string
  readonly targetId: string
  readonly scopeSnapshotId: string
  readonly tenantRef?: string
  readonly role: string
  readonly ownerLabel: string
  readonly purpose: string
  readonly allowedOperations: readonly IdentityContextOperation[]
  readonly contrastIdentityIds?: readonly string[]
  readonly exclusiveWith?: readonly string[]
  readonly confirmationAuditRef: string
  readonly ttlMs: number
  /** Reissue an existing context chain with a bumped version. */
  readonly identityContextId?: string
}

/**
 * Issues versioned IdentityContexts from user-confirmed material only.
 * Models, Agents, page content, and tool output cannot mint or mutate a
 * context: issuance is a deterministic Application service that re-reads the
 * persisted IdentityRecord and credential metadata. When identity material
 * changes or confirmation expires, the old version stops being current and
 * dependent bundles lose freshness instead of silently swapping identity.
 */
export class IdentityContextService {
  readonly #repository: AgentGoRepository
  readonly #identitySessions: IdentitySessionRepository
  readonly #credentialStore: FileCredentialStore
  readonly #now: () => Date

  constructor(dependencies: {
    readonly repository: AgentGoRepository
    readonly identitySessionRepository: IdentitySessionRepository
    readonly credentialStore: FileCredentialStore
    readonly now?: () => Date
  }) {
    this.#repository = dependencies.repository
    this.#identitySessions = dependencies.identitySessionRepository
    this.#credentialStore = dependencies.credentialStore
    this.#now = dependencies.now ?? (() => new Date())
  }

  async issueIdentityContext(input: IssueIdentityContextInput): Promise<IdentityContext> {
    const identity = await this.#requireIdentity(input.identityId, input.targetId)
    this.#assertConfirmedRole(identity, input.role)
    const contrastIdentityIds = [...(input.contrastIdentityIds ?? [])]
    for (const contrastId of contrastIdentityIds) {
      const contrast = await this.#repository.getIdentity(contrastId)
      if (!contrast || contrast.targetId !== input.targetId || !contrast.isTestIdentity) {
        throw new IdentityContextError(
          'contrast-identity-invalid',
          'Contrast identities must be test identities on the same target.'
        )
      }
    }

    const issuedAtDate = this.#now()
    const issuedAt = issuedAtDate.toISOString()
    const expiresAt = new Date(issuedAtDate.getTime() + input.ttlMs).toISOString()
    const credential = this.#credentialRefFor(identity)

    let identityContextId = input.identityContextId ?? randomUUID()
    let version = 1
    if (input.identityContextId) {
      const latest = await this.#identitySessions.getLatestIdentityContextVersion(
        input.identityContextId
      )
      if (latest === undefined) {
        throw new IdentityContextError(
          'context-missing',
          'Cannot reissue an identity context chain that does not exist.'
        )
      }
      version = latest + 1
      identityContextId = input.identityContextId
    }

    const payload: IdentityContextPayload = {
      schemaVersion: 'agentgo-identity-session/1.0',
      identityContextId,
      identityContextVersion: version,
      identityId: identity.id,
      targetId: input.targetId,
      scopeSnapshotId: input.scopeSnapshotId,
      ...(input.tenantRef ? { tenantRef: input.tenantRef } : {}),
      role: identity.role,
      ownerLabel: input.ownerLabel,
      purpose: input.purpose,
      allowedOperations: [...input.allowedOperations],
      contrastIdentityIds,
      exclusiveWith: [...(input.exclusiveWith ?? [])],
      credential,
      confirmationAuditRef: input.confirmationAuditRef,
      issuedAt,
      expiresAt
    }
    const sealed = sealIdentityContext(payload)
    IdentityContextSchema.parse(sealed)
    return this.#identitySessions.insertIdentityContext(sealed)
  }

  async getCurrentIdentityContext(identityId: string): Promise<IdentityContext | undefined> {
    return this.#identitySessions.getCurrentIdentityContext(identityId)
  }

  /**
   * Freshness check used before bundle submission, approval, and every L2
   * execution step. Any drift fails closed; callers route the candidate to
   * `awaiting-user` instead of attempting another identity.
   */
  async assertIdentityContextCurrent(
    identityId: string,
    expectedVersion: number,
    expectedContextId?: string
  ): Promise<IdentityContext> {
    const current = await this.#identitySessions.getCurrentIdentityContext(identityId)
    if (!current) {
      throw new IdentityContextError('context-missing', 'No active identity context exists.')
    }
    if (
      current.identityContextVersion !== expectedVersion ||
      (expectedContextId !== undefined && current.identityContextId !== expectedContextId)
    ) {
      throw new IdentityContextError(
        'version-mismatch',
        'The identity context version is no longer current.'
      )
    }
    if (Date.parse(current.expiresAt) <= this.#now().getTime()) {
      throw new IdentityContextError('context-expired', 'The identity context has expired.')
    }
    return current
  }

  /** Identity material changed: every active context for it stops being current. */
  async revokeIdentityContextsForIdentity(identityId: string): Promise<void> {
    await this.#identitySessions.revokeIdentityContextsForIdentity(identityId)
  }

  async #requireIdentity(identityId: string, targetId: string): Promise<IdentityRecord> {
    const identity = await this.#repository.getIdentity(identityId)
    if (!identity) {
      throw new IdentityContextError('identity-missing', 'Identity does not exist.')
    }
    if (identity.targetId !== targetId) {
      throw new IdentityContextError(
        'identity-target-mismatch',
        'Identity belongs to a different target.'
      )
    }
    if (!identity.isTestIdentity) {
      throw new IdentityContextError(
        'identity-not-test',
        'Identity contexts require a designated test identity.'
      )
    }
    return identity
  }

  #assertConfirmedRole(identity: IdentityRecord, confirmedRole: string): void {
    if (identity.role !== confirmedRole) {
      throw new IdentityContextError(
        'identity-target-mismatch',
        'The confirmed role must match the persisted test identity role.'
      )
    }
  }

  #credentialRefFor(identity: IdentityRecord): IdentityContextPayload['credential'] {
    if (identity.authType === 'none' || !identity.credentialId) {
      return { kind: 'none', sensitiveLevel: 'standard' }
    }
    const metadata = this.#credentialStore
      .list()
      .find((entry) => entry.id === identity.credentialId)
    if (!metadata) {
      throw new IdentityContextError(
        'identity-missing',
        'Identity credential material is unavailable.'
      )
    }
    return {
      kind: identity.authType,
      credentialId: metadata.id,
      credentialGeneration: metadata.generation,
      sensitiveLevel: identity.authType === 'basic' ? 'sensitive' : 'standard'
    }
  }
}

/** Stable slot encoding for L2 bundles: the monotonically increasing version. */
export function identityContextSlotVersion(context: IdentityContext): string {
  return String(context.identityContextVersion)
}

export function identityContextHashForAudit(context: IdentityContext): string {
  return hashIdentitySessionValue({
    identityContextId: context.identityContextId,
    identityContextVersion: context.identityContextVersion,
    identityId: context.identityId,
    contextHash: context.contextHash
  })
}
