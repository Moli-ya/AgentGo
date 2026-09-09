import {
  L2ActionBundlePayloadSchema,
  type L2ActionBundle,
  type L2ProtocolReasonCode
} from '@agentgo/contracts'
import { sealL2ActionBundle } from '@agentgo/domain'
import type { IdentitySessionRepository, L2Repository } from '@agentgo/db'
import type { AuthorizationMatrixService } from './authorization-matrix-service'
import type { CsrfBindingService } from './csrf-binding-service'
import {
  IdentityContextError,
  type IdentityContextService
} from './identity-context-service'
import {
  L2ProtocolError,
  L2ProtocolService,
  type L2BundleView
} from './l2-protocol-service'
import { AuthorizationMatrixError } from './authorization-matrix-service'
import { CsrfBindingError } from './csrf-binding-service'
import { SessionVault, SessionVaultError } from './session-vault'

export class L2BindingError extends Error {
  readonly reasonCode: L2ProtocolReasonCode

  constructor(reasonCode: L2ProtocolReasonCode, message: string) {
    super(message)
    this.name = 'L2BindingError'
    this.reasonCode = reasonCode
  }
}

export interface ResolvedL2Bindings {
  readonly identityContextVersion: string
  readonly sessionGeneration: string
  readonly csrfBindingVersion: string
  readonly authorizationMatrixVersion: string
}

export function encodeIdentityContextSlot(input: {
  readonly identityContextId: string
  readonly version: number
}): string {
  return `${input.identityContextId}:${input.version}`
}

export function encodeSessionGenerationSlot(input: {
  readonly sessionId: string
  readonly generation: number
}): string {
  return `${input.sessionId}:${input.generation}`
}

export function encodeMatrixSlot(input: {
  readonly matrixId: string
  readonly version: number
}): string {
  return `${input.matrixId}:${input.version}`
}

function decodeSlot(value: string): { readonly id: string; readonly version: number } | undefined {
  const separator = value.lastIndexOf(':')
  if (separator <= 0) return undefined
  const id = value.slice(0, separator)
  const version = Number(value.slice(separator + 1))
  if (!Number.isSafeInteger(version) || version < 0) return undefined
  return { id, version }
}

/**
 * Day 9 §6: deterministically binds a draft bundle to the current
 * identity/session/CSRF/matrix versions. Any reference change produces a new
 * bundle hash and a new bundle version; the old version is revoked instead
 * of refreshed in place. Resolution only earns the `pending-approval`
 * candidacy — it is not an approval.
 */
export class L2BindingService {
  readonly #l2: L2ProtocolService
  readonly #l2Repository: L2Repository
  readonly #identityContexts: IdentityContextService
  readonly #sessionVault: SessionVault
  readonly #csrfBindings: CsrfBindingService
  readonly #matrices: AuthorizationMatrixService
  readonly #identitySessions: IdentitySessionRepository
  readonly #now: () => Date

  constructor(dependencies: {
    readonly l2ProtocolService: L2ProtocolService
    readonly l2Repository: L2Repository
    readonly identityContextService: IdentityContextService
    readonly sessionVault: SessionVault
    readonly csrfBindingService: CsrfBindingService
    readonly authorizationMatrixService: AuthorizationMatrixService
    readonly identitySessionRepository: IdentitySessionRepository
    readonly now?: () => Date
  }) {
    this.#l2 = dependencies.l2ProtocolService
    this.#l2Repository = dependencies.l2Repository
    this.#identityContexts = dependencies.identityContextService
    this.#sessionVault = dependencies.sessionVault
    this.#csrfBindings = dependencies.csrfBindingService
    this.#matrices = dependencies.authorizationMatrixService
    this.#identitySessions = dependencies.identitySessionRepository
    this.#now = dependencies.now ?? (() => new Date())
  }

  /**
   * Resolves all four binding slots against the current backend state and
   * submits a fresh bundle version for approval. The matrix must already
   * cover the write and cleanup operations for this TestObject; anything
   * missing fails closed instead of inferring permission from responses.
   */
  async resolveBundleBindings(input: {
    readonly bundleId: string
    readonly bundleVersion: number
    readonly expectedRowVersion: number
    readonly csrfBindingHash: string
  }): Promise<L2BundleView> {
    const view = await this.#l2.getBundleView(input.bundleId, input.bundleVersion)
    if (!view) throw new L2BindingError('missing-test-object', 'Bundle does not exist.')
    if (view.runtime.state !== 'draft') {
      throw new L2BindingError(
        'illegal-transition',
        'Only a draft bundle can receive binding resolution.'
      )
    }
    const { bundle, testObject } = view

    const identityContext = await this.#identityContexts.getCurrentIdentityContext(
      bundle.identityId
    )
    if (!identityContext) {
      throw new L2BindingError(
        'session-binding-unresolved',
        'No current identity context exists for the bundle identity.'
      )
    }
    if (
      !identityContext.allowedOperations.includes('write-test-object') ||
      !identityContext.allowedOperations.includes('cleanup-test-object')
    ) {
      throw new L2BindingError(
        'session-binding-unresolved',
        'The identity context does not allow test-object write and cleanup operations.'
      )
    }

    const session = await this.#sessionVault.getSession(
      (
        await this.#requireSessionForIdentity(
          bundle.identityId,
          bundle.scopeSnapshotId
        )
      ).sessionId
    )
    if (!session || session.status !== 'active') {
      throw new L2BindingError(
        'session-binding-unresolved',
        'No active session exists for the bundle identity.'
      )
    }

    const csrfBinding = await this.#csrfBindings.assertBindingFresh(input.csrfBindingHash)
    if (csrfBinding.identityId !== bundle.identityId) {
      throw new L2BindingError('identity-mismatch', 'CSRF binding belongs to another identity.')
    }

    const matrix = await this.#matrices.getCurrentMatrix(
      bundle.targetId,
      bundle.scopeSnapshotId
    )
    if (!matrix) {
      throw new L2BindingError(
        'session-binding-unresolved',
        'No current authorization matrix exists for the bundle scope.'
      )
    }
    await this.#requireMatrixCoverage(
      { matrixId: matrix.matrixId, version: matrix.matrixVersion },
      {
        targetId: bundle.targetId,
        scopeSnapshotId: bundle.scopeSnapshotId,
        identityId: bundle.identityId,
        resourceRef: testObject.canonicalResource.resourceId
      }
    )

    const createdAt = this.#now().toISOString()
    const payload = L2ActionBundlePayloadSchema.parse({
      schemaVersion: 'agentgo-l2-protocol/1.0',
      bundleId: bundle.bundleId,
      bundleVersion: bundle.bundleVersion + 1,
      scanId: bundle.scanId,
      targetId: bundle.targetId,
      testObjectId: bundle.testObjectId,
      testObjectVersion: bundle.testObjectVersion,
      testObjectHash: bundle.testObjectHash,
      identityId: bundle.identityId,
      ...(bundle.tenantRef ? { tenantRef: bundle.tenantRef } : {}),
      scopeSnapshotId: bundle.scopeSnapshotId,
      sideEffectEnvelope: bundle.sideEffectEnvelope,
      identityContextVersion: {
        status: 'resolved',
        version: encodeIdentityContextSlot({
          identityContextId: identityContext.identityContextId,
          version: identityContext.identityContextVersion
        })
      },
      sessionGeneration: {
        status: 'resolved',
        version: encodeSessionGenerationSlot({
          sessionId: session.sessionId,
          generation: session.generation
        })
      },
      csrfBindingVersion: {
        status: 'resolved',
        version: csrfBinding.bindingHash
      },
      authorizationMatrixVersion: {
        status: 'resolved',
        version: encodeMatrixSlot({
          matrixId: matrix.matrixId,
          version: matrix.matrixVersion
        })
      },
      steps: bundle.steps,
      createdAt
    })
    const sealed = sealL2ActionBundle(payload)

    // The old draft never lingers as a parallel candidacy.
    await this.#l2.applyEvent({
      bundleId: bundle.bundleId,
      bundleVersion: bundle.bundleVersion,
      event: 'revoke',
      expectedRowVersion: input.expectedRowVersion
    })
    await this.#l2Repository.insertBundle({
      bundle: sealed,
      state: 'draft',
      now: Date.parse(createdAt)
    })
    const inserted = await this.#l2.getBundleView(sealed.bundleId, sealed.bundleVersion)
    if (!inserted) throw new L2BindingError('missing-test-object', 'Bundle insert failed.')
    return this.#l2.applyEvent({
      bundleId: sealed.bundleId,
      bundleVersion: sealed.bundleVersion,
      event: 'submit-for-approval',
      expectedRowVersion: inserted.runtime.rowVersion
    })
  }

  /**
   * Freshness gate for approval and every execution step. Session rotation,
   * identity-context reissue, CSRF expiry, or matrix reconfirmation all
   * invalidate the bound versions and fail closed.
   */
  async assertBindingsFresh(
    bundle: L2ActionBundle
  ): Promise<'ok' | L2ProtocolReasonCode> {
    const identitySlot =
      bundle.identityContextVersion.status === 'resolved'
        ? decodeSlot(bundle.identityContextVersion.version)
        : undefined
    const sessionSlot =
      bundle.sessionGeneration.status === 'resolved'
        ? decodeSlot(bundle.sessionGeneration.version)
        : undefined
    const csrfHash =
      bundle.csrfBindingVersion.status === 'resolved'
        ? bundle.csrfBindingVersion.version
        : undefined
    const matrixSlot =
      bundle.authorizationMatrixVersion.status === 'resolved'
        ? decodeSlot(bundle.authorizationMatrixVersion.version)
        : undefined
    if (!identitySlot || !sessionSlot || !csrfHash || !matrixSlot) {
      return 'session-binding-unresolved'
    }
    try {
      await this.#identityContexts.assertIdentityContextCurrent(
        bundle.identityId,
        identitySlot.version,
        identitySlot.id
      )
      await this.#sessionVault.assertActiveGeneration(sessionSlot.id, sessionSlot.version)
      await this.#csrfBindings.assertBindingFresh(csrfHash)
      await this.#matrices.assertMatrixCurrent(
        bundle.targetId,
        bundle.scopeSnapshotId,
        { matrixId: matrixSlot.id, version: matrixSlot.version }
      )
    } catch (error) {
      if (
        error instanceof IdentityContextError ||
        error instanceof SessionVaultError ||
        error instanceof CsrfBindingError
      ) {
        return 'session-binding-unresolved'
      }
      if (error instanceof AuthorizationMatrixError) {
        return error.code === 'matrix-expired' ? 'expired' : 'version-mismatch'
      }
      throw error
    }
    return 'ok'
  }

  /**
   * Rotation/clear/vault-loss propagation: every non-terminal bundle whose
   * session slot references the invalidated session is revoked immediately.
   */
  async invalidateBundlesForSession(sessionId: string): Promise<number> {
    let invalidated = 0
    const candidates = await this.#l2Repository.listOpenBundles()
    for (const candidate of candidates) {
      const slot =
        candidate.bundle.sessionGeneration.status === 'resolved'
          ? decodeSlot(candidate.bundle.sessionGeneration.version)
          : undefined
      if (!slot || slot.id !== sessionId) continue
      try {
        await this.#l2.applyEvent({
          bundleId: candidate.bundle.bundleId,
          bundleVersion: candidate.bundle.bundleVersion,
          event: 'revoke',
          expectedRowVersion: candidate.runtime.rowVersion
        })
        invalidated += 1
      } catch (error) {
        if (error instanceof L2ProtocolError) continue
        throw error
      }
    }
    return invalidated
  }

  /** Startup sweep: bundles bound to vault-lost or otherwise stale versions die. */
  async invalidateStaleBundles(): Promise<number> {
    let invalidated = 0
    const candidates = await this.#l2Repository.listOpenBundles()
    for (const candidate of candidates) {
      const freshness = await this.assertBindingsFresh(candidate.bundle)
      if (freshness === 'ok') continue
      try {
        await this.#l2.applyEvent({
          bundleId: candidate.bundle.bundleId,
          bundleVersion: candidate.bundle.bundleVersion,
          event: 'revoke',
          expectedRowVersion: candidate.runtime.rowVersion
        })
        invalidated += 1
      } catch (error) {
        if (error instanceof L2ProtocolError) continue
        throw error
      }
    }
    return invalidated
  }

  async #requireSessionForIdentity(identityId: string, scopeSnapshotId: string) {
    const session = await this.#identitySessions.getSessionForIdentity(
      identityId,
      scopeSnapshotId
    )
    if (!session) {
      throw new L2BindingError(
        'session-binding-unresolved',
        'No session exists for the bundle identity.'
      )
    }
    return session
  }

  async #requireMatrixCoverage(
    matrixSlot: { readonly matrixId: string; readonly version: number },
    input: {
      readonly targetId: string
      readonly scopeSnapshotId: string
      readonly identityId: string
      readonly resourceRef: string
    }
  ): Promise<void> {
    const matrix = await this.#matrices.assertMatrixCurrent(
      input.targetId,
      input.scopeSnapshotId,
      matrixSlot
    )
    for (const operation of ['write', 'delete'] as const) {
      try {
        await this.#matrices.requireExpectation({
          matrix,
          subjectIdentityId: input.identityId,
          resourceRef: input.resourceRef,
          operation
        })
      } catch (error) {
        if (error instanceof AuthorizationMatrixError) {
          throw new L2BindingError(
            'session-binding-unresolved',
            `The authorization matrix does not cover ${operation} on the test object.`
          )
        }
        throw error
      }
    }
  }
}
