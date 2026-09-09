import { randomUUID } from 'node:crypto'
import {
  SessionGenerationRefSchema,
  type SessionGenerationRef
} from '@agentgo/contracts'
import {
  cookieJarKey,
  cookieMatchesRequest,
  parseSetCookieHeader,
  serializeCookieHeader,
  type SetCookieOutcome,
  type VaultCookie
} from '@agentgo/domain'
import type {
  AgentGoRepository,
  FileCredentialStore,
  IdentitySessionRepository,
  SessionVaultRecord
} from '@agentgo/db'
import type {
  SecretRefResolver,
  SecretRefResolverInput
} from './request-compiler'

function namedCookieValue(
  headerValue: string | undefined,
  cookieName: string
): string | undefined {
  if (!headerValue) return undefined
  const prefix = `${cookieName}=`
  for (const part of headerValue.split(';')) {
    const trimmed = part.trim()
    if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length)
  }
  return undefined
}

export class SessionVaultError extends Error {
  readonly code:
    | 'identity-missing'
    | 'identity-not-test'
    | 'session-missing'
    | 'session-not-active'
    | 'session-generation-mismatch'
    | 'credential-unavailable'
    | 'scope-mismatch'

  constructor(code: SessionVaultError['code'], message: string) {
    super(message)
    this.name = 'SessionVaultError'
    this.code = code
  }
}

export type SessionVaultEvent =
  | 'establish'
  | 'reinitialize'
  | 'rotate'
  | 'clear'
  | 'expire'
  | 'revoke'
  | 'vault-lost'

export interface SessionVaultAuditSink {
  recordSessionEvent(input: {
    readonly sessionId: string
    readonly identityId: string
    readonly targetId: string
    readonly scopeSnapshotId: string
    readonly event: SessionVaultEvent
    readonly generation: number
  }): void
}

/**
 * Protected, process-local session material. Cookie jars and resolved tokens
 * live only in memory; SQLite stores metadata, credential references, and the
 * monotonic generation. Persisted rows can never resurrect secret material:
 * process restart marks every active session `vault-lost`, and reactivation
 * always advances the generation so old bundles, grants, and approvals die.
 */
export class SessionVault {
  static readonly COOKIE_RESOLVER_ID = 'session-vault.cookie.v1'
  static readonly CREDENTIAL_RESOLVER_ID = 'session-vault.credential.v1'

  readonly #identitySessions: IdentitySessionRepository
  readonly #repository: AgentGoRepository
  readonly #credentialStore: FileCredentialStore
  readonly #auditSink?: SessionVaultAuditSink
  readonly #now: () => number
  readonly #jars = new Map<string, Map<string, VaultCookie>>()

  constructor(dependencies: {
    readonly identitySessionRepository: IdentitySessionRepository
    readonly repository: AgentGoRepository
    readonly credentialStore: FileCredentialStore
    readonly auditSink?: SessionVaultAuditSink
    readonly now?: () => number
  }) {
    this.#identitySessions = dependencies.identitySessionRepository
    this.#repository = dependencies.repository
    this.#credentialStore = dependencies.credentialStore
    this.#auditSink = dependencies.auditSink
    this.#now = dependencies.now ?? Date.now
  }

  /**
   * Process-start boundary. Persisted active sessions lose their in-memory
   * jar on restart, so they are terminally marked vault-lost with a bumped
   * generation. Callers must re-establish and re-inject material.
   */
  markActiveSessionsVaultLost(): number {
    this.#jars.clear()
    return this.#identitySessions.markActiveSessionsVaultLost(this.#now())
  }

  /**
   * Returns the active session for (identity, scope), creating an empty
   * container when none exists. This never performs login: sessions become
   * useful only after explicit user-provided material is injected.
   */
  async establishSession(input: {
    readonly identityId: string
    readonly scopeSnapshotId: string
  }): Promise<SessionVaultRecord> {
    const identity = await this.#requireTestIdentity(input.identityId)
    const scope = await this.#repository.getScope(input.scopeSnapshotId)
    if (!scope || scope.targetId !== identity.targetId) {
      throw new SessionVaultError('scope-mismatch', 'Session scope belongs to another target or is missing.')
    }
    const existing = await this.#identitySessions.getSessionForIdentity(
      input.identityId,
      input.scopeSnapshotId
    )
    if (!existing) {
      const created = await this.#identitySessions.createSession({
        sessionId: randomUUID(),
        identityId: identity.id,
        targetId: identity.targetId,
        scopeSnapshotId: input.scopeSnapshotId,
        now: this.#now()
      })
      this.#jars.set(created.sessionId, new Map())
      this.#audit('establish', created)
      return created
    }
    if (existing.status === 'active') {
      return existing
    }
    // A vault-lost/expired/revoked row is reactivated only with a new
    // generation; the database trigger rejects revival without one.
    const reinitialized = await this.#identitySessions.advanceSession(
      existing.sessionId,
      { status: 'active', incrementGeneration: true },
      this.#now()
    )
    if (!reinitialized) {
      throw new SessionVaultError('session-missing', 'The session disappeared during setup.')
    }
    this.#jars.set(reinitialized.sessionId, new Map())
    this.#audit('reinitialize', reinitialized)
    return reinitialized
  }

  async getSession(sessionId: string): Promise<SessionVaultRecord | undefined> {
    return this.#identitySessions.getSession(sessionId)
  }

  /**
   * Ingests one Set-Cookie value into the private jar. The raw value never
   * leaves the vault: it is not written to the database, evidence, logs, or
   * audit payloads. Rotation-safe: the session must be active.
   */
  async ingestSetCookie(
    sessionId: string,
    headerValue: string,
    requestUrl: string
  ): Promise<SetCookieOutcome> {
    const session = await this.#requireActiveSession(sessionId)
    const scope = await this.#repository.getScope(session.scopeSnapshotId)
    let origin: string
    try {
      origin = new URL(requestUrl).origin
    } catch {
      return { ok: false, reason: 'malformed' }
    }
    if (!scope || scope.targetId !== session.targetId || !scope.allowedOrigins.includes(origin)) {
      throw new SessionVaultError('scope-mismatch', 'Cookie source is outside the session scope.')
    }
    const outcome = parseSetCookieHeader(headerValue, { url: requestUrl }, this.#now())
    if (!outcome.ok) return outcome
    const jar = new Map(this.#jars.get(session.sessionId))
    const key = `${origin}\0${cookieJarKey(outcome.cookie)}`
    if (outcome.cookie.expiresAt !== null && outcome.cookie.expiresAt <= this.#now()) {
      jar.delete(key)
    } else {
      jar.set(key, outcome.cookie)
    }
    // Every injection, including a server-side rotation or deletion, changes
    // the authority generation. Snapshot resolvers retain the old jar identity
    // and therefore cannot return material after this update.
    const updated = await this.#identitySessions.advanceSession(
      sessionId,
      { status: 'active', incrementGeneration: true },
      this.#now()
    )
    if (!updated) throw new SessionVaultError('session-missing', 'Session disappeared during cookie injection.')
    this.#jars.set(sessionId, jar)
    this.#audit('rotate', updated)
    return outcome
  }

  /**
   * Materializes the Cookie header for a wire request at send time. Fails
   * closed when the session generation drifted since the caller looked it up.
   */
  async cookieHeaderFor(
    sessionId: string,
    url: string,
    expectedGeneration?: number
  ): Promise<string | undefined> {
    const session = await this.#requireActiveSession(sessionId)
    if (expectedGeneration !== undefined && session.generation !== expectedGeneration) {
      throw new SessionVaultError(
        'session-generation-mismatch',
        'The session generation changed before dispatch.'
      )
    }
    const jar = this.#jars.get(sessionId)
    if (!jar || jar.size === 0) return undefined
    const now = this.#now()
    const matching: VaultCookie[] = []
    for (const cookie of jar.values()) {
      if (cookieMatchesRequest(cookie, { url }, now)) {
        matching.push(cookie)
      }
    }
    if (matching.length === 0) return undefined
    return serializeCookieHeader(matching)
  }

  /**
   * Snapshots one named cookie value for request compilation. The Cookie
   * header itself is reserved on the wire template, so individual names go
   * through `requestTemplate.cookies` as secret-refs.
   */
  async namedCookieSecretResolverFor(
    sessionId: string,
    cookieName: string,
    url: string
  ): Promise<{
    readonly sessionRef: SessionGenerationRef
    readonly cookieValue: string | undefined
    readonly resolver: SecretRefResolver
  }> {
    const session = await this.#requireActiveSession(sessionId)
    const sessionRef = SessionGenerationRefSchema.parse({
      id: session.sessionId,
      generation: session.generation,
      ownerRef: session.targetId,
      scopeSnapshotId: session.scopeSnapshotId,
      statusSummary: 'active'
    })
    const headerValue = await this.cookieHeaderFor(sessionId, url, session.generation)
    const cookieValue = namedCookieValue(headerValue, cookieName)
    const jar = this.#jars.get(sessionId)
    const assertSnapshotCurrent = () => {
      if (this.#jars.get(sessionId) !== jar || !jar ||
          ![...jar.values()].some((cookie) => cookie.name === cookieName &&
            cookie.value === cookieValue && cookieMatchesRequest(cookie, { url }, this.#now()))) {
        throw new Error('Session cookie material is no longer current.')
      }
    }
    const resolver: SecretRefResolver = Object.freeze({
      resolverId: SessionVault.COOKIE_RESOLVER_ID,
      version: '1.0.0',
      resolve(input: SecretRefResolverInput): unknown {
        assertSnapshotCurrent()
        if (
          input.secretRef !== session.sessionId ||
          input.generation !== session.generation ||
          input.sessionRef?.id !== session.sessionId ||
          input.sessionRef.generation !== session.generation
        ) {
          throw new Error('Session cookie binding changed.')
        }
        if (cookieValue === undefined) {
          throw new Error('No named session cookie applies to the bound request.')
        }
        return cookieValue
      }
    })
    return Object.freeze({ sessionRef, cookieValue, resolver })
  }

  /** Rotation bumps the generation and drops all cookie material. */
  async rotateSession(sessionId: string): Promise<SessionVaultRecord> {
    const session = await this.#requireSession(sessionId)
    const rotated = await this.#identitySessions.advanceSession(
      session.sessionId,
      { status: 'active', incrementGeneration: true },
      this.#now()
    )
    if (!rotated) {
      throw new SessionVaultError('session-missing', 'The session disappeared during rotation.')
    }
    this.#jars.set(sessionId, new Map())
    this.#audit('rotate', rotated)
    return rotated
  }

  /** Logout/clear drops material and terminates the generation. */
  async clearSession(sessionId: string): Promise<SessionVaultRecord> {
    return this.#terminate(sessionId, 'expired', 'clear')
  }

  async revokeSession(sessionId: string): Promise<SessionVaultRecord> {
    return this.#terminate(sessionId, 'revoked', 'revoke')
  }

  /**
   * The opaque reference embedded in compiled requests and grants. Only
   * active sessions yield a reference; there is no fallback identity.
   */
  async sessionGenerationRef(sessionId: string): Promise<SessionGenerationRef> {
    const session = await this.#requireActiveSession(sessionId)
    return SessionGenerationRefSchema.parse({
      id: session.sessionId,
      generation: session.generation,
      ownerRef: session.targetId,
      scopeSnapshotId: session.scopeSnapshotId,
      statusSummary: 'active'
    })
  }

  /** Generation check used by grant issuance and the dispatch guard. */
  async assertActiveGeneration(sessionId: string, generation: number): Promise<void> {
    const session = await this.#requireActiveSession(sessionId)
    if (session.generation !== generation) {
      throw new SessionVaultError(
        'session-generation-mismatch',
        'The session generation is no longer current.'
      )
    }
  }

  /**
   * Materializes the Cookie header for one exact request URL and pins it to
   * the current session generation. The returned resolver is single-purpose:
   * it replays the snapshot only when the compiled proof carries the same
   * session id and generation. Any rotation between materialization and
   * compile invalidates the pin.
   */
  async cookieSecretResolverFor(
    sessionId: string,
    url: string
  ): Promise<{
    readonly sessionRef: SessionGenerationRef
    readonly headerValue: string | undefined
    readonly resolver: SecretRefResolver
  }> {
    const session = await this.#requireActiveSession(sessionId)
    const sessionRef = SessionGenerationRefSchema.parse({
      id: session.sessionId,
      generation: session.generation,
      ownerRef: session.targetId,
      scopeSnapshotId: session.scopeSnapshotId,
      statusSummary: 'active'
    })
    const headerValue = await this.cookieHeaderFor(sessionId, url, session.generation)
    const jar = this.#jars.get(sessionId)
    const assertSnapshotCurrent = () => {
      const current = jar ? serializeCookieHeader(
        [...jar.values()].filter((cookie) => cookieMatchesRequest(cookie, { url }, this.#now()))
      ) : undefined
      if (this.#jars.get(sessionId) !== jar || !jar || current !== headerValue) {
        throw new Error('Session cookie material is no longer current.')
      }
    }
    const resolver: SecretRefResolver = Object.freeze({
      resolverId: SessionVault.COOKIE_RESOLVER_ID,
      version: '1.0.0',
      resolve(input: SecretRefResolverInput): unknown {
        assertSnapshotCurrent()
        if (
          input.secretRef !== session.sessionId ||
          input.generation !== session.generation ||
          input.sessionRef?.id !== session.sessionId ||
          input.sessionRef.generation !== session.generation
        ) {
          throw new Error('Session cookie binding changed.')
        }
        if (headerValue === undefined) {
          throw new Error('No session cookies apply to the bound request.')
        }
        return headerValue
      }
    })
    return Object.freeze({ sessionRef, headerValue, resolver })
  }

  /**
   * Minimal-capability credential resolution for the request compiler.
   * Callers cannot enumerate vault contents: resolution requires the exact
   * credential id plus the generation pinned by the compiled proof.
   */
  credentialSecretResolver(): SecretRefResolver {
    const credentialStore = this.#credentialStore
    return Object.freeze({
      resolverId: SessionVault.CREDENTIAL_RESOLVER_ID,
      version: '1.0.0',
      resolve(input: SecretRefResolverInput): unknown {
        const metadata = credentialStore
          .list()
          .find((entry) => entry.id === input.secretRef)
        if (!metadata || metadata.generation !== input.generation) {
          throw new Error('Credential generation is no longer current.')
        }
        const secret = credentialStore.get(input.secretRef)
        if (!secret) throw new Error('Credential material is unavailable.')
        return secret
      }
    })
  }

  async #requireTestIdentity(identityId: string) {
    const identity = await this.#repository.getIdentity(identityId)
    if (!identity) {
      throw new SessionVaultError('identity-missing', 'Identity does not exist.')
    }
    if (!identity.isTestIdentity) {
      throw new SessionVaultError(
        'identity-not-test',
        'Sessions can only be established for designated test identities.'
      )
    }
    return identity
  }

  async #requireSession(sessionId: string): Promise<SessionVaultRecord> {
    const session = await this.#identitySessions.getSession(sessionId)
    if (!session) {
      throw new SessionVaultError('session-missing', 'Session does not exist.')
    }
    return session
  }

  async #requireActiveSession(sessionId: string): Promise<SessionVaultRecord> {
    const session = await this.#requireSession(sessionId)
    if (session.status !== 'active') {
      throw new SessionVaultError(
        'session-not-active',
        `Session is ${session.status}; user re-injection is required.`
      )
    }
    return session
  }

  async #terminate(
    sessionId: string,
    status: 'expired' | 'revoked',
    event: SessionVaultEvent
  ): Promise<SessionVaultRecord> {
    const session = await this.#requireActiveSession(sessionId)
    const updated = await this.#identitySessions.advanceSession(
      session.sessionId,
      { status, incrementGeneration: true },
      this.#now()
    )
    if (!updated) {
      throw new SessionVaultError('session-missing', 'The session disappeared.')
    }
    this.#jars.delete(sessionId)
    this.#audit(event, updated)
    return updated
  }

  #audit(event: SessionVaultEvent, session: SessionVaultRecord): void {
    this.#auditSink?.recordSessionEvent({
      sessionId: session.sessionId,
      identityId: session.identityId,
      targetId: session.targetId,
      scopeSnapshotId: session.scopeSnapshotId,
      event,
      generation: session.generation
    })
  }
}
