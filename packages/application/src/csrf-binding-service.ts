import { randomUUID } from 'node:crypto'
import {
  CsrfBindingSchema,
  type CsrfBinding,
  type CsrfBindingFailureReason,
  type CsrfBindingRule
} from '@agentgo/contracts'
import {
  assertCsrfBindingUsable,
  extractCsrfToken,
  hashIdentitySessionValue,
  sealCsrfBinding,
  type CsrfExtractionResponse
} from '@agentgo/domain'
import type { IdentitySessionRepository } from '@agentgo/db'
import { SessionVault, SessionVaultError } from './session-vault'
import type { SecretRefResolver, SecretRefResolverInput } from './request-compiler'

export class CsrfBindingError extends Error {
  readonly code:
    | 'session-not-active'
    | 'rule-version-mismatch'
    | 'binding-missing'
    | 'binding-not-active'
    | CsrfBindingFailureReason

  constructor(code: CsrfBindingError['code'], message: string) {
    super(message)
    this.name = 'CsrfBindingError'
    this.code = code
  }
}

export type CaptureCsrfBindingResult =
  | { readonly ok: true; readonly binding: CsrfBinding }
  | { readonly ok: false; readonly reason: CsrfBindingFailureReason | 'session-not-active' }

interface ResolvedCsrfToken {
  readonly binding: CsrfBinding
  readonly token: string
}

/**
 * Versioned CSRF bindings. Token plaintext lives only in process memory and
 * only until expiry; SQLite stores the sealed binding with the token hash.
 * Extraction is deterministic (no model involvement), and a binding is bound
 * to exactly one identity, session generation, origin, method, and path.
 */
export class CsrfBindingService {
  readonly #identitySessions: IdentitySessionRepository
  readonly #sessionVault: SessionVault
  readonly #now: () => number
  readonly #tokens = new Map<string, { readonly token: string; readonly expiresAt: number }>()

  constructor(dependencies: {
    readonly identitySessionRepository: IdentitySessionRepository
    readonly sessionVault: SessionVault
    readonly now?: () => number
  }) {
    this.#identitySessions = dependencies.identitySessionRepository
    this.#sessionVault = dependencies.sessionVault
    this.#now = dependencies.now ?? Date.now
  }

  /**
   * Extracts a token from an observed response under an exact rule and seals
   * a new binding. The rule version is caller-declared; any rule change must
   * capture a new binding, which invalidates old bundle references.
   */
  async captureBinding(input: {
    readonly identityId: string
    readonly sessionId: string
    readonly origin: string
    readonly boundMethod: 'POST' | 'PUT' | 'PATCH'
    readonly boundPath: string
    readonly rule: CsrfBindingRule
    readonly response: CsrfExtractionResponse
    readonly ttlMs: number
  }): Promise<CaptureCsrfBindingResult> {
    let session
    try {
      session = await this.#sessionVault.getSession(input.sessionId)
    } catch (error) {
      if (error instanceof SessionVaultError) {
        return { ok: false, reason: 'session-not-active' }
      }
      throw error
    }
    if (!session || session.status !== 'active') {
      return { ok: false, reason: 'session-not-active' }
    }
    if (session.identityId !== input.identityId) {
      return { ok: false, reason: 'identity-mismatch' }
    }

    const extraction = extractCsrfToken(input.rule, input.response)
    if (!extraction.ok) return extraction

    const issuedAtMs = this.#now()
    const expiresAtMs = issuedAtMs + input.ttlMs
    const binding = sealCsrfBinding({
      schemaVersion: 'agentgo-identity-session/1.0',
      csrfBindingId: randomUUID(),
      csrfBindingVersion: 1,
      identityId: input.identityId,
      sessionId: session.sessionId,
      sessionGeneration: session.generation,
      origin: input.origin,
      boundMethod: input.boundMethod,
      boundPath: input.boundPath,
      rule: input.rule,
      tokenHash: hashIdentitySessionValue({ csrfToken: extraction.token }),
      issuedAt: new Date(issuedAtMs).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString()
    })
    CsrfBindingSchema.parse(binding)
    const stored = await this.#identitySessions.insertCsrfBinding(binding)
    this.#tokens.set(binding.bindingHash, {
      token: extraction.token,
      expiresAt: expiresAtMs
    })
    return { ok: true, binding: stored.binding }
  }

  /**
   * Resolves the live token for one exact request. Every check re-validates
   * identity, session generation, origin, method/path, expiry, and the use
   * limit; the use is recorded atomically before the token is returned.
   */
  async resolveTokenForRequest(input: {
    readonly bindingHash: string
    readonly request: {
      readonly identityId: string
      readonly url: string
      readonly method: string
    }
  }): Promise<ResolvedCsrfToken> {
    const row = await this.#identitySessions.getCsrfBindingByHash(input.bindingHash)
    if (!row) {
      throw new CsrfBindingError('binding-missing', 'CSRF binding does not exist.')
    }
    if (row.status !== 'active') {
      throw new CsrfBindingError('binding-not-active', `CSRF binding is ${row.status}.`)
    }
    const binding = row.binding
    const usability = assertCsrfBindingUsable({
      rule: binding.rule,
      binding,
      request: {
        identityId: input.request.identityId,
        sessionId: binding.sessionId,
        sessionGeneration: binding.sessionGeneration,
        url: input.request.url,
        method: input.request.method
      },
      now: this.#now()
    })
    if (!usability.ok) {
      throw new CsrfBindingError(usability.reason, `CSRF binding rejected: ${usability.reason}.`)
    }
    await this.#sessionVault.assertActiveGeneration(
      binding.sessionId,
      binding.sessionGeneration
    )
    if (row.useCount >= binding.rule.maxUses) {
      throw new CsrfBindingError('use-limit-exceeded', 'CSRF binding use limit reached.')
    }
    const tokenEntry = this.#tokens.get(input.bindingHash)
    if (!tokenEntry || tokenEntry.expiresAt <= this.#now()) {
      throw new CsrfBindingError(
        'token-expired',
        'CSRF token material is no longer available in the vault.'
      )
    }
    const used = await this.#identitySessions.recordCsrfUse(
      binding.csrfBindingId,
      binding.csrfBindingVersion,
      this.#now()
    )
    if (!used) {
      throw new CsrfBindingError('binding-not-active', 'CSRF binding could not record its use.')
    }
    if (used.useCount >= binding.rule.maxUses) {
      await this.#identitySessions.setCsrfBindingStatus(
        binding.csrfBindingId,
        binding.csrfBindingVersion,
        'exhausted'
      )
      this.#tokens.delete(input.bindingHash)
    }
    return { binding, token: tokenEntry.token }
  }

  async getBinding(bindingHash: string): Promise<CsrfBinding | undefined> {
    const row = await this.#identitySessions.getCsrfBindingByHash(bindingHash)
    return row?.binding
  }

  /**
   * Freshness check for bundle submission/approval/execution steps.
   * Exhausted bindings remain the same csrfBindingVersion: mutating uses are
   * spent, but later read/verify steps must not look like a session drift.
   */
  async assertBindingFresh(bindingHash: string): Promise<CsrfBinding> {
    const row = await this.#identitySessions.getCsrfBindingByHash(bindingHash)
    if (!row || (row.status !== 'active' && row.status !== 'exhausted')) {
      throw new CsrfBindingError('binding-not-active', 'CSRF binding is no longer active.')
    }
    if (Date.parse(row.binding.expiresAt) <= this.#now()) {
      throw new CsrfBindingError('token-expired', 'CSRF binding has expired.')
    }
    await this.#sessionVault.assertActiveGeneration(
      row.binding.sessionId,
      row.binding.sessionGeneration
    )
    if (row.status === 'active' && !this.#tokens.has(bindingHash)) {
      throw new CsrfBindingError(
        'token-expired',
        'CSRF token material is unavailable after vault loss.'
      )
    }
    return row.binding
  }

  static readonly TOKEN_RESOLVER_ID = 'csrf-binding.token.v1'

  /**
   * Snapshots the live CSRF token for one compile. Use is recorded now so
   * the compiler's synchronous resolver can replay the exact value without
   * a second consumption.
   */
  async tokenSecretResolverFor(input: {
    readonly bindingHash: string
    readonly request: {
      readonly identityId: string
      readonly url: string
      readonly method: string
    }
  }): Promise<{
    readonly binding: CsrfBinding
    readonly resolver: SecretRefResolver
  }> {
    const resolved = await this.resolveTokenForRequest(input)
    const binding = resolved.binding
    const token = resolved.token
    const resolver: SecretRefResolver = Object.freeze({
      resolverId: CsrfBindingService.TOKEN_RESOLVER_ID,
      version: '1.0.0',
      resolve(secretInput: SecretRefResolverInput): unknown {
        if (
          secretInput.secretRef !== binding.csrfBindingId ||
          secretInput.generation !== binding.csrfBindingVersion
        ) {
          throw new Error('CSRF binding changed.')
        }
        return token
      }
    })
    return Object.freeze({ binding, resolver })
  }

  /** Session rotation/termination immediately invalidates every binding. */
  async revokeBindingsForSession(sessionId: string): Promise<void> {
    const heldHashes = [...this.#tokens.keys()]
    const sessionHashes = new Set<string>()
    for (const hash of heldHashes) {
      const row = await this.#identitySessions.getCsrfBindingByHash(hash)
      if (row?.binding.sessionId === sessionId) sessionHashes.add(hash)
    }
    await this.#identitySessions.revokeCsrfBindingsForSession(sessionId)
    for (const hash of sessionHashes) {
      this.#tokens.delete(hash)
    }
  }

  /** Process restart drops token plaintext; persisted bindings stay but can no longer resolve. */
  dropTokenMaterial(): void {
    this.#tokens.clear()
  }
}
