/**
 * Deterministic awaiting-user classification for session, CSRF, MFA/CAPTCHA,
 * and identity-ownership gaps. These codes never trigger credential guesses,
 * login/refresh attempts, or identity fallback.
 */

export const IdentitySessionAwaitingUserReason = {
  'session-expired': 'session-expired',
  'vault-lost': 'vault-lost',
  'mfa-required': 'mfa-required',
  'captcha-required': 'captcha-required',
  'ownership-unknown': 'ownership-unknown',
  'csrf-ambiguous': 'csrf-ambiguous',
  'csrf-missing': 'csrf-missing',
  'identity-unconfirmed': 'identity-unconfirmed'
} as const

export type IdentitySessionAwaitingUserReason =
  (typeof IdentitySessionAwaitingUserReason)[keyof typeof IdentitySessionAwaitingUserReason]

export interface IdentitySessionAwaitingUserSignal {
  readonly sessionStatus?: 'active' | 'expired' | 'revoked' | 'vault-lost'
  readonly csrfFailure?:
    | 'token-missing'
    | 'token-ambiguous'
    | 'token-expired'
    | 'identity-mismatch'
    | 'session-generation-mismatch'
    | 'origin-mismatch'
    | 'method-path-mismatch'
    | 'untrusted-source'
    | 'rule-version-mismatch'
    | 'use-limit-exceeded'
  readonly challengeKind?: 'mfa' | 'captcha' | 'none'
  readonly ownershipConfirmed?: boolean
}

/**
 * Maps observed session/CSRF/challenge conditions to a stable awaiting-user
 * reason. Callers must stop and wait; they must not rotate credentials or
 * impersonate another identity.
 */
export function classifyIdentitySessionAwaitingUser(
  signal: IdentitySessionAwaitingUserSignal
): IdentitySessionAwaitingUserReason | undefined {
  if (signal.challengeKind === 'mfa') return 'mfa-required'
  if (signal.challengeKind === 'captcha') return 'captcha-required'
  if (signal.sessionStatus === 'vault-lost') return 'vault-lost'
  if (signal.sessionStatus === 'expired' || signal.sessionStatus === 'revoked') {
    return 'session-expired'
  }
  if (signal.ownershipConfirmed === false) return 'ownership-unknown'
  if (signal.csrfFailure === 'token-ambiguous') return 'csrf-ambiguous'
  if (
    signal.csrfFailure === 'token-missing' ||
    signal.csrfFailure === 'untrusted-source'
  ) {
    return 'csrf-missing'
  }
  if (signal.csrfFailure !== undefined) return 'identity-unconfirmed'
  return undefined
}
