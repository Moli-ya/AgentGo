/**
 * Deterministic RFC 6265 subset for the protected SessionVault.
 *
 * The vault is a programmatic client, not a browser: there is no navigation
 * concept, so SameSite=Lax is enforced with the same strictness as
 * SameSite=Strict (same-origin sends only). All cookies are additionally
 * isolated by their source origin. Public/private suffixes are checked using
 * the pinned, offline Public Suffix List bundled with tldts.
 */

import { parseRuntimeUrl, type RuntimeUrl } from './runtime-url'
import { getPublicSuffix } from 'tldts'

export interface VaultCookie {
  readonly origin: string
  readonly name: string
  readonly value: string
  readonly domain: string
  readonly path: string
  readonly hostOnly: boolean
  readonly secure: boolean
  readonly httpOnly: boolean
  readonly sameSite: 'strict' | 'lax' | 'none'
  readonly expiresAt: number | null
  readonly createdAt: number
}

export type SetCookieRejection =
  | 'malformed'
  | 'empty-name'
  | 'invalid-character'
  | 'domain-not-suffix'
  | 'public-suffix-forbidden'
  | 'secure-required'
  | 'already-expired'

export type SetCookieOutcome =
  | { readonly ok: true; readonly cookie: VaultCookie }
  | { readonly ok: false; readonly reason: SetCookieRejection }

const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u
const CONTROL_OR_SEPARATOR = /[;\x00-\x1f\x7f]/u

function isIpLiteral(host: string): boolean {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(host)) return true
  return host.includes(':')
}

function normalizeHost(host: string): string {
  return host.toLowerCase()
}

function isForbiddenDomainAttribute(domain: string, requestHost: string): boolean {
  if (isIpLiteral(domain)) return domain !== requestHost
  if (!domain.includes('.')) return domain !== requestHost
  return getPublicSuffix(domain, { allowPrivateDomains: true }) === domain
}

function domainMatches(requestHost: string, cookieDomain: string): boolean {
  return (
    requestHost === cookieDomain ||
    requestHost.endsWith('.' + cookieDomain)
  )
}

function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true
  if (!requestPath.startsWith(cookiePath)) return false
  if (cookiePath.endsWith('/')) return true
  return requestPath.charAt(cookiePath.length) === '/'
}

function defaultCookiePath(requestPath: string): string {
  if (!requestPath.startsWith('/')) return '/'
  if (requestPath === '/') return '/'
  const lastSlash = requestPath.lastIndexOf('/')
  if (lastSlash <= 0) return '/'
  return requestPath.slice(0, lastSlash)
}

export function parseSetCookieHeader(
  headerValue: string,
  request: { readonly url: string },
  now: number
): SetCookieOutcome {
  const url: RuntimeUrl | undefined = parseRuntimeUrl(request.url)
  if (!url) return { ok: false, reason: 'malformed' }
  const requestHost = normalizeHost(url.hostname)
  const segments = headerValue.split(';')
  const pair = segments.shift()
  if (pair === undefined) return { ok: false, reason: 'malformed' }
  const equals = pair.indexOf('=')
  if (equals <= 0) return { ok: false, reason: 'malformed' }
  const name = pair.slice(0, equals).trim()
  let value = pair.slice(equals + 1).trim()
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    value = value.slice(1, -1)
  }
  if (name.length === 0) return { ok: false, reason: 'empty-name' }
  if (!COOKIE_NAME_PATTERN.test(name)) return { ok: false, reason: 'invalid-character' }
  if (CONTROL_OR_SEPARATOR.test(value)) {
    return { ok: false, reason: 'invalid-character' }
  }

  let domain: string | undefined
  let path: string | undefined
  let secure = false
  let httpOnly = false
  let sameSite: VaultCookie['sameSite'] = 'lax'
  let expiresAt: number | null = null
  let maxAge: number | undefined

  for (const attribute of segments) {
    const attributeEquals = attribute.indexOf('=')
    const attributeName = (
      attributeEquals === -1 ? attribute : attribute.slice(0, attributeEquals)
    )
      .trim()
      .toLowerCase()
    const attributeValue =
      attributeEquals === -1 ? '' : attribute.slice(attributeEquals + 1).trim()
    switch (attributeName) {
      case 'domain': {
        const candidate = normalizeHost(
          attributeValue.startsWith('.') ? attributeValue.slice(1) : attributeValue
        )
        if (!domainMatches(requestHost, candidate)) {
          return { ok: false, reason: 'domain-not-suffix' }
        }
        if (isForbiddenDomainAttribute(candidate, requestHost)) {
          return { ok: false, reason: 'public-suffix-forbidden' }
        }
        if (isIpLiteral(candidate) && candidate !== requestHost) {
          return { ok: false, reason: 'domain-not-suffix' }
        }
        domain = candidate
        break
      }
      case 'path': {
        path =
          attributeValue.startsWith('/') && !CONTROL_OR_SEPARATOR.test(attributeValue)
            ? attributeValue
            : undefined
        if (path === undefined) {
          path = defaultCookiePath(url.pathname)
        }
        break
      }
      case 'max-age': {
        if (!/^-?\d+$/u.test(attributeValue)) break
        const seconds = Number(attributeValue)
        if (!Number.isSafeInteger(seconds)) break
        maxAge = seconds
        break
      }
      case 'expires': {
        const parsed = Date.parse(attributeValue)
        if (Number.isFinite(parsed)) {
          expiresAt = parsed
        }
        break
      }
      case 'secure':
        secure = true
        break
      case 'httponly':
        httpOnly = true
        break
      case 'samesite': {
        const candidate = attributeValue.toLowerCase()
        if (candidate === 'strict' || candidate === 'lax' || candidate === 'none') {
          sameSite = candidate
        }
        break
      }
      default:
        break
    }
  }

  if (sameSite === 'none' && !secure) {
    return { ok: false, reason: 'secure-required' }
  }
  if (secure && url.protocol !== 'https:') {
    return { ok: false, reason: 'secure-required' }
  }
  if (maxAge !== undefined) expiresAt = maxAge <= 0 ? 0 : Math.min(8.64e15, now + maxAge * 1_000)

  return {
    ok: true,
    cookie: {
      origin: url.origin,
      name,
      value,
      domain: domain ?? requestHost,
      path: path ?? defaultCookiePath(url.pathname),
      hostOnly: domain === undefined,
      secure,
      httpOnly,
      sameSite,
      expiresAt,
      createdAt: now
    }
  }
}

export function cookieMatchesRequest(
  cookie: VaultCookie,
  request: { readonly url: string },
  now: number
): boolean {
  const url: RuntimeUrl | undefined = parseRuntimeUrl(request.url)
  if (!url) return false
  if (url.origin !== cookie.origin) return false
  if (cookie.expiresAt !== null && cookie.expiresAt <= now) return false
  if (cookie.secure && url.protocol !== 'https:') return false
  const requestHost = normalizeHost(url.hostname)
  if (cookie.hostOnly) {
    if (requestHost !== cookie.domain) return false
  } else if (!domainMatches(requestHost, cookie.domain)) {
    return false
  }
  const requestPath = url.pathname === '' ? '/' : url.pathname
  return pathMatches(requestPath, cookie.path)
}

/**
 * RFC 6265 §5.4 send order: longer paths first, then earlier creation.
 */
export function orderCookiesForSend(
  cookies: readonly VaultCookie[]
): VaultCookie[] {
  return [...cookies].sort((left, right) => {
    if (right.path.length !== left.path.length) {
      return right.path.length - left.path.length
    }
    return left.createdAt - right.createdAt
  })
}

export function serializeCookieHeader(cookies: readonly VaultCookie[]): string {
  return orderCookiesForSend(cookies)
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join('; ')
}

export function cookieJarKey(cookie: Pick<VaultCookie, 'name' | 'domain' | 'path'>): string {
  return `${cookie.name}\0${cookie.domain}\0${cookie.path}`
}
