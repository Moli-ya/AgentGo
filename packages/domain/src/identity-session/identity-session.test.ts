import { describe, expect, it } from 'vitest'
import {
  cookieJarKey,
  cookieMatchesRequest,
  orderCookiesForSend,
  parseSetCookieHeader,
  serializeCookieHeader
} from './cookie'
import {
  assertCsrfBindingUsable,
  extractCsrfToken,
  injectCsrfToken
} from './csrf'
import {
  lookupAuthorizationExpectation
} from './matrix'
import { sealAuthorizationMatrix } from './hash'
import type { CsrfBindingRule } from '@agentgo/contracts'

const NOW = Date.parse('2026-08-26T00:00:00.000Z')

function parse(header: string, url = 'https://app.example.test/account/settings') {
  return parseSetCookieHeader(header, { url }, NOW)
}

describe('vault cookie semantics', () => {
  it('parses host-only cookies with defaults and rejects empty names', () => {
    const outcome = parse('sid=abc123; Path=/account; HttpOnly; SameSite=Strict')
    expect(outcome.ok).toBe(true)
    if (!outcome.ok) return
    expect(outcome.cookie).toMatchObject({
      name: 'sid',
      value: 'abc123',
      domain: 'app.example.test',
      path: '/account',
      hostOnly: true,
      httpOnly: true,
      sameSite: 'strict',
      secure: false,
      expiresAt: null
    })
    expect(parse('=orphan; Path=/').ok).toBe(false)
  })

  it('enforces domain suffix, host-only isolation, and public-suffix rejection', () => {
    const widened = parse('sid=a; Domain=example.test', 'https://app.example.test/')
    expect(widened.ok).toBe(true)
    if (widened.ok) {
      expect(
        cookieMatchesRequest(widened.cookie, { url: 'https://sub.example.test/' }, NOW)
      ).toBe(false)
      expect(
        cookieMatchesRequest(widened.cookie, { url: 'https://other.test/' }, NOW)
      ).toBe(false)
    }

    expect(parse('sid=a; Domain=other.test', 'https://app.example.test/').ok).toBe(false)
    expect(parse('sid=a; Domain=test', 'https://app.example.test/')).toMatchObject({
      ok: false,
      reason: 'public-suffix-forbidden'
    })
    expect(parse('sid=a; Domain=com', 'https://app.example.test/').ok).toBe(false)
    for (const [domain, host] of [['co.uk', 'app.example.co.uk'], ['github.io', 'app.github.io']]) {
      expect(parse(`sid=a; Domain=${domain}`, `https://${host}/`)).toMatchObject({
        ok: false, reason: 'public-suffix-forbidden'
      })
    }

    const hostOnly = parse('sid=a', 'https://app.example.test/')
    expect(hostOnly.ok).toBe(true)
    if (hostOnly.ok) {
      expect(
        cookieMatchesRequest(hostOnly.cookie, { url: 'https://sub.app.example.test/' }, NOW)
      ).toBe(false)
    }
  })

  it('enforces path match, secure transport, and same-site-none secure pairing', () => {
    const pathed = parse('sid=a; Path=/account', 'https://app.example.test/account/x')
    expect(pathed.ok).toBe(true)
    if (pathed.ok) {
      expect(
        cookieMatchesRequest(pathed.cookie, { url: 'https://app.example.test/account' }, NOW)
      ).toBe(true)
      expect(
        cookieMatchesRequest(pathed.cookie, { url: 'https://app.example.test/accounting' }, NOW)
      ).toBe(false)
      expect(
        cookieMatchesRequest(pathed.cookie, { url: 'https://app.example.test/other' }, NOW)
      ).toBe(false)
    }

    const secure = parse('sid=a; Secure', 'https://app.example.test/')
    expect(secure.ok).toBe(true)
    if (secure.ok) {
      expect(
        cookieMatchesRequest(secure.cookie, { url: 'http://app.example.test/' }, NOW)
      ).toBe(false)
    }
    expect(parse('sid=a; SameSite=None', 'https://app.example.test/')).toMatchObject({
      ok: false,
      reason: 'secure-required'
    })
    expect(parse('sid=a; SameSite=None; Secure', 'https://app.example.test/').ok).toBe(true)
  })

  it('handles expiry, max-age precedence, and rotation replacement', () => {
    const expired = parse(`sid=a; Expires=${new Date(NOW - 1_000).toUTCString()}`)
    expect(expired).toMatchObject({ ok: true, cookie: { expiresAt: NOW - 1_000 } })
    expect(parse('sid=; Max-Age=0')).toMatchObject({ ok: true, cookie: { expiresAt: 0 } })
    expect(parse('sid=a; Max-Age=60junk')).toMatchObject({ ok: true, cookie: { expiresAt: null } })

    const maxAge = parse('sid=a; Max-Age=60; Expires=Wed, 01 Jan 2030 00:00:00 GMT')
    expect(maxAge.ok).toBe(true)
    if (maxAge.ok) expect(maxAge.cookie.expiresAt).toBe(NOW + 60_000)

    const first = parse('sid=old; Path=/')
    const rotated = parse('sid=new; Path=/')
    expect(first.ok && rotated.ok).toBe(true)
    if (first.ok && rotated.ok) {
      expect(cookieJarKey(first.cookie)).toBe(cookieJarKey(rotated.cookie))
    }
  })

  it('orders longer paths first and rejects control characters', () => {
    const root = parse('a=1; Path=/')
    const deep = parse('b=2; Path=/account/sub')
    const mid = parse('c=3; Path=/account')
    expect(root.ok && deep.ok && mid.ok).toBe(true)
    if (root.ok && deep.ok && mid.ok) {
      const ordered = orderCookiesForSend([root.cookie, deep.cookie, mid.cookie])
      expect(ordered.map((cookie) => cookie.name)).toEqual(['b', 'c', 'a'])
      expect(serializeCookieHeader([root.cookie, mid.cookie])).toBe('c=3; a=1')
    }
    expect(parse('sid=a; Path=/xy').ok).toBe(true)
    expect(parse('sid=va;lue').ok).toBe(true)
    expect(parse('sid=bad value with; semicolon').ok).toBe(true)
  })
})

const csrfRule: CsrfBindingRule = {
  ruleVersion: 'fixture-csrf/1.0',
  sourceKind: 'json-pointer',
  sourceSelector: '/csrfToken',
  sourceOrigin: 'http://127.0.0.1:8080',
  sourcePathPrefix: '/l2/',
  encoding: 'raw',
  injectionLocation: 'header',
  injectionName: 'x-csrf-token',
  maxUses: 2
}

describe('deterministic CSRF extraction and injection', () => {
  it('extracts a single json-pointer token and rejects missing/ambiguous values', () => {
    const extracted = extractCsrfToken(csrfRule, {
      url: 'http://127.0.0.1:8080/l2/session',
      bodyText: '{"csrfToken":"token-123"}'
    })
    expect(extracted).toEqual({ ok: true, token: 'token-123' })

    expect(
      extractCsrfToken(csrfRule, {
        url: 'http://127.0.0.1:8080/l2/session',
        bodyText: '{"other":1}'
      })
    ).toEqual({ ok: false, reason: 'token-missing' })

    expect(
      extractCsrfToken(
        { ...csrfRule, sourceKind: 'html-input', sourceSelector: 'csrf' },
        {
          url: 'http://127.0.0.1:8080/l2/form',
          bodyText:
            '<input name="csrf" value="a"><input name="csrf" value="b">'
        }
      )
    ).toEqual({ ok: false, reason: 'token-ambiguous' })
  })

  it('rejects tokens from untrusted origins or outside the declared path prefix', () => {
    expect(
      extractCsrfToken(csrfRule, {
        url: 'http://evil.example/l2/session',
        bodyText: '{"csrfToken":"x"}'
      })
    ).toEqual({ ok: false, reason: 'untrusted-source' })
    expect(
      extractCsrfToken(csrfRule, {
        url: 'http://127.0.0.1:8080/other',
        bodyText: '{"csrfToken":"x"}'
      })
    ).toEqual({ ok: false, reason: 'untrusted-source' })
  })

  it('extracts from headers, html input, html meta, and form fields', () => {
    expect(
      extractCsrfToken(
        { ...csrfRule, sourceKind: 'response-header', sourceSelector: 'x-csrf-token' },
        { url: 'http://127.0.0.1:8080/l2/session', headers: { 'X-CSRF-Token': 'h-token' } }
      )
    ).toEqual({ ok: true, token: 'h-token' })
    expect(
      extractCsrfToken(
        { ...csrfRule, sourceKind: 'html-meta', sourceSelector: 'csrf-token' },
        {
          url: 'http://127.0.0.1:8080/l2/page',
          bodyText: '<meta name="csrf-token" content="meta-token">'
        }
      )
    ).toEqual({ ok: true, token: 'meta-token' })
    expect(
      extractCsrfToken(
        { ...csrfRule, sourceKind: 'form-field', sourceSelector: 'csrf' },
        { url: 'http://127.0.0.1:8080/l2/form', bodyText: 'a=1&csrf=form-token' }
      )
    ).toEqual({ ok: true, token: 'form-token' })
  })

  it('injects into headers, forms, and JSON bodies without overwriting existing values', () => {
    const headerInjection = injectCsrfToken(csrfRule, 'tok', {
      location: 'header',
      headers: { accept: 'application/json' }
    })
    expect(headerInjection.ok).toBe(true)
    if (headerInjection.ok) {
      expect(headerInjection.headers).toEqual({
        accept: 'application/json',
        'x-csrf-token': 'tok'
      })
    }
    expect(
      injectCsrfToken(csrfRule, 'tok', {
        location: 'header',
        headers: { 'X-CSRF-TOKEN': 'existing' }
      })
    ).toMatchObject({ ok: false, reason: 'token-ambiguous' })

    const formRule: CsrfBindingRule = {
      ...csrfRule,
      injectionLocation: 'form-field',
      injectionName: 'csrf'
    }
    const formInjection = injectCsrfToken(formRule, 'tok', {
      location: 'form-field',
      bodyText: 'title=hello'
    })
    expect(formInjection.ok).toBe(true)
    if (formInjection.ok) {
      expect(formInjection.bodyText).toContain('title=hello')
      expect(formInjection.bodyText).toContain('csrf=tok')
    }
    expect(
      injectCsrfToken(formRule, 'tok', { location: 'form-field', bodyText: 'csrf=old' }).ok
    ).toBe(false)

    const jsonRule: CsrfBindingRule = {
      ...csrfRule,
      injectionLocation: 'json-pointer',
      injectionName: '/meta/csrf'
    }
    const jsonInjection = injectCsrfToken(jsonRule, 'tok', {
      location: 'json-pointer',
      bodyText: '{"meta":{}}'
    })
    expect(jsonInjection.ok).toBe(true)
    if (jsonInjection.ok) {
      expect(JSON.parse(jsonInjection.bodyText ?? '{}')).toEqual({
        meta: { csrf: 'tok' }
      })
    }
  })

  it('binds usage to identity, session generation, origin, method, path, and expiry', () => {
    const binding = {
      identityId: 'identity-1',
      sessionId: 'session-1',
      sessionGeneration: 3,
      origin: 'http://127.0.0.1:8080',
      boundMethod: 'POST',
      boundPath: '/l2/test-objects/obj-1',
      expiresAt: '2026-08-26T01:00:00.000Z'
    }
    const request = {
      identityId: 'identity-1',
      sessionId: 'session-1',
      sessionGeneration: 3,
      url: 'http://127.0.0.1:8080/l2/test-objects/obj-1',
      method: 'POST'
    }
    expect(
      assertCsrfBindingUsable({ rule: csrfRule, binding, request, now: NOW })
    ).toEqual({ ok: true })

    const drift = (
      changes: Partial<typeof request>
    ): ReturnType<typeof assertCsrfBindingUsable> =>
      assertCsrfBindingUsable({
        rule: csrfRule,
        binding,
        request: { ...request, ...changes },
        now: NOW
      })
    expect(drift({ identityId: 'identity-2' })).toEqual({
      ok: false,
      reason: 'identity-mismatch'
    })
    expect(drift({ sessionGeneration: 4 })).toEqual({
      ok: false,
      reason: 'session-generation-mismatch'
    })
    expect(drift({ url: 'http://other.host:8080/l2/test-objects/obj-1' })).toEqual({
      ok: false,
      reason: 'origin-mismatch'
    })
    expect(drift({ method: 'PUT' })).toEqual({ ok: false, reason: 'method-path-mismatch' })
    expect(drift({ url: 'http://127.0.0.1:8080/l2/test-objects/other' })).toEqual({
      ok: false,
      reason: 'method-path-mismatch'
    })
    expect(
      assertCsrfBindingUsable({
        rule: csrfRule,
        binding,
        request,
        now: Date.parse('2026-08-26T02:00:00.000Z')
      })
    ).toEqual({ ok: false, reason: 'token-expired' })
  })
})

describe('authorization matrix reads', () => {
  const matrix = sealAuthorizationMatrix({
    schemaVersion: 'agentgo-identity-session/1.0',
    matrixId: '11111111-1111-4111-8111-111111111111',
    matrixVersion: 1,
    targetId: '22222222-2222-4222-8222-222222222222',
    scopeSnapshotId: '33333333-3333-4333-8333-333333333333',
    entries: [
      {
        subjectIdentityId: '44444444-4444-4444-8444-444444444444',
        resourceOwnerIdentityId: '44444444-4444-4444-8444-444444444444',
        role: 'owner',
        operation: 'write',
        resourceRef: 'obj-1',
        expected: 'state-allowed',
        humanSource: 'fixture declaration'
      }
    ],
    humanAttestationRef: '55555555-5555-4555-8555-555555555555',
    issuedAt: '2026-08-26T00:00:00.000Z',
    expiresAt: '2026-08-26T01:00:00.000Z'
  })

  it('returns exact subject/resource/operation matches and fails closed on absence', () => {
    expect(
      lookupAuthorizationExpectation(matrix, {
        subjectIdentityId: '44444444-4444-4444-8444-444444444444',
        resourceRef: 'obj-1',
        operation: 'write'
      })?.expected
    ).toBe('state-allowed')
    expect(
      lookupAuthorizationExpectation(matrix, {
        subjectIdentityId: '44444444-4444-4444-8444-444444444444',
        resourceRef: 'obj-1',
        operation: 'read'
      })
    ).toBeUndefined()
    expect(
      lookupAuthorizationExpectation(matrix, {
        subjectIdentityId: '66666666-6666-4666-8666-666666666666',
        resourceRef: 'obj-1',
        operation: 'write'
      })
    ).toBeUndefined()
  })
})
