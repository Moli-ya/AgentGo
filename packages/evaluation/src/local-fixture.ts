import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { randomBytes } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import {
  LEGACY_V1_FAMILY_IDS,
  LOCAL_FIXTURE_ID,
  LOCAL_FIXTURE_VERSION,
  isLegacyV1VulnerabilityFamily,
  type LegacyV1VulnerabilityFamily
} from '@agentgo/contracts'
import { canonicalJson, sha256Text } from '@agentgo/domain'

export { LOCAL_FIXTURE_ID, LOCAL_FIXTURE_VERSION }

export interface LocalBenchmarkFixture {
  version: typeof LOCAL_FIXTURE_VERSION
  baseUrl: string
  bindAddress: '127.0.0.1'
  port: number
  attestationHash: string
  namespaceHash: string
  outboundAttempts: readonly string[]
  reset(): FixtureResetResult
  close(): Promise<void>
}

export interface FixtureIdentityPlan {
  ownerToken: string
  memberToken: string
  ownerResourceId: string
  memberResourceId: string
}

export interface FixtureResetResult {
  generation: number
  namespaceHash: string
}

export interface FixtureNamespaceState {
  generation: number
  notes: Record<string, never>
}

const FIXTURE_ROUTE_TABLE = Object.freeze(
  LEGACY_V1_FAMILY_IDS.flatMap((family) =>
    (['positive', 'negative'] as const).flatMap((polarity) =>
      Array.from({ length: 5 }, (_, index) =>
        `/cases/${family}/${polarity}/${index + 1}`
      )
    )
  )
)

export function localFixtureAttestationProfile() {
  return Object.freeze({
    fixtureId: LOCAL_FIXTURE_ID,
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    bindAddress: '127.0.0.1' as const,
    portPolicy: 'ephemeral' as const,
    outboundPolicy: 'loopback-same-origin-callback-only' as const,
    resetPolicy: 'fixture-namespace-only' as const,
    methods: Object.freeze(['GET'] as const),
    selector: 'query' as const,
    families: [...LEGACY_V1_FAMILY_IDS],
    routes: [...FIXTURE_ROUTE_TABLE]
  })
}

export function localFixtureAttestationHash(): string {
  return sha256Text(canonicalJson(localFixtureAttestationProfile()))
}

function emptyNamespace(generation: number): FixtureNamespaceState {
  return {
    generation,
    notes: {}
  }
}

export function fixtureNamespaceHash(state: FixtureNamespaceState): string {
  return sha256Text(canonicalJson({ notes: state.notes }))
}

export function isFixtureLoopbackUrl(value: URL, fixtureOrigin: string): boolean {
  return (
    (value.hostname === '127.0.0.1' || value.hostname === 'localhost') &&
    value.origin === fixtureOrigin
  )
}

function send(
  response: ServerResponse,
  status: number,
  contentType: string,
  body: string
): void {
  response.writeHead(status, {
    'content-type': contentType,
    'cache-control': 'no-store',
    'x-agentgo-fixture-version': LOCAL_FIXTURE_VERSION,
    'x-agentgo-fixture-id': LOCAL_FIXTURE_ID
  })
  response.end(body)
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function lastPathSegment(pathname: string): string {
  const parts = pathname.split('/').filter(Boolean)
  try {
    return decodeURIComponent(parts.at(-1) ?? '')
  } catch {
    return parts.at(-1) ?? ''
  }
}

function booleanSqliBody(positive: boolean, value: string): string {
  const isFalseCondition = /AND\s+(?:1\s*=\s*2|'1'\s*=\s*'2')/i.test(value)
  return positive && isFalseCondition
    ? '<html><body>no rows</body></html>'
    : '<html><body>product: visible</body></html>'
}

async function handleSqliResearch(
  request: IncomingMessage,
  url: URL,
  response: ServerResponse
): Promise<boolean> {
  const pathname = url.pathname
  if (!pathname.startsWith('/research/sqli/')) return false

  if (pathname === '/research/sqli/form/positive') {
    if (request.method !== 'POST') {
      send(response, 405, 'text/plain; charset=utf-8', 'method not allowed')
      return true
    }
    send(response, 200, 'application/json; charset=utf-8', '{"ok":true}')
    return true
  }
  if (pathname === '/research/sqli/json/positive') {
    if (request.method !== 'POST') {
      send(response, 405, 'text/plain; charset=utf-8', 'method not allowed')
      return true
    }
    send(response, 200, 'application/json; charset=utf-8', '{"rows":[{"id":1}]}')
    return true
  }
  if (pathname === '/research/sqli/json/negative') {
    if (request.method !== 'POST') {
      send(response, 405, 'text/plain; charset=utf-8', 'method not allowed')
      return true
    }
    send(response, 200, 'application/json; charset=utf-8', '{"rows":[]}')
    return true
  }

  if (pathname.startsWith('/research/sqli/boolean/path/positive/')) {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      booleanSqliBody(true, lastPathSegment(pathname))
    )
    return true
  }
  if (pathname.startsWith('/research/sqli/boolean/path/negative/')) {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      booleanSqliBody(false, lastPathSegment(pathname))
    )
    return true
  }
  if (pathname === '/research/sqli/boolean/query/row-positive') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      booleanSqliBody(
        true,
        url.searchParams.get('row') ?? url.searchParams.get('id') ?? ''
      )
    )
    return true
  }
  if (pathname === '/research/sqli/boolean/query/row-negative') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      booleanSqliBody(
        false,
        url.searchParams.get('row') ?? url.searchParams.get('id') ?? ''
      )
    )
    return true
  }
  if (pathname === '/research/sqli/error/query/positive') {
    const value = url.searchParams.get('msg') ?? ''
    if (value.includes("'")) {
      send(
        response,
        200,
        'text/plain; charset=utf-8',
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
      )
      return true
    }
    send(response, 200, 'text/plain; charset=utf-8', 'message stored')
    return true
  }
  if (pathname === '/research/sqli/error/query/negative') {
    send(response, 200, 'text/plain; charset=utf-8', 'message stored')
    return true
  }
  if (pathname === '/research/sqli/error/query/generic-500') {
    send(response, 500, 'text/plain; charset=utf-8', 'Internal Server Error')
    return true
  }
  if (pathname === '/research/sqli/error/query/waf') {
    send(response, 403, 'text/plain; charset=utf-8', 'request blocked by web application firewall')
    return true
  }
  if (pathname === '/research/sqli/time/query/positive') {
    const value = url.searchParams.get('wait') ?? ''
    if (/SLEEP\s*\(\s*2\s*\)/i.test(value)) {
      await new Promise((resolve) => setTimeout(resolve, 2_000))
    }
    send(response, 200, 'text/plain; charset=utf-8', 'ready')
    return true
  }
  if (pathname === '/research/sqli/time/query/negative') {
    send(response, 200, 'text/plain; charset=utf-8', 'ready')
    return true
  }
  if (pathname === '/research/sqli/time/query/jitter') {
    await new Promise((resolve) => setTimeout(resolve, 200 + Math.floor(Math.random() * 1_800)))
    send(response, 200, 'text/plain; charset=utf-8', 'ready')
    return true
  }
  if (pathname === '/research/sqli/boolean/query/cached-positive') {
    const body = booleanSqliBody(true, url.searchParams.get('id') ?? '')
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=60',
      etag: '"sqli-cached-positive"',
      'x-agentgo-fixture-version': LOCAL_FIXTURE_VERSION,
      'x-agentgo-fixture-id': LOCAL_FIXTURE_ID
    })
    response.end(body)
    return true
  }
  if (pathname === '/research/sqli/boolean/query/item-positive') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      booleanSqliBody(true, url.searchParams.get('item') ?? '')
    )
    return true
  }
  if (pathname === '/research/sqli/boolean/query/item-negative') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      booleanSqliBody(false, url.searchParams.get('item') ?? '')
    )
    return true
  }
  if (pathname === '/research/sqli/boolean/query/random-negative') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `${booleanSqliBody(false, url.searchParams.get('id') ?? '')}<span>${token()}</span>`
    )
    return true
  }
  return false
}

function researchIdorIdentity(): FixtureIdentityPlan {
  return fixtureIdentityPlan(1)
}

function researchBearer(request: IncomingMessage): string | undefined {
  const header = request.headers.authorization
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return undefined
  return header.slice('Bearer '.length)
}

async function handleSsrfResearch(
  request: IncomingMessage,
  url: URL,
  response: ServerResponse,
  context: { readonly baseUrl: string; readonly outboundAttempts: string[] }
): Promise<boolean> {
  const pathname = url.pathname
  if (!pathname.startsWith('/research/ssrf/')) return false
  if (request.method !== 'GET') {
    send(response, 405, 'text/plain; charset=utf-8', 'method not allowed')
    return true
  }

  const destination =
    url.searchParams.get('target') ??
    url.searchParams.get('callback') ??
    url.searchParams.get('webhook') ??
    url.searchParams.get('image') ??
    url.searchParams.get('avatar') ??
    url.searchParams.get('url') ??
    ''

  if (
    pathname === '/research/ssrf/reflected/positive' ||
    pathname === '/research/ssrf/reflected/image-positive'
  ) {
    try {
      const target = new URL(destination)
      context.outboundAttempts.push(target.href)
      if (!isFixtureLoopbackUrl(target, new URL(context.baseUrl).origin)) {
        send(response, 200, 'text/plain; charset=utf-8', 'target rejected')
        return true
      }
      const fetched = await fetch(target)
      send(response, 200, 'text/plain; charset=utf-8', await fetched.text())
    } catch {
      send(response, 200, 'text/plain; charset=utf-8', 'invalid url')
    }
    return true
  }
  if (
    pathname === '/research/ssrf/oob/positive' ||
    pathname === '/research/ssrf/oob/webhook-positive'
  ) {
    try {
      const target = new URL(destination)
      context.outboundAttempts.push(target.href)
      if (target.hostname !== '127.0.0.1') {
        send(response, 200, 'text/plain; charset=utf-8', 'target rejected')
        return true
      }
      await fetch(target)
      send(response, 200, 'text/plain; charset=utf-8', 'fetched')
    } catch {
      send(response, 504, 'text/plain; charset=utf-8', 'collector down')
    }
    return true
  }
  if (pathname === '/research/ssrf/file-scheme/negative') {
    send(response, 200, 'text/plain; charset=utf-8', 'non-http scheme rejected')
    return true
  }
  if (pathname === '/research/ssrf/metadata/negative') {
    send(response, 200, 'text/plain; charset=utf-8', 'metadata destination rejected')
    return true
  }
  if (pathname === '/research/ssrf/allow-list/negative') {
    send(response, 200, 'text/plain; charset=utf-8', 'allow-list proxy ok')
    return true
  }
  if (pathname === '/research/ssrf/client-fetch/negative') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body><img src="${destination}"></body></html>`
    )
    return true
  }
  if (pathname === '/research/ssrf/old-token/negative') {
    send(response, 200, 'text/plain; charset=utf-8', 'stale token ignored')
    return true
  }
  if (pathname === '/research/ssrf/redirect-out/inconclusive') {
    response.writeHead(302, {
      location: 'http://169.254.169.254/',
      'content-type': 'text/plain; charset=utf-8'
    })
    response.end('redirect')
    return true
  }
  if (pathname === '/research/ssrf/collector-down/inconclusive') {
    send(response, 504, 'text/plain; charset=utf-8', 'collector down')
    return true
  }
  if (pathname === '/research/ssrf/dynamic/inconclusive') {
    send(response, 200, 'text/plain; charset=utf-8', `dynamic-${token()}`)
    return true
  }
  if (pathname.startsWith('/research/headers/')) {
    return false
  }
  send(response, 404, 'text/plain; charset=utf-8', 'not-found')
  return true
}

function handleHeadersResearch(url: URL, response: ServerResponse): boolean {
  const pathname = url.pathname
  if (!pathname.startsWith('/research/headers/')) return false
  if (pathname === '/research/headers/missing') {
    send(response, 200, 'text/html; charset=utf-8', '<html><body>ok</body></html>')
    return true
  }
  if (pathname === '/research/headers/complete') {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'strict-transport-security': 'max-age=63072000',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store'
    })
    response.end('<html><body>ok</body></html>')
    return true
  }
  if (pathname === '/research/headers/proxy-rewritten') {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff, nosniff',
      via: '1.1 proxy.example',
      'x-forwarded-proto': 'https'
    })
    response.end('<html><body>ok</body></html>')
    return true
  }
  send(response, 404, 'text/plain; charset=utf-8', 'not-found')
  return true
}

function handleIdorResearch(
  request: IncomingMessage,
  url: URL,
  response: ServerResponse
): boolean {
  const pathname = url.pathname
  if (!pathname.startsWith('/research/idor/')) return false
  const identity = researchIdorIdentity()
  const tokenValue = researchBearer(request)
  const role =
    tokenValue === identity.ownerToken
      ? 'owner'
      : tokenValue === identity.memberToken
        ? 'member'
        : tokenValue === 'agentgo-admin-1'
          ? 'admin'
          : tokenValue === 'agentgo-public-1'
            ? 'public'
            : undefined

  if (pathname === '/research/idor/bola/session-expired') {
    send(response, 401, 'application/json; charset=utf-8', '{"error":"unauthorized"}')
    return true
  }
  if (pathname === '/research/idor/bola/dynamic') {
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({
        id: identity.ownerResourceId,
        ownerId: 'owner',
        value: token()
      })
    )
    return true
  }
  if (pathname === '/research/idor/bola/cached') {
    response.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'public, max-age=60',
      'x-agentgo-fixture-version': LOCAL_FIXTURE_VERSION,
      'x-agentgo-fixture-id': LOCAL_FIXTURE_ID
    })
    response.end(
      JSON.stringify({
        id: identity.ownerResourceId,
        ownerId: 'owner',
        value: 'cached'
      })
    )
    return true
  }
  if (pathname === '/research/idor/bola/public/negative') {
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({
        id: 'public-resource-1',
        ownerId: 'public',
        visibility: 'public',
        value: 'shared-notice'
      })
    )
    return true
  }
  if (pathname === '/research/idor/bola/shared/negative') {
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({
        id: identity.ownerResourceId,
        ownerId: 'owner',
        visibility: 'shared',
        value: 'team-doc'
      })
    )
    return true
  }
  if (pathname === '/research/idor/bola/admin/negative') {
    if (role !== 'admin') {
      send(response, 403, 'application/json; charset=utf-8', '{"error":"forbidden"}')
      return true
    }
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({
        id: identity.ownerResourceId,
        ownerId: 'owner',
        value: 'admin-visible'
      })
    )
    return true
  }

  const pathMatch = /^\/research\/idor\/bola\/path\/(positive|negative)\/([^/]+)$/.exec(
    pathname
  )
  const resourceId = pathMatch
    ? decodeURIComponent(pathMatch[2] ?? '')
    : url.searchParams.get('item_id') ??
      url.searchParams.get('account_id') ??
      url.searchParams.get('id') ??
      url.searchParams.get('document_id') ??
      lastPathSegment(pathname)
  const polarity = pathMatch
    ? pathMatch[1]
    : pathname.includes('/negative')
      ? 'negative'
      : 'positive'

  if (!role) {
    send(response, 401, 'application/json; charset=utf-8', '{"error":"unauthorized"}')
    return true
  }
  const ownResource = role === 'owner' ? identity.ownerResourceId : identity.memberResourceId
  const crossDenied =
    polarity === 'negative' &&
    role !== 'owner' &&
    role !== 'admin' &&
    resourceId !== ownResource
  if (crossDenied) {
    send(response, 403, 'application/json; charset=utf-8', '{"error":"forbidden"}')
    return true
  }
  send(
    response,
    200,
    'application/json; charset=utf-8',
    JSON.stringify({
      id: resourceId,
      ownerId: resourceId === identity.ownerResourceId ? 'owner' : 'member',
      tenantId: pathname.includes('cross-tenant') ? 'tenant-a' : 'tenant-a',
      parentId: pathname.includes('parent') ? 'parent-1' : undefined,
      value: `test-only-${resourceId}`
    })
  )
  return true
}

function handleXssResearch(
  request: IncomingMessage,
  url: URL,
  response: ServerResponse
): boolean {
  const pathname = url.pathname
  if (!pathname.startsWith('/research/xss/')) return false

  if (pathname === '/research/xss/stored/positive') {
    if (request.method !== 'POST') {
      send(response, 405, 'text/plain; charset=utf-8', 'method not allowed')
      return true
    }
    send(response, 200, 'application/json; charset=utf-8', '{"ok":true,"object":"xss-test"}')
    return true
  }

  const value =
    url.searchParams.get('q') ??
    url.searchParams.get('message') ??
    url.searchParams.get('name') ??
    url.searchParams.get('hash') ??
    url.hash.replace(/^#/, '') ??
    lastPathSegment(pathname)

  if (pathname === '/research/xss/html/positive') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body>Search: ${value}</body></html>`
    )
    return true
  }
  if (pathname === '/research/xss/html/negative') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body>Search: ${escapeHtml(value)}</body></html>`
    )
    return true
  }
  if (pathname === '/research/xss/attribute/positive') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body><input value="${value}"></body></html>`
    )
    return true
  }
  if (pathname === '/research/xss/attribute/negative') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body><input value="${escapeHtml(value)}"></body></html>`
    )
    return true
  }
  if (pathname === '/research/xss/json/negative') {
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({ message: value })
    )
    return true
  }
  if (pathname === '/research/xss/sanitizer/negative') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body>${escapeHtml(value).replaceAll('svg', '')}</body></html>`
    )
    return true
  }
  if (pathname === '/research/xss/csp/inconclusive') {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': "default-src 'none'",
      'cache-control': 'no-store',
      'x-agentgo-fixture-version': LOCAL_FIXTURE_VERSION,
      'x-agentgo-fixture-id': LOCAL_FIXTURE_ID
    })
    response.end(`<html><body>Search: ${value}</body></html>`)
    return true
  }
  if (pathname === '/research/xss/nonce/inconclusive') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body data-nonce="${token()}">Search: ${escapeHtml(value)}</body></html>`
    )
    return true
  }
  if (pathname === '/research/xss/dom/positive') {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body id="sink"></body><script>document.getElementById('sink').innerHTML=location.hash.slice(1)</script></html>`
    )
    return true
  }
  if (pathname.startsWith('/research/xss/html/path/positive/')) {
    send(
      response,
      200,
      'text/html; charset=utf-8',
      `<html><body>Search: ${lastPathSegment(pathname)}</body></html>`
    )
    return true
  }
  send(response, 404, 'application/json; charset=utf-8', '{"error":"not-found"}')
  return true
}

function parseCase(pathname: string): {
  family: LegacyV1VulnerabilityFamily
  polarity: 'positive' | 'negative'
  number: number
} | undefined {
  const match = /^\/cases\/([^/]+)\/(positive|negative)\/([1-5])$/.exec(
    pathname
  )
  if (!match) return undefined
  const family = match[1]
  const polarity = match[2]
  if (
    !isLegacyV1VulnerabilityFamily(family) ||
    (polarity !== 'positive' && polarity !== 'negative')
  ) {
    return undefined
  }
  return {
    family,
    polarity,
    number: Number(match[3])
  }
}

export function fixtureIdentityPlan(caseNumber: number): FixtureIdentityPlan {
  if (!Number.isInteger(caseNumber) || caseNumber < 1 || caseNumber > 5) {
    throw new Error('Fixture case number must be between 1 and 5.')
  }
  return {
    ownerToken: `agentgo-owner-${caseNumber}`,
    memberToken: `agentgo-member-${caseNumber}`,
    ownerResourceId: `owner-resource-${caseNumber}`,
    memberResourceId: `member-resource-${caseNumber}`
  }
}

function fixtureIndex(baseUrl: string): string {
  const links = LEGACY_V1_FAMILY_IDS.flatMap((family) =>
    (['positive', 'negative'] as const).flatMap((polarity) =>
      Array.from({ length: 5 }, (_, index) => {
        const parameter = family === 'xss' ? 'q' : family === 'ssrf' ? 'url' : 'id'
        const value = family === 'idor' ? `owner-resource-${index + 1}` : '1'
        const path = `/cases/${family}/${polarity}/${index + 1}?${parameter}=${encodeURIComponent(value)}`
        return `<li><a href="${path}">${family}-${polarity}-${index + 1}</a></li>`
      })
    )
  )
  return `<!doctype html><html><head><meta charset="utf-8"><title>AgentGo Local Fixture</title></head><body><h1>AgentGo Local Fixture</h1><p>${baseUrl}</p><ul>${links.join('')}</ul></body></html>`
}

function parseCookie(header: string | string[] | undefined, name: string): string | undefined {
  const raw = Array.isArray(header) ? header.join('; ') : header
  if (!raw) return undefined
  for (const part of raw.split(';')) {
    const trimmed = part.trim()
    const separator = trimmed.indexOf('=')
    if (separator <= 0) continue
    if (trimmed.slice(0, separator) === name) return trimmed.slice(separator + 1)
  }
  return undefined
}

function readRequestBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    request.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    request.on('error', reject)
  })
}

function token(): string {
  return randomBytes(16).toString('hex')
}

async function handleL2Route(input: {
  readonly request: IncomingMessage
  readonly response: ServerResponse
  readonly url: URL
  readonly sessionId: string
  readonly csrfToken: string
  readonly l2Objects: Map<string, { status: 'draft' | 'submitted' }>
  readonly rotateSession: () => void
}): Promise<void> {
  const { request, response, url, sessionId, csrfToken, l2Objects } = input
  const cookie = parseCookie(request.headers.cookie, 'sid')

  if (url.pathname === '/l2/session') {
    if (request.method !== 'GET') {
      send(response, 405, 'application/json; charset=utf-8', '{"error":"method-not-allowed"}')
      return
    }
    response.setHeader('set-cookie', `sid=${sessionId}; Path=/; HttpOnly`)
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({ csrfToken, session: 'active' })
    )
    return
  }

  const objectMatch = /^\/l2\/objects\/([^/]+)$/.exec(url.pathname)
  if (!objectMatch) {
    send(response, 404, 'application/json; charset=utf-8', '{"error":"not-found"}')
    return
  }
  const objectId = decodeURIComponent(objectMatch[1] ?? '')
  if (cookie !== sessionId) {
    send(response, 401, 'application/json; charset=utf-8', '{"error":"unauthorized"}')
    return
  }

  if (request.method === 'GET') {
    const current = l2Objects.get(objectId) ?? { status: 'draft' as const }
    l2Objects.set(objectId, current)
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({ id: objectId, status: current.status, csrfToken })
    )
    return
  }

  if (request.method !== 'POST') {
    send(response, 405, 'application/json; charset=utf-8', '{"error":"method-not-allowed"}')
    return
  }

  const csrfHeader = request.headers['x-csrf-token']
  const provided = Array.isArray(csrfHeader) ? csrfHeader[0] : csrfHeader
  if (provided !== csrfToken) {
    send(response, 403, 'application/json; charset=utf-8', '{"error":"csrf"}')
    return
  }

  let parsed: { status?: unknown; action?: unknown }
  try {
    parsed = JSON.parse(await readRequestBody(request)) as {
      status?: unknown
      action?: unknown
    }
  } catch {
    send(response, 400, 'application/json; charset=utf-8', '{"error":"invalid-json"}')
    return
  }

  const current = l2Objects.get(objectId) ?? { status: 'draft' as const }
  if (parsed.action === 'reset') {
    l2Objects.set(objectId, { status: 'draft' })
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({ id: objectId, status: 'draft' })
    )
    return
  }
  if (parsed.status === 'submitted') {
    l2Objects.set(objectId, { status: 'submitted' })
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({ id: objectId, status: 'submitted' })
    )
    return
  }
  send(
    response,
    400,
    'application/json; charset=utf-8',
    JSON.stringify({ id: objectId, status: current.status, error: 'unsupported-mutation' })
  )
}

export async function startLocalBenchmarkFixture(): Promise<LocalBenchmarkFixture> {
  let baseUrl = ''
  let namespace = emptyNamespace(0)
  const outboundAttempts: string[] = []
  const l2Objects = new Map<string, { status: 'draft' | 'submitted' }>()
  let sessionId = token()
  let csrfToken = token()
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', baseUrl || 'http://127.0.0.1')
    const isL2 = url.pathname === '/l2/session' || url.pathname.startsWith('/l2/objects/')

    if (isL2) {
      await handleL2Route({
        request,
        response,
        url,
        sessionId,
        csrfToken,
        l2Objects,
        rotateSession: () => {
          sessionId = token()
          csrfToken = token()
        }
      })
      return
    }

    if (await handleSqliResearch(request, url, response)) return
    if (await handleSsrfResearch(request, url, response, { baseUrl, outboundAttempts })) {
      return
    }
    if (handleHeadersResearch(url, response)) return
    if (handleIdorResearch(request, url, response)) return
    if (handleXssResearch(request, url, response)) return

    if (request.method !== 'GET') {
      send(response, 405, 'application/json; charset=utf-8', '{"error":"method-not-allowed"}')
      return
    }
    if (url.pathname === '/') {
      send(response, 200, 'text/html; charset=utf-8', fixtureIndex(baseUrl))
      return
    }
    if (url.pathname === '/health') {
      send(
        response,
        200,
        'application/json; charset=utf-8',
        JSON.stringify({
          ok: true,
          version: LOCAL_FIXTURE_VERSION,
          attestationHash: localFixtureAttestationHash(),
          namespaceHash: fixtureNamespaceHash(namespace)
        })
      )
      return
    }
    if (url.pathname === '/reset') {
      namespace = emptyNamespace(namespace.generation + 1)
      send(
        response,
        200,
        'application/json; charset=utf-8',
        JSON.stringify({
          ok: true,
          generation: namespace.generation,
          namespaceHash: fixtureNamespaceHash(namespace)
        })
      )
      return
    }
    if (url.pathname === '/callback') {
      const token = url.searchParams.get('agentgo_token') ?? 'missing'
      send(
        response,
        200,
        'text/plain; charset=utf-8',
        `AGENTGO_CALLBACK_PROOF_${token}`
      )
      return
    }

    const testCase = parseCase(url.pathname)
    if (!testCase) {
      send(response, 404, 'application/json; charset=utf-8', '{"error":"not-found"}')
      return
    }

    if (testCase.family === 'sqli') {
      const value = url.searchParams.get('id') ?? ''
      const isFalseCondition = /AND\s+(?:1\s*=\s*2|'1'\s*=\s*'2')/i.test(value)
      const body =
        testCase.polarity === 'positive' && isFalseCondition
          ? '<html><body>no rows</body></html>'
          : '<html><body>product: visible</body></html>'
      send(response, 200, 'text/html; charset=utf-8', body)
      return
    }

    if (testCase.family === 'xss') {
      const value = url.searchParams.get('q') ?? ''
      const rendered = testCase.polarity === 'positive' ? value : escapeHtml(value)
      send(
        response,
        200,
        'text/html; charset=utf-8',
        `<html><head><title>Search</title></head><body>Search: ${rendered}</body></html>`
      )
      return
    }

    if (testCase.family === 'ssrf') {
      const targetValue = url.searchParams.get('url') ?? ''
      if (testCase.polarity === 'negative') {
        send(response, 200, 'text/plain; charset=utf-8', 'remote fetch disabled')
        return
      }
      try {
        const target = new URL(targetValue)
        outboundAttempts.push(target.href)
        if (!isFixtureLoopbackUrl(target, new URL(baseUrl).origin) || target.pathname !== '/callback') {
          send(response, 200, 'text/plain; charset=utf-8', 'target rejected')
          return
        }
        const callbackResponse = await fetch(target)
        send(response, 200, 'text/plain; charset=utf-8', await callbackResponse.text())
      } catch {
        send(response, 200, 'text/plain; charset=utf-8', 'invalid url')
      }
      return
    }

    const identity = fixtureIdentityPlan(testCase.number)
    const authorization = request.headers.authorization
    const role = authorization === `Bearer ${identity.ownerToken}`
      ? 'owner'
      : authorization === `Bearer ${identity.memberToken}`
        ? 'member'
        : undefined
    if (!role) {
      send(response, 401, 'application/json; charset=utf-8', '{"error":"unauthorized"}')
      return
    }
    const resourceId = url.searchParams.get('id') ?? ''
    const ownResource = role === 'owner' ? identity.ownerResourceId : identity.memberResourceId
    if (testCase.polarity === 'negative' && resourceId !== ownResource) {
      send(response, 403, 'application/json; charset=utf-8', '{"error":"forbidden"}')
      return
    }
    send(
      response,
      200,
      'application/json; charset=utf-8',
      JSON.stringify({ id: resourceId, value: `test-only-${resourceId}` })
    )
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      resolve()
    })
  })
  const address = server.address() as AddressInfo
  baseUrl = `http://127.0.0.1:${address.port}`

  return {
    version: LOCAL_FIXTURE_VERSION,
    baseUrl,
    bindAddress: '127.0.0.1',
    port: address.port,
    attestationHash: localFixtureAttestationHash(),
    get namespaceHash() {
      return fixtureNamespaceHash(namespace)
    },
    get outboundAttempts() {
      return Object.freeze([...outboundAttempts])
    },
    reset: () => {
      namespace = emptyNamespace(namespace.generation + 1)
      outboundAttempts.length = 0
      l2Objects.clear()
      sessionId = token()
      csrfToken = token()
      return {
        generation: namespace.generation,
        namespaceHash: fixtureNamespaceHash(namespace)
      }
    },
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()))
    })
  }
}
