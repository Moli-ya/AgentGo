import { createServer, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  HOLDOUT_FIXTURE_ID,
  HOLDOUT_FIXTURE_VERSION,
  LEGACY_V1_FAMILY_IDS
} from '@agentgo/contracts'
import { canonicalJson, sha256Text } from '@agentgo/domain'

export { HOLDOUT_FIXTURE_ID, HOLDOUT_FIXTURE_VERSION }

export interface HoldoutIdentityPlan {
  readonly ownerToken: string
  readonly memberToken: string
  readonly ownerResourceId: string
  readonly memberResourceId: string
}

export interface LocalHoldoutFixture {
  readonly version: typeof HOLDOUT_FIXTURE_VERSION
  readonly baseUrl: string
  readonly bindAddress: '127.0.0.1'
  readonly port: number
  readonly attestationHash: string
  readonly packHash: string
  reset(): { generation: number }
  close(): Promise<void>
}

const HOLDOUT_ROUTES = Object.freeze([
  '/holdout/v1/catalog',
  '/holdout/v1/catalog-safe',
  '/holdout/v1/search',
  '/holdout/v1/search-safe',
  '/holdout/v1/proxy',
  '/holdout/v1/proxy-safe',
  '/holdout/v1/accounts',
  '/holdout/v1/accounts-safe',
  '/holdout/v1/unstable',
  '/holdout/v1/callback'
])

export function holdoutIdentityPlan(): HoldoutIdentityPlan {
  return {
    ownerToken: 'holdout-owner-1',
    memberToken: 'holdout-member-1',
    ownerResourceId: 'holdout-account-a',
    memberResourceId: 'holdout-account-b'
  }
}

export function holdoutAttestationProfile() {
  return Object.freeze({
    fixtureId: HOLDOUT_FIXTURE_ID,
    fixtureVersion: HOLDOUT_FIXTURE_VERSION,
    bindAddress: '127.0.0.1' as const,
    portPolicy: 'ephemeral' as const,
    outboundPolicy: 'loopback-same-origin-callback-only' as const,
    resetPolicy: 'fixture-namespace-only' as const,
    methods: Object.freeze(['GET'] as const),
    selector: 'query' as const,
    families: [...LEGACY_V1_FAMILY_IDS],
    routes: [...HOLDOUT_ROUTES]
  })
}

export function holdoutAttestationHash(): string {
  return sha256Text(canonicalJson(holdoutAttestationProfile()))
}

export function holdoutPackManifest() {
  return Object.freeze({
    packId: HOLDOUT_FIXTURE_ID,
    packVersion: HOLDOUT_FIXTURE_VERSION,
    source: 'project-authored-sealed-local-holdout',
    license: 'project-internal-test-data',
    coverageClass: 'self-built-fixture',
    note:
      'Sealed local holdout pack. Not a third-party product. Do not use scores to claim real-world accuracy.'
  })
}

export function holdoutPackHash(): string {
  return sha256Text(canonicalJson(holdoutPackManifest()))
}

function send(
  response: ServerResponse,
  status: number,
  contentType: string,
  body: string
): void {
  response.writeHead(status, {
    'content-type': contentType,
    'x-agentgo-fixture-version': HOLDOUT_FIXTURE_VERSION,
    'x-agentgo-fixture-id': HOLDOUT_FIXTURE_ID
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

function booleanBody(positive: boolean, value: string): string {
  const isFalseCondition = /AND\s+(?:1\s*=\s*2|'1'\s*=\s*'2')/i.test(value)
  return positive && isFalseCondition
    ? '<html><body>no rows</body></html>'
    : '<html><body>catalog: visible</body></html>'
}

function isHoldoutLoopbackUrl(target: URL, origin: string): boolean {
  return target.origin === origin && target.hostname === '127.0.0.1'
}

export async function startLocalHoldoutFixture(): Promise<LocalHoldoutFixture> {
  let baseUrl = ''
  let generation = 0
  const outboundAttempts: string[] = []
  const identity = holdoutIdentityPlan()
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', baseUrl || 'http://127.0.0.1')
    if (request.method !== 'GET') {
      send(response, 405, 'text/plain; charset=utf-8', 'method not allowed')
      return
    }

    if (url.pathname === '/holdout/v1/health') {
      send(
        response,
        200,
        'application/json; charset=utf-8',
        JSON.stringify({
          ok: true,
          version: HOLDOUT_FIXTURE_VERSION,
          attestationHash: holdoutAttestationHash(),
          packHash: holdoutPackHash(),
          generation
        })
      )
      return
    }
    if (url.pathname === '/holdout/v1/reset') {
      generation += 1
      outboundAttempts.length = 0
      send(
        response,
        200,
        'application/json; charset=utf-8',
        JSON.stringify({ ok: true, generation })
      )
      return
    }
    if (url.pathname === '/holdout/v1/callback') {
      const token = url.searchParams.get('agentgo_token') ?? 'missing'
      send(response, 200, 'text/plain; charset=utf-8', `AGENTGO_CALLBACK_PROOF_${token}`)
      return
    }
    if (url.pathname === '/holdout/v1/catalog') {
      send(
        response,
        200,
        'text/html; charset=utf-8',
        booleanBody(true, url.searchParams.get('id') ?? '')
      )
      return
    }
    if (url.pathname === '/holdout/v1/catalog-safe') {
      send(
        response,
        200,
        'text/html; charset=utf-8',
        booleanBody(false, url.searchParams.get('id') ?? '')
      )
      return
    }
    if (url.pathname === '/holdout/v1/search') {
      const value = url.searchParams.get('q') ?? ''
      send(
        response,
        200,
        'text/html; charset=utf-8',
        `<html><body>Search: ${value}</body></html>`
      )
      return
    }
    if (url.pathname === '/holdout/v1/search-safe') {
      const value = url.searchParams.get('q') ?? ''
      send(
        response,
        200,
        'text/html; charset=utf-8',
        `<html><body>Search: ${escapeHtml(value)}</body></html>`
      )
      return
    }
    if (url.pathname === '/holdout/v1/proxy') {
      const targetValue = url.searchParams.get('url') ?? ''
      try {
        const target = new URL(targetValue)
        outboundAttempts.push(target.href)
        if (
          !isHoldoutLoopbackUrl(target, new URL(baseUrl).origin) ||
          target.pathname !== '/holdout/v1/callback'
        ) {
          send(response, 200, 'text/plain; charset=utf-8', 'target rejected')
          return
        }
        const fetched = await fetch(target)
        send(response, 200, 'text/plain; charset=utf-8', await fetched.text())
      } catch {
        send(response, 200, 'text/plain; charset=utf-8', 'invalid url')
      }
      return
    }
    if (url.pathname === '/holdout/v1/proxy-safe') {
      send(response, 200, 'text/plain; charset=utf-8', 'remote fetch disabled')
      return
    }
    if (url.pathname === '/holdout/v1/unstable') {
      send(
        response,
        200,
        'text/html; charset=utf-8',
        `<html><body>catalog: visible <span>${generation}-${Date.now()}</span></body></html>`
      )
      return
    }
    if (
      url.pathname === '/holdout/v1/accounts' ||
      url.pathname === '/holdout/v1/accounts-safe'
    ) {
      const authorization = request.headers.authorization
      const role =
        authorization === `Bearer ${identity.ownerToken}`
          ? 'owner'
          : authorization === `Bearer ${identity.memberToken}`
            ? 'member'
            : undefined
      if (!role) {
        send(response, 401, 'application/json; charset=utf-8', '{"error":"unauthorized"}')
        return
      }
      const resourceId = url.searchParams.get('account_id') ?? ''
      const ownResource =
        role === 'owner' ? identity.ownerResourceId : identity.memberResourceId
      const denyCross = url.pathname === '/holdout/v1/accounts-safe'
      if (denyCross && resourceId !== ownResource) {
        send(response, 403, 'application/json; charset=utf-8', '{"error":"forbidden"}')
        return
      }
      send(
        response,
        200,
        'application/json; charset=utf-8',
        JSON.stringify({ id: resourceId, value: `holdout-only-${resourceId}` })
      )
      return
    }

    send(response, 404, 'application/json; charset=utf-8', '{"error":"not-found"}')
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
    version: HOLDOUT_FIXTURE_VERSION,
    baseUrl,
    bindAddress: '127.0.0.1',
    port: address.port,
    attestationHash: holdoutAttestationHash(),
    packHash: holdoutPackHash(),
    reset: () => {
      generation += 1
      outboundAttempts.length = 0
      return { generation }
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
      })
  }
}
