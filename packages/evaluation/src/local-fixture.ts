import { createServer, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  LEGACY_V1_FAMILY_IDS,
  isLegacyV1VulnerabilityFamily,
  type LegacyV1VulnerabilityFamily
} from '@agentgo/contracts'

export const LOCAL_FIXTURE_VERSION = 'agentgo-local-fixture/1.0.0'

export interface LocalBenchmarkFixture {
  version: typeof LOCAL_FIXTURE_VERSION
  baseUrl: string
  close(): Promise<void>
}

export interface FixtureIdentityPlan {
  ownerToken: string
  memberToken: string
  ownerResourceId: string
  memberResourceId: string
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
    'x-agentgo-fixture-version': LOCAL_FIXTURE_VERSION
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

export async function startLocalBenchmarkFixture(): Promise<LocalBenchmarkFixture> {
  let baseUrl = ''
  const server = createServer(async (request, response) => {
    if (request.method !== 'GET') {
      send(response, 405, 'application/json; charset=utf-8', '{"error":"method-not-allowed"}')
      return
    }

    const url = new URL(request.url ?? '/', baseUrl || 'http://127.0.0.1')
    if (url.pathname === '/') {
      send(response, 200, 'text/html; charset=utf-8', fixtureIndex(baseUrl))
      return
    }
    if (url.pathname === '/health') {
      send(
        response,
        200,
        'application/json; charset=utf-8',
        JSON.stringify({ ok: true, version: LOCAL_FIXTURE_VERSION })
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
        if (target.origin !== new URL(baseUrl).origin || target.pathname !== '/callback') {
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
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()))
    })
  }
}
