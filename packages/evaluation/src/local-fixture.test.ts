import { readFileSync } from 'node:fs'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { GroundTruthManifestSchema } from './index'
import {
  LOCAL_FIXTURE_VERSION,
  fixtureIdentityPlan,
  localFixtureAttestationProfile,
  startLocalBenchmarkFixture,
  type LocalBenchmarkFixture
} from './local-fixture'

const manifest = GroundTruthManifestSchema.parse(
  JSON.parse(
    readFileSync(new URL('../../../benchmarks/v1-ground-truth.json', import.meta.url), 'utf8')
  )
)

let fixture: LocalBenchmarkFixture

beforeAll(async () => {
  fixture = await startLocalBenchmarkFixture()
})

afterAll(async () => {
  await fixture.close()
})

describe('AgentGo fixed local benchmark fixture', () => {
  it('implements every checked-in ground-truth endpoint at the fixed version', async () => {
    expect(fixture.version).toBe(LOCAL_FIXTURE_VERSION)
    expect(manifest.targetVersion).toBe(LOCAL_FIXTURE_VERSION)

    for (const item of manifest.cases) {
      const url = new URL(item.endpoint, fixture.baseUrl)
      const caseNumber = Number(item.caseId.slice(-2))
      const identity = fixtureIdentityPlan(caseNumber)
      url.searchParams.set(
        item.parameter ?? 'id',
        item.family === 'xss'
          ? 'hello'
          : item.family === 'idor'
            ? identity.ownerResourceId
            : '1'
      )
      const response = await fetch(url, {
        headers: item.family === 'idor'
          ? { authorization: `Bearer ${identity.ownerToken}` }
          : undefined
      })
      expect(response.status, item.caseId).toBe(200)
      expect(response.headers.get('x-agentgo-fixture-version')).toBe(LOCAL_FIXTURE_VERSION)
      expect(response.headers.get('x-agentgo-fixture-id')).toBe('agentgo-local-fixture')
    }
  })

  it('separates positive and negative behavior for all four V1 families', async () => {
    const callback = new URL('/callback?agentgo_token=fixtureproof01', fixture.baseUrl)

    for (let caseNumber = 1; caseNumber <= 5; caseNumber += 1) {
      const sqliPositive = new URL(`/cases/sqli/positive/${caseNumber}?id=1`, fixture.baseUrl)
      const sqliNegative = new URL(`/cases/sqli/negative/${caseNumber}?id=1`, fixture.baseUrl)
      const positiveTrue = await fetch(`${sqliPositive.toString()}%20AND%201=1`).then((item) => item.text())
      const positiveFalse = await fetch(`${sqliPositive.toString()}%20AND%201=2`).then((item) => item.text())
      const negativeFalse = await fetch(`${sqliNegative.toString()}%20AND%201=2`).then((item) => item.text())
      expect(positiveTrue).not.toBe(positiveFalse)
      expect(negativeFalse).toContain('product: visible')

      const marker = '<svg data-agentgo-marker="test"></svg>'
      const xssPositive = await fetch(
        new URL(`/cases/xss/positive/${caseNumber}?q=${encodeURIComponent(marker)}`, fixture.baseUrl)
      ).then((item) => item.text())
      const xssNegative = await fetch(
        new URL(`/cases/xss/negative/${caseNumber}?q=${encodeURIComponent(marker)}`, fixture.baseUrl)
      ).then((item) => item.text())
      expect(xssPositive).toContain(marker)
      expect(xssNegative).not.toContain(marker)

      const ssrfPositive = new URL(`/cases/ssrf/positive/${caseNumber}`, fixture.baseUrl)
      ssrfPositive.searchParams.set('url', callback.toString())
      const ssrfNegative = new URL(`/cases/ssrf/negative/${caseNumber}`, fixture.baseUrl)
      ssrfNegative.searchParams.set('url', callback.toString())
      expect(await fetch(ssrfPositive).then((item) => item.text())).toContain(
        'AGENTGO_CALLBACK_PROOF_fixtureproof01'
      )
      expect(await fetch(ssrfNegative).then((item) => item.text())).not.toContain(
        'AGENTGO_CALLBACK_PROOF_'
      )

      const identity = fixtureIdentityPlan(caseNumber)
      const idorPositive = new URL(`/cases/idor/positive/${caseNumber}`, fixture.baseUrl)
      idorPositive.searchParams.set('id', identity.ownerResourceId)
      const idorNegative = new URL(`/cases/idor/negative/${caseNumber}`, fixture.baseUrl)
      idorNegative.searchParams.set('id', identity.ownerResourceId)
      const memberHeaders = { authorization: `Bearer ${identity.memberToken}` }
      expect((await fetch(idorPositive, { headers: memberHeaders })).status).toBe(200)
      expect((await fetch(idorNegative, { headers: memberHeaders })).status).toBe(403)
    }
  })

  it('does not treat an open family ID as a legacy fixture route', async () => {
    const response = await fetch(
      new URL('/cases/security.headers/positive/1', fixture.baseUrl)
    )

    expect(response.status).toBe(404)
  })

  it('serves SQLi V2 research selectors without changing the 40-case attestation table', async () => {
    const pathPositive = new URL('/research/sqli/boolean/path/positive/1', fixture.baseUrl)
    const pathTrue = await fetch(`${pathPositive.toString()}%20AND%201=1`).then((item) => item.text())
    const pathFalse = await fetch(`${pathPositive.toString()}%20AND%201=2`).then((item) => item.text())
    expect(pathTrue).not.toBe(pathFalse)

    const rowPositive = new URL('/research/sqli/boolean/query/row-positive?row=1', fixture.baseUrl)
    const rowTrue = await fetch(`${rowPositive.toString()}%20AND%201=1`).then((item) => item.text())
    const rowFalse = await fetch(`${rowPositive.toString()}%20AND%201=2`).then((item) => item.text())
    expect(rowTrue).not.toBe(rowFalse)

    const errorPositive = new URL("/research/sqli/error/query/positive?msg=1'", fixture.baseUrl)
    const errorNegative = new URL('/research/sqli/error/query/negative?msg=1', fixture.baseUrl)
    expect(await fetch(errorPositive).then((item) => item.text())).toMatch(/SQL syntax/i)
    expect(await fetch(errorNegative).then((item) => item.text())).toBe('message stored')
    expect(
      (await fetch(new URL('/research/sqli/error/query/generic-500?msg=1', fixture.baseUrl))).status
    ).toBe(500)
    expect(
      (await fetch(new URL('/research/sqli/error/query/waf?msg=1', fixture.baseUrl))).status
    ).toBe(403)

    const timePositive = new URL(
      '/research/sqli/time/query/positive?wait=1%20AND%20SLEEP(2)',
      fixture.baseUrl
    )
    const started = Date.now()
    expect(await fetch(timePositive).then((item) => item.text())).toBe('ready')
    expect(Date.now() - started).toBeGreaterThanOrEqual(1_500)

    const form = await fetch(new URL('/research/sqli/form/positive', fixture.baseUrl), {
      method: 'POST'
    })
    expect(form.status).toBe(200)

    const jsonPositive = await fetch(new URL('/research/sqli/json/positive', fixture.baseUrl), {
      method: 'POST'
    })
    const jsonNegative = await fetch(new URL('/research/sqli/json/negative', fixture.baseUrl), {
      method: 'POST'
    })
    expect(await jsonPositive.json()).toEqual({ rows: [{ id: 1 }] })
    expect(await jsonNegative.json()).toEqual({ rows: [] })

    const cached = await fetch(
      new URL('/research/sqli/boolean/query/cached-positive?id=1', fixture.baseUrl)
    )
    expect(cached.headers.get('cache-control')).toBe('public, max-age=60')

    const randomA = await fetch(
      new URL('/research/sqli/boolean/query/random-negative?id=1', fixture.baseUrl)
    ).then((item) => item.text())
    const randomB = await fetch(
      new URL('/research/sqli/boolean/query/random-negative?id=1', fixture.baseUrl)
    ).then((item) => item.text())
    expect(randomA).not.toBe(randomB)
    expect(randomA).toContain('product: visible')
  })

  it('serves IDOR/BOLA and XSS V2 research selectors outside the 40-case attestation table', async () => {
    const identity = fixtureIdentityPlan(1)
    const ownerHeaders = { authorization: `Bearer ${identity.ownerToken}` }
    const memberHeaders = { authorization: `Bearer ${identity.memberToken}` }

    const pathPositive = new URL(
      `/research/idor/bola/path/positive/${identity.ownerResourceId}`,
      fixture.baseUrl
    )
    const pathBody = await fetch(pathPositive, { headers: memberHeaders }).then((item) =>
      item.json()
    )
    expect(pathBody).toMatchObject({
      id: identity.ownerResourceId,
      ownerId: 'owner'
    })

    const queryPositive = new URL('/research/idor/bola/query/positive', fixture.baseUrl)
    queryPositive.searchParams.set('item_id', identity.ownerResourceId)
    expect((await fetch(queryPositive, { headers: memberHeaders })).status).toBe(200)

    const tenant = new URL('/research/idor/bola/cross-tenant/positive', fixture.baseUrl)
    tenant.searchParams.set('item_id', identity.ownerResourceId)
    expect(await fetch(tenant, { headers: memberHeaders }).then((item) => item.json())).toMatchObject(
      { tenantId: 'tenant-a' }
    )

    const parent = new URL(
      `/research/idor/bola/parent/positive/${identity.ownerResourceId}`,
      fixture.baseUrl
    )
    expect(await fetch(parent, { headers: memberHeaders }).then((item) => item.json())).toMatchObject(
      { parentId: 'parent-1' }
    )

    expect(
      (
        await fetch(new URL('/research/idor/bola/public/negative', fixture.baseUrl), {
          headers: memberHeaders
        })
      ).status
    ).toBe(200)
    expect(
      (
        await fetch(new URL('/research/idor/bola/shared/negative', fixture.baseUrl), {
          headers: memberHeaders
        })
      ).status
    ).toBe(200)
    expect(
      (
        await fetch(new URL('/research/idor/bola/admin/negative', fixture.baseUrl), {
          headers: memberHeaders
        })
      ).status
    ).toBe(403)
    const queryNegative = new URL('/research/idor/bola/query/negative', fixture.baseUrl)
    queryNegative.searchParams.set('item_id', identity.ownerResourceId)
    expect((await fetch(queryNegative, { headers: memberHeaders })).status).toBe(403)
    expect(
      (await fetch(new URL('/research/idor/bola/session-expired', fixture.baseUrl))).status
    ).toBe(401)
    expect(
      (await fetch(new URL('/research/idor/bola/dynamic', fixture.baseUrl), { headers: ownerHeaders }))
        .status
    ).toBe(200)

    const marker = 'agx_0123456789abcdef0123456789abcdef'
    const htmlPositive = await fetch(
      new URL(`/research/xss/html/positive?q=${encodeURIComponent(`<svg data-agentgo-marker="${marker}"></svg>`)}`, fixture.baseUrl)
    ).then((item) => item.text())
    const htmlNegative = await fetch(
      new URL(`/research/xss/html/negative?q=${encodeURIComponent(`<svg data-agentgo-marker="${marker}"></svg>`)}`, fixture.baseUrl)
    ).then((item) => item.text())
    expect(htmlPositive).toContain(`data-agentgo-marker="${marker}"`)
    expect(htmlNegative).not.toContain(`<svg data-agentgo-marker="${marker}"`)

    const attributePositive = await fetch(
      new URL(`/research/xss/attribute/positive?q=${encodeURIComponent(marker)}`, fixture.baseUrl)
    ).then((item) => item.text())
    expect(attributePositive).toContain(`value="${marker}"`)
    const jsonNegative = await fetch(
      new URL(`/research/xss/json/negative?q=${encodeURIComponent(marker)}`, fixture.baseUrl)
    ).then((item) => item.json())
    expect(jsonNegative).toEqual({ message: marker })
    expect(
      (
        await fetch(
          new URL(`/research/xss/sanitizer/negative?q=${encodeURIComponent('<svg></svg>')}`, fixture.baseUrl)
        )
      ).status
    ).toBe(200)
    expect(
      (
        await fetch(new URL('/research/xss/csp/inconclusive?q=1', fixture.baseUrl))
      ).headers.get('content-security-policy')
    ).toBe("default-src 'none'")
    expect(
      (await fetch(new URL('/research/xss/nonce/inconclusive?q=1', fixture.baseUrl))).status
    ).toBe(200)
    expect(
      (await fetch(new URL('/research/xss/dom/positive', fixture.baseUrl))).status
    ).toBe(200)
    expect(
      (
        await fetch(new URL('/research/xss/stored/positive', fixture.baseUrl), { method: 'POST' })
      ).status
    ).toBe(200)
  })

  it('resets only the fixture namespace and keeps attestation stable', () => {
    const first = fixture.reset()
    const second = fixture.reset()
    expect(first.namespaceHash).toBe(second.namespaceHash)
    expect(second.generation).toBe(first.generation + 1)
    expect(fixture.attestationHash).toMatch(/^[a-f0-9]{64}$/)
    expect(fixture.bindAddress).toBe('127.0.0.1')
  })

  it('covers SSRF V2 research routes without entering the 40-case attestation table', async () => {
    const callback = new URL('/callback?agentgo_token=researchproof01', fixture.baseUrl)
    const reflected = new URL('/research/ssrf/reflected/positive', fixture.baseUrl)
    reflected.searchParams.set('target', callback.toString())
    expect(await fetch(reflected).then((item) => item.text())).toContain(
      'AGENTGO_CALLBACK_PROOF_researchproof01'
    )
    expect(
      await fetch(new URL('/research/ssrf/allow-list/negative', fixture.baseUrl)).then((item) =>
        item.text()
      )
    ).toBe('allow-list proxy ok')
    expect(
      await fetch(new URL('/research/ssrf/client-fetch/negative?callback=http://127.0.0.1/', fixture.baseUrl)).then(
        (item) => item.text()
      )
    ).toContain('<img')
    expect(
      (await fetch(new URL('/research/ssrf/old-token/negative', fixture.baseUrl))).status
    ).toBe(200)
    expect(
      (await fetch(new URL('/research/ssrf/redirect-out/inconclusive', fixture.baseUrl), {
        redirect: 'manual'
      })).status
    ).toBe(302)
    expect(
      (await fetch(new URL('/research/ssrf/collector-down/inconclusive', fixture.baseUrl))).status
    ).toBe(504)
    expect(
      (await fetch(new URL('/research/ssrf/dynamic/inconclusive', fixture.baseUrl))).status
    ).toBe(200)
    expect(
      (await fetch(new URL('/research/headers/missing', fixture.baseUrl))).headers.get(
        'strict-transport-security'
      )
    ).toBeNull()
    expect(
      (await fetch(new URL('/research/headers/complete', fixture.baseUrl))).headers.get(
        'x-content-type-options'
      )
    ).toBe('nosniff')
    const image = new URL('/research/ssrf/reflected/image-positive', fixture.baseUrl)
    image.searchParams.set('image', callback.toString())
    expect(await fetch(image).then((item) => item.text())).toContain(
      'AGENTGO_CALLBACK_PROOF_researchproof01'
    )
    const webhook = new URL('/research/ssrf/oob/webhook-positive', fixture.baseUrl)
    webhook.searchParams.set('webhook', callback.toString())
    expect((await fetch(webhook)).status).toBe(200)
    expect(
      await fetch(
        new URL('/research/ssrf/file-scheme/negative?url=file:///etc/passwd', fixture.baseUrl)
      ).then((item) => item.text())
    ).toBe('non-http scheme rejected')
    const metadataBefore = fixture.outboundAttempts.length
    expect(
      await fetch(
        new URL(
          '/research/ssrf/metadata/negative?url=http://169.254.169.254/',
          fixture.baseUrl
        )
      ).then((item) => item.text())
    ).toBe('metadata destination rejected')
    expect(fixture.outboundAttempts.slice(metadataBefore)).toEqual([])
    expect(
      (await fetch(new URL('/research/headers/proxy-rewritten', fixture.baseUrl))).headers.get(
        'via'
      )
    ).toBe('1.1 proxy.example')
  })

  it('rejects non-loopback SSRF targets without making an outbound fetch', async () => {
    const before = fixture.outboundAttempts.length
    const target = new URL(`/cases/ssrf/positive/1`, fixture.baseUrl)
    target.searchParams.set('url', 'http://example.test/callback')
    expect(await fetch(target).then((item) => item.text())).toBe('target rejected')
    expect(fixture.outboundAttempts.slice(before)).toEqual([
      'http://example.test/callback'
    ])
  })

  it('binds only loopback ephemeral ports', async () => {
    const second = await startLocalBenchmarkFixture()
    try {
      expect(second.port).not.toBe(fixture.port)
      expect(new URL(second.baseUrl).hostname).toBe('127.0.0.1')
      expect(second.attestationHash).toBe(fixture.attestationHash)
    } finally {
      await second.close()
    }
  })

  it('keeps the Day 7 attestation profile on GET-only legacy routes', () => {
    const profile = localFixtureAttestationProfile()
    expect(profile.methods).toEqual(['GET'])
    expect(profile.routes.every((route) => route.startsWith('/cases/'))).toBe(true)
    expect(profile.routes.some((route) => route.startsWith('/l2/'))).toBe(false)
    expect(profile.fixtureVersion).toBe(LOCAL_FIXTURE_VERSION)
  })

  it('issues an L2 session cookie and CSRF token, then accepts JSON reset', async () => {
    const session = await fetch(new URL('/l2/session', fixture.baseUrl))
    expect(session.status).toBe(200)
    const setCookie = session.headers.get('set-cookie') ?? ''
    expect(setCookie).toMatch(/sid=/)
    expect(setCookie).toMatch(/HttpOnly/i)
    const sessionBody = (await session.json()) as { csrfToken: string }
    expect(sessionBody.csrfToken).toMatch(/^[a-f0-9]+$/)
    const cookie = setCookie.split(';')[0] ?? ''
    const objectUrl = new URL('/l2/objects/fixture-obj-1', fixture.baseUrl)
    const pre = await fetch(objectUrl, { headers: { cookie } })
    expect(pre.status).toBe(200)
    expect(await pre.json()).toMatchObject({ id: 'fixture-obj-1', status: 'draft' })
    const submitted = await fetch(objectUrl, {
      method: 'POST',
      headers: {
        cookie,
        'content-type': 'application/json',
        'x-csrf-token': sessionBody.csrfToken
      },
      body: JSON.stringify({ status: 'submitted' })
    })
    expect(submitted.status).toBe(200)
    expect(await submitted.json()).toMatchObject({ status: 'submitted' })
    const reset = await fetch(objectUrl, {
      method: 'POST',
      headers: {
        cookie,
        'content-type': 'application/json',
        'x-csrf-token': sessionBody.csrfToken
      },
      body: JSON.stringify({ action: 'reset' })
    })
    expect(reset.status).toBe(200)
    expect(await reset.json()).toMatchObject({ status: 'draft' })
    const denied = await fetch(objectUrl, {
      method: 'DELETE',
      headers: { cookie, 'x-csrf-token': sessionBody.csrfToken }
    })
    expect(denied.status).toBe(405)
    const legacyPost = await fetch(new URL('/cases/sqli/positive/1?id=1', fixture.baseUrl), {
      method: 'POST'
    })
    expect(legacyPost.status).toBe(405)
  })
})
