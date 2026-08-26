import { readFileSync } from 'node:fs'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { GroundTruthManifestSchema } from './index'
import {
  LOCAL_FIXTURE_VERSION,
  fixtureIdentityPlan,
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

  it('resets only the fixture namespace and keeps attestation stable', () => {
    const first = fixture.reset()
    const second = fixture.reset()
    expect(first.namespaceHash).toBe(second.namespaceHash)
    expect(second.generation).toBe(first.generation + 1)
    expect(fixture.attestationHash).toMatch(/^[a-f0-9]{64}$/)
    expect(fixture.bindAddress).toBe('127.0.0.1')
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
})
