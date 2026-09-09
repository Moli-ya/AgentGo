import { HOLDOUT_FIXTURE_ID, HOLDOUT_FIXTURE_VERSION } from '@agentgo/contracts'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  holdoutIdentityPlan,
  holdoutPackHash,
  holdoutPackManifest,
  startLocalHoldoutFixture,
  type LocalHoldoutFixture
} from './holdout-fixture'
import {
  createHoldoutBenchmarkSuites,
  listHoldoutRunnerCases,
  SELF_BUILT_HOLDOUT_SUITE_ID
} from './holdout-suites'

let fixture: LocalHoldoutFixture

beforeAll(async () => {
  fixture = await startLocalHoldoutFixture()
})

afterAll(async () => {
  await fixture.close()
})

describe('sealed local holdout fixture', () => {
  it('is version-pinned, resettable, and separate from the 40-case fixture', async () => {
    expect(fixture.version).toBe(HOLDOUT_FIXTURE_VERSION)
    expect(fixture.bindAddress).toBe('127.0.0.1')
    expect(fixture.packHash).toBe(holdoutPackHash())
    expect(holdoutPackManifest().coverageClass).toBe('self-built-fixture')
    const health = await fetch(new URL('/holdout/v1/health', fixture.baseUrl)).then((item) =>
      item.json()
    )
    expect(health).toMatchObject({
      ok: true,
      version: HOLDOUT_FIXTURE_VERSION
    })
    const reset = await fetch(new URL('/holdout/v1/reset', fixture.baseUrl)).then((item) =>
      item.json()
    )
    expect(reset.generation).toBeGreaterThan(0)
    expect(new URL(fixture.baseUrl).pathname).toBe('/')
  })

  it('implements holdout ground-truth polarity without using /cases or /research', async () => {
    const identity = holdoutIdentityPlan()
    const marker = '<svg data-agentgo-marker="holdout"></svg>'
    const catalogTrue = await fetch(
      new URL('/holdout/v1/catalog?id=1%20AND%201=1', fixture.baseUrl)
    ).then((item) => item.text())
    const catalogFalse = await fetch(
      new URL('/holdout/v1/catalog?id=1%20AND%201=2', fixture.baseUrl)
    ).then((item) => item.text())
    const catalogSafeFalse = await fetch(
      new URL('/holdout/v1/catalog-safe?id=1%20AND%201=2', fixture.baseUrl)
    ).then((item) => item.text())
    expect(catalogTrue).not.toBe(catalogFalse)
    expect(catalogSafeFalse).toContain('catalog: visible')

    const xssPositive = await fetch(
      new URL(`/holdout/v1/search?q=${encodeURIComponent(marker)}`, fixture.baseUrl)
    ).then((item) => item.text())
    const xssNegative = await fetch(
      new URL(`/holdout/v1/search-safe?q=${encodeURIComponent(marker)}`, fixture.baseUrl)
    ).then((item) => item.text())
    expect(xssPositive).toContain(marker)
    expect(xssNegative).not.toContain(marker)

    const callback = new URL('/holdout/v1/callback?agentgo_token=holdoutproof', fixture.baseUrl)
    const proxy = new URL('/holdout/v1/proxy', fixture.baseUrl)
    proxy.searchParams.set('url', callback.toString())
    const proxyBody = await fetch(proxy).then((item) => item.text())
    expect(proxyBody).toContain('AGENTGO_CALLBACK_PROOF_holdoutproof')
    const proxySafe = await fetch(
      new URL(`/holdout/v1/proxy-safe?url=${encodeURIComponent(callback.toString())}`, fixture.baseUrl)
    ).then((item) => item.text())
    expect(proxySafe).toBe('remote fetch disabled')

    const ownerCross = await fetch(
      new URL(`/holdout/v1/accounts?account_id=${identity.ownerResourceId}`, fixture.baseUrl),
      { headers: { authorization: `Bearer ${identity.memberToken}` } }
    ).then((item) => item.json())
    expect(ownerCross).toMatchObject({ id: identity.ownerResourceId })
    const denied = await fetch(
      new URL(`/holdout/v1/accounts-safe?account_id=${identity.ownerResourceId}`, fixture.baseUrl),
      { headers: { authorization: `Bearer ${identity.memberToken}` } }
    )
    expect(denied.status).toBe(403)
  })

  it('registers a sealed holdout suite that is not the 40-case fixture', () => {
    const suites = createHoldoutBenchmarkSuites()
    const cases = listHoldoutRunnerCases()
    expect(
      suites.every((suite) => suite.suiteId === SELF_BUILT_HOLDOUT_SUITE_ID)
    ).toBe(true)
    expect(JSON.stringify(suites)).not.toContain('external-local-holdout')
    expect(cases.every((item) => item.endpoint.startsWith('/holdout/v1/'))).toBe(true)
    expect(cases.some((item) => item.category === 'policy-denied')).toBe(true)
    expect(HOLDOUT_FIXTURE_ID).not.toBe('agentgo-local-fixture')
  })
})
