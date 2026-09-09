import { describe, expect, it } from 'vitest'
import {
  LoopbackCallbackCollector,
  ensureAttestedFixtureCallbackListen,
  isLoopbackCallbackCollector,
  issueLoopbackCallbackToken,
  listenLoopbackCallbackCollector,
  loopbackCollectorScopeAuthorization
} from './loopback-callback-collector'

describe('LoopbackCallbackCollector', () => {
  it('accepts one server-side event and rejects replay, browser, and expired tokens', async () => {
    let now = Date.parse('2026-09-06T00:00:00.000Z')
    const collector = new LoopbackCallbackCollector({
      now: () => now,
      ttlMs: 1_000
    })
    const token = issueLoopbackCallbackToken()
    const { collectorId } = await collector.register(token)
    expect(collector.tokenFor(collectorId)).toBe(token)
    await expect(collector.register(token)).rejects.toThrow(/unique/i)

    expect(
      collector.recordInbound({
        token,
        sourceKind: 'browser',
        sourceMetadata: { via: 'broker' }
      })
    ).toBe(true)
    expect((await collector.poll(collectorId, 10)).received).toBe(false)

    const other = issueLoopbackCallbackToken()
    const otherReg = await collector.register(other)
    expect(
      collector.recordInbound({
        token: other,
        sourceKind: 'server',
        sourceMetadata: { via: 'target' }
      })
    ).toBe(true)
    expect((await collector.poll(otherReg.collectorId, 10)).received).toBe(true)

    const fresh = issueLoopbackCallbackToken()
    const registered = await collector.register(fresh)
    expect(
      collector.recordInbound({
        token: fresh,
        sourceKind: 'server',
        sourceMetadata: { via: 'target' }
      })
    ).toBe(true)
    expect(
      collector.recordInbound({
        token: fresh,
        sourceKind: 'server',
        sourceMetadata: { via: 'target' }
      })
    ).toBe(false)
    const consumed = await collector.consume(registered.collectorId)
    expect(consumed.observation).toMatch(/^[a-f0-9]{64}$/u)
    expect((await collector.poll(registered.collectorId, 10)).received).toBe(false)

    const late = issueLoopbackCallbackToken()
    const expired = await collector.register(late)
    now += 2_000
    expect(
      collector.recordInbound({
        token: late,
        sourceKind: 'server',
        sourceMetadata: { via: 'target' }
      })
    ).toBe(false)
    expect((await collector.poll(expired.collectorId, 10)).received).toBe(false)
  })

  it('isolates concurrent tokens, scan bindings, and the expiry clock boundary', async () => {
    let now = Date.parse('2026-09-06T00:00:00.000Z')
    const collector = new LoopbackCallbackCollector({
      now: () => now,
      ttlMs: 1_000
    })
    const first = issueLoopbackCallbackToken()
    const second = issueLoopbackCallbackToken()
    const [left, right] = await Promise.all([
      collector.register(first),
      collector.register(second)
    ])
    expect(left.collectorId).not.toBe(right.collectorId)
    collector.bind({
      collectorId: left.collectorId,
      scanId: 'scan-a',
      tenantId: 'tenant-a'
    })
    collector.bind({
      collectorId: right.collectorId,
      scanId: 'scan-b',
      tenantId: 'tenant-b'
    })
    expect(
      collector.recordInbound({
        token: first,
        sourceKind: 'server',
        sourceMetadata: { via: 'target', scanId: 'scan-b', tenantId: 'tenant-b' }
      })
    ).toBe(false)
    expect(
      collector.recordInbound({
        token: first,
        sourceKind: 'server',
        sourceMetadata: { via: 'target', scanId: 'scan-a', tenantId: 'tenant-a' }
      })
    ).toBe(true)
    expect((await collector.poll(right.collectorId, 10)).received).toBe(false)
    expect((await collector.poll(left.collectorId, 10)).received).toBe(true)

    const boundary = issueLoopbackCallbackToken()
    const expired = await collector.register(boundary)
    now += 1_000
    expect(
      collector.recordInbound({
        token: boundary,
        sourceKind: 'server',
        sourceMetadata: { via: 'target' }
      })
    ).toBe(false)
    expect((await collector.poll(expired.collectorId, 10)).staleOrReplay).toBe(true)
  })

  it('starts a listen URL for attested-fixture collectors without relying on instanceof', async () => {
    const collector = new LoopbackCallbackCollector()
    const alien = {
      register: collector.register.bind(collector),
      poll: collector.poll.bind(collector),
      consume: collector.consume.bind(collector),
      bind: collector.bind.bind(collector),
      recordInbound: collector.recordInbound.bind(collector),
      tokenFor: collector.tokenFor.bind(collector),
      collectorIdForToken: collector.collectorIdForToken.bind(collector)
    }
    expect(alien instanceof LoopbackCallbackCollector).toBe(false)
    expect(isLoopbackCallbackCollector(alien)).toBe(true)
    expect(
      await ensureAttestedFixtureCallbackListen({
        environment: 'authorized-real-target',
        collector
      })
    ).toBeUndefined()
    const server = await ensureAttestedFixtureCallbackListen({
      environment: 'attested-fixture',
      collector: alien
    })
    expect(server?.baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/u)
    expect(loopbackCollectorScopeAuthorization(server!.baseUrl)).toEqual({
      origin: server!.baseUrl,
      port: Number(new URL(server!.baseUrl).port)
    })
    await server?.close()
  })

  it('records only server-side loopback HTTP hits for a registered token', async () => {
    const collector = new LoopbackCallbackCollector()
    const token = issueLoopbackCallbackToken()
    const { collectorId } = await collector.register(token)
    const server = await listenLoopbackCallbackCollector(collector)
    try {
      const missed = await fetch(`${server.baseUrl}/callback?agentgo_token=oob.00`)
      expect(missed.status).toBe(404)
      const hit = await fetch(
        `${server.baseUrl}/callback?agentgo_token=${encodeURIComponent(token)}`
      )
      expect(hit.status).toBe(204)
      expect((await collector.poll(collectorId, 10)).received).toBe(true)
    } finally {
      await server.close()
    }
  })
})
