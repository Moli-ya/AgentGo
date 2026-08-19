import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  PlaywrightBrowserRunner,
  buildInertXssMarkerPayload,
  findSystemBrowserExecutable
} from './index'

describe('browser runner safety helpers', () => {
  it('only builds inert AgentGo marker payloads from constrained random markers', () => {
    const marker = `agx_${randomBytes(12).toString('hex')}`
    const payload = buildInertXssMarkerPayload(marker)
    expect(payload).toContain('data-agentgo-marker')
    expect(payload).toContain(marker)
    expect(payload).not.toMatch(/fetch|xmlhttprequest|cookie/i)
    expect(() => buildInertXssMarkerPayload('not-safe')).toThrow('marker')
  })

  it('fails closed when no browser executable is configured', async () => {
    const runner = new PlaywrightBrowserRunner({ executablePath: '' })
    const result = await runner.execute({
      requestId: 'browser-unavailable',
      baseUrl: 'https://lab.example.test/',
      html: '<h1>Lab</h1>',
      action: 'inspect-dom',
      timeoutMs: 2_000
    })

    expect(result.status).toBe('failed')
    expect(result.errorCode).toBe('browser-unavailable')
    expect(result.networkRequestsBlocked).toBe(0)
  })
})

const executablePath = findSystemBrowserExecutable()
const browserIt = executablePath ? it : it.skip

describe('PlaywrightBrowserRunner isolated rendering', () => {
  browserIt('enforces the overall timeout during offline rendering', async () => {
    const runner = new PlaywrightBrowserRunner({ executablePath })
    const result = await runner.execute({
      requestId: 'browser-timeout',
      baseUrl: 'https://lab.example.test/',
      html: '<h1>Lab</h1>',
      action: 'inspect-dom',
      timeoutMs: 1
    })

    expect(result.status).toBe('failed')
    expect(result.errorCode).toBe('timeout')
    expect(result.durationMs).toBeLessThan(1_000)
  }, 10_000)

  browserIt('cancels an in-flight offline rendering request', async () => {
    const runner = new PlaywrightBrowserRunner({ executablePath })
    const execution = runner.execute({
      requestId: 'browser-cancelled',
      baseUrl: 'https://lab.example.test/',
      html: '<h1>Lab</h1>',
      action: 'inspect-dom',
      timeoutMs: 20_000
    })

    await runner.cancel('browser-cancelled')
    const result = await execution

    expect(result.status).toBe('cancelled')
    expect(result.errorCode).toBe('cancelled')
  }, 10_000)

  browserIt('detects marker execution, inventories forms and blocks all network requests', async () => {
    const marker = `agx_${randomBytes(12).toString('hex')}`
    const payload = buildInertXssMarkerPayload(marker)
    const runner = new PlaywrightBrowserRunner({ executablePath })
    const result = await runner.execute({
      requestId: 'browser-xss',
      baseUrl: 'https://lab.example.test/search?q=marker',
      html: `<html><head><title>Search</title></head><body>
        <input value="${payload}">
        <a href="/next">Next</a>
        <form action="/search" method="get"><input name="q" required></form>
        <img src="https://network.invalid/blocked.png">
      </body></html>`,
      action: 'verify-xss',
      marker,
      timeoutMs: 20_000
    })

    expect(result.status).toBe('succeeded')
    expect(result.markerExecuted).toBe(true)
    expect(result.forms[0]).toMatchObject({ method: 'GET' })
    expect(result.links).toContain('https://lab.example.test/next')
    expect(result.networkRequestsBlocked).toBeGreaterThan(0)
    expect(result.screenshot?.byteLength).toBeGreaterThan(100)
  }, 30_000)

  browserIt('respects a supplied CSP instead of treating reflection as execution', async () => {
    const marker = `agx_${randomBytes(12).toString('hex')}`
    const runner = new PlaywrightBrowserRunner({ executablePath })
    const result = await runner.execute({
      requestId: 'browser-csp',
      baseUrl: 'https://lab.example.test/',
      html: `<input value="${buildInertXssMarkerPayload(marker)}">`,
      contentSecurityPolicy: "default-src 'none'; script-src 'none'",
      action: 'verify-xss',
      marker,
      timeoutMs: 20_000
    })

    expect(result.status).toBe('succeeded')
    expect(result.markerExecuted).toBe(false)
  }, 30_000)
})
