import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import {
  UndiciHttpRunner,
  type HttpExecutionAuthorizationInput,
  type HttpExecutionGuard
} from './index'

const servers: Server[] = []

async function listen(server: Server): Promise<string> {
  servers.push(server)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address() as AddressInfo
  return `http://127.0.0.1:${address.port}`
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => server.close(() => resolve()))
    )
  )
})

describe('UndiciHttpRunner', () => {
  it('pins resolved addresses, follows an authorized redirect and redacts headers', async () => {
    const observed: HttpExecutionAuthorizationInput[] = []
    const guard: HttpExecutionGuard = {
      authorize: async (input) => {
        observed.push(input)
      }
    }
    const baseUrl = await listen(
      createServer((request, response) => {
        if (request.url === '/start') {
          response.writeHead(302, { location: '/final' })
          response.end('redirect')
          return
        }
        response.writeHead(200, {
          'content-type': 'text/plain',
          'set-cookie': 'session=secret'
        })
        response.end('runner-ok')
      })
    )

    const result = await new UndiciHttpRunner(guard).execute({
      requestId: 'request-redirect',
      policyDecisionId: 'decision-1',
      targetUrl: `${baseUrl}/start`,
      method: 'GET',
      headers: { Authorization: 'Bearer secret-token' },
      timeoutMs: 2_000
    })

    expect(result.status).toBe('succeeded')
    expect(Buffer.from(result.responseBody ?? []).toString('utf8')).toBe('runner-ok')
    expect(result.redirectChain).toHaveLength(1)
    expect(result.requestHeaders.authorization).toBe('[REDACTED]')
    expect(result.responseHeaders['set-cookie']).toBe('[REDACTED]')
    expect(result.resolvedAddresses).toContain('127.0.0.1')
    expect(observed).toHaveLength(2)
  })

  it('removes credentials on a cross-origin redirect', async () => {
    let receivedAuthorization = 'not-observed'
    const destination = await listen(
      createServer((request, response) => {
        receivedAuthorization = request.headers.authorization ?? ''
        response.end('destination')
      })
    )
    const source = await listen(
      createServer((_request, response) => {
        response.writeHead(302, { location: `${destination}/final` })
        response.end()
      })
    )
    const runner = new UndiciHttpRunner({ authorize: async () => undefined })
    const result = await runner.execute({
      requestId: 'request-cross-origin',
      policyDecisionId: 'decision-2',
      targetUrl: `${source}/start`,
      method: 'GET',
      headers: { authorization: 'Bearer must-not-leak' },
      timeoutMs: 2_000
    })

    expect(result.status).toBe('succeeded')
    expect(receivedAuthorization).toBe('')
  })

  it('fails closed when a redirect hop is rejected', async () => {
    const destination = await listen(
      createServer((_request, response) => response.end('must-not-be-reached'))
    )
    const source = await listen(
      createServer((_request, response) => {
        response.writeHead(302, { location: `${destination}/blocked` })
        response.end()
      })
    )
    const runner = new UndiciHttpRunner({
      authorize: async (input) => {
        if (input.redirectFrom) throw new Error('redirect out of scope')
      }
    })
    const result = await runner.execute({
      requestId: 'request-denied-redirect',
      policyDecisionId: 'decision-3',
      targetUrl: `${source}/start`,
      method: 'GET',
      timeoutMs: 2_000
    })

    expect(result.status).toBe('failed')
    expect(result.errorCode).toBe('authorization-denied')
  })

  it('enforces response size and cancellation limits', async () => {
    const baseUrl = await listen(
      createServer((request, response) => {
        if (request.url === '/large') {
          response.end('x'.repeat(4_096))
          return
        }
        setTimeout(() => response.end('late'), 300)
      })
    )
    const runner = new UndiciHttpRunner({ authorize: async () => undefined })
    const large = await runner.execute({
      requestId: 'request-large',
      policyDecisionId: 'decision-4',
      targetUrl: `${baseUrl}/large`,
      method: 'GET',
      timeoutMs: 2_000,
      maxResponseBytes: 128
    })
    expect(large.errorCode).toBe('response-too-large')

    const pending = runner.execute({
      requestId: 'request-cancel',
      policyDecisionId: 'decision-5',
      targetUrl: `${baseUrl}/slow`,
      method: 'GET',
      timeoutMs: 2_000
    })
    setTimeout(() => void runner.cancel('request-cancel'), 20)
    const cancelled = await pending
    expect(cancelled.status).toBe('cancelled')
    expect(cancelled.errorCode).toBe('cancelled')
  })
})
