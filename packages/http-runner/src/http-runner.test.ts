import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import {
  HTTP_TRANSPORT_DERIVED_HEADER_NAMES,
  UndiciHttpRunner,
  type HttpExecutionClaimInput,
  type HttpExecutionGuard,
  type HttpExecutionRequest,
  type HttpExactWireRequest,
  type HttpWireHeader,
  type ResolvedAddress
} from './index'

interface TestClaimToken {
  readonly claimId: string
}

const servers: Server[] = []

async function listen(server: Server): Promise<string> {
  servers.push(server)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address() as AddressInfo
  return `http://127.0.0.1:${address.port}`
}

function allowingGuard(events: string[] = []): HttpExecutionGuard<TestClaimToken> {
  let claimSequence = 0
  return {
    claim: async () => {
      events.push('claim')
      claimSequence += 1
      return Object.freeze({ claimId: `claim-${claimSequence}` })
    },
    validateResolvedAddresses: async () => {
      events.push('addresses')
    },
    markDispatched: async () => {
      events.push('mark')
    },
    markResponseStarted: async () => {
      events.push('response-started')
    }
  }
}

function rawHeaderEntries(rawHeaders: string[]): HttpWireHeader[] {
  const entries: HttpWireHeader[] = []
  for (let index = 0; index < rawHeaders.length; index += 2) {
    entries.push({
      name: rawHeaders[index]!.toLowerCase(),
      value: rawHeaders[index + 1]!
    })
  }
  return entries
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => server.close(() => resolve()))
    )
  )
})

describe('UndiciHttpRunner single-hop lease guard', () => {
  it('claims the exact wire and sends exactly its authorized headers plus transport-derived fields', async () => {
    const events: string[] = []
    const observedClaims: HttpExecutionClaimInput[] = []
    const observedAddresses: (readonly ResolvedAddress[])[] = []
    const claimToken = Object.freeze({ claimId: 'claim-exact-wire' })
    let receivedBody = ''
    let receivedHeaders: HttpWireHeader[] = []
    const baseUrl = await listen(
      createServer((incoming, response) => {
        events.push('network')
        receivedHeaders = rawHeaderEntries(incoming.rawHeaders)
        const chunks: Buffer[] = []
        incoming.on('data', (chunk: Buffer) => chunks.push(chunk))
        incoming.on('end', () => {
          receivedBody = Buffer.concat(chunks).toString('utf8')
          response.writeHead(200, {
            'content-type': 'text/plain',
            'set-cookie': 'session=must-not-leak'
          })
          response.end('runner-ok')
        })
      })
    )
    const body = Buffer.from('runner-body')
    const authorizedHeaders = [
      { name: 'authorization', value: 'Bearer secret-token' },
      { name: 'content-length', value: String(body.byteLength) },
      { name: 'content-type', value: 'text/plain' },
      { name: 'x-agentgo-a', value: 'first' },
      { name: 'x-agentgo-b', value: 'second' }
    ] as const
    const guard: HttpExecutionGuard<typeof claimToken> = {
      claim: async (input) => {
        events.push('claim')
        observedClaims.push(input)
        return claimToken
      },
      validateResolvedAddresses: async (token, addresses) => {
        events.push('addresses')
        expect(token).toBe(claimToken)
        observedAddresses.push(addresses)
      },
      markDispatched: async (token) => {
        events.push('mark')
        expect(token).toBe(claimToken)
      },
      markResponseStarted: async (token) => {
        events.push('response-started')
        expect(token).toBe(claimToken)
      }
    }

    const result = await new UndiciHttpRunner(guard).execute({
      requestId: 'request-exact-wire',
      leaseId: 'lease-exact-wire',
      wire: {
        method: 'POST',
        url: `${baseUrl}/ordered`,
        headers: authorizedHeaders,
        bodyBytes: [...body]
      },
      timeoutMs: 2_000,
      maxResponseBytes: 1_024
    })

    expect(events).toEqual([
      'claim',
      'addresses',
      'mark',
      'network',
      'response-started'
    ])
    expect(observedClaims).toHaveLength(1)
    expect(observedClaims[0]).toMatchObject({
      leaseId: 'lease-exact-wire',
      limits: { timeoutMs: 2_000, maxResponseBytes: 1_024 },
      wire: {
        method: 'POST',
        url: `${baseUrl}/ordered`,
        bodyBytes: [...body]
      }
    })
    expect(Object.isFrozen(observedClaims[0]?.wire)).toBe(true)
    expect(Object.isFrozen(observedClaims[0]?.wire.headers)).toBe(true)
    expect(Object.isFrozen(observedClaims[0]?.wire.bodyBytes)).toBe(true)
    expect(Object.isFrozen(observedClaims[0]?.limits)).toBe(true)
    expect(observedAddresses).toEqual([
      [{ address: '127.0.0.1', family: 4 }]
    ])
    const derivedHeaderNames = new Set<string>(
      HTTP_TRANSPORT_DERIVED_HEADER_NAMES
    )
    const receivedAuthorizedHeaders = receivedHeaders
      .filter(({ name }) => !derivedHeaderNames.has(name))
      .sort((left, right) => left.name.localeCompare(right.name))
    const receivedTransportHeaders = receivedHeaders.filter(({ name }) =>
      derivedHeaderNames.has(name)
    )
    expect(receivedAuthorizedHeaders).toEqual(authorizedHeaders)
    expect(
      receivedTransportHeaders.map(({ name }) => name).sort()
    ).toEqual([...HTTP_TRANSPORT_DERIVED_HEADER_NAMES].sort())
    expect(receivedTransportHeaders).toEqual(
      expect.arrayContaining([
        { name: 'host', value: new URL(baseUrl).host },
        {
          name: 'connection',
          value: expect.stringMatching(/^(?:close|keep-alive)$/u)
        }
      ])
    )
    expect(receivedBody).toBe('runner-body')
    expect(result.status).toBe('succeeded')
    expect(result.claimToken).toBe(claimToken)
    expect(JSON.stringify(result)).not.toContain('claim-exact-wire')
    expect(result.requestHeaders).toEqual([
      { name: 'authorization', value: '[REDACTED]' },
      { name: 'content-length', value: '[REDACTED]' },
      { name: 'content-type', value: '[REDACTED]' },
      { name: 'x-agentgo-a', value: '[REDACTED]' },
      { name: 'x-agentgo-b', value: '[REDACTED]' }
    ])
    expect(result.responseHeaders['content-type']).toBe('text/plain')
    expect(result.responseHeaders['set-cookie']).toBeUndefined()
    expect(result.resolvedAddresses).toEqual(['127.0.0.1'])
    expect(Buffer.from(result.responseBody ?? []).toString('utf8')).toBe('runner-ok')
  })

  it('sends zero requests when claim or durable dispatch marking fails', async () => {
    let networkRequests = 0
    const baseUrl = await listen(
      createServer((_request, response) => {
        networkRequests += 1
        response.end('must-not-be-reached')
      })
    )
    let claimRejectedMarkCalls = 0
    const claimRejected = await new UndiciHttpRunner({
      claim: async () => {
        throw new Error('Bearer must-not-escape-through-errors')
      },
      validateResolvedAddresses: async () => undefined,
      markDispatched: async () => {
        claimRejectedMarkCalls += 1
      },
      markResponseStarted: async () => undefined
    }).execute({
      requestId: 'request-claim-rejected',
      leaseId: 'lease-claim-rejected',
      wire: { method: 'GET', url: `${baseUrl}/claim`, headers: [] },
      timeoutMs: 2_000
    })

    expect(claimRejected.errorCode).toBe('claim-rejected')
    expect(claimRejected.claimToken).toBeUndefined()
    expect(claimRejected.errorMessage).not.toContain('Bearer')
    expect(claimRejectedMarkCalls).toBe(0)
    expect(networkRequests).toBe(0)

    const token = Object.freeze({ claimId: 'claim-mark-failed' })
    const guardEvents: string[] = []
    const markRejected = await new UndiciHttpRunner({
      claim: async () => {
        guardEvents.push('claim')
        return token
      },
      validateResolvedAddresses: async () => {
        guardEvents.push('addresses')
      },
      markDispatched: async (received) => {
        guardEvents.push('mark')
        expect(received).toBe(token)
        throw new Error('database unavailable')
      },
      markResponseStarted: async () => undefined
    }).execute({
      requestId: 'request-mark-rejected',
      leaseId: 'lease-mark-rejected',
      wire: { method: 'GET', url: `${baseUrl}/mark`, headers: [] },
      timeoutMs: 2_000
    })

    expect(guardEvents).toEqual(['claim', 'addresses', 'mark'])
    expect(markRejected.errorCode).toBe('dispatch-mark-failed')
    expect(markRejected.claimToken).toBe(token)
    expect(JSON.stringify(markRejected)).not.toContain('claim-mark-failed')
    expect(networkRequests).toBe(0)
  })

  it('returns the claim token when response-start persistence fails', async () => {
    const events: string[] = []
    const token = Object.freeze({ claimId: 'claim-response-start-failed' })
    const baseUrl = await listen(
      createServer((_request, response) => {
        events.push('network')
        response.end('body-must-not-be-consumed')
      })
    )
    const result = await new UndiciHttpRunner({
      claim: async () => {
        events.push('claim')
        return token
      },
      validateResolvedAddresses: async () => {
        events.push('addresses')
      },
      markDispatched: async (received) => {
        events.push('mark')
        expect(received).toBe(token)
      },
      markResponseStarted: async (received) => {
        events.push('response-started')
        expect(received).toBe(token)
        throw new Error('database unavailable')
      }
    }).execute({
      requestId: 'request-response-start-rejected',
      leaseId: 'lease-response-start-rejected',
      wire: { method: 'GET', url: `${baseUrl}/response-start`, headers: [] },
      timeoutMs: 2_000
    })

    expect(events).toEqual([
      'claim',
      'addresses',
      'mark',
      'network',
      'response-started'
    ])
    expect(result.status).toBe('failed')
    expect(result.statusCode).toBe(200)
    expect(result.errorCode).toBe('response-start-mark-failed')
    expect(result.responseBytes).toBe(0)
    expect(result.responseBody).toBeUndefined()
    expect(result.claimToken).toBe(token)
    expect(JSON.stringify(result)).not.toContain('claim-response-start-failed')
  })

  it('returns a redirect response without following it', async () => {
    const paths: string[] = []
    const events: string[] = []
    const baseUrl = await listen(
      createServer((request, response) => {
        events.push('network')
        paths.push(request.url ?? '')
        if (request.url === '/start') {
          response.writeHead(302, { location: '/final' })
          response.end('single-hop')
          return
        }
        response.end('must-not-be-reached')
      })
    )

    const result = await new UndiciHttpRunner(allowingGuard(events)).execute({
      requestId: 'request-redirect',
      leaseId: 'lease-redirect',
      wire: { method: 'GET', url: `${baseUrl}/start`, headers: [] },
      timeoutMs: 2_000
    })

    expect(result.status).toBe('succeeded')
    expect(result.statusCode).toBe(302)
    expect(result.redirectLocation).toBe('/final')
    expect(Buffer.from(result.responseBody ?? []).toString('utf8')).toBe('single-hop')
    expect(paths).toEqual(['/start'])
    expect(events).toEqual([
      'claim',
      'addresses',
      'mark',
      'network',
      'response-started'
    ])
  })

  it('rejects a non-canonical header order before claim or network send', async () => {
    let claimCalls = 0
    let networkRequests = 0
    const baseUrl = await listen(
      createServer((_request, response) => {
        networkRequests += 1
        response.end('must-not-be-reached')
      })
    )
    const result = await new UndiciHttpRunner({
      claim: async () => {
        claimCalls += 1
        return Object.freeze({ claimId: 'must-not-exist' })
      },
      validateResolvedAddresses: async () => undefined,
      markDispatched: async () => undefined,
      markResponseStarted: async () => undefined
    }).execute({
      requestId: 'request-unsorted-headers',
      leaseId: 'lease-unsorted-headers',
      wire: {
        method: 'GET',
        url: `${baseUrl}/unsorted`,
        headers: [
          { name: 'x-z-last', value: 'last' },
          { name: 'x-a-first', value: 'first' }
        ]
      },
      timeoutMs: 2_000
    })

    expect(result.errorCode).toBe('invalid-wire')
    expect(result.claimToken).toBeUndefined()
    expect(claimCalls).toBe(0)
    expect(networkRequests).toBe(0)
  })

  it('rejects accessor-backed wire fields before claim or network send', async () => {
    let claimCalls = 0
    let networkRequests = 0
    let accessorReads = 0
    const baseUrl = await listen(
      createServer((_request, response) => {
        networkRequests += 1
        response.end('must-not-be-reached')
      })
    )
    const wire = Object.defineProperties(
      {},
      {
        method: {
          enumerable: true,
          value: 'GET'
        },
        url: {
          enumerable: true,
          get: () => {
            accessorReads += 1
            return accessorReads === 1
              ? `${baseUrl}/approved`
              : `${baseUrl}/evil`
          }
        },
        headers: {
          enumerable: true,
          value: []
        }
      }
    ) as HttpExactWireRequest
    const result = await new UndiciHttpRunner({
      claim: async () => {
        claimCalls += 1
        return Object.freeze({ claimId: 'must-not-exist' })
      },
      validateResolvedAddresses: async () => undefined,
      markDispatched: async () => undefined,
      markResponseStarted: async () => undefined
    }).execute({
      requestId: 'request-accessor-wire',
      leaseId: 'lease-accessor-wire',
      wire,
      timeoutMs: 2_000
    })

    expect(result.errorCode).toBe('invalid-wire')
    expect(result.claimToken).toBeUndefined()
    expect(accessorReads).toBe(0)
    expect(claimCalls).toBe(0)
    expect(networkRequests).toBe(0)
  })

  it('rejects accessor-backed execution limits before claim or network send', async () => {
    let claimCalls = 0
    let networkRequests = 0
    let accessorReads = 0
    const baseUrl = await listen(
      createServer((_request, response) => {
        networkRequests += 1
        response.end('must-not-be-reached')
      })
    )
    const requestInput = Object.defineProperties(
      {},
      {
        requestId: {
          enumerable: true,
          value: 'request-accessor-limit'
        },
        leaseId: {
          enumerable: true,
          value: 'lease-accessor-limit'
        },
        wire: {
          enumerable: true,
          value: {
            method: 'GET',
            url: `${baseUrl}/approved`,
            headers: []
          }
        },
        timeoutMs: {
          enumerable: true,
          get: () => {
            accessorReads += 1
            return accessorReads === 1 ? 2_000 : 1
          }
        }
      }
    ) as HttpExecutionRequest
    const result = await new UndiciHttpRunner({
      claim: async () => {
        claimCalls += 1
        return Object.freeze({ claimId: 'must-not-exist' })
      },
      validateResolvedAddresses: async () => undefined,
      markDispatched: async () => undefined,
      markResponseStarted: async () => undefined
    }).execute(requestInput)

    expect(result.errorCode).toBe('invalid-wire')
    expect(result.claimToken).toBeUndefined()
    expect(accessorReads).toBe(0)
    expect(claimCalls).toBe(0)
    expect(networkRequests).toBe(0)
  })

  it('rejects caller-controlled transport fields and ambiguous framing before claim', async () => {
    let claimCalls = 0
    let networkRequests = 0
    const baseUrl = await listen(
      createServer((_request, response) => {
        networkRequests += 1
        response.end('must-not-be-reached')
      })
    )
    const runner = new UndiciHttpRunner({
      claim: async () => {
        claimCalls += 1
        return Object.freeze({ claimId: 'must-not-exist' })
      },
      validateResolvedAddresses: async () => undefined,
      markDispatched: async () => undefined,
      markResponseStarted: async () => undefined
    })
    const transportFields = [
      'connection',
      'expect',
      'host',
      'keep-alive',
      'proxy-connection',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade'
    ]
    const invalidWires: HttpExactWireRequest[] = [
      ...transportFields.map((name) => ({
        method: 'GET',
        url: `${baseUrl}/transport-${name}`,
        headers: [{ name, value: 'caller-controlled' }]
      })),
      {
        method: 'POST',
        url: `${baseUrl}/missing-content-length`,
        headers: [],
        bodyBytes: [1]
      },
      {
        method: 'POST',
        url: `${baseUrl}/mismatched-content-length`,
        headers: [{ name: 'content-length', value: '2' }],
        bodyBytes: [1]
      },
      {
        method: 'POST',
        url: `${baseUrl}/content-length-without-body`,
        headers: [{ name: 'content-length', value: '0' }]
      },
      {
        method: 'GET',
        url: `${baseUrl}/duplicate-header`,
        headers: [
          { name: 'x-duplicate', value: 'first' },
          { name: 'x-duplicate', value: 'second' }
        ]
      }
    ]

    for (const [index, wire] of invalidWires.entries()) {
      const result = await runner.execute({
        requestId: `request-invalid-transport-${index}`,
        leaseId: `lease-invalid-transport-${index}`,
        wire,
        timeoutMs: 2_000
      })
      expect(result.errorCode, JSON.stringify(wire)).toBe('invalid-wire')
      expect(result.claimToken).toBeUndefined()
    }
    expect(claimCalls).toBe(0)
    expect(networkRequests).toBe(0)
  })

  it('keeps response size and cancellation limits and returns claimed tokens', async () => {
    const baseUrl = await listen(
      createServer((request, response) => {
        if (request.url === '/large') {
          response.end('x'.repeat(4_096))
          return
        }
        response.writeHead(200, { 'content-type': 'text/plain' })
        response.flushHeaders()
        setTimeout(() => response.end('late'), 300)
      })
    )
    const limitEvents: string[] = []
    const runner = new UndiciHttpRunner(allowingGuard(limitEvents))
    const large = await runner.execute({
      requestId: 'request-large',
      leaseId: 'lease-large',
      wire: { method: 'GET', url: `${baseUrl}/large`, headers: [] },
      timeoutMs: 2_000,
      maxResponseBytes: 128
    })
    expect(large.errorCode).toBe('response-too-large')
    expect(large.claimToken).toBeDefined()

    const pending = runner.execute({
      requestId: 'request-cancel',
      leaseId: 'lease-cancel',
      wire: { method: 'GET', url: `${baseUrl}/slow`, headers: [] },
      timeoutMs: 2_000
    })
    setTimeout(() => void runner.cancel('request-cancel'), 20)
    const cancelled = await pending
    expect(cancelled.status).toBe('cancelled')
    expect(cancelled.errorCode).toBe('cancelled')
    expect(cancelled.claimToken).toBeDefined()
    expect(limitEvents.filter((event) => event === 'response-started')).toHaveLength(2)
  })
})
