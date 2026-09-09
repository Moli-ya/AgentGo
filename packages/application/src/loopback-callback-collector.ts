import { createServer, type Server } from 'node:http'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import type { CallbackCollectorPort } from './validation-plan-executor'

export type LoopbackCallbackSourceKind =
  | 'server'
  | 'browser'
  | 'broker'
  | 'health-check'
  | 'replay'
  | 'expired'

export interface LoopbackCallbackBinding {
  readonly collectorId: string
  readonly token: string
  readonly scanId?: string
  readonly candidateId?: string
  readonly stepId?: string
  readonly targetRef?: string
  readonly tenantId?: string
  readonly createdAt: number
  readonly expiresAt: number
}

export interface LoopbackCallbackInbound {
  readonly token: string
  readonly receivedAt: number
  readonly sourceKind: LoopbackCallbackSourceKind
  readonly protocol: 'http'
  readonly sourceMetadataHash: string
  readonly integrityHash: string
}

const TOKEN_PATTERN = /^oob\.[a-f0-9]{32}$/u
const DEFAULT_TTL_MS = 60_000

export function issueLoopbackCallbackToken(): string {
  return `oob.${randomBytes(16).toString('hex')}`
}

export function isLoopbackCallbackCollector(
  collector: CallbackCollectorPort | undefined
): collector is LoopbackCallbackCollector {
  if (!collector) return false
  if (collector instanceof LoopbackCallbackCollector) return true
  const candidate = collector as Partial<LoopbackCallbackCollector>
  return (
    typeof candidate.recordInbound === 'function' &&
    typeof candidate.tokenFor === 'function' &&
    typeof candidate.collectorIdForToken === 'function' &&
    typeof candidate.register === 'function'
  )
}

export async function ensureAttestedFixtureCallbackListen(input: {
  readonly environment: string
  readonly collector?: CallbackCollectorPort
  readonly existing?: LoopbackCallbackHttpServer
}): Promise<LoopbackCallbackHttpServer | undefined> {
  if (input.environment !== 'attested-fixture') return undefined
  if (!isLoopbackCallbackCollector(input.collector)) return undefined
  return input.existing ?? listenLoopbackCallbackCollector(input.collector)
}

export function loopbackCollectorScopeAuthorization(listenUrl: string): {
  readonly origin: string
  readonly port: number
} {
  const url = new URL(listenUrl)
  if (url.hostname !== '127.0.0.1' || url.protocol !== 'http:') {
    throw new Error('Loopback collector scope must stay on http://127.0.0.1.')
  }
  const port = Number(url.port)
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error('Loopback collector listen URL is missing a port.')
  }
  return { origin: url.origin, port }
}

export function hashCallbackMetadata(
  value: Readonly<Record<string, string>>
): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

/**
 * In-process collector for attested fixtures and loopback evaluation.
 * It is not a production remote OOB service: no TLS tenant plane, no
 * mock-as-production remote collector.
 */
export class LoopbackCallbackCollector implements CallbackCollectorPort {
  readonly #bindings = new Map<string, LoopbackCallbackBinding>()
  readonly #byToken = new Map<string, string>()
  readonly #events = new Map<string, LoopbackCallbackInbound>()
  readonly #consumed = new Set<string>()
  readonly #now: () => number
  readonly #ttlMs: number

  constructor(options: { readonly now?: () => number; readonly ttlMs?: number } = {}) {
    this.#now = options.now ?? Date.now
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
  }

  async register(token: string): Promise<{ collectorId: string }> {
    const normalized = TOKEN_PATTERN.test(token) ? token : issueLoopbackCallbackToken()
    const existing = this.#byToken.get(normalized)
    if (existing) {
      throw new Error('Callback token is not unique.')
    }
    const now = this.#now()
    const collectorId = randomUUID()
    const binding: LoopbackCallbackBinding = {
      collectorId,
      token: normalized,
      createdAt: now,
      expiresAt: now + this.#ttlMs
    }
    this.#bindings.set(collectorId, binding)
    this.#byToken.set(normalized, collectorId)
    return { collectorId }
  }

  bind(input: {
    readonly collectorId: string
    readonly scanId?: string
    readonly candidateId?: string
    readonly stepId?: string
    readonly targetRef?: string
    readonly tenantId?: string
  }): void {
    const current = this.#bindings.get(input.collectorId)
    if (!current) throw new Error('Callback collector does not exist.')
    this.#bindings.set(input.collectorId, {
      ...current,
      ...(input.scanId ? { scanId: input.scanId } : {}),
      ...(input.candidateId ? { candidateId: input.candidateId } : {}),
      ...(input.stepId ? { stepId: input.stepId } : {}),
      ...(input.targetRef ? { targetRef: input.targetRef } : {}),
      ...(input.tenantId ? { tenantId: input.tenantId } : {})
    })
  }

  recordInbound(input: {
    readonly token: string
    readonly sourceKind: LoopbackCallbackSourceKind
    readonly sourceMetadata: Readonly<Record<string, string>>
  }): boolean {
    const collectorId = this.#byToken.get(input.token)
    if (!collectorId) return false
    const binding = this.#bindings.get(collectorId)
    if (!binding) return false
    const now = this.#now()
    if (now >= binding.expiresAt) return false
    if (this.#consumed.has(collectorId) || this.#events.has(collectorId)) return false
    if (
      binding.scanId &&
      input.sourceMetadata.scanId &&
      input.sourceMetadata.scanId !== binding.scanId
    ) {
      return false
    }
    if (
      binding.tenantId &&
      input.sourceMetadata.tenantId &&
      input.sourceMetadata.tenantId !== binding.tenantId
    ) {
      return false
    }
    const sourceMetadataHash = hashCallbackMetadata(input.sourceMetadata)
    this.#events.set(collectorId, {
      token: input.token,
      receivedAt: now,
      sourceKind: input.sourceKind,
      protocol: 'http',
      sourceMetadataHash,
      integrityHash: hashCallbackMetadata({
        token: input.token,
        collectorId,
        sourceKind: input.sourceKind,
        sourceMetadataHash
      })
    })
    return true
  }

  async poll(
    collectorId: string,
    _timeoutMs: number
  ): Promise<{
    received: boolean
    sourceKind?: LoopbackCallbackSourceKind
    staleOrReplay?: boolean
    clientOrBrokerOrHealth?: boolean
  }> {
    const binding = this.#bindings.get(collectorId)
    const event = this.#events.get(collectorId)
    const expired = Boolean(binding && this.#now() >= binding.expiresAt)
    const attributed = this.attributedEvent(collectorId)
    return {
      received: attributed !== undefined,
      ...(event ? { sourceKind: event.sourceKind } : {}),
      staleOrReplay: expired || event?.sourceKind === 'replay' || event?.sourceKind === 'expired',
      clientOrBrokerOrHealth:
        event !== undefined &&
        (event.sourceKind === 'browser' ||
          event.sourceKind === 'broker' ||
          event.sourceKind === 'health-check')
    }
  }

  async consume(
    collectorId: string
  ): Promise<{
    observation?: string
    sourceKind?: LoopbackCallbackSourceKind
    staleOrReplay?: boolean
    clientOrBrokerOrHealth?: boolean
  }> {
    const peeked = await this.poll(collectorId, 0)
    const event = this.attributedEvent(collectorId)
    if (!event) {
      return {
        ...(peeked.sourceKind ? { sourceKind: peeked.sourceKind } : {}),
        staleOrReplay: peeked.staleOrReplay,
        clientOrBrokerOrHealth: peeked.clientOrBrokerOrHealth
      }
    }
    this.#consumed.add(collectorId)
    return {
      observation: event.integrityHash,
      sourceKind: event.sourceKind,
      staleOrReplay: false,
      clientOrBrokerOrHealth: false
    }
  }

  attributedEvent(collectorId: string): LoopbackCallbackInbound | undefined {
    const binding = this.#bindings.get(collectorId)
    const event = this.#events.get(collectorId)
    if (!binding || !event) return undefined
    if (this.#now() >= binding.expiresAt) return undefined
    if (event.sourceKind !== 'server') return undefined
    if (this.#consumed.has(collectorId)) return undefined
    return event
  }

  tokenFor(collectorId: string): string | undefined {
    return this.#bindings.get(collectorId)?.token
  }

  collectorIdForToken(token: string): string | undefined {
    return this.#byToken.get(token)
  }
}

export interface LoopbackCallbackHttpServer {
  readonly baseUrl: string
  readonly port: number
  close(): Promise<void>
}

/**
 * Loopback HTTP face for attested fixtures. It is not a remote production
 * collector: no TLS, no tenant plane, no replay-auth protocol.
 */
export async function listenLoopbackCallbackCollector(
  collector: LoopbackCallbackCollector
): Promise<LoopbackCallbackHttpServer> {
  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1')
    if (request.method !== 'GET' || url.pathname !== '/callback') {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('not-found')
      return
    }
    const token = url.searchParams.get('agentgo_token') ?? ''
    const accepted = collector.recordInbound({
      token,
      sourceKind: 'server',
      sourceMetadata: {
        via: 'loopback-http',
        path: url.pathname
      }
    })
    response.writeHead(accepted ? 204 : 404, {
      'content-type': 'text/plain; charset=utf-8'
    })
    response.end()
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      resolve()
    })
  })
  const address = server.address() as AddressInfo
  server.unref()
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    port: address.port,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()))
      })
  }
}
