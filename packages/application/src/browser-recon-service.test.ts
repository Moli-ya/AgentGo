import { createHash, randomUUID } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  findSystemBrowserExecutable,
  PlaywrightBrokeredBrowserRecon
} from '@agentgo/browser-runner'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  AgentGoRepository,
  DiscoveryRuntimeRepository,
  ImportDiscoveryRepository,
  openAgentGoDatabase,
  type AgentGoDatabase
} from '@agentgo/db'
import { DEFAULT_PROBE_CAPABILITY_CATALOG } from '@agentgo/security-policy'
import { AssetManifestService } from './asset-manifest-service'
import { BrowserReconService } from './browser-recon-service'
import type {
  BrokeredBrowserRequest,
  BrokeredBrowserSession,
  BrokeredBrowserSessionInput,
  BrokeredBrowserSessionResult
} from './browser-recon-session'
import type {
  ExecutionPort,
  ExecutionPortInput,
  HttpExecutionResultView,
  MediatedHttpExecutionStepInput,
  StoredExecutionResult
} from './execution-port'
import { InventoryMergeService } from './inventory-merge-service'
import { InventoryService } from './inventory-service'

const directories: string[] = []
const openDatabases: AgentGoDatabase[] = []
const servers: Server[] = []

afterEach(async () => {
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()))
    })
  }
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

class ScriptedSession implements BrokeredBrowserSession {
  constructor(private readonly script: readonly BrokeredBrowserRequest[]) {}

  async run(input: BrokeredBrowserSessionInput): Promise<BrokeredBrowserSessionResult> {
    if (input.signal?.aborted) {
      return {
        status: 'cancelled',
        finalUrl: input.startUrl,
        blockedTransports: 0
      }
    }
    for (const request of this.script) {
      if (input.signal?.aborted) {
        return {
          status: 'cancelled',
          finalUrl: input.startUrl,
          blockedTransports: 0
        }
      }
      await input.broker.handle(request)
    }
    return {
      status: 'succeeded',
      finalUrl: input.startUrl,
      blockedTransports: 0
    }
  }
}

class PlaywrightSession implements BrokeredBrowserSession {
  async run(input: BrokeredBrowserSessionInput): Promise<BrokeredBrowserSessionResult> {
    const recon = new PlaywrightBrokeredBrowserRecon()
    const result = await recon.execute(
      {
        requestId: randomUUID(),
        startUrl: input.startUrl,
        timeoutMs: input.timeoutMs,
        ...(input.signal ? { signal: input.signal } : {})
      },
      {
        async handle(request) {
          const decision = await input.broker.handle(request)
          if (decision.verdict === 'fulfill' && decision.fulfillment) {
            return { action: 'fulfill', fulfillment: decision.fulfillment }
          }
          return { action: 'abort' }
        }
      }
    )
    return {
      status: result.status,
      finalUrl: result.finalUrl,
      blockedTransports: result.blockedTransports
    }
  }
}

class RecordingPort implements ExecutionPort {
  readonly mediated: MediatedHttpExecutionStepInput[] = []

  constructor(
    private readonly bodies: ReadonlyMap<string, Uint8Array>,
    private readonly responseHeaders: Readonly<Record<string, string>> = {
      'content-type': 'text/html'
    }
  ) {}

  execute(_input: ExecutionPortInput): never {
    throw new Error('L1 execute is not used by browser recon.')
  }

  executeL2Http(): never {
    throw new Error('L2 is not used by browser recon.')
  }

  async executeMediatedHttp(
    input: MediatedHttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>> {
    this.mediated.push(input)
    const body = this.bodies.get(input.desiredUrl) ?? new TextEncoder().encode('ok')
    return {
      result: {
        requestId: randomUUID(),
        status: 'succeeded',
        finalUrl: input.desiredUrl,
        method: input.method,
        statusCode: 200,
        requestHeaders: [],
        responseHeaders: this.responseHeaders,
        responseBody: body,
        responseBodySha256: sha256(body),
        responseBytes: body.byteLength,
        durationMs: 1,
        resolvedAddresses: ['127.0.0.1'],
        redirectChain: []
      },
      interactionIds: [],
      evidenceRefs: [randomUUID()],
      toolCallId: randomUUID(),
      toolCallIds: [],
      proposalIds: [],
      policyDecisionIds: [randomUUID()],
      grantIds: [randomUUID()],
      leaseIds: [randomUUID()]
    }
  }
}

const HTML = '<html><script src="/app.js"></script></html>'
const JS = 'fetch("/api/read");fetch("/api/write",{method:"POST",body:"{}"});'

async function harness(
  script: readonly BrokeredBrowserRequest[],
  options?: {
    readonly session?: BrokeredBrowserSession
    readonly extraBodies?: ReadonlyMap<string, Uint8Array>
    readonly extraEntries?: ReadonlyArray<{
      readonly path: string
      readonly resourceType: 'html' | 'javascript'
      readonly body: Uint8Array
    }>
    readonly responseHeaders?: Readonly<Record<string, string>>
  }
) {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-recon-'))
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({ name: 'recon', description: '' })
  const created = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'spa',
    baseUrl: 'http://127.0.0.1:4150',
    description: '',
    authorizationReference: 'recon-test',
    scope: {
      allowedOrigins: ['http://127.0.0.1:4150'],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [4150],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: true,
      allowLoopbackTargets: true,
      networkEntries: [
        {
          id: 'recon-loopback',
          addressClass: 'loopback',
          ip: '127.0.0.1',
          ports: [4150],
          purpose: 'execution'
        }
      ],
      maxRequestsPerMinute: 20,
      maxConcurrency: 1
    }
  })
  const plan = createDefaultScanPlan(['xss'])
  const scan = await repository.createScan(
    {
      targetId: created.target.id,
      name: 'recon',
      description: '',
      families: ['xss'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() }
  )
  const html = new TextEncoder().encode(HTML)
  const js = new TextEncoder().encode(JS)
  const inventory = new InventoryService(repository, DEFAULT_PROBE_CAPABILITY_CATALOG)
  const runtime = new DiscoveryRuntimeRepository(database)
  const discovery = new ImportDiscoveryRepository(database)
  const merge = new InventoryMergeService(inventory, repository, runtime)
  const bodies = new Map<string, Uint8Array>([
    ['http://127.0.0.1:4150/', html],
    ['http://127.0.0.1:4150/app.js', js]
  ])
  if (options?.extraBodies) {
    for (const [url, body] of options.extraBodies) bodies.set(url, body)
  }
  const port = new RecordingPort(bodies, options?.responseHeaders)
  const recon = new BrowserReconService(
    repository,
    inventory,
    merge,
    port,
    runtime,
    options?.session ?? new ScriptedSession(script)
  )
  const manifests = new AssetManifestService(repository, discovery)
  const extraEntries = options?.extraEntries ?? []
  const draft = await manifests.saveDraft({
    scanId: scan.id,
    scopeSnapshotId: scan.scopeSnapshotId,
    reviewer: 'fixture.reviewer',
    entries: [
      {
        origin: 'http://127.0.0.1:4150',
        normalizedPath: '/',
        resourceType: 'html',
        artifactRef: randomUUID(),
        contentHash: sha256(html),
        maxResponseBytes: 65_536,
        scopeSnapshotId: scan.scopeSnapshotId
      },
      {
        origin: 'http://127.0.0.1:4150',
        normalizedPath: '/app.js',
        resourceType: 'javascript',
        artifactRef: randomUUID(),
        contentHash: sha256(js),
        maxResponseBytes: 65_536,
        scopeSnapshotId: scan.scopeSnapshotId
      },
      ...extraEntries.map((entry) => ({
        origin: 'http://127.0.0.1:4150',
        normalizedPath: entry.path,
        resourceType: entry.resourceType,
        artifactRef: randomUUID(),
        contentHash: sha256(entry.body),
        maxResponseBytes: 65_536,
        scopeSnapshotId: scan.scopeSnapshotId
      }))
    ]
  })
  const frozen = await manifests.freeze({
    manifestId: draft.manifestId,
    manifestHash: draft.manifestHash,
    reviewer: 'fixture.reviewer',
    scopeSnapshotId: scan.scopeSnapshotId
  })
  return { scan, recon, port, frozen, runtime, inventory, repository }
}

describe('BrowserReconService', () => {
  it('fulfills frozen manifest documents and does not send writes', async () => {
    const { scan, recon, port, frozen, runtime } = await harness([
      {
        url: 'http://127.0.0.1:4150/',
        method: 'GET',
        resourceType: 'document',
        headers: {},
        isNavigation: true,
        pageUrl: 'http://127.0.0.1:4150/'
      },
      {
        url: 'http://127.0.0.1:4150/app.js',
        method: 'GET',
        resourceType: 'script',
        headers: {},
        isNavigation: false,
        pageUrl: 'http://127.0.0.1:4150/'
      },
      {
        url: 'http://127.0.0.1:4150/api/unknown',
        method: 'GET',
        resourceType: 'fetch',
        headers: {},
        isNavigation: false,
        pageUrl: 'http://127.0.0.1:4150/'
      },
      {
        url: 'http://127.0.0.1:4150/api/write',
        method: 'POST',
        resourceType: 'fetch',
        headers: { 'content-type': 'application/json' },
        postData: '{"x":1}',
        isNavigation: false,
        pageUrl: 'http://127.0.0.1:4150/'
      },
      {
        url: 'http://127.0.0.1:4150/ws',
        method: 'GET',
        resourceType: 'websocket',
        headers: {},
        isNavigation: false,
        pageUrl: 'http://127.0.0.1:4150/'
      }
    ])
    await recon.run({
      scanId: scan.id,
      agentRunId: randomUUID(),
      familyId: 'xss',
      startUrl: 'http://127.0.0.1:4150/',
      manifest: frozen,
      timeoutMs: 5_000
    })
    expect(port.mediated.map((item) => item.desiredUrl).sort()).toEqual([
      'http://127.0.0.1:4150/',
      'http://127.0.0.1:4150/app.js'
    ])
    expect(port.mediated.every((item) => item.method === 'GET')).toBe(true)
    const observations = await runtime.listBrowserReconObservations(scan.id)
    expect(observations.some((item) => item.verdict === 'fulfill')).toBe(true)
    expect(observations.some((item) => item.verdict === 'awaiting-review')).toBe(true)
    expect(observations.some((item) => item.verdict === 'unsupported')).toBe(true)
    expect(observations.some((item) => item.verdict === 'inventory-only')).toBe(true)
  })

  it('sends reviewed read-only XHR through ExecutionPort', async () => {
    const xhrBody = new TextEncoder().encode('{"ok":true}')
    const { scan, recon, port, frozen, inventory } = await harness(
      [
        {
          url: 'http://127.0.0.1:4150/api/read',
          method: 'GET',
          resourceType: 'xhr',
          headers: {},
          isNavigation: false,
          pageUrl: 'http://127.0.0.1:4150/'
        }
      ],
      { extraBodies: new Map([['http://127.0.0.1:4150/api/read', xhrBody]]) }
    )
    const upserted = await inventory.upsertInventory({
      scanId: scan.id,
      method: 'GET',
      url: 'http://127.0.0.1:4150/api/read',
      bodyShape: { rootType: 'none', fields: [] },
      codec: 'none',
      transport: 'standard-http',
      allowedHeaders: [],
      templateVersion: '1.0.0',
      requiredCapabilityIds: ['http.reviewed-read'],
      selectors: [],
      preview: { url: 'http://127.0.0.1:4150/api/read' },
      source: {
        type: 'browser.recon',
        sourceHash: sha256('reviewed-xhr'),
        confidence: 1
      }
    })
    await inventory.reviewVariant({
      scanId: scan.id,
      requestVariantId: upserted.requestVariant.id,
      reviewStatus: 'reviewed',
      reviewedBy: 'fixture.reviewer'
    })
    await recon.run({
      scanId: scan.id,
      agentRunId: randomUUID(),
      familyId: 'xss',
      startUrl: 'http://127.0.0.1:4150/',
      manifest: frozen,
      timeoutMs: 5_000
    })
    expect(port.mediated.map((item) => item.desiredUrl)).toEqual([
      'http://127.0.0.1:4150/api/read'
    ])
    expect(port.mediated[0]?.stepId).toBe('recon.xhr')
  })

  it('strips Set-Cookie before fulfilling browser reads', async () => {
    const { scan, recon, port, frozen, repository } = await harness(
      [
        {
          url: 'http://127.0.0.1:4150/',
          method: 'GET',
          resourceType: 'document',
          headers: {},
          isNavigation: true,
          pageUrl: 'http://127.0.0.1:4150/'
        }
      ],
      {
        responseHeaders: {
          'content-type': 'text/html',
          'set-cookie': 'session=secret; HttpOnly'
        }
      }
    )
    const decision = await recon.handleRequest({
      request: {
        url: 'http://127.0.0.1:4150/',
        method: 'GET',
        resourceType: 'document',
        headers: {},
        isNavigation: true,
        pageUrl: 'http://127.0.0.1:4150/'
      },
      input: {
        scanId: scan.id,
        agentRunId: randomUUID(),
        familyId: 'xss',
        startUrl: 'http://127.0.0.1:4150/',
        manifest: frozen,
        timeoutMs: 5_000
      },
      manifest: frozen,
      scope: (await repository.getScope(scan.scopeSnapshotId))!
    })
    void port
    expect(decision.verdict).toBe('fulfill')
    expect(decision.fulfillment?.headers).toEqual({ 'content-type': 'text/html' })
  })

  it('fails closed on out-of-scope origins without calling ExecutionPort', async () => {
    const { scan, recon, port, frozen } = await harness([
      {
        url: 'https://evil.example.test/app.js',
        method: 'GET',
        resourceType: 'script',
        headers: {},
        isNavigation: false,
        pageUrl: 'http://127.0.0.1:4150/'
      }
    ])
    await recon.run({
      scanId: scan.id,
      agentRunId: randomUUID(),
      familyId: 'xss',
      startUrl: 'http://127.0.0.1:4150/',
      manifest: frozen,
      timeoutMs: 5_000
    })
    expect(port.mediated).toEqual([])
  })

  it('fails closed when a frozen asset hash does not match', async () => {
    const { scan, recon, port, frozen, runtime } = await harness(
      [
        {
          url: 'http://127.0.0.1:4150/app.js',
          method: 'GET',
          resourceType: 'script',
          headers: {},
          isNavigation: false,
          pageUrl: 'http://127.0.0.1:4150/'
        }
      ],
      {
        extraBodies: new Map([
          ['http://127.0.0.1:4150/app.js', new TextEncoder().encode('tampered')]
        ])
      }
    )
    await recon.run({
      scanId: scan.id,
      agentRunId: randomUUID(),
      familyId: 'xss',
      startUrl: 'http://127.0.0.1:4150/',
      manifest: frozen,
      timeoutMs: 5_000
    })
    expect(port.mediated).toHaveLength(1)
    const observations = await runtime.listBrowserReconObservations(scan.id)
    expect(observations.some((item) => item.verdict === 'fail-closed')).toBe(true)
  })

  it('does not dispatch after cancellation', async () => {
    const controller = new AbortController()
    controller.abort()
    const { scan, recon, port, frozen } = await harness([
      {
        url: 'http://127.0.0.1:4150/',
        method: 'GET',
        resourceType: 'document',
        headers: {},
        isNavigation: true,
        pageUrl: 'http://127.0.0.1:4150/'
      }
    ])
    await recon.run({
      scanId: scan.id,
      agentRunId: randomUUID(),
      familyId: 'xss',
      startUrl: 'http://127.0.0.1:4150/',
      manifest: frozen,
      timeoutMs: 5_000,
      signal: controller.signal
    })
    expect(port.mediated).toEqual([])
  })
})

describe('Brokered Playwright recon', () => {
  it.skipIf(!findSystemBrowserExecutable())(
    'does not let Chromium reach the fixture HTTP server',
    async () => {
      let hits = 0
      const server = createServer((_request, response) => {
        hits += 1
        response.writeHead(500)
        response.end('unreachable')
      })
      servers.push(server)
      await new Promise<void>((resolve) => {
        server.listen(4150, '127.0.0.1', resolve)
      })
      const { scan, recon, port, frozen } = await harness([], {
        session: new PlaywrightSession()
      })
      await recon.run({
        scanId: scan.id,
        agentRunId: randomUUID(),
        familyId: 'xss',
        startUrl: 'http://127.0.0.1:4150/',
        manifest: frozen,
        timeoutMs: 15_000
      })
      expect(hits).toBe(0)
      expect(port.mediated.some((item) => item.desiredUrl === 'http://127.0.0.1:4150/')).toBe(
        true
      )
    }
  )
})
