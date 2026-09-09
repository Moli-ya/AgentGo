import { createHash, randomUUID } from 'node:crypto'
import {
  type AssetManifest,
  type AssetManifestEntry,
  type AssetResourceType,
  type BrowserNetworkIntent,
  type BrowserNetworkVerdict,
  type BrowserReconObservation,
  type BrowserResourceType,
  type InventoryMergeCountBucket,
  type InventoryMergeProducer,
  type LegacyV1VulnerabilityFamily,
  type TargetScopeRecord,
  type UpsertInventoryInput
} from '@agentgo/contracts'
import { canonicalizeInventoryUrl, redactInventoryUrlPreview, sha256Text } from '@agentgo/domain'
import {
  AgentGoRepository,
  DiscoveryRuntimeRepository,
} from '@agentgo/db'
import { evaluateProbe } from '@agentgo/security-policy'
import { assertFrozenAssetManifest } from './asset-manifest-service'
import type {
  BrokeredBrowserRequest,
  BrokeredBrowserSession,
  BrowserNetworkBrokerDecision
} from './browser-recon-session'
import type { ExecutionPort } from './execution-port'
import { InventoryMergeService } from './inventory-merge-service'
import { InventoryService } from './inventory-service'
import {
  createEmptyHttpBodyShape,
  createMediatedReadTemplateVersion
} from './mediated-read-compiler'

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const SOURCE_TYPE = 'browser.recon'
const PRODUCER: InventoryMergeProducer = 'browser.recon'
const TEMPLATE_VERSION = createMediatedReadTemplateVersion()

export interface BrowserReconRunInput {
  readonly scanId: string
  readonly agentRunId: string
  readonly familyId: LegacyV1VulnerabilityFamily
  readonly startUrl: string
  readonly manifest: AssetManifest
  readonly timeoutMs: number
  readonly signal?: AbortSignal
}

export class BrowserReconService {
  readonly deltas: Array<{
    readonly producer: InventoryMergeProducer
    readonly capabilityId: string
    readonly counts: InventoryMergeCountBucket
  }> = []

  constructor(
    private readonly repository: AgentGoRepository,
    private readonly inventory: InventoryService,
    private readonly merge: InventoryMergeService,
    private readonly execution: ExecutionPort,
    private readonly runtime: DiscoveryRuntimeRepository,
    private readonly session: BrokeredBrowserSession
  ) {}

  async run(input: BrowserReconRunInput): Promise<{
    readonly blockedOrInventoried: number
    readonly fulfilled: number
  }> {
    const manifest = assertFrozenAssetManifest(input.manifest)
    const scan = await this.repository.getScan(input.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    if (scan.scopeSnapshotId !== manifest.scopeSnapshotId) {
      throw new Error('Frozen AssetManifest scope snapshot drifted from the scan.')
    }
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!scope) throw new Error('Scan scope snapshot is missing.')
    if (input.signal?.aborted) {
      await this.merge.persistReport({
        scanId: input.scanId,
        scopeSnapshotId: scan.scopeSnapshotId,
        deltas: []
      })
      return { blockedOrInventoried: 0, fulfilled: 0 }
    }
    let fulfilled = 0
    let blockedOrInventoried = 0
    const result = await this.session.run({
      startUrl: input.startUrl,
      timeoutMs: input.timeoutMs,
      ...(input.signal ? { signal: input.signal } : {}),
      broker: {
        handle: (request) =>
          this.handleRequest({
            request,
            input,
            manifest,
            scope
          })
      }
    })
    void result
    for (const delta of this.deltas) {
      blockedOrInventoried +=
        delta.counts.inventoryOnly +
        delta.counts.awaitingReview +
        delta.counts.unsupported +
        delta.counts.rejected +
        delta.counts.outOfScope
      fulfilled += delta.counts.created + delta.counts.merged
    }
    await this.merge.persistReport({
      scanId: input.scanId,
      scopeSnapshotId: scan.scopeSnapshotId,
      deltas: this.deltas
    })
    return { blockedOrInventoried, fulfilled }
  }

  async handleRequest(context: {
    readonly request: BrokeredBrowserRequest
    readonly input: BrowserReconRunInput
    readonly manifest: AssetManifest
    readonly scope: TargetScopeRecord
  }): Promise<BrowserNetworkBrokerDecision> {
    const { request, input, manifest, scope } = context
    if (input.signal?.aborted) {
      return this.finish({
        intent: toIntent(request, request.method.toUpperCase()),
        verdict: 'fail-closed',
        reason: 'Browser recon was cancelled.',
        input,
        scope,
        url: request.url,
        method: request.method.toUpperCase()
      })
    }
    const method = request.method.toUpperCase()
    const intent = toIntent(request, method)
    const parsed = safeUrl(request.url)
    if (!parsed) {
      return this.finish({
        intent,
        verdict: 'fail-closed',
        reason: 'URL is not a supported HTTP(S) target.',
        input,
        scope
      })
    }
    if (!this.scopeAllows(parsed.href, scope)) {
      return this.finish({
        intent,
        verdict: 'fail-closed',
        reason: 'Request is outside the scan scope.',
        input,
        scope,
        url: parsed.href,
        method
      })
    }
    if (WRITE_METHODS.has(method) || intent.kind === 'beacon' || intent.kind === 'form-submit') {
      const ingested = await this.ingest(input.scanId, scope, {
        method,
        url: parsed.href,
        capabilityIds: [],
        transport: 'standard-http'
      })
      return this.finish({
        intent,
        verdict: 'awaiting-review',
        reason: 'Write, beacon, and form-submit traffic is inventory-only.',
        input,
        scope,
        url: parsed.href,
        method,
        ingested
      })
    }
    if (intent.kind === 'websocket' || intent.kind === 'sse') {
      const ingested = await this.ingest(input.scanId, scope, {
        method: 'GET',
        url: parsed.href,
        capabilityIds: [],
        transport: intent.kind === 'websocket' ? 'websocket' : 'sse'
      })
      return this.finish({
        intent,
        verdict: 'unsupported',
        reason: 'WebSocket and SSE are inventory-only until a dedicated runner exists.',
        input,
        scope,
        url: parsed.href,
        method: 'GET',
        ingested
      })
    }

    const entry = matchManifest(manifest, parsed, intent.resourceType)
    const executable = Boolean(entry) || (await this.hasReviewedRead(input.scanId, method, parsed.href))
    const capabilityIds = executable ? (['http.reviewed-read'] as const) : []
    const ingested = await this.ingest(input.scanId, scope, {
      method,
      url: parsed.href,
      capabilityIds: [...capabilityIds],
      transport: 'standard-http',
      pageUrl: request.pageUrl,
      initiator: request.frameUrl
    })
    if (!executable || !ingested?.result) {
      return this.finish({
        intent,
        verdict: 'inventory-only',
        reason: 'Unknown GET is inventoried and not sent.',
        input,
        scope,
        url: parsed.href,
        method,
        ingested
      })
    }

    if (entry && ingested.result.requestVariant.reviewStatus === 'unreviewed') {
      await this.inventory.reviewVariant({
        scanId: input.scanId,
        requestVariantId: ingested.result.requestVariant.id,
        reviewStatus: 'reviewed',
        reviewedBy: manifest.reviewer
      })
    } else if (ingested.result.requestVariant.reviewStatus !== 'reviewed') {
      return this.finish({
        intent,
        verdict: 'awaiting-review',
        reason: 'Read-only fetch/XHR is waiting for review.',
        input,
        scope,
        url: parsed.href,
        method,
        ingested
      })
    }

    const executed = await this.execution.executeMediatedHttp({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      familyId: input.familyId,
      stepId: stepIdFor(intent),
      purpose: 'read',
      summary: 'Policy-mediated browser recon read',
      expectedEvidence: 'HTTP response hash-only evidence',
      adapterKind: 'http',
      method: method === 'HEAD' ? 'HEAD' : 'GET',
      endpointId: ingested.result.endpoint.id,
      requestVariantId: ingested.result.requestVariant.id,
      desiredUrl: parsed.href,
      ...(entry ? { expectedContentHash: entry.contentHash } : {}),
      timeoutMs: 10_000,
      maxResponseBytes: entry?.maxResponseBytes ?? 1_048_576,
      ...(input.signal ? { signal: input.signal } : {})
    })
    if (executed.result.status !== 'succeeded' || executed.result.responseBody === undefined) {
      return this.finish({
        intent,
        verdict: 'fail-closed',
        reason: executed.result.errorMessage ?? 'Mediated read failed closed.',
        input,
        scope,
        url: parsed.href,
        method,
        ingested,
        policyDecisionId: executed.policyDecisionIds.at(-1),
        leaseId: executed.leaseIds.at(-1),
        evidenceRef: executed.evidenceRefs.at(-1)
      })
    }
    if (entry && !hashesMatch(entry, executed.result.responseBody)) {
      return this.finish({
        intent,
        verdict: 'fail-closed',
        reason: 'Response hash does not match the frozen AssetManifest.',
        input,
        scope,
        url: parsed.href,
        method,
        ingested,
        policyDecisionId: executed.policyDecisionIds.at(-1),
        leaseId: executed.leaseIds.at(-1),
        evidenceRef: executed.evidenceRefs.at(-1)
      })
    }
    const headers = Object.fromEntries(
      Object.entries(executed.result.responseHeaders).filter(
        ([name]) => name.toLowerCase() !== 'set-cookie'
      )
    )
    return this.finish({
      intent,
      verdict: 'fulfill',
      reason: 'Mediated read completed through ExecutionPort.',
      input,
      scope,
      url: parsed.href,
      method,
      ingested,
      policyDecisionId: executed.policyDecisionIds.at(-1),
      leaseId: executed.leaseIds.at(-1),
      evidenceRef: executed.evidenceRefs.at(-1),
      fulfillment: {
        status: executed.result.statusCode ?? 200,
        headers,
        body: executed.result.responseBody
      }
    })
  }

  private async ingest(
    scanId: string,
    scope: TargetScopeRecord,
    input: {
      readonly method: string
      readonly url: string
      readonly capabilityIds: readonly string[]
      readonly transport: UpsertInventoryInput['transport']
      readonly pageUrl?: string
      readonly initiator?: string
    }
  ) {
    const sourceHash = sha256Text(
      `${SOURCE_TYPE}\0${input.method}\0${canonicalizeInventoryUrl(input.url)}\0${input.transport}`
    )
    const inventory: UpsertInventoryInput = {
      scanId,
      method: input.method,
      url: input.url,
      bodyShape: createEmptyHttpBodyShape(),
      codec: 'none',
      transport: input.transport,
      allowedHeaders: [],
      templateVersion: TEMPLATE_VERSION,
      requiredCapabilityIds: [...input.capabilityIds] as UpsertInventoryInput['requiredCapabilityIds'],
      selectors: [],
      preview: { url: input.url },
      source: {
        type: SOURCE_TYPE,
        sourceHash,
        ...(input.initiator ? { initiator: input.initiator } : {}),
        confidence: 1
      }
    }
    const ingested = await this.merge.ingest({
      producer: PRODUCER,
      scope,
      inventory
    })
    this.deltas.push({
      producer: PRODUCER,
      capabilityId: input.capabilityIds[0] ?? 'none',
      counts: ingested.reportDelta
    })
    return ingested
  }

  private async hasReviewedRead(
    scanId: string,
    method: string,
    url: string
  ): Promise<boolean> {
    const canonical = canonicalizeInventoryUrl(url)
    const endpoints = await this.repository.listInventoryEndpoints(scanId)
    const endpoint = endpoints.find(
      (item) => item.method === method && canonicalizeInventoryUrl(item.url) === canonical
    )
    if (!endpoint) return false
    const variants = await this.repository.listInventoryRequestVariants(scanId)
    return variants.some(
      (variant) =>
        variant.endpointId === endpoint.id &&
        variant.reviewStatus === 'reviewed' &&
        variant.executionClass === 'active-l1' &&
        variant.requiredCapabilityIds.includes('http.reviewed-read')
    )
  }

  private scopeAllows(url: string, scope: TargetScopeRecord): boolean {
    return evaluateProbe(
      {
        id: 'browser-recon-scope',
        kind: 'http-request',
        targetUrl: url,
        method: 'GET',
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: 'Browser recon scope check',
        expectedEvidence: 'none',
        maxRequests: 1,
        timeoutMs: 1_000,
        userApproved: false
      },
      scope
    ).allowed
  }

  private async finish(input: {
    readonly intent: BrowserNetworkIntent
    readonly verdict: BrowserNetworkVerdict
    readonly reason: string
    readonly input: BrowserReconRunInput
    readonly scope: TargetScopeRecord
    readonly url?: string
    readonly method?: string
    readonly ingested?: Awaited<ReturnType<InventoryMergeService['ingest']>>
    readonly policyDecisionId?: string
    readonly leaseId?: string
    readonly evidenceRef?: string
    readonly fulfillment?: BrowserNetworkBrokerDecision['fulfillment']
  }): Promise<BrowserNetworkBrokerDecision> {
    const observation: BrowserReconObservation = {
      observationId: randomUUID(),
      scanId: input.input.scanId,
      method: input.method ?? input.intent.method,
      sanitizedUrl: redactInventoryUrlPreview(input.url ?? input.intent.url),
      resourceType: input.intent.resourceType,
      intentKind: input.intent.kind,
      verdict: input.verdict,
      ...(input.intent.pageUrl ? { pageUrl: input.intent.pageUrl } : {}),
      ...(input.intent.frameUrl ? { frameUrl: input.intent.frameUrl } : {}),
      ...(input.intent.initiator ? { initiator: input.intent.initiator } : {}),
      capabilityVerdict:
        input.verdict === 'fulfill'
          ? 'active-l1'
          : input.verdict === 'unsupported'
            ? 'unsupported'
            : input.verdict === 'fail-closed'
              ? 'forbidden'
              : 'inventory-only',
      sourceRefs: input.ingested?.result ? [input.ingested.result.source.id] : [],
      ...(input.policyDecisionId ? { policyDecisionId: input.policyDecisionId } : {}),
      ...(input.leaseId ? { leaseId: input.leaseId } : {}),
      ...(input.evidenceRef ? { evidenceRef: input.evidenceRef } : {}),
      createdAt: new Date().toISOString()
    }
    await this.runtime.saveBrowserReconObservation(observation)
    return {
      verdict: input.verdict,
      reason: input.reason,
      intent: input.intent,
      ...(input.fulfillment ? { fulfillment: input.fulfillment } : {})
    }
  }
}

function toIntent(
  request: BrokeredBrowserRequest,
  method: string
): BrowserNetworkIntent {
  const resourceType = mapResourceType(request.resourceType)
  const kind =
    request.isNavigation || resourceType === 'document'
      ? 'navigation'
      : resourceType === 'fetch'
        ? 'fetch'
        : resourceType === 'xhr'
          ? 'xhr'
          : resourceType === 'ping'
            ? 'beacon'
            : resourceType === 'websocket'
              ? 'websocket'
              : resourceType === 'eventsource'
                ? 'sse'
                : method !== 'GET' && method !== 'HEAD'
                  ? 'form-submit'
                  : 'subresource'
  return {
    kind,
    method,
    url: request.url,
    resourceType,
    isNavigation: request.isNavigation,
    ...(request.pageUrl ? { pageUrl: request.pageUrl } : {}),
    ...(request.frameUrl ? { frameUrl: request.frameUrl } : {}),
    ...(request.frameUrl ? { initiator: request.frameUrl } : {})
  }
}

function mapResourceType(value: string): BrowserResourceType {
  switch (value) {
    case 'document':
    case 'script':
    case 'stylesheet':
    case 'image':
    case 'font':
    case 'fetch':
    case 'xhr':
    case 'websocket':
    case 'eventsource':
    case 'manifest':
      return value
    case 'ping':
      return 'ping'
    default:
      return 'other'
  }
}

function matchManifest(
  manifest: AssetManifest,
  url: URL,
  resourceType: BrowserResourceType
): AssetManifestEntry | undefined {
  const path = url.pathname
  const wanted = resourceTypeToAsset(resourceType)
  return manifest.entries.find(
    (entry) =>
      entry.origin === url.origin &&
      entry.normalizedPath === path &&
      (wanted === undefined || entry.resourceType === wanted)
  )
}

function resourceTypeToAsset(
  resourceType: BrowserResourceType
): AssetResourceType | undefined {
  switch (resourceType) {
    case 'document':
      return 'html'
    case 'script':
      return 'javascript'
    case 'stylesheet':
      return 'css'
    case 'image':
      return 'image'
    case 'font':
      return 'font'
    default:
      return undefined
  }
}

function hashesMatch(entry: AssetManifestEntry, body: Uint8Array): boolean {
  const digest = createHash('sha256').update(body).digest('hex')
  if (digest !== entry.contentHash) return false
  if (!entry.sri) return true
  const encoded = Buffer.from(createHash('sha256').update(body).digest()).toString('base64')
  return entry.sri === `sha256-${encoded}`
}

function safeUrl(value: string): URL | undefined {
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined
    return url
  } catch {
    return undefined
  }
}

function stepIdFor(intent: BrowserNetworkIntent): string {
  if (intent.kind === 'navigation') return 'recon.document'
  if (intent.kind === 'fetch' || intent.kind === 'xhr') return 'recon.xhr'
  return 'recon.asset'
}
