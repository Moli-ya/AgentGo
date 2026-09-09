import { randomUUID } from 'node:crypto'
import {
  DEFAULT_STATIC_DISCOVERY_BUDGET,
  StaticDiscoveryCandidateBatchSchema,
  StaticDiscoveryInputSchema,
  type StaticDiscoveryCandidate,
  type StaticDiscoveryCandidateBatch,
  type StaticDiscoveryResourceBudget,
  type TargetScope
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  ImportDiscoveryRepository
} from '@agentgo/db'
import { redactInventoryText } from '@agentgo/domain'
import { sha256Bytes } from '../importers/bounded-document'
import { extractHtmlCandidates } from './static/html'
import { extractJavaScriptCandidates } from './static/javascript'
import { extractSourceMapCandidates } from './static/source-map'

export class StaticDiscoveryService {
  constructor(
    private readonly repository: AgentGoRepository,
    private readonly discoveryRepository: ImportDiscoveryRepository,
    private readonly evidenceStore: EvidenceStore
  ) {}

  async analyze(input: unknown): Promise<StaticDiscoveryCandidateBatch> {
    const parsed = StaticDiscoveryInputSchema.parse(input)
    const scan = await this.repository.getScan(parsed.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    const scope = await this.repository.getScope(parsed.scopeSnapshotId)
    if (!scope) throw new Error('Scan scope snapshot does not exist.')
    if (scan.scopeSnapshotId !== parsed.scopeSnapshotId) {
      throw new Error('Static discovery scope snapshot does not match the scan.')
    }

    const read = await this.evidenceStore.read(parsed.artifactRef)
    if (read.metadata.scanId !== parsed.scanId) {
      throw new Error('Artifact does not belong to this scan.')
    }
    if (read.metadata.sha256 !== parsed.expectedHash) {
      throw new Error('Artifact content hash mismatch.')
    }

    const budget = parsed.budget ?? DEFAULT_STATIC_DISCOVERY_BUDGET
    if (read.content.byteLength > budget.maxFileBytes) {
      throw new Error('Static discovery file exceeds the size budget.')
    }

    const bytes = new Uint8Array(read.content)
    const artifactHash = sha256Bytes(bytes)
    if (artifactHash !== parsed.expectedHash) {
      throw new Error('Artifact bytes hash mismatch.')
    }

    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    const extracted = extractForMediaType(
      parsed.mediaType,
      text,
      bytes,
      scope,
      parsed.baseUrlHint,
      budget
    )
    const candidates = dedupeArtifactCandidates(extracted.candidates)
    const batch = StaticDiscoveryCandidateBatchSchema.parse({
      schemaVersion: 'agentgo.static-discovery.v1',
      batchId: randomUUID(),
      scanId: parsed.scanId,
      artifactRef: parsed.artifactRef,
      artifactHash,
      mediaType: parsed.mediaType,
      producer: 'static-offline',
      candidates,
      warnings: extracted.warnings.map((warning) => redactInventoryText(warning, 2_048)),
      createdAt: new Date().toISOString()
    })
    return this.discoveryRepository.saveStaticDiscoveryBatch(batch)
  }
}

function extractForMediaType(
  mediaType: string,
  text: string,
  bytes: Uint8Array,
  scope: TargetScope,
  baseUrlHint: string | undefined,
  budget: StaticDiscoveryResourceBudget
): { readonly candidates: StaticDiscoveryCandidate[]; readonly warnings: string[] } {
  if (mediaType === 'text/html') {
    return extractHtmlCandidates(text, scope, baseUrlHint, budget)
  }
  if (mediaType === 'application/javascript' || mediaType === 'text/javascript') {
    return extractJavaScriptCandidates(text, scope, baseUrlHint, budget)
  }
  if (mediaType === 'application/json') {
    return extractSourceMapCandidates(bytes, scope, baseUrlHint, budget)
  }
  return {
    candidates: [],
    warnings: [`Media type ${mediaType} is not a static discovery producer.`]
  }
}

function dedupeArtifactCandidates(
  candidates: readonly StaticDiscoveryCandidate[]
): StaticDiscoveryCandidate[] {
  const seen = new Set<string>()
  const output: StaticDiscoveryCandidate[] = []
  for (const candidate of candidates) {
    if (seen.has(candidate.key)) continue
    seen.add(candidate.key)
    output.push(candidate)
  }
  return output
}
