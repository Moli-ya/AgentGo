import { randomUUID } from 'node:crypto'
import {
  AssetManifestSchema,
  type AssetManifest,
  type AssetManifestEntry
} from '@agentgo/contracts'
import { AgentGoRepository, ImportDiscoveryRepository } from '@agentgo/db'
import { stableInventoryHash } from '@agentgo/domain'

export class AssetManifestService {
  constructor(
    private readonly repository: AgentGoRepository,
    private readonly discoveryRepository: ImportDiscoveryRepository
  ) {}

  async saveDraft(input: {
    readonly scanId: string
    readonly scopeSnapshotId: string
    readonly reviewer: string
    readonly entries: readonly AssetManifestEntry[]
  }): Promise<AssetManifest> {
    const scan = await this.repository.getScan(input.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    if (scan.scopeSnapshotId !== input.scopeSnapshotId) {
      throw new Error('Asset manifest scope snapshot does not match the scan.')
    }
    const createdAt = new Date().toISOString()
    const unsigned = {
      schemaVersion: 'agentgo.asset-manifest.v1' as const,
      manifestId: randomUUID(),
      manifestVersion: 1,
      scanId: input.scanId,
      scopeSnapshotId: input.scopeSnapshotId,
      reviewer: input.reviewer,
      frozen: false,
      entries: input.entries.map((entry) => assertFreezeableEntry(entry, input.scopeSnapshotId)),
      createdAt
    }
    const manifest = AssetManifestSchema.parse({
      ...unsigned,
      manifestHash: stableInventoryHash(unsigned)
    })
    return this.discoveryRepository.saveAssetManifest(manifest)
  }

  async freeze(input: {
    readonly manifestId: string
    readonly manifestHash: string
    readonly reviewer: string
    readonly scopeSnapshotId: string
  }): Promise<AssetManifest> {
    const current = await this.discoveryRepository.getAssetManifest(input.manifestId)
    if (!current) throw new Error('Asset manifest does not exist.')
    if (current.frozen) {
      if (current.manifestHash !== input.manifestHash) {
        throw new Error('Frozen asset manifest hash mismatch.')
      }
      return current
    }
    if (current.manifestHash !== input.manifestHash) {
      throw new Error('Asset manifest hash mismatch.')
    }
    if (current.reviewer !== input.reviewer) {
      throw new Error('Asset manifest reviewer mismatch.')
    }
    if (current.scopeSnapshotId !== input.scopeSnapshotId) {
      throw new Error('Asset manifest scope snapshot mismatch.')
    }
    const scan = await this.repository.getScan(current.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    if (scan.scopeSnapshotId !== current.scopeSnapshotId) {
      throw new Error('Scan scope snapshot changed after the manifest draft.')
    }
    for (const entry of current.entries) {
      assertFreezeableEntry(entry, current.scopeSnapshotId)
    }
    const frozenAt = new Date().toISOString()
    const unsigned = {
      schemaVersion: current.schemaVersion,
      manifestId: current.manifestId,
      manifestVersion: current.manifestVersion,
      scanId: current.scanId,
      scopeSnapshotId: current.scopeSnapshotId,
      reviewer: current.reviewer,
      frozen: true,
      entries: current.entries,
      createdAt: current.createdAt,
      frozenAt
    }
    const frozen = AssetManifestSchema.parse({
      ...unsigned,
      manifestHash: stableInventoryHash(unsigned)
    })
    return this.discoveryRepository.freezeAssetManifest(frozen)
  }
}

export async function resolveFrozenAssetHtml(input: {
  readonly manifests: readonly AssetManifest[]
  readonly url: string
  readonly readArtifact: (artifactRef: string) => Promise<{ readonly content: Uint8Array | string }>
}): Promise<string | undefined> {
  let parsed: URL
  try {
    parsed = new URL(input.url)
  } catch {
    return undefined
  }
  const origin = parsed.origin
  const path = parsed.pathname
  for (const manifest of input.manifests) {
    if (!manifest.frozen) continue
    const entry = manifest.entries.find(
      (item) => item.origin === origin && item.normalizedPath === path
    )
    if (!entry) continue
    const read = await input.readArtifact(entry.artifactRef)
    const html = typeof read.content === 'string'
      ? read.content
      : Buffer.from(read.content).toString('utf8')
    if (html.trim().length === 0) continue
    return html
  }
  return undefined
}

export function assertFrozenAssetManifest(manifest: AssetManifest): AssetManifest {
  const parsed = AssetManifestSchema.parse(manifest)
  if (!parsed.frozen || parsed.frozenAt === undefined) {
    throw new Error('Day13 can only consume a frozen AssetManifest.')
  }
  const unsigned = {
    schemaVersion: parsed.schemaVersion,
    manifestId: parsed.manifestId,
    manifestVersion: parsed.manifestVersion,
    scanId: parsed.scanId,
    scopeSnapshotId: parsed.scopeSnapshotId,
    reviewer: parsed.reviewer,
    frozen: parsed.frozen,
    entries: parsed.entries,
    createdAt: parsed.createdAt,
    frozenAt: parsed.frozenAt
  }
  if (parsed.manifestHash !== stableInventoryHash(unsigned)) {
    throw new Error('Asset manifest hash changed after freeze.')
  }
  return parsed
}

function assertFreezeableEntry(
  entry: AssetManifestEntry,
  scopeSnapshotId: string
): AssetManifestEntry {
  if (entry.scopeSnapshotId !== scopeSnapshotId) {
    throw new Error('Asset entry scope snapshot must match the manifest.')
  }
  if (entry.origin.includes('*') || entry.normalizedPath.includes('*')) {
    throw new Error('Wildcard origin or path cannot be frozen.')
  }
  if (/[?#]/.test(entry.normalizedPath)) {
    throw new Error('Asset path cannot contain query or fragment.')
  }
  if (!entry.normalizedPath.startsWith('/')) {
    throw new Error('Asset path must be origin-absolute.')
  }
  if (!entry.contentHash) {
    throw new Error('Asset entries require a content hash.')
  }
  return entry
}
