import { createHash, randomUUID } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { dirname, extname, join, relative, resolve, sep } from 'node:path'
import { and, asc, eq } from 'drizzle-orm'
import type { EvidenceSummary } from '@agentgo/contracts'
import type { AgentGoDatabase } from './database'
import { evidenceItems } from './schema'

export interface EvidenceWriteInput {
  workspaceId: string
  scanId: string
  interactionId?: string
  policyDecisionId?: string
  type: string
  mimeType: string
  content: string | Uint8Array
  source: string
  createdBy: string
  captureTool: string
  captureToolVersion: string
  derivedFrom?: string
  redactionState?: 'original' | 'redacted'
  retentionUntil?: string
}

export interface EvidenceItemRecord extends EvidenceSummary {
  workspaceId: string
  interactionId?: string
  policyDecisionId?: string
  filePath: string
  source: string
  createdBy: string
  captureTool: string
  captureToolVersion: string
  derivedFrom?: string
  retentionUntil?: string
}

export interface EvidenceReadResult {
  metadata: EvidenceItemRecord
  content: Buffer
}

function sha256(content: Uint8Array): string {
  return createHash('sha256').update(content).digest('hex')
}

function toBuffer(content: string | Uint8Array): Buffer {
  return typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content)
}

function toIso(value: number): string {
  return new Date(value).toISOString()
}

function extensionFor(mimeType: string): string {
  const normalized = mimeType.split(';')[0]?.trim().toLowerCase()
  const extensions: Record<string, string> = {
    'application/json': '.json',
    'application/har+json': '.har',
    'application/zip': '.zip',
    'text/plain': '.txt',
    'text/html': '.html',
    'text/markdown': '.md',
    'image/png': '.png',
    'image/jpeg': '.jpg'
  }
  return extensions[normalized ?? ''] ?? '.bin'
}

function assertInside(root: string, candidate: string): void {
  const relativePath = relative(root, candidate)
  if (relativePath.startsWith(`..${sep}`) || relativePath === '..' || resolve(candidate) === resolve(root)) {
    throw new Error('Evidence path escaped the configured root.')
  }
}

function workspaceDirectoryName(workspaceId: string): string {
  return createHash('sha256').update(workspaceId).digest('hex').slice(0, 20)
}

function mapEvidence(row: typeof evidenceItems.$inferSelect): EvidenceItemRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    scanId: row.scanId,
    ...(row.interactionId ? { interactionId: row.interactionId } : {}),
    ...(row.policyDecisionId ? { policyDecisionId: row.policyDecisionId } : {}),
    type: row.type,
    mimeType: row.mimeType,
    filePath: row.filePath,
    sha256: row.sha256,
    size: row.size,
    source: row.source,
    createdBy: row.createdBy,
    captureTool: row.captureTool,
    captureToolVersion: row.captureToolVersion,
    ...(row.derivedFrom ? { derivedFrom: row.derivedFrom } : {}),
    redactionState: row.redactionState,
    integrityStatus: row.integrityStatus,
    ...(row.retentionUntil !== null
      ? { retentionUntil: toIso(row.retentionUntil) }
      : {}),
    createdAt: toIso(row.createdAt)
  }
}

export function redactEvidenceText(value: string): string {
  const patterns: Array<[RegExp, string]> = [
    [/("?authorization"?\s*[:=]\s*"?)(?:bearer\s+)?[^\s,;"']+/gi, '$1[REDACTED]'],
    [/("?cookie"?\s*[:=]\s*"?)[^\r\n"']+/gi, '$1[REDACTED]'],
    [/("?set-cookie"?\s*[:=]\s*"?)[^\r\n"']+/gi, '$1[REDACTED]'],
    [/("?api[_-]?key"?\s*[:=]\s*"?)[^\s,;"']+/gi, '$1[REDACTED]'],
    [/("?password"?\s*[:=]\s*"?)[^\s,;"']+/gi, '$1[REDACTED]'],
    [/("?token"?\s*[:=]\s*"?)[^\s,;"']+/gi, '$1[REDACTED]']
  ]
  return patterns.reduce(
    (redacted, [pattern, replacement]) => redacted.replace(pattern, replacement),
    value
  )
}

export function isTextualEvidenceMimeType(mimeType: string): boolean {
  const normalized = mimeType.split(';')[0]?.trim().toLowerCase() ?? ''
  return (
    normalized.startsWith('text/') ||
    normalized === 'application/json' ||
    normalized.endsWith('+json')
  )
}

export class EvidenceStore {
  private readonly root: string

  constructor(
    private readonly database: AgentGoDatabase,
    rootDirectory: string
  ) {
    this.root = resolve(rootDirectory)
    mkdirSync(this.root, { recursive: true })
  }

  async save(input: EvidenceWriteInput): Promise<EvidenceItemRecord> {
    const content = toBuffer(input.content)
    const digest = sha256(content)
    const [existing] = await this.database.orm
      .select()
      .from(evidenceItems)
      .where(
        and(
          eq(evidenceItems.scanId, input.scanId),
          eq(evidenceItems.sha256, digest),
          eq(evidenceItems.type, input.type)
        )
      )
      .limit(1)
    if (existing) return mapEvidence(existing)

    const workspaceDirectory = workspaceDirectoryName(input.workspaceId)
    const relativePath = join(
      workspaceDirectory,
      'evidence',
      digest.slice(0, 2),
      `${digest}${extensionFor(input.mimeType)}`
    )
    const absolutePath = resolve(this.root, relativePath)
    assertInside(this.root, absolutePath)
    mkdirSync(dirname(absolutePath), { recursive: true })

    let createdFile = false
    if (!existsSync(absolutePath)) {
      writeFileSync(absolutePath, content, { flag: 'wx', mode: 0o600 })
      createdFile = true
    } else {
      const existingContent = readFileSync(absolutePath)
      if (sha256(existingContent) !== digest) {
        throw new Error('Existing content-addressed evidence file failed integrity verification.')
      }
    }

    const now = Date.now()
    const row: typeof evidenceItems.$inferSelect = {
      id: randomUUID(),
      workspaceId: input.workspaceId,
      scanId: input.scanId,
      interactionId: input.interactionId ?? null,
      policyDecisionId: input.policyDecisionId ?? null,
      type: input.type,
      mimeType: input.mimeType,
      filePath: relativePath,
      sha256: digest,
      size: content.byteLength,
      source: input.source,
      createdBy: input.createdBy,
      captureTool: input.captureTool,
      captureToolVersion: input.captureToolVersion,
      derivedFrom: input.derivedFrom ?? null,
      redactionState: input.redactionState ?? 'original',
      integrityStatus: 'verified',
      retentionUntil: input.retentionUntil ? Date.parse(input.retentionUntil) : null,
      createdAt: now
    }

    try {
      await this.database.orm.insert(evidenceItems).values(row)
    } catch (error) {
      if (createdFile && existsSync(absolutePath)) unlinkSync(absolutePath)
      throw error
    }
    return mapEvidence(row)
  }

  async getMetadata(id: string): Promise<EvidenceItemRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(evidenceItems)
      .where(eq(evidenceItems.id, id))
      .limit(1)
    return row ? mapEvidence(row) : undefined
  }

  async list(scanId: string): Promise<EvidenceItemRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(evidenceItems)
      .where(eq(evidenceItems.scanId, scanId))
      .orderBy(asc(evidenceItems.createdAt))
    return rows.map(mapEvidence)
  }

  async read(id: string): Promise<EvidenceReadResult> {
    const metadata = await this.getMetadata(id)
    if (!metadata) throw new Error('Evidence item does not exist.')
    const absolutePath = resolve(this.root, metadata.filePath)
    assertInside(this.root, absolutePath)
    const content = readFileSync(absolutePath)
    const integrityStatus =
      sha256(content) === metadata.sha256 && statSync(absolutePath).size === metadata.size
        ? 'verified'
        : 'failed'

    if (integrityStatus !== metadata.integrityStatus) {
      await this.database.orm
        .update(evidenceItems)
        .set({ integrityStatus })
        .where(eq(evidenceItems.id, id))
      metadata.integrityStatus = integrityStatus
    }
    if (integrityStatus === 'failed') {
      throw new Error('Evidence integrity verification failed.')
    }
    return { metadata, content }
  }

  async createRedactedTextDerivative(
    id: string,
    createdBy: string
  ): Promise<EvidenceItemRecord> {
    const original = await this.read(id)
    if (!isTextualEvidenceMimeType(original.metadata.mimeType)) {
      throw new Error('Only textual evidence can be automatically redacted.')
    }
    return this.save({
      workspaceId: original.metadata.workspaceId,
      scanId: original.metadata.scanId,
      ...(original.metadata.interactionId
        ? { interactionId: original.metadata.interactionId }
        : {}),
      ...(original.metadata.policyDecisionId
        ? { policyDecisionId: original.metadata.policyDecisionId }
        : {}),
      type: `${original.metadata.type}-redacted`,
      mimeType: original.metadata.mimeType,
      content: redactEvidenceText(original.content.toString('utf8')),
      source: 'derived-redaction',
      createdBy,
      captureTool: 'agentgo-evidence-store',
      captureToolVersion: '1.0.0',
      derivedFrom: original.metadata.id,
      redactionState: 'redacted',
      ...(original.metadata.retentionUntil
        ? { retentionUntil: original.metadata.retentionUntil }
        : {})
    })
  }

  resolveStoredPath(relativePath: string): string {
    const absolutePath = resolve(this.root, relativePath)
    assertInside(this.root, absolutePath)
    if (extname(absolutePath).length === 0) {
      throw new Error('Evidence path has no controlled extension.')
    }
    return absolutePath
  }

  async deleteUnreferencedFiles(relativePaths: string[]): Promise<number> {
    let deleted = 0
    for (const relativePath of new Set(relativePaths)) {
      const [referenced] = await this.database.orm
        .select({ id: evidenceItems.id })
        .from(evidenceItems)
        .where(eq(evidenceItems.filePath, relativePath))
        .limit(1)
      if (referenced) continue
      const absolutePath = resolve(this.root, relativePath)
      assertInside(this.root, absolutePath)
      if (existsSync(absolutePath)) {
        unlinkSync(absolutePath)
        deleted += 1
      }
    }
    return deleted
  }

  deleteWorkspaceArtifacts(workspaceId: string): boolean {
    const absolutePath = resolve(this.root, workspaceDirectoryName(workspaceId))
    assertInside(this.root, absolutePath)
    if (!existsSync(absolutePath)) return false
    rmSync(absolutePath, { recursive: true, force: true })
    return true
  }
}
