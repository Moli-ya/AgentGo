import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID
} from 'node:crypto'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { join, relative, resolve, sep } from 'node:path'
import { and, asc, eq, isNull, lte, ne, sql } from 'drizzle-orm'
import {
  EvidenceArtifactDraftSchema,
  PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
  PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
  PROTECTED_EVIDENCE_PROTECTION_SCHEME,
  PROTECTED_EVIDENCE_POLICY_VERSION,
  type EvidenceArtifactDraft,
  type EvidenceSummary
} from '@agentgo/contracts'
import { canonicalJson } from '@agentgo/domain'
import type { SecretProtector } from './credential-store'
import type { AgentGoDatabase } from './database'
import { isEvidenceItemReferenced } from './evidence-reference-guard'
import {
  auditLogs,
  evidenceItems,
  policyDecisions,
  probeProposals,
  protectedEvidenceItems,
  scans,
  targets
} from './schema'

const PROTECTED_ORIGINAL_TYPE = 'evidence-capture-protected-original'
const PROTECTED_DERIVATIVE_TYPE = 'evidence-capture-protected-derivative'
const PROTECTED_STORAGE_SCHEMA_VERSION =
  'protected-evidence-storage.v1' as const
const PROTECTED_ENCRYPTION_ALGORITHM =
  'aes-256-gcm+os-key-wrap' as const
const PROTECTED_AAD_DOMAIN = 'agentgo.protected-evidence.aad.v1'

type ProtectedOriginalArtifact = Extract<
  EvidenceArtifactDraft,
  { type: 'evidence-capture-protected-original' }
>

type ProtectedEvidenceRecord = {
  evidence: typeof evidenceItems.$inferSelect
  protected: typeof protectedEvidenceItems.$inferSelect
}

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
  redactionState: 'redacted'
  retentionUntil?: string
}

export type EvidenceItemRecord = EvidenceSummary & {
  workspaceId: string
  interactionId?: string
  policyDecisionId?: string
  filePath: string
  source: string
  createdBy: string
  captureTool: string
  captureToolVersion: string
  protectionState: 'unprotected' | 'protected-original'
  availabilityState?: 'available' | 'expired'
  plaintextSha256?: string
  plaintextSize?: number
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

export interface ProtectedEvidenceWriteInput {
  artifact: ProtectedOriginalArtifact
  content: Uint8Array
}

export interface ProtectedEvidenceWriteResult {
  original: EvidenceItemRecord
  derivative: EvidenceItemRecord
}

export interface ProtectedEvidenceSweepResult {
  expiredItems: number
  deletedCiphertextFiles: number
}

export interface EvidenceStoreOptions {
  protector?: SecretProtector
  clock?: () => number
}

interface InternalEvidenceWriteInput
  extends Omit<EvidenceWriteInput, 'redactionState'> {
  redactionState: 'original' | 'redacted'
}

interface InternalSaveOptions {
  evidenceId?: string
  forceBinaryExtension?: boolean
}

class ProtectedEvidenceAccessDeniedError extends Error {
  constructor(
    readonly metadata: EvidenceItemRecord,
    message = 'Protected Evidence cannot be read through the generic API.'
  ) {
    super(message)
    this.name = 'ProtectedEvidenceAccessDeniedError'
  }
}

class ProtectedEvidenceIntegrityError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ProtectedEvidenceIntegrityError'
  }
}

const CONTROLLED_EVIDENCE_EXTENSIONS = new Set([
  '.bin',
  '.har',
  '.html',
  '.jpg',
  '.json',
  '.md',
  '.png',
  '.txt',
  '.zip'
])

const evidenceMutationTails = new Map<string, Promise<void>>()

function serializeEvidenceMutation<T>(
  root: string,
  operation: () => Promise<T>
): Promise<T> {
  const previous = evidenceMutationTails.get(root) ?? Promise.resolve()
  const result = previous.then(operation, operation)
  const tail = result.then(
    () => undefined,
    () => undefined
  )
  evidenceMutationTails.set(root, tail)
  void tail.then(() => {
    if (evidenceMutationTails.get(root) === tail) {
      evidenceMutationTails.delete(root)
    }
  })
  return result
}

function assertInside(root: string, candidate: string): void {
  const relativePath = relative(root, candidate)
  if (relativePath.startsWith(`..${sep}`) || relativePath === '..' || resolve(candidate) === resolve(root)) {
    throw new Error('Evidence path escaped the configured root.')
  }
}

interface ControlledEvidencePath {
  canonicalPath: string
  workspaceDirectory: string
  bucket: string
  fileName: string
}

function parseControlledEvidencePath(value: string): ControlledEvidencePath {
  const canonicalPath = value.replace(/\\/gu, '/')
  const match =
    /^(?<workspace>[0-9a-f]{20})\/evidence\/(?<bucket>[0-9a-f]{2})\/(?<fileName>(?<digest>[0-9a-f]{64})(?<extension>\.[a-z0-9]+))$/u.exec(
      canonicalPath
    )
  const workspaceDirectory = match?.groups?.workspace
  const bucket = match?.groups?.bucket
  const digest = match?.groups?.digest
  const fileName = match?.groups?.fileName
  const extension = match?.groups?.extension
  if (
    !workspaceDirectory ||
    !bucket ||
    !digest ||
    !fileName ||
    !extension ||
    !CONTROLLED_EVIDENCE_EXTENSIONS.has(extension) ||
    digest.slice(0, 2) !== bucket
  ) {
    throw new Error('Evidence path is not a controlled content-addressed path.')
  }
  return {
    canonicalPath,
    workspaceDirectory,
    bucket,
    fileName
  }
}

function assertSafeDirectory(root: string, directory: string): void {
  const metadata = lstatSync(directory)
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error('Evidence directory contains a symbolic link or reparse point.')
  }
  assertInside(root, realpathSync(directory))
}

function ensureSafeDirectory(
  root: string,
  parent: string,
  name: string
): string {
  const directory = resolve(parent, name)
  assertInside(root, directory)
  if (!existsSync(directory)) {
    mkdirSync(directory)
  }
  assertSafeDirectory(root, directory)
  return directory
}

function resolveControlledEvidenceFile(
  root: string,
  value: string
): {
  canonicalPath: string
  absolutePath: string
  exists: boolean
  size?: number
} {
  const controlled = parseControlledEvidencePath(value)
  const workspaceDirectory = resolve(
    root,
    controlled.workspaceDirectory
  )
  const evidenceDirectory = resolve(workspaceDirectory, 'evidence')
  const bucketDirectory = resolve(evidenceDirectory, controlled.bucket)
  const absolutePath = resolve(bucketDirectory, controlled.fileName)
  assertInside(root, workspaceDirectory)
  assertInside(root, evidenceDirectory)
  assertInside(root, bucketDirectory)
  assertInside(root, absolutePath)
  for (const directory of [
    workspaceDirectory,
    evidenceDirectory,
    bucketDirectory
  ]) {
    if (!existsSync(directory)) {
      return {
        canonicalPath: controlled.canonicalPath,
        absolutePath,
        exists: false
      }
    }
    assertSafeDirectory(root, directory)
  }
  if (!existsSync(absolutePath)) {
    return {
      canonicalPath: controlled.canonicalPath,
      absolutePath,
      exists: false
    }
  }
  const metadata = lstatSync(absolutePath)
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error('Evidence content path is not a regular file.')
  }
  assertInside(root, realpathSync(absolutePath))
  return {
    canonicalPath: controlled.canonicalPath,
    absolutePath,
    exists: true,
    size: metadata.size
  }
}

function listControlledEvidenceFiles(root: string): string[] {
  const candidates: string[] = []
  for (const workspaceEntry of readdirSync(root, { withFileTypes: true })) {
    if (
      workspaceEntry.isSymbolicLink() ||
      !workspaceEntry.isDirectory() ||
      !/^[0-9a-f]{20}$/u.test(workspaceEntry.name)
    ) {
      continue
    }
    const workspaceDirectory = join(root, workspaceEntry.name)
    const evidenceDirectory = join(workspaceDirectory, 'evidence')
    try {
      assertSafeDirectory(root, workspaceDirectory)
      if (!existsSync(evidenceDirectory)) continue
      assertSafeDirectory(root, evidenceDirectory)
    } catch {
      continue
    }
    for (const bucketEntry of readdirSync(evidenceDirectory, {
      withFileTypes: true
    })) {
      if (
        bucketEntry.isSymbolicLink() ||
        !bucketEntry.isDirectory() ||
        !/^[0-9a-f]{2}$/u.test(bucketEntry.name)
      ) {
        continue
      }
      const bucketDirectory = join(evidenceDirectory, bucketEntry.name)
      try {
        assertSafeDirectory(root, bucketDirectory)
      } catch {
        continue
      }
      for (const fileEntry of readdirSync(bucketDirectory, {
        withFileTypes: true
      })) {
        if (fileEntry.isSymbolicLink() || !fileEntry.isFile()) continue
        const candidate = [
          workspaceEntry.name,
          'evidence',
          bucketEntry.name,
          fileEntry.name
        ].join('/')
        try {
          if (resolveControlledEvidenceFile(root, candidate).exists) {
            candidates.push(candidate)
          }
        } catch {
          // Unknown links, junctions and non-regular files are never followed.
        }
      }
    }
  }
  return candidates
}

function workspaceDirectoryName(workspaceId: string): string {
  return createHash('sha256').update(workspaceId).digest('hex').slice(0, 20)
}

function mapEvidence(
  row: typeof evidenceItems.$inferSelect,
  protectedRow?: typeof protectedEvidenceItems.$inferSelect | null
): EvidenceItemRecord {
  const common = {
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
    integrityStatus: row.integrityStatus,
    createdAt: toIso(row.createdAt)
  }
  if (protectedRow) {
    if (
      row.type !== PROTECTED_ORIGINAL_TYPE ||
      row.redactionState !== 'original' ||
      row.retentionUntil === null
    ) {
      throw new Error('Protected Evidence metadata is inconsistent.')
    }
    return {
      ...common,
      redactionState: 'original',
      protectionState: 'protected-original',
      availabilityState: protectedRow.availabilityState,
      plaintextSha256: protectedRow.plaintextSha256,
      plaintextSize: protectedRow.plaintextSize,
      retentionUntil: toIso(row.retentionUntil)
    }
  }
  if (row.type === PROTECTED_ORIGINAL_TYPE) {
    throw new Error('Protected Evidence envelope is missing.')
  }
  if (row.redactionState !== 'redacted') {
    throw new Error('Unprotected original Evidence is not readable.')
  }
  return {
    ...common,
    redactionState: 'redacted',
    protectionState: 'unprotected',
    ...(row.derivedFrom ? { derivedFrom: row.derivedFrom } : {}),
    ...(row.retentionUntil !== null
      ? { retentionUntil: toIso(row.retentionUntil) }
      : {})
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
  private readonly pendingFileCleanup = new Set<string>()
  private readonly protector?: SecretProtector
  private readonly clock: () => number

  constructor(
    private readonly database: AgentGoDatabase,
    rootDirectory: string,
    options: EvidenceStoreOptions = {}
  ) {
    const requestedRoot = resolve(rootDirectory)
    mkdirSync(requestedRoot, { recursive: true })
    const physicalRoot = realpathSync(requestedRoot)
    if (!lstatSync(physicalRoot).isDirectory()) {
      throw new Error('Evidence root is not a directory.')
    }
    this.root = physicalRoot
    this.protector = options.protector
    this.clock = options.clock ?? Date.now
  }

  #withMutationBoundary<T>(operation: () => Promise<T>): Promise<T> {
    return serializeEvidenceMutation(this.root, operation)
  }

  async #retryPendingFileCleanupUnlocked(): Promise<void> {
    if (this.pendingFileCleanup.size === 0) return
    const pending = [...this.pendingFileCleanup]
    try {
      await this.#deleteUnreferencedFilesUnlocked(pending)
      for (const relativePath of pending) {
        this.pendingFileCleanup.delete(relativePath)
      }
    } catch {
      // Keep every candidate queued. Retrying an already deleted path is safe.
    }
  }

  save(input: EvidenceWriteInput): Promise<EvidenceItemRecord> {
    if (input.redactionState !== 'redacted') {
      return Promise.reject(
        new Error(
          'Unprotected Evidence writes must be explicitly redacted before persistence.'
        )
      )
    }
    if (
      input.type === PROTECTED_ORIGINAL_TYPE ||
      input.type === PROTECTED_DERIVATIVE_TYPE
    ) {
      return Promise.reject(
        new Error('Protected Evidence types require the protected persistence API.')
      )
    }
    return this.#withMutationBoundary(async () => {
      const evidence = await this.#saveUnlocked(input)
      await this.#retryPendingFileCleanupUnlocked()
      return evidence
    })
  }

  async #saveUnlocked(
    input: InternalEvidenceWriteInput,
    options: InternalSaveOptions = {}
  ): Promise<EvidenceItemRecord> {
    const content = toBuffer(input.content)
    const digest = sha256(content)
    const workspaceDirectory = workspaceDirectoryName(input.workspaceId)
    const relativePath = [
      workspaceDirectory,
      'evidence',
      digest.slice(0, 2),
      `${digest}${
        options.forceBinaryExtension ? '.bin' : extensionFor(input.mimeType)
      }`
    ].join('/')
    const controlled = parseControlledEvidencePath(relativePath)
    const absolutePath = resolve(
      this.root,
      controlled.workspaceDirectory,
      'evidence',
      controlled.bucket,
      controlled.fileName
    )
    assertInside(this.root, absolutePath)
    let createdFile = false
    const now = this.clock()
    const row: typeof evidenceItems.$inferSelect = {
      id: options.evidenceId ?? randomUUID(),
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
      redactionState: input.redactionState,
      integrityStatus: 'verified',
      retentionUntil: input.retentionUntil ? Date.parse(input.retentionUntil) : null,
      createdAt: now
    }
    try {
      return await this.database.orm.transaction(
        async (transaction) => {
          const workspacePath = ensureSafeDirectory(
            this.root,
            this.root,
            controlled.workspaceDirectory
          )
          const evidencePath = ensureSafeDirectory(
            this.root,
            workspacePath,
            'evidence'
          )
          const bucketPath = ensureSafeDirectory(
            this.root,
            evidencePath,
            controlled.bucket
          )
          const transactionPath = resolve(
            bucketPath,
            controlled.fileName
          )
          if (transactionPath !== absolutePath) {
            throw new Error('Evidence content path changed during persistence.')
          }
          if (!existsSync(absolutePath)) {
            try {
              writeFileSync(absolutePath, content, {
                flag: 'wx',
                mode: 0o600
              })
              createdFile = true
            } catch (error) {
              if (
                !error ||
                typeof error !== 'object' ||
                !('code' in error) ||
                error.code !== 'EEXIST'
              ) {
                throw error
              }
            }
          }
          const storedFile = resolveControlledEvidenceFile(
            this.root,
            relativePath
          )
          if (!storedFile.exists) {
            throw new Error(
              'Evidence content file disappeared before persistence.'
            )
          }
          const existingContent = readFileSync(absolutePath)
          if (sha256(existingContent) !== digest) {
            throw new Error(
              'Existing content-addressed evidence file failed integrity verification.'
            )
          }
          try {
            await transaction.insert(evidenceItems).values(row)
          } catch (error) {
            if (createdFile) {
              try {
                const [referenced] = await transaction
                  .select({ id: evidenceItems.id })
                  .from(evidenceItems)
                  .where(
                    sql`replace(${evidenceItems.filePath}, ${'\\'}, ${'/'}) = ${relativePath}`
                  )
                  .limit(1)
                if (!referenced && existsSync(absolutePath)) {
                  unlinkSync(absolutePath)
                }
              } catch {
                this.pendingFileCleanup.add(relativePath)
              }
            }
            throw error
          }
          return mapEvidence(row)
        },
        { behavior: 'immediate' }
      )
    } catch (error) {
      if (createdFile && existsSync(absolutePath)) {
        this.pendingFileCleanup.add(relativePath)
      }
      throw error
    }
  }

  async getMetadata(id: string): Promise<EvidenceItemRecord | undefined> {
    const [row] = await this.database.orm
      .select({
        evidence: evidenceItems,
        protected: protectedEvidenceItems
      })
      .from(evidenceItems)
      .leftJoin(
        protectedEvidenceItems,
        eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
      )
      .where(eq(evidenceItems.id, id))
      .limit(1)
    return row ? mapEvidence(row.evidence, row.protected) : undefined
  }

  async list(scanId: string): Promise<EvidenceItemRecord[]> {
    const rows = await this.database.orm
      .select({
        evidence: evidenceItems,
        protected: protectedEvidenceItems
      })
      .from(evidenceItems)
      .leftJoin(
        protectedEvidenceItems,
        eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
      )
      .where(eq(evidenceItems.scanId, scanId))
      .orderBy(asc(evidenceItems.createdAt))
    return rows.map((row) => mapEvidence(row.evidence, row.protected))
  }

  read(id: string): Promise<EvidenceReadResult> {
    return this.#withMutationBoundary(async () => {
      const metadata = await this.getMetadata(id)
      if (metadata?.protectionState === 'protected-original') {
        await this.#addProtectedAudit(metadata, 'access-denied', {
          purpose: 'generic-read',
          reasonCode: 'protected-api-required'
        })
        throw new ProtectedEvidenceAccessDeniedError(metadata)
      }
      return this.#readUnlocked(id)
    })
  }

  async #readUnlocked(id: string): Promise<EvidenceReadResult> {
    const result = await this.database.orm.transaction(
      async (transaction) => {
        const [row] = await transaction
          .select({
            evidence: evidenceItems,
            protected: protectedEvidenceItems
          })
          .from(evidenceItems)
          .leftJoin(
            protectedEvidenceItems,
            eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
          )
          .where(eq(evidenceItems.id, id))
          .limit(1)
        if (!row) throw new Error('Evidence item does not exist.')
        const metadata = mapEvidence(row.evidence, row.protected)
        if (row.protected) {
          throw new ProtectedEvidenceAccessDeniedError(metadata)
        }
        const storedFile = resolveControlledEvidenceFile(
          this.root,
          metadata.filePath
        )
        if (!storedFile.exists || storedFile.size === undefined) {
          throw new Error('Evidence content file does not exist.')
        }
        const content = readFileSync(storedFile.absolutePath)
        const integrityStatus =
          sha256(content) === metadata.sha256 &&
          storedFile.size === metadata.size
            ? 'verified'
            : 'failed'

        if (integrityStatus !== metadata.integrityStatus) {
          await transaction
            .update(evidenceItems)
            .set({ integrityStatus })
            .where(eq(evidenceItems.id, id))
          metadata.integrityStatus = integrityStatus
        }
        return { metadata, content, integrityStatus }
      },
      { behavior: 'immediate' }
    )
    if (result.integrityStatus === 'failed') {
      throw new Error('Evidence integrity verification failed.')
    }
    return {
      metadata: result.metadata,
      content: result.content
    }
  }

  createRedactedTextDerivative(
    id: string,
    createdBy: string
  ): Promise<EvidenceItemRecord> {
    return this.#withMutationBoundary(async () => {
      const original = await this.#readUnlocked(id)
      if (!isTextualEvidenceMimeType(original.metadata.mimeType)) {
        throw new Error('Only textual evidence can be automatically redacted.')
      }
      const derivative = await this.#saveUnlocked({
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
      await this.#retryPendingFileCleanupUnlocked()
      return derivative
    })
  }

  saveProtectedOriginalWithDerivative(
    input: ProtectedEvidenceWriteInput
  ): Promise<ProtectedEvidenceWriteResult> {
    return this.#withMutationBoundary(async () => {
      const parsedArtifact = EvidenceArtifactDraftSchema.safeParse(
        input.artifact
      )
      if (
        !parsedArtifact.success ||
        parsedArtifact.data.type !== PROTECTED_ORIGINAL_TYPE
      ) {
        throw new Error('Protected Evidence artifact is invalid.')
      }
      const artifact = parsedArtifact.data
      const plan = artifact.payload.protectionPlan
      if (
        plan.protectionScheme !== PROTECTED_EVIDENCE_PROTECTION_SCHEME ||
        plan.accessPolicyId !== PROTECTED_EVIDENCE_ACCESS_POLICY_ID ||
        plan.accessPolicyVersion !== PROTECTED_EVIDENCE_POLICY_VERSION ||
        plan.derivativePolicyId !==
          PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID ||
        plan.derivativePolicyVersion !== PROTECTED_EVIDENCE_POLICY_VERSION
      ) {
        throw new Error('Protected Evidence policy is not supported.')
      }
      const now = this.clock()
      const [authorization] = await this.database.orm
        .select({
          workspaceId: targets.workspaceId,
          allowed: policyDecisions.allowed,
          policyCreatedAt: policyDecisions.createdAt,
          policyValidUntil: policyDecisions.validUntil
        })
        .from(policyDecisions)
        .innerJoin(
          probeProposals,
          eq(policyDecisions.proposalId, probeProposals.id)
        )
        .innerJoin(scans, eq(probeProposals.scanId, scans.id))
        .innerJoin(targets, eq(scans.targetId, targets.id))
        .where(
          and(
            eq(policyDecisions.id, artifact.policyDecisionId),
            eq(scans.id, artifact.scanId)
          )
        )
        .limit(1)
      const occurredAt = Date.parse(artifact.payload.captureContext.occurredAt)
      if (
        !authorization ||
        !authorization.allowed ||
        authorization.policyValidUntil === null ||
        occurredAt < authorization.policyCreatedAt ||
        occurredAt > authorization.policyValidUntil ||
        occurredAt > now
      ) {
        throw new Error(
          'Protected Evidence policy authorization is missing or outside its validity window.'
        )
      }
      const retentionUntil = assertCanonicalFutureIso(
        artifact.payload.retentionUntil,
        now,
        'Protected Evidence retention'
      )
      if (
        retentionUntil >
        now + artifact.payload.protectionPlan.retentionSeconds * 1_000
      ) {
        throw new Error(
          'Protected Evidence retention exceeds its authorized duration.'
        )
      }
      const plaintext = toBuffer(input.content)
      let dataKey: Buffer | undefined
      let nonce: Buffer | undefined
      let aad: Buffer | undefined
      let ciphertext: Buffer | undefined
      let wrappedDataKey: Buffer | undefined
      let derivativeContent: Buffer | undefined
      const createdPaths = new Set<string>()
      try {
        if (
          plaintext.byteLength !== artifact.payload.plaintextSize ||
          sha256(plaintext) !== artifact.sourceHash.digest ||
          artifact.sourceHash.coverage !== 'complete' ||
          artifact.sourceHash.basis !== 'source-bytes'
        ) {
          throw new Error(
            'Protected Evidence plaintext does not match its policy hash.'
          )
        }
        const [existing] = await this.database.orm
          .select({
            evidence: evidenceItems,
            protected: protectedEvidenceItems
          })
          .from(protectedEvidenceItems)
          .innerJoin(
            evidenceItems,
            eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
          )
          .where(
            eq(
              protectedEvidenceItems.captureDecisionId,
              artifact.captureDecisionId
            )
          )
          .limit(1)
        if (existing) {
          if (
            existing.protected.availabilityState !== 'available' ||
            existing.protected.plaintextSha256 !==
              artifact.sourceHash.digest ||
            existing.protected.plaintextSize !== plaintext.byteLength ||
            canonicalJson(existing.protected.captureArtifact) !==
              canonicalJson(artifact)
          ) {
            throw new Error(
              'Protected Evidence capture decision conflicts with an existing item.'
            )
          }
          const [derivativeRow] = await this.database.orm
            .select()
            .from(evidenceItems)
            .where(
              eq(
                evidenceItems.id,
                existing.protected.derivativeEvidenceId
              )
            )
            .limit(1)
          if (
            !derivativeRow ||
            derivativeRow.sha256 !== existing.protected.derivativeSha256 ||
            derivativeRow.derivedFrom !== existing.evidence.id
          ) {
            throw new Error(
              'Protected Evidence derivative binding is incomplete.'
            )
          }
          return {
            original: mapEvidence(
              existing.evidence,
              existing.protected
            ),
            derivative: mapEvidence(derivativeRow)
          }
        }
        if (!this.protector?.isAvailable()) {
          throw new Error('Protected Evidence encryption is unavailable.')
        }

        const evidenceId = randomUUID()
        const derivativeId = randomUUID()
        dataKey = randomBytes(32)
        nonce = randomBytes(12)
        aad = protectedEvidenceAad({
          evidenceId,
          workspaceId: authorization.workspaceId,
          artifact
        })
        const cipher = createCipheriv('aes-256-gcm', dataKey, nonce)
        cipher.setAAD(aad)
        ciphertext = Buffer.concat([
          cipher.update(plaintext),
          cipher.final()
        ])
        const authTag = cipher.getAuthTag()
        wrappedDataKey = this.protector.protect(dataKey.toString('base64'))
        if (wrappedDataKey.byteLength === 0) {
          throw new Error('Protected Evidence key wrapping failed.')
        }
        derivativeContent = Buffer.from(
          protectedDerivativeContent(evidenceId, artifact),
          'utf8'
        )
        const prepare = (
          evidenceInput: InternalEvidenceWriteInput,
          id: string,
          forceBinaryExtension = false
        ): {
          row: typeof evidenceItems.$inferSelect
          content: Buffer
          relativePath: string
          absolutePath: string
          controlled: ControlledEvidencePath
        } => {
          const content = toBuffer(evidenceInput.content)
          const digest = sha256(content)
          const relativePath = [
            workspaceDirectoryName(evidenceInput.workspaceId),
            'evidence',
            digest.slice(0, 2),
            `${digest}${
              forceBinaryExtension
                ? '.bin'
                : extensionFor(evidenceInput.mimeType)
            }`
          ].join('/')
          const controlled = parseControlledEvidencePath(relativePath)
          const absolutePath = resolve(
            this.root,
            controlled.workspaceDirectory,
            'evidence',
            controlled.bucket,
            controlled.fileName
          )
          assertInside(this.root, absolutePath)
          return {
            content,
            relativePath,
            absolutePath,
            controlled,
            row: {
              id,
              workspaceId: evidenceInput.workspaceId,
              scanId: evidenceInput.scanId,
              interactionId: evidenceInput.interactionId ?? null,
              policyDecisionId: evidenceInput.policyDecisionId ?? null,
              type: evidenceInput.type,
              mimeType: evidenceInput.mimeType,
              filePath: relativePath,
              sha256: digest,
              size: content.byteLength,
              source: evidenceInput.source,
              createdBy: evidenceInput.createdBy,
              captureTool: evidenceInput.captureTool,
              captureToolVersion: evidenceInput.captureToolVersion,
              derivedFrom: evidenceInput.derivedFrom ?? null,
              redactionState: evidenceInput.redactionState,
              integrityStatus: 'verified',
              retentionUntil: evidenceInput.retentionUntil
                ? Date.parse(evidenceInput.retentionUntil)
                : null,
              createdAt: now
            }
          }
        }
        const originalPrepared = prepare(
          {
            workspaceId: authorization.workspaceId,
            scanId: artifact.scanId,
            policyDecisionId: artifact.policyDecisionId,
            type: PROTECTED_ORIGINAL_TYPE,
            mimeType: artifact.payload.originalMimeType,
            content: ciphertext,
            source: artifact.source,
            createdBy: 'evidence-capture-policy',
            captureTool: 'evidence-capture-policy',
            captureToolVersion: artifact.capturePolicyVersion,
            redactionState: 'original',
            retentionUntil: artifact.payload.retentionUntil
          },
          evidenceId,
          true
        )
        const derivativePrepared = prepare(
          {
            workspaceId: authorization.workspaceId,
            scanId: artifact.scanId,
            policyDecisionId: artifact.policyDecisionId,
            type: PROTECTED_DERIVATIVE_TYPE,
            mimeType: 'application/json',
            content: derivativeContent,
            source: 'protected-evidence-derivative',
            createdBy: 'evidence-store',
            captureTool: 'metadata-only-redacted-derivative',
            captureToolVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
            derivedFrom: evidenceId,
            redactionState: 'redacted',
            retentionUntil: artifact.payload.retentionUntil
          },
          derivativeId
        )
        const persistFile = (
          prepared:
            | typeof originalPrepared
            | typeof derivativePrepared
        ): void => {
          const workspacePath = ensureSafeDirectory(
            this.root,
            this.root,
            prepared.controlled.workspaceDirectory
          )
          const evidencePath = ensureSafeDirectory(
            this.root,
            workspacePath,
            'evidence'
          )
          const bucketPath = ensureSafeDirectory(
            this.root,
            evidencePath,
            prepared.controlled.bucket
          )
          const resolvedPath = resolve(
            bucketPath,
            prepared.controlled.fileName
          )
          if (resolvedPath !== prepared.absolutePath) {
            throw new Error(
              'Evidence content path changed during persistence.'
            )
          }
          if (!existsSync(prepared.absolutePath)) {
            try {
              writeFileSync(prepared.absolutePath, prepared.content, {
                flag: 'wx',
                mode: 0o600
              })
              createdPaths.add(prepared.relativePath)
            } catch (error) {
              if (
                !error ||
                typeof error !== 'object' ||
                !('code' in error) ||
                error.code !== 'EEXIST'
              ) {
                throw error
              }
            }
          }
          const storedFile = resolveControlledEvidenceFile(
            this.root,
            prepared.relativePath
          )
          if (
            !storedFile.exists ||
            storedFile.size !== prepared.row.size ||
            sha256(readFileSync(prepared.absolutePath)) !==
              prepared.row.sha256
          ) {
            throw new Error(
              'Protected Evidence content-addressed file failed verification.'
            )
          }
        }
        persistFile(originalPrepared)
        persistFile(derivativePrepared)

        const protectedRow: typeof protectedEvidenceItems.$inferSelect = {
          evidenceId,
          schemaVersion: PROTECTED_STORAGE_SCHEMA_VERSION,
          captureDecisionId: artifact.captureDecisionId,
          evidenceRole: artifact.role,
          derivativeEvidenceId: derivativeId,
          derivativeSha256: derivativePrepared.row.sha256,
          captureArtifact:
            artifact as unknown as Record<string, unknown>,
          sourceHash: artifact.sourceHash,
          protectionPlan: plan as unknown as Record<string, unknown>,
          originalMimeType: artifact.payload.originalMimeType,
          plaintextSha256: artifact.sourceHash.digest,
          plaintextSize: artifact.payload.plaintextSize,
          storageSha256: originalPrepared.row.sha256,
          storageSize: originalPrepared.row.size,
          encryptionAlgorithm: PROTECTED_ENCRYPTION_ALGORITHM,
          wrappedDataKey: wrappedDataKey.toString('base64'),
          nonce: nonce.toString('base64'),
          authTag: authTag.toString('base64'),
          availabilityState: 'available',
          retentionUntil,
          expiredAt: null,
          createdAt: now
        }
        await this.database.orm.transaction(
          async (transaction) => {
            const [workspaceUsage] = await transaction
              .select({
                total: sql<number>`coalesce(sum(${protectedEvidenceItems.plaintextSize}), 0)`
              })
              .from(protectedEvidenceItems)
              .innerJoin(
                evidenceItems,
                eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
              )
              .where(
                and(
                  eq(
                    protectedEvidenceItems.availabilityState,
                    'available'
                  ),
                  eq(
                    evidenceItems.workspaceId,
                    authorization.workspaceId
                  )
                )
              )
            const [scanUsage] = await transaction
              .select({
                total: sql<number>`coalesce(sum(${protectedEvidenceItems.plaintextSize}), 0)`
              })
              .from(protectedEvidenceItems)
              .innerJoin(
                evidenceItems,
                eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
              )
              .where(
                and(
                  eq(
                    protectedEvidenceItems.availabilityState,
                    'available'
                  ),
                  eq(evidenceItems.scanId, artifact.scanId)
                )
              )
            if (
              Number(workspaceUsage?.total ?? 0) +
                protectedRow.plaintextSize >
              plan.maxWorkspacePlaintextBytes
            ) {
              throw new Error(
                'Protected Evidence workspace quota would be exceeded.'
              )
            }
            if (
              Number(scanUsage?.total ?? 0) +
                protectedRow.plaintextSize >
              plan.maxScanPlaintextBytes
            ) {
              throw new Error(
                'Protected Evidence scan quota would be exceeded.'
              )
            }
            await transaction
              .insert(evidenceItems)
              .values(originalPrepared.row)
            await transaction
              .insert(protectedEvidenceItems)
              .values(protectedRow)
            await transaction
              .insert(evidenceItems)
              .values(derivativePrepared.row)
            await transaction.insert(auditLogs).values({
              id: randomUUID(),
              workspaceId: authorization.workspaceId,
              scanId: artifact.scanId,
              event: 'evidence.protected.created',
              actor: 'system',
              detailJson: {
                evidenceId,
                derivativeEvidenceId: derivativeId,
                captureDecisionId: artifact.captureDecisionId,
                role: artifact.role,
                source: artifact.source,
                retentionUntil: artifact.payload.retentionUntil
              },
              createdAt: now
            })
          },
          { behavior: 'immediate' }
        )
        await this.#retryPendingFileCleanupUnlocked()
        return {
          original: mapEvidence(
            originalPrepared.row,
            protectedRow
          ),
          derivative: mapEvidence(derivativePrepared.row)
        }
      } catch (error) {
        for (const relativePath of createdPaths) {
          this.pendingFileCleanup.add(relativePath)
        }
        await this.#retryPendingFileCleanupUnlocked()
        throw error
      } finally {
        plaintext.fill(0)
        dataKey?.fill(0)
        nonce?.fill(0)
        aad?.fill(0)
        ciphertext?.fill(0)
        wrappedDataKey?.fill(0)
        derivativeContent?.fill(0)
      }
    })
  }

  verifyProtectedOriginal(input: {
    id: string
    workspaceId: string
    scanId: string
  }): Promise<boolean> {
    return this.#withMutationBoundary(async () => {
      const record = await this.#loadProtectedRecord(input.id)
      if (!record) throw new Error('Protected Evidence item does not exist.')
      const metadata = mapEvidence(record.evidence, record.protected)
      if (
        metadata.workspaceId !== input.workspaceId ||
        metadata.scanId !== input.scanId
      ) {
        await this.#addProtectedAudit(metadata, 'access-denied', {
          purpose: 'integrity-verification',
          reasonCode: 'scope-mismatch'
        })
        throw new Error('Protected Evidence access scope does not match.')
      }
      if (record.evidence.integrityStatus === 'failed') {
        await this.#addProtectedAudit(metadata, 'access-denied', {
          purpose: 'integrity-verification',
          reasonCode: 'integrity-already-failed'
        })
        throw new Error(
          'Protected Evidence integrity has already failed and cannot be restored.'
        )
      }
      if (
        record.protected.availabilityState !== 'available' ||
        record.protected.retentionUntil <= this.clock()
      ) {
        await this.#addProtectedAudit(metadata, 'access-denied', {
          purpose: 'integrity-verification',
          reasonCode: 'expired'
        })
        throw new Error('Protected Evidence is no longer available.')
      }
      if (!this.protector?.isAvailable()) {
        throw new Error('Protected Evidence encryption is unavailable.')
      }

      const storedFile = resolveControlledEvidenceFile(
        this.root,
        record.evidence.filePath
      )
      let ciphertext: Buffer | undefined
      let dataKey: Buffer | undefined
      let nonceBytes: Buffer | undefined
      let authTagBytes: Buffer | undefined
      let plaintext: Buffer | undefined
      let aad: Buffer | undefined
      try {
        const artifactResult = EvidenceArtifactDraftSchema.safeParse(
          record.protected.captureArtifact
        )
        if (
          !artifactResult.success ||
          artifactResult.data.type !== PROTECTED_ORIGINAL_TYPE
        ) {
          throw new ProtectedEvidenceIntegrityError(
            'Protected Evidence metadata failed validation.'
          )
        }
        const artifact = artifactResult.data
        await this.#assertProtectedRecordConsistency(record, artifact)
        if (!storedFile.exists || storedFile.size === undefined) {
          throw new ProtectedEvidenceIntegrityError(
            'Protected Evidence ciphertext is unavailable.'
          )
        }
        ciphertext = readFileSync(storedFile.absolutePath)
        if (
          storedFile.size !== record.protected.storageSize ||
          ciphertext.byteLength !== record.evidence.size ||
          sha256(ciphertext) !== record.protected.storageSha256 ||
          record.protected.storageSha256 !== record.evidence.sha256
        ) {
          throw new ProtectedEvidenceIntegrityError(
            'Protected Evidence ciphertext integrity failed.'
          )
        }
        const wrappedDataKey = record.protected.wrappedDataKey
        const nonceValue = record.protected.nonce
        const authTagValue = record.protected.authTag
        if (!wrappedDataKey || !nonceValue || !authTagValue) {
          throw new ProtectedEvidenceIntegrityError(
            'Protected Evidence key material is unavailable.'
          )
        }
        const unwrapped = this.protector.unprotect(
          Buffer.from(wrappedDataKey, 'base64')
        )
        dataKey = decodeCanonicalBase64(
          unwrapped,
          32,
          'Protected Evidence data key'
        )
        try {
          nonceBytes = decodeCanonicalBase64(
            nonceValue,
            12,
            'Protected Evidence nonce'
          )
          authTagBytes = decodeCanonicalBase64(
            authTagValue,
            16,
            'Protected Evidence authentication tag'
          )
        } catch (error) {
          throw new ProtectedEvidenceIntegrityError(
            error instanceof Error
              ? error.message
              : 'Protected Evidence encryption metadata is invalid.'
          )
        }
        aad = protectedEvidenceAad({
          evidenceId: record.evidence.id,
          workspaceId: record.evidence.workspaceId,
          artifact
        })
        const decipher = createDecipheriv(
          'aes-256-gcm',
          dataKey,
          nonceBytes
        )
        decipher.setAAD(aad)
        decipher.setAuthTag(authTagBytes)
        try {
          plaintext = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
          ])
        } catch {
          throw new ProtectedEvidenceIntegrityError(
            'Protected Evidence authentication failed.'
          )
        }
        if (
          plaintext.byteLength !== record.protected.plaintextSize ||
          sha256(plaintext) !== record.protected.plaintextSha256 ||
          record.protected.plaintextSha256 !== artifact.sourceHash.digest
        ) {
          throw new ProtectedEvidenceIntegrityError(
            'Protected Evidence plaintext integrity failed.'
          )
        }
      } catch (error) {
        if (error instanceof ProtectedEvidenceIntegrityError) {
          await this.database.orm.transaction(
            async (transaction) => {
              await transaction
                .update(evidenceItems)
                .set({ integrityStatus: 'failed' })
                .where(eq(evidenceItems.id, record.evidence.id))
              await transaction.insert(auditLogs).values({
                id: randomUUID(),
                workspaceId: metadata.workspaceId,
                scanId: metadata.scanId,
                event: 'evidence.protected.access-denied',
                actor: 'system',
                detailJson: {
                  evidenceId: metadata.id,
                  purpose: 'integrity-verification',
                  reasonCode: 'integrity-failed'
                },
                createdAt: this.clock()
              })
            },
            { behavior: 'immediate' }
          )
          throw new Error(
            'Protected Evidence integrity verification failed.',
            { cause: error }
          )
        }
        throw new Error(
          'Protected Evidence verification could not be completed.',
          { cause: error }
        )
      } finally {
        ciphertext?.fill(0)
        dataKey?.fill(0)
        nonceBytes?.fill(0)
        authTagBytes?.fill(0)
        plaintext?.fill(0)
        aad?.fill(0)
      }
      await this.#addProtectedAudit(metadata, 'accessed', {
        purpose: 'integrity-verification',
        result: 'verified'
      })
      return true
    })
  }

  sweepExpiredProtectedOriginals(): Promise<ProtectedEvidenceSweepResult> {
    return this.#withMutationBoundary(async () => {
      const now = this.clock()
      const rows = await this.database.orm
        .select({
          evidence: evidenceItems,
          protected: protectedEvidenceItems
        })
        .from(protectedEvidenceItems)
        .innerJoin(
          evidenceItems,
          eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
        )
        .where(lte(protectedEvidenceItems.retentionUntil, now))
        .orderBy(asc(protectedEvidenceItems.retentionUntil))
      let expiredItems = 0
      let deletedCiphertextFiles = 0
      for (const record of rows) {
        let transitioned = false
        if (record.protected.availabilityState === 'available') {
          const expiredAt = Math.max(now, record.protected.retentionUntil)
          transitioned = await this.database.orm.transaction(
            async (transaction) => {
              const updated = await transaction
                .update(protectedEvidenceItems)
                .set({
                  availabilityState: 'expired',
                  wrappedDataKey: null,
                  nonce: null,
                  authTag: null,
                  expiredAt
                })
                .where(
                  and(
                    eq(
                      protectedEvidenceItems.evidenceId,
                      record.evidence.id
                    ),
                    eq(protectedEvidenceItems.availabilityState, 'available')
                  )
                )
                .returning({
                  evidenceId: protectedEvidenceItems.evidenceId
                })
              if (updated.length !== 1) return false
              await transaction
                .update(evidenceItems)
                .set({ integrityStatus: 'expired' })
                .where(eq(evidenceItems.id, record.evidence.id))
              await transaction.insert(auditLogs).values({
                id: randomUUID(),
                workspaceId: record.evidence.workspaceId,
                scanId: record.evidence.scanId,
                event: 'evidence.protected.expired',
                actor: 'system',
                detailJson: {
                  evidenceId: record.evidence.id,
                  retentionUntil: toIso(record.protected.retentionUntil),
                  ciphertextState: 'crypto-erased'
                },
                createdAt: expiredAt
              })
              return true
            },
            { behavior: 'immediate' }
          )
          if (transitioned) expiredItems += 1
        }
        try {
          if (
            record.protected.availabilityState === 'available' &&
            !transitioned
          ) {
            continue
          }
          const deleted = await this.database.orm.transaction(
            async (transaction) => {
              const [sharedReference] = await transaction
                .select({ id: evidenceItems.id })
                .from(evidenceItems)
                .where(
                  and(
                    ne(evidenceItems.id, record.evidence.id),
                    sql`replace(${evidenceItems.filePath}, ${'\\'}, ${'/'}) = ${record.evidence.filePath.replace(/\\/gu, '/')}`
                  )
                )
                .limit(1)
              if (sharedReference) return false
              const storedFile = resolveControlledEvidenceFile(
                this.root,
                record.evidence.filePath
              )
              if (!storedFile.exists) return false
              unlinkSync(storedFile.absolutePath)
              return true
            },
            { behavior: 'immediate' }
          )
          if (deleted) deletedCiphertextFiles += 1
        } catch {
          // The wrapped key was already erased transactionally. A later sweep
          // retries physical ciphertext cleanup without restoring access.
        }
      }
      return { expiredItems, deletedCiphertextFiles }
    })
  }

  async #loadProtectedRecord(
    id: string
  ): Promise<ProtectedEvidenceRecord | undefined> {
    const [row] = await this.database.orm
      .select({
        evidence: evidenceItems,
        protected: protectedEvidenceItems
      })
      .from(protectedEvidenceItems)
      .innerJoin(
        evidenceItems,
        eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
      )
      .where(eq(protectedEvidenceItems.evidenceId, id))
      .limit(1)
    return row
  }

  async #assertProtectedRecordConsistency(
    record: ProtectedEvidenceRecord,
    artifact: ProtectedOriginalArtifact
  ): Promise<void> {
    try {
      const expectedRetentionUntil = Date.parse(
        artifact.payload.retentionUntil
      )
      const originalIsBound =
        record.evidence.scanId === artifact.scanId &&
        record.evidence.policyDecisionId === artifact.policyDecisionId &&
        record.evidence.type === PROTECTED_ORIGINAL_TYPE &&
        record.evidence.mimeType === artifact.payload.originalMimeType &&
        record.evidence.source === artifact.source &&
        record.evidence.createdBy === 'evidence-capture-policy' &&
        record.evidence.captureTool === 'evidence-capture-policy' &&
        record.evidence.captureToolVersion ===
          artifact.capturePolicyVersion &&
        record.evidence.derivedFrom === null &&
        record.evidence.redactionState === 'original' &&
        record.evidence.integrityStatus === 'verified' &&
        record.evidence.retentionUntil === expectedRetentionUntil &&
        record.evidence.sha256 === record.protected.storageSha256 &&
        record.evidence.size === record.protected.storageSize
      const envelopeIsBound =
        record.protected.schemaVersion ===
          PROTECTED_STORAGE_SCHEMA_VERSION &&
        record.protected.captureDecisionId ===
          artifact.captureDecisionId &&
        record.protected.evidenceRole === artifact.role &&
        record.protected.originalMimeType ===
          artifact.payload.originalMimeType &&
        record.protected.plaintextSha256 ===
          artifact.sourceHash.digest &&
        record.protected.plaintextSize ===
          artifact.payload.plaintextSize &&
        record.protected.encryptionAlgorithm ===
          PROTECTED_ENCRYPTION_ALGORITHM &&
        record.protected.availabilityState === 'available' &&
        record.protected.wrappedDataKey !== null &&
        record.protected.nonce !== null &&
        record.protected.authTag !== null &&
        record.protected.expiredAt === null &&
        record.protected.retentionUntil === expectedRetentionUntil &&
        record.protected.createdAt === record.evidence.createdAt &&
        canonicalJson(record.protected.captureArtifact) ===
          canonicalJson(artifact) &&
        canonicalJson(record.protected.sourceHash) ===
          canonicalJson(artifact.sourceHash) &&
        canonicalJson(record.protected.protectionPlan) ===
          canonicalJson(artifact.payload.protectionPlan)
      if (!originalIsBound || !envelopeIsBound) {
        throw new Error('protected original metadata mismatch')
      }

      const [derivative] = await this.database.orm
        .select()
        .from(evidenceItems)
        .where(
          eq(
            evidenceItems.id,
            record.protected.derivativeEvidenceId
          )
        )
        .limit(1)
      if (
        !derivative ||
        derivative.workspaceId !== record.evidence.workspaceId ||
        derivative.scanId !== artifact.scanId ||
        derivative.policyDecisionId !== artifact.policyDecisionId ||
        derivative.type !== PROTECTED_DERIVATIVE_TYPE ||
        derivative.mimeType !== 'application/json' ||
        derivative.source !== 'protected-evidence-derivative' ||
        derivative.createdBy !== 'evidence-store' ||
        derivative.captureTool !== 'metadata-only-redacted-derivative' ||
        derivative.captureToolVersion !==
          PROTECTED_EVIDENCE_POLICY_VERSION ||
        derivative.derivedFrom !== record.evidence.id ||
        derivative.redactionState !== 'redacted' ||
        derivative.integrityStatus !== 'verified' ||
        derivative.retentionUntil !== expectedRetentionUntil ||
        derivative.createdAt !== record.evidence.createdAt ||
        derivative.sha256 !== record.protected.derivativeSha256
      ) {
        throw new Error('protected derivative metadata mismatch')
      }
      const derivativeFile = resolveControlledEvidenceFile(
        this.root,
        derivative.filePath
      )
      if (!derivativeFile.exists || derivativeFile.size === undefined) {
        throw new Error('protected derivative file missing')
      }
      const derivativeContent = readFileSync(
        derivativeFile.absolutePath
      )
      try {
        const expectedContent = Buffer.from(
          protectedDerivativeContent(record.evidence.id, artifact),
          'utf8'
        )
        try {
          if (
            derivativeFile.size !== derivative.size ||
            derivativeContent.byteLength !== derivative.size ||
            sha256(derivativeContent) !== derivative.sha256 ||
            !derivativeContent.equals(expectedContent)
          ) {
            throw new Error('protected derivative content mismatch')
          }
        } finally {
          expectedContent.fill(0)
        }
      } finally {
        derivativeContent.fill(0)
      }
    } catch (error) {
      if (error instanceof ProtectedEvidenceIntegrityError) throw error
      throw new ProtectedEvidenceIntegrityError(
        'Protected Evidence relational integrity failed.'
      )
    }
  }

  async #addProtectedAudit(
    metadata: EvidenceItemRecord,
    event: 'created' | 'accessed' | 'access-denied',
    detail: Record<string, string>
  ): Promise<void> {
    await this.database.orm.insert(auditLogs).values({
      id: randomUUID(),
      workspaceId: metadata.workspaceId,
      scanId: metadata.scanId,
      event: `evidence.protected.${event}`,
      actor: 'system',
      detailJson: {
        evidenceId: metadata.id,
        ...detail
      },
      createdAt: this.clock()
    })
  }

  resolveStoredPath(relativePath: string): string {
    const controlled = parseControlledEvidencePath(relativePath)
    const absolutePath = resolve(
      this.root,
      controlled.workspaceDirectory,
      'evidence',
      controlled.bucket,
      controlled.fileName
    )
    assertInside(this.root, absolutePath)
    return absolutePath
  }

  deleteUnreferencedFiles(relativePaths: string[]): Promise<number> {
    return this.#withMutationBoundary(async () => {
      const candidates = [
        ...new Set(
          [...this.pendingFileCleanup, ...relativePaths].map(
            (relativePath) =>
              parseControlledEvidencePath(relativePath).canonicalPath
          )
        )
      ]
      try {
        const deleted =
          await this.#deleteUnreferencedFilesUnlocked(candidates)
        for (const relativePath of candidates) {
          this.pendingFileCleanup.delete(relativePath)
        }
        return deleted
      } catch (error) {
        for (const relativePath of candidates) {
          this.pendingFileCleanup.add(relativePath)
        }
        throw error
      }
    })
  }

  /**
   * Recovers the file side of a prior metadata-first cleanup after a process
   * crash. Only exact EvidenceStore content-addressed paths are considered;
   * unknown files and directories under the artifact root are left untouched.
   */
  sweepUnreferencedContentFiles(): Promise<number> {
    return this.#withMutationBoundary(async () => {
      const candidates = [
        ...new Set([
          ...this.pendingFileCleanup,
          ...listControlledEvidenceFiles(this.root)
        ])
      ]
      try {
        const deleted =
          await this.#deleteUnreferencedFilesUnlocked(candidates)
        for (const relativePath of candidates) {
          this.pendingFileCleanup.delete(relativePath)
        }
        return deleted
      } catch (error) {
        for (const relativePath of candidates) {
          this.pendingFileCleanup.add(relativePath)
        }
        throw error
      }
    })
  }

  async #deleteUnreferencedFilesUnlocked(
    relativePaths: string[]
  ): Promise<number> {
    return this.database.orm.transaction(
      async (transaction) => {
        let deleted = 0
        for (const relativePath of new Set(relativePaths)) {
          const controlled =
            parseControlledEvidencePath(relativePath).canonicalPath
          const [referenced] = await transaction
            .select({ id: evidenceItems.id })
            .from(evidenceItems)
            .where(
              sql`replace(${evidenceItems.filePath}, ${'\\'}, ${'/'}) = ${controlled}`
            )
            .limit(1)
          if (referenced) continue
          const storedFile = resolveControlledEvidenceFile(
            this.root,
            controlled
          )
          if (storedFile.exists) {
            unlinkSync(storedFile.absolutePath)
            deleted += 1
          }
        }
        return deleted
      },
      { behavior: 'immediate' }
    )
  }

  discardUnboundEvidence(
    evidence: Pick<EvidenceItemRecord, 'id' | 'filePath' | 'sha256'>
  ): Promise<boolean> {
    return this.#withMutationBoundary(() =>
      this.#discardUnboundEvidenceUnlocked(evidence)
    )
  }

  async #discardUnboundEvidenceUnlocked(
    evidence: Pick<EvidenceItemRecord, 'id' | 'filePath' | 'sha256'>
  ): Promise<boolean> {
    const controlledFilePath =
      parseControlledEvidencePath(evidence.filePath).canonicalPath
    const discarded = await this.database.orm.transaction(
      async (transaction) => {
        const [candidate] = await transaction
          .select({
            id: evidenceItems.id,
            filePath: evidenceItems.filePath,
            sha256: evidenceItems.sha256,
            type: evidenceItems.type
          })
          .from(evidenceItems)
          .where(
            and(
              eq(evidenceItems.id, evidence.id),
              eq(evidenceItems.filePath, evidence.filePath),
              eq(evidenceItems.sha256, evidence.sha256),
              isNull(evidenceItems.interactionId)
            )
          )
          .limit(1)
        if (!candidate) return false
        if (
          candidate.type === PROTECTED_ORIGINAL_TYPE ||
          candidate.type === PROTECTED_DERIVATIVE_TYPE
        ) {
          return false
        }
        if (
          isEvidenceItemReferenced(
            this.database.native,
            evidence.id
          )
        ) {
          return false
        }
        const rows = await transaction
          .delete(evidenceItems)
          .where(
            and(
              eq(evidenceItems.id, evidence.id),
              eq(evidenceItems.filePath, evidence.filePath),
              eq(evidenceItems.sha256, evidence.sha256),
              isNull(evidenceItems.interactionId)
            )
          )
          .returning({ id: evidenceItems.id })
        return rows.length === 1
      },
      { behavior: 'immediate' }
    )
    if (discarded) {
      try {
        await this.#deleteUnreferencedFilesUnlocked([controlledFilePath])
        this.pendingFileCleanup.delete(controlledFilePath)
      } catch {
        // The metadata deletion is authoritative. A best-effort file cleanup
        // failure must not make callers treat the now-missing Evidence ID as
        // retained and then attempt to bind it to an execution lease.
        this.pendingFileCleanup.add(controlledFilePath)
      }
    }
    return discarded
  }

  deleteWorkspaceArtifacts(workspaceId: string): Promise<boolean> {
    return this.#withMutationBoundary(() =>
      this.database.orm.transaction(
        async () => {
          const absolutePath = resolve(
            this.root,
            workspaceDirectoryName(workspaceId)
          )
          assertInside(this.root, absolutePath)
          if (!existsSync(absolutePath)) return false
          assertSafeDirectory(this.root, absolutePath)
          rmSync(absolutePath, { recursive: true, force: true })
          return true
        },
        { behavior: 'immediate' }
      )
    )
  }
}

function assertCanonicalFutureIso(
  value: string,
  now: number,
  label: string
): number {
  const timestamp = Date.parse(value)
  if (
    !Number.isFinite(timestamp) ||
    new Date(timestamp).toISOString() !== value ||
    timestamp <= now
  ) {
    throw new Error(`${label} must be a canonical future timestamp.`)
  }
  return timestamp
}

function decodeCanonicalBase64(
  value: string,
  expectedBytes: number,
  label: string
): Buffer {
  const decoded = Buffer.from(value, 'base64')
  if (
    decoded.byteLength !== expectedBytes ||
    decoded.toString('base64') !== value
  ) {
    decoded.fill(0)
    throw new Error(`${label} is invalid.`)
  }
  return decoded
}

function protectedEvidenceAad(input: Readonly<{
  evidenceId: string
  workspaceId: string
  artifact: ProtectedOriginalArtifact
}>): Buffer {
  return Buffer.from(
    canonicalJson({
      domain: PROTECTED_AAD_DOMAIN,
      evidenceId: input.evidenceId,
      workspaceId: input.workspaceId,
      artifact: input.artifact
    }),
    'utf8'
  )
}

function protectedDerivativeContent(
  originalId: string,
  artifact: ProtectedOriginalArtifact
): string {
  return canonicalJson({
    schemaVersion: 'protected-evidence-redacted-derivative.v1',
    kind: 'metadata-only-redacted-derivative',
    sourceEvidenceId: originalId,
    source: artifact.source,
    role: artifact.role,
    captureDecisionId: artifact.captureDecisionId,
    capturePolicyId: artifact.capturePolicyId,
    capturePolicyVersion: artifact.capturePolicyVersion,
    sourceHash: artifact.sourceHash,
    originalMimeType: artifact.payload.originalMimeType,
    plaintextSize: artifact.payload.plaintextSize,
    redaction: {
      policyId: PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
      policyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
      contentIncluded: false
    }
  })
}
