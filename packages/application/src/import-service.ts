import { randomUUID } from 'node:crypto'
import {
  CommitImportPreviewInputSchema,
  CreateImportPreviewInputSchema,
  DEFAULT_IMPORT_PARSER_LIMITS,
  ImportCommitResultSchema,
  ImportPreviewSchema,
  type ImportCommitResult,
  type ImportPreview,
  type ImportPreviewOperation,
  type ImportWarning,
  type InventoryBodyShape,
  type SelectorRef,
  type UpsertInventoryInput
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  ImportDiscoveryRepository
} from '@agentgo/db'
import {
  redactInventoryText,
  redactInventoryUrlPreview,
  stableInventoryHash
} from '@agentgo/domain'
import { InventoryService } from './inventory-service'
import {
  OfflineParseError,
  extractImportedDocument,
  profileFor,
  sha256Bytes
} from './importers'

const PREVIEW_TTL_MS = 30 * 60 * 1000
const TERMINAL_SCAN_STATUSES = new Set(['completed', 'failed', 'cancelled'])
const FORBIDDEN_IMPORT_METHODS = new Set(['CONNECT', 'DELETE', 'TRACE'])

export class ImportService {
  constructor(
    private readonly repository: AgentGoRepository,
    private readonly inventoryService: InventoryService,
    private readonly discoveryRepository: ImportDiscoveryRepository,
    private readonly evidenceStore?: EvidenceStore
  ) {}

  async preview(input: unknown): Promise<ImportPreview> {
    const parsed = CreateImportPreviewInputSchema.parse(input)
    const scan = await this.repository.getScan(parsed.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    if (TERMINAL_SCAN_STATUSES.has(scan.status)) {
      throw new Error('Terminal scans cannot accept import previews.')
    }
    const target = await this.repository.getTarget(scan.targetId)
    if (!target) throw new Error('Scan target does not exist.')
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!scope) throw new Error('Scan scope snapshot does not exist.')

    const bytes = parsed.bytes
      ? parsed.bytes
      : await this.readEvidenceBytes(parsed.evidenceRef!, parsed.expectedHash!, parsed.scanId)
    const sourceBytesHash = sha256Bytes(bytes)
    const limits = parsed.limits ?? DEFAULT_IMPORT_PARSER_LIMITS
    const mediaType = parsed.mediaType ?? 'application/octet-stream'

    let extracted
    try {
      extracted = extractImportedDocument(bytes, mediaType, scope, limits)
    } catch (error) {
      if (error instanceof OfflineParseError) {
        throw redactError(error)
      }
      throw redactError(error)
    }

    const profile = profileFor(extracted.format)
    const warnings = [
      ...extracted.parserWarnings,
      ...extracted.warnings,
      ...extracted.operations.flatMap((operation) => operation.warnings)
    ].map(sanitizeWarning)
    const operations = extracted.operations.map(sanitizeOperation)
    const accepted: ImportPreviewOperation[] = []
    const rejected: ImportPreviewOperation[] = []
    let unsupported = profile.status === 'unsupported' ? 1 : 0
    for (const operation of operations) {
      if (FORBIDDEN_IMPORT_METHODS.has(operation.method)) {
        rejected.push({
          ...operation,
          warnings: [
            ...operation.warnings,
            {
              code: 'unsupported-protocol',
              location: operation.operationRef,
              message: `${operation.method} is cataloged as rejected; execution class forbidden is not import-promotable.`
            }
          ]
        })
        unsupported += 1
        continue
      }
      if (operation.scopeVerdict === 'in-scope') {
        accepted.push(operation)
      } else {
        rejected.push(operation)
      }
      if (
        operation.transport !== 'standard-http' ||
        operation.codec === 'graphql' ||
        profile.status !== 'fully-parsed'
      ) {
        unsupported += 1
      }
    }

    const createdAt = new Date()
    const previewId = randomUUID()
    const unsigned = {
      previewId,
      scanId: scan.id,
      workspaceId: target.workspaceId,
      scopeSnapshotId: scan.scopeSnapshotId,
      sourceBytesHash,
      mediaType,
      format: extracted.format,
      parserName: profile.parserName,
      parserVersion: profile.parserVersion,
      adapterStatus: profile.status,
      operations: accepted,
      rejectedOperations: rejected,
      warnings,
      stats: {
        accepted: accepted.length,
        rejectedOutOfScope: rejected.filter((item) => item.scopeVerdict === 'out-of-scope').length,
        unresolved: rejected.filter((item) => item.scopeVerdict === 'unresolved').length,
        unsupported
      },
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + PREVIEW_TTL_MS).toISOString()
    }
    const preview = ImportPreviewSchema.parse({
      ...unsigned,
      previewHash: stableInventoryHash(unsigned)
    })
    assertNoSecretLeak(preview, bytes)
    return this.discoveryRepository.saveImportPreview(preview)
  }

  async commit(input: unknown): Promise<ImportCommitResult> {
    const parsed = CommitImportPreviewInputSchema.parse(input)
    const preview = await this.discoveryRepository.getImportPreview(parsed.previewId)
    if (!preview) throw new Error('Import preview does not exist.')
    if (preview.previewHash !== parsed.previewHash) {
      throw new Error('Import preview hash mismatch.')
    }
    if (preview.sourceBytesHash !== parsed.sourceBytesHash) {
      throw new Error('Import source hash mismatch.')
    }
    if (preview.parserVersion !== parsed.parserVersion) {
      throw new Error('Import parser version mismatch.')
    }
    if (Date.parse(preview.expiresAt) <= Date.now()) {
      throw new Error('Import preview has expired.')
    }

    const scan = await this.repository.getScan(preview.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    if (TERMINAL_SCAN_STATUSES.has(scan.status)) {
      throw new Error('Terminal scans cannot accept import commits.')
    }
    if (scan.scopeSnapshotId !== preview.scopeSnapshotId) {
      throw new Error('Scan scope snapshot changed after preview.')
    }

    const existing = await this.discoveryRepository.getImportCommitByIdempotency({
      scanId: preview.scanId,
      sourceBytesHash: preview.sourceBytesHash,
      parserVersion: preview.parserVersion
    })
    if (existing) {
      return existing
    }

    const sourceIds: string[] = []
    for (const operation of preview.operations) {
      if (operation.scopeVerdict !== 'in-scope') continue
      let upsertInput: UpsertInventoryInput
      try {
        upsertInput = toInventoryInput(preview, operation)
      } catch (error) {
        throw redactError(error)
      }
      const result = await this.inventoryService.upsertInventory(upsertInput)
      if (result.requestVariant.executionClass !== 'inventory-only') {
        throw new Error('Imported variants must remain inventory-only.')
      }
      if (result.requestVariant.reviewStatus !== 'unreviewed') {
        throw new Error('Imported variants must remain unreviewed.')
      }
      sourceIds.push(result.source.id)
    }

    const commit = await this.discoveryRepository.saveImportCommit({
      commitId: randomUUID(),
      previewId: preview.previewId,
      scanId: preview.scanId,
      sourceBytesHash: preview.sourceBytesHash,
      parserVersion: preview.parserVersion,
      importActorRef: parsed.importActorRef,
      acceptedCount: sourceIds.length,
      sourceIds,
      createdAt: Date.now()
    })
    await this.discoveryRepository.markImportPreviewCommitted(preview.previewId)
    return ImportCommitResultSchema.parse(commit)
  }

  private async readEvidenceBytes(
    evidenceRef: string,
    expectedHash: string,
    scanId: string
  ): Promise<Uint8Array> {
    if (!this.evidenceStore) {
      throw new Error('Evidence-backed import requires EvidenceStore.')
    }
    const read = await this.evidenceStore.read(evidenceRef)
    if (read.metadata.scanId !== scanId) {
      throw new Error('Evidence reference does not belong to this scan.')
    }
    if (read.metadata.sha256 !== expectedHash) {
      throw new Error('Evidence content hash mismatch.')
    }
    return new Uint8Array(read.content)
  }
}

function toInventoryInput(
  preview: ImportPreview,
  operation: ImportPreviewOperation
): UpsertInventoryInput {
  if (!/^https?:\/\//iu.test(operation.url)) {
    throw new Error('In-scope import operations must have an absolute HTTP URL.')
  }
  const codec = operation.codec === 'none' ? 'none' : operation.codec
  return {
    scanId: preview.scanId,
    method: operation.method,
    url: operation.url,
    ...(operation.contentType ? { contentType: operation.contentType } : {}),
    bodyShape: bodyShapeFor(codec),
    codec,
    transport: operation.transport,
    allowedHeaders: [],
    templateVersion: preview.parserVersion,
    requiredCapabilityIds: [],
    selectors: selectorsFor(operation),
    preview: { url: operation.url },
    source: {
      type: preview.parserName,
      sourceHash: preview.sourceBytesHash,
      confidence: preview.adapterStatus === 'fully-parsed' ? 1 : 0.4,
      initiator: redactInventoryText(operation.operationRef, 256)
    }
  }
}

function bodyShapeFor(codec: ImportPreviewOperation['codec']): InventoryBodyShape {
  if (codec === 'none') return { rootType: 'none', fields: [] }
  if (codec === 'json' || codec === 'graphql' || codec === 'form' || codec === 'multipart') {
    return { rootType: 'object', fields: [] }
  }
  return { rootType: 'string', fields: [] }
}

function selectorsFor(operation: ImportPreviewOperation): SelectorRef[] {
  if (operation.parameters && operation.parameters.length > 0) {
    return operation.parameters.flatMap(selectorForParameter)
  }
  const selectors: SelectorRef[] = []
  if (operation.parameterLocations.includes('query')) {
    selectors.push({ kind: 'query', name: 'imported', valueType: 'unknown', required: false })
  }
  if (operation.parameterLocations.includes('path')) {
    selectors.push({ kind: 'path', name: 'imported', valueType: 'string', required: true })
  }
  if (operation.parameterLocations.includes('header')) {
    selectors.push({ kind: 'header', name: 'x-imported', valueType: 'string', required: false })
  }
  if (operation.parameterLocations.includes('cookie')) {
    selectors.push({ kind: 'cookie', name: 'imported', valueType: 'string', required: false })
  }
  if (operation.parameterLocations.includes('form')) {
    selectors.push({ kind: 'form', name: 'imported', valueType: 'unknown', required: false })
  }
  if (operation.parameterLocations.includes('body') && operation.codec === 'json') {
    selectors.push({ kind: 'json-pointer', pointer: '/', valueType: 'object', required: false })
  }
  if (operation.parameterLocations.includes('body') && operation.codec === 'graphql') {
    selectors.push({
      kind: 'graphql-variable',
      variableName: 'imported',
      valueType: 'unknown',
      required: false
    })
  }
  return selectors
}

function selectorForParameter(
  parameter: NonNullable<ImportPreviewOperation['parameters']>[number]
): SelectorRef[] {
  const valueType = parameter.valueType
  const required = parameter.required
  switch (parameter.location) {
    case 'query':
      return [{ kind: 'query', name: parameter.name, valueType, required }]
    case 'path':
      return [{ kind: 'path', name: parameter.name, valueType, required }]
    case 'header':
      return [
        {
          kind: 'header',
          name: parameter.name.toLowerCase(),
          valueType,
          required
        }
      ]
    case 'cookie':
      return [{ kind: 'cookie', name: parameter.name, valueType, required }]
    case 'form':
      return [{ kind: 'form', name: parameter.name, valueType, required }]
    case 'body':
      return [
        {
          kind: 'json-pointer',
          pointer: `/${parameter.name}`,
          valueType,
          required
        }
      ]
  }
}

function sanitizeOperation(operation: ImportPreviewOperation): ImportPreviewOperation {
  const url = sanitizeUrl(operation.url)
  return {
    ...operation,
    url,
    warnings: operation.warnings.map(sanitizeWarning),
    securitySchemes: operation.securitySchemes.map((scheme) =>
      redactInventoryText(scheme, 200)
    )
  }
}

function sanitizeWarning(warning: ImportWarning): ImportWarning {
  return {
    ...warning,
    location: redactInventoryText(warning.location, 256),
    message: redactInventoryText(warning.message, 2_048)
  }
}

function sanitizeUrl(url: string): string {
  try {
    return redactInventoryUrlPreview(url)
  } catch {
    return redactInventoryText(url, 2_048)
  }
}

function assertNoSecretLeak(preview: ImportPreview, source: Uint8Array): void {
  const serialized = JSON.stringify(preview)
  const sourceText = new TextDecoder('utf-8', { fatal: false }).decode(source)
  const sentinels = sourceText.match(
    /(?:authorization|cookie|password|token|api[-_]?key)\s*[:=]\s*([^\s"',\\]+)/giu
  )
  if (!sentinels) return
  for (const match of sentinels) {
    const value = match.split(/[:=]/u)[1]?.trim()
    if (value && value.length >= 8 && serialized.includes(value)) {
      throw new Error('Import preview leaked a secret sentinel.')
    }
  }
}

function redactError(error: unknown): Error {
  const message = error instanceof Error ? error.message : 'Import failed.'
  return new Error(redactInventoryText(message, 2_048))
}
