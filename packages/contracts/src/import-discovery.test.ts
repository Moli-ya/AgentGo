import { describe, expect, it } from 'vitest'
import {
  AssetManifestSchema,
  CommitImportPreviewInputSchema,
  CreateImportPreviewInputSchema,
  DEFAULT_IMPORT_PARSER_LIMITS,
  ExtractionRuleDraftSchema,
  ImportAdapterProfileSchema,
  ImportPreviewSchema,
  StaticDiscoveryCandidateBatchSchema,
  StaticDiscoveryInputSchema
} from './index'

const uuid = '10000000-0000-4000-8000-000000000001'
const hash = 'a'.repeat(64)
const now = '2026-08-26T09:00:00.000Z'

describe('import contracts', () => {
  it('requires exactly one of bytes or evidenceRef', () => {
    expect(
      CreateImportPreviewInputSchema.safeParse({
        scanId: uuid,
        importActorRef: 'import.test-harness'
      }).success
    ).toBe(false)
    expect(
      CreateImportPreviewInputSchema.safeParse({
        scanId: uuid,
        importActorRef: 'import.test-harness',
        bytes: new Uint8Array([1]),
        evidenceRef: uuid,
        expectedHash: hash
      }).success
    ).toBe(false)
    expect(
      CreateImportPreviewInputSchema.safeParse({
        scanId: uuid,
        importActorRef: 'import.test-harness',
        evidenceRef: uuid
      }).success
    ).toBe(false)
    expect(
      CreateImportPreviewInputSchema.parse({
        scanId: uuid,
        importActorRef: 'import.test-harness',
        bytes: new Uint8Array([1])
      }).bytes
    ).toBeInstanceOf(Uint8Array)
  })

  it('rejects replayable or executable adapter profiles', () => {
    expect(
      ImportAdapterProfileSchema.safeParse({
        format: 'openapi-3.0',
        parserName: 'import.openapi',
        parserVersion: '1.0.0',
        status: 'fully-parsed',
        replayable: true,
        executable: false,
        supportedMediaTypes: ['application/json'],
        supportedKeywords: [],
        unsupportedKeywords: [],
        notes: []
      }).success
    ).toBe(false)
  })

  it('parses a preview and commit envelope', () => {
    const preview = ImportPreviewSchema.parse({
      previewId: uuid,
      previewHash: hash,
      scanId: uuid,
      workspaceId: uuid,
      scopeSnapshotId: uuid,
      sourceBytesHash: hash,
      mediaType: 'application/json',
      format: 'openapi-3.0',
      parserName: 'import.openapi',
      parserVersion: '1.0.0',
      adapterStatus: 'fully-parsed',
      operations: [],
      rejectedOperations: [],
      warnings: [],
      stats: { accepted: 0, rejectedOutOfScope: 0, unresolved: 0, unsupported: 0 },
      createdAt: now,
      expiresAt: '2026-08-26T09:30:00.000Z'
    })
    expect(preview.adapterStatus).toBe('fully-parsed')
    expect(
      CommitImportPreviewInputSchema.parse({
        previewId: uuid,
        previewHash: hash,
        sourceBytesHash: hash,
        parserVersion: '1.0.0',
        importActorRef: 'import.test-harness'
      }).previewId
    ).toBe(uuid)
    expect(DEFAULT_IMPORT_PARSER_LIMITS.maxYamlAliases).toBe(32)
  })
})

describe('discovery contracts', () => {
  it('rejects wildcard asset paths and unfrozen consumption shape', () => {
    expect(
      AssetManifestSchema.safeParse({
        schemaVersion: 'agentgo.asset-manifest.v1',
        manifestId: uuid,
        manifestVersion: 1,
        manifestHash: hash,
        scanId: uuid,
        scopeSnapshotId: uuid,
        reviewer: 'day12.reviewer',
        frozen: true,
        entries: [
          {
            origin: 'https://app.example.test',
            normalizedPath: '/*',
            resourceType: 'javascript',
            artifactRef: uuid,
            contentHash: hash,
            maxResponseBytes: 1024,
            scopeSnapshotId: uuid
          }
        ],
        createdAt: now,
        frozenAt: now
      }).success
    ).toBe(false)
  })

  it('parses a static discovery batch and extraction draft', () => {
    expect(
      StaticDiscoveryInputSchema.parse({
        scanId: uuid,
        artifactRef: uuid,
        expectedHash: hash,
        mediaType: 'text/html',
        scopeSnapshotId: uuid
      }).mediaType
    ).toBe('text/html')
    expect(
      StaticDiscoveryCandidateBatchSchema.parse({
        schemaVersion: 'agentgo.static-discovery.v1',
        batchId: uuid,
        scanId: uuid,
        artifactRef: uuid,
        artifactHash: hash,
        mediaType: 'text/html',
        producer: 'static-offline',
        candidates: [
          {
            key: 'worker:-:https://app.example.test/worker.js',
            kind: 'worker',
            url: 'https://app.example.test/worker.js',
            location: 'new Worker()',
            sourceProvenance: {
              generated: {
                file: 'https://app.example.test/app.js',
                line: 3,
                column: 2
              }
            },
            confidence: 0.6,
            capabilityStatus: 'unsupported',
            secretClassification: 'none',
            warnings: ['Worker is never executed.']
          }
        ],
        warnings: [],
        createdAt: now
      }).producer
    ).toBe('static-offline')
    expect(
      ExtractionRuleDraftSchema.parse({
        scanId: uuid,
        name: 'extract.csrf',
        sourceKind: 'json-pointer',
        sourceSelector: '/token',
        valueType: 'string',
        secretClassification: 'none',
        targetVariable: 'csrf.token',
        sourceRef: uuid,
        version: '1.0.0'
      }).sourceKind
    ).toBe('json-pointer')
  })
})
