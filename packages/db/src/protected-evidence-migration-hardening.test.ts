import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  EvidenceArtifactDraftSchema,
  PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
  PROTECTED_EVIDENCE_ARTIFACT_SCHEMA_VERSION,
  PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
  PROTECTED_EVIDENCE_PROTECTION_SCHEME,
  PROTECTED_EVIDENCE_POLICY_VERSION,
  type EvidenceArtifactDraft,
  type ProtectedEvidencePlan
} from '@agentgo/contracts'
import {
  openAgentGoDatabase,
  type AgentGoDatabase
} from './database'
import { AgentGoRepository } from './repository'

type ProtectedOriginalArtifact = Extract<
  EvidenceArtifactDraft,
  { type: 'evidence-capture-protected-original' }
>

type JsonObject = Record<string, unknown>

interface Fixture {
  database: AgentGoDatabase
  workspaceId: string
  scanId: string
  policyDecisionId: string
  now: number
  artifact: ProtectedOriginalArtifact
  plaintextSha256: string
  plaintextSize: number
  retentionUntil: number
}

interface ProtectedRows {
  evidenceId: string
  derivativeId: string
  storageSha256: string
  storageSize: number
  derivativeSha256: string
  retentionUntil: number
  artifactJson: JsonObject
  sourceHashJson: JsonObject
  protectionPlanJson: JsonObject
}

interface DerivativeOverrides {
  type?: string
  workspaceId?: string
  scanId?: string
  policyDecisionId?: string | null
  interactionId?: string | null
  mimeType?: string
  sha256?: string
  size?: number
  source?: string
  createdBy?: string
  captureTool?: string
  captureToolVersion?: string
  derivedFrom?: string | null
  redactionState?: string
  integrityStatus?: string
  retentionUntil?: number | null
}

const directories: string[] = []
const databases: AgentGoDatabase[] = []

afterEach(() => {
  for (const database of databases.splice(0)) {
    database.close()
  }
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function jsonObject(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`)
  }
  return value as JsonObject
}

function atPath(
  root: JsonObject,
  label: string,
  ...path: readonly string[]
): JsonObject {
  let current: unknown = root
  for (const segment of path) {
    current = jsonObject(current, label)[segment]
  }
  return jsonObject(current, label)
}

function cloneArtifact(artifact: ProtectedOriginalArtifact): JsonObject {
  return jsonObject(
    JSON.parse(JSON.stringify(artifact)) as unknown,
    'artifact'
  )
}

function removeAndPad(
  object: JsonObject,
  key: string,
  padding: unknown
): void {
  delete object[key]
  object.__padding = padding
}

function protectedPlan(plaintextSize: number): ProtectedEvidencePlan {
  const scanQuota = Math.max(plaintextSize, 32)
  return {
    protectionScheme: PROTECTED_EVIDENCE_PROTECTION_SCHEME,
    accessPolicyId: PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
    accessPolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
    derivativePolicyId: PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
    derivativePolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
    retentionSeconds: 3_600,
    maxScanPlaintextBytes: scanQuota,
    maxWorkspacePlaintextBytes: scanQuota * 2
  }
}

async function createFixture(): Promise<Fixture> {
  const directory = mkdtempSync(
    join(tmpdir(), 'agentgo-protected-migration-hardening-')
  )
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  databases.push(database)
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({
    name: 'Protected migration hardening',
    description: ''
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Protected migration hardening target',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'protected-migration-hardening',
    scope: {
      allowedOrigins: ['https://lab.example.test'],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [443],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      networkEntries: [],
      maxRequestsPerMinute: 10,
      maxConcurrency: 1
    }
  })
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'Protected migration hardening scan',
      description: 'Exercises protected Evidence SQL boundaries.',
      families: ['sqli'],
      identityIds: [],
      budget: {
        maxRequests: 10,
        maxRequestsPerMinute: 10,
        maxConcurrency: 1,
        maxPlanRevisions: 1,
        maxDurationMinutes: 10,
        maxModelTokens: 1_000,
        maxEstimatedCost: 1,
        maxRequestBytes: 10 * 1_146_880,
        maxResponseBytes: 10 * 16_777_216
      }
    },
    {},
    {}
  )
  const agentRun = await repository.createAgentRun({
    scanId: scan.id,
    role: 'strategy',
    promptId: 'protected-migration-hardening',
    promptVersion: '1.0.0',
    promptHash: sha256(
      Buffer.from('protected-migration-hardening-prompt')
    ),
    modelProfileId: 'deterministic-test-profile'
  })
  const proposal = await repository.createProbeProposal({
    scanId: scan.id,
    agentRunId: agentRun.id,
    action: {
      id: randomUUID(),
      kind: 'http-request',
      targetUrl: 'https://lab.example.test/items',
      method: 'GET',
      scopeSnapshotId: scan.scopeSnapshotId,
      probeLevel: 'active-safe',
      sideEffect: 'none',
      summary: 'Read-only protected Evidence SQL fixture.',
      expectedEvidence: 'Protected response body.',
      maxRequests: 1,
      timeoutMs: 5_000,
      userApproved: false
    },
    stopConditions: ['single request']
  })
  const policyDecision = await repository.recordPolicyDecision({
    proposalId: proposal.id,
    scopeSnapshotId: scan.scopeSnapshotId,
    decision: {
      allowed: true,
      requiresApproval: false,
      code: 'allowed',
      reasons: ['authorized protected Evidence SQL fixture'],
      normalizedTarget: 'https://lab.example.test/items'
    }
  })
  if (policyDecision.validUntil === null) {
    throw new Error('The protected Evidence fixture requires a policy window.')
  }

  const content = Buffer.from('P1-4 protected envelope')
  const plaintextSha256 = sha256(content)
  const plaintextSize = content.byteLength
  const now = Date.parse(policyDecision.createdAt) + 1
  const occurredAt = new Date(now).toISOString()
  const plan = protectedPlan(plaintextSize)
  const sourceHash = {
    domain: 'agentgo.evidence-source.v1' as const,
    algorithm: 'sha256' as const,
    digest: plaintextSha256,
    basis: 'source-bytes' as const,
    coverage: 'complete' as const,
    hashedBytes: plaintextSize,
    knownTotalBytes: plaintextSize
  }
  const captureDecisionId = randomUUID()
  const captureContext = {
    scanId: scan.id,
    policyDecisionId: policyDecision.id,
    techniqueId: 'sqli.boolean' as const,
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    executionState: 'succeeded' as const,
    source: 'http-response-body' as const,
    role: 'response-body',
    occurredAt,
    response: {
      mediaType: 'text/plain',
      charset: 'utf-8' as const,
      contentEncoding: 'identity' as const,
      declaredSizeBytes: plaintextSize
    }
  }
  const captureDecision = {
    id: captureDecisionId,
    scanId: scan.id,
    policyDecisionId: policyDecision.id,
    capturePolicyId: 'default-minimized-evidence',
    capturePolicyVersion: '1.0.0',
    techniqueId: 'sqli.boolean' as const,
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    executionState: 'succeeded' as const,
    source: 'http-response-body' as const,
    role: 'response-body',
    action: 'protected-original' as const,
    validFrom: policyDecision.createdAt,
    validUntil: policyDecision.validUntil,
    maxSourceBytes: Math.max(plaintextSize, 32),
    maxExcerptBytes: 32,
    jsonPointers: [],
    oobMetadataFields: [],
    protectedOriginalPlan: plan
  }
  const parsed = EvidenceArtifactDraftSchema.parse({
    type: 'evidence-capture-protected-original',
    mimeType: 'application/vnd.agentgo.protected-evidence',
    source: 'http-response-body',
    role: 'response-body',
    captureDecisionId,
    capturePolicyId: 'default-minimized-evidence',
    capturePolicyVersion: '1.0.0',
    redactionState: 'original',
    scanId: scan.id,
    policyDecisionId: policyDecision.id,
    techniqueId: 'sqli.boolean',
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    sourceHash,
    payload: {
      schemaVersion: PROTECTED_EVIDENCE_ARTIFACT_SCHEMA_VERSION,
      kind: 'protected-original-persistence-plan',
      originalMimeType: 'text/plain',
      plaintextSize,
      retentionUntil: new Date(
        now + plan.retentionSeconds * 1_000
      ).toISOString(),
      protectionPlan: plan,
      sourceHash,
      captureContext,
      captureDecision
    }
  })
  if (parsed.type !== 'evidence-capture-protected-original') {
    throw new Error('Expected a protected-original artifact.')
  }

  return {
    database,
    workspaceId: workspace.id,
    scanId: scan.id,
    policyDecisionId: policyDecision.id,
    now,
    artifact: parsed,
    plaintextSha256,
    plaintextSize,
    retentionUntil: Date.parse(parsed.payload.retentionUntil)
  }
}

function protectedRows(
  fixture: Fixture,
  options: {
    artifactJson?: JsonObject
    evidenceId?: string
    derivativeId?: string
    retentionUntil?: number
  } = {}
): ProtectedRows {
  const artifactJson =
    options.artifactJson ?? cloneArtifact(fixture.artifact)
  const payload = atPath(artifactJson, 'payload', 'payload')
  return {
    evidenceId: options.evidenceId ?? randomUUID(),
    derivativeId: options.derivativeId ?? randomUUID(),
    storageSha256: 'b'.repeat(64),
    storageSize: 48,
    derivativeSha256: 'd'.repeat(64),
    retentionUntil: options.retentionUntil ?? fixture.retentionUntil,
    artifactJson,
    sourceHashJson: jsonObject(
      artifactJson.sourceHash,
      'artifact.sourceHash'
    ),
    protectionPlanJson: jsonObject(
      payload.protectionPlan,
      'artifact.payload.protectionPlan'
    )
  }
}

function insertOriginal(fixture: Fixture, rows: ProtectedRows): void {
  fixture.database.native
    .prepare(
      `INSERT INTO evidence_items (
         id, workspace_id, scan_id, interaction_id, policy_decision_id,
         type, mime_type, file_path, sha256, size, source, created_by,
         capture_tool, capture_tool_version, derived_from, redaction_state,
         integrity_status, retention_until, created_at
       ) VALUES (
         ?, ?, ?, NULL, ?,
         'evidence-capture-protected-original', ?, ?, ?, ?, ?,
         'evidence-capture-policy', 'evidence-capture-policy', ?,
         NULL, 'original', 'verified', ?, ?
       )`
    )
    .run(
      rows.evidenceId,
      fixture.workspaceId,
      fixture.scanId,
      fixture.policyDecisionId,
      fixture.artifact.payload.originalMimeType,
      `fixture/evidence/${rows.storageSha256}.bin`,
      rows.storageSha256,
      rows.storageSize,
      fixture.artifact.source,
      fixture.artifact.capturePolicyVersion,
      rows.retentionUntil,
      fixture.now
    )
}

function insertProtected(fixture: Fixture, rows: ProtectedRows): void {
  fixture.database.native
    .prepare(
      `INSERT INTO protected_evidence_items (
         evidence_id, schema_version, capture_decision_id, evidence_role,
         derivative_evidence_id, derivative_sha256, capture_artifact_json,
         source_hash_json, protection_plan_json, original_mime_type,
         plaintext_sha256, plaintext_size, storage_sha256, storage_size,
         encryption_algorithm, wrapped_data_key, nonce, auth_tag,
         availability_state, retention_until, expired_at, created_at
       ) VALUES (
         ?, 'protected-evidence-storage.v1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
         ?, ?, 'aes-256-gcm+os-key-wrap', 'wrapped', 'nonce', 'tag',
         'available', ?, NULL, ?
       )`
    )
    .run(
      rows.evidenceId,
      fixture.artifact.captureDecisionId,
      fixture.artifact.role,
      rows.derivativeId,
      rows.derivativeSha256,
      JSON.stringify(rows.artifactJson),
      JSON.stringify(rows.sourceHashJson),
      JSON.stringify(rows.protectionPlanJson),
      fixture.artifact.payload.originalMimeType,
      fixture.plaintextSha256,
      fixture.plaintextSize,
      rows.storageSha256,
      rows.storageSize,
      rows.retentionUntil,
      fixture.now
    )
}

function insertDerivative(
  fixture: Fixture,
  rows: ProtectedRows,
  overrides: DerivativeOverrides = {}
): void {
  const sha = overrides.sha256 ?? rows.derivativeSha256
  fixture.database.native
    .prepare(
      `INSERT INTO evidence_items (
         id, workspace_id, scan_id, interaction_id, policy_decision_id,
         type, mime_type, file_path, sha256, size, source, created_by,
         capture_tool, capture_tool_version, derived_from, redaction_state,
         integrity_status, retention_until, created_at
       ) VALUES (
         ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
       )`
    )
    .run(
      rows.derivativeId,
      overrides.workspaceId ?? fixture.workspaceId,
      overrides.scanId ?? fixture.scanId,
      overrides.interactionId ?? null,
      overrides.policyDecisionId ?? fixture.policyDecisionId,
      overrides.type ?? 'evidence-capture-protected-derivative',
      overrides.mimeType ?? 'application/json',
      `fixture/evidence/${sha}.json`,
      sha,
      overrides.size ?? 96,
      overrides.source ?? 'protected-evidence-derivative',
      overrides.createdBy ?? 'evidence-store',
      overrides.captureTool ?? 'metadata-only-redacted-derivative',
      overrides.captureToolVersion ?? '1.0.0',
      overrides.derivedFrom ?? rows.evidenceId,
      overrides.redactionState ?? 'redacted',
      overrides.integrityStatus ?? 'verified',
      overrides.retentionUntil ?? rows.retentionUntil,
      fixture.now
    )
}

function inTransaction(
  database: AgentGoDatabase,
  action: () => void
): void {
  database.native.exec('BEGIN IMMEDIATE')
  try {
    action()
    database.native.exec('COMMIT')
  } catch (error) {
    database.native.exec('ROLLBACK')
    throw error
  }
}

describe('Protected Evidence SQL hardening', () => {
  it('preserves the production original-child-derivative transaction order', async () => {
    const fixture = await createFixture()
    const rows = protectedRows(fixture)

    expect(() =>
      inTransaction(fixture.database, () => {
        insertOriginal(fixture, rows)
        insertProtected(fixture, rows)
        insertDerivative(fixture, rows)
      })
    ).not.toThrow()

    const counts = fixture.database.native
      .prepare(
        `SELECT
           (SELECT count(*) FROM protected_evidence_items) AS protected_count,
           (SELECT count(*) FROM evidence_items
             WHERE type = 'evidence-capture-protected-derivative')
             AS derivative_count`
      )
      .get() as {
      protected_count: number
      derivative_count: number
    }
    expect(counts).toEqual({
      protected_count: 1,
      derivative_count: 1
    })
  })

  it('rejects retention extension beyond the authenticated artifact', async () => {
    const fixture = await createFixture()
    const rows = protectedRows(fixture, {
      retentionUntil: fixture.retentionUntil + 1_000
    })

    expect(() =>
      inTransaction(fixture.database, () => {
        insertOriginal(fixture, rows)
        insertProtected(fixture, rows)
      })
    ).toThrow(/protected evidence .*binding is invalid/iu)
  })

  it('rejects capture occurrence outside the persisted policy decision window', async () => {
    const fixture = await createFixture()
    fixture.database.native
      .prepare('UPDATE policy_decisions SET created_at = ? WHERE id = ?')
      .run(fixture.now + 1, fixture.policyDecisionId)
    const rows = protectedRows(fixture)

    expect(() =>
      inTransaction(fixture.database, () => {
        insertOriginal(fixture, rows)
        insertProtected(fixture, rows)
      })
    ).toThrow(/protected evidence .*binding is invalid/iu)
  })

  it('rejects padded JSON that omits a mandatory field at every envelope layer', async () => {
    const fixture = await createFixture()
    const cases: readonly {
      name: string
      mutate: (artifact: JsonObject) => void
    }[] = [
      {
        name: 'top-level',
        mutate: (artifact) => {
          removeAndPad(artifact, 'mimeType', 'application/json')
        }
      },
      {
        name: 'payload',
        mutate: (artifact) => {
          removeAndPad(
            atPath(artifact, 'payload', 'payload'),
            'plaintextSize',
            fixture.plaintextSize
          )
        }
      },
      {
        name: 'capture context',
        mutate: (artifact) => {
          removeAndPad(
            atPath(
              artifact,
              'capture context',
              'payload',
              'captureContext'
            ),
            'executionState',
            'succeeded'
          )
        }
      },
      {
        name: 'response descriptor',
        mutate: (artifact) => {
          removeAndPad(
            atPath(
              artifact,
              'response descriptor',
              'payload',
              'captureContext',
              'response'
            ),
            'charset',
            'utf-8'
          )
        }
      },
      {
        name: 'capture decision',
        mutate: (artifact) => {
          removeAndPad(
            atPath(
              artifact,
              'capture decision',
              'payload',
              'captureDecision'
            ),
            'maxExcerptBytes',
            32
          )
        }
      },
      {
        name: 'protection plan',
        mutate: (artifact) => {
          removeAndPad(
            atPath(
              artifact,
              'payload protection plan',
              'payload',
              'protectionPlan'
            ),
            'retentionSeconds',
            3_600
          )
          removeAndPad(
            atPath(
              artifact,
              'decision protection plan',
              'payload',
              'captureDecision',
              'protectedOriginalPlan'
            ),
            'retentionSeconds',
            3_600
          )
        }
      },
      {
        name: 'source hash',
        mutate: (artifact) => {
          removeAndPad(
            atPath(artifact, 'outer source hash', 'sourceHash'),
            'knownTotalBytes',
            fixture.plaintextSize
          )
          removeAndPad(
            atPath(
              artifact,
              'payload source hash',
              'payload',
              'sourceHash'
            ),
            'knownTotalBytes',
            fixture.plaintextSize
          )
        }
      }
    ]

    for (const testCase of cases) {
      const artifact = cloneArtifact(fixture.artifact)
      testCase.mutate(artifact)
      const rows = protectedRows(fixture, { artifactJson: artifact })
      expect(
        () =>
          inTransaction(fixture.database, () => {
            insertOriginal(fixture, rows)
            insertProtected(fixture, rows)
          }),
        testCase.name
      ).toThrow(/protected evidence .*binding is invalid/iu)
    }
  })

  it('rejects self and malformed derivative bindings in either insertion order', async () => {
    const fixture = await createFixture()

    const selfRows = protectedRows(fixture)
    selfRows.derivativeId = selfRows.evidenceId
    expect(() =>
      inTransaction(fixture.database, () => {
        insertOriginal(fixture, selfRows)
        insertProtected(fixture, selfRows)
      })
    ).toThrow(/protected evidence .*binding is invalid/iu)

    const preexistingRows = protectedRows(fixture)
    expect(() =>
      inTransaction(fixture.database, () => {
        insertOriginal(fixture, preexistingRows)
        insertDerivative(fixture, preexistingRows, {
          type: 'ordinary-evidence'
        })
        insertProtected(fixture, preexistingRows)
      })
    ).toThrow(/protected evidence .*binding is invalid/iu)

    const deferredRows = protectedRows(fixture)
    expect(() =>
      inTransaction(fixture.database, () => {
        insertOriginal(fixture, deferredRows)
        insertProtected(fixture, deferredRows)
        insertDerivative(fixture, deferredRows, {
          type: 'ordinary-evidence'
        })
      })
    ).toThrow(
      /referenced protected evidence derivative binding is invalid/iu
    )

    const wrongMetadataRows = protectedRows(fixture)
    expect(() =>
      inTransaction(fixture.database, () => {
        insertOriginal(fixture, wrongMetadataRows)
        insertProtected(fixture, wrongMetadataRows)
        insertDerivative(fixture, wrongMetadataRows, {
          derivedFrom: randomUUID()
        })
      })
    ).toThrow(/protected evidence derivative binding is invalid/iu)
  })

  it('rejects updates that enter either protected reserved type', async () => {
    const fixture = await createFixture()
    const evidenceId = randomUUID()
    const digest = 'a'.repeat(64)
    fixture.database.native
      .prepare(
        `INSERT INTO evidence_items (
           id, workspace_id, scan_id, interaction_id, policy_decision_id,
           type, mime_type, file_path, sha256, size, source, created_by,
           capture_tool, capture_tool_version, derived_from,
           redaction_state, integrity_status, retention_until, created_at
         ) VALUES (
           ?, ?, ?, NULL, ?, 'ordinary-evidence', 'text/plain', ?, ?, 1,
           'test', 'test', 'test', '1.0.0', NULL,
           'redacted', 'verified', NULL, ?
         )`
      )
      .run(
        evidenceId,
        fixture.workspaceId,
        fixture.scanId,
        fixture.policyDecisionId,
        `fixture/evidence/${digest}.txt`,
        digest,
        fixture.now
      )

    for (const reservedType of [
      'evidence-capture-protected-original',
      'evidence-capture-protected-derivative'
    ] as const) {
      expect(() =>
        fixture.database.native
          .prepare('UPDATE evidence_items SET type = ? WHERE id = ?')
          .run(reservedType, evidenceId)
      ).toThrow(/ordinary evidence cannot enter a reserved protected type/iu)
    }
    const row = fixture.database.native
      .prepare('SELECT type FROM evidence_items WHERE id = ?')
      .get(evidenceId) as { type: string }
    expect(row.type).toBe('ordinary-evidence')
  })
})
