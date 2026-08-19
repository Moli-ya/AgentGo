import { createHash, randomUUID } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
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
import type { SecretProtector } from './credential-store'
import { openAgentGoDatabase } from './database'
import { EvidenceStore } from './evidence-store'
import { AgentGoRepository } from './repository'

const SENTINEL = 'DAY4-PROTECTED-ORIGINAL-SENTINEL'
const WRAP_MASK = Buffer.from(
  '9d11ed9fc4ac475bb8ad836a0c7f49e7',
  'hex'
)
const directories: string[] = []

type ProtectedOriginalArtifact = Extract<
  EvidenceArtifactDraft,
  { type: 'evidence-capture-protected-original' }
>

interface ProtectedFixture {
  database: ReturnType<typeof openAgentGoDatabase>
  workspaceId: string
  scanId: string
  policyDecisionId: string
  captureValidFrom: string
  captureValidUntil: string
  captureNow: number
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

function testProtector(available = true): SecretProtector {
  const transform = (value: Buffer): Buffer => {
    const output = Buffer.alloc(value.byteLength)
    for (let index = 0; index < value.byteLength; index += 1) {
      output[index] =
        value[index]! ^ WRAP_MASK[index % WRAP_MASK.byteLength]!
    }
    return output
  }
  return {
    isAvailable: () => available,
    protect: (value) => {
      if (!available) throw new Error('test protector unavailable')
      return transform(Buffer.from(value, 'utf8'))
    },
    unprotect: (value) => {
      if (!available) throw new Error('test protector unavailable')
      return transform(value).toString('utf8')
    }
  }
}

async function createProtectedFixture(
  directory: string
): Promise<ProtectedFixture> {
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({
    name: 'Protected Evidence',
    description: ''
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Protected Evidence Lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'protected-evidence-test',
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
      maxRequestsPerMinute: 10,
      maxConcurrency: 1
    }
  })
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'Protected Evidence scan',
      description: 'Day 4 protected Evidence test fixture.',
      families: ['sqli'],
      identityIds: [],
      budget: {
        maxRequests: 10,
        maxRequestsPerMinute: 10,
        maxConcurrency: 1,
        maxPlanRevisions: 1,
        maxDurationMinutes: 10,
        maxModelTokens: 1_000,
        maxEstimatedCost: 1
      }
    },
    {},
    {}
  )
  const agentRun = await repository.createAgentRun({
    scanId: scan.id,
    role: 'strategy',
    promptId: 'protected-evidence-test',
    promptVersion: '1.0.0',
    promptHash: sha256(Buffer.from('protected-evidence-test-prompt')),
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
      summary: 'Read-only protected Evidence fixture.',
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
      reasons: ['authorized protected Evidence fixture'],
      normalizedTarget: 'https://lab.example.test/items'
    }
  })
  return {
    database,
    workspaceId: workspace.id,
    scanId: scan.id,
    policyDecisionId: policyDecision.id,
    captureValidFrom: policyDecision.createdAt,
    captureValidUntil:
      policyDecision.validUntil ??
      new Date(Date.parse(policyDecision.createdAt) + 60_000).toISOString(),
    captureNow: Date.parse(policyDecision.createdAt) + 1
  }
}

function protectedPlan(
  plaintextBytes: number,
  overrides: Partial<ProtectedEvidencePlan> = {}
): ProtectedEvidencePlan {
  return {
    protectionScheme: PROTECTED_EVIDENCE_PROTECTION_SCHEME,
    accessPolicyId: PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
    accessPolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
    derivativePolicyId: PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
    derivativePolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
    retentionSeconds: 3_600,
    maxScanPlaintextBytes: Math.max(plaintextBytes, 1),
    maxWorkspacePlaintextBytes: Math.max(plaintextBytes * 2, 1),
    ...overrides
  }
}

function protectedArtifact(input: {
  fixture: ProtectedFixture
  content: Uint8Array
  now: number
  plan?: ProtectedEvidencePlan
  captureDecisionId?: string
}): ProtectedOriginalArtifact {
  const plan = input.plan ?? protectedPlan(input.content.byteLength)
  const sourceHash = {
    domain: 'agentgo.evidence-source.v1' as const,
    algorithm: 'sha256' as const,
    digest: sha256(input.content),
    basis: 'source-bytes' as const,
    coverage: 'complete' as const,
    hashedBytes: input.content.byteLength,
    knownTotalBytes: input.content.byteLength
  }
  const occurredAt = new Date(input.now).toISOString()
  const captureContext = {
    scanId: input.fixture.scanId,
    policyDecisionId: input.fixture.policyDecisionId,
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
      declaredSizeBytes: input.content.byteLength
    }
  }
  const captureDecision = {
    id: input.captureDecisionId ?? randomUUID(),
    scanId: input.fixture.scanId,
    policyDecisionId: input.fixture.policyDecisionId,
    capturePolicyId: 'default-minimized-evidence',
    capturePolicyVersion: '1.0.0',
    techniqueId: 'sqli.boolean' as const,
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    executionState: 'succeeded' as const,
    source: 'http-response-body' as const,
    role: 'response-body',
    action: 'protected-original' as const,
    validFrom: input.fixture.captureValidFrom,
    validUntil: input.fixture.captureValidUntil,
    maxSourceBytes: Math.max(input.content.byteLength, 32),
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
    captureDecisionId: captureDecision.id,
    capturePolicyId: 'default-minimized-evidence',
    capturePolicyVersion: '1.0.0',
    redactionState: 'original',
    scanId: input.fixture.scanId,
    policyDecisionId: input.fixture.policyDecisionId,
    techniqueId: 'sqli.boolean',
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    sourceHash,
    payload: {
      schemaVersion: PROTECTED_EVIDENCE_ARTIFACT_SCHEMA_VERSION,
      kind: 'protected-original-persistence-plan',
      originalMimeType: 'text/plain',
      plaintextSize: input.content.byteLength,
      retentionUntil: new Date(
        input.now + plan.retentionSeconds * 1_000
      ).toISOString(),
      protectionPlan: plan,
      sourceHash,
      captureContext,
      captureDecision
    }
  })
  if (parsed.type !== 'evidence-capture-protected-original') {
    throw new Error('Expected protected-original artifact.')
  }
  return parsed
}

describe('protected EvidenceStore', () => {
  it('encrypts an authorized original, denies generic reads, and creates a metadata-only derivative', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(`${SENTINEL}\nAuthorization: Bearer secret`)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => now }
    )
    const artifact = protectedArtifact({ fixture, content, now })

    const saved = await store.saveProtectedOriginalWithDerivative({
      artifact,
      content
    })

    expect(saved.original).toMatchObject({
      protectionState: 'protected-original',
      availabilityState: 'available',
      plaintextSha256: artifact.sourceHash.digest,
      plaintextSize: content.byteLength,
      redactionState: 'original'
    })
    expect(saved.derivative).toMatchObject({
      protectionState: 'unprotected',
      derivedFrom: saved.original.id,
      redactionState: 'redacted'
    })
    const ciphertext = readFileSync(
      store.resolveStoredPath(saved.original.filePath)
    )
    expect(ciphertext.toString('utf8')).not.toContain(SENTINEL)
    expect(saved.original.filePath.endsWith('.bin')).toBe(true)
    await expect(store.read(saved.original.id)).rejects.toThrow(
      'generic API'
    )
    const derivative = (
      await store.read(saved.derivative.id)
    ).content.toString('utf8')
    expect(derivative).not.toContain(SENTINEL)
    expect(derivative).toContain('"contentIncluded":false')
    await expect(
      store.verifyProtectedOriginal({
        id: saved.original.id,
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId
      })
    ).resolves.toBe(true)
    const persistedJson = fixture.database.native
      .prepare(
        `SELECT capture_artifact_json, source_hash_json,
                protection_plan_json, wrapped_data_key
           FROM protected_evidence_items
          WHERE evidence_id = ?`
      )
      .get(saved.original.id)
    expect(JSON.stringify(persistedJson)).not.toContain(SENTINEL)
    const auditJson = fixture.database.native
      .prepare(
        `SELECT group_concat(detail_json, '') AS details
           FROM audit_logs
          WHERE event LIKE 'evidence.protected.%'`
      )
      .get() as { details?: string } | undefined
    expect(auditJson?.details ?? '').not.toContain(SENTINEL)
    fixture.database.close()
  })

  it('fails integrity verification after ciphertext tampering without exposing plaintext', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => now }
    )
    const saved = await store.saveProtectedOriginalWithDerivative({
      artifact: protectedArtifact({ fixture, content, now }),
      content
    })
    const ciphertextPath = store.resolveStoredPath(saved.original.filePath)
    const originalCiphertext = readFileSync(ciphertextPath)
    writeFileSync(
      ciphertextPath,
      Buffer.alloc(saved.original.size, 0x41)
    )

    await expect(
      store.verifyProtectedOriginal({
        id: saved.original.id,
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId
      })
    ).rejects.toThrow('integrity verification failed')
    expect((await store.getMetadata(saved.original.id))?.integrityStatus).toBe(
      'failed'
    )
    writeFileSync(ciphertextPath, originalCiphertext)
    await expect(
      store.verifyProtectedOriginal({
        id: saved.original.id,
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId
      })
    ).rejects.toThrow('cannot be restored')
    const successfulAccessCount = fixture.database.native
      .prepare(
        `SELECT count(*) AS count
           FROM audit_logs
          WHERE event = 'evidence.protected.accessed'
            AND json_extract(detail_json, '$.evidenceId') = ?`
      )
      .get(saved.original.id) as { count: number }
    expect(successfulAccessCount.count).toBe(0)
    fixture.database.close()
  })

  it('enforces scan quota atomically and leaves no failed-write metadata', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const plan = protectedPlan(content.byteLength, {
      maxScanPlaintextBytes: content.byteLength,
      maxWorkspacePlaintextBytes: content.byteLength
    })
    const artifactRoot = join(directory, 'artifacts')
    const firstStore = new EvidenceStore(fixture.database, artifactRoot, {
      protector: testProtector(),
      clock: () => now
    })
    const secondDatabase = openAgentGoDatabase(
      join(directory, 'agentgo.sqlite')
    )
    const secondStore = new EvidenceStore(secondDatabase, artifactRoot, {
      protector: testProtector(),
      clock: () => now
    })

    try {
      const results = await Promise.allSettled([
        firstStore.saveProtectedOriginalWithDerivative({
          artifact: protectedArtifact({ fixture, content, now, plan }),
          content
        }),
        secondStore.saveProtectedOriginalWithDerivative({
          artifact: protectedArtifact({ fixture, content, now, plan }),
          content
        })
      ])
      expect(results.filter(({ status }) => status === 'fulfilled')).toHaveLength(
        1
      )
      expect(results.filter(({ status }) => status === 'rejected')).toHaveLength(
        1
      )
      const count = fixture.database.native
        .prepare(
          `SELECT count(*) AS count
             FROM protected_evidence_items
            WHERE availability_state = 'available'`
        )
        .get() as { count: number }
      expect(count.count).toBe(1)
      expect(await firstStore.list(fixture.scanId)).toHaveLength(2)
    } finally {
      secondDatabase.close()
      fixture.database.close()
    }
  })

  it('crypto-erases expired originals, retains metadata and derivative, and releases quota', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    let now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const plan = protectedPlan(content.byteLength, {
      retentionSeconds: 60,
      maxScanPlaintextBytes: content.byteLength,
      maxWorkspacePlaintextBytes: content.byteLength
    })
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => now }
    )
    const first = await store.saveProtectedOriginalWithDerivative({
      artifact: protectedArtifact({ fixture, content, now, plan }),
      content
    })
    const ciphertextPath = store.resolveStoredPath(first.original.filePath)
    now += 61_000

    await expect(store.sweepExpiredProtectedOriginals()).resolves.toEqual({
      expiredItems: 1,
      deletedCiphertextFiles: 1
    })
    expect(existsSync(ciphertextPath)).toBe(false)
    expect(await store.getMetadata(first.original.id)).toMatchObject({
      protectionState: 'protected-original',
      availabilityState: 'expired',
      integrityStatus: 'expired'
    })
    await expect(store.read(first.derivative.id)).resolves.toBeDefined()
    await expect(
      store.verifyProtectedOriginal({
        id: first.original.id,
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId
      })
    ).rejects.toThrow('no longer available')
    const keyState = fixture.database.native
      .prepare(
        `SELECT wrapped_data_key, nonce, auth_tag
           FROM protected_evidence_items
          WHERE evidence_id = ?`
      )
      .get(first.original.id) as {
      wrapped_data_key: string | null
      nonce: string | null
      auth_tag: string | null
    }
    expect(keyState).toEqual({
      wrapped_data_key: null,
      nonce: null,
      auth_tag: null
    })

    await expect(
      store.saveProtectedOriginalWithDerivative({
        artifact: protectedArtifact({ fixture, content, now, plan }),
        content
      })
    ).resolves.toBeDefined()
    fixture.database.close()
  })

  it('fails closed without an OS-backed protector and writes no Evidence metadata', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(false), clock: () => now }
    )

    await expect(
      store.saveProtectedOriginalWithDerivative({
        artifact: protectedArtifact({ fixture, content, now }),
        content
      })
    ).rejects.toThrow('encryption is unavailable')
    expect(await store.list(fixture.scanId)).toEqual([])
    fixture.database.close()
  })

  it('commits original, derivative, and created audit atomically', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => now }
    )
    fixture.database.native.exec(`
      CREATE TRIGGER synthetic_protected_audit_failure
      BEFORE INSERT ON audit_logs
      WHEN NEW.event = 'evidence.protected.created'
      BEGIN
        SELECT RAISE(ABORT, 'synthetic protected audit failure');
      END;
    `)

    await expect(
      store.saveProtectedOriginalWithDerivative({
        artifact: protectedArtifact({ fixture, content, now }),
        content
      })
    ).rejects.toThrow('Failed query')
    expect(await store.list(fixture.scanId)).toEqual([])
    const evidenceCount = fixture.database.native
      .prepare('SELECT count(*) AS count FROM evidence_items')
      .get() as { count: number }
    expect(evidenceCount.count).toBe(0)
    await expect(store.sweepUnreferencedContentFiles()).resolves.toBe(0)
    fixture.database.close()
  })

  it('keeps a verified item healthy when success-audit or key unwrap fails operationally', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const baseProtector = testProtector()
    let unwrapUnavailable = false
    const protector: SecretProtector = {
      isAvailable: () => true,
      protect: (value) => baseProtector.protect(value),
      unprotect: (value) => {
        if (unwrapUnavailable) {
          throw new Error('synthetic unwrap outage')
        }
        return baseProtector.unprotect(value)
      }
    }
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector, clock: () => now }
    )
    const saved = await store.saveProtectedOriginalWithDerivative({
      artifact: protectedArtifact({ fixture, content, now }),
      content
    })
    unwrapUnavailable = true
    await expect(
      store.verifyProtectedOriginal({
        id: saved.original.id,
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId
      })
    ).rejects.toThrow('could not be completed')
    expect((await store.getMetadata(saved.original.id))?.integrityStatus).toBe(
      'verified'
    )

    unwrapUnavailable = false
    fixture.database.native.exec(`
      CREATE TRIGGER synthetic_protected_access_audit_failure
      BEFORE INSERT ON audit_logs
      WHEN NEW.event = 'evidence.protected.accessed'
      BEGIN
        SELECT RAISE(ABORT, 'synthetic access audit failure');
      END;
    `)
    await expect(
      store.verifyProtectedOriginal({
        id: saved.original.id,
        workspaceId: fixture.workspaceId,
        scanId: fixture.scanId
      })
    ).rejects.toThrow('Failed query')
    expect((await store.getMetadata(saved.original.id))?.integrityStatus).toBe(
      'verified'
    )
    fixture.database.close()
  })

  it('makes protected rows and derivatives immutable and rejects generic discard', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => now }
    )
    const saved = await store.saveProtectedOriginalWithDerivative({
      artifact: protectedArtifact({ fixture, content, now }),
      content
    })

    expect(() =>
      fixture.database.native
        .prepare(
          `UPDATE evidence_items
              SET source = 'unsafe-replacement'
            WHERE id = ?`
        )
        .run(saved.derivative.id)
    ).toThrow('immutable')
    expect(() =>
      fixture.database.native
        .prepare(
          'DELETE FROM protected_evidence_items WHERE evidence_id = ?'
        )
        .run(saved.original.id)
    ).toThrow('requires parent deletion')
    await expect(store.discardUnboundEvidence(saved.original)).resolves.toBe(
      false
    )
    await expect(store.discardUnboundEvidence(saved.derivative)).resolves.toBe(
      false
    )
    fixture.database.close()
  })

  it('is idempotent for one capture decision and emits one creation audit', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => now }
    )
    const artifact = protectedArtifact({ fixture, content, now })

    const first = await store.saveProtectedOriginalWithDerivative({
      artifact,
      content
    })
    const second = await store.saveProtectedOriginalWithDerivative({
      artifact,
      content
    })

    expect(second.original.id).toBe(first.original.id)
    expect(second.derivative.id).toBe(first.derivative.id)
    expect(await store.list(fixture.scanId)).toHaveLength(2)
    const auditCount = fixture.database.native
      .prepare(
        `SELECT count(*) AS count
           FROM audit_logs
          WHERE event = 'evidence.protected.created'`
      )
      .get() as { count: number }
    expect(auditCount.count).toBe(1)
    fixture.database.close()
  })

  it('lets only one concurrent expiry sweep erase and audit an item', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    let now = fixture.captureNow
    const content = Buffer.from(SENTINEL)
    const plan = protectedPlan(content.byteLength, {
      retentionSeconds: 60
    })
    const artifactRoot = join(directory, 'artifacts')
    const firstStore = new EvidenceStore(fixture.database, artifactRoot, {
      protector: testProtector(),
      clock: () => now
    })
    const secondDatabase = openAgentGoDatabase(
      join(directory, 'agentgo.sqlite')
    )
    const secondStore = new EvidenceStore(secondDatabase, artifactRoot, {
      protector: testProtector(),
      clock: () => now
    })
    try {
      await firstStore.saveProtectedOriginalWithDerivative({
        artifact: protectedArtifact({ fixture, content, now, plan }),
        content
      })
      now += 61_000
      const sweeps = await Promise.all([
        firstStore.sweepExpiredProtectedOriginals(),
        secondStore.sweepExpiredProtectedOriginals()
      ])
      expect(
        sweeps.reduce((total, sweep) => total + sweep.expiredItems, 0)
      ).toBe(1)
      const auditCount = fixture.database.native
        .prepare(
          `SELECT count(*) AS count
             FROM audit_logs
            WHERE event = 'evidence.protected.expired'`
        )
        .get() as { count: number }
      expect(auditCount.count).toBe(1)
    } finally {
      secondDatabase.close()
      fixture.database.close()
    }
  })

  it('rejects protected metadata JSON with missing mandatory fields at the SQL boundary', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const evidenceId = randomUUID()
    const derivativeId = randomUUID()
    const digest = 'b'.repeat(64)
    const retentionUntil = fixture.captureNow + 60_000
    fixture.database.native
      .prepare(
        `INSERT INTO evidence_items (
           id, workspace_id, scan_id, interaction_id, policy_decision_id,
           type, mime_type, file_path, sha256, size, source, created_by,
           capture_tool, capture_tool_version, derived_from,
           redaction_state, integrity_status, retention_until, created_at
         ) VALUES (
           ?, ?, ?, NULL, ?,
           'evidence-capture-protected-original', 'text/plain',
           'bbbbbbbbbbbbbbbbbbbb/evidence/bb/${digest}.bin',
           ?, 1, 'http-response-body', 'test',
           'test', '1.0.0', NULL,
           'original', 'verified', ?, ?
         )`
      )
      .run(
        evidenceId,
        fixture.workspaceId,
        fixture.scanId,
        fixture.policyDecisionId,
        digest,
        retentionUntil,
        fixture.captureNow
      )

    expect(() =>
      fixture.database.native
        .prepare(
          `INSERT INTO protected_evidence_items (
             evidence_id, schema_version, capture_decision_id, evidence_role,
             derivative_evidence_id, derivative_sha256,
             capture_artifact_json, source_hash_json, protection_plan_json,
             original_mime_type, plaintext_sha256, plaintext_size,
             storage_sha256, storage_size, encryption_algorithm,
             wrapped_data_key, nonce, auth_tag, availability_state,
             retention_until, expired_at, created_at
           ) VALUES (
             ?, 'protected-evidence-storage.v1', ?, 'response-body',
             ?, ?, '{}',
             '{"domain":"agentgo.evidence-source.v1","algorithm":"sha256","digest":"${digest}","basis":"source-bytes","coverage":"complete","hashedBytes":1,"knownTotalBytes":1}',
             '{"protectionScheme":"os-wrapped-aes-256-gcm.v1","accessPolicyId":"backend-only-protected-evidence","accessPolicyVersion":"1.0.0","derivativePolicyId":"metadata-only-redacted-derivative","derivativePolicyVersion":"1.0.0","retentionSeconds":60,"maxScanPlaintextBytes":1,"maxWorkspacePlaintextBytes":1}',
             'text/plain', ?, 1, ?, 1,
             'aes-256-gcm+os-key-wrap', 'wrapped', 'nonce', 'tag',
             'available', ?, NULL, ?
           )`
        )
        .run(
          evidenceId,
          randomUUID(),
          derivativeId,
          digest,
          digest,
          digest,
          retentionUntil,
          fixture.captureNow
        )
    ).toThrow()
    const protectedCount = fixture.database.native
      .prepare(
        'SELECT count(*) AS count FROM protected_evidence_items'
      )
      .get() as { count: number }
    expect(protectedCount.count).toBe(0)
    fixture.database.close()
  })

  it('fails closed for a protected-original parent whose envelope row is missing', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => fixture.captureNow }
    )
    const content = Buffer.from(SENTINEL)
    const digest = sha256(content)
    const workspaceDirectory = createHash('sha256')
      .update(fixture.workspaceId)
      .digest('hex')
      .slice(0, 20)
    const relativePath =
      `${workspaceDirectory}/evidence/${digest.slice(0, 2)}/${digest}.bin`
    const absolutePath = store.resolveStoredPath(relativePath)
    mkdirSync(dirname(absolutePath), { recursive: true })
    writeFileSync(absolutePath, content)
    const evidenceId = randomUUID()
    fixture.database.native
      .prepare(
        `INSERT INTO evidence_items (
           id, workspace_id, scan_id, interaction_id, policy_decision_id,
           type, mime_type, file_path, sha256, size, source, created_by,
           capture_tool, capture_tool_version, derived_from,
           redaction_state, integrity_status, retention_until, created_at
         ) VALUES (
           ?, ?, ?, NULL, ?,
           'evidence-capture-protected-original', 'text/plain',
           ?, ?, ?, 'http-response-body', 'test',
           'test', '1.0.0', NULL,
           'original', 'verified', ?, ?
         )`
      )
      .run(
        evidenceId,
        fixture.workspaceId,
        fixture.scanId,
        fixture.policyDecisionId,
        relativePath,
        digest,
        content.byteLength,
        fixture.captureNow + 60_000,
        fixture.captureNow
      )

    await expect(store.getMetadata(evidenceId)).rejects.toThrow(
      'envelope is missing'
    )
    await expect(store.list(fixture.scanId)).rejects.toThrow(
      'envelope is missing'
    )
    await expect(store.read(evidenceId)).rejects.toThrow(
      'envelope is missing'
    )
    await expect(
      store.createRedactedTextDerivative(evidenceId, 'test')
    ).rejects.toThrow('envelope is missing')
    expect(readFileSync(absolutePath).toString('utf8')).toBe(SENTINEL)
    fixture.database.close()
  })

  it('allows an authorized workspace cascade to remove the protected pair', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-protected-evidence-'))
    directories.push(directory)
    const fixture = await createProtectedFixture(directory)
    const content = Buffer.from(SENTINEL)
    const store = new EvidenceStore(
      fixture.database,
      join(directory, 'artifacts'),
      { protector: testProtector(), clock: () => fixture.captureNow }
    )
    await store.saveProtectedOriginalWithDerivative({
      artifact: protectedArtifact({
        fixture,
        content,
        now: fixture.captureNow
      }),
      content
    })

    expect(() =>
      fixture.database.native
        .prepare('DELETE FROM workspaces WHERE id = ?')
        .run(fixture.workspaceId)
    ).not.toThrow()
    const remaining = fixture.database.native
      .prepare(
        `SELECT
           (SELECT count(*) FROM evidence_items) AS evidence_count,
           (SELECT count(*) FROM protected_evidence_items) AS protected_count`
      )
      .get() as { evidence_count: number; protected_count: number }
    expect(remaining).toEqual({
      evidence_count: 0,
      protected_count: 0
    })
    fixture.database.close()
  })
})
