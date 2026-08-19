import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  EvidenceSummarySchema,
  PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
  PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
  PROTECTED_EVIDENCE_PROTECTION_SCHEME,
  PROTECTED_EVIDENCE_POLICY_VERSION,
  type ProtectedOriginalEvidenceCaptureContext,
  type ProtectedOriginalEvidenceCaptureDecision
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  openAgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import {
  AgentGoApplicationService,
  EvidenceCapturePolicy,
  ProtectedEvidenceCaptureService,
  createDay2VulnerabilityPlatform
} from './index'

const directories: string[] = []

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function protector(): SecretProtector {
  const mask = 0x5a
  const transform = (value: Buffer): Buffer =>
    Buffer.from(value.map((byte) => byte ^ mask))
  return {
    isAvailable: () => true,
    protect: (value) => transform(Buffer.from(value, 'utf8')),
    unprotect: (value) => transform(value).toString('utf8')
  }
}

async function createFixture() {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-report-security-'))
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({
    name: 'Report security',
    description: ''
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Report fixture',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'report-security-test',
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
  const createScan = (name: string) =>
    repository.createScan(
      {
        targetId: target.target.id,
        name,
        description: 'Report projection integration fixture.',
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
  const scan = await createScan('Primary report scan')
  const evidenceStore = new EvidenceStore(
    database,
    join(directory, 'artifacts'),
    { protector: protector() }
  )
  const application = new AgentGoApplicationService({
    repository,
    credentialStore: new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector()
    ),
    evidenceStore,
    vulnerabilityPlatform: createDay2VulnerabilityPlatform(),
    vulnerabilityExecutionEnvironment: 'authorized-test-environment'
  })
  return {
    application,
    createScan,
    database,
    directory,
    evidenceStore,
    repository,
    scan,
    target,
    workspace
  }
}

async function createProtectedPair(
  fixture: Awaited<ReturnType<typeof createFixture>>
) {
  const run = await fixture.repository.createAgentRun({
    scanId: fixture.scan.id,
    role: 'strategy',
    promptId: 'report-protected-fixture',
    promptVersion: '1.0.0',
    promptHash: sha256('report-protected-fixture'),
    modelProfileId: 'deterministic-test-profile'
  })
  const proposal = await fixture.repository.createProbeProposal({
    scanId: fixture.scan.id,
    agentRunId: run.id,
    action: {
      id: randomUUID(),
      kind: 'http-request',
      targetUrl: 'https://lab.example.test/protected-report-source',
      method: 'GET',
      scopeSnapshotId: fixture.scan.scopeSnapshotId,
      probeLevel: 'active-safe',
      sideEffect: 'none',
      summary: 'Read-only protected report source.',
      expectedEvidence: 'Encrypted response bytes.',
      maxRequests: 1,
      timeoutMs: 5_000,
      userApproved: false
    },
    stopConditions: ['single request']
  })
  const policyDecision = await fixture.repository.recordPolicyDecision({
    proposalId: proposal.id,
    scopeSnapshotId: fixture.scan.scopeSnapshotId,
    decision: {
      allowed: true,
      requiresApproval: false,
      code: 'allowed',
      reasons: ['authorized report fixture'],
      normalizedTarget:
        'https://lab.example.test/protected-report-source'
    }
  })
  const content = Buffer.from(
    'REPORT-PROTECTED-PLAINTEXT-SENTINEL',
    'utf8'
  )
  const occurredAt = new Date(
    Date.parse(policyDecision.createdAt) + 1
  ).toISOString()
  const context: ProtectedOriginalEvidenceCaptureContext = {
    scanId: fixture.scan.id,
    policyDecisionId: policyDecision.id,
    techniqueId: 'sqli.boolean',
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    executionState: 'succeeded',
    source: 'http-response-body',
    role: 'response-body',
    occurredAt,
    response: {
      mediaType: 'application/octet-stream',
      charset: 'not-applicable',
      contentEncoding: 'compressed',
      declaredSizeBytes: content.byteLength
    }
  }
  const plan = {
    protectionScheme: PROTECTED_EVIDENCE_PROTECTION_SCHEME,
    accessPolicyId: PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
    accessPolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
    derivativePolicyId: PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
    derivativePolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
    retentionSeconds: 3_600,
    maxScanPlaintextBytes: content.byteLength,
    maxWorkspacePlaintextBytes: content.byteLength
  } as const
  const decision: ProtectedOriginalEvidenceCaptureDecision = {
    id: randomUUID(),
    scanId: fixture.scan.id,
    policyDecisionId: policyDecision.id,
    capturePolicyId: 'default-minimized-evidence',
    capturePolicyVersion: '1.0.0',
    techniqueId: 'sqli.boolean',
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    executionState: 'succeeded',
    source: 'http-response-body',
    role: 'response-body',
    action: 'protected-original',
    validFrom: policyDecision.createdAt,
    validUntil:
      policyDecision.validUntil ??
      new Date(
        Date.parse(policyDecision.createdAt) + 60_000
      ).toISOString(),
    maxSourceBytes: content.byteLength,
    maxExcerptBytes: 32,
    jsonPointers: [],
    oobMetadataFields: [],
    protectedOriginalPlan: plan
  }
  return new ProtectedEvidenceCaptureService(
    new EvidenceCapturePolicy(),
    fixture.evidenceStore
  ).captureAndPersist({
    context,
    decision,
    content,
    knownTotalBytes: content.byteLength
  })
}

function insertReport(
  fixture: Awaited<ReturnType<typeof createFixture>>,
  input: {
    scanId: string
    contentRef: string
    sha256: string
    redacted: boolean
    format?: 'markdown' | 'json' | 'html'
  }
): string {
  const id = randomUUID()
  fixture.database.native
    .prepare(
      `INSERT INTO reports (
        id, scan_id, title, format, file_path, sha256,
        redacted, content_ref, created_at
      ) VALUES (?, ?, 'Legacy report', ?, NULL, ?, ?, ?, ?)`
    )
    .run(
      id,
      input.scanId,
      input.format ?? 'json',
      input.sha256,
      input.redacted ? 1 : 0,
      input.contentRef,
      Date.now()
    )
  return id
}

describe('ReportService protected Evidence boundaries', () => {
  it('projects strict scan metadata and renders only redacted unprotected summaries', async () => {
    const fixture = await createFixture()
    try {
      const ordinary = await fixture.evidenceStore.save({
        workspaceId: fixture.workspace.id,
        scanId: fixture.scan.id,
        type: 'evidence-capture-hash-only',
        mimeType: 'application/json',
        content: '{"safe":"ordinary"}',
        source: 'report-test',
        createdBy: 'report-test',
        captureTool: 'report-test',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      const protectedCapture = await createProtectedPair(fixture)

      const detail = await fixture.application.getScanDetail(fixture.scan.id)
      expect(detail.evidence).toHaveLength(3)
      for (const summary of detail.evidence) {
        expect(EvidenceSummarySchema.parse(summary)).toEqual(summary)
        expect(summary).not.toHaveProperty('filePath')
        expect(summary).not.toHaveProperty('workspaceId')
        expect(summary).not.toHaveProperty('source')
        expect(summary).not.toHaveProperty('plaintextSha256')
        expect(summary).not.toHaveProperty('plaintextSize')
      }
      expect(
        detail.evidence.find(
          ({ id }) => id === protectedCapture.evidence.original.id
        )
      ).toMatchObject({
        protectionState: 'protected-original',
        redactionState: 'original',
        availabilityState: 'available'
      })
      expect(
        detail.evidence.find(
          ({ id }) => id === protectedCapture.evidence.derivative.id
        )
      ).toMatchObject({
        protectionState: 'unprotected',
        redactionState: 'redacted',
        derivedFrom: protectedCapture.evidence.original.id
      })

      const report = await fixture.application.generateReport({
        scanId: fixture.scan.id,
        format: 'json',
        redacted: true
      })
      const content = await fixture.application.readReport(report.id)
      const rendered = JSON.parse(content.content.toString('utf8')) as {
        evidence: Array<Record<string, unknown> & { id: string }>
      }
      const renderedIds = rendered.evidence.map(({ id }) => id)
      expect(renderedIds).toContain(ordinary.id)
      expect(renderedIds).toContain(
        protectedCapture.evidence.derivative.id
      )
      expect(renderedIds).not.toContain(
        protectedCapture.evidence.original.id
      )
      for (const summary of rendered.evidence) {
        expect(EvidenceSummarySchema.parse(summary)).toEqual(summary)
        expect(summary).not.toHaveProperty('filePath')
        expect(summary).not.toHaveProperty('workspaceId')
        expect(summary).not.toHaveProperty('plaintextSha256')
      }
      expect(content.content.toString('utf8')).not.toContain(
        'REPORT-PROTECTED-PLAINTEXT-SENTINEL'
      )

      await fixture.application.markReportExported(
        report.id,
        'authorized-report.json'
      )
      expect(await fixture.repository.getReport(report.id)).toMatchObject({
        redacted: true,
        filePath: 'authorized-report.json'
      })
    } finally {
      fixture.database.close()
    }
  })

  it('rejects legacy, cross-scan, protected, mistyped and hash-mismatched report refs', async () => {
    const fixture = await createFixture()
    try {
      const validContent = await fixture.evidenceStore.save({
        workspaceId: fixture.workspace.id,
        scanId: fixture.scan.id,
        type: 'report-json',
        mimeType: 'application/json',
        content: '{"report":"redacted"}',
        source: 'reporting',
        createdBy: 'report-service',
        captureTool: 'agentgo-reporting',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      const legacyId = insertReport(fixture, {
        scanId: fixture.scan.id,
        contentRef: validContent.id,
        sha256: validContent.sha256,
        redacted: false
      })
      await expect(
        fixture.application.readReport(legacyId)
      ).rejects.toThrow(/unredacted/i)
      await expect(
        fixture.application.markReportExported(
          legacyId,
          'must-not-export.json'
        )
      ).rejects.toThrow(/unredacted/i)

      const secondScan = await fixture.createScan('Second report scan')
      const crossScanContent = await fixture.evidenceStore.save({
        workspaceId: fixture.workspace.id,
        scanId: secondScan.id,
        type: 'report-json',
        mimeType: 'application/json',
        content: '{"report":"other-scan"}',
        source: 'reporting',
        createdBy: 'report-service',
        captureTool: 'agentgo-reporting',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      const crossScanId = insertReport(fixture, {
        scanId: fixture.scan.id,
        contentRef: crossScanContent.id,
        sha256: crossScanContent.sha256,
        redacted: true
      })
      await expect(
        fixture.application.readReport(crossScanId)
      ).rejects.toThrow(/exact redacted/i)

      const mistypedContent = await fixture.evidenceStore.save({
        workspaceId: fixture.workspace.id,
        scanId: fixture.scan.id,
        type: 'evidence-capture-hash-only',
        mimeType: 'application/json',
        content: '{"not":"a-report"}',
        source: 'report-test',
        createdBy: 'report-test',
        captureTool: 'report-test',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      const mistypedId = insertReport(fixture, {
        scanId: fixture.scan.id,
        contentRef: mistypedContent.id,
        sha256: mistypedContent.sha256,
        redacted: true
      })
      await expect(
        fixture.application.readReport(mistypedId)
      ).rejects.toThrow(/exact redacted/i)
      await expect(
        fixture.application.markReportExported(
          mistypedId,
          'must-not-export.json'
        )
      ).rejects.toThrow(/exact redacted/i)

      const wrongMimeContent = await fixture.evidenceStore.save({
        workspaceId: fixture.workspace.id,
        scanId: fixture.scan.id,
        type: 'report-json',
        mimeType: 'text/plain',
        content: '{"report":"wrong-mime"}',
        source: 'report-test',
        createdBy: 'report-test',
        captureTool: 'report-test',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      const wrongMimeId = insertReport(fixture, {
        scanId: fixture.scan.id,
        contentRef: wrongMimeContent.id,
        sha256: wrongMimeContent.sha256,
        redacted: true
      })
      await expect(
        fixture.application.readReport(wrongMimeId)
      ).rejects.toThrow(/exact redacted/i)

      const wrongHashId = insertReport(fixture, {
        scanId: fixture.scan.id,
        contentRef: validContent.id,
        sha256: 'f'.repeat(64),
        redacted: true
      })
      await expect(
        fixture.application.readReport(wrongHashId)
      ).rejects.toThrow(/exact redacted/i)

      const protectedCapture = await createProtectedPair(fixture)
      const protectedId = insertReport(fixture, {
        scanId: fixture.scan.id,
        contentRef: protectedCapture.evidence.original.id,
        sha256: protectedCapture.evidence.original.sha256,
        redacted: true
      })
      await expect(
        fixture.application.readReport(protectedId)
      ).rejects.toThrow(/exact redacted/i)

      await expect(
        fixture.repository.createReport({
          scanId: fixture.scan.id,
          title: 'Unredacted repository bypass',
          format: 'json',
          sha256: validContent.sha256,
          redacted: false,
          contentRef: validContent.id
        })
      ).rejects.toThrow(/redacted/i)
      await expect(
        fixture.repository.createReport({
          scanId: fixture.scan.id,
          title: 'Cross-scan repository bypass',
          format: 'json',
          sha256: crossScanContent.sha256,
          redacted: true,
          contentRef: crossScanContent.id
        })
      ).rejects.toThrow(/exact redacted/i)
      await expect(
        fixture.repository.createReport({
          scanId: fixture.scan.id,
          title: 'Protected repository bypass',
          format: 'json',
          sha256: protectedCapture.evidence.original.sha256,
          redacted: true,
          contentRef: protectedCapture.evidence.original.id
        })
      ).rejects.toThrow(/exact redacted/i)
      await expect(
        fixture.repository.createReport({
          scanId: fixture.scan.id,
          title: 'Mistyped repository bypass',
          format: 'json',
          sha256: mistypedContent.sha256,
          redacted: true,
          contentRef: mistypedContent.id
        })
      ).rejects.toThrow(/exact redacted/i)
      await expect(
        fixture.repository.createReport({
          scanId: fixture.scan.id,
          title: 'MIME repository bypass',
          format: 'json',
          sha256: wrongMimeContent.sha256,
          redacted: true,
          contentRef: wrongMimeContent.id
        })
      ).rejects.toThrow(/exact redacted/i)
      await expect(
        fixture.repository.createReport({
          scanId: fixture.scan.id,
          title: 'Hash repository bypass',
          format: 'json',
          sha256: 'e'.repeat(64),
          redacted: true,
          contentRef: validContent.id
        })
      ).rejects.toThrow(/exact redacted/i)

      expect(await fixture.repository.getReport(legacyId)).not.toHaveProperty(
        'filePath'
      )
      expect(
        await fixture.repository.getReport(mistypedId)
      ).not.toHaveProperty('filePath')
    } finally {
      fixture.database.close()
    }
  })
})
