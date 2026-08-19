import { createHash, randomUUID } from 'node:crypto'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
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
  openAgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { EvidenceCapturePolicy } from './evidence-capture-policy'
import { ProtectedEvidenceCaptureService } from './protected-evidence-capture-service'
import { ProtectedEvidenceRetentionScheduler } from './protected-evidence-retention-scheduler'

const SENTINEL = 'DAY4-END-TO-END-PROTECTED-SENTINEL'
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

describe('ProtectedEvidenceCaptureService', () => {
  it('persists exact encoded bytes only through the real policy and encrypted backend boundary', async () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'agentgo-protected-capture-service-')
    )
    directories.push(directory)
    const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
    const repository = new AgentGoRepository(database)
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    let retentionScheduler: ProtectedEvidenceRetentionScheduler | undefined
    try {
      const workspace = await repository.createWorkspace({
        name: 'Protected service',
        description: ''
      })
      const target = await repository.createTarget({
        workspaceId: workspace.id,
        name: 'Protected service lab',
        baseUrl: 'https://lab.example.test',
        description: '',
        authorizationReference: 'protected-service-test',
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
          name: 'Protected service scan',
          description: 'Policy-to-store integration fixture.',
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
      const run = await repository.createAgentRun({
        scanId: scan.id,
        role: 'strategy',
        promptId: 'protected-service-test',
        promptVersion: '1.0.0',
        promptHash: sha256('protected-service-test-prompt'),
        modelProfileId: 'deterministic-test-profile'
      })
      const proposal = await repository.createProbeProposal({
        scanId: scan.id,
        agentRunId: run.id,
        action: {
          id: randomUUID(),
          kind: 'http-request',
          targetUrl: 'https://lab.example.test/archive',
          method: 'GET',
          scopeSnapshotId: scan.scopeSnapshotId,
          probeLevel: 'active-safe',
          sideEffect: 'none',
          summary: 'Read-only protected capture.',
          expectedEvidence: 'Encrypted response bytes.',
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
          reasons: ['authorized integration fixture'],
          normalizedTarget: 'https://lab.example.test/archive'
        }
      })
      const content = Buffer.from(
        `compressed-fixture:${SENTINEL}`,
        'utf8'
      )
      const occurredAt = new Date(
        Date.parse(policyDecision.createdAt) + 1
      ).toISOString()
      const context: ProtectedOriginalEvidenceCaptureContext = {
        scanId: scan.id,
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
        scanId: scan.id,
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
          new Date(Date.parse(policyDecision.createdAt) + 60_000).toISOString(),
        maxSourceBytes: content.byteLength,
        maxExcerptBytes: 32,
        jsonPointers: [],
        oobMetadataFields: [],
        protectedOriginalPlan: plan
      }
      let storeNow = Date.parse(occurredAt) + 1
      const store = new EvidenceStore(
        database,
        join(directory, 'artifacts'),
        {
          protector: protector(),
          clock: () => storeNow
        }
      )
      const service = new ProtectedEvidenceCaptureService(
        new EvidenceCapturePolicy(),
        store
      )

      const persisted = await service.captureAndPersist({
        context,
        decision,
        content,
        knownTotalBytes: content.byteLength
      })

      expect(persisted.capture).toMatchObject({
        state: 'captured',
        reason: 'protected-original-authorized'
      })
      const artifact = persisted.capture.artifacts[0]
      expect(artifact).toMatchObject({
        type: 'evidence-capture-protected-original',
        payload: {
          captureContext: {
            response: {
              contentEncoding: 'compressed',
              charset: 'not-applicable'
            }
          },
          captureDecision: decision
        }
      })
      expect(JSON.stringify(persisted.capture)).not.toContain(SENTINEL)
      expect(
        readFileSync(
          store.resolveStoredPath(persisted.evidence.original.filePath)
        ).toString('utf8')
      ).not.toContain(SENTINEL)
      expect(
        (
          await store.read(persisted.evidence.derivative.id)
        ).content.toString('utf8')
      ).not.toContain(SENTINEL)
      await expect(
        store.read(persisted.evidence.original.id)
      ).rejects.toThrow('generic API')
      expect(content.toString('utf8')).toContain(SENTINEL)
      expect(fetchSpy).not.toHaveBeenCalled()

      retentionScheduler = new ProtectedEvidenceRetentionScheduler(store, {
        intervalMs: 5
      })
      retentionScheduler.start()
      storeNow = Date.parse(persisted.evidence.original.retentionUntil!)
      await vi.waitFor(
        async () => {
          const metadata = await store.getMetadata(
            persisted.evidence.original.id
          )
          expect(metadata).toMatchObject({
            availabilityState: 'expired',
            integrityStatus: 'expired'
          })
          expect(
            existsSync(
              store.resolveStoredPath(
                persisted.evidence.original.filePath
              )
            )
          ).toBe(false)
        },
        { timeout: 1_000, interval: 10 }
      )
    } finally {
      await retentionScheduler?.stop()
      fetchSpy.mockRestore()
      database.close()
    }
  })
})
