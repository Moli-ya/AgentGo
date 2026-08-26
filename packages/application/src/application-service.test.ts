import { randomUUID } from 'node:crypto'
import {
  existsSync,
  mkdtempSync,
  rmSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  openAgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import type { McpConnectionSecrets, McpHub } from '@agentgo/mcp-hub'
import { DefaultModelGateway, type ModelGateway } from '@agentgo/model-gateway'
import {
  AgentGoApplicationService,
  AgentPromptCatalog,
  EvidenceCapturePolicy,
  createVulnerabilityPlatform
} from './index'

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

const protector: SecretProtector = {
  isAvailable: () => true,
  protect: (value) => Buffer.from(value, 'utf8'),
  unprotect: (value) => value.toString('utf8')
}

function vulnerabilityDependencies() {
  return {
    vulnerabilityPlatform: createVulnerabilityPlatform(),
    vulnerabilityExecutionEnvironment: 'authorized-test-environment' as const
  }
}

function interruptedRecoveryContext(scanId: string) {
  const grantId = randomUUID()
  const leaseId = randomUUID()
  return {
    lease: {
      schemaVersion: 'execution-lease.v1',
      id: leaseId,
      grantId,
      attempt: 1,
      state: 'claimed',
      issuedAt: '2026-07-28T00:00:00.000Z',
      expiresAt: '2099-07-28T00:05:00.000Z',
      claimedAt: '2026-07-28T00:00:01.000Z',
      claimedBy: randomUUID(),
      claimTokenHash: 'a'.repeat(64),
      deliveryState: 'possibly-sent',
      evidenceRefs: []
    },
    grant: {
      id: grantId,
      scanId,
      policyDecisionId: randomUUID(),
      techniqueId: 'sqli.error-differential',
      techniqueVersion: '1.0.0',
      stepId: 'sqli.baseline',
      adapterKind: 'http',
      purpose: 'read'
    },
    captureDecision: {
      validFrom: '2020-01-01T00:00:00.000Z',
      validUntil: '2099-01-01T00:00:00.000Z'
    }
  } as unknown as Awaited<
    ReturnType<AgentGoRepository['listClaimedExecutionLeasesForRecovery']>
  >[number]
}

function recoveredInterruptedLease(
  context: ReturnType<typeof interruptedRecoveryContext>
) {
  return {
    ...context.lease,
    state: 'failed',
    deliveryState: 'unknown',
    terminalAt: '2026-07-28T00:05:01.000Z',
    terminalReason: 'interrupted',
    outcomeSummary: {
      executionState: 'interrupted',
      deliveryState: 'unknown',
      verdictImpact: 'inconclusive',
      errorCode: 'execution.interrupted'
    }
  } as const
}

async function createRunningRecoveryScan(repository: AgentGoRepository) {
  const workspace = await repository.createWorkspace({
    name: 'Execution recovery test',
    description: ''
  })
  const target = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Authorized recovery fixture',
    baseUrl: 'http://127.0.0.1:3000/',
    description: '',
    authorizationReference: 'automated-execution-recovery-test',
    scope: {
      allowedOrigins: ['http://127.0.0.1:3000'],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [3000],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: true,
      allowLoopbackTargets: true,
      networkEntries: [],
      maxRequestsPerMinute: 30,
      maxConcurrency: 1,
      authorizationReference: 'automated-execution-recovery-test'
    }
  })
  const plan = createDefaultScanPlan(['sqli'])
  const scan = await repository.createScan(
    {
      targetId: target.target.id,
      name: 'Claimed execution recovery',
      description: 'Claimed lease recovery fixture.',
      families: ['sqli'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() }
  )
  await repository.updateScan(scan.id, {
    status: 'running',
    phase: 'validation',
    startedAt: Date.now(),
    runtimeJson: {
      ...createRuntimeState(),
      phase: 'validation',
      status: 'running'
    }
  })
  return { workspace, target, scan }
}

describe('AgentGoApplicationService recovery', () => {
  it('pauses an interrupted scan and records a checkpoint plus warning event', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-recovery-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const workspace = await repository.createWorkspace({
        name: 'Recovery test',
        description: ''
      })
      const target = await repository.createTarget({
        workspaceId: workspace.id,
        name: 'Authorized local fixture',
        baseUrl: 'http://127.0.0.1:3000/',
        description: '',
        authorizationReference: 'automated-recovery-test',
        scope: {
          allowedOrigins: ['http://127.0.0.1:3000'],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [3000],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          networkEntries: [],
          maxRequestsPerMinute: 30,
          maxConcurrency: 1,
          authorizationReference: 'automated-recovery-test'
        }
      })
      const plan = createDefaultScanPlan(['sqli'])
      const scan = await repository.createScan(
        {
          targetId: target.target.id,
          name: 'Interrupted scan',
          description: '中断恢复授权测试夹具。',
          families: ['sqli'],
          identityIds: [],
          budget: plan.budget
        },
        { ...plan },
        { ...createRuntimeState() }
      )
      await repository.updateScan(scan.id, {
        status: 'running',
        phase: 'validation',
        startedAt: Date.now(),
        runtimeJson: { ...createRuntimeState(), phase: 'validation', status: 'running' }
      })

      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        )
      })
      await application.initialize()

      const recovered = await repository.getScanRow(scan.id)
      expect(recovered?.status).toBe('paused')
      expect(recovered?.phase).toBe('validation')
      expect(recovered?.runtimeJson).toMatchObject({
        phase: 'validation',
        status: 'paused'
      })
      expect(recovered?.checkpointCount).toBe(1)

      const checkpoint = await repository.getLatestCheckpoint(scan.id)
      expect(checkpoint).toMatchObject({
        scanId: scan.id,
        phase: 'validation',
        reason: 'recovered-after-interruption',
        state: { phase: 'validation', status: 'paused' }
      })

      const recoveryEvent = (await repository.listScanEvents(scan.id)).at(-1)
      expect(recoveryEvent).toMatchObject({
        type: 'status',
        level: 'warning',
        detail: { recoveredPhase: 'validation' }
      })
      expect(recoveryEvent?.message).toContain('已安全恢复为暂停状态')
    } finally {
      database.close()
    }
  })

  it('terminalizes a claimed lease without fabricating Evidence when EvidenceStore is absent', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-execution-no-evidence-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { scan } = await createRunningRecoveryScan(repository)
      const context = interruptedRecoveryContext(scan.id)
      vi.spyOn(
        repository,
        'listClaimedExecutionLeasesForRecovery'
      ).mockResolvedValue([context])
      const fallback = vi
        .spyOn(repository, 'recoverInterruptedExecutionLeaseWithCleanup')
        .mockResolvedValue({
          lease: recoveredInterruptedLease(context),
          discardedEvidence: []
        })
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        )
      })

      await application.initialize()

      expect(fallback).toHaveBeenCalledWith({
        leaseId: context.lease.id,
        discardUnboundStagedEvidence: false
      })
      expect(await repository.getScan(scan.id)).toMatchObject({
        status: 'awaiting-user'
      })
      expect(await repository.getLatestCheckpoint(scan.id)).toMatchObject({
        reason: 'execution-interrupted-unknown',
        state: { status: 'awaiting-user' }
      })
      const event = (await repository.listScanEvents(scan.id)).at(-1)
      expect(event?.detail).toMatchObject({
        executionState: 'interrupted',
        deliveryState: 'unknown',
        verdictImpact: 'inconclusive',
        evidenceState: 'partially-unavailable',
        evidenceUnavailableLeaseIds: [context.lease.id]
      })
      await expect(application.controlScan(scan.id, 'resume')).rejects.toThrow(
        '自动重放'
      )
    } finally {
      database.close()
    }
  })

  it('recovers the scan after a crash between lease terminalization and checkpointing', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-execution-crash-window-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { scan } = await createRunningRecoveryScan(repository)
      const claimed = interruptedRecoveryContext(scan.id)
      const recovered = recoveredInterruptedLease(claimed)
      vi.spyOn(
        repository,
        'listClaimedExecutionLeasesForRecovery'
      ).mockResolvedValue([])
      vi.spyOn(
        repository,
        'listInterruptedExecutionLeasesForScanRecovery'
      ).mockResolvedValue([
        {
          lease: recovered,
          grant: claimed.grant
        }
      ])
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        )
      })

      await application.initialize()

      expect(await repository.getScan(scan.id)).toMatchObject({
        status: 'awaiting-user'
      })
      expect(await repository.getLatestCheckpoint(scan.id)).toMatchObject({
        reason: 'execution-interrupted-unknown'
      })
      expect(
        (await repository.listScanEvents(scan.id)).at(-1)?.detail
      ).toMatchObject({
        leaseIds: [recovered.id],
        evidenceState: 'partially-unavailable'
      })
      await application.initialize()
      expect((await repository.getScanRow(scan.id))?.checkpointCount).toBe(1)
    } finally {
      database.close()
    }
  })

  it('uses no-Evidence recovery when scan target lookup is unavailable', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-execution-missing-target-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { scan } = await createRunningRecoveryScan(repository)
      const context = interruptedRecoveryContext(scan.id)
      vi.spyOn(
        repository,
        'listClaimedExecutionLeasesForRecovery'
      ).mockResolvedValue([context])
      vi.spyOn(repository, 'getTarget').mockResolvedValueOnce(undefined)
      const fallback = vi
        .spyOn(repository, 'recoverInterruptedExecutionLeaseWithCleanup')
        .mockResolvedValue({
          lease: recoveredInterruptedLease(context),
          discardedEvidence: []
        })
      const evidenceStore = new EvidenceStore(
        database,
        join(directory, 'artifacts')
      )
      const save = vi.spyOn(evidenceStore, 'save')
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        ),
        evidenceStore
      })

      await application.initialize()

      expect(save).not.toHaveBeenCalled()
      expect(fallback).toHaveBeenCalledWith({
        leaseId: context.lease.id,
        discardUnboundStagedEvidence: true
      })
      expect(await repository.getScan(scan.id)).toMatchObject({
        status: 'awaiting-user'
      })
    } finally {
      database.close()
    }
  })

  it('cleans recovered staging files without reopening a terminalized lease when file deletion fails', async () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'agentgo-execution-staging-file-cleanup-')
    )
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { scan } = await createRunningRecoveryScan(repository)
      const context = interruptedRecoveryContext(scan.id)
      const stagedDigest = 'c'.repeat(64)
      const stagedPath = [
        'f'.repeat(20),
        'evidence',
        stagedDigest.slice(0, 2),
        `${stagedDigest}.json`
      ].join('/')
      vi.spyOn(
        repository,
        'listClaimedExecutionLeasesForRecovery'
      ).mockResolvedValue([context])
      vi.spyOn(repository, 'getTarget').mockResolvedValueOnce(undefined)
      vi.spyOn(
        repository,
        'recoverInterruptedExecutionLeaseWithCleanup'
      ).mockResolvedValue({
        lease: recoveredInterruptedLease(context),
        discardedEvidence: [
          {
            id: randomUUID(),
            filePath: stagedPath,
            sha256: 'c'.repeat(64)
          }
        ]
      })
      const evidenceStore = new EvidenceStore(
        database,
        join(directory, 'artifacts')
      )
      const cleanup = vi
        .spyOn(evidenceStore, 'deleteUnreferencedFiles')
        .mockRejectedValue(new Error('synthetic file lock'))
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        ),
        evidenceStore
      })

      await application.initialize()

      expect(cleanup).toHaveBeenCalledWith([stagedPath])
      expect(await repository.getScan(scan.id)).toMatchObject({
        status: 'awaiting-user'
      })
      expect(await repository.getLatestCheckpoint(scan.id)).toMatchObject({
        reason: 'execution-interrupted-unknown'
      })
    } finally {
      database.close()
    }
  })

  it('removes files whose crash-staged metadata was atomically discarded', async () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'agentgo-execution-staging-file-delete-')
    )
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { workspace, scan } =
        await createRunningRecoveryScan(repository)
      const context = interruptedRecoveryContext(scan.id)
      const artifactRoot = join(directory, 'artifacts')
      const evidenceStore = new EvidenceStore(database, artifactRoot)
      const staged = await evidenceStore.save({
        workspaceId: workspace.id,
        scanId: scan.id,
        type: 'evidence-capture-hash-only',
        mimeType: 'application/json',
        content: '{"staged":true}',
        source: 'execution-request-summary',
        createdBy: 'execution-service',
        captureTool: 'evidence-capture-policy',
        captureToolVersion: '2.0.0',
        redactionState: 'redacted'
      })
      const absolutePath = evidenceStore.resolveStoredPath(staged.filePath)
      vi.spyOn(
        repository,
        'listClaimedExecutionLeasesForRecovery'
      ).mockResolvedValue([context])
      vi.spyOn(repository, 'getTarget').mockResolvedValueOnce(undefined)
      vi.spyOn(
        repository,
        'recoverInterruptedExecutionLeaseWithCleanup'
      ).mockImplementation(async () => {
        database.native
          .prepare('DELETE FROM evidence_items WHERE id = ?')
          .run(staged.id)
        return {
          lease: recoveredInterruptedLease(context),
          discardedEvidence: [staged]
        }
      })
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        ),
        evidenceStore
      })

      await application.initialize()

      expect(existsSync(absolutePath)).toBe(false)
      expect(await repository.getScan(scan.id)).toMatchObject({
        status: 'awaiting-user'
      })
    } finally {
      database.close()
    }
  })

  it('keeps the current recovery summary and removes one abandoned by a second crash', async () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'agentgo-execution-repeated-recovery-')
    )
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { workspace, scan } = await createRunningRecoveryScan(repository)
      const context = interruptedRecoveryContext(scan.id)
      Reflect.set(context.grant, 'policyDecisionId', undefined)
      const evidenceStore = new EvidenceStore(
        database,
        join(directory, 'artifacts')
      )
      const abandoned = await evidenceStore.save({
        workspaceId: workspace.id,
        scanId: scan.id,
        type: 'evidence-capture-hash-only',
        mimeType: 'application/json',
        content: '{"attempt":"abandoned-before-recovery-transaction"}',
        source: 'execution-interruption-summary',
        createdBy: 'application-service',
        captureTool: 'evidence-capture-policy',
        captureToolVersion: '2.0.0',
        redactionState: 'redacted'
      })
      const abandonedPath = evidenceStore.resolveStoredPath(
        abandoned.filePath
      )
      vi.spyOn(
        repository,
        'listClaimedExecutionLeasesForRecovery'
      ).mockResolvedValue([context])
      const recover = vi
        .spyOn(repository, 'recoverInterruptedExecutionLeaseWithCleanup')
        .mockImplementation(async (input) => {
          const currentEvidenceId = input.evidenceId
          if (!currentEvidenceId) {
            throw new Error('Current recovery Evidence was not supplied.')
          }
          expect(input.discardUnboundStagedEvidence).toBe(true)
          expect(currentEvidenceId).not.toBe(abandoned.id)
          database.native
            .prepare('DELETE FROM evidence_items WHERE id = ?')
            .run(abandoned.id)
          return {
            lease: {
              ...recoveredInterruptedLease(context),
              evidenceRefs: [currentEvidenceId]
            },
            discardedEvidence: [
              {
                id: abandoned.id,
                filePath: abandoned.filePath,
                sha256: abandoned.sha256
              }
            ]
          }
        })
      const evidenceCapturePolicy = new EvidenceCapturePolicy()
      vi.spyOn(evidenceCapturePolicy, 'capture').mockReturnValue({
        state: 'hash-only',
        reason: 'policy-hash-only',
        sourceHash: {
          domain: 'agentgo.evidence-source.v1',
          algorithm: 'sha256',
          digest: 'e'.repeat(64),
          basis: 'source-bytes',
          coverage: 'complete',
          hashedBytes: 1
        },
        artifacts: [
          {
            type: 'evidence-capture-hash-only',
            mimeType: 'application/json',
            source: 'execution-interruption-summary',
            attempt: 'current-recovery'
          }
        ]
      } as never)
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        ),
        evidenceStore,
        evidenceCapturePolicy
      })

      await application.initialize()

      expect(recover).toHaveBeenCalledOnce()
      expect(await evidenceStore.getMetadata(abandoned.id)).toBeUndefined()
      expect(existsSync(abandonedPath)).toBe(false)
      const currentId = recover.mock.calls[0]?.[0].evidenceId
      if (!currentId) {
        throw new Error('Current recovery Evidence ID was not observed.')
      }
      const current = await evidenceStore.getMetadata(currentId)
      expect(current).toBeDefined()
      expect(
        current && existsSync(evidenceStore.resolveStoredPath(current.filePath))
      ).toBe(true)
    } finally {
      database.close()
    }
  })

  it('sweeps a content file left after metadata commit but before file GC', async () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'agentgo-execution-persistent-file-gc-')
    )
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { workspace, scan } = await createRunningRecoveryScan(repository)
      const evidenceStore = new EvidenceStore(
        database,
        join(directory, 'artifacts')
      )
      const orphaned = await evidenceStore.save({
        workspaceId: workspace.id,
        scanId: scan.id,
        type: 'evidence-capture-hash-only',
        mimeType: 'application/json',
        content: '{"metadata":"removed-before-file-gc"}',
        source: 'execution-interruption-summary',
        createdBy: 'application-service',
        captureTool: 'evidence-capture-policy',
        captureToolVersion: '2.0.0',
        redactionState: 'redacted'
      })
      const orphanedPath = evidenceStore.resolveStoredPath(orphaned.filePath)
      database.native
        .prepare('DELETE FROM evidence_items WHERE id = ?')
        .run(orphaned.id)
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        ),
        evidenceStore
      })

      await application.initialize()

      expect(existsSync(orphanedPath)).toBe(false)
    } finally {
      database.close()
    }
  })

  it('falls back to no-Evidence terminalization when recovery Evidence cannot be saved', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-execution-save-failure-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)

    try {
      const { scan } = await createRunningRecoveryScan(repository)
      const context = interruptedRecoveryContext(scan.id)
      vi.spyOn(
        repository,
        'listClaimedExecutionLeasesForRecovery'
      ).mockResolvedValue([context])
      const fallback = vi
        .spyOn(repository, 'recoverInterruptedExecutionLeaseWithCleanup')
        .mockResolvedValue({
          lease: recoveredInterruptedLease(context),
          discardedEvidence: []
        })
      const evidenceStore = new EvidenceStore(
        database,
        join(directory, 'artifacts')
      )
      const save = vi
        .spyOn(evidenceStore, 'save')
        .mockRejectedValue(new Error('synthetic Evidence save failure'))
      const evidenceCapturePolicy = new EvidenceCapturePolicy()
      vi.spyOn(evidenceCapturePolicy, 'capture').mockReturnValue({
        state: 'hash-only',
        reason: 'policy-hash-only',
        sourceHash: {
          domain: 'agentgo.evidence-source.v1',
          algorithm: 'sha256',
          digest: 'b'.repeat(64),
          basis: 'source-bytes',
          coverage: 'complete',
          hashedBytes: 1
        },
        artifacts: [
          {
            type: 'evidence-capture-hash-only',
            mimeType: 'application/json',
            source: 'execution-interruption-summary'
          }
        ]
      } as never)
      const application = new AgentGoApplicationService({
        ...vulnerabilityDependencies(),
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        ),
        evidenceStore,
        evidenceCapturePolicy
      })

      await application.initialize()

      expect(save).toHaveBeenCalledOnce()
      expect(fallback).toHaveBeenCalledWith({
        leaseId: context.lease.id,
        discardUnboundStagedEvidence: true
      })
      expect(await repository.getScan(scan.id)).toMatchObject({
        status: 'awaiting-user'
      })
    } finally {
      database.close()
    }
  })

  it('returns each concurrent target update exact scope instead of rereading the head', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-exact-scope-return-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const application = new AgentGoApplicationService({
      ...vulnerabilityDependencies(),
      repository,
      credentialStore: new FileCredentialStore(
        join(directory, 'credentials.json'),
        protector
      )
    })

    try {
      const workspace = await application.createWorkspace({
        name: 'Exact scope return test',
        description: ''
      })
      const baseScope = {
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
        maxRequestsPerMinute: 20,
        maxConcurrency: 1
      }
      const created = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Exact scope fixture',
        baseUrl: 'https://lab.example.test',
        description: '',
        authorizationReference: 'synthetic-exact-scope-test',
        scope: baseScope
      })
      const getLatestScopeSpy = vi.spyOn(repository, 'getLatestScope')

      const [first, second] = await Promise.all([
        application.updateTarget({
          id: created.target.id,
          scope: {
            ...baseScope,
            maxRequestsPerMinute: 21
          }
        }),
        application.updateTarget({
          id: created.target.id,
          scope: {
            ...baseScope,
            maxRequestsPerMinute: 22
          }
        })
      ])

      expect(getLatestScopeSpy).not.toHaveBeenCalled()
      expect(first.scope).toMatchObject({
        revision: 2,
        maxRequestsPerMinute: 21
      })
      expect(second.scope).toMatchObject({
        revision: 3,
        maxRequestsPerMinute: 22
      })
      getLatestScopeSpy.mockRestore()
    } finally {
      database.close()
    }
  })

  it('freezes explicit per-agent model profiles and rejects cross-role routing', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-profile-routing-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    const modelGateway = {
      testConnection: async () => ({
        ok: true,
        message: 'model ready',
        promptTokens: 7,
        completionTokens: 3,
        totalTokens: 10
      }),
      structuredCompletion: async () => {
        throw new Error('not used in this test')
      }
    } as ModelGateway
    const application = new AgentGoApplicationService({
      ...vulnerabilityDependencies(),
      repository,
      credentialStore,
      modelGateway
    })

    try {
      await application.initialize()
      const deterministicPlanner = (await application.listModelProfiles()).find(
        (profile) => profile.agentRole === 'planner' && profile.provider === 'deterministic'
      )
      expect(deterministicPlanner).toBeDefined()
      const externalPlanner = await application.saveModelProfile({
        name: 'External planner routing test',
        agentRole: 'planner',
        provider: 'openai-compatible',
        baseUrl: 'https://planner.example.test/v1/',
        model: 'planner-model',
        apiKey: 'routing-test-key',
        timeoutMs: 5_000,
        rpmLimit: 30,
        tpmLimit: 100_000,
        tokenBudget: 1_000_000,
        costBudget: 1
      })
      expect(externalPlanner.costBudget).toBe(0)
      const connection = await application.testModelProfile(externalPlanner.id)
      expect(connection.totalTokens).toBe(10)
      expect(await application.listModelProfileUsage()).toMatchObject([
        {
          profileId: externalPlanner.id,
          invocationCount: 1,
          promptTokens: 7,
          completionTokens: 3,
          totalTokens: 10
        }
      ])
      const workspace = await application.createWorkspace({
        name: 'Routing test',
        description: ''
      })
      const target = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Routing fixture',
        baseUrl: 'https://lab.example.test/',
        description: '',
        authorizationReference: 'routing-test-authorization',
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
          maxRequestsPerMinute: 20,
          maxConcurrency: 1
        }
      })
      const plan = createDefaultScanPlan()
      const scan = await application.createScan({
        targetId: target.target.id,
        name: 'Frozen routing scan',
        description: '明确使用本地 Planner，其余角色采用当前首选 Profile。',
        families: ['sqli'],
        identityIds: [],
        modelProfileIds: { planner: deterministicPlanner!.id },
        budget: plan.budget
      })

      expect(scan.description).toBe('明确使用本地 Planner，其余角色采用当前首选 Profile。')
      expect(scan.modelProfileIds.planner).toBe(deterministicPlanner!.id)
      expect(scan.modelProfileIds.planner).not.toBe(externalPlanner.id)
      expect(Object.values(scan.modelProfileIds)).toHaveLength(5)

      await expect(
        application.createScan({
          targetId: target.target.id,
          name: 'Invalid cross-role scan',
          description: '该任务应因 Profile 角色不匹配而拒绝。',
          families: ['sqli'],
          identityIds: [],
          modelProfileIds: { knowledge: externalPlanner.id },
          budget: plan.budget
        })
      ).rejects.toThrow('不属于 knowledge Agent')
    } finally {
      database.close()
    }
  })

  it('extracts, independently reviews and publishes imported vulnerability intelligence', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-knowledge-ingestion-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    const modelGateway = new DefaultModelGateway({
      profiles: repository,
      credentials: credentialStore,
      prompts: new AgentPromptCatalog(),
      invocations: repository
    })
    const application = new AgentGoApplicationService({
      ...vulnerabilityDependencies(),
      repository,
      credentialStore,
      modelGateway
    })

    try {
      await application.initialize()
      const profiles = await application.listModelProfiles()
      const extractor = profiles.find(
        (profile) => profile.agentRole === 'knowledge' && profile.provider === 'deterministic'
      )
      const reviewer = profiles.find(
        (profile) => profile.agentRole === 'verifier' && profile.provider === 'deterministic'
      )
      expect(extractor).toBeDefined()
      expect(reviewer).toBeDefined()

      const imported = await application.createKnowledgeImport({
        sourceType: 'public-poc',
        title: 'Acme Portal SQL Injection CVE-2026-12345',
        sourceUrl: 'https://example.test/acme-poc',
        author: 'Security Researcher',
        license: 'MIT',
        vendorHint: 'Acme',
        productHint: 'Portal',
        rawContent: [
          'Acme Portal SQL Injection CVE-2026-12345',
          'POST /api/products/query?id=1 HTTP/1.1',
          'Host: target.example',
          'Content-Type: application/json',
          'Authorization: Bearer public-poc-placeholder',
          '',
          '{"productId":"1"}'
        ].join('\n')
      })
      expect(imported.status).toBe('needs-review')
      expect(imported.instructionFlags).toContain('sensitive-data-redacted')
      expect(imported.rawContent).not.toContain('public-poc-placeholder')

      const extracted = await application.extractKnowledgeImport({
        id: imported.id,
        extractorProfileId: extractor!.id,
        reviewerProfileId: reviewer!.id
      })
      expect(extracted.status).toBe('ready-for-review')
      expect(extracted.candidate).toMatchObject({
        vendor: 'Acme',
        product: 'Portal',
        family: 'sqli',
        identifiers: { cve: ['CVE-2026-12345'] }
      })
      expect(extracted.candidate?.affectedEndpoints[0]).toMatchObject({
        method: 'POST',
        pathTemplate: '/api/products/query?id=%7B%7BID_VALUE%7D%7D',
        unsafeToExecute: true,
        headersTemplate: { Authorization: '{{TEST_CREDENTIAL}}' }
      })
      expect(extracted.runs).toHaveLength(2)
      expect(extracted.runs[1]?.parentRunId).toBe(extracted.runs[0]?.id)

      const published = await application.reviewKnowledgeImport({
        id: imported.id,
        action: 'publish'
      })
      expect(published.status).toBe('published')
      const search = await application.searchKnowledge({
        query: 'Acme Portal',
        families: [],
        limit: 20
      })
      expect(search).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ vendor: 'Acme', product: 'Portal' })
        ])
      )
      const usage = await application.listModelProfileUsage()
      expect(usage.find((item) => item.profileId === extractor!.id)?.totalTokens).toBeGreaterThan(0)
      expect(usage.find((item) => item.profileId === reviewer!.id)?.totalTokens).toBeGreaterThan(0)

      await expect(
        application.extractKnowledgeImport({
          id: imported.id,
          extractorProfileId: extractor!.id,
          reviewerProfileId: reviewer!.id
        })
      ).rejects.toThrow('必须先重新打开审核')
      await expect(
        application.updateKnowledgeCandidate({
          id: imported.id,
          candidate: published.candidate!
        })
      ).rejects.toThrow('必须先重新打开审核')
      await expect(application.deleteKnowledgeImport(imported.id)).rejects.toThrow(
        '必须先重新打开审核'
      )
      await application.reviewKnowledgeImport({ id: imported.id, action: 'reopen' })
      await expect(application.deleteKnowledgeImport(imported.id)).resolves.toEqual({
        deleted: true
      })
    } finally {
      database.close()
    }
  })

  it('blocks deletion during execution and removes target credentials plus artifacts', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-delete-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    const evidenceStore = new EvidenceStore(database, join(directory, 'artifacts'))
    const application = new AgentGoApplicationService({
      ...vulnerabilityDependencies(),
      repository,
      credentialStore,
      evidenceStore
    })

    try {
      await application.initialize()
      const workspace = await application.createWorkspace({
        name: 'Deletion test',
        description: ''
      })
      const target = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Disposable fixture',
        baseUrl: 'http://127.0.0.1:3000/',
        description: '',
        authorizationReference: 'automated-deletion-test',
        scope: {
          allowedOrigins: ['http://127.0.0.1:3000'],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [3000],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          networkEntries: [],
          maxRequestsPerMinute: 30,
          maxConcurrency: 1,
          authorizationReference: 'automated-deletion-test'
        }
      })
      const identity = await application.saveIdentity({
        targetId: target.target.id,
        label: 'Disposable identity',
        role: 'test-user',
        authType: 'bearer',
        secret: 'delete-me',
        isTestIdentity: true,
        ownedResourceIds: []
      })
      const plan = createDefaultScanPlan()
      const scan = await application.createScan({
        targetId: target.target.id,
        name: 'Disposable scan',
        description: '目标删除和证据清理授权测试夹具。',
        families: ['sqli'],
        identityIds: [],
        budget: plan.budget
      })
      const evidence = await evidenceStore.save({
        workspaceId: workspace.id,
        scanId: scan.id,
        type: 'test-response',
        mimeType: 'text/plain',
        content: 'disposable evidence',
        source: 'automated-test',
        createdBy: 'test',
        captureTool: 'test',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      const evidencePath = evidenceStore.resolveStoredPath(evidence.filePath)
      expect(existsSync(evidencePath)).toBe(true)
      expect(identity.credentialId && credentialStore.get(identity.credentialId)).toBe(
        'delete-me'
      )

      await repository.updateScan(scan.id, {
        status: 'running',
        runtimeJson: { ...createRuntimeState(), status: 'running' }
      })
      await expect(application.deleteTarget(target.target.id)).rejects.toThrow(
        '请先暂停或取消任务'
      )
      expect(existsSync(evidencePath)).toBe(true)

      await repository.updateScan(scan.id, {
        status: 'paused',
        runtimeJson: { ...createRuntimeState(), status: 'paused' }
      })
      await expect(application.deleteTarget(target.target.id)).resolves.toEqual({
        deleted: true
      })
      expect(await repository.getTarget(target.target.id)).toBeUndefined()
      expect(identity.credentialId && credentialStore.get(identity.credentialId)).toBeUndefined()
      expect(existsSync(evidencePath)).toBe(false)

      const workspaceTarget = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Workspace cleanup fixture',
        baseUrl: 'http://127.0.0.1:3001/',
        description: '',
        authorizationReference: 'automated-workspace-deletion-test',
        scope: {
          allowedOrigins: ['http://127.0.0.1:3001'],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [3001],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          networkEntries: [],
          maxRequestsPerMinute: 30,
          maxConcurrency: 1,
          authorizationReference: 'automated-workspace-deletion-test'
        }
      })
      const workspaceIdentity = await application.saveIdentity({
        targetId: workspaceTarget.target.id,
        label: 'Workspace identity',
        role: 'test-user',
        authType: 'bearer',
        secret: 'delete-workspace-secret',
        isTestIdentity: true,
        ownedResourceIds: []
      })
      const workspaceScan = await application.createScan({
        targetId: workspaceTarget.target.id,
        name: 'Workspace scan',
        description: '工作区删除和凭据清理授权测试夹具。',
        families: ['xss'],
        identityIds: [],
        budget: plan.budget
      })
      const workspaceEvidence = await evidenceStore.save({
        workspaceId: workspace.id,
        scanId: workspaceScan.id,
        type: 'workspace-test-response',
        mimeType: 'text/plain',
        content: 'workspace disposable evidence',
        source: 'automated-test',
        createdBy: 'test',
        captureTool: 'test',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      const workspaceEvidencePath = evidenceStore.resolveStoredPath(
        workspaceEvidence.filePath
      )

      await expect(application.deleteWorkspace(workspace.id)).resolves.toEqual({
        deleted: true
      })
      expect(await repository.getWorkspace(workspace.id)).toBeUndefined()
      expect(
        workspaceIdentity.credentialId &&
          credentialStore.get(workspaceIdentity.credentialId)
      ).toBeUndefined()
      expect(existsSync(workspaceEvidencePath)).toBe(false)
    } finally {
      database.close()
    }
  })

  it('stores MCP secrets outside SQLite and persists capability discovery', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-mcp-config-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    let receivedSecrets: McpConnectionSecrets | undefined
    const mcpHub: McpHub = {
      testConnection: async (_server, secrets) => {
        receivedSecrets = secrets
        return {
          ok: true,
          message: 'MCP ready',
          durationMs: 5,
          serverName: 'test-mcp',
          serverVersion: '1.0.0',
          tools: [{ name: 'safe-tool', description: 'fixture' }],
          resources: [],
          prompts: []
        }
      }
    }
    const application = new AgentGoApplicationService({
      ...vulnerabilityDependencies(),
      repository,
      credentialStore,
      mcpHub
    })

    try {
      await application.initialize()
      const saved = await application.saveMcpServer({
        name: 'Local test MCP',
        transport: 'stdio',
        enabled: false,
        command: 'node',
        args: ['server.mjs'],
        authType: 'none',
        environment: { MCP_TOKEN: 'mcp-secret-value' },
        timeoutMs: 5_000,
        roots: ['F:\\Agentgo'],
        allowedAgentRoles: ['strategy'],
        riskLabels: []
      })

      expect(saved.enabled).toBe(false)
      expect(saved.riskLabels).toEqual(
        expect.arrayContaining(['command-execution', 'file-access'])
      )
      expect(JSON.stringify(saved)).not.toContain('mcp-secret-value')
      expect(saved.credentialId && credentialStore.get(saved.credentialId)).toContain(
        'mcp-secret-value'
      )

      const result = await application.testMcpServer(saved.id)
      expect(result.ok).toBe(true)
      expect(receivedSecrets?.environment).toEqual({ MCP_TOKEN: 'mcp-secret-value' })
      expect((await application.listMcpServers())[0]).toMatchObject({
        status: 'ready',
        serverName: 'test-mcp',
        tools: [{ name: 'safe-tool', description: 'fixture' }]
      })

      await expect(application.deleteMcpServer(saved.id)).resolves.toEqual({ deleted: true })
      expect(saved.credentialId && credentialStore.get(saved.credentialId)).toBeUndefined()
    } finally {
      database.close()
    }
  })
})
