import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import type { ScanModuleSnapshotDraft } from '@agentgo/contracts'
import {
  AgentGoRepository,
  FileCredentialStore,
  agentRuns,
  openAgentGoDatabase,
  toolCalls,
  type SecretProtector
} from '@agentgo/db'
import { AgentGoApplicationService, type ScanCoordinator } from './index'
import {
  buildScanModuleSnapshotDrafts,
  computeScanModuleSnapshotHash,
  verifyScanModuleSnapshots
} from './scan-module-snapshot'
import { createVulnerabilityPlatform } from './vulnerability-platform'

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
  vi.restoreAllMocks()
})

const protector: SecretProtector = {
  isAvailable: () => true,
  protect: (value) => Buffer.from(value, 'utf8'),
  unprotect: (value) => value.toString('utf8')
}

describe('scan-scoped module snapshot persistence gate', () => {
  it('creates exact immutable snapshots atomically and rejects forged scan fields', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-module-snapshot-'))
    temporaryDirectories.push(directory)
    const database = openAgentGoDatabase(':memory:')
    const repository = new AgentGoRepository(database)
    const platform = createVulnerabilityPlatform()
    const application = new AgentGoApplicationService({
      repository,
      credentialStore: new FileCredentialStore(
        join(directory, 'credentials.json'),
        protector
      ),
      vulnerabilityPlatform: platform,
      vulnerabilityExecutionEnvironment: 'authorized-test-environment'
    })
    try {
      await application.initialize()
      const workspace = await application.createWorkspace({
        name: 'Snapshot workspace',
        description: ''
      })
      const target = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Authorized snapshot fixture',
        baseUrl: 'https://snapshot.example.test/',
        description: '',
        authorizationReference: 'snapshot-test',
        scope: {
          allowedOrigins: ['https://snapshot.example.test'],
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
          maxConcurrency: 1,
          authorizationReference: 'snapshot-test'
        }
      })
      const input = {
        targetId: target.target.id,
        name: 'Frozen scan',
        description: 'Frozen module snapshot integration test.',
        identityIds: [],
        budget: createDefaultScanPlan().budget
      }
      const scan = await application.createScan(input)
      const snapshots = await repository.listScanModuleSnapshots(scan.id)
      expect(snapshots.map(({ familyId }) => familyId)).toEqual([
        'idor',
        'sqli',
        'ssrf',
        'xss'
      ])
      expect(
        snapshots.every(
          (snapshot) =>
            snapshot.snapshotHash ===
            computeScanModuleSnapshotHash({
              familyId: snapshot.familyId,
              moduleId: snapshot.moduleId,
              moduleVersion: snapshot.moduleVersion,
              definitionHash: snapshot.definitionHash,
              techniqueId: snapshot.techniqueId,
              techniqueVersion: snapshot.techniqueVersion,
              strategyRefs: snapshot.strategyRefs,
              confirmationRuleRefs: snapshot.confirmationRuleRefs,
              evidenceProfileRefs: snapshot.evidenceProfileRefs,
              remediationRefs: snapshot.remediationRefs,
              requiredCapabilityIds: snapshot.requiredCapabilityIds,
              capabilityDescriptors: snapshot.capabilityDescriptors,
              capabilitySnapshotHash: snapshot.capabilitySnapshotHash,
              selectedCapabilitiesHash: snapshot.selectedCapabilitiesHash,
              selectedDefinitionsHash: snapshot.selectedDefinitionsHash,
              registrySnapshotHash: snapshot.registrySnapshotHash,
              environment: snapshot.environment,
              authorization: snapshot.authorization
            })
        )
      ).toBe(true)
      expect(() =>
        verifyScanModuleSnapshots(
          snapshots,
          scan.id,
          scan.families,
          'authorized-test-environment',
          platform
        )
      ).not.toThrow()
      expect(() =>
        database.native
          .prepare('UPDATE scan_module_snapshots SET module_version = ? WHERE scan_id = ?')
          .run('9.9.9', scan.id)
      ).toThrow(/immutable/)
      expect(
        database.native
          .prepare('SELECT module_snapshots_sealed AS sealed FROM scans WHERE id = ?')
          .get(scan.id)
      ).toEqual({ sealed: 1 })
      expect(() =>
        database.native
          .prepare(
            `INSERT INTO scan_module_snapshots (
               id, scan_id, family_id, module_id, module_version,
               definition_hash, technique_id, technique_version,
               strategy_refs_json, confirmation_rule_refs_json,
               evidence_profile_refs_json, remediation_refs_json,
               required_capability_ids_json, capability_descriptors_json,
               capability_snapshot_hash, selected_capabilities_hash,
               selected_definitions_hash, registry_snapshot_hash, environment,
               authorization, snapshot_hash, created_at
             )
             SELECT ?, scan_id, 'synthetic.extra', module_id, module_version,
                    definition_hash, 'synthetic.extra.technique', technique_version,
                    strategy_refs_json, confirmation_rule_refs_json,
                    evidence_profile_refs_json, remediation_refs_json,
                    required_capability_ids_json, capability_descriptors_json,
                    capability_snapshot_hash, selected_capabilities_hash,
                    selected_definitions_hash, registry_snapshot_hash, environment,
                    authorization, snapshot_hash, created_at
             FROM scan_module_snapshots
             WHERE scan_id = ?
             LIMIT 1`
          )
          .run(randomUUID(), scan.id)
      ).toThrow(/snapshot set is sealed/)

      const unsealedScanId = randomUUID()
      database.native
        .prepare(
          `INSERT INTO scans (
             id, target_id, name, scope_snapshot_id, status, phase, progress,
             budget_json, config_json, plan_json, runtime_json,
             request_count, model_tokens, estimated_cost_micros,
             checkpoint_count, last_error, module_snapshots_sealed,
             created_at, updated_at, started_at, completed_at
           )
           SELECT ?, target_id, 'Unsealed snapshot fixture', scope_snapshot_id,
                  'draft', phase, progress, budget_json, config_json, plan_json,
                  runtime_json, request_count, model_tokens,
                  estimated_cost_micros, checkpoint_count, NULL, 0,
                  created_at, updated_at, NULL, NULL
           FROM scans
           WHERE id = ?`
        )
        .run(unsealedScanId, scan.id)
      database.native
        .prepare(
          `INSERT INTO scan_module_snapshots (
             id, scan_id, family_id, module_id, module_version,
             definition_hash, technique_id, technique_version,
             strategy_refs_json, confirmation_rule_refs_json,
             evidence_profile_refs_json, remediation_refs_json,
             required_capability_ids_json, capability_descriptors_json,
             capability_snapshot_hash, selected_capabilities_hash,
             selected_definitions_hash, registry_snapshot_hash, environment,
             authorization, snapshot_hash, created_at
           )
           SELECT 'unsealed-' || id, ?, family_id, module_id, module_version,
                  definition_hash, technique_id, technique_version,
                  strategy_refs_json, confirmation_rule_refs_json,
                  evidence_profile_refs_json, remediation_refs_json,
                  required_capability_ids_json, capability_descriptors_json,
                  capability_snapshot_hash, selected_capabilities_hash,
                  selected_definitions_hash, registry_snapshot_hash, environment,
                  authorization, snapshot_hash, created_at
           FROM scan_module_snapshots
           WHERE scan_id = ?`
        )
        .run(unsealedScanId, scan.id)
      expect(() =>
        database.native
          .prepare('UPDATE scans SET status = ? WHERE id = ?')
          .run('running', unsealedScanId)
      ).toThrow(/must be sealed before execution/)
      const unsealedResult = await application.controlScan(unsealedScanId, 'start')
      expect(unsealedResult.status).toBe('awaiting-user')
      expect(unsealedResult.lastError).toMatch(/Inconclusive/)
      expect((await repository.getLatestCheckpoint(unsealedScanId))?.reason).toBe(
        'module-snapshot-incompatible:snapshot-set-unsealed'
      )

      const before = database.native.prepare('SELECT count(*) AS count FROM scans').get() as {
        count: number
      }
      await expect(
        application.createScan({
          ...input,
          moduleVersion: '9.9.9',
          moduleSnapshots: []
        } as never)
      ).rejects.toBeDefined()
      const after = database.native.prepare('SELECT count(*) AS count FROM scans').get() as {
        count: number
      }
      expect(after.count).toBe(before.count)
    } finally {
      database.close()
    }
  })

  it.each([
    { mode: 'missing' as const, expectedCode: 'snapshot-family-set-mismatch' },
    { mode: 'stale' as const, expectedCode: 'snapshot-definition-mismatch' },
    {
      mode: 'unavailable' as const,
      expectedCode: 'snapshot-definition-unavailable'
    }
  ])(
    'moves a $mode historical scan to awaiting-user before coordinator/tool side effects',
    async ({ mode, expectedCode }) => {
      const directory = mkdtempSync(join(tmpdir(), `agentgo-inventory-${mode}-`))
      temporaryDirectories.push(directory)
      const database = openAgentGoDatabase(':memory:')
      const repository = new AgentGoRepository(database)
      const platform = createVulnerabilityPlatform()
      const coordinatorControl = vi.fn()
      const coordinator = { control: coordinatorControl } as unknown as ScanCoordinator
      const application = new AgentGoApplicationService({
        repository,
        credentialStore: new FileCredentialStore(
          join(directory, 'credentials.json'),
          protector
        ),
        scanCoordinator: coordinator,
        vulnerabilityPlatform: platform,
        vulnerabilityExecutionEnvironment: 'authorized-test-environment'
      })
      try {
        await application.initialize()
        const workspace = await repository.createWorkspace({
          name: `${mode} workspace`,
          description: ''
        })
        const target = await repository.createTarget({
          workspaceId: workspace.id,
          name: `${mode} target`,
          baseUrl: 'https://snapshot.example.test/',
          description: '',
          authorizationReference: `${mode}-test`,
          scope: {
            allowedOrigins: ['https://snapshot.example.test'],
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
            maxConcurrency: 1,
            authorizationReference: `${mode}-test`
          }
        })
        const familyId = mode === 'unavailable' ? 'unknown.family' : 'sqli'
        const plan = createDefaultScanPlan([familyId])
        const currentDraft = buildScanModuleSnapshotDrafts(
          ['sqli'],
          'authorized-test-environment',
          platform
        )[0]!
        const historicalDraft: ScanModuleSnapshotDraft =
          mode === 'unavailable'
            ? { ...currentDraft, familyId }
            : { ...currentDraft, moduleVersion: '9.9.9' }
        const scan = await repository.createScan(
          {
            targetId: target.target.id,
            name: `${mode} scan`,
            description: '',
            families: [familyId],
            identityIds: [],
            budget: plan.budget
          },
          { ...plan },
          { ...createRuntimeState() },
          mode === 'missing'
            ? []
            : [
                {
                  draft: historicalDraft,
                  snapshotHash: computeScanModuleSnapshotHash(historicalDraft)
                }
              ]
        )

        const result = await application.controlScan(scan.id, 'start')
        expect(result.status).toBe('awaiting-user')
        expect(result.lastError).toMatch(/Inconclusive/)
        expect(coordinatorControl).not.toHaveBeenCalled()
        expect(await database.orm.select().from(agentRuns)).toHaveLength(0)
        expect(await database.orm.select().from(toolCalls)).toHaveLength(0)
        const checkpoint = await repository.getLatestCheckpoint(scan.id)
        expect(checkpoint?.reason).toBe(
          `module-snapshot-incompatible:${expectedCode}`
        )
        const event = (await repository.listScanEvents(scan.id)).at(-1)
        expect(event?.detail).toMatchObject({
          code: expectedCode,
          endState: 'inconclusive'
        })
      } finally {
        database.close()
      }
    }
  )
})
