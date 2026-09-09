import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  L2_CLEANUP_CAPABILITY_ID,
  ScanModuleSnapshotDraftSchema,
  type ActorContext,
  type CsrfBindingRule,
  type L2BundleStep,
  type SideEffectEnvelope,
  type TestObject
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  FileCredentialStore,
  IdentitySessionRepository,
  L2Repository,
  openAgentGoDatabase,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import {
  ApprovalService,
  FixtureApprovalAdapter
} from './approval-service'
import { AuthorizationMatrixService } from './authorization-matrix-service'
import { CsrfBindingService } from './csrf-binding-service'
import { IdentityContextService } from './identity-context-service'
import { L2BindingService } from './l2-binding-service'
import { L2ProtocolService } from './l2-protocol-service'
import { SessionVault } from './session-vault'

const HASH = 'b'.repeat(64)
const NOW = new Date('2026-08-26T00:00:00.000Z')
const COOKIE_SENTINEL = 'binding-cookie'
const CSRF_SENTINEL = 'binding-token'

const temporaryDirectories: string[] = []
const openDatabases: AgentGoDatabase[] = []

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
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

const csrfRule: CsrfBindingRule = {
  ruleVersion: 'fixture-csrf/1.0',
  sourceKind: 'json-pointer',
  sourceSelector: '/csrfToken',
  sourceOrigin: 'https://lab.example.test',
  sourcePathPrefix: '/test-objects/',
  encoding: 'raw',
  injectionLocation: 'header',
  injectionName: 'x-csrf-token',
  maxUses: 2
}

async function createHarness(now = NOW) {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-l2-approval-'))
  temporaryDirectories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const identitySessions = new IdentitySessionRepository(database)
  const l2Repository = new L2Repository(database)
  const credentialStore = new FileCredentialStore(
    join(directory, 'credentials.json'),
    protector()
  )
  const workspace = await repository.createWorkspace({
    name: 'L2 approval',
    description: 'Day 10 approval tests.'
  })
  const created = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'L2 approval lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'l2-approval-test',
    scope: {
      allowedOrigins: ['https://lab.example.test'],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [443],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: true,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      networkEntries: [],
      maxRequestsPerMinute: 20,
      maxConcurrency: 2
    }
  })
  const identity = await repository.saveIdentity({
    targetId: created.target.id,
    label: 'owner identity',
    role: 'owner',
    authType: 'cookie',
    headerName: undefined,
    isTestIdentity: true,
    ownedResourceIds: ['obj-1']
  })
  await repository.updateTarget({
    id: created.target.id,
    scope: {
      allowedOrigins: created.scope.allowedOrigins,
      allowedPathPrefixes: created.scope.allowedPathPrefixes,
      deniedPathPrefixes: created.scope.deniedPathPrefixes,
      allowedPorts: created.scope.allowedPorts,
      allowedIdentityIds: [identity.id],
      allowActiveProbing: true,
      allowSensitiveProbing: true,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      networkEntries: created.scope.networkEntries,
      maxRequestsPerMinute: 20,
      maxConcurrency: 2
    }
  })
  const moduleDraft = ScanModuleSnapshotDraftSchema.parse({
    familyId: 'sqli',
    moduleId: 'test.sqli.module',
    moduleVersion: '1.0.0',
    definitionHash: sha256('l2-approval-module'),
    techniqueId: 'sqli.query-differential',
    techniqueVersion: '1.0.0',
    strategyRefs: [{ id: 'test.sqli.strategy', version: '1.0.0' }],
    confirmationRuleRefs: [{ id: 'test.sqli.rule', version: '1.0.0' }],
    evidenceProfileRefs: [{ id: 'test.sqli.evidence', version: '1.0.0' }],
    remediationRefs: [{ id: 'test.sqli.remediation', version: '1.0.0' }],
    requiredCapabilityIds: ['http.reviewed-read'],
    capabilityDescriptors: [
      {
        id: 'http.reviewed-read',
        riskFloor: 'l1',
        descriptorHash: sha256('http.reviewed-read')
      }
    ],
    capabilitySnapshotHash: sha256('l2-approval-capability'),
    selectedCapabilitiesHash: sha256('l2-approval-selected-cap'),
    selectedDefinitionsHash: sha256('l2-approval-selected-def'),
    registrySnapshotHash: sha256('l2-approval-registry'),
    environment: 'authorized-test-environment',
    authorization: 'qualified'
  })
  const scan = await repository.createScan(
    {
      targetId: created.target.id,
      name: 'L2 approval scan',
      description: 'Day 10.',
      families: ['sqli'],
      identityIds: [identity.id],
      budget: {
        maxRequests: 8,
        maxRequestsPerMinute: 20,
        maxConcurrency: 2,
        maxPlanRevisions: 0,
        maxDurationMinutes: 10,
        maxModelTokens: 0,
        maxEstimatedCost: 0,
        maxRequestBytes: 1_146_880,
        maxResponseBytes: 16_777_216
      }
    },
    { version: '1.0.0', steps: ['l2.protocol'] },
    {},
    [{ draft: moduleDraft, snapshotHash: sha256('l2-approval-snapshot') }]
  )
  const l2 = new L2ProtocolService({
    l2Repository,
    scanRepository: repository,
    now: () => now
  })
  const vault = new SessionVault({
    identitySessionRepository: identitySessions,
    repository,
    credentialStore,
    now: () => now.getTime()
  })
  const identityContexts = new IdentityContextService({
    repository,
    identitySessionRepository: identitySessions,
    credentialStore,
    now: () => now
  })
  const csrf = new CsrfBindingService({
    identitySessionRepository: identitySessions,
    sessionVault: vault,
    now: () => now.getTime()
  })
  const matrices = new AuthorizationMatrixService({
    repository,
    identitySessionRepository: identitySessions,
    now: () => now
  })
  const bindings = new L2BindingService({
    l2ProtocolService: l2,
    l2Repository,
    identityContextService: identityContexts,
    sessionVault: vault,
    csrfBindingService: csrf,
    authorizationMatrixService: matrices,
    identitySessionRepository: identitySessions,
    now: () => now
  })
  l2.setBindingFreshnessVerifier((bundle) => bindings.assertBindingsFresh(bundle))
  return {
    l2,
    vault,
    identityContexts,
    csrf,
    matrices,
    bindings,
    identitySessions,
    repository,
    scan,
    identity,
    targetId: created.target.id,
    scopeSnapshotId: scan.scopeSnapshotId
  }
}

type Harness = Awaited<ReturnType<typeof createHarness>>

function envelope(): SideEffectEnvelope {
  return {
    expectedStateChange: 'status:draft-to-submitted',
    maxImpactScope: 'single-test-object-fields',
    writableResourceId: 'obj-1',
    fieldWrites: [
      {
        fieldPath: 'status',
        oldValueConstraint: 'draft',
        newValueConstraint: 'submitted'
      }
    ],
    externalSideEffects: [],
    observationRoles: {
      preRead: 'pre-read',
      postRead: 'post-read',
      terminalRead: 'terminal-read'
    },
    unknownSideEffects: [],
    unobservableSideEffects: [],
    irreversibleItems: []
  }
}

function steps(object: TestObject): L2BundleStep[] {
  const bind = (purpose: 'read' | 'primary' | 'cleanup') => ({
    purpose,
    testObjectVersion: object.objectVersion,
    scopeSnapshotId: object.scopeSnapshotId,
    familyId: 'sqli' as const,
    moduleId: 'legacy.sqli.boolean-differential',
    moduleVersion: '1.0.0',
    techniqueId: 'sqli.boolean-differential',
    techniqueVersion: '1.0.0',
    templateIntentHash: {
      domain: 'agentgo.template-intent.v1' as const,
      algorithm: 'sha256' as const,
      digest: HASH
    },
    budget: { maxRequests: 1, maxDurationMs: 5_000 }
  })
  return [
    { kind: 'pre-read', binding: bind('read') },
    { kind: 'primary', binding: bind('primary') },
    { kind: 'post-read', binding: bind('read') },
    {
      kind: 'cleanup',
      binding: bind('cleanup'),
      cleanupProtocol: object.cleanupProtocol
    },
    { kind: 'cleanup-verify', binding: bind('read') },
    { kind: 'terminal-read', binding: bind('read') }
  ]
}

async function createObject(harness: Harness) {
  return harness.l2.createTestObject({
    scanId: harness.scan.id,
    targetId: harness.targetId,
    identityId: harness.identity.id,
    objectType: 'record',
    allowedFields: ['status'],
    allowedStates: ['draft', 'submitted', 'absent'],
    canonicalResource: {
      kind: 'http-resource',
      origin: 'https://lab.example.test',
      method: 'POST',
      path: '/test-objects/obj-1',
      resourceId: 'obj-1'
    },
    cleanupProtocol: {
      kind: 'reset',
      declaredByTarget: true,
      capabilityId: L2_CLEANUP_CAPABILITY_ID,
      method: 'POST',
      path: '/test-objects/obj-1',
      expectedTerminalState: 'absent',
      maxRequests: 1
    },
    closeConditions: ['expired', 'externally-modified'],
    expiresAt: '2026-08-27T00:00:00.000Z',
    creationEvidenceHash: HASH,
    baselineEvidenceHash: HASH
  })
}

async function prepareDay9Bindings(harness: Harness) {
  await harness.identityContexts.issueIdentityContext({
    identityId: harness.identity.id,
    targetId: harness.targetId,
    scopeSnapshotId: harness.scopeSnapshotId,
    role: 'owner',
    ownerLabel: 'owner identity',
    purpose: 'L2 approval test',
    allowedOperations: ['write-test-object', 'cleanup-test-object'],
    confirmationAuditRef: randomUUID(),
    ttlMs: 3_600_000
  })
  const session = await harness.vault.establishSession({
    identityId: harness.identity.id,
    scopeSnapshotId: harness.scopeSnapshotId
  })
  await harness.vault.ingestSetCookie(
    session.sessionId,
    `sid=${COOKIE_SENTINEL}; Path=/; HttpOnly`,
    'https://lab.example.test/'
  )
  const csrfCapture = await harness.csrf.captureBinding({
    identityId: harness.identity.id,
    sessionId: session.sessionId,
    origin: 'https://lab.example.test',
    boundMethod: 'POST',
    boundPath: '/test-objects/obj-1',
    rule: csrfRule,
    response: {
      url: 'https://lab.example.test/test-objects/obj-1/edit',
      bodyText: `{"csrfToken":"${CSRF_SENTINEL}"}`
    },
    ttlMs: 600_000
  })
  if (!csrfCapture.ok) throw new Error('CSRF capture failed in test setup.')
  await harness.matrices.confirmMatrix({
    targetId: harness.targetId,
    scopeSnapshotId: harness.scopeSnapshotId,
    entries: [
      {
        subjectIdentityId: harness.identity.id,
        resourceOwnerIdentityId: harness.identity.id,
        role: 'owner',
        operation: 'write',
        resourceRef: 'obj-1',
        expected: 'state-allowed',
        humanSource: 'test declaration'
      },
      {
        subjectIdentityId: harness.identity.id,
        resourceOwnerIdentityId: harness.identity.id,
        role: 'owner',
        operation: 'delete',
        resourceRef: 'obj-1',
        expected: 'state-allowed',
        humanSource: 'test declaration'
      }
    ],
    humanAttestationRef: randomUUID(),
    ttlMs: 3_600_000
  })
  return { session, csrf: csrfCapture.binding }
}

async function pendingBundle(harness: Harness) {
  const object = await createObject(harness)
  const draft = await harness.l2.proposeBundle({
    scanId: harness.scan.id,
    targetId: harness.targetId,
    testObjectId: object.testObjectId,
    testObjectVersion: object.objectVersion,
    sideEffectEnvelope: envelope(),
    steps: steps(object)
  })
  const bindings = await prepareDay9Bindings(harness)
  const resolved = await harness.bindings.resolveBundleBindings({
    bundleId: draft.bundle.bundleId,
    bundleVersion: draft.bundle.bundleVersion,
    expectedRowVersion: draft.runtime.rowVersion,
    csrfBindingHash: bindings.csrf.bindingHash
  })
  return { object, resolved, ...bindings }
}

function fixtureApprovals(harness: Harness, now: () => Date = () => NOW) {
  return new ApprovalService({
    identitySessionRepository: harness.identitySessions,
    l2ProtocolService: harness.l2,
    bindingService: harness.bindings,
    approvalMode: 'fixture-only',
    now
  })
}

afterEach(() => {
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('ApprovalService (Day 10 trust boundary)', () => {
  it('rejects forged actor proofs, roles, and userApproved as authorization', async () => {
    const harness = await createHarness()
    const { resolved } = await pendingBundle(harness)
    const approvals = fixtureApprovals(harness)
    const adapter = new FixtureApprovalAdapter(approvals)
    const actor = adapter.mint([harness.targetId])
    const proposal = await approvals.createProposal(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )

    const forgedDigest: ActorContext = {
      ...actor,
      handle: { ...actor.handle, digest: 'a'.repeat(64) }
    }
    await expect(
      approvals.approve({ actor: forgedDigest, proposalId: proposal.proposalId })
    ).resolves.toMatchObject({ ok: false, reasonCode: 'untrusted-actor' })

    const forgedRole: ActorContext = {
      ...actor,
      roles: Object.freeze([]) as unknown as ActorContext['roles']
    }
    await expect(
      approvals.approve({ actor: forgedRole, proposalId: proposal.proposalId })
    ).resolves.toMatchObject({ ok: false, reasonCode: 'untrusted-actor' })

    await expect(
      approvals.approve({
        actor: forgedDigest,
        proposalId: proposal.proposalId,
        userApproved: true
      })
    ).resolves.toMatchObject({
      ok: false,
      reasonCode: 'legacy-user-approved-ignored'
    })

    const wrongTarget = adapter.mint([randomUUID()])
    await expect(
      approvals.approve({ actor: wrongTarget, proposalId: proposal.proposalId })
    ).resolves.toMatchObject({ ok: false, reasonCode: 'actor-scope-mismatch' })
  })

  it('ignores userApproved when a trusted fixture actor is present', async () => {
    const harness = await createHarness()
    const { resolved } = await pendingBundle(harness)
    const approvals = fixtureApprovals(harness)
    const actor = new FixtureApprovalAdapter(approvals).mint([harness.targetId])
    const proposal = await approvals.createProposal(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    const result = await approvals.approve({
      actor,
      proposalId: proposal.proposalId,
      userApproved: true
    })
    expect(result).toMatchObject({
      ok: true,
      ignoredUserApproved: true
    })
    if (!result.ok) throw new Error('expected approval')
    expect(result.view.record.approvalMode).toBe('fixture-only')
    expect(result.view.record.decision).toBe('approved')
    const view = await harness.l2.getBundleView(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    expect(view?.runtime.state).toBe('approved')
  })

  it('rejects, revokes, and refuses a second consume of a single-use approval', async () => {
    const harness = await createHarness()
    const { resolved } = await pendingBundle(harness)
    const approvals = fixtureApprovals(harness)
    const actor = new FixtureApprovalAdapter(approvals).mint([harness.targetId])
    const proposal = await approvals.createProposal(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    const rejected = await approvals.reject({
      actor,
      proposalId: proposal.proposalId
    })
    expect(rejected).toMatchObject({ ok: true })
    if (!rejected.ok) throw new Error('expected reject')
    expect(rejected.view.status).toBe('rejected')
    const afterReject = await harness.l2.getBundleView(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    expect(afterReject?.runtime.state).toBe('revoked')

    const harness2 = await createHarness()
    const pending = await pendingBundle(harness2)
    const approvals2 = fixtureApprovals(harness2)
    const actor2 = new FixtureApprovalAdapter(approvals2).mint([harness2.targetId])
    const proposal2 = await approvals2.createProposal(
      pending.resolved.bundle.bundleId,
      pending.resolved.bundle.bundleVersion
    )
    const approved = await approvals2.approve({
      actor: actor2,
      proposalId: proposal2.proposalId
    })
    expect(approved.ok).toBe(true)
    if (!approved.ok) throw new Error('expected approve')
    const consumed = await approvals2.consumeForPrimary(approved.view.record.approvalId)
    expect(consumed.status).toBe('consumed')
    await expect(
      approvals2.consumeForPrimary(approved.view.record.approvalId)
    ).rejects.toMatchObject({ reasonCode: 'already-consumed' })
    await expect(
      approvals2.revoke({
        actor: actor2,
        approvalId: approved.view.record.approvalId,
        reason: 'late revoke'
      })
    ).resolves.toMatchObject({ ok: false, reasonCode: 'already-consumed' })

    const harness3 = await createHarness()
    const pending3 = await pendingBundle(harness3)
    const approvals3 = fixtureApprovals(harness3)
    const actor3 = new FixtureApprovalAdapter(approvals3).mint([harness3.targetId])
    const proposal3 = await approvals3.createProposal(
      pending3.resolved.bundle.bundleId,
      pending3.resolved.bundle.bundleVersion
    )
    const live = await approvals3.approve({
      actor: actor3,
      proposalId: proposal3.proposalId
    })
    if (!live.ok) throw new Error('expected approve')
    const revoked = await approvals3.revoke({
      actor: actor3,
      approvalId: live.view.record.approvalId,
      reason: 'operator revoke'
    })
    expect(revoked).toMatchObject({ ok: true })
    if (!revoked.ok) throw new Error('expected revoke')
    expect(revoked.view.status).toBe('revoked')
  })

  it('invalidates a proposal when session generation drifts', async () => {
    const harness = await createHarness()
    const { resolved, session } = await pendingBundle(harness)
    const approvals = fixtureApprovals(harness)
    const actor = new FixtureApprovalAdapter(approvals).mint([harness.targetId])
    const proposal = await approvals.createProposal(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    await harness.vault.rotateSession(session.sessionId)
    await expect(
      approvals.approve({ actor, proposalId: proposal.proposalId })
    ).resolves.toMatchObject({ ok: false, reasonCode: 'binding-version-drift' })
  })

  it('does not persist Cookie or CSRF plaintext in the proposal', async () => {
    const harness = await createHarness()
    const { resolved } = await pendingBundle(harness)
    const approvals = fixtureApprovals(harness)
    const proposal = await approvals.createProposal(
      resolved.bundle.bundleId,
      resolved.bundle.bundleVersion
    )
    const serialized = JSON.stringify(proposal)
    expect(serialized).not.toContain(COOKIE_SENTINEL)
    expect(serialized).not.toContain(CSRF_SENTINEL)
    expect(proposal.humanRiskNotes.join(' ')).toContain('approvalMode=fixture-only')
    expect(proposal.bindings.sessionGeneration).toMatch(/:/)
  })

  it('refuses fixture actors on a trusted-backend service and the reverse', async () => {
    const harness = await createHarness()
    const trusted = new ApprovalService({
      identitySessionRepository: harness.identitySessions,
      l2ProtocolService: harness.l2,
      bindingService: harness.bindings,
      approvalMode: 'trusted-backend',
      now: () => NOW
    })
    expect(() =>
      trusted.mintFixtureActor({ allowedTargetIds: [harness.targetId] })
    ).toThrow(/fixture/i)
    expect(
      () =>
        new FixtureApprovalAdapter(
          fixtureApprovals(harness)
        )
    ).not.toThrow()
    expect(() => new FixtureApprovalAdapter(trusted)).toThrow(/fixture-only/i)
  })
})
