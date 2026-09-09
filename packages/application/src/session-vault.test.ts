import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  AgentGoRepository,
  FileCredentialStore,
  IdentitySessionRepository,
  openAgentGoDatabase,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { SessionVault, SessionVaultError } from './session-vault'
import { IdentityContextService } from './identity-context-service'

const temporaryDirectories: string[] = []
const openDatabases: AgentGoDatabase[] = []

const COOKIE_SENTINEL = 'VAULT-COOKIE-SENTINEL-7f3a9c'
const TOKEN_SENTINEL = 'VAULT-BEARER-SENTINEL-91cd42'

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

async function createHarness(now = Date.parse('2026-08-26T00:00:00.000Z')) {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-session-vault-'))
  temporaryDirectories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const identitySessions = new IdentitySessionRepository(database)
  const credentialStore = new FileCredentialStore(
    join(directory, 'credentials.json'),
    protector()
  )
  const workspace = await repository.createWorkspace({ name: 'Vault', description: '' })
  const created = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'Vault lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'vault-test',
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
  const scopeSnapshotId = created.scope.id
  const targetId = created.target.id
  const saveIdentity = (label: string, authType: 'none' | 'bearer' | 'cookie' = 'none') =>
    repository.saveIdentity({
      targetId,
      label,
      role: 'owner',
      authType,
      isTestIdentity: true,
      ownedResourceIds: []
    })
  const vault = new SessionVault({
    identitySessionRepository: identitySessions,
    repository,
    credentialStore,
    now: () => now
  })
  return {
    vault,
    repository,
    identitySessions,
    credentialStore,
    database,
    directory,
    targetId,
    scopeSnapshotId,
    saveIdentity
  }
}

afterEach(() => {
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('SessionVault', () => {
  it('ingests Set-Cookie into the private jar and materializes exact request headers', async () => {
    const harness = await createHarness()
    const identity = await harness.saveIdentity('alice')
    const session = await harness.vault.establishSession({
      identityId: identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    const ingested = await harness.vault.ingestSetCookie(
      session.sessionId,
      `sid=${COOKIE_SENTINEL}; Path=/app; HttpOnly; SameSite=Strict`,
      'https://lab.example.test/app/login'
    )
    expect(ingested.ok).toBe(true)

    await expect(
      harness.vault.cookieHeaderFor(session.sessionId, 'https://lab.example.test/app/data')
    ).resolves.toBe(`sid=${COOKIE_SENTINEL}`)
    await expect(
      harness.vault.cookieHeaderFor(session.sessionId, 'https://lab.example.test/other')
    ).resolves.toBeUndefined()
  })

  it('isolates jars per identity and never shares cookies across identities', async () => {
    const harness = await createHarness()
    const alice = await harness.saveIdentity('alice')
    const bob = await harness.saveIdentity('bob')
    const aliceSession = await harness.vault.establishSession({
      identityId: alice.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    const bobSession = await harness.vault.establishSession({
      identityId: bob.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    await harness.vault.ingestSetCookie(
      aliceSession.sessionId,
      `sid=${COOKIE_SENTINEL}; Path=/`,
      'https://lab.example.test/'
    )
    await expect(
      harness.vault.cookieHeaderFor(bobSession.sessionId, 'https://lab.example.test/')
    ).resolves.toBeUndefined()
    expect(aliceSession.sessionId).not.toBe(bobSession.sessionId)
  })

  it('invalidates every reference on rotation, clear, and revoke', async () => {
    const harness = await createHarness()
    const identity = await harness.saveIdentity('alice')
    const session = await harness.vault.establishSession({
      identityId: identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    const generationZero = await harness.vault.sessionGenerationRef(session.sessionId)
    expect(generationZero.generation).toBe(0)

    const rotated = await harness.vault.rotateSession(session.sessionId)
    expect(rotated.generation).toBe(1)
    await expect(
      harness.vault.assertActiveGeneration(session.sessionId, 0)
    ).rejects.toMatchObject({ code: 'session-generation-mismatch' })
    await expect(
      harness.vault.cookieHeaderFor(session.sessionId, 'https://lab.example.test/', 0)
    ).rejects.toMatchObject({ code: 'session-generation-mismatch' })

    await harness.vault.clearSession(session.sessionId)
    await expect(
      harness.vault.sessionGenerationRef(session.sessionId)
    ).rejects.toMatchObject({ code: 'session-not-active' })

    const rebuilt = await harness.vault.establishSession({
      identityId: identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    expect(rebuilt.sessionId).toBe(session.sessionId)
    expect(rebuilt.status).toBe('active')
    expect(rebuilt.generation).toBeGreaterThan(1)

    await harness.vault.revokeSession(session.sessionId)
    await expect(
      harness.vault.assertActiveGeneration(session.sessionId, rebuilt.generation)
    ).rejects.toMatchObject({ code: 'session-not-active' })
  })

  it('marks active sessions vault-lost on restart and requires re-injection with a new generation', async () => {
    const harness = await createHarness()
    const identity = await harness.saveIdentity('alice')
    const session = await harness.vault.establishSession({
      identityId: identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    await harness.vault.ingestSetCookie(
      session.sessionId,
      `sid=${COOKIE_SENTINEL}; Path=/`,
      'https://lab.example.test/'
    )

    const injected = await harness.vault.sessionGenerationRef(session.sessionId)
    const lost = harness.vault.markActiveSessionsVaultLost()
    expect(lost).toBe(1)
    const afterLoss = await harness.vault.getSession(session.sessionId)
    expect(afterLoss?.status).toBe('vault-lost')
    expect(afterLoss?.generation).toBe(injected.generation + 1)
    await expect(
      harness.vault.cookieHeaderFor(session.sessionId, 'https://lab.example.test/')
    ).rejects.toMatchObject({ code: 'session-not-active' })

    const rebuilt = await harness.vault.establishSession({
      identityId: identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    expect(rebuilt.status).toBe('active')
    expect(rebuilt.generation).toBe(injected.generation + 2)
    await expect(
      harness.vault.cookieHeaderFor(session.sessionId, 'https://lab.example.test/')
    ).resolves.toBeUndefined()
  })

  it('refuses to establish sessions for non-test identities', async () => {
    const harness = await createHarness()
    const realIdentity = await harness.repository.saveIdentity({
      targetId: harness.targetId,
      label: 'production-user',
      role: 'owner',
      authType: 'none',
      isTestIdentity: false,
      ownedResourceIds: []
    })
    await expect(
      harness.vault.establishSession({
        identityId: realIdentity.id,
        scopeSnapshotId: harness.scopeSnapshotId
      })
    ).rejects.toBeInstanceOf(SessionVaultError)
  })

  it('rejects a session scope from another target', async () => {
    const harness = await createHarness()
    const identity = await harness.saveIdentity('alice')
    const other = await harness.repository.createTarget({
      workspaceId: (await harness.repository.getTarget(harness.targetId))!.workspaceId,
      name: 'Other target', baseUrl: 'https://other.example.test', description: '',
      authorizationReference: 'other-test',
      scope: { ...(await harness.repository.getScope(harness.scopeSnapshotId))!, allowedOrigins: ['https://other.example.test'] }
    })
    await expect(harness.vault.establishSession({ identityId: identity.id, scopeSnapshotId: other.scope.id }))
      .rejects.toMatchObject({ code: 'scope-mismatch' })
  })

  it('invalidates pinned resolvers and authority after every injection, rotation, and cookie deletion', async () => {
    const harness = await createHarness()
    const identity = await harness.saveIdentity('alice')
    const session = await harness.vault.establishSession({ identityId: identity.id, scopeSnapshotId: harness.scopeSnapshotId })
    const url = 'https://lab.example.test/'
    await harness.vault.ingestSetCookie(session.sessionId, 'sid=first; Path=/', url)
    await expect(harness.vault.assertActiveGeneration(session.sessionId, session.generation))
      .rejects.toMatchObject({ code: 'session-generation-mismatch' })
    const named = await harness.vault.namedCookieSecretResolverFor(session.sessionId, 'sid', url)
    const all = await harness.vault.cookieSecretResolverFor(session.sessionId, url)
    const input = { secretRef: session.sessionId, generation: named.sessionRef.generation, sessionRef: named.sessionRef }
    expect(named.resolver.resolve(input)).toBe('first')
    expect(all.resolver.resolve(input)).toBe('sid=first')
    await harness.vault.ingestSetCookie(session.sessionId, 'sid=second; Path=/', url)
    expect(() => named.resolver.resolve(input)).toThrow(/no longer current/)
    expect(() => all.resolver.resolve(input)).toThrow(/no longer current/)
    await expect(harness.vault.cookieHeaderFor(session.sessionId, 'http://lab.example.test/')).resolves.toBeUndefined()
    await expect(harness.vault.cookieHeaderFor(session.sessionId, 'https://lab.example.test:8443/')).resolves.toBeUndefined()
    await harness.vault.ingestSetCookie(session.sessionId, 'sid=; Path=/; Max-Age=0', url)
    await expect(harness.vault.cookieHeaderFor(session.sessionId, url)).resolves.toBeUndefined()
  })

  it('never persists cookie or token plaintext in any database table', async () => {
    const harness = await createHarness()
    const metadata = harness.credentialStore.save({
      kind: 'identity',
      label: 'bearer-alice',
      secret: TOKEN_SENTINEL
    })
    const identity = await harness.repository.saveIdentity(
      {
        targetId: harness.targetId,
        label: 'bearer-alice',
        role: 'owner',
        authType: 'bearer',
        isTestIdentity: true,
        ownedResourceIds: []
      },
      metadata.id
    )
    const session = await harness.vault.establishSession({
      identityId: identity.id,
      scopeSnapshotId: harness.scopeSnapshotId
    })
    await harness.vault.ingestSetCookie(
      session.sessionId,
      `sid=${COOKIE_SENTINEL}; Path=/`,
      'https://lab.example.test/'
    )
    const context = await new IdentityContextService({
      repository: harness.repository,
      identitySessionRepository: harness.identitySessions,
      credentialStore: harness.credentialStore,
      now: () => new Date('2026-08-26T00:00:00.000Z')
    }).issueIdentityContext({
      identityId: identity.id,
      targetId: harness.targetId,
      scopeSnapshotId: harness.scopeSnapshotId,
      role: 'owner',
      ownerLabel: 'alice',
      purpose: 'L2 fixture validation',
      allowedOperations: ['write-test-object', 'cleanup-test-object'],
      confirmationAuditRef: randomUUID(),
      ttlMs: 60_000
    })
    expect(context.credential.credentialId).toBe(metadata.id)

    const rows = harness.database.native
      .prepare(
        `SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`
      )
      .all() as { name: string }[]
    const serialized = rows
      .map(({ name }) =>
        JSON.stringify(
          harness.database.native.prepare(`SELECT * FROM "${name}"`).all()
        )
      )
      .join('\n')
    expect(serialized).not.toContain(COOKIE_SENTINEL)
    expect(serialized).not.toContain(TOKEN_SENTINEL)
  })
})
