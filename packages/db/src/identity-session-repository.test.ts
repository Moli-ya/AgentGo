import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sealCsrfBinding } from '@agentgo/domain'
import { openAgentGoDatabase, type AgentGoDatabase } from './database'
import { IdentitySessionRepository } from './identity-session-repository'
import { AgentGoRepository } from './repository'

const resources: { database: AgentGoDatabase; directory: string }[] = []
const now = Date.parse('2026-09-06T00:00:00.000Z')

afterEach(() => {
  for (const { database, directory } of resources.splice(0)) {
    database.close()
    rmSync(directory, { recursive: true, force: true })
  }
})

async function setup(maxUses = 1) {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-csrf-atomic-'))
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  resources.push({ database, directory })
  const repository = new AgentGoRepository(database)
  const sessions = new IdentitySessionRepository(database)
  const workspace = await repository.createWorkspace({ name: 'CSRF atomicity', description: '' })
  const { target, scope } = await repository.createTarget({
    workspaceId: workspace.id, name: 'Local test', description: '',
    baseUrl: 'https://lab.example.test', authorizationReference: 'synthetic-test',
    scope: {
      allowedOrigins: ['https://lab.example.test'], allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [], allowedPorts: [443], allowedIdentityIds: [],
      allowActiveProbing: true, allowSensitiveProbing: true,
      allowPrivateNetworkTargets: false, allowLoopbackTargets: false,
      networkEntries: [], maxRequestsPerMinute: 20, maxConcurrency: 1
    }
  })
  const identity = await repository.saveIdentity({
    targetId: target.id, label: 'Test owner', role: 'owner', authType: 'cookie',
    isTestIdentity: true, ownedResourceIds: []
  })
  const session = await sessions.createSession({
    sessionId: randomUUID(), identityId: identity.id,
    targetId: target.id, scopeSnapshotId: scope.id, now
  })
  const binding = sealCsrfBinding({
    schemaVersion: 'agentgo-identity-session/1.0', csrfBindingId: randomUUID(),
    csrfBindingVersion: 1, identityId: identity.id, sessionId: session.sessionId,
    sessionGeneration: session.generation, origin: target.baseUrl,
    boundMethod: 'POST', boundPath: '/objects', tokenHash: 'a'.repeat(64),
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString(),
    rule: {
      ruleVersion: 'csrf-atomic-test/1.0', sourceKind: 'json-pointer',
      sourceSelector: '/token', sourceOrigin: target.baseUrl, sourcePathPrefix: '/',
      encoding: 'raw', injectionLocation: 'header', injectionName: 'x-csrf-token', maxUses
    }
  })
  await sessions.insertCsrfBinding(binding)
  return { database, sessions, session, binding }
}

describe('atomic CSRF token reservations', () => {
  it.each([1, 2, 16])('grants exactly %i uses under concurrent reservation', async (maxUses) => {
    const { sessions, binding } = await setup(maxUses)
    const attempts = await Promise.all(Array.from({ length: 32 }, () =>
      sessions.recordCsrfUse(binding.csrfBindingId, binding.csrfBindingVersion, now)))
    expect(attempts.filter(Boolean)).toHaveLength(maxUses)
    const stored = await sessions.getCsrfBinding(binding.csrfBindingId, binding.csrfBindingVersion)
    expect(stored).toMatchObject({ useCount: maxUses, status: 'exhausted' })
  })

  it('rejects reservations for expired bindings without spending a use', async () => {
    const { sessions, binding } = await setup()
    expect(await sessions.recordCsrfUse(binding.csrfBindingId, 1, now + 60_000)).toBeUndefined()
    expect(await sessions.getCsrfBinding(binding.csrfBindingId, 1)).toMatchObject({ useCount: 0 })
  })

  it.each(['active', 'revoked', 'vault-lost'] as const)(
    'rejects a stale generation after transition to %s', async (status) => {
      const { sessions, binding, session } = await setup()
      await sessions.advanceSession(session.sessionId, { status, incrementGeneration: true }, now)
      expect(await sessions.recordCsrfUse(binding.csrfBindingId, 1, now)).toBeUndefined()
      expect(await sessions.getCsrfBinding(binding.csrfBindingId, 1)).toMatchObject({ useCount: 0 })
    }
  )
})
