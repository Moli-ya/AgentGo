import { describe, expect, it, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  AgentGoRepository,
  openAgentGoDatabase,
  type AgentGoDatabase
} from '@agentgo/db'
import { buildKnowledgePack } from '@agentgo/knowledge-base'
import { RetrievalService } from './retrieval-service'

const directories: string[] = []
const openDatabases: AgentGoDatabase[] = []

afterEach(() => {
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('RetrievalService', () => {
  it('matches buildKnowledgePack for built-in families and keeps suggestions referenced', () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-retrieval-'))
    directories.push(directory)
    const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
    openDatabases.push(database)
    const repository = new AgentGoRepository(database)
    const retrieval = new RetrievalService(repository)
    const families = ['sqli', 'xss'] as const
    const pack = buildKnowledgePack({
      families: [...families],
      techTags: [],
      signalTerms: ['id', 'q'],
      tokenBudget: 2_000
    })
    const result = retrieval.retrieve({
      families: [...families],
      signalTerms: ['id', 'q'],
      tokenBudget: 2_000
    })
    expect(result.pack.matchedEntryIds).toEqual(pack.matchedEntryIds)
    expect(result.coordinatorOutput.matchedEntryIds.length).toBeGreaterThan(0)
    expect(result.suggestions.length).toBeGreaterThan(0)
    expect(result.suggestions[0]?.sourceRefs.length).toBeGreaterThan(0)
    expect(result.suggestions[0]?.forbiddenCapabilityRefs.length).toBeGreaterThan(0)
    expect(result.unmappedIntelligence).toEqual([])
  })

  it('keeps unregistered imported families out of compiler guidance', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-retrieval-unmap-'))
    directories.push(directory)
    const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
    openDatabases.push(database)
    const repository = new AgentGoRepository(database)
    const imported = await repository.createKnowledgeImport(
      {
        sourceType: 'research',
        title: 'Unregistered SSTI research note',
        rawContent: 'Server-side template injection research note for ssti-unmapped-unique.'
      },
      []
    )
    await repository.saveKnowledgeCandidate(
      imported.id,
      {
        schemaVersion: 'vulnerability-intel.v1',
        title: 'Unregistered SSTI research note',
        vendor: 'Lab',
        product: 'Demo',
        vulnerabilityType: 'ssti',
        family: 'ssti',
        identifiers: { cve: [], cwe: [], other: [] },
        affectedVersions: [],
        preconditions: [],
        affectedEndpoints: [],
        signals: ['ssti-unmapped-unique'],
        confirmationRules: ['do-not-execute-raw-poc'],
        remediation: ['upgrade-template-engine'],
        forbiddenActions: ['execute-raw-poc'],
        fieldEvidence: [
          {
            field: 'title',
            quote: 'Unregistered SSTI research note',
            confidence: 1
          }
        ],
        extractionConfidence: 0.8
      },
      [],
      'ready-for-review'
    )
    await repository.reviewKnowledgeImport(imported.id, 'publish')
    const retrieval = new RetrievalService(repository)
    const result = await retrieval.retrieveForScan({
      families: ['ssti'],
      signalTerms: ['ssti-unmapped-unique']
    })
    expect(result.unmappedIntelligence.some((item) => item.reason === 'unregistered-technique')).toBe(
      true
    )
    expect(result.coordinatorOutput.guidance.every((item) => item.family !== 'ssti')).toBe(true)
    expect(
      result.coordinatorOutput.guidance.every((item) =>
        ['sqli', 'xss', 'ssrf', 'idor'].includes(item.family)
      )
    ).toBe(true)
  })
})
