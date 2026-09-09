import type {
  Environment,
  ScanModuleSnapshotRecord,
  VulnerabilityFamily
} from '@agentgo/contracts'
import { AgentGoRepository } from '@agentgo/db'
import {
  buildKnowledgePack,
  V1_KNOWLEDGE_ENTRIES,
  type KnowledgePack,
  type KnowledgeQuery
} from '@agentgo/knowledge-base'
import type { KnowledgeAgentOutput } from './agent-prompts'

export interface RetrievalSuggestion {
  readonly family: VulnerabilityFamily
  readonly sourceRefs: readonly string[]
  readonly confirmationRuleRefs: readonly string[]
  readonly negativeControlRefs: readonly string[]
  readonly forbiddenCapabilityRefs: readonly string[]
  readonly remediationRefs: readonly string[]
}

export interface UnmappedIntelligence {
  readonly chunkId: string
  readonly family?: string
  readonly reason: 'unregistered-technique' | 'unreviewed-import'
}

export interface RetrievalResult {
  readonly pack: KnowledgePack
  readonly coordinatorOutput: KnowledgeAgentOutput
  readonly suggestions: readonly RetrievalSuggestion[]
  readonly unmappedIntelligence: readonly UnmappedIntelligence[]
}

export interface RetrievalInput {
  readonly families: readonly VulnerabilityFamily[]
  readonly signalTerms: readonly string[]
  readonly snapshots?: readonly ScanModuleSnapshotRecord[]
  readonly environment?: Environment
  readonly tokenBudget?: number
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)]
}

const REGISTERED_TECHNIQUE_FAMILIES = new Set(
  V1_KNOWLEDGE_ENTRIES.map((entry) => entry.family)
)

export class RetrievalService {
  constructor(private readonly repository: AgentGoRepository) {}

  retrieve(input: RetrievalInput): RetrievalResult {
    const snapshotFamilies = (input.snapshots ?? [])
      .filter(
        (snapshot) =>
          input.environment === undefined || snapshot.environment === input.environment
      )
      .map((snapshot) => snapshot.familyId)
    const families =
      snapshotFamilies.length > 0
        ? input.families.filter((family) => snapshotFamilies.includes(family))
        : [...input.families]
    const pack = buildKnowledgePack({
      families,
      techTags: [],
      signalTerms: [...input.signalTerms],
      tokenBudget: input.tokenBudget ?? 2_000
    })
    return {
      pack,
      coordinatorOutput: this.toCoordinatorOutput(families, [...input.signalTerms]),
      suggestions: this.suggestions(pack.query, pack),
      unmappedIntelligence: []
    }
  }

  retrieveForScan(input: {
    readonly families: readonly VulnerabilityFamily[]
    readonly signalTerms: readonly string[]
  }): Promise<RetrievalResult> {
    const baseline = this.retrieve({
      families: input.families,
      signalTerms: input.signalTerms
    })
    return this.mergePublishedImports(baseline, input.families, input.signalTerms)
  }

  private suggestions(
    query: KnowledgeQuery,
    pack: KnowledgePack
  ): RetrievalSuggestion[] {
    void query
    return V1_KNOWLEDGE_ENTRIES.filter((entry) =>
      pack.matchedEntryIds.includes(entry.id)
    ).map((entry) => ({
      family: entry.family,
      sourceRefs: entry.sourceRefs,
      confirmationRuleRefs: entry.confirmationRules,
      negativeControlRefs: entry.falsePositivePatterns,
      forbiddenCapabilityRefs: entry.forbiddenActions,
      remediationRefs: entry.remediationHints
    }))
  }

  private toCoordinatorOutput(
    families: readonly VulnerabilityFamily[],
    signalTerms: string[]
  ): KnowledgeAgentOutput {
    const entryById = new Map(V1_KNOWLEDGE_ENTRIES.map((entry) => [entry.id, entry]))
    const baselineIds = families.flatMap((family) =>
      V1_KNOWLEDGE_ENTRIES.filter((entry) => entry.family === family).map((entry) => entry.id)
    )
    const matchedIds = unique([
      ...baselineIds,
      ...families.flatMap((family) =>
        this.repository.searchKnowledgeEntryIds({
          query: signalTerms.join(' '),
          families: [family],
          limit: 5
        })
      )
    ])
    const entries = matchedIds
      .map((entryId) => entryById.get(entryId))
      .filter((entry): entry is (typeof V1_KNOWLEDGE_ENTRIES)[number] => Boolean(entry))
    return {
      matchedEntryIds: entries.map((entry) => entry.id),
      guidance: entries.map((entry) => ({
        family: entry.family,
        applicability: entry.applicability,
        safeProbePrinciples: entry.safeProbePrinciples,
        confirmationRules: entry.confirmationRules,
        falsePositivePatterns: entry.falsePositivePatterns,
        remediationHints: entry.remediationHints
      })),
      sourceRefs: unique(entries.flatMap((entry) => entry.sourceRefs)),
      policyConstraints: unique(entries.flatMap((entry) => entry.forbiddenActions)),
      ...(entries.length === 0
        ? {
            sourceRefs: [],
            policyConstraints: [
              '知识检索未命中时不得扩大测试范围或生成未经规则审查的动作。'
            ]
          }
        : {})
    }
  }

  private async mergePublishedImports(
    baseline: RetrievalResult,
    families: readonly VulnerabilityFamily[],
    signalTerms: readonly string[]
  ): Promise<RetrievalResult> {
    const entryById = new Map(V1_KNOWLEDGE_ENTRIES.map((entry) => [entry.id, entry]))
    const baselineIds = families.flatMap((family) =>
      V1_KNOWLEDGE_ENTRIES.filter((entry) => entry.family === family).map((entry) => entry.id)
    )
    const matchedIds = unique([
      ...baselineIds,
      ...families.flatMap((family) =>
        this.repository.searchKnowledgeEntryIds({
          query: signalTerms.join(' '),
          families: [family],
          limit: 5
        })
      )
    ])
    const importedEntries = (
      await this.repository.listPublishedKnowledgeEntries(matchedIds)
    ).filter((entry) => entry.candidate.family !== undefined)
    const mapped = importedEntries.filter((entry) =>
      REGISTERED_TECHNIQUE_FAMILIES.has(entry.candidate.family as VulnerabilityFamily)
    )
    const unmapped: UnmappedIntelligence[] = importedEntries
      .filter(
        (entry) =>
          !REGISTERED_TECHNIQUE_FAMILIES.has(entry.candidate.family as VulnerabilityFamily)
      )
      .map((entry) => ({
        chunkId: entry.chunkId,
        family: entry.candidate.family,
        reason: 'unregistered-technique' as const
      }))
    const builtIn = matchedIds
      .map((entryId) => entryById.get(entryId))
      .filter((entry): entry is (typeof V1_KNOWLEDGE_ENTRIES)[number] => Boolean(entry))
    const coordinatorOutput: KnowledgeAgentOutput = {
      matchedEntryIds: [
        ...builtIn.map((entry) => entry.id),
        ...mapped.map((entry) => entry.chunkId)
      ],
      guidance: [
        ...builtIn.map((entry) => ({
          family: entry.family,
          applicability: entry.applicability,
          safeProbePrinciples: entry.safeProbePrinciples,
          confirmationRules: entry.confirmationRules,
          falsePositivePatterns: entry.falsePositivePatterns,
          remediationHints: entry.remediationHints
        })),
        ...mapped.map((entry) => ({
          family: entry.candidate.family!,
          applicability: [
            ...entry.candidate.affectedVersions,
            ...entry.candidate.preconditions
          ],
          safeProbePrinciples: [
            '导入请求模板仅用于形成假设，执行前必须重新经过 SecurityPolicy。',
            '不得直接执行原始 PoC，必须使用低影响、带负对照的验证动作。'
          ],
          confirmationRules: entry.candidate.confirmationRules,
          falsePositivePatterns: [],
          remediationHints: entry.candidate.remediation
        }))
      ],
      sourceRefs: unique([
        ...builtIn.flatMap((entry) => entry.sourceRefs),
        ...mapped.map((entry) => entry.chunkId)
      ]),
      policyConstraints: unique([
        ...builtIn.flatMap((entry) => entry.forbiddenActions),
        ...mapped.flatMap((entry) => entry.candidate.forbiddenActions)
      ]),
      ...(builtIn.length === 0 && mapped.length === 0
        ? {
            sourceRefs: [],
            policyConstraints: [
              '知识检索未命中时不得扩大测试范围或生成未经规则审查的动作。'
            ]
          }
        : {})
    }
    return {
      ...baseline,
      coordinatorOutput,
      unmappedIntelligence: unmapped
    }
  }
}
