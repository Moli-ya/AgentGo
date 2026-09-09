import { randomUUID } from 'node:crypto'
import {
  ExtractionRuleDraftSchema,
  ExtractionRuleSchema,
  type ExtractionRule,
  type ExtractionRuleDraft
} from '@agentgo/contracts'
import { AgentGoRepository, ImportDiscoveryRepository } from '@agentgo/db'
import { stableInventoryHash } from '@agentgo/domain'

const CATASTROPHIC_REGEX = new RegExp(
  String.raw`(\([^()]*[+*][^()]*\)[+*])|(\([^()]*[+*][^()]*\)\{)|((?:[+*?]|\{\d+,){2,})`,
  'u'
)

export class ExtractionRuleService {
  constructor(
    private readonly repository: AgentGoRepository,
    private readonly discoveryRepository: ImportDiscoveryRepository
  ) {}

  async createDraft(input: unknown): Promise<ExtractionRule> {
    const draft = ExtractionRuleDraftSchema.parse(input)
    assertSafeDraft(draft)
    const scan = await this.repository.getScan(draft.scanId)
    if (!scan) throw new Error('Scan does not exist.')
    const createdAt = new Date().toISOString()
    const unsigned = {
      ...draft,
      ruleId: randomUUID(),
      reviewStatus: 'unreviewed' as const,
      frozen: false,
      createdAt
    }
    const rule = ExtractionRuleSchema.parse({
      ...unsigned,
      ruleHash: stableInventoryHash(unsigned)
    })
    return this.discoveryRepository.saveExtractionRule(rule)
  }

  async review(input: {
    readonly ruleId: string
    readonly reviewStatus: 'reviewed' | 'rejected'
    readonly reviewedBy: string
  }): Promise<ExtractionRule> {
    const current = await this.discoveryRepository.getExtractionRule(input.ruleId)
    if (!current) throw new Error('Extraction rule does not exist.')
    if (current.frozen) throw new Error('Frozen extraction rules cannot be re-reviewed.')
    const reviewedAt = new Date().toISOString()
    const unsigned = {
      scanId: current.scanId,
      name: current.name,
      sourceKind: current.sourceKind,
      sourceSelector: current.sourceSelector,
      valueType: current.valueType,
      secretClassification: current.secretClassification,
      targetVariable: current.targetVariable,
      ...(current.identityScope ? { identityScope: current.identityScope } : {}),
      ...(current.tenantScope ? { tenantScope: current.tenantScope } : {}),
      sourceRef: current.sourceRef,
      version: current.version,
      ruleId: current.ruleId,
      reviewStatus: input.reviewStatus,
      frozen: false,
      createdAt: current.createdAt,
      reviewedBy: input.reviewedBy,
      reviewedAt
    }
    const updated = ExtractionRuleSchema.parse({
      ...unsigned,
      ruleHash: stableInventoryHash(unsigned)
    })
    return this.discoveryRepository.updateExtractionRule(updated)
  }

  async freeze(input: { readonly ruleId: string; readonly ruleHash: string }): Promise<ExtractionRule> {
    const current = await this.discoveryRepository.getExtractionRule(input.ruleId)
    if (!current) throw new Error('Extraction rule does not exist.')
    if (current.frozen) {
      if (current.ruleHash !== input.ruleHash) {
        throw new Error('Frozen extraction rule hash mismatch.')
      }
      return current
    }
    if (current.ruleHash !== input.ruleHash) {
      throw new Error('Extraction rule hash mismatch.')
    }
    if (current.reviewStatus !== 'reviewed') {
      throw new Error('Unreviewed extraction rules cannot be frozen.')
    }
    assertSafeDraft(current)
    if (current.secretClassification === 'likely-secret') {
      throw new Error('Likely-secret extraction rules cannot be frozen as raw values.')
    }
    const unsigned = {
      scanId: current.scanId,
      name: current.name,
      sourceKind: current.sourceKind,
      sourceSelector: current.sourceSelector,
      valueType: current.valueType,
      secretClassification: current.secretClassification,
      targetVariable: current.targetVariable,
      ...(current.identityScope ? { identityScope: current.identityScope } : {}),
      ...(current.tenantScope ? { tenantScope: current.tenantScope } : {}),
      sourceRef: current.sourceRef,
      version: current.version,
      ruleId: current.ruleId,
      reviewStatus: current.reviewStatus,
      frozen: true,
      createdAt: current.createdAt,
      reviewedBy: current.reviewedBy,
      reviewedAt: current.reviewedAt
    }
    const frozen = ExtractionRuleSchema.parse({
      ...unsigned,
      ruleHash: stableInventoryHash(unsigned)
    })
    return this.discoveryRepository.updateExtractionRule(frozen)
  }
}

export function assertSafeDraft(draft: ExtractionRuleDraft): void {
  if (draft.sourceKind === 'regex-capture') {
    if (CATASTROPHIC_REGEX.test(draft.sourceSelector) || draft.sourceSelector.length > 256) {
      throw new Error('Catastrophic or oversized regex cannot be frozen.')
    }
    try {
      void new RegExp(draft.sourceSelector, 'u')
    } catch {
      throw new Error('Extraction regex is invalid.')
    }
  }
  if (draft.sourceKind === 'html-selector' && /<script|javascript:/iu.test(draft.sourceSelector)) {
    throw new Error('Illegal HTML selector.')
  }
  if (draft.sourceKind === 'json-pointer' && draft.sourceSelector !== '' && !draft.sourceSelector.startsWith('/')) {
    throw new Error('JSON Pointer selector must be empty or start with /.')
  }
}
