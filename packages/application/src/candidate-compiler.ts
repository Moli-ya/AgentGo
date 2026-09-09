import { randomUUID } from 'node:crypto'
import {
  CandidateSchema,
  type Candidate,
  type CandidateCompilerDecision,
  type CandidateSeed,
  type Environment
} from '@agentgo/contracts'
import type { DefinitionRegistry } from '@agentgo/domain'
import { hasLegacyParityAdapter } from './legacy-parity-adapters'
import { IDOR_V2_TECHNIQUE_IDS } from './vulnerability-bundles'

export interface AgentCandidateSuggestion {
  readonly family: string
  readonly endpointId: string
  readonly parameterId: string
  readonly reason: string
}

export interface CandidateCompilerSurface {
  readonly endpointId: string
  readonly method: string
  readonly variantId?: string
  readonly variantIds?: readonly string[]
  readonly reviewStatus?: string
  readonly executionClass?: string
  readonly codec?: string
  readonly parameters?: readonly {
    readonly id: string
    readonly location: 'query' | 'path' | 'header' | 'cookie' | 'form' | 'json'
  }[]
}

export interface CandidateCompilerInput {
  readonly seeds: readonly CandidateSeed[]
  readonly suggestions: readonly AgentCandidateSuggestion[]
  readonly registry: DefinitionRegistry
  readonly surfaces: readonly CandidateCompilerSurface[]
  readonly environment: Environment
}

export interface CompiledCandidateRecord {
  readonly candidate: Candidate
  readonly decision: CandidateCompilerDecision
  readonly reason: string
  readonly waitFor?: 'input' | 'session' | 'approval'
}

function endpointIdOf(seed: CandidateSeed): string | undefined {
  return seed.subjectRefs.find((ref) => ref.kind === 'endpoint')?.id
}

function endpointRefCount(seed: CandidateSeed): number {
  return seed.subjectRefs.filter((ref) => ref.kind === 'endpoint').length
}

function suggestionKey(family: string, endpointId: string, parameterId: string): string {
  return `${family}\u0000${endpointId}\u0000${parameterId}`
}

/**
 * Selects strategy or returns inventory-only / awaiting-user / forbidden.
 * Agents do not choose risk level.
 */
export class CandidateCompiler {
  compile(input: CandidateCompilerInput): CompiledCandidateRecord[] {
    const suggestionByKey = new Map(
      input.suggestions.map((item) => [
        suggestionKey(item.family, item.endpointId, item.parameterId),
        item
      ])
    )
    const compiled = input.seeds.map((seed, index) =>
      this.compileSeed(seed, index, suggestionByKey, input)
    )
    const seedKeys = new Set(
      compiled.map((item) =>
        suggestionKey(
          item.candidate.familyId,
          endpointIdOf(item.candidate as unknown as CandidateSeed) ??
            item.candidate.subjectRefs.find((ref) => ref.kind === 'endpoint')?.id ??
            '',
          item.candidate.parameterId ?? ''
        )
      )
    )
    for (const suggestion of input.suggestions) {
      const key = suggestionKey(
        suggestion.family,
        suggestion.endpointId,
        suggestion.parameterId
      )
      if (seedKeys.has(key)) continue
      compiled.push(
        this.rejectUnknownSuggestion(suggestion, input.registry)
      )
    }
    return compiled.sort((left, right) => (left.candidate.rank ?? 0) - (right.candidate.rank ?? 0))
  }

  private compileSeed(
    seed: CandidateSeed,
    index: number,
    suggestions: ReadonlyMap<string, AgentCandidateSuggestion>,
    input: CandidateCompilerInput
  ): CompiledCandidateRecord {
    const endpointId = endpointIdOf(seed)
    const suggestion =
      endpointId && seed.parameterId
        ? suggestions.get(suggestionKey(seed.familyId, endpointId, seed.parameterId))
        : undefined
    const technique = input.registry.getTechnique(seed.techniqueId, seed.moduleVersion)
    const candidate = CandidateSchema.parse({
      candidateId: randomUUID(),
      familyId: seed.familyId,
      techniqueId: seed.techniqueId,
      moduleVersion: seed.moduleVersion,
      subjectRefs: seed.subjectRefs,
      variantRefs: seed.variantRefs,
      dependencyRefs: seed.dependencyRefs,
      identityRefs: seed.identityRefs,
      testObjectRefs: seed.testObjectRefs,
      matrixRefs: seed.matrixRefs,
      ...(seed.parameterId ? { parameterId: seed.parameterId } : {}),
      reason: suggestion?.reason ?? seed.reason,
      expectedSignal: seed.expectedSignal,
      suggestedStrategy: seed.suggestedStrategy,
      rank: index
    })
    if (!technique) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Technique is not present in the frozen DefinitionRegistry.'
      }
    }
    if (technique.familyId !== seed.familyId) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Candidate family does not match the frozen technique definition.'
      }
    }
    if (!technique.detectorRefs.some((ref) => ref.id === seed.detectorId)) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Candidate detector is not linked by the frozen technique definition.'
      }
    }
    if (!technique.strategyRefs.some((ref) => ref.id === seed.suggestedStrategy)) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Candidate strategy is not linked by the frozen technique definition.'
      }
    }
    if (!technique.allowedEnvironments.includes(input.environment)) {
      return {
        candidate,
        decision: 'forbidden',
        reason: 'Technique is not allowed in the current execution environment.'
      }
    }
    if (
      technique.declaredMode === 'forbidden'
    ) {
      return {
        candidate,
        decision: 'forbidden',
        reason: `Technique ${technique.techniqueId} is forbidden.`
      }
    }
    if (
      technique.declaredMode === 'inventory-only' ||
      technique.declaredMode === 'signal-only'
    ) {
      return {
        candidate,
        decision: 'inventory-only',
        reason: `Technique ${technique.techniqueId} is ${technique.declaredMode}.`
      }
    }
    if (endpointRefCount(seed) !== 1 || !endpointId) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Active candidates must bind exactly one frozen endpoint subject.'
      }
    }
    const surface = input.surfaces.find((item) => item.endpointId === endpointId)
    if (!surface) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Candidate subject is not in the frozen inventory surface.'
      }
    }
    const frozenVariantIds = new Set(
      [surface.variantId, ...(surface.variantIds ?? [])].filter(
        (variantId): variantId is string => Boolean(variantId)
      )
    )
    if (
      seed.variantRefs.length === 0 ||
      frozenVariantIds.size === 0 ||
      seed.variantRefs.some((variantId) => !frozenVariantIds.has(variantId))
    ) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Candidate request variants are not fully bound to the frozen inventory surface.'
      }
    }
    const parameter = seed.parameterId
      ? surface.parameters?.find((item) => item.id === seed.parameterId)
      : undefined
    if (seed.parameterId && !parameter) {
      return {
        candidate,
        decision: 'rejected',
        reason: 'Candidate parameter is not in the frozen inventory surface.'
      }
    }
    if (surface.reviewStatus !== 'reviewed') {
      return {
        candidate,
        decision: 'awaiting-user',
        waitFor: 'input',
        reason: 'Request variant is not reviewed.'
      }
    }
    if (technique.declaredMode === 'active-l2') {
      if (surface.executionClass !== 'active-l2') {
        return {
          candidate,
          decision: 'inventory-only',
          reason: 'Active L2 technique requires an active-l2 inventory variant.'
        }
      }
      return {
        candidate,
        decision: 'awaiting-user',
        waitFor: 'approval',
        reason: 'Active L2 techniques require a trusted approval record.'
      }
    }
    const parameterLocation = parameter?.location
    if (parameterLocation === 'header' || parameterLocation === 'cookie') {
      return {
        candidate,
        decision: 'inventory-only',
        reason: 'Header and cookie selectors remain inventory-only.'
      }
    }
    if (parameterLocation === 'form' || parameterLocation === 'json') {
      return {
        candidate,
        decision: 'awaiting-user',
        waitFor: 'approval',
        reason: 'Form and JSON Pointer selectors require an approved L2 test object.'
      }
    }
    if (surface.method.toUpperCase() !== 'GET') {
      return {
        candidate,
        decision: 'inventory-only',
        reason: 'Non-GET variants remain inventory-only unless they are approved form/JSON selectors.'
      }
    }
    if (surface.codec && surface.codec !== 'none') {
      return {
        candidate,
        decision: 'inventory-only',
        reason: 'Active execution today only uses reviewed none-codec GET query/path selectors.'
      }
    }
    if (surface.executionClass !== 'active-l1') {
      return {
        candidate,
        decision: 'inventory-only',
        reason: 'Active L1 execution requires an active-l1 inventory variant.'
      }
    }
    if (technique.declaredMode === 'active-l1' && !hasLegacyParityAdapter(technique.techniqueId)) {
      return {
        candidate,
        decision: 'forbidden',
        reason: 'No registered validation adapter exists for this technique.'
      }
    }
    if (
      seed.techniqueId === IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential &&
      seed.matrixRefs.length === 0
    ) {
      return {
        candidate,
        decision: 'awaiting-user',
        waitFor: 'input',
        reason: 'AuthorizationMatrix is required before BOLA read-differential execution.'
      }
    }
    return {
      candidate,
      decision: 'executable',
      reason: candidate.reason
    }
  }

  private rejectUnknownSuggestion(
    suggestion: AgentCandidateSuggestion,
    registry: DefinitionRegistry
  ): CompiledCandidateRecord {
    const familyKnown = registry.hasFamily(suggestion.family)
    const candidate = CandidateSchema.parse({
      candidateId: randomUUID(),
      familyId: suggestion.family,
      techniqueId: familyKnown ? `${suggestion.family}.unknown` : 'unknown.unknown',
      moduleVersion: '0.0.0',
      subjectRefs: [{ kind: 'endpoint', id: suggestion.endpointId }],
      variantRefs: [],
      dependencyRefs: [],
      identityRefs: [],
      testObjectRefs: [],
      matrixRefs: [],
      parameterId: suggestion.parameterId,
      reason: suggestion.reason,
      expectedSignal: 'unmapped-agent-suggestion',
      suggestedStrategy: 'none'
    })
    return {
      candidate,
      decision: 'rejected',
      reason: familyKnown
        ? 'Agent suggestion is not backed by a Detector seed.'
        : 'Agent suggested an unknown family or technique.'
    }
  }
}
