import {
  VulnerabilityTechniqueActivationViewSchema,
  type Environment,
  type QualificationRecord,
  type VulnerabilityTechniqueActivationView
} from '@agentgo/contracts'
import {
  DefinitionRegistry
} from '@agentgo/domain'
import {
  RegisteredOnlyActivationCatalog,
  type ActivationCatalogLookup,
  type VulnerabilityActivationCatalog
} from './vulnerability-execution-gate'
import {
  computeQualificationBuildHash,
  evaluateQualificationRecord
} from './qualification-record'

function activationKey(lookup: ActivationCatalogLookup): string {
  return [
    lookup.moduleId,
    lookup.moduleVersion,
    lookup.techniqueId,
    lookup.techniqueVersion
  ].join('\u0000')
}

/**
 * Production ActivationCatalog. It only consumes validated QualificationRecords
 * and a frozen DefinitionRegistry. It must not import fixture or benchmark code.
 */
export class RecordBackedActivationCatalog
  implements VulnerabilityActivationCatalog
{
  readonly #byKey: ReadonlyMap<string, VulnerabilityTechniqueActivationView>
  readonly #views: readonly VulnerabilityTechniqueActivationView[]
  readonly acceptedRecords: readonly QualificationRecord[]

  constructor(options: {
    registry: DefinitionRegistry
    records: readonly QualificationRecord[]
    policyCatalogHash: string
    now?: Date
  }) {
    if (!options.registry.frozen) {
      throw new Error('ActivationCatalog requires a frozen DefinitionRegistry.')
    }

    const expectedBuildHash = computeQualificationBuildHash({
      definitionSnapshotHash: options.registry.snapshot().snapshotHash,
      policyCatalogHash: options.policyCatalogHash
    })
    const registeredOnly = new RegisteredOnlyActivationCatalog(options.registry)
    const byKey = new Map<string, VulnerabilityTechniqueActivationView>()
    for (const view of registeredOnly.list()) {
      byKey.set(activationKey(view), view)
    }

    const accepted: QualificationRecord[] = []
    for (const record of options.records) {
      const validity = evaluateQualificationRecord({
        record,
        registry: options.registry,
        now: options.now,
        expectedBuildHash
      })
      if (validity !== 'valid') continue
      const key = activationKey(record)
      const current = byKey.get(key)
      if (!current) continue
      const mergedEnvironments = Object.freeze(
        [
          ...new Set([
            ...current.qualifiedEnvironments,
            ...record.qualifiedEnvironments
          ])
        ].sort() as Environment[]
      )
      byKey.set(
        key,
        VulnerabilityTechniqueActivationViewSchema.parse({
          moduleId: current.moduleId,
          moduleVersion: current.moduleVersion,
          familyId: current.familyId,
          techniqueId: current.techniqueId,
          techniqueVersion: current.techniqueVersion,
          activationStatus: 'qualified',
          qualifiedEnvironments: mergedEnvironments
        })
      )
      accepted.push(record)
    }

    this.acceptedRecords = Object.freeze(accepted)
    this.#byKey = byKey
    this.#views = Object.freeze(
      [...byKey.values()].sort((left, right) =>
        activationKey(left).localeCompare(activationKey(right))
      )
    )
    Object.freeze(this)
  }

  get(
    lookup: ActivationCatalogLookup
  ): VulnerabilityTechniqueActivationView | undefined {
    return this.#byKey.get(activationKey(lookup))
  }

  list(): readonly VulnerabilityTechniqueActivationView[] {
    return this.#views
  }
}
