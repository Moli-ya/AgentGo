import {
  EnvironmentSchema,
  ScanModuleSnapshotDraftSchema,
  ScanModuleSnapshotRecordSchema,
  type Environment,
  type ScanModuleSnapshotDraft,
  type ScanModuleSnapshotRecord,
  type VersionedDefinitionRef,
  type VulnerabilityFamilyId
} from '@agentgo/contracts'
import {
  compareText,
  deepFreeze,
  stableInventoryHash
} from '@agentgo/domain'
import type { ExecutableLegacyV1Binding } from './vulnerability-execution-gate'
import type { Day2VulnerabilityPlatform } from './vulnerability-platform'

export type ScanModuleSnapshotErrorCode =
  | 'snapshot-set-unsealed'
  | 'snapshot-schema-invalid'
  | 'snapshot-hash-mismatch'
  | 'snapshot-duplicate-family'
  | 'snapshot-family-set-mismatch'
  | 'snapshot-legacy-environment'
  | 'snapshot-environment-mismatch'
  | 'snapshot-authorization-mismatch'
  | 'snapshot-definition-unavailable'
  | 'snapshot-definition-mismatch'
  | 'snapshot-capability-unavailable'
  | 'snapshot-capability-mismatch'

export class ScanModuleSnapshotError extends Error {
  readonly code: ScanModuleSnapshotErrorCode
  readonly familyId: string

  constructor(
    code: ScanModuleSnapshotErrorCode,
    familyId: string,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options)
    this.name = 'ScanModuleSnapshotError'
    this.code = code
    this.familyId = familyId
  }
}

type SnapshotPlatform = Pick<
  Day2VulnerabilityPlatform,
  | 'capabilityCatalog'
  | 'capabilitySnapshot'
  | 'definitionRegistry'
  | 'definitionSnapshot'
  | 'executionGate'
>

function fail(
  code: ScanModuleSnapshotErrorCode,
  familyId: string,
  message: string,
  options?: ErrorOptions
): never {
  throw new ScanModuleSnapshotError(code, familyId, message, options)
}

/** Execution must never observe a snapshot set that can still be appended to. */
export function requireSealedScanModuleSnapshotSet(sealed: boolean): void {
  if (!sealed) {
    fail(
      'snapshot-set-unsealed',
      '<scan-snapshot-set>',
      'The scan module snapshot set is not sealed.'
    )
  }
}

function compareRef(
  left: VersionedDefinitionRef,
  right: VersionedDefinitionRef
): number {
  return compareText(left.id, right.id) || compareText(left.version, right.version)
}

function sortRefs(
  refs: readonly VersionedDefinitionRef[]
): readonly VersionedDefinitionRef[] {
  return refs
    .map(({ id, version }) => ({ id, version }))
    .sort(compareRef)
}

function selectedDefinitionsValue(
  binding: ExecutableLegacyV1Binding,
  draft: {
    readonly strategyRefs: readonly VersionedDefinitionRef[]
    readonly confirmationRuleRefs: readonly VersionedDefinitionRef[]
    readonly evidenceProfileRefs: readonly VersionedDefinitionRef[]
    readonly remediationRefs: readonly VersionedDefinitionRef[]
  }
): unknown {
  return {
    familyId: binding.familyId,
    moduleId: binding.moduleId,
    moduleVersion: binding.moduleVersion,
    moduleDefinitionHash: binding.definitionHash,
    techniqueId: binding.techniqueId,
    techniqueVersion: binding.techniqueVersion,
    strategyRefs: draft.strategyRefs,
    confirmationRuleRefs: draft.confirmationRuleRefs,
    evidenceProfileRefs: draft.evidenceProfileRefs,
    remediationRefs: draft.remediationRefs
  }
}

function selectedCapabilitiesValue(
  descriptors: ScanModuleSnapshotDraft['capabilityDescriptors']
): unknown {
  return { descriptors }
}

function toDraft(record: ScanModuleSnapshotRecord): ScanModuleSnapshotDraft {
  return ScanModuleSnapshotDraftSchema.parse({
    familyId: record.familyId,
    moduleId: record.moduleId,
    moduleVersion: record.moduleVersion,
    definitionHash: record.definitionHash,
    techniqueId: record.techniqueId,
    techniqueVersion: record.techniqueVersion,
    strategyRefs: record.strategyRefs,
    confirmationRuleRefs: record.confirmationRuleRefs,
    evidenceProfileRefs: record.evidenceProfileRefs,
    remediationRefs: record.remediationRefs,
    requiredCapabilityIds: record.requiredCapabilityIds,
    capabilityDescriptors: record.capabilityDescriptors,
    capabilitySnapshotHash: record.capabilitySnapshotHash,
    selectedCapabilitiesHash: record.selectedCapabilitiesHash,
    selectedDefinitionsHash: record.selectedDefinitionsHash,
    registrySnapshotHash: record.registrySnapshotHash,
    environment: record.environment,
    authorization: record.authorization
  })
}

/** Hashes exactly the persisted draft contract, excluding record metadata. */
export function computeScanModuleSnapshotHash(
  draft: ScanModuleSnapshotDraft
): string {
  return stableInventoryHash(ScanModuleSnapshotDraftSchema.parse(draft))
}

function buildDraftForBinding(
  binding: ExecutableLegacyV1Binding,
  platform: SnapshotPlatform
): ScanModuleSnapshotDraft {
  const registered = platform.definitionRegistry.getBundle(
    binding.moduleId,
    binding.moduleVersion
  )
  const technique = registered?.bundle.manifest.techniques.find(
    (candidate) =>
      candidate.techniqueId === binding.techniqueId &&
      candidate.version === binding.techniqueVersion
  )
  if (
    !registered ||
    !technique ||
    registered.definitionHash !== binding.definitionHash ||
    technique.familyId !== binding.familyId
  ) {
    fail(
      'snapshot-definition-unavailable',
      binding.familyId,
      `The exact frozen module definition is unavailable for ${binding.familyId}.`
    )
  }

  const strategyRefs = sortRefs(technique.strategyRefs)
  const confirmationRuleRefs = sortRefs(technique.confirmationRuleRefs)
  const evidenceProfileRefs = sortRefs(technique.evidenceProfileRefs)
  const remediationRefs = sortRefs(technique.remediationRefs)
  const requiredCapabilityIds = [...technique.requiredCapabilityIds].sort(
    compareText
  )
  const capabilityDescriptors = requiredCapabilityIds.map((id) => {
    const descriptor = platform.capabilityCatalog.get(id)
    if (!descriptor) {
      fail(
        'snapshot-capability-unavailable',
        binding.familyId,
        `Required capability ${id} is unavailable for ${binding.familyId}.`
      )
    }
    return {
      id: descriptor.id,
      riskFloor: descriptor.riskFloor,
      descriptorHash: stableInventoryHash({
        description: descriptor.description,
        id: descriptor.id,
        riskFloor: descriptor.riskFloor
      })
    }
  })

  const selectedDefinitions = {
    strategyRefs,
    confirmationRuleRefs,
    evidenceProfileRefs,
    remediationRefs
  }
  const draft = ScanModuleSnapshotDraftSchema.parse({
    familyId: binding.familyId,
    moduleId: binding.moduleId,
    moduleVersion: binding.moduleVersion,
    definitionHash: binding.definitionHash,
    techniqueId: binding.techniqueId,
    techniqueVersion: binding.techniqueVersion,
    ...selectedDefinitions,
    requiredCapabilityIds,
    capabilityDescriptors,
    capabilitySnapshotHash: platform.capabilitySnapshot.snapshotHash,
    selectedCapabilitiesHash: stableInventoryHash(
      selectedCapabilitiesValue(capabilityDescriptors)
    ),
    selectedDefinitionsHash: stableInventoryHash(
      selectedDefinitionsValue(binding, selectedDefinitions)
    ),
    registrySnapshotHash: platform.definitionSnapshot.snapshotHash,
    environment: binding.environment,
    authorization: binding.authorization
  })
  return deepFreeze(draft) as ScanModuleSnapshotDraft
}

function requireUniqueFamilies(
  familyIds: readonly VulnerabilityFamilyId[],
  code: ScanModuleSnapshotErrorCode
): void {
  const seen = new Set<string>()
  for (const familyId of familyIds) {
    if (seen.has(familyId)) {
      fail(code, familyId, `Duplicate scan module snapshot family: ${familyId}.`)
    }
    seen.add(familyId)
  }
}

/** Builds one immutable, deterministically ordered module snapshot per family. */
export function buildScanModuleSnapshotDrafts(
  familyIds: readonly VulnerabilityFamilyId[],
  environment: Environment,
  platform: SnapshotPlatform
): readonly ScanModuleSnapshotDraft[] {
  requireUniqueFamilies(familyIds, 'snapshot-duplicate-family')
  const parsedEnvironment = EnvironmentSchema.parse(environment)
  const bindings = platform.executionGate
    .requireExecutableFamilies(familyIds, parsedEnvironment)
    .slice()
    .sort((left, right) => compareText(left.familyId, right.familyId))
  const drafts = bindings.map((binding) =>
    buildDraftForBinding(binding, platform)
  )
  return deepFreeze(drafts) as readonly ScanModuleSnapshotDraft[]
}

function sameValue(left: unknown, right: unknown): boolean {
  return stableInventoryHash(left) === stableInventoryHash(right)
}

function expectedBindings(
  familyIds: readonly VulnerabilityFamilyId[],
  environment: Environment,
  platform: SnapshotPlatform
): readonly ExecutableLegacyV1Binding[] {
  try {
    return platform.executionGate.requireExecutableFamilies(
      familyIds,
      environment
    )
  } catch (cause) {
    fail(
      'snapshot-definition-unavailable',
      '<scan-families>',
      'One or more exact historical scan module definitions are unavailable.',
      { cause }
    )
  }
}

/**
 * Verifies resume compatibility against selected definitions and capabilities.
 * Global Registry/catalog hashes remain audit facts and may drift when an
 * unrelated bundle or capability is added after the scan was created.
 */
export function verifyScanModuleSnapshots(
  inputs: readonly ScanModuleSnapshotRecord[],
  familyIds: readonly VulnerabilityFamilyId[],
  environment: Environment,
  platform: SnapshotPlatform
): void {
  const parsedEnvironment = EnvironmentSchema.parse(environment)
  requireUniqueFamilies(familyIds, 'snapshot-duplicate-family')

  const records = inputs.map((input) => {
    const result = ScanModuleSnapshotRecordSchema.safeParse(input)
    if (!result.success) {
      fail(
        'snapshot-schema-invalid',
        typeof input?.familyId === 'string' ? input.familyId : '<unknown>',
        'A persisted scan module snapshot does not match its strict contract.',
        { cause: result.error }
      )
    }
    return result.data
  })
  requireUniqueFamilies(
    records.map(({ familyId }) => familyId),
    'snapshot-duplicate-family'
  )

  const expectedFamilyIds = [...familyIds].sort(compareText)
  const actualFamilyIds = records
    .map(({ familyId }) => familyId)
    .sort(compareText)
  if (!sameValue(actualFamilyIds, expectedFamilyIds)) {
    fail(
      'snapshot-family-set-mismatch',
      '<scan-families>',
      'Persisted module snapshots do not exactly match the scan family set.'
    )
  }

  const bindings = expectedBindings(
    expectedFamilyIds,
    parsedEnvironment,
    platform
  )
  const bindingByFamily = new Map<string, ExecutableLegacyV1Binding>(
    bindings.map((binding) => [binding.familyId, binding] as const)
  )

  for (const record of records) {
    const draft = toDraft(record)
    if (computeScanModuleSnapshotHash(draft) !== record.snapshotHash) {
      fail(
        'snapshot-hash-mismatch',
        record.familyId,
        `Persisted module snapshot hash mismatch for ${record.familyId}.`
      )
    }
    if (record.environment === 'legacy-unknown') {
      fail(
        'snapshot-legacy-environment',
        record.familyId,
        `Legacy scan ${record.scanId} has no verified execution environment.`
      )
    }
    if (record.environment !== parsedEnvironment) {
      fail(
        'snapshot-environment-mismatch',
        record.familyId,
        `Snapshot environment does not match the scan for ${record.familyId}.`
      )
    }

    const binding = bindingByFamily.get(record.familyId)
    if (!binding) {
      fail(
        'snapshot-family-set-mismatch',
        record.familyId,
        `No executable binding exists for snapshot family ${record.familyId}.`
      )
    }
    if (record.authorization !== binding.authorization) {
      fail(
        'snapshot-authorization-mismatch',
        record.familyId,
        `Snapshot authorization no longer matches ${record.familyId}.`
      )
    }

    const current = buildDraftForBinding(binding, platform)
    const definitionFields = {
      familyId: record.familyId,
      moduleId: record.moduleId,
      moduleVersion: record.moduleVersion,
      definitionHash: record.definitionHash,
      techniqueId: record.techniqueId,
      techniqueVersion: record.techniqueVersion,
      strategyRefs: record.strategyRefs,
      confirmationRuleRefs: record.confirmationRuleRefs,
      evidenceProfileRefs: record.evidenceProfileRefs,
      remediationRefs: record.remediationRefs,
      selectedDefinitionsHash: record.selectedDefinitionsHash
    }
    const currentDefinitionFields = {
      familyId: current.familyId,
      moduleId: current.moduleId,
      moduleVersion: current.moduleVersion,
      definitionHash: current.definitionHash,
      techniqueId: current.techniqueId,
      techniqueVersion: current.techniqueVersion,
      strategyRefs: current.strategyRefs,
      confirmationRuleRefs: current.confirmationRuleRefs,
      evidenceProfileRefs: current.evidenceProfileRefs,
      remediationRefs: current.remediationRefs,
      selectedDefinitionsHash: current.selectedDefinitionsHash
    }
    if (!sameValue(definitionFields, currentDefinitionFields)) {
      fail(
        'snapshot-definition-mismatch',
        record.familyId,
        `Selected module definitions changed or are unavailable for ${record.familyId}.`
      )
    }

    const capabilityFields = {
      requiredCapabilityIds: record.requiredCapabilityIds,
      capabilityDescriptors: record.capabilityDescriptors,
      selectedCapabilitiesHash: record.selectedCapabilitiesHash
    }
    const currentCapabilityFields = {
      requiredCapabilityIds: current.requiredCapabilityIds,
      capabilityDescriptors: current.capabilityDescriptors,
      selectedCapabilitiesHash: current.selectedCapabilitiesHash
    }
    if (!sameValue(capabilityFields, currentCapabilityFields)) {
      fail(
        'snapshot-capability-mismatch',
        record.familyId,
        `Selected capability semantics changed or are unavailable for ${record.familyId}.`
      )
    }
  }
}
