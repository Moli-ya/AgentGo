import {
  VulnerabilityModuleBundleSchema,
  type ConfirmationRuleDefinition,
  type DetectorDefinition,
  type EvidenceProfileDefinition,
  type ProbeStrategyDefinition,
  type RemediationDefinition,
  type SignalKindDefinition,
  type VersionedDefinitionRef,
  type VulnerabilityFamilyManifest,
  type VulnerabilityModuleBundle,
  type VulnerabilityTechniqueManifest
} from '@agentgo/contracts'

import {
  canonicalJson,
  compareText,
  deepFreeze,
  sha256Text,
  type DeepReadonly
} from './canonical'

export type DefinitionRegistryCapabilityRiskFloor = 'l0' | 'l1' | 'l2'

export interface DefinitionRegistryCapabilityDescriptor {
  readonly riskFloor: DefinitionRegistryCapabilityRiskFloor
}

export interface DefinitionRegistryCapabilityCatalogPort {
  get(
    capabilityId: string
  ): DefinitionRegistryCapabilityDescriptor | undefined
}

export type DefinitionRegistryErrorCode =
  | 'invalid-bundle'
  | 'registry-frozen'
  | 'registry-not-frozen'
  | 'duplicate-identity'
  | 'duplicate-value'
  | 'family-description-conflict'
  | 'dangling-reference'
  | 'reference-mismatch'
  | 'unknown-capability'
  | 'invalid-mode-combination'
  | 'unreferenced-definition'

export class DefinitionRegistryError extends Error {
  readonly code: DefinitionRegistryErrorCode

  constructor(code: DefinitionRegistryErrorCode, message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'DefinitionRegistryError'
    this.code = code
  }
}

export interface RegisteredVulnerabilityBundle {
  readonly bundle: DeepReadonly<VulnerabilityModuleBundle>
  readonly canonicalBundleJson: string
  readonly definitionHash: string
}

export interface DefinitionRegistrySnapshot {
  readonly bundles: readonly RegisteredVulnerabilityBundle[]
  readonly canonicalSnapshotJson: string
  readonly snapshotHash: string
}

type ReadonlyFamily = DeepReadonly<VulnerabilityFamilyManifest>
type ReadonlyTechnique = DeepReadonly<VulnerabilityTechniqueManifest>
type ReadonlyDetector = DeepReadonly<DetectorDefinition>
type ReadonlySignalKind = DeepReadonly<SignalKindDefinition>
type ReadonlyStrategy = DeepReadonly<ProbeStrategyDefinition>
type ReadonlyConfirmationRule = DeepReadonly<ConfirmationRuleDefinition>
type ReadonlyEvidenceProfile = DeepReadonly<EvidenceProfileDefinition>
type ReadonlyRemediation = DeepReadonly<RemediationDefinition>

interface DefinitionMaps {
  detectors: Map<string, ReadonlyDetector>
  signalKinds: Map<string, ReadonlySignalKind>
  strategies: Map<string, ReadonlyStrategy>
  confirmationRules: Map<string, ReadonlyConfirmationRule>
  evidenceProfiles: Map<string, ReadonlyEvidenceProfile>
  remediations: Map<string, ReadonlyRemediation>
}

interface ReferencedDefinitionKeys {
  detectors: Set<string>
  signalKinds: Set<string>
  strategies: Set<string>
  confirmationRules: Set<string>
  evidenceProfiles: Set<string>
  remediations: Set<string>
}

function registryError(
  code: DefinitionRegistryErrorCode,
  message: string,
  options?: ErrorOptions
): never {
  throw new DefinitionRegistryError(code, message, options)
}

function versionedKey(id: string, version: string): string {
  return `${id}\u0000${version}`
}

function refKey(ref: VersionedDefinitionRef): string {
  return versionedKey(ref.id, ref.version)
}

function compareVersioned(
  left: { id: string; version: string },
  right: { id: string; version: string }
): number {
  return compareText(left.id, right.id) || compareText(left.version, right.version)
}

function compareByIdentity<T>(
  id: (value: T) => string,
  version: (value: T) => string
): (left: T, right: T) => number {
  return (left, right) =>
    compareText(id(left), id(right)) || compareText(version(left), version(right))
}

function assertUnique<T>(
  values: readonly T[],
  identity: (value: T) => string,
  path: string,
  code: DefinitionRegistryErrorCode = 'duplicate-value'
): void {
  const seen = new Set<string>()
  for (const value of values) {
    const key = identity(value)
    if (seen.has(key)) registryError(code, `${path} contains duplicate value ${JSON.stringify(key)}.`)
    seen.add(key)
  }
}

function sortedStrings<T extends string>(values: readonly T[], path: string): T[] {
  assertUnique(values, (value) => value, path)
  return [...values].sort(compareText)
}

function sortedObjects<T>(values: readonly T[], path: string): T[] {
  assertUnique(values, canonicalJson, path)
  return [...values].sort((left, right) => compareText(canonicalJson(left), canonicalJson(right)))
}

function sortedRefs(values: readonly VersionedDefinitionRef[], path: string): VersionedDefinitionRef[] {
  assertUnique(values, refKey, path)
  return values.map((ref) => ({ ...ref })).sort(compareVersioned)
}

function normalizeFamily(family: VulnerabilityFamilyManifest): VulnerabilityFamilyManifest {
  return {
    ...family,
    cweIds: sortedStrings(family.cweIds, 'manifest.family.cweIds'),
    wstgRefs: sortedStrings(family.wstgRefs, 'manifest.family.wstgRefs'),
    asvsRefs: sortedStrings(family.asvsRefs, 'manifest.family.asvsRefs'),
    apiSecurityRefs: sortedStrings(
      family.apiSecurityRefs,
      'manifest.family.apiSecurityRefs'
    )
  }
}

function normalizeTechnique(
  technique: VulnerabilityTechniqueManifest,
  index: number
): VulnerabilityTechniqueManifest {
  const path = `manifest.techniques[${index}]`
  return {
    ...technique,
    supportedSubjectKinds: sortedStrings(
      technique.supportedSubjectKinds,
      `${path}.supportedSubjectKinds`
    ),
    protocols: sortedObjects(technique.protocols, `${path}.protocols`),
    selectors: sortedObjects(technique.selectors, `${path}.selectors`),
    requiredCapabilityIds: sortedStrings(
      technique.requiredCapabilityIds,
      `${path}.requiredCapabilityIds`
    ),
    allowedEnvironments: sortedStrings(
      technique.allowedEnvironments,
      `${path}.allowedEnvironments`
    ),
    detectorRefs: sortedRefs(technique.detectorRefs, `${path}.detectorRefs`),
    strategyRefs: sortedRefs(technique.strategyRefs, `${path}.strategyRefs`),
    confirmationRuleRefs: sortedRefs(
      technique.confirmationRuleRefs,
      `${path}.confirmationRuleRefs`
    ),
    evidenceProfileRefs: sortedRefs(
      technique.evidenceProfileRefs,
      `${path}.evidenceProfileRefs`
    ),
    remediationRefs: sortedRefs(technique.remediationRefs, `${path}.remediationRefs`),
    ...(technique.expectedSuiteRef
      ? { expectedSuiteRef: { ...technique.expectedSuiteRef } }
      : {})
  }
}

function normalizeBundle(bundle: VulnerabilityModuleBundle): VulnerabilityModuleBundle {
  const techniques = bundle.manifest.techniques.map(normalizeTechnique)
  assertUnique(
    techniques,
    (technique) => versionedKey(technique.techniqueId, technique.version),
    'manifest.techniques',
    'duplicate-identity'
  )

  const detectors = bundle.detectors.map((definition, index) => ({
    ...definition,
    candidateBasis: sortedStrings(
      definition.candidateBasis,
      `detectors[${index}].candidateBasis`
    ),
    falsePositiveRisks: sortedStrings(
      definition.falsePositiveRisks,
      `detectors[${index}].falsePositiveRisks`
    )
  }))
  const signalKinds = bundle.signalKinds.map((definition, index) => ({
    ...definition,
    requiredAttributes: sortedStrings(
      definition.requiredAttributes,
      `signalKinds[${index}].requiredAttributes`
    )
  }))
  const strategies = bundle.strategies.map((definition, index) => ({
    ...definition,
    requiredCapabilityIds: sortedStrings(
      definition.requiredCapabilityIds,
      `strategies[${index}].requiredCapabilityIds`
    ),
    emittedSignalKindRefs: sortedRefs(
      definition.emittedSignalKindRefs,
      `strategies[${index}].emittedSignalKindRefs`
    )
  }))
  const confirmationRules = bundle.confirmationRules.map((definition, index) => ({
    ...definition,
    inputSignalKindRefs: sortedRefs(
      definition.inputSignalKindRefs,
      `confirmationRules[${index}].inputSignalKindRefs`
    ),
    requiredEvidenceRoles: sortedStrings(
      definition.requiredEvidenceRoles,
      `confirmationRules[${index}].requiredEvidenceRoles`
    )
  }))
  const evidenceProfiles = bundle.evidenceProfiles.map((definition, index) => {
    assertUnique(
      definition.roles,
      (role) => role.role,
      `evidenceProfiles[${index}].roles`
    )
    return {
      ...definition,
      roles: definition.roles
        .map((role) => ({ ...role }))
        .sort((left, right) => compareText(left.role, right.role)),
      forbiddenCaptureFields: sortedStrings(
        definition.forbiddenCaptureFields,
        `evidenceProfiles[${index}].forbiddenCaptureFields`
      )
    }
  })
  const remediations = bundle.remediations.map((definition, index) => ({
    ...definition,
    applicableTechniqueIds: sortedStrings(
      definition.applicableTechniqueIds,
      `remediations[${index}].applicableTechniqueIds`
    ),
    cweIds: sortedStrings(definition.cweIds, `remediations[${index}].cweIds`),
    wstgRefs: sortedStrings(definition.wstgRefs, `remediations[${index}].wstgRefs`),
    asvsRefs: sortedStrings(definition.asvsRefs, `remediations[${index}].asvsRefs`),
    apiSecurityRefs: sortedStrings(
      definition.apiSecurityRefs,
      `remediations[${index}].apiSecurityRefs`
    ),
    sourceRefs: sortedStrings(definition.sourceRefs, `remediations[${index}].sourceRefs`)
  }))

  assertUnique(
    detectors,
    (definition) => versionedKey(definition.detectorId, definition.version),
    'detectors',
    'duplicate-identity'
  )
  assertUnique(
    signalKinds,
    (definition) => versionedKey(definition.signalKindId, definition.version),
    'signalKinds',
    'duplicate-identity'
  )
  assertUnique(
    strategies,
    (definition) => versionedKey(definition.strategyId, definition.version),
    'strategies',
    'duplicate-identity'
  )
  assertUnique(
    confirmationRules,
    (definition) => versionedKey(definition.confirmationRuleId, definition.version),
    'confirmationRules',
    'duplicate-identity'
  )
  assertUnique(
    evidenceProfiles,
    (definition) => versionedKey(definition.evidenceProfileId, definition.version),
    'evidenceProfiles',
    'duplicate-identity'
  )
  assertUnique(
    remediations,
    (definition) => versionedKey(definition.remediationId, definition.version),
    'remediations',
    'duplicate-identity'
  )

  return {
    manifest: {
      ...bundle.manifest,
      family: normalizeFamily(bundle.manifest.family),
      techniques: techniques.sort(
        compareByIdentity(
          (technique) => technique.techniqueId,
          (technique) => technique.version
        )
      ),
      sourceRefs: sortedStrings(bundle.manifest.sourceRefs, 'manifest.sourceRefs')
    },
    detectors: detectors.sort(
      compareByIdentity(
        (definition) => definition.detectorId,
        (definition) => definition.version
      )
    ),
    signalKinds: signalKinds.sort(
      compareByIdentity(
        (definition) => definition.signalKindId,
        (definition) => definition.version
      )
    ),
    strategies: strategies.sort(
      compareByIdentity(
        (definition) => definition.strategyId,
        (definition) => definition.version
      )
    ),
    confirmationRules: confirmationRules.sort(
      compareByIdentity(
        (definition) => definition.confirmationRuleId,
        (definition) => definition.version
      )
    ),
    evidenceProfiles: evidenceProfiles.sort(
      compareByIdentity(
        (definition) => definition.evidenceProfileId,
        (definition) => definition.version
      )
    ),
    remediations: remediations.sort(
      compareByIdentity(
        (definition) => definition.remediationId,
        (definition) => definition.version
      )
    )
  }
}

function newDefinitionMaps(bundle: VulnerabilityModuleBundle): DefinitionMaps {
  return {
    detectors: new Map(
      bundle.detectors.map((definition) => [
        versionedKey(definition.detectorId, definition.version),
        definition
      ])
    ),
    signalKinds: new Map(
      bundle.signalKinds.map((definition) => [
        versionedKey(definition.signalKindId, definition.version),
        definition
      ])
    ),
    strategies: new Map(
      bundle.strategies.map((definition) => [
        versionedKey(definition.strategyId, definition.version),
        definition
      ])
    ),
    confirmationRules: new Map(
      bundle.confirmationRules.map((definition) => [
        versionedKey(definition.confirmationRuleId, definition.version),
        definition
      ])
    ),
    evidenceProfiles: new Map(
      bundle.evidenceProfiles.map((definition) => [
        versionedKey(definition.evidenceProfileId, definition.version),
        definition
      ])
    ),
    remediations: new Map(
      bundle.remediations.map((definition) => [
        versionedKey(definition.remediationId, definition.version),
        definition
      ])
    )
  }
}

function emptyReferencedKeys(): ReferencedDefinitionKeys {
  return {
    detectors: new Set(),
    signalKinds: new Set(),
    strategies: new Set(),
    confirmationRules: new Set(),
    evidenceProfiles: new Set(),
    remediations: new Set()
  }
}

function resolveDefinition<T>(
  ref: VersionedDefinitionRef,
  local: ReadonlyMap<string, T>,
  registered: ReadonlyMap<string, T>,
  kind: string,
  technique: VulnerabilityTechniqueManifest
): T {
  const definition = local.get(refKey(ref)) ?? registered.get(refKey(ref))
  if (!definition) {
    registryError(
      'dangling-reference',
      `Technique ${technique.techniqueId}@${technique.version} references missing ${kind} ${ref.id}@${ref.version}.`
    )
  }
  return definition
}

function assertDefinitionOwner(
  definition: { familyId: string; techniqueId: string },
  kind: string,
  identity: string,
  technique: VulnerabilityTechniqueManifest
): void {
  if (
    definition.familyId !== technique.familyId ||
    definition.techniqueId !== technique.techniqueId
  ) {
    registryError(
      'reference-mismatch',
      `${kind} ${identity} belongs to ${definition.familyId}/${definition.techniqueId}, not ${technique.familyId}/${technique.techniqueId}.`
    )
  }
}

function assertNonEmptyTechniqueSurface(technique: VulnerabilityTechniqueManifest): void {
  const requiredArrays: ReadonlyArray<readonly [string, readonly unknown[]]> = [
    ['supportedSubjectKinds', technique.supportedSubjectKinds],
    ['protocols', technique.protocols],
    ['selectors', technique.selectors],
    ['allowedEnvironments', technique.allowedEnvironments],
    ['detectorRefs', technique.detectorRefs],
    ['strategyRefs', technique.strategyRefs],
    ['confirmationRuleRefs', technique.confirmationRuleRefs],
    ['evidenceProfileRefs', technique.evidenceProfileRefs],
    ['remediationRefs', technique.remediationRefs]
  ]
  for (const [field, values] of requiredArrays) {
    if (values.length === 0) {
      registryError(
        'invalid-mode-combination',
        `${technique.declaredMode} technique ${technique.techniqueId}@${technique.version} must declare ${field}.`
      )
    }
  }
}

function l2Flags(strategy: ReadonlyStrategy): readonly boolean[] {
  return [
    strategy.requiresTestObject,
    strategy.requiresSideEffectEnvelope,
    strategy.requiresCleanup,
    strategy.requiresCleanupVerification
  ]
}

const capabilityRiskRank: Record<
  DefinitionRegistryCapabilityRiskFloor,
  number
> = {
  l0: 0,
  l1: 1,
  l2: 2
}

function declaredModeRiskCeiling(
  mode: VulnerabilityTechniqueManifest['declaredMode']
): DefinitionRegistryCapabilityRiskFloor {
  if (mode === 'inventory-only' || mode === 'forbidden') return 'l0'
  if (mode === 'active-l1') return 'l1'
  return 'l2'
}

function assertCapabilityRiskFloor(
  technique: VulnerabilityTechniqueManifest,
  capabilityId: string,
  descriptor: DefinitionRegistryCapabilityDescriptor
): void {
  const ceiling = declaredModeRiskCeiling(technique.declaredMode)
  if (capabilityRiskRank[descriptor.riskFloor] > capabilityRiskRank[ceiling]) {
    registryError(
      'invalid-mode-combination',
      `${technique.declaredMode} technique ${technique.techniqueId}@${technique.version} cannot require ${capabilityId} with SecurityPolicy risk floor ${descriptor.riskFloor}.`
    )
  }
}

function assertModeCombination(
  technique: VulnerabilityTechniqueManifest,
  strategies: readonly ReadonlyStrategy[],
  confirmationRules: readonly ReadonlyConfirmationRule[],
  evidenceProfiles: readonly ReadonlyEvidenceProfile[]
): void {
  if (technique.declaredMode === 'forbidden') {
    const forbiddenSurface: ReadonlyArray<readonly [string, readonly unknown[]]> = [
      ['supportedSubjectKinds', technique.supportedSubjectKinds],
      ['protocols', technique.protocols],
      ['selectors', technique.selectors],
      ['requiredCapabilityIds', technique.requiredCapabilityIds],
      ['allowedEnvironments', technique.allowedEnvironments]
    ]
    for (const [field, values] of forbiddenSurface) {
      if (values.length > 0) {
        registryError(
          'invalid-mode-combination',
          `Forbidden technique ${technique.techniqueId}@${technique.version} must not declare ${field}.`
        )
      }
    }
    if (technique.expectedSuiteRef) {
      registryError(
        'invalid-mode-combination',
        `Forbidden technique ${technique.techniqueId}@${technique.version} must not declare an expected suite.`
      )
    }
  } else {
    assertNonEmptyTechniqueSurface(technique)
  }

  const isActive =
    technique.declaredMode === 'active-l1' || technique.declaredMode === 'active-l2'
  if (isActive && !technique.expectedSuiteRef) {
    registryError(
      'invalid-mode-combination',
      `Active technique ${technique.techniqueId}@${technique.version} must declare expectedSuiteRef.`
    )
  }
  if (isActive && technique.allowedEnvironments.includes('offline')) {
    registryError(
      'invalid-mode-combination',
      `Active technique ${technique.techniqueId}@${technique.version} cannot run in the offline environment.`
    )
  }
  if (
    technique.declaredMode === 'fixture-only' &&
    (technique.allowedEnvironments.length !== 1 ||
      technique.allowedEnvironments[0] !== 'attested-fixture')
  ) {
    registryError(
      'invalid-mode-combination',
      `Fixture-only technique ${technique.techniqueId}@${technique.version} is limited to attested-fixture.`
    )
  }

  for (const strategy of strategies) {
    const flags = l2Flags(strategy)
    if (technique.declaredMode === 'active-l2') {
      if (!flags.every(Boolean)) {
        registryError(
          'invalid-mode-combination',
          `Active L2 strategy ${strategy.strategyId}@${strategy.version} must declare all L2 safety booleans.`
        )
      }
    } else if (technique.declaredMode === 'fixture-only') {
      const enabledCount = flags.filter(Boolean).length
      if (enabledCount !== 0 && enabledCount !== flags.length) {
        registryError(
          'invalid-mode-combination',
          `Fixture-only strategy ${strategy.strategyId}@${strategy.version} must declare either all or none of the L2 safety booleans.`
        )
      }
    } else if (flags.some(Boolean)) {
      registryError(
        'invalid-mode-combination',
        `${technique.declaredMode} strategy ${strategy.strategyId}@${strategy.version} must not declare L2 safety booleans.`
      )
    }
  }

  const availableRoles = new Set(
    evidenceProfiles.flatMap((profile) => profile.roles.map((role) => role.role))
  )
  for (const rule of confirmationRules) {
    for (const role of rule.requiredEvidenceRoles) {
      if (!availableRoles.has(role)) {
        registryError(
          'reference-mismatch',
          `Confirmation rule ${rule.confirmationRuleId}@${rule.version} requires evidence role ${role}, but no referenced evidence profile supplies it.`
        )
      }
    }
  }

  if (!isActive) return

  if (availableRoles.size === 0) {
    registryError(
      'invalid-mode-combination',
      `Active technique ${technique.techniqueId}@${technique.version} must define minimum evidence roles.`
    )
  }
  for (const rule of confirmationRules) {
    if (!rule.negativeControlRequired) {
      registryError(
        'invalid-mode-combination',
        `Active confirmation rule ${rule.confirmationRuleId}@${rule.version} must require a negative control.`
      )
    }
  }
}

function assertAllLocalDefinitionsReferenced(
  local: DefinitionMaps,
  referenced: ReferencedDefinitionKeys
): void {
  const collections: ReadonlyArray<
    readonly [keyof DefinitionMaps, ReadonlyMap<string, unknown>, ReadonlySet<string>]
  > = [
    ['detectors', local.detectors, referenced.detectors],
    ['signalKinds', local.signalKinds, referenced.signalKinds],
    ['strategies', local.strategies, referenced.strategies],
    ['confirmationRules', local.confirmationRules, referenced.confirmationRules],
    ['evidenceProfiles', local.evidenceProfiles, referenced.evidenceProfiles],
    ['remediations', local.remediations, referenced.remediations]
  ]
  for (const [kind, definitions, references] of collections) {
    for (const key of definitions.keys()) {
      if (!references.has(key)) {
        const [id = key, version = 'unknown'] = key.split('\u0000')
        registryError(
          'unreferenced-definition',
          `Bundle declares unreferenced ${kind} definition ${id}@${version}.`
        )
      }
    }
  }
}

function assertNoRegisteredCollision<T>(
  local: ReadonlyMap<string, T>,
  registered: ReadonlyMap<string, T>,
  kind: string
): void {
  for (const key of local.keys()) {
    if (registered.has(key)) {
      const [id = key, version = 'unknown'] = key.split('\u0000')
      registryError(
        'duplicate-identity',
        `${kind} ${id}@${version} is already registered.`
      )
    }
  }
}

export class DefinitionRegistry {
  readonly #capabilityCatalog: DefinitionRegistryCapabilityCatalogPort
  readonly #bundles = new Map<string, RegisteredVulnerabilityBundle>()
  readonly #families = new Map<string, ReadonlyFamily>()
  readonly #techniques = new Map<string, ReadonlyTechnique>()
  readonly #detectors = new Map<string, ReadonlyDetector>()
  readonly #signalKinds = new Map<string, ReadonlySignalKind>()
  readonly #strategies = new Map<string, ReadonlyStrategy>()
  readonly #confirmationRules = new Map<string, ReadonlyConfirmationRule>()
  readonly #evidenceProfiles = new Map<string, ReadonlyEvidenceProfile>()
  readonly #remediations = new Map<string, ReadonlyRemediation>()
  #snapshot: DefinitionRegistrySnapshot | undefined

  constructor(capabilityCatalog: DefinitionRegistryCapabilityCatalogPort) {
    if (!capabilityCatalog || typeof capabilityCatalog.get !== 'function') {
      throw new TypeError('DefinitionRegistry requires an injected capability catalog port.')
    }
    this.#capabilityCatalog = capabilityCatalog
  }

  get frozen(): boolean {
    return this.#snapshot !== undefined
  }

  registerBundle(input: unknown): RegisteredVulnerabilityBundle {
    if (this.frozen) {
      registryError('registry-frozen', 'Cannot register a bundle after the registry is frozen.')
    }

    const parsed = VulnerabilityModuleBundleSchema.safeParse(input)
    if (!parsed.success) {
      registryError('invalid-bundle', 'Vulnerability module bundle schema validation failed.', {
        cause: parsed.error
      })
    }

    const normalized = normalizeBundle(parsed.data)
    const moduleKey = versionedKey(
      normalized.manifest.moduleId,
      normalized.manifest.moduleVersion
    )
    if (this.#bundles.has(moduleKey)) {
      registryError(
        'duplicate-identity',
        `Module ${normalized.manifest.moduleId}@${normalized.manifest.moduleVersion} is already registered.`
      )
    }

    const existingFamily = this.#families.get(normalized.manifest.family.familyId)
    if (
      existingFamily &&
      canonicalJson(existingFamily) !== canonicalJson(normalized.manifest.family)
    ) {
      registryError(
        'family-description-conflict',
        `Family ${normalized.manifest.family.familyId} was registered with a conflicting descriptor.`
      )
    }

    for (const technique of normalized.manifest.techniques) {
      if (technique.familyId !== normalized.manifest.family.familyId) {
        registryError(
          'reference-mismatch',
          `Technique ${technique.techniqueId}@${technique.version} belongs to ${technique.familyId}, not manifest family ${normalized.manifest.family.familyId}.`
        )
      }
      const key = versionedKey(technique.techniqueId, technique.version)
      if (this.#techniques.has(key)) {
        registryError(
          'duplicate-identity',
          `Technique ${technique.techniqueId}@${technique.version} is already registered.`
        )
      }
    }

    const local = newDefinitionMaps(normalized)
    assertNoRegisteredCollision(local.detectors, this.#detectors, 'Detector')
    assertNoRegisteredCollision(local.signalKinds, this.#signalKinds, 'Signal kind')
    assertNoRegisteredCollision(local.strategies, this.#strategies, 'Strategy')
    assertNoRegisteredCollision(
      local.confirmationRules,
      this.#confirmationRules,
      'Confirmation rule'
    )
    assertNoRegisteredCollision(local.evidenceProfiles, this.#evidenceProfiles, 'Evidence profile')
    assertNoRegisteredCollision(local.remediations, this.#remediations, 'Remediation')

    for (const technique of normalized.manifest.techniques) {
      for (const capabilityId of technique.requiredCapabilityIds) {
        const capability = this.#capabilityCatalog.get(capabilityId)
        if (!capability) {
          registryError(
            'unknown-capability',
            `Technique ${technique.techniqueId}@${technique.version} requires unknown capability ${capabilityId}.`
          )
        }
        assertCapabilityRiskFloor(technique, capabilityId, capability)
      }
    }
    for (const strategy of normalized.strategies) {
      for (const capabilityId of strategy.requiredCapabilityIds) {
        if (!this.#capabilityCatalog.get(capabilityId)) {
          registryError(
            'unknown-capability',
            `Strategy ${strategy.strategyId}@${strategy.version} requires unknown capability ${capabilityId}.`
          )
        }
      }
    }

    const referenced = emptyReferencedKeys()
    for (const technique of normalized.manifest.techniques) {
      const detectors = technique.detectorRefs.map((ref) => {
        referenced.detectors.add(refKey(ref))
        const definition = resolveDefinition(
          ref,
          local.detectors,
          this.#detectors,
          'detector',
          technique
        )
        assertDefinitionOwner(
          definition,
          'Detector',
          `${definition.detectorId}@${definition.version}`,
          technique
        )
        return definition
      })
      const strategies = technique.strategyRefs.map((ref) => {
        referenced.strategies.add(refKey(ref))
        const definition = resolveDefinition(
          ref,
          local.strategies,
          this.#strategies,
          'strategy',
          technique
        )
        assertDefinitionOwner(
          definition,
          'Strategy',
          `${definition.strategyId}@${definition.version}`,
          technique
        )
        for (const capabilityId of definition.requiredCapabilityIds) {
          if (!technique.requiredCapabilityIds.includes(capabilityId)) {
            registryError(
              'reference-mismatch',
              `Technique ${technique.techniqueId}@${technique.version} does not declare capability ${capabilityId} required by strategy ${definition.strategyId}@${definition.version}.`
            )
          }
        }
        for (const signalRef of definition.emittedSignalKindRefs) {
          referenced.signalKinds.add(refKey(signalRef))
          resolveDefinition(
            signalRef,
            local.signalKinds,
            this.#signalKinds,
            'emitted signal kind',
            technique
          )
        }
        return definition
      })
      const confirmationRules = technique.confirmationRuleRefs.map((ref) => {
        referenced.confirmationRules.add(refKey(ref))
        const definition = resolveDefinition(
          ref,
          local.confirmationRules,
          this.#confirmationRules,
          'confirmation rule',
          technique
        )
        assertDefinitionOwner(
          definition,
          'Confirmation rule',
          `${definition.confirmationRuleId}@${definition.version}`,
          technique
        )
        for (const signalRef of definition.inputSignalKindRefs) {
          referenced.signalKinds.add(refKey(signalRef))
          resolveDefinition(
            signalRef,
            local.signalKinds,
            this.#signalKinds,
            'confirmation input signal kind',
            technique
          )
        }
        return definition
      })
      const evidenceProfiles = technique.evidenceProfileRefs.map((ref) => {
        referenced.evidenceProfiles.add(refKey(ref))
        const definition = resolveDefinition(
          ref,
          local.evidenceProfiles,
          this.#evidenceProfiles,
          'evidence profile',
          technique
        )
        assertDefinitionOwner(
          definition,
          'Evidence profile',
          `${definition.evidenceProfileId}@${definition.version}`,
          technique
        )
        return definition
      })
      const remediations = technique.remediationRefs.map((ref) => {
        referenced.remediations.add(refKey(ref))
        const definition = resolveDefinition(
          ref,
          local.remediations,
          this.#remediations,
          'remediation',
          technique
        )
        if (
          definition.familyId !== technique.familyId ||
          !definition.applicableTechniqueIds.includes(technique.techniqueId)
        ) {
          registryError(
            'reference-mismatch',
            `Remediation ${definition.remediationId}@${definition.version} does not apply to ${technique.familyId}/${technique.techniqueId}.`
          )
        }
        return definition
      })

      void detectors
      void remediations
      assertModeCombination(technique, strategies, confirmationRules, evidenceProfiles)
    }

    assertAllLocalDefinitionsReferenced(local, referenced)

    const canonicalBundleJson = canonicalJson(normalized)
    const registered = deepFreeze({
      bundle: normalized,
      canonicalBundleJson,
      definitionHash: sha256Text(canonicalBundleJson)
    }) as RegisteredVulnerabilityBundle

    this.#bundles.set(moduleKey, registered)
    this.#families.set(registered.bundle.manifest.family.familyId, registered.bundle.manifest.family)
    for (const technique of registered.bundle.manifest.techniques) {
      this.#techniques.set(versionedKey(technique.techniqueId, technique.version), technique)
    }
    for (const definition of registered.bundle.detectors) {
      this.#detectors.set(versionedKey(definition.detectorId, definition.version), definition)
    }
    for (const definition of registered.bundle.signalKinds) {
      this.#signalKinds.set(versionedKey(definition.signalKindId, definition.version), definition)
    }
    for (const definition of registered.bundle.strategies) {
      this.#strategies.set(versionedKey(definition.strategyId, definition.version), definition)
    }
    for (const definition of registered.bundle.confirmationRules) {
      this.#confirmationRules.set(
        versionedKey(definition.confirmationRuleId, definition.version),
        definition
      )
    }
    for (const definition of registered.bundle.evidenceProfiles) {
      this.#evidenceProfiles.set(
        versionedKey(definition.evidenceProfileId, definition.version),
        definition
      )
    }
    for (const definition of registered.bundle.remediations) {
      this.#remediations.set(versionedKey(definition.remediationId, definition.version), definition)
    }

    return registered
  }

  freeze(): DefinitionRegistrySnapshot {
    if (this.#snapshot) return this.#snapshot

    const bundles = [...this.#bundles.values()].sort((left, right) =>
      compareVersioned(
        {
          id: left.bundle.manifest.moduleId,
          version: left.bundle.manifest.moduleVersion
        },
        {
          id: right.bundle.manifest.moduleId,
          version: right.bundle.manifest.moduleVersion
        }
      )
    )
    const canonicalSnapshotJson = canonicalJson({
      bundles: bundles.map((registered) => ({
        bundle: registered.bundle,
        definitionHash: registered.definitionHash
      }))
    })
    this.#snapshot = deepFreeze({
      bundles,
      canonicalSnapshotJson,
      snapshotHash: sha256Text(canonicalSnapshotJson)
    }) as DefinitionRegistrySnapshot
    return this.#snapshot
  }

  snapshot(): DefinitionRegistrySnapshot {
    return this.#requireSnapshot()
  }

  listBundles(): readonly RegisteredVulnerabilityBundle[] {
    return this.#requireSnapshot().bundles
  }

  hasFamily(familyId: string): boolean {
    this.#requireSnapshot()
    return this.#families.has(familyId)
  }

  getFamily(familyId: string): ReadonlyFamily | undefined {
    this.#requireSnapshot()
    return this.#families.get(familyId)
  }

  hasModule(moduleId: string, moduleVersion?: string): boolean {
    this.#requireSnapshot()
    if (moduleVersion !== undefined) return this.#bundles.has(versionedKey(moduleId, moduleVersion))
    return [...this.#bundles.values()].some(
      (registered) => registered.bundle.manifest.moduleId === moduleId
    )
  }

  getBundle(moduleId: string, moduleVersion: string): RegisteredVulnerabilityBundle | undefined {
    this.#requireSnapshot()
    return this.#bundles.get(versionedKey(moduleId, moduleVersion))
  }

  hasTechnique(techniqueId: string, techniqueVersion?: string): boolean {
    this.#requireSnapshot()
    if (techniqueVersion !== undefined) {
      return this.#techniques.has(versionedKey(techniqueId, techniqueVersion))
    }
    return [...this.#techniques.values()].some(
      (technique) => technique.techniqueId === techniqueId
    )
  }

  getTechnique(techniqueId: string, techniqueVersion: string): ReadonlyTechnique | undefined {
    this.#requireSnapshot()
    return this.#techniques.get(versionedKey(techniqueId, techniqueVersion))
  }

  #requireSnapshot(): DefinitionRegistrySnapshot {
    if (!this.#snapshot) {
      registryError(
        'registry-not-frozen',
        'DefinitionRegistry lookups require a frozen registry snapshot.'
      )
    }
    return this.#snapshot
  }
}
