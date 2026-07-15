import {
  VulnerabilityModuleBundleSchema,
  type DeclaredMode,
  type VulnerabilityModuleBundle
} from '@agentgo/contracts'
import { describe, expect, it, vi } from 'vitest'

import { canonicalJson, sha256Text } from './canonical'
import { ModuleConformanceTestkit } from './conformance-testkit'
import {
  DefinitionRegistry,
  DefinitionRegistryError,
  type DefinitionRegistryErrorCode
} from './registry'

const KNOWN_CAPABILITIES = new Map([
  ['inventory.offline-import', { riskFloor: 'l0' as const }],
  ['http.reviewed-read', { riskFloor: 'l1' as const }],
  ['http.test-object-write', { riskFloor: 'l2' as const }]
])

function capabilityCatalog() {
  return {
    get: (capabilityId: string) => KNOWN_CAPABILITIES.get(capabilityId)
  }
}

function makeRegistry(): DefinitionRegistry {
  return new DefinitionRegistry(capabilityCatalog())
}

function makeBundle(suffix: string, declaredMode: DeclaredMode = 'active-l1') {
  const familyId = `example.${suffix}`
  const techniqueId = `${familyId}.technique`
  const detectorId = `${techniqueId}.detector`
  const signalKindId = `${techniqueId}.signal`
  const strategyId = `${techniqueId}.strategy`
  const confirmationRuleId = `${techniqueId}.confirmation`
  const evidenceProfileId = `${techniqueId}.evidence`
  const remediationId = `${techniqueId}.remediation`
  const version = '1.0.0'
  const forbidden = declaredMode === 'forbidden'
  const l2 = declaredMode === 'active-l2'
  const capabilityId =
    declaredMode === 'inventory-only'
      ? 'inventory.offline-import'
      : 'http.reviewed-read'

  const bundle: VulnerabilityModuleBundle = {
    manifest: {
      moduleId: `module.${suffix}`,
      moduleVersion: version,
      family: {
        familyId,
        displayName: `Example ${suffix}`,
        category: 'test',
        description: `Family descriptor for ${suffix}.`,
        defaultEnabled: false,
        cweIds: ['CWE-79', 'CWE-20'],
        wstgRefs: ['WSTG-INPV-01'],
        asvsRefs: ['ASVS-V5'],
        apiSecurityRefs: ['API8:2023']
      },
      techniques: [
        {
          techniqueId,
          familyId,
          version,
          displayName: `Technique ${suffix}`,
          description: `Technique descriptor for ${suffix}.`,
          declaredMode,
          supportedSubjectKinds: forbidden ? [] : ['selector', 'endpoint'],
          protocols: forbidden
            ? []
            : [
                { transport: 'standard-http', bodyEncoding: 'none' },
                { transport: 'standard-http', bodyEncoding: 'json' }
              ],
          selectors: forbidden ? [] : [{ kind: 'header' }, { kind: 'query' }],
          requiredCapabilityIds: forbidden ? [] : [capabilityId],
          allowedEnvironments: forbidden
            ? []
            : declaredMode === 'fixture-only'
              ? ['attested-fixture']
              : declaredMode === 'inventory-only'
                ? ['offline']
                : ['authorized-test-environment'],
          detectorRefs: [{ id: detectorId, version }],
          strategyRefs: [{ id: strategyId, version }],
          confirmationRuleRefs: [{ id: confirmationRuleId, version }],
          evidenceProfileRefs: [{ id: evidenceProfileId, version }],
          remediationRefs: [{ id: remediationId, version }],
          ...(declaredMode === 'active-l1' || declaredMode === 'active-l2'
            ? { expectedSuiteRef: { id: `${techniqueId}.suite`, version } }
            : {})
        }
      ],
      sourceRefs: ['source-z', 'source-a']
    },
    detectors: [
      {
        detectorId,
        version,
        familyId,
        techniqueId,
        description: 'Pure candidate detector.',
        inputSchemaVersion: version,
        candidateBasis: ['structured-inventory', 'reviewed-observation'],
        falsePositiveRisks: ['framework-default', 'intermediary-normalization'],
        maxCandidates: 10
      }
    ],
    signalKinds: [
      {
        signalKindId,
        version,
        description: 'A structured deterministic signal.',
        attributeSchemaVersion: version,
        requiredAttributes: ['observed-value', 'baseline-value']
      }
    ],
    strategies: [
      {
        strategyId,
        version,
        familyId,
        techniqueId,
        description: 'A bounded strategy descriptor.',
        requiredCapabilityIds: forbidden ? [] : [capabilityId],
        requiresTestObject: l2,
        requiresSideEffectEnvelope: l2,
        requiresCleanup: l2,
        requiresCleanupVerification: l2,
        emittedSignalKindRefs: [{ id: signalKindId, version }]
      }
    ],
    confirmationRules: [
      {
        confirmationRuleId,
        version,
        familyId,
        techniqueId,
        description: 'A deterministic three-state confirmation rule.',
        inputSignalKindRefs: [{ id: signalKindId, version }],
        requiredEvidenceRoles: ['test', 'negative-control', 'baseline'],
        negativeControlRequired: true,
        supportedVerdicts: ['confirmed', 'not-confirmed', 'inconclusive']
      }
    ],
    evidenceProfiles: [
      {
        evidenceProfileId,
        version,
        familyId,
        techniqueId,
        description: 'Minimum redacted evidence.',
        roles: [
          { role: 'test', minCount: 1 },
          { role: 'baseline', minCount: 1 },
          { role: 'negative-control', minCount: 1 }
        ],
        redactionRequired: true,
        forbiddenCaptureFields: ['authorization', 'cookie']
      }
    ],
    remediations: [
      {
        remediationId,
        version,
        familyId,
        applicableTechniqueIds: [techniqueId],
        rootCause: 'Untrusted input reaches a sensitive decision.',
        shortTermMitigation: 'Constrain the affected input.',
        remediation: 'Use a context-safe deterministic implementation.',
        regressionTest: 'Retain positive and negative regression cases.',
        cweIds: ['CWE-79', 'CWE-20'],
        wstgRefs: ['WSTG-INPV-01'],
        asvsRefs: ['ASVS-V5'],
        apiSecurityRefs: ['API8:2023'],
        sourceRefs: ['remediation-source-b', 'remediation-source-a']
      }
    ]
  }
  return bundle
}

function cloneBundle(bundle: VulnerabilityModuleBundle): VulnerabilityModuleBundle {
  return VulnerabilityModuleBundleSchema.parse(bundle)
}

function expectRegistryError(
  action: () => unknown,
  code: DefinitionRegistryErrorCode
): DefinitionRegistryError {
  try {
    action()
  } catch (error) {
    expect(error).toBeInstanceOf(DefinitionRegistryError)
    expect((error as DefinitionRegistryError).code).toBe(code)
    return error as DefinitionRegistryError
  }
  throw new Error(`Expected DefinitionRegistryError with code ${code}.`)
}

function expectRejectedAtomically(
  input: unknown,
  code: DefinitionRegistryErrorCode
): DefinitionRegistryError {
  const result = new ModuleConformanceTestkit(
    capabilityCatalog()
  ).expectRegistrationRejected({ bundle: input, expectedCode: code })
  expect(result.snapshotAfterRejection.bundles).toHaveLength(0)
  return result.error
}

function firstTechnique(bundle: VulnerabilityModuleBundle) {
  const technique = bundle.manifest.techniques[0]
  if (!technique) throw new Error('Test bundle has no technique.')
  return technique
}

function firstStrategy(bundle: VulnerabilityModuleBundle) {
  const strategy = bundle.strategies[0]
  if (!strategy) throw new Error('Test bundle has no strategy.')
  return strategy
}

function addSecondaryDefinitions(bundle: VulnerabilityModuleBundle): void {
  const technique = firstTechnique(bundle)
  const version = technique.version

  const detector = {
    ...bundle.detectors[0]!,
    detectorId: `${bundle.detectors[0]!.detectorId}.secondary`
  }
  bundle.detectors.push(detector)
  technique.detectorRefs.push({ id: detector.detectorId, version })

  const signalKind = {
    ...bundle.signalKinds[0]!,
    signalKindId: `${bundle.signalKinds[0]!.signalKindId}.secondary`
  }
  bundle.signalKinds.push(signalKind)
  firstStrategy(bundle).emittedSignalKindRefs.push({ id: signalKind.signalKindId, version })
  bundle.confirmationRules[0]!.inputSignalKindRefs.push({
    id: signalKind.signalKindId,
    version
  })

  const strategy = {
    ...bundle.strategies[0]!,
    strategyId: `${bundle.strategies[0]!.strategyId}.secondary`
  }
  bundle.strategies.push(strategy)
  technique.strategyRefs.push({ id: strategy.strategyId, version })

  const confirmationRule = {
    ...bundle.confirmationRules[0]!,
    confirmationRuleId: `${bundle.confirmationRules[0]!.confirmationRuleId}.secondary`
  }
  bundle.confirmationRules.push(confirmationRule)
  technique.confirmationRuleRefs.push({ id: confirmationRule.confirmationRuleId, version })

  const evidenceProfile = {
    ...bundle.evidenceProfiles[0]!,
    evidenceProfileId: `${bundle.evidenceProfiles[0]!.evidenceProfileId}.secondary`
  }
  bundle.evidenceProfiles.push(evidenceProfile)
  technique.evidenceProfileRefs.push({ id: evidenceProfile.evidenceProfileId, version })

  const remediation = {
    ...bundle.remediations[0]!,
    remediationId: `${bundle.remediations[0]!.remediationId}.secondary`
  }
  bundle.remediations.push(remediation)
  technique.remediationRefs.push({ id: remediation.remediationId, version })
}

describe('canonical definition encoding', () => {
  it('uses canonical object-key ordering and standard UTF-8 SHA-256', () => {
    expect(canonicalJson({ z: 1, a: ['中文', true] })).toBe(
      '{"a":["中文",true],"z":1}'
    )
    expect(sha256Text('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )
    expect(sha256Text('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    )
    expect(sha256Text('中文')).toBe(
      '72726d8818f693066ceb69afa364218b692e62ea92b385782363780f47529c21'
    )
  })

  it('rejects non-JSON and cyclic values', () => {
    expect(() => canonicalJson({ missing: undefined })).toThrow(/does not accept undefined/)
    const cyclic: { self?: unknown } = {}
    cyclic.self = cyclic
    expect(() => canonicalJson(cyclic)).toThrow(/cyclic/)
  })
})

describe('ModuleConformanceTestkit', () => {
  it('accepts complete bundles and returns immutable registration evidence', () => {
    const result = new ModuleConformanceTestkit(capabilityCatalog()).accept([
      makeBundle('testkit.accepted')
    ])

    expect(result.registeredBundles).toHaveLength(1)
    expect(result.snapshot.bundles).toHaveLength(1)
    expect(Object.isFrozen(result)).toBe(true)
    expect(Object.isFrozen(result.snapshot)).toBe(true)
  })
})

describe('DefinitionRegistry valid maturity combinations', () => {
  it.each<DeclaredMode>([
    'active-l1',
    'active-l2',
    'signal-only',
    'fixture-only',
    'inventory-only',
    'forbidden'
  ])('atomically registers a complete %s bundle as definition metadata', (mode) => {
    const registry = makeRegistry()
    const bundle = makeBundle(mode.replaceAll('-', '.'), mode)
    const registered = registry.registerBundle(bundle)
    const snapshot = registry.freeze()
    const technique = firstTechnique(bundle)

    expect(registered.definitionHash).toHaveLength(64)
    expect(registered.definitionHash).toBe(sha256Text(registered.canonicalBundleJson))
    expect(snapshot.snapshotHash).toBe(sha256Text(snapshot.canonicalSnapshotJson))
    expect(registry.hasFamily(technique.familyId)).toBe(true)
    expect(registry.hasModule(bundle.manifest.moduleId, bundle.manifest.moduleVersion)).toBe(true)
    expect(registry.hasTechnique(technique.techniqueId, technique.version)).toBe(true)
    expect(registry.getTechnique(technique.techniqueId, technique.version)?.declaredMode).toBe(
      mode
    )
    expect(registry.getBundle(bundle.manifest.moduleId, bundle.manifest.moduleVersion)).toBe(
      registered
    )
  })

  it('allows fixture-only definitions to declare a complete L2 safety set', () => {
    const bundle = makeBundle('fixture.l2', 'fixture-only')
    const strategy = firstStrategy(bundle)
    strategy.requiresTestObject = true
    strategy.requiresSideEffectEnvelope = true
    strategy.requiresCleanup = true
    strategy.requiresCleanupVerification = true

    const registry = makeRegistry()
    registry.registerBundle(bundle)
    expect(registry.freeze().bundles).toHaveLength(1)
  })
})

describe('DefinitionRegistry schema, uniqueness, and atomic staging', () => {
  it('rejects a missing rule without exposing a partial bundle', () => {
    const bundle = makeBundle('missing.rule')
    const invalid = { ...bundle, confirmationRules: [] }
    expectRejectedAtomically(invalid, 'invalid-bundle')
  })

  const duplicateDefinitionCases: Array<
    readonly [string, (bundle: VulnerabilityModuleBundle) => void]
  > = [
    [
      'detector',
      (bundle) => bundle.detectors.push({ ...bundle.detectors[0]! })
    ],
    [
      'signal kind',
      (bundle) => bundle.signalKinds.push({ ...bundle.signalKinds[0]! })
    ],
    [
      'strategy',
      (bundle) => bundle.strategies.push({ ...bundle.strategies[0]! })
    ],
    [
      'confirmation rule',
      (bundle) => bundle.confirmationRules.push({ ...bundle.confirmationRules[0]! })
    ],
    [
      'evidence profile',
      (bundle) => bundle.evidenceProfiles.push({ ...bundle.evidenceProfiles[0]! })
    ],
    [
      'remediation',
      (bundle) => bundle.remediations.push({ ...bundle.remediations[0]! })
    ]
  ]

  it.each(duplicateDefinitionCases)(
    'rejects duplicate %s ID/version within a bundle',
    (_name, mutate) => {
      const bundle = makeBundle('duplicate.local')
      mutate(bundle)
      expectRejectedAtomically(bundle, 'duplicate-identity')
    }
  )

  it('rejects duplicate technique ID/version within a bundle', () => {
    const bundle = makeBundle('duplicate.technique.local')
    bundle.manifest.techniques.push({ ...firstTechnique(bundle) })
    expectRejectedAtomically(bundle, 'duplicate-identity')
  })

  it('rejects duplicate module and technique identities across bundles', () => {
    const moduleRegistry = makeRegistry()
    const first = makeBundle('duplicate.module')
    moduleRegistry.registerBundle(first)
    expectRegistryError(() => moduleRegistry.registerBundle(cloneBundle(first)), 'duplicate-identity')
    expect(moduleRegistry.freeze().bundles).toHaveLength(1)

    const techniqueRegistry = makeRegistry()
    const original = makeBundle('duplicate.technique.one')
    const duplicate = makeBundle('duplicate.technique.two')
    const originalTechnique = firstTechnique(original)
    const duplicateTechnique = firstTechnique(duplicate)
    duplicateTechnique.techniqueId = originalTechnique.techniqueId
    duplicate.detectors[0]!.techniqueId = originalTechnique.techniqueId
    duplicate.strategies[0]!.techniqueId = originalTechnique.techniqueId
    duplicate.confirmationRules[0]!.techniqueId = originalTechnique.techniqueId
    duplicate.evidenceProfiles[0]!.techniqueId = originalTechnique.techniqueId
    duplicate.remediations[0]!.applicableTechniqueIds = [originalTechnique.techniqueId]
    techniqueRegistry.registerBundle(original)
    expectRegistryError(
      () => techniqueRegistry.registerBundle(duplicate),
      'duplicate-identity'
    )
    expect(techniqueRegistry.freeze().bundles).toHaveLength(1)
  })

  const crossBundleDefinitionCases: Array<
    readonly [
      string,
      (
        original: VulnerabilityModuleBundle,
        duplicate: VulnerabilityModuleBundle
      ) => void
    ]
  > = [
    [
      'detector',
      (original, duplicate) => {
        duplicate.detectors[0]!.detectorId = original.detectors[0]!.detectorId
        duplicate.detectors[0]!.version = original.detectors[0]!.version
        firstTechnique(duplicate).detectorRefs = [
          {
            id: duplicate.detectors[0]!.detectorId,
            version: duplicate.detectors[0]!.version
          }
        ]
      }
    ],
    [
      'signal kind',
      (original, duplicate) => {
        duplicate.signalKinds[0]!.signalKindId = original.signalKinds[0]!.signalKindId
        duplicate.signalKinds[0]!.version = original.signalKinds[0]!.version
      }
    ],
    [
      'strategy',
      (original, duplicate) => {
        duplicate.strategies[0]!.strategyId = original.strategies[0]!.strategyId
        duplicate.strategies[0]!.version = original.strategies[0]!.version
        firstTechnique(duplicate).strategyRefs = [
          {
            id: duplicate.strategies[0]!.strategyId,
            version: duplicate.strategies[0]!.version
          }
        ]
      }
    ],
    [
      'confirmation rule',
      (original, duplicate) => {
        duplicate.confirmationRules[0]!.confirmationRuleId =
          original.confirmationRules[0]!.confirmationRuleId
        duplicate.confirmationRules[0]!.version = original.confirmationRules[0]!.version
        firstTechnique(duplicate).confirmationRuleRefs = [
          {
            id: duplicate.confirmationRules[0]!.confirmationRuleId,
            version: duplicate.confirmationRules[0]!.version
          }
        ]
      }
    ],
    [
      'evidence profile',
      (original, duplicate) => {
        duplicate.evidenceProfiles[0]!.evidenceProfileId =
          original.evidenceProfiles[0]!.evidenceProfileId
        duplicate.evidenceProfiles[0]!.version = original.evidenceProfiles[0]!.version
        firstTechnique(duplicate).evidenceProfileRefs = [
          {
            id: duplicate.evidenceProfiles[0]!.evidenceProfileId,
            version: duplicate.evidenceProfiles[0]!.version
          }
        ]
      }
    ],
    [
      'remediation',
      (original, duplicate) => {
        duplicate.remediations[0]!.remediationId = original.remediations[0]!.remediationId
        duplicate.remediations[0]!.version = original.remediations[0]!.version
        firstTechnique(duplicate).remediationRefs = [
          {
            id: duplicate.remediations[0]!.remediationId,
            version: duplicate.remediations[0]!.version
          }
        ]
      }
    ]
  ]

  it.each(crossBundleDefinitionCases)(
    'rejects duplicate %s ID/version across bundles atomically',
    (_name, collide) => {
      const registry = makeRegistry()
      const original = makeBundle('duplicate.cross.one')
      const duplicate = makeBundle('duplicate.cross.two')
      registry.registerBundle(original)
      collide(original, duplicate)
      expectRegistryError(() => registry.registerBundle(duplicate), 'duplicate-identity')
      expect(registry.freeze().bundles).toHaveLength(1)
    }
  )

  it('uses ID plus version as identity and permits distinct versions', () => {
    const first = makeBundle('versioned')
    const second = cloneBundle(first)
    second.manifest.moduleVersion = '2.0.0'
    const technique = firstTechnique(second)
    technique.version = '2.0.0'
    for (const ref of [
      ...technique.detectorRefs,
      ...technique.strategyRefs,
      ...technique.confirmationRuleRefs,
      ...technique.evidenceProfileRefs,
      ...technique.remediationRefs
    ]) {
      ref.version = '2.0.0'
    }
    for (const definition of second.detectors) definition.version = '2.0.0'
    for (const definition of second.signalKinds) definition.version = '2.0.0'
    for (const definition of second.strategies) {
      definition.version = '2.0.0'
      for (const ref of definition.emittedSignalKindRefs) ref.version = '2.0.0'
    }
    for (const definition of second.confirmationRules) {
      definition.version = '2.0.0'
      for (const ref of definition.inputSignalKindRefs) ref.version = '2.0.0'
    }
    for (const definition of second.evidenceProfiles) definition.version = '2.0.0'
    for (const definition of second.remediations) definition.version = '2.0.0'

    const registry = makeRegistry()
    registry.registerBundle(first)
    registry.registerBundle(second)
    registry.freeze()
    expect(registry.hasModule(first.manifest.moduleId, '1.0.0')).toBe(true)
    expect(registry.hasModule(first.manifest.moduleId, '2.0.0')).toBe(true)
    expect(registry.hasTechnique(technique.techniqueId, '1.0.0')).toBe(true)
    expect(registry.hasTechnique(technique.techniqueId, '2.0.0')).toBe(true)
  })

  it('rejects duplicate values in set-like manifest and definition arrays', () => {
    const bundle = makeBundle('duplicate.values')
    bundle.manifest.sourceRefs.push(bundle.manifest.sourceRefs[0]!)
    expectRejectedAtomically(bundle, 'duplicate-value')
  })
})

describe('DefinitionRegistry descriptions, references, and capabilities', () => {
  it('allows an identical family descriptor and rejects a conflicting descriptor', () => {
    const original = makeBundle('family.original')
    const matching = makeBundle('family.matching')
    matching.manifest.family = cloneBundle(original).manifest.family
    const matchingTechnique = firstTechnique(matching)
    matchingTechnique.familyId = original.manifest.family.familyId
    matching.detectors[0]!.familyId = original.manifest.family.familyId
    matching.strategies[0]!.familyId = original.manifest.family.familyId
    matching.confirmationRules[0]!.familyId = original.manifest.family.familyId
    matching.evidenceProfiles[0]!.familyId = original.manifest.family.familyId
    matching.remediations[0]!.familyId = original.manifest.family.familyId

    const registry = makeRegistry()
    registry.registerBundle(original)
    registry.registerBundle(matching)
    expect(registry.freeze().bundles).toHaveLength(2)

    const conflict = cloneBundle(matching)
    conflict.manifest.family.description = 'Conflicting family semantics.'
    const result = new ModuleConformanceTestkit(
      capabilityCatalog()
    ).expectRegistrationRejected({
      preRegisteredBundles: [original],
      bundle: conflict,
      expectedCode: 'family-description-conflict'
    })
    expect(result.snapshotAfterRejection.bundles).toHaveLength(1)
  })

  it('rejects dangling manifest and signal-kind references', () => {
    const missingRule = makeBundle('dangling.rule')
    firstTechnique(missingRule).confirmationRuleRefs[0]!.id = 'missing.confirmation'
    expectRejectedAtomically(missingRule, 'dangling-reference')

    const missingSignal = makeBundle('dangling.signal')
    firstStrategy(missingSignal).emittedSignalKindRefs[0]!.id = 'missing.signal'
    expectRejectedAtomically(missingSignal, 'dangling-reference')
  })

  it('rejects cross-technique ownership and incomplete capability declarations', () => {
    const ownerMismatch = makeBundle('owner.mismatch')
    ownerMismatch.detectors[0]!.techniqueId = 'other.technique'
    expectRejectedAtomically(ownerMismatch, 'reference-mismatch')

    const capabilityMismatch = makeBundle('capability.mismatch')
    firstTechnique(capabilityMismatch).requiredCapabilityIds = []
    expectRejectedAtomically(capabilityMismatch, 'reference-mismatch')

    const remediationMismatch = makeBundle('remediation.mismatch')
    remediationMismatch.remediations[0]!.applicableTechniqueIds = ['other.technique']
    expectRejectedAtomically(remediationMismatch, 'reference-mismatch')
  })

  it('rejects unknown manifest and strategy capabilities through the injected port', () => {
    const checked = vi.fn((id: string) => KNOWN_CAPABILITIES.get(id))
    const registry = new DefinitionRegistry({ get: checked })
    const manifestUnknown = makeBundle('unknown.manifest')
    firstTechnique(manifestUnknown).requiredCapabilityIds.push('unknown.capability')
    expectRegistryError(
      () => registry.registerBundle(manifestUnknown),
      'unknown-capability'
    )
    expect(checked).toHaveBeenCalledWith('unknown.capability')
    expect(registry.freeze().bundles).toHaveLength(0)

    const strategyUnknown = makeBundle('unknown.strategy')
    firstStrategy(strategyUnknown).requiredCapabilityIds.push('unknown.capability')
    expectRejectedAtomically(strategyUnknown, 'unknown-capability')
  })

  const unreferencedCases: Array<
    readonly [string, (bundle: VulnerabilityModuleBundle) => void]
  > = [
    [
      'detector',
      (bundle) =>
        bundle.detectors.push({
          ...bundle.detectors[0]!,
          detectorId: `${bundle.detectors[0]!.detectorId}.unused`
        })
    ],
    [
      'signal kind',
      (bundle) =>
        bundle.signalKinds.push({
          ...bundle.signalKinds[0]!,
          signalKindId: `${bundle.signalKinds[0]!.signalKindId}.unused`
        })
    ],
    [
      'strategy',
      (bundle) =>
        bundle.strategies.push({
          ...bundle.strategies[0]!,
          strategyId: `${bundle.strategies[0]!.strategyId}.unused`
        })
    ],
    [
      'confirmation rule',
      (bundle) =>
        bundle.confirmationRules.push({
          ...bundle.confirmationRules[0]!,
          confirmationRuleId: `${bundle.confirmationRules[0]!.confirmationRuleId}.unused`
        })
    ],
    [
      'evidence profile',
      (bundle) =>
        bundle.evidenceProfiles.push({
          ...bundle.evidenceProfiles[0]!,
          evidenceProfileId: `${bundle.evidenceProfiles[0]!.evidenceProfileId}.unused`
        })
    ],
    [
      'remediation',
      (bundle) =>
        bundle.remediations.push({
          ...bundle.remediations[0]!,
          remediationId: `${bundle.remediations[0]!.remediationId}.unused`
        })
    ]
  ]

  it.each(unreferencedCases)('rejects an unreferenced %s definition', (_name, addUnused) => {
    const bundle = makeBundle('unreferenced')
    addUnused(bundle)
    expectRejectedAtomically(bundle, 'unreferenced-definition')
  })
})

describe('DefinitionRegistry maturity constraints', () => {
  it('enforces SecurityPolicy capability risk floors without allowing mode downgrade', () => {
    const downgradedL1 = makeBundle('risk.floor.active.l1')
    firstTechnique(downgradedL1).requiredCapabilityIds = [
      'http.test-object-write'
    ]
    firstStrategy(downgradedL1).requiredCapabilityIds = [
      'http.test-object-write'
    ]
    expectRejectedAtomically(downgradedL1, 'invalid-mode-combination')

    const downgradedInventory = makeBundle(
      'risk.floor.inventory',
      'inventory-only'
    )
    firstTechnique(downgradedInventory).requiredCapabilityIds = [
      'http.reviewed-read'
    ]
    firstStrategy(downgradedInventory).requiredCapabilityIds = [
      'http.reviewed-read'
    ]
    expectRejectedAtomically(
      downgradedInventory,
      'invalid-mode-combination'
    )

    const declaredL2 = makeBundle('risk.floor.active.l2', 'active-l2')
    firstTechnique(declaredL2).requiredCapabilityIds = [
      'http.test-object-write'
    ]
    firstStrategy(declaredL2).requiredCapabilityIds = [
      'http.test-object-write'
    ]
    expect(() => makeRegistry().registerBundle(declaredL2)).not.toThrow()
  })

  it('requires an expected suite, negative control, and supplied minimum evidence roles for active modes', () => {
    const missingSuite = makeBundle('active.no.suite')
    delete firstTechnique(missingSuite).expectedSuiteRef
    expectRejectedAtomically(missingSuite, 'invalid-mode-combination')

    const missingNegative = makeBundle('active.no.negative')
    missingNegative.confirmationRules[0]!.negativeControlRequired = false
    expectRejectedAtomically(missingNegative, 'invalid-mode-combination')

    const missingEvidenceRole = makeBundle('active.no.evidence.role')
    missingEvidenceRole.confirmationRules[0]!.requiredEvidenceRoles.push('missing-role')
    expectRejectedAtomically(missingEvidenceRole, 'reference-mismatch')
  })

  it('requires evidence profiles to supply rule roles for non-active modes', () => {
    const signalOnly = makeBundle(
      'signal.only.missing.evidence.role',
      'signal-only'
    )
    signalOnly.confirmationRules[0]!.requiredEvidenceRoles.push(
      'missing-role'
    )
    expectRejectedAtomically(signalOnly, 'reference-mismatch')
  })

  it.each([
    'requiresTestObject',
    'requiresSideEffectEnvelope',
    'requiresCleanup',
    'requiresCleanupVerification'
  ] as const)('requires active-l2 strategy boolean %s', (field) => {
    const bundle = makeBundle(`active.l2.${field.toLowerCase()}`, 'active-l2')
    firstStrategy(bundle)[field] = false
    expectRejectedAtomically(bundle, 'invalid-mode-combination')
  })

  it.each<DeclaredMode>(['active-l1', 'signal-only', 'inventory-only', 'forbidden'])(
    'rejects L2 declarations for %s',
    (mode) => {
      const bundle = makeBundle(`no.l2.${mode.replaceAll('-', '.')}`, mode)
      firstStrategy(bundle).requiresCleanup = true
      expectRejectedAtomically(bundle, 'invalid-mode-combination')
    }
  )

  it('rejects partial fixture-only L2 declarations', () => {
    const bundle = makeBundle('fixture.partial', 'fixture-only')
    firstStrategy(bundle).requiresTestObject = true
    expectRejectedAtomically(bundle, 'invalid-mode-combination')
  })

  it('limits fixture-only to attested fixtures and active modes to online authorized environments', () => {
    const fixture = makeBundle('fixture.environment', 'fixture-only')
    firstTechnique(fixture).allowedEnvironments = ['authorized-test-environment']
    expectRejectedAtomically(fixture, 'invalid-mode-combination')

    const active = makeBundle('active.environment')
    firstTechnique(active).allowedEnvironments.push('offline')
    expectRejectedAtomically(active, 'invalid-mode-combination')
  })

  const requiredSurfaceCases: Array<
    readonly [string, (bundle: VulnerabilityModuleBundle) => void]
  > = [
    ['subject kinds', (bundle) => (firstTechnique(bundle).supportedSubjectKinds = [])],
    ['protocols', (bundle) => (firstTechnique(bundle).protocols = [])],
    ['selectors', (bundle) => (firstTechnique(bundle).selectors = [])],
    ['environments', (bundle) => (firstTechnique(bundle).allowedEnvironments = [])],
    ['detector refs', (bundle) => (firstTechnique(bundle).detectorRefs = [])],
    ['strategy refs', (bundle) => (firstTechnique(bundle).strategyRefs = [])],
    ['confirmation refs', (bundle) => (firstTechnique(bundle).confirmationRuleRefs = [])],
    ['evidence refs', (bundle) => (firstTechnique(bundle).evidenceProfileRefs = [])],
    ['remediation refs', (bundle) => (firstTechnique(bundle).remediationRefs = [])]
  ]

  it.each(requiredSurfaceCases)(
    'requires non-forbidden techniques to declare %s',
    (_name, remove) => {
      const bundle = makeBundle('surface.required', 'signal-only')
      remove(bundle)
      expectRejectedAtomically(bundle, 'invalid-mode-combination')
    }
  )

  const forbiddenSurfaceCases: Array<
    readonly [string, (bundle: VulnerabilityModuleBundle) => void]
  > = [
    [
      'subject kind',
      (bundle) => firstTechnique(bundle).supportedSubjectKinds.push('endpoint')
    ],
    [
      'protocol',
      (bundle) =>
        firstTechnique(bundle).protocols.push({
          transport: 'standard-http',
          bodyEncoding: 'none'
        })
    ],
    ['selector', (bundle) => firstTechnique(bundle).selectors.push({ kind: 'query' })],
    [
      'capability',
      (bundle) => firstTechnique(bundle).requiredCapabilityIds.push('http.reviewed-read')
    ],
    [
      'environment',
      (bundle) => firstTechnique(bundle).allowedEnvironments.push('offline')
    ],
    [
      'expected suite',
      (bundle) => {
        firstTechnique(bundle).expectedSuiteRef = { id: 'forbidden.suite', version: '1.0.0' }
      }
    ]
  ]

  it.each(forbiddenSurfaceCases)(
    'rejects forbidden technique %s declarations while retaining auditable definition refs',
    (_name, add) => {
      const bundle = makeBundle('forbidden.surface', 'forbidden')
      add(bundle)
      expectRejectedAtomically(bundle, 'invalid-mode-combination')
    }
  )
})

describe('DefinitionRegistry freeze, isolation, and deterministic snapshots', () => {
  it('requires freeze for lookup, freezes deeply, and is idempotent', () => {
    const registry = makeRegistry()
    const bundle = makeBundle('frozen')
    registry.registerBundle(bundle)
    expectRegistryError(() => registry.hasFamily(bundle.manifest.family.familyId), 'registry-not-frozen')

    const snapshot = registry.freeze()
    expect(registry.freeze()).toBe(snapshot)
    expect(registry.snapshot()).toBe(snapshot)
    expect(Object.isFrozen(snapshot)).toBe(true)
    expect(Object.isFrozen(snapshot.bundles)).toBe(true)
    expect(Object.isFrozen(snapshot.bundles[0]?.bundle)).toBe(true)
    expect(Object.isFrozen(snapshot.bundles[0]?.bundle.evidenceProfiles[0]?.roles)).toBe(true)

    const mutableView = snapshot.bundles[0]?.bundle as VulnerabilityModuleBundle
    expect(() => {
      mutableView.manifest.family.description = 'mutated'
    }).toThrow(TypeError)
  })

  it('isolates registered state from subsequent input mutation', () => {
    const registry = makeRegistry()
    const input = makeBundle('mutation.isolation')
    const registered = registry.registerBundle(input)
    const originalHash = registered.definitionHash
    input.manifest.family.description = 'external mutation'
    input.manifest.sourceRefs.push('external-source')
    input.detectors[0]!.candidateBasis.push('external-basis')

    const snapshot = registry.freeze()
    const stored = snapshot.bundles[0]
    expect(stored?.definitionHash).toBe(originalHash)
    expect(stored?.bundle.manifest.family.description).not.toBe('external mutation')
    expect(stored?.bundle.manifest.sourceRefs).not.toContain('external-source')
    expect(stored?.bundle.detectors[0]?.candidateBasis).not.toContain('external-basis')
  })

  it('rejects all post-freeze injection without changing the snapshot', () => {
    const result = new ModuleConformanceTestkit(
      capabilityCatalog()
    ).expectPostFreezeInjectionRejected(
      [makeBundle('freeze.first')],
      makeBundle('freeze.second')
    )
    expect(result.error.code).toBe('registry-frozen')
    expect(result.snapshotAfterRejection.bundles).toHaveLength(1)
  })

  it('normalizes set-like order before computing a bundle definition hash', () => {
    const original = makeBundle('canonical.bundle')
    addSecondaryDefinitions(original)
    const reordered = cloneBundle(original)
    reordered.manifest.sourceRefs.reverse()
    reordered.manifest.family.cweIds.reverse()
    firstTechnique(reordered).supportedSubjectKinds.reverse()
    firstTechnique(reordered).protocols.reverse()
    firstTechnique(reordered).selectors.reverse()
    reordered.detectors[0]!.candidateBasis.reverse()
    reordered.signalKinds[0]!.requiredAttributes.reverse()
    reordered.confirmationRules[0]!.requiredEvidenceRoles.reverse()
    reordered.evidenceProfiles[0]!.roles.reverse()
    reordered.remediations[0]!.sourceRefs.reverse()
    firstTechnique(reordered).detectorRefs.reverse()
    firstTechnique(reordered).strategyRefs.reverse()
    firstTechnique(reordered).confirmationRuleRefs.reverse()
    firstTechnique(reordered).evidenceProfileRefs.reverse()
    firstTechnique(reordered).remediationRefs.reverse()
    reordered.detectors.reverse()
    reordered.signalKinds.reverse()
    reordered.strategies.reverse()
    reordered.confirmationRules.reverse()
    reordered.evidenceProfiles.reverse()
    reordered.remediations.reverse()

    const firstRegistry = makeRegistry()
    const secondRegistry = makeRegistry()
    const first = firstRegistry.registerBundle(original)
    const second = secondRegistry.registerBundle(reordered)
    expect(first.canonicalBundleJson).toBe(second.canonicalBundleJson)
    expect(first.definitionHash).toBe(second.definitionHash)
  })

  it('sorts modules by ID/version so the global snapshot is registration-order independent', () => {
    const alpha = makeBundle('order.alpha')
    const beta = makeBundle('order.beta')
    const forward = makeRegistry()
    forward.registerBundle(alpha)
    forward.registerBundle(beta)
    const reverse = makeRegistry()
    reverse.registerBundle(cloneBundle(beta))
    reverse.registerBundle(cloneBundle(alpha))

    const forwardSnapshot = forward.freeze()
    const reverseSnapshot = reverse.freeze()
    expect(forwardSnapshot.canonicalSnapshotJson).toBe(reverseSnapshot.canonicalSnapshotJson)
    expect(forwardSnapshot.snapshotHash).toBe(reverseSnapshot.snapshotHash)
    expect(forwardSnapshot.bundles.map((entry) => entry.bundle.manifest.moduleId)).toEqual([
      'module.order.alpha',
      'module.order.beta'
    ])
  })
})
