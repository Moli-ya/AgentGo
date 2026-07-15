import type {
  DefinitionRegistryCapabilityCatalogPort,
  DefinitionRegistryErrorCode,
  DefinitionRegistrySnapshot,
  RegisteredVulnerabilityBundle
} from './registry'
import {
  DefinitionRegistry,
  DefinitionRegistryError
} from './registry'

export interface ModuleConformanceAcceptance {
  readonly registeredBundles: readonly RegisteredVulnerabilityBundle[]
  readonly snapshot: DefinitionRegistrySnapshot
}

export interface ModuleConformanceRejection {
  readonly error: DefinitionRegistryError
  readonly snapshotAfterRejection: DefinitionRegistrySnapshot
}

export interface ModuleRegistrationRejectionInput {
  readonly bundle: unknown
  readonly expectedCode: DefinitionRegistryErrorCode
  readonly preRegisteredBundles?: readonly unknown[]
}

/**
 * Framework-independent assertions for module authors. The testkit always
 * creates an isolated registry and proves that a rejected bundle exposes no
 * partial definitions before returning the frozen snapshot as evidence.
 */
export class ModuleConformanceTestkit {
  readonly #capabilityCatalog: DefinitionRegistryCapabilityCatalogPort

  constructor(capabilityCatalog: DefinitionRegistryCapabilityCatalogPort) {
    this.#capabilityCatalog = capabilityCatalog
    // Validate the injected port immediately instead of deferring a bad test
    // harness until its first assertion.
    void new DefinitionRegistry(capabilityCatalog)
    Object.freeze(this)
  }

  accept(bundles: readonly unknown[]): ModuleConformanceAcceptance {
    const registry = new DefinitionRegistry(this.#capabilityCatalog)
    const registeredBundles = bundles.map((bundle) =>
      registry.registerBundle(bundle)
    )
    return Object.freeze({
      registeredBundles: Object.freeze(registeredBundles),
      snapshot: registry.freeze()
    })
  }

  expectRegistrationRejected(
    input: ModuleRegistrationRejectionInput
  ): ModuleConformanceRejection {
    const registry = new DefinitionRegistry(this.#capabilityCatalog)
    const preRegistered = input.preRegisteredBundles ?? []
    for (const bundle of preRegistered) registry.registerBundle(bundle)

    let rejected: DefinitionRegistryError | undefined
    try {
      registry.registerBundle(input.bundle)
    } catch (error) {
      if (error instanceof DefinitionRegistryError) rejected = error
      else throw error
    }
    if (!rejected) {
      throw new Error(
        `Module conformance expected ${input.expectedCode}, but registration succeeded.`
      )
    }
    if (rejected.code !== input.expectedCode) {
      throw new Error(
        `Module conformance expected ${input.expectedCode}, but received ${rejected.code}.`,
        { cause: rejected }
      )
    }

    const snapshotAfterRejection = registry.freeze()
    if (snapshotAfterRejection.bundles.length !== preRegistered.length) {
      throw new Error(
        'Rejected module registration exposed partial bundle definitions.'
      )
    }
    return Object.freeze({ error: rejected, snapshotAfterRejection })
  }

  expectPostFreezeInjectionRejected(
    registeredBundles: readonly unknown[],
    injectedBundle: unknown
  ): ModuleConformanceRejection {
    const registry = new DefinitionRegistry(this.#capabilityCatalog)
    for (const bundle of registeredBundles) registry.registerBundle(bundle)
    const snapshot = registry.freeze()

    let rejected: DefinitionRegistryError | undefined
    try {
      registry.registerBundle(injectedBundle)
    } catch (error) {
      if (error instanceof DefinitionRegistryError) rejected = error
      else throw error
    }
    if (!rejected || rejected.code !== 'registry-frozen') {
      throw new Error(
        `Post-freeze injection must fail with registry-frozen, received ${rejected?.code ?? 'success'}.`,
        { cause: rejected }
      )
    }
    if (registry.snapshot() !== snapshot) {
      throw new Error('Post-freeze injection changed the registry snapshot.')
    }
    return Object.freeze({ error: rejected, snapshotAfterRejection: snapshot })
  }
}
