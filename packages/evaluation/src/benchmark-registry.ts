import {
  BenchmarkSuiteManifestSchema,
  type BenchmarkSuiteManifest
} from '@agentgo/contracts'

export class BenchmarkSuiteRegistryError extends Error {
  readonly code: 'duplicate-suite' | 'registry-frozen' | 'invalid-suite'

  constructor(code: BenchmarkSuiteRegistryError['code'], message: string) {
    super(message)
    this.name = 'BenchmarkSuiteRegistryError'
    this.code = code
  }
}

export function benchmarkSuiteKey(input: {
  suiteId: string
  suiteVersion: string
  techniqueId: string
}): string {
  return `${input.suiteId}\u0000${input.suiteVersion}\u0000${input.techniqueId}`
}

/**
 * Discovers versioned technique suites by explicit registration. It never
 * walks `VulnerabilityFamilySchema.options` or any global family enum.
 */
export class BenchmarkSuiteRegistry {
  readonly #suites = new Map<string, BenchmarkSuiteManifest>()
  #frozen = false

  get frozen(): boolean {
    return this.#frozen
  }

  register(suite: unknown): BenchmarkSuiteManifest {
    if (this.#frozen) {
      throw new BenchmarkSuiteRegistryError(
        'registry-frozen',
        'BenchmarkSuiteRegistry is frozen.'
      )
    }
    const parsedResult = BenchmarkSuiteManifestSchema.safeParse(suite)
    if (!parsedResult.success) {
      throw new BenchmarkSuiteRegistryError(
        'invalid-suite',
        parsedResult.error.issues.map((issue) => issue.message).join('; ')
      )
    }
    const parsed = parsedResult.data
    const key = benchmarkSuiteKey(parsed)
    if (this.#suites.has(key)) {
      throw new BenchmarkSuiteRegistryError(
        'duplicate-suite',
        `Duplicate suite ${parsed.suiteId}@${parsed.suiteVersion} for ${parsed.techniqueId}.`
      )
    }
    this.#suites.set(key, parsed)
    return parsed
  }

  freeze(): readonly BenchmarkSuiteManifest[] {
    this.#frozen = true
    Object.freeze(this)
    return this.list()
  }

  get(
    suiteId: string,
    suiteVersion: string,
    techniqueId: string
  ): BenchmarkSuiteManifest | undefined {
    return this.#suites.get(
      benchmarkSuiteKey({ suiteId, suiteVersion, techniqueId })
    )
  }

  list(): readonly BenchmarkSuiteManifest[] {
    return Object.freeze(
      [...this.#suites.values()].sort((left, right) =>
        benchmarkSuiteKey(left).localeCompare(benchmarkSuiteKey(right))
      )
    )
  }

  listLegacyV1(): readonly BenchmarkSuiteManifest[] {
    return this.list().filter((suite) => suite.suiteId === 'legacy-v1')
  }
}

export function createFrozenBenchmarkSuiteRegistry(
  suites: readonly unknown[]
): BenchmarkSuiteRegistry {
  const registry = new BenchmarkSuiteRegistry()
  for (const suite of suites) registry.register(suite)
  registry.freeze()
  return registry
}
