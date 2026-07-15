/**
 * Stable capability identifiers use a lowercase dotted namespace. Hyphens are
 * allowed inside a segment, but empty segments and leading/trailing separators
 * are rejected.
 */
const PROBE_CAPABILITY_ID_PATTERN =
  /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$/

const PROBE_CAPABILITY_RISK_FLOORS = ['l0', 'l1', 'l2'] as const

export type ProbeCapabilityRiskFloor =
  (typeof PROBE_CAPABILITY_RISK_FLOORS)[number]

/**
 * A descriptor records the minimum policy level implied by a capability. It
 * does not grant that capability, qualify a module, or authorize execution.
 */
export interface ProbeCapabilityDescriptor {
  readonly id: string
  readonly riskFloor: ProbeCapabilityRiskFloor
  readonly description: string
}

export function isProbeCapabilityId(value: string): boolean {
  return value.length <= 128 && PROBE_CAPABILITY_ID_PATTERN.test(value)
}

function parseDescriptor(
  descriptor: ProbeCapabilityDescriptor,
  index: number
): Readonly<ProbeCapabilityDescriptor> {
  if (!descriptor || typeof descriptor !== 'object') {
    throw new TypeError(`Probe capability descriptor at index ${index} must be an object.`)
  }

  if (typeof descriptor.id !== 'string' || !isProbeCapabilityId(descriptor.id)) {
    throw new TypeError(
      `Invalid probe capability ID at index ${index}: ${String(descriptor.id)}`
    )
  }

  if (
    !PROBE_CAPABILITY_RISK_FLOORS.includes(
      descriptor.riskFloor as ProbeCapabilityRiskFloor
    )
  ) {
    throw new TypeError(
      `Invalid risk floor for probe capability ${descriptor.id}: ${String(descriptor.riskFloor)}`
    )
  }

  if (
    typeof descriptor.description !== 'string' ||
    descriptor.description.trim().length === 0
  ) {
    throw new TypeError(
      `Probe capability ${descriptor.id} must have a non-empty description.`
    )
  }

  return Object.freeze({
    id: descriptor.id,
    riskFloor: descriptor.riskFloor,
    description: descriptor.description.trim()
  })
}

/**
 * Trusted, immutable catalog of capability semantics.
 *
 * The complete descriptor set is supplied by the composition root. There is
 * deliberately no register or mutation method: unknown IDs remain unknown for
 * the lifetime of the catalog and must be rejected by DefinitionRegistry.
 */
export class ProbeCapabilityCatalog {
  readonly #byId: ReadonlyMap<string, Readonly<ProbeCapabilityDescriptor>>
  readonly #ordered: readonly Readonly<ProbeCapabilityDescriptor>[]

  constructor(descriptors: readonly ProbeCapabilityDescriptor[]) {
    if (!Array.isArray(descriptors)) {
      throw new TypeError('Probe capability descriptors must be an array.')
    }

    const byId = new Map<string, Readonly<ProbeCapabilityDescriptor>>()

    descriptors.forEach((input, index) => {
      const descriptor = parseDescriptor(input, index)
      if (byId.has(descriptor.id)) {
        throw new Error(`Duplicate probe capability ID: ${descriptor.id}`)
      }
      byId.set(descriptor.id, descriptor)
    })

    this.#byId = byId
    this.#ordered = Object.freeze(
      [...byId.values()].sort((left, right) => left.id.localeCompare(right.id))
    )
    Object.freeze(this)
  }

  has(id: string): boolean {
    return isProbeCapabilityId(id) && this.#byId.has(id)
  }

  get(id: string): Readonly<ProbeCapabilityDescriptor> | undefined {
    if (!isProbeCapabilityId(id)) {
      return undefined
    }
    return this.#byId.get(id)
  }

  list(): readonly Readonly<ProbeCapabilityDescriptor>[] {
    return this.#ordered
  }
}

export const BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS = Object.freeze([
  Object.freeze({
    id: 'inventory.offline-import',
    riskFloor: 'l0',
    description: 'Import and inventory already captured material without target I/O.'
  }),
  Object.freeze({
    id: 'evidence.existing-response-analysis',
    riskFloor: 'l0',
    description: 'Analyze an existing response as evidence without issuing a new request.'
  }),
  Object.freeze({
    id: 'http.reviewed-read',
    riskFloor: 'l1',
    description: 'Issue a reviewed, bounded, read-only HTTP request.'
  }),
  Object.freeze({
    id: 'http.identity-read-compare',
    riskFloor: 'l1',
    description: 'Compare bounded read-only HTTP responses between authorized test identities.'
  }),
  Object.freeze({
    id: 'browser.offline-replay',
    riskFloor: 'l1',
    description: 'Replay captured content in an isolated browser with external network access disabled.'
  }),
  Object.freeze({
    id: 'browser.mediated-read',
    riskFloor: 'l1',
    description: 'Perform a policy-mediated, bounded, read-only browser interaction.'
  }),
  Object.freeze({
    id: 'oob.controlled-observe',
    riskFloor: 'l1',
    description: 'Observe a bounded callback through an AgentGo-controlled out-of-band service.'
  }),
  Object.freeze({
    id: 'http.test-object-write',
    riskFloor: 'l2',
    description: 'Write only to an owned disposable TestObject under per-action approval and cleanup.'
  })
] as const satisfies readonly ProbeCapabilityDescriptor[])

/**
 * Closed Day 2 catalog. Catalog membership is not runtime support or an
 * ActivationCatalog qualification record.
 */
export const DEFAULT_PROBE_CAPABILITY_CATALOG = new ProbeCapabilityCatalog(
  BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS
)
