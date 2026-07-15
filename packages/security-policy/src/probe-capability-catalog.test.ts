import { describe, expect, it } from 'vitest'
import {
  BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS,
  DEFAULT_PROBE_CAPABILITY_CATALOG,
  ProbeCapabilityCatalog,
  isProbeCapabilityId,
  type ProbeCapabilityDescriptor
} from './probe-capability-catalog'

describe('ProbeCapabilityCatalog', () => {
  it('provides the closed Day 2 capability set without implying activation', () => {
    const expected = [
      'browser.mediated-read',
      'browser.offline-replay',
      'evidence.existing-response-analysis',
      'http.identity-read-compare',
      'http.reviewed-read',
      'http.test-object-write',
      'inventory.offline-import',
      'oob.controlled-observe'
    ]

    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.list().map(({ id }) => id)).toEqual(
      expected
    )
    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.has('http.reviewed-read')).toBe(true)
    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.get('http.test-object-write')).toEqual({
      id: 'http.test-object-write',
      riskFloor: 'l2',
      description:
        'Write only to an owned disposable TestObject under per-action approval and cleanup.'
    })
    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.has('http.not-registered')).toBe(false)
    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.get('http.not-registered')).toBeUndefined()
  })

  it('validates the stable lowercase dotted ID format', () => {
    expect(isProbeCapabilityId('http.identity-read-compare')).toBe(true)
    expect(isProbeCapabilityId('http')).toBe(false)
    expect(isProbeCapabilityId('HTTP.reviewed-read')).toBe(false)
    expect(isProbeCapabilityId('http..reviewed-read')).toBe(false)
    expect(isProbeCapabilityId('http.reviewed_read')).toBe(false)

    expect(
      () =>
        new ProbeCapabilityCatalog([
          {
            id: 'HTTP.reviewed-read',
            riskFloor: 'l1',
            description: 'Invalid uppercase namespace.'
          }
        ])
    ).toThrow(/Invalid probe capability ID/)
  })

  it('rejects duplicate IDs and malformed descriptor fields', () => {
    const descriptor: ProbeCapabilityDescriptor = {
      id: 'test.reviewed-read',
      riskFloor: 'l1',
      description: 'Test capability.'
    }

    expect(() => new ProbeCapabilityCatalog([descriptor, descriptor])).toThrow(
      'Duplicate probe capability ID: test.reviewed-read'
    )
    expect(
      () =>
        new ProbeCapabilityCatalog([
          { ...descriptor, description: '   ' }
        ])
    ).toThrow(/non-empty description/)
    expect(
      () =>
        new ProbeCapabilityCatalog([
          { ...descriptor, riskFloor: 'l3' as 'l1' }
        ])
    ).toThrow(/Invalid risk floor/)
  })

  it('defensively copies and freezes the catalog, list, and descriptors', () => {
    const source = {
      id: 'test.offline-analysis',
      riskFloor: 'l0' as const,
      description: 'Original description.'
    }
    const catalog = new ProbeCapabilityCatalog([source])
    source.description = 'Changed after construction.'

    const listed = catalog.list()
    const descriptor = listed[0]

    expect(Object.isFrozen(catalog)).toBe(true)
    expect(Object.isFrozen(listed)).toBe(true)
    expect(Object.isFrozen(descriptor)).toBe(true)
    expect(descriptor?.description).toBe('Original description.')
    expect(Reflect.set(descriptor ?? {}, 'description', 'Mutated.')).toBe(false)
    expect(() => (listed as ProbeCapabilityDescriptor[]).push(source)).toThrow()
  })

  it('does not expose mutable built-in descriptor inputs', () => {
    expect(Object.isFrozen(BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS)).toBe(true)
    expect(
      BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS.every((descriptor) =>
        Object.isFrozen(descriptor)
      )
    ).toBe(true)
  })
})
