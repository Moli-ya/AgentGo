import { createHash } from 'node:crypto'
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

  it('provides a canonical, order-independent SHA-256 snapshot', () => {
    const descriptors: readonly ProbeCapabilityDescriptor[] = [
      {
        id: 'test.reviewed-read',
        riskFloor: 'l1',
        description: 'Reviewed read.'
      },
      {
        id: 'test.offline-analysis',
        riskFloor: 'l0',
        description: 'Offline analysis.'
      }
    ]
    const forward = new ProbeCapabilityCatalog(descriptors).snapshot()
    const reverse = new ProbeCapabilityCatalog([...descriptors].reverse()).snapshot()

    expect(forward).toEqual(reverse)
    expect(forward.canonicalSnapshotJson).toBe(
      '{"descriptors":[{"description":"Offline analysis.","id":"test.offline-analysis","riskFloor":"l0"},{"description":"Reviewed read.","id":"test.reviewed-read","riskFloor":"l1"}]}'
    )
    expect(forward.snapshotHash).toBe(
      createHash('sha256').update(forward.canonicalSnapshotJson, 'utf8').digest('hex')
    )
  })

  it('freezes and reuses the audit snapshot without opening catalog membership', () => {
    const snapshot = DEFAULT_PROBE_CAPABILITY_CATALOG.snapshot()

    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.snapshot()).toBe(snapshot)
    expect(snapshot.descriptors).toBe(DEFAULT_PROBE_CAPABILITY_CATALOG.list())
    expect(snapshot.descriptors.map(({ id }) => id)).toEqual(
      DEFAULT_PROBE_CAPABILITY_CATALOG.list().map(({ id }) => id)
    )
    expect(Object.isFrozen(snapshot)).toBe(true)
    expect(Object.isFrozen(snapshot.descriptors)).toBe(true)
    expect(Reflect.set(snapshot, 'snapshotHash', '0'.repeat(64))).toBe(false)
    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.has('http.not-registered')).toBe(false)
    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.get('http.not-registered')).toBeUndefined()
  })

  it('pins the built-in Day 2 catalog snapshot hash', () => {
    expect(DEFAULT_PROBE_CAPABILITY_CATALOG.snapshot().snapshotHash).toBe(
      'd7f3aa70efd0b55c981e7d5a105e097b32c95d558eeb5e7b7645f17e490a2792'
    )
  })
})
