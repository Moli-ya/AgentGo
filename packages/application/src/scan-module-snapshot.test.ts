import {
  ScanModuleSnapshotDraftSchema,
  ScanModuleSnapshotRecordSchema,
  type ScanModuleSnapshotDraft,
  type ScanModuleSnapshotRecord
} from '@agentgo/contracts'
import {
  BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS,
  ProbeCapabilityCatalog
} from '@agentgo/security-policy'
import { describe, expect, it, vi } from 'vitest'
import {
  buildScanModuleSnapshotDrafts,
  computeScanModuleSnapshotHash,
  requireSealedScanModuleSnapshotSet,
  ScanModuleSnapshotError,
  verifyScanModuleSnapshots as verifyPersistedScanModuleSnapshots
} from './scan-module-snapshot'
import { createVulnerabilityPlatform } from './vulnerability-platform'

const CREATED_AT = '2026-07-17T00:00:00.000Z'
const SCAN_ID = 'scan-inventory'

function verifyScanModuleSnapshots(
  inputs: readonly ScanModuleSnapshotRecord[],
  familyIds: Parameters<typeof verifyPersistedScanModuleSnapshots>[2],
  environment: Parameters<typeof verifyPersistedScanModuleSnapshots>[3],
  platform: Parameters<typeof verifyPersistedScanModuleSnapshots>[4]
): void {
  verifyPersistedScanModuleSnapshots(
    inputs,
    SCAN_ID,
    familyIds,
    environment,
    platform
  )
}

function asRecords(
  drafts: readonly ScanModuleSnapshotDraft[]
): readonly ScanModuleSnapshotRecord[] {
  return drafts.map((draft, index) =>
    ScanModuleSnapshotRecordSchema.parse({
      id: `snapshot-${index}`,
      scanId: SCAN_ID,
      ...draft,
      snapshotHash: computeScanModuleSnapshotHash(draft),
      createdAt: CREATED_AT
    })
  )
}

function replaceDraft(
  record: ScanModuleSnapshotRecord,
  changes: Partial<ScanModuleSnapshotDraft>
): ScanModuleSnapshotRecord {
  const draft = ScanModuleSnapshotDraftSchema.parse({
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
    authorization: record.authorization,
    ...changes
  })
  return ScanModuleSnapshotRecordSchema.parse({
    id: record.id,
    scanId: record.scanId,
    ...draft,
    snapshotHash: computeScanModuleSnapshotHash(draft),
    createdAt: record.createdAt
  })
}

function expectSnapshotError(
  action: () => unknown,
  code: ScanModuleSnapshotError['code']
): void {
  try {
    action()
    throw new Error(`Expected ${code}.`)
  } catch (error) {
    expect(error).toBeInstanceOf(ScanModuleSnapshotError)
    expect(error).toMatchObject({ code })
  }
}

describe('scan module snapshots', () => {
  it('requires an immutable sealed snapshot set before execution', () => {
    expect(() => requireSealedScanModuleSnapshotSet(true)).not.toThrow()
    expectSnapshotError(
      () => requireSealedScanModuleSnapshotSet(false),
      'snapshot-set-unsealed'
    )
  })

  it('builds immutable, binary-ordered drafts and verifies a network-free roundtrip', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const platform = createVulnerabilityPlatform()
    const first = buildScanModuleSnapshotDrafts(
      ['xss', 'sqli'],
      'authorized-real-target',
      platform
    )
    const second = buildScanModuleSnapshotDrafts(
      ['sqli', 'xss'],
      'authorized-real-target',
      platform
    )

    expect(first.map(({ familyId }) => familyId)).toEqual(['sqli', 'xss'])
    expect(first).toEqual(second)
    expect(Object.isFrozen(first)).toBe(true)
    expect(Object.isFrozen(first[0])).toBe(true)
    expect(Object.isFrozen(first[0]?.strategyRefs)).toBe(true)
    expect(Object.isFrozen(first[0]?.strategyRefs[0])).toBe(true)
    expect(Object.isFrozen(first[0]?.capabilityDescriptors)).toBe(true)
    expect(Object.isFrozen(first[0]?.capabilityDescriptors[0])).toBe(true)

    const records = asRecords(first)
    expect(() =>
      verifyScanModuleSnapshots(
        records,
        ['xss', 'sqli'],
        'authorized-real-target',
        platform
      )
    ).not.toThrow()
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  it('rejects a non-canonical self hash and strict-schema forgery', () => {
    const platform = createVulnerabilityPlatform()
    const [record] = asRecords(
      buildScanModuleSnapshotDrafts(
        ['sqli'],
        'authorized-real-target',
        platform
      )
    )
    expect(record).toBeDefined()

    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [{ ...record!, snapshotHash: '0'.repeat(64) }],
          ['sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-hash-mismatch'
    )
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [{ ...record!, forgedModuleVersion: '99.0.0' } as ScanModuleSnapshotRecord],
          ['sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-schema-invalid'
    )
  })

  it('rejects semantically valid snapshots bound to another scan', () => {
    const platform = createVulnerabilityPlatform()
    const records = asRecords(
      buildScanModuleSnapshotDrafts(
        ['sqli', 'xss'],
        'authorized-real-target',
        platform
      )
    )

    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          records.map((record) => ({ ...record, scanId: 'other-scan' })),
          ['sqli', 'xss'],
          'authorized-real-target',
          platform
        ),
      'snapshot-scan-mismatch'
    )
  })

  it('fails closed for missing, extra, and duplicate family snapshots', () => {
    const platform = createVulnerabilityPlatform()
    const records = asRecords(
      buildScanModuleSnapshotDrafts(
        ['sqli', 'xss'],
        'authorized-real-target',
        platform
      )
    )
    const [sqli] = records
    expect(sqli).toBeDefined()

    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          records.slice(0, 1),
          ['sqli', 'xss'],
          'authorized-real-target',
          platform
        ),
      'snapshot-family-set-mismatch'
    )
    const extra = replaceDraft(sqli!, { familyId: 'ssrf' })
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [...records, extra],
          ['sqli', 'xss'],
          'authorized-real-target',
          platform
        ),
      'snapshot-family-set-mismatch'
    )
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [...records, { ...sqli!, id: 'duplicate-sqli' }],
          ['sqli', 'xss'],
          'authorized-real-target',
          platform
        ),
      'snapshot-duplicate-family'
    )
    expectSnapshotError(
      () =>
        buildScanModuleSnapshotDrafts(
          ['sqli', 'sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-duplicate-family'
    )
  })

  it('rejects legacy-unknown, environment, authorization, and selected definition drift', () => {
    const platform = createVulnerabilityPlatform()
    const [record] = asRecords(
      buildScanModuleSnapshotDrafts(
        ['sqli'],
        'authorized-real-target',
        platform
      )
    )
    expect(record).toBeDefined()

    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [replaceDraft(record!, { environment: 'legacy-unknown' })],
          ['sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-legacy-environment'
    )
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [replaceDraft(record!, { environment: 'authorized-test-environment' })],
          ['sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-environment-mismatch'
    )
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [replaceDraft(record!, { authorization: 'legacy-v1-compatibility' })],
          ['sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-authorization-mismatch'
    )
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [replaceDraft(record!, { definitionHash: '0'.repeat(64) })],
          ['sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-definition-mismatch'
    )
  })

  it('rejects selected capability drift but permits unrelated global snapshot drift', () => {
    const platform = createVulnerabilityPlatform()
    const [record] = asRecords(
      buildScanModuleSnapshotDrafts(
        ['sqli'],
        'authorized-real-target',
        platform
      )
    )
    expect(record).toBeDefined()

    const descriptor = record!.capabilityDescriptors[0]
    expect(descriptor).toBeDefined()
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [
            replaceDraft(record!, {
              capabilityDescriptors: [
                {
                  ...descriptor!,
                  riskFloor: descriptor!.riskFloor === 'l1' ? 'l2' : 'l1'
                }
              ]
            })
          ],
          ['sqli'],
          'authorized-real-target',
          platform
        ),
      'snapshot-capability-mismatch'
    )

    const selectedSemanticDrift = createVulnerabilityPlatform(
      new ProbeCapabilityCatalog(
        BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS.map((capability) =>
          capability.id === 'http.reviewed-read'
            ? {
                ...capability,
                description: 'Changed semantics for the selected read capability.'
              }
            : capability
        )
      )
    )
    expectSnapshotError(
      () =>
        verifyScanModuleSnapshots(
          [record!],
          ['sqli'],
          'authorized-real-target',
          selectedSemanticDrift
        ),
      'snapshot-definition-unavailable'
    )

    const unrelatedCatalogDrift = createVulnerabilityPlatform(
      new ProbeCapabilityCatalog([
        ...BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS,
        {
          id: 'http.unrelated-read',
          riskFloor: 'l0',
          description: 'An unrelated capability added after the scan was created.'
        }
      ])
    )
    expect(() =>
      verifyScanModuleSnapshots(
        [record!],
        ['sqli'],
        'authorized-real-target',
        unrelatedCatalogDrift
      )
    ).not.toThrow()

    const globallyDrifted = replaceDraft(record!, {
      capabilitySnapshotHash: 'a'.repeat(64),
      registrySnapshotHash: 'b'.repeat(64)
    })
    expect(() =>
      verifyScanModuleSnapshots(
        [globallyDrifted],
        ['sqli'],
        'authorized-real-target',
        platform
      )
    ).not.toThrow()
  })
})
