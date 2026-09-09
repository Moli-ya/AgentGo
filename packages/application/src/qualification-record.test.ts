import { describe, expect, it } from 'vitest'
import { QualificationRecordSchema } from '@agentgo/contracts'
import { DefinitionRegistry } from '@agentgo/domain'
import { DEFAULT_PROBE_CAPABILITY_CATALOG } from '@agentgo/security-policy'
import { createPinnedLegacyV1QualificationRecords } from './legacy-v1-qualification-records'
import {
  computeLegacyV1PolicyHash,
  evaluateQualificationRecord,
  sealQualificationRecord
} from './qualification-record'
import { RecordBackedActivationCatalog } from './record-backed-activation-catalog'
import { createVulnerabilityBundles } from './vulnerability-bundles'
import { createVulnerabilityPlatform } from './vulnerability-platform'
import { RegisteredOnlyActivationCatalog } from './vulnerability-execution-gate'

describe('Record-backed activation', () => {
  it('qualifies the four legacy techniques from pinned records without the compatibility allowlist', () => {
    const platform = createVulnerabilityPlatform()
    const qualified = platform.activationCatalog
      .list()
      .filter((view) => view.activationStatus === 'qualified')
    expect(qualified).toHaveLength(5)
    expect(
      platform.activationCatalog
        .list()
        .find((view) => view.techniqueId === 'security.headers.baseline')
    ).toMatchObject({ activationStatus: 'qualified' })
    expect(
      platform.activationCatalog
        .list()
        .find((view) => view.techniqueId === 'security.headers.existing-response-audit')
    ).toMatchObject({ activationStatus: 'registered' })
    expect(
      platform.executionGate.requireExecutableFamily('sqli', 'attested-fixture')
    ).toMatchObject({
      authorization: 'qualified'
    })
  })

  it('ignores hash-mutated, expired, or unverifiable records', () => {
    const platform = createVulnerabilityPlatform()
    const policyCatalogHash = computeLegacyV1PolicyHash(platform.capabilityCatalog)
    const [record] = createPinnedLegacyV1QualificationRecords({
      definitionSnapshotHash: platform.definitionSnapshot.snapshotHash,
      policyCatalogHash
    })
    expect(record).toBeDefined()
    const { recordHash: _recordHash, ...payload } = record!

    const mutated = QualificationRecordSchema.parse({
      ...record,
      definitionHash: '0'.repeat(64)
    })
    expect(
      evaluateQualificationRecord({
        record: mutated,
        registry: platform.definitionRegistry,
        expectedBuildHash: record!.buildHash
      })
    ).toBe('hash-mismatch')

    const expired = sealQualificationRecord({
      ...payload,
      expiresAt: '2020-01-01T00:00:00.000Z'
    })
    expect(
      evaluateQualificationRecord({
        record: expired,
        registry: platform.definitionRegistry,
        now: new Date('2026-08-20T00:00:00.000Z'),
        expectedBuildHash: record!.buildHash
      })
    ).toBe('expired')

    const registry = new DefinitionRegistry(DEFAULT_PROBE_CAPABILITY_CATALOG)
    for (const bundle of createVulnerabilityBundles()) {
      registry.registerBundle(bundle)
    }
    registry.freeze()
    const catalog = new RecordBackedActivationCatalog({
      registry,
      records: [mutated],
      policyCatalogHash
    })
    expect(catalog.acceptedRecords).toHaveLength(0)
    expect(
      catalog.get({
        moduleId: record!.moduleId,
        moduleVersion: record!.moduleVersion,
        techniqueId: record!.techniqueId,
        techniqueVersion: record!.techniqueVersion
      })
    ).toMatchObject({ activationStatus: 'registered' })
    expect(new RegisteredOnlyActivationCatalog(registry).list()).toHaveLength(17)
  })
})
