import {
  LEGACY_V1_FAMILY_IDS,
  LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
  LEGACY_V1_SUITE_ID,
  LOCAL_FIXTURE_VERSION,
  QUALIFICATION_RECORD_ISSUED_AT,
  type QualificationRecord
} from '@agentgo/contracts'
import {
  LEGACY_V1_MODULE_VERSIONS,
  LEGACY_V1_RUNTIME_BINDINGS,
  LEGACY_V1_TECHNIQUE_IDS
} from './vulnerability-bundles'
import {
  computeQualificationBuildHash,
  sealQualificationRecord
} from './qualification-record'

export const LEGACY_V1_QUALIFICATION_PINS = Object.freeze({
  definitionSnapshotHash:
    'eb92ca5eb4dc6e1aa7b661079863d44283fda3a3083f02c62d349ef714116521',
  policyCatalogHash:
    'a36cad68217b72a76df3e235ad6010a9264296bd41c46a9c08dfe989a773f449',
  fixtureAttestationHash:
    'b4d2ebebb9dfaf72c765eba032458ba306ad4f9674d954e40e5db3a80d3df0a0',
  buildHash:
    'fd20266c1a141563b25a2de9f61c22d31508228b998ff8b906be25170038f1e4',
  suiteHashes: Object.freeze({
    sqli: 'b4ec8e92759620d98c1b9205c29e7a2e2e3b00a00f0bbddf9ad7d4f4a730200c',
    xss: 'a496c5ba5aa119d3ac8cb97b0869aced18f5c798bfeaed419338c445a416e0fa',
    ssrf: 'c2f334e3735aeec2fa676f268cdff1ef17405aee8b63ceace160cdc6e83501fa',
    idor: 'd4db0cada8e7d67f142c92cf4aa0b8df63b3552362c9dd88de221144640daa8c'
  })
})

export function createPinnedLegacyV1QualificationRecords(input: {
  definitionSnapshotHash: string
  policyCatalogHash: string
}): readonly QualificationRecord[] {
  if (
    input.definitionSnapshotHash !==
    LEGACY_V1_QUALIFICATION_PINS.definitionSnapshotHash
  ) {
    throw new Error(
      'Definition snapshot hash drifted; pinned qualification records are invalid.'
    )
  }
  if (
    input.policyCatalogHash !== LEGACY_V1_QUALIFICATION_PINS.policyCatalogHash
  ) {
    throw new Error(
      'Capability catalog hash drifted; pinned qualification records are invalid.'
    )
  }
  const buildHash = computeQualificationBuildHash({
    definitionSnapshotHash: input.definitionSnapshotHash,
    policyCatalogHash: input.policyCatalogHash
  })
  if (buildHash !== LEGACY_V1_QUALIFICATION_PINS.buildHash) {
    throw new Error(
      'Qualification build hash drifted; pinned qualification records are invalid.'
    )
  }

  return Object.freeze(
    LEGACY_V1_FAMILY_IDS.map((familyId) => {
      const binding = LEGACY_V1_RUNTIME_BINDINGS.find(
        (candidate) => candidate.familyId === familyId
      )
      if (!binding) {
        throw new Error(`Missing legacy runtime binding for ${familyId}.`)
      }
      return sealQualificationRecord({
        schemaVersion: 'agentgo-qualification-record/1.0',
        familyId,
        techniqueId: LEGACY_V1_TECHNIQUE_IDS[familyId],
        techniqueVersion: LEGACY_V1_MODULE_VERSIONS[familyId],
        moduleId: binding.moduleId,
        moduleVersion: binding.moduleVersion,
        definitionHash: binding.definitionHash,
        definitionSnapshotHash: LEGACY_V1_QUALIFICATION_PINS.definitionSnapshotHash,
        buildHash: LEGACY_V1_QUALIFICATION_PINS.buildHash,
        suiteId: LEGACY_V1_SUITE_ID,
        suiteVersion: LEGACY_V1_MODULE_VERSIONS[familyId],
        suiteHash: LEGACY_V1_QUALIFICATION_PINS.suiteHashes[familyId],
        fixtureVersion: LOCAL_FIXTURE_VERSION,
        fixtureAttestationHash:
          LEGACY_V1_QUALIFICATION_PINS.fixtureAttestationHash,
        policyCatalogHash: LEGACY_V1_QUALIFICATION_PINS.policyCatalogHash,
        protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
        selectorKind: 'query',
        resultClass: 'self-built-fixture',
        result: 'passed',
        qualifiedEnvironments: [
          'attested-fixture',
          'authorized-test-environment',
          'authorized-real-target'
        ],
        issuedAt: QUALIFICATION_RECORD_ISSUED_AT
      })
    })
  )
}
