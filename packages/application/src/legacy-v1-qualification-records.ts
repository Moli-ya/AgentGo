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
  LEGACY_V1_TECHNIQUE_IDS,
  SECURITY_HEADERS_MODULE_ID,
  SECURITY_HEADERS_MODULE_VERSION,
  SECURITY_HEADERS_RUNTIME_BINDING,
  SECURITY_HEADERS_TECHNIQUE_IDS
} from './vulnerability-bundles'
import {
  computeQualificationBuildHash,
  sealQualificationRecord
} from './qualification-record'

export const LEGACY_V1_QUALIFICATION_PINS = Object.freeze({
  definitionSnapshotHash:
    'bf80c70e1431dba2b62c4a34ea354d74262ae2df37d3b27049e6e740e1f2dfd7',
  policyCatalogHash:
    'a36cad68217b72a76df3e235ad6010a9264296bd41c46a9c08dfe989a773f449',
  fixtureAttestationHash:
    'b4d2ebebb9dfaf72c765eba032458ba306ad4f9674d954e40e5db3a80d3df0a0',
  buildHash:
    '1b1c185d7f96e6b52e45771c88b9920d31e2aed8c7fb89f4a7a24a52273404bf',
  suiteHashes: Object.freeze({
    sqli: '3afb1460fdfee638f95f487b1728d1901186211be28f7658420cdea5acab204f',
    xss: 'e43cc3b4ebad0975f0547a97b8297e61f85576e35cbb56ad4ac956996bbe480d',
    ssrf: 'b3271d66cf51aafcedb4668c23a874eaf444ab5ae9b857cbdde579232d3adeff',
    idor: 'b98e32c1709ec1d1596d0a43d197c9ba346dbb2e85ff3d9d0e3c7b7bf538817d',
    securityHeaders:
      '712a872d258ed82afb1ab9c482d1e84a8e077b114ffcc82671b2f300a14b83e8'
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

export function createPinnedSecurityHeadersQualificationRecord(input: {
  definitionSnapshotHash: string
  policyCatalogHash: string
}): QualificationRecord {
  if (
    input.definitionSnapshotHash !==
      LEGACY_V1_QUALIFICATION_PINS.definitionSnapshotHash ||
    input.policyCatalogHash !== LEGACY_V1_QUALIFICATION_PINS.policyCatalogHash
  ) {
    throw new Error(
      'Definition snapshot hash drifted; pinned qualification records are invalid.'
    )
  }
  return sealQualificationRecord({
    schemaVersion: 'agentgo-qualification-record/1.0',
    familyId: 'security.headers',
    techniqueId: SECURITY_HEADERS_TECHNIQUE_IDS.baseline,
    techniqueVersion: SECURITY_HEADERS_MODULE_VERSION,
    moduleId: SECURITY_HEADERS_MODULE_ID,
    moduleVersion: SECURITY_HEADERS_MODULE_VERSION,
    definitionHash: SECURITY_HEADERS_RUNTIME_BINDING.definitionHash,
    definitionSnapshotHash: LEGACY_V1_QUALIFICATION_PINS.definitionSnapshotHash,
    buildHash: LEGACY_V1_QUALIFICATION_PINS.buildHash,
    suiteId: 'security-headers-baseline',
    suiteVersion: SECURITY_HEADERS_MODULE_VERSION,
    suiteHash: LEGACY_V1_QUALIFICATION_PINS.suiteHashes.securityHeaders,
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    fixtureAttestationHash: LEGACY_V1_QUALIFICATION_PINS.fixtureAttestationHash,
    policyCatalogHash: LEGACY_V1_QUALIFICATION_PINS.policyCatalogHash,
    protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
    selectorKind: 'header',
    resultClass: 'self-built-fixture',
    result: 'passed',
    qualifiedEnvironments: [
      'attested-fixture',
      'authorized-test-environment',
      'authorized-real-target'
    ],
    issuedAt: QUALIFICATION_RECORD_ISSUED_AT
  })
}

export function createPinnedActivationRecords(input: {
  definitionSnapshotHash: string
  policyCatalogHash: string
}): readonly QualificationRecord[] {
  return Object.freeze([
    ...createPinnedLegacyV1QualificationRecords(input),
    createPinnedSecurityHeadersQualificationRecord(input)
  ])
}
