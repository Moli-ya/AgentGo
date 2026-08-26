import { readFileSync } from 'node:fs'
import {
  BenchmarkSuiteManifestSchema,
  EVALUATION_CORE_META_SUITE_ID,
  GroundTruthManifestSchema,
  LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
  LEGACY_V1_SUITE_ID,
  LOCAL_FIXTURE_VERSION,
  isLegacyV1VulnerabilityFamily,
  type BenchmarkSuiteManifest,
  type GroundTruthCase,
  type EvaluationGroundTruthCase,
  type GroundTruthManifest,
  type LegacyV1VulnerabilityFamily
} from '@agentgo/contracts'
import {
  LEGACY_V1_EVIDENCE_ROLES,
  LEGACY_V1_MODULE_VERSIONS,
  LEGACY_V1_TECHNIQUE_IDS
} from '@agentgo/application'
import { localFixtureAttestationProfile } from './local-fixture'

const FORBIDDEN_LEGACY_CAPABILITIES = ['http.test-object-write'] as const

const attestation = {
  fixtureId: localFixtureAttestationProfile().fixtureId,
  fixtureVersion: localFixtureAttestationProfile().fixtureVersion,
  bindAddress: localFixtureAttestationProfile().bindAddress,
  portPolicy: localFixtureAttestationProfile().portPolicy,
  outboundPolicy: localFixtureAttestationProfile().outboundPolicy,
  resetPolicy: localFixtureAttestationProfile().resetPolicy
}

export function loadCheckedInLegacyV1Manifest(): GroundTruthManifest {
  return GroundTruthManifestSchema.parse(
    JSON.parse(
      readFileSync(
        new URL('../../../benchmarks/v1-ground-truth.json', import.meta.url),
        'utf8'
      )
    )
  )
}

function toEvaluationGroundTruthCase(
  item: GroundTruthCase,
  family: LegacyV1VulnerabilityFamily
): EvaluationGroundTruthCase {
  return {
    caseId: item.caseId,
    name: item.name,
    targetVersion: item.targetVersion,
    familyId: family,
    techniqueId: LEGACY_V1_TECHNIQUE_IDS[family],
    moduleVersion: LEGACY_V1_MODULE_VERSIONS[family],
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    category: item.expectedVerdict === 'confirmed' ? 'positive' : 'negative',
    expectedVerdict: item.expectedVerdict,
    protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
    selectorKind: 'query',
    requiredEvidenceRoles: [...LEGACY_V1_EVIDENCE_ROLES[family]],
    identityRequirement:
      family === 'idor' ? 'two-test-identities' : 'single-test-identity',
    workflowRequirement: 'none',
    testObjectRequirement: 'none',
    riskLevel: 'l1',
    maxRequests: 30,
    forbiddenCapabilityIds: [...FORBIDDEN_LEGACY_CAPABILITIES],
    environment: 'attested-fixture',
    executable: true,
    endpoint: item.endpoint,
    parameter: item.parameter,
    confirmationRule: item.confirmationRule,
    resetProcedure: item.resetProcedure,
    forbiddenActions: item.forbiddenActions,
    source: item.source,
    license: item.license,
    reviewer: item.reviewer
  }
}

export function createLegacyV1BenchmarkSuites(
  manifest: GroundTruthManifest = loadCheckedInLegacyV1Manifest()
): readonly BenchmarkSuiteManifest[] {
  const families: LegacyV1VulnerabilityFamily[] = [
    'sqli',
    'xss',
    'ssrf',
    'idor'
  ]
  return Object.freeze(
    families.map((family) => {
      const cases = manifest.cases.filter((item) => item.family === family)
      if (cases.some((item) => !isLegacyV1VulnerabilityFamily(item.family))) {
        throw new Error(`Legacy suite ${family} contains a non-legacy family.`)
      }
      return BenchmarkSuiteManifestSchema.parse({
        schemaVersion: 'agentgo-benchmark-suite/1.0',
        suiteId: LEGACY_V1_SUITE_ID,
        suiteVersion: LEGACY_V1_MODULE_VERSIONS[family],
        familyId: family,
        techniqueId: LEGACY_V1_TECHNIQUE_IDS[family],
        moduleVersion: LEGACY_V1_MODULE_VERSIONS[family],
        fixtureVersion: LOCAL_FIXTURE_VERSION,
        protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
        selectorKind: 'query',
        allowedMaturities: ['active-l1'],
        environment: 'attested-fixture',
        requiredCaseCategories: ['positive', 'negative'],
        attestation,
        cases: cases.map((item) => toEvaluationGroundTruthCase(item, family))
      })
    })
  )
}

function metaCase(
  overrides: Pick<
    EvaluationGroundTruthCase,
    'caseId' | 'name' | 'category' | 'expectedVerdict' | 'executable'
  > &
    Partial<Pick<EvaluationGroundTruthCase, 'expectedReasonCode'>>
): EvaluationGroundTruthCase {
  return {
    targetVersion: LOCAL_FIXTURE_VERSION,
    familyId: 'sqli',
    techniqueId: LEGACY_V1_TECHNIQUE_IDS.sqli,
    moduleVersion: LEGACY_V1_MODULE_VERSIONS.sqli,
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
    selectorKind: 'query',
    requiredEvidenceRoles: [...LEGACY_V1_EVIDENCE_ROLES.sqli],
    identityRequirement: 'single-test-identity',
    workflowRequirement: 'none',
    testObjectRequirement: 'none',
    riskLevel: 'l1',
    maxRequests: 30,
    forbiddenCapabilityIds: [...FORBIDDEN_LEGACY_CAPABILITIES],
    environment: 'attested-fixture',
    confirmationRule: 'sqli-boolean-differential@1.0.0',
    resetProcedure: 'reset the fixture namespace only',
    forbiddenActions: ['destructive writes'],
    source: 'AgentGo evaluation-core meta suite',
    license: 'project-internal-test-data',
    reviewer: 'project-team',
    ...overrides
  }
}

export function createEvaluationCoreMetaSuite(): BenchmarkSuiteManifest {
  return BenchmarkSuiteManifestSchema.parse({
    schemaVersion: 'agentgo-benchmark-suite/1.0',
    suiteId: EVALUATION_CORE_META_SUITE_ID,
    suiteVersion: '1.0.0',
    familyId: 'sqli',
    techniqueId: LEGACY_V1_TECHNIQUE_IDS.sqli,
    moduleVersion: LEGACY_V1_MODULE_VERSIONS.sqli,
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
    selectorKind: 'query',
    allowedMaturities: ['active-l1'],
    environment: 'attested-fixture',
    requiredCaseCategories: [
      'positive',
      'negative',
      'inconclusive',
      'policy-denied',
      'version-mismatch',
      'cleanup-failure'
    ],
    attestation,
    cases: [
      metaCase({
        caseId: 'meta-positive',
        name: 'Evaluation core positive',
        category: 'positive',
        expectedVerdict: 'confirmed',
        executable: true
      }),
      metaCase({
        caseId: 'meta-negative',
        name: 'Evaluation core negative',
        category: 'negative',
        expectedVerdict: 'not-confirmed',
        executable: true
      }),
      metaCase({
        caseId: 'meta-inconclusive',
        name: 'Evaluation core inconclusive',
        category: 'inconclusive',
        expectedVerdict: 'inconclusive',
        executable: true
      }),
      metaCase({
        caseId: 'meta-policy-denied',
        name: 'Evaluation core policy denied',
        category: 'policy-denied',
        expectedVerdict: 'inconclusive',
        expectedReasonCode: 'out-of-scope',
        executable: true
      }),
      metaCase({
        caseId: 'meta-version-mismatch',
        name: 'Evaluation core version mismatch',
        category: 'version-mismatch',
        expectedVerdict: 'inconclusive',
        expectedReasonCode: 'fixture-version-mismatch',
        executable: true
      }),
      metaCase({
        caseId: 'meta-cleanup-failure',
        name: 'Evaluation core reserved cleanup-failure',
        category: 'cleanup-failure',
        expectedVerdict: 'inconclusive',
        executable: false
      })
    ]
  })
}
