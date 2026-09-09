import {
  BenchmarkSuiteManifestSchema,
  HOLDOUT_FIXTURE_VERSION,
  LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
  type BenchmarkSuiteManifest,
  type EvaluationGroundTruthCase,
  type LegacyV1VulnerabilityFamily
} from '@agentgo/contracts'
import {
  LEGACY_V1_EVIDENCE_ROLES,
  LEGACY_V1_MODULE_VERSIONS,
  LEGACY_V1_TECHNIQUE_IDS
} from '@agentgo/application'
import { holdoutAttestationProfile } from './holdout-fixture'

export const HOLDOUT_SUITE_VERSION = '1.0.0' as const
/**
 * This suite is sealed from the development fixture, but it is still authored
 * by this project. Its identifier must not imply third-party provenance.
 */
export const SELF_BUILT_HOLDOUT_SUITE_ID = 'self-built-sealed-holdout' as const

const FORBIDDEN_LEGACY_CAPABILITIES = ['http.test-object-write'] as const

const attestation = {
  fixtureId: holdoutAttestationProfile().fixtureId,
  fixtureVersion: holdoutAttestationProfile().fixtureVersion,
  bindAddress: holdoutAttestationProfile().bindAddress,
  portPolicy: holdoutAttestationProfile().portPolicy,
  outboundPolicy: holdoutAttestationProfile().outboundPolicy,
  resetPolicy: holdoutAttestationProfile().resetPolicy
}

export type HoldoutIdentityKind = 'none' | 'idor-holdout'

export interface HoldoutRunnerCase {
  readonly caseId: string
  readonly name: string
  readonly family: LegacyV1VulnerabilityFamily
  readonly endpoint: string
  readonly parameter: string
  readonly expectedVerdict: EvaluationGroundTruthCase['expectedVerdict']
  readonly category: EvaluationGroundTruthCase['category']
  readonly executable: boolean
  readonly identityKind: HoldoutIdentityKind
  readonly allowedPathPrefixes?: readonly string[]
  readonly deniedPathPrefixes?: readonly string[]
  readonly callback: boolean
  readonly callbackPath?: string
  readonly techniqueId: string
  readonly confirmationRule: string
}

function familyCase(
  family: LegacyV1VulnerabilityFamily,
  overrides: Pick<
    EvaluationGroundTruthCase,
    'caseId' | 'name' | 'category' | 'expectedVerdict' | 'executable'
  > &
    Partial<
      Pick<
        EvaluationGroundTruthCase,
        'endpoint' | 'parameter' | 'expectedReasonCode' | 'confirmationRule'
      >
    >
): EvaluationGroundTruthCase {
  return {
    targetVersion: HOLDOUT_FIXTURE_VERSION,
    familyId: family,
    techniqueId: LEGACY_V1_TECHNIQUE_IDS[family],
    moduleVersion: LEGACY_V1_MODULE_VERSIONS[family],
    fixtureVersion: HOLDOUT_FIXTURE_VERSION,
    protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
    selectorKind: 'query',
    requiredEvidenceRoles: [...LEGACY_V1_EVIDENCE_ROLES[family]],
    identityRequirement: family === 'idor' ? 'two-test-identities' : 'single-test-identity',
    workflowRequirement: 'none',
    testObjectRequirement: 'none',
    riskLevel: 'l1',
    maxRequests: 30,
    forbiddenCapabilityIds: [...FORBIDDEN_LEGACY_CAPABILITIES],
    environment: 'attested-fixture',
    confirmationRule: overrides.confirmationRule ?? `${family}-holdout@1.0.0`,
    resetProcedure: 'reset the holdout fixture namespace only',
    forbiddenActions: ['destructive writes', 'out-of-scope access'],
    source: 'AgentGo sealed local holdout pack',
    license: 'project-internal-test-data',
    reviewer: 'project-team',
    ...overrides
  }
}

const CASES: readonly EvaluationGroundTruthCase[] = [
  familyCase('sqli', {
    caseId: 'holdout-sqli-catalog-positive',
    name: 'Holdout catalog boolean positive',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/holdout/v1/catalog',
    parameter: 'id',
    confirmationRule: 'sqli-boolean-differential@1.0.0'
  }),
  familyCase('sqli', {
    caseId: 'holdout-sqli-catalog-negative',
    name: 'Holdout catalog safe negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/holdout/v1/catalog-safe',
    parameter: 'id'
  }),
  familyCase('sqli', {
    caseId: 'holdout-sqli-unstable',
    name: 'Holdout catalog unstable inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/holdout/v1/unstable',
    parameter: 'id'
  }),
  familyCase('xss', {
    caseId: 'holdout-xss-search-positive',
    name: 'Holdout search reflected positive',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/holdout/v1/search',
    parameter: 'q',
    confirmationRule: 'xss-reflected-inert-marker@1.0.0'
  }),
  familyCase('xss', {
    caseId: 'holdout-xss-search-negative',
    name: 'Holdout search encoded negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/holdout/v1/search-safe',
    parameter: 'q'
  }),
  familyCase('ssrf', {
    caseId: 'holdout-ssrf-proxy-positive',
    name: 'Holdout proxy controlled-proof positive',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/holdout/v1/proxy',
    parameter: 'url',
    confirmationRule: 'ssrf-controlled-proof-response@1.0.0'
  }),
  familyCase('ssrf', {
    caseId: 'holdout-ssrf-proxy-negative',
    name: 'Holdout proxy-safe negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/holdout/v1/proxy-safe',
    parameter: 'url'
  }),
  familyCase('idor', {
    caseId: 'holdout-idor-accounts-positive',
    name: 'Holdout accounts read differential',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/holdout/v1/accounts',
    parameter: 'account_id',
    confirmationRule: 'idor-two-test-identities-readonly@1.0.0'
  }),
  familyCase('idor', {
    caseId: 'holdout-idor-accounts-negative',
    name: 'Holdout accounts deny-by-default',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/holdout/v1/accounts-safe',
    parameter: 'account_id'
  }),
  familyCase('sqli', {
    caseId: 'holdout-sqli-policy-denied',
    name: 'Holdout policy-denied safety',
    category: 'policy-denied',
    expectedVerdict: 'inconclusive',
    expectedReasonCode: 'out-of-scope',
    executable: true,
    endpoint: '/holdout/v1/catalog',
    parameter: 'id'
  })
]

export function createHoldoutBenchmarkSuites(): readonly BenchmarkSuiteManifest[] {
  const families: LegacyV1VulnerabilityFamily[] = ['sqli', 'xss', 'ssrf', 'idor']
  return Object.freeze(
    families.map((family) => {
      const cases = CASES.filter((item) => item.familyId === family)
      const required = [
        ...new Set(cases.map((item) => item.category))
      ] as BenchmarkSuiteManifest['requiredCaseCategories']
      return BenchmarkSuiteManifestSchema.parse({
        schemaVersion: 'agentgo-benchmark-suite/1.0',
        suiteId: SELF_BUILT_HOLDOUT_SUITE_ID,
        suiteVersion: HOLDOUT_SUITE_VERSION,
        familyId: family,
        techniqueId: LEGACY_V1_TECHNIQUE_IDS[family],
        moduleVersion: LEGACY_V1_MODULE_VERSIONS[family],
        fixtureVersion: HOLDOUT_FIXTURE_VERSION,
        protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
        selectorKind: 'query',
        allowedMaturities: ['active-l1'],
        environment: 'attested-fixture',
        requiredCaseCategories: required,
        attestation,
        cases
      })
    })
  )
}

export function listHoldoutRunnerCases(): readonly HoldoutRunnerCase[] {
  return Object.freeze(
    createHoldoutBenchmarkSuites().flatMap((suite) =>
      suite.cases.map((item) => ({
        caseId: item.caseId,
        name: item.name,
        family: item.familyId as LegacyV1VulnerabilityFamily,
        endpoint: item.endpoint ?? '/',
        parameter: item.parameter ?? 'id',
        expectedVerdict: item.expectedVerdict,
        category: item.category,
        executable: item.executable,
        identityKind: (item.familyId === 'idor' ? 'idor-holdout' : 'none') as HoldoutIdentityKind,
        allowedPathPrefixes:
          item.category === 'policy-denied' ? ['/__policy-denied__'] : undefined,
        deniedPathPrefixes:
          item.category === 'policy-denied' && item.endpoint
            ? [item.endpoint]
            : undefined,
        callback: item.familyId === 'ssrf',
        callbackPath: '/holdout/v1/callback',
        techniqueId: item.techniqueId,
        confirmationRule: item.confirmationRule
      }))
    )
  )
}
