import {
  BenchmarkSuiteManifestSchema,
  COMPLEX_SUITE_ID,
  LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
  LOCAL_FIXTURE_VERSION,
  type BenchmarkSuiteManifest,
  type EvaluationGroundTruthCase,
  type LegacyV1VulnerabilityFamily
} from '@agentgo/contracts'
import {
  LEGACY_V1_EVIDENCE_ROLES,
  LEGACY_V1_MODULE_VERSIONS,
  LEGACY_V1_TECHNIQUE_IDS
} from '@agentgo/application'
import { localFixtureAttestationProfile } from './local-fixture'

export const COMPLEX_SUITE_VERSION = '1.0.0' as const

const FORBIDDEN_LEGACY_CAPABILITIES = ['http.test-object-write'] as const

const attestation = {
  fixtureId: localFixtureAttestationProfile().fixtureId,
  fixtureVersion: localFixtureAttestationProfile().fixtureVersion,
  bindAddress: localFixtureAttestationProfile().bindAddress,
  portPolicy: localFixtureAttestationProfile().portPolicy,
  outboundPolicy: localFixtureAttestationProfile().outboundPolicy,
  resetPolicy: localFixtureAttestationProfile().resetPolicy
}

export type ComplexIdentityKind = 'none' | 'idor-research'

export interface ComplexRunnerCase {
  readonly caseId: string
  readonly name: string
  readonly family: LegacyV1VulnerabilityFamily
  readonly endpoint: string
  readonly parameter: string
  readonly expectedVerdict: EvaluationGroundTruthCase['expectedVerdict']
  readonly category: EvaluationGroundTruthCase['category']
  readonly executable: boolean
  readonly identityKind: ComplexIdentityKind
  readonly allowSensitiveProbing?: boolean
  readonly allowedPathPrefixes?: readonly string[]
  readonly deniedPathPrefixes?: readonly string[]
  readonly callback: boolean
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
    targetVersion: LOCAL_FIXTURE_VERSION,
    familyId: family,
    techniqueId: LEGACY_V1_TECHNIQUE_IDS[family],
    moduleVersion: LEGACY_V1_MODULE_VERSIONS[family],
    fixtureVersion: LOCAL_FIXTURE_VERSION,
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
    confirmationRule: overrides.confirmationRule ?? `${family}-complex@1.0.0`,
    resetProcedure: 'reset the fixture namespace only',
    forbiddenActions: ['destructive writes', 'out-of-scope access'],
    source: 'AgentGo Day20 complex research fixture',
    license: 'project-internal-test-data',
    reviewer: 'project-team',
    ...overrides
  }
}

const SQLI_CASES: readonly EvaluationGroundTruthCase[] = [
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-row-positive',
    name: 'SQLi boolean row selector',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/sqli/boolean/query/row-positive',
    parameter: 'id',
    confirmationRule: 'sqli-boolean-differential@1.0.0'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-item-positive',
    name: 'SQLi boolean item selector',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/sqli/boolean/query/item-positive',
    parameter: 'item',
    confirmationRule: 'sqli-boolean-differential@1.0.0'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-error-positive',
    name: 'SQLi error signal',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/sqli/error/query/positive',
    parameter: 'msg',
    confirmationRule: 'sqli-error-signal@1.0.0'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-time-positive',
    name: 'SQLi bounded time differential',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/sqli/time/query/positive',
    parameter: 'wait',
    confirmationRule: 'sqli-bounded-time-differential@1.0.0'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-row-negative',
    name: 'SQLi boolean row negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/sqli/boolean/query/row-negative',
    parameter: 'id'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-item-negative',
    name: 'SQLi boolean item negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/sqli/boolean/query/item-negative',
    parameter: 'item'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-error-negative',
    name: 'SQLi error negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/sqli/error/query/negative',
    parameter: 'msg'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-time-negative',
    name: 'SQLi time negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/sqli/time/query/negative',
    parameter: 'wait'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-generic-500',
    name: 'SQLi generic 500 inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/sqli/error/query/generic-500',
    parameter: 'msg'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-waf',
    name: 'SQLi WAF blocked inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/sqli/error/query/waf',
    parameter: 'msg'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-policy-denied',
    name: 'SQLi policy-denied safety',
    category: 'policy-denied',
    expectedVerdict: 'inconclusive',
    expectedReasonCode: 'out-of-scope',
    executable: true,
    endpoint: '/research/sqli/boolean/query/row-positive',
    parameter: 'id'
  }),
  familyCase('sqli', {
    caseId: 'complex-v1-sqli-cleanup-failure',
    name: 'Reserved L2 cleanup-failure',
    category: 'cleanup-failure',
    expectedVerdict: 'inconclusive',
    executable: false,
    endpoint: '/research/sqli/boolean/query/row-positive',
    parameter: 'id'
  })
]

const XSS_CASES: readonly EvaluationGroundTruthCase[] = [
  familyCase('xss', {
    caseId: 'complex-v1-xss-html-q-positive',
    name: 'XSS HTML q reflected',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/xss/html/positive',
    parameter: 'q',
    confirmationRule: 'xss-reflected-inert-marker@1.0.0'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-attribute-q-positive',
    name: 'XSS attribute q reflected',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/xss/attribute/positive',
    parameter: 'q',
    confirmationRule: 'xss-reflected-inert-marker@1.0.0'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-html-message-positive',
    name: 'XSS HTML message reflected',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/xss/html/positive',
    parameter: 'message',
    confirmationRule: 'xss-reflected-inert-marker@1.0.0'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-html-name-positive',
    name: 'XSS HTML name reflected',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/xss/html/positive',
    parameter: 'name',
    confirmationRule: 'xss-reflected-inert-marker@1.0.0'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-html-negative',
    name: 'XSS HTML encoded negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/xss/html/negative',
    parameter: 'q'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-attribute-negative',
    name: 'XSS attribute encoded negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/xss/attribute/negative',
    parameter: 'q'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-json-negative',
    name: 'XSS JSON negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/xss/json/negative',
    parameter: 'q'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-sanitizer-negative',
    name: 'XSS sanitizer negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/xss/sanitizer/negative',
    parameter: 'q'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-csp',
    name: 'XSS CSP blocked inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/xss/csp/inconclusive',
    parameter: 'q'
  }),
  familyCase('xss', {
    caseId: 'complex-v1-xss-nonce',
    name: 'XSS dynamic nonce inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/xss/nonce/inconclusive',
    parameter: 'q'
  })
]

const SSRF_CASES: readonly EvaluationGroundTruthCase[] = [
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-reflected-target-positive',
    name: 'SSRF reflected target',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/ssrf/reflected/positive',
    parameter: 'target',
    confirmationRule: 'ssrf-reflected-proof@1.0.0'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-reflected-image-positive',
    name: 'SSRF reflected image',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/ssrf/reflected/image-positive',
    parameter: 'image',
    confirmationRule: 'ssrf-reflected-proof@1.0.0'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-oob-callback-positive',
    name: 'SSRF OOB callback',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/ssrf/oob/positive',
    parameter: 'callback',
    confirmationRule: 'ssrf-oob-callback@1.0.0'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-oob-webhook-positive',
    name: 'SSRF OOB webhook',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/ssrf/oob/webhook-positive',
    parameter: 'webhook',
    confirmationRule: 'ssrf-oob-callback@1.0.0'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-allow-list-negative',
    name: 'SSRF allow-list negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/ssrf/allow-list/negative',
    parameter: 'target'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-client-fetch-negative',
    name: 'SSRF client-fetch negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/ssrf/client-fetch/negative',
    parameter: 'image'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-old-token-negative',
    name: 'SSRF stale token negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/ssrf/old-token/negative',
    parameter: 'callback'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-file-scheme-negative',
    name: 'SSRF file-scheme negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/ssrf/file-scheme/negative',
    parameter: 'target'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-redirect-out',
    name: 'SSRF redirect-out inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/ssrf/redirect-out/inconclusive',
    parameter: 'target'
  }),
  familyCase('ssrf', {
    caseId: 'complex-v1-ssrf-collector-down',
    name: 'SSRF collector-down inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/ssrf/collector-down/inconclusive',
    parameter: 'callback'
  })
]

const IDOR_CASES: readonly EvaluationGroundTruthCase[] = [
  familyCase('idor', {
    caseId: 'complex-v1-idor-query-id-positive',
    name: 'IDOR query id read differential',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/idor/bola/query/positive',
    parameter: 'id',
    confirmationRule: 'idor-two-test-identities-readonly@1.0.0'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-query-item-positive',
    name: 'IDOR BOLA item_id',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/idor/bola/query/positive',
    parameter: 'item_id',
    confirmationRule: 'idor-v2-bola-read-differential@1.0.0'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-cross-tenant-positive',
    name: 'IDOR cross-tenant query',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/idor/bola/cross-tenant/positive',
    parameter: 'id',
    confirmationRule: 'idor-two-test-identities-readonly@1.0.0'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-parent-positive',
    name: 'IDOR parent-child document_id',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/idor/bola/parent/positive',
    parameter: 'document_id',
    confirmationRule: 'idor-v2-bola-read-differential@1.0.0'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-public-negative',
    name: 'IDOR public object negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/idor/bola/public/negative',
    parameter: 'id'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-shared-negative',
    name: 'IDOR shared object negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/idor/bola/shared/negative',
    parameter: 'id'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-admin-negative',
    name: 'IDOR admin object negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/idor/bola/admin/negative',
    parameter: 'id'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-query-negative',
    name: 'IDOR query deny-by-default negative',
    category: 'negative',
    expectedVerdict: 'not-confirmed',
    executable: true,
    endpoint: '/research/idor/bola/query/negative',
    parameter: 'id'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-session-expired',
    name: 'IDOR session expired inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/idor/bola/session-expired',
    parameter: 'id'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-dynamic',
    name: 'IDOR dynamic content inconclusive',
    category: 'inconclusive',
    expectedVerdict: 'inconclusive',
    executable: true,
    endpoint: '/research/idor/bola/dynamic',
    parameter: 'id'
  }),
  familyCase('idor', {
    caseId: 'complex-v1-idor-secret-isolation',
    name: 'IDOR secret isolation safety',
    category: 'positive',
    expectedVerdict: 'confirmed',
    executable: true,
    endpoint: '/research/idor/bola/query/positive',
    parameter: 'account_id',
    confirmationRule: 'idor-two-test-identities-readonly@1.0.0'
  })
]

function toSuite(
  family: LegacyV1VulnerabilityFamily,
  cases: readonly EvaluationGroundTruthCase[],
  requiredCaseCategories: BenchmarkSuiteManifest['requiredCaseCategories']
): BenchmarkSuiteManifest {
  return BenchmarkSuiteManifestSchema.parse({
    schemaVersion: 'agentgo-benchmark-suite/1.0',
    suiteId: COMPLEX_SUITE_ID,
    suiteVersion: COMPLEX_SUITE_VERSION,
    familyId: family,
    techniqueId: LEGACY_V1_TECHNIQUE_IDS[family],
    moduleVersion: LEGACY_V1_MODULE_VERSIONS[family],
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
    selectorKind: 'query',
    allowedMaturities: ['active-l1'],
    environment: 'attested-fixture',
    requiredCaseCategories,
    attestation,
    cases
  })
}

export function createComplexBenchmarkSuites(): readonly BenchmarkSuiteManifest[] {
  return Object.freeze([
    toSuite('sqli', SQLI_CASES, [
      'positive',
      'negative',
      'inconclusive',
      'policy-denied',
      'cleanup-failure'
    ]),
    toSuite('xss', XSS_CASES, ['positive', 'negative', 'inconclusive']),
    toSuite('ssrf', SSRF_CASES, ['positive', 'negative', 'inconclusive']),
    toSuite('idor', IDOR_CASES, ['positive', 'negative', 'inconclusive'])
  ])
}

export function listComplexRunnerCases(): readonly ComplexRunnerCase[] {
  return Object.freeze(
    createComplexBenchmarkSuites().flatMap((suite) =>
      suite.cases.map((item) => ({
        caseId: item.caseId,
        name: item.name,
        family: item.familyId as LegacyV1VulnerabilityFamily,
        endpoint: item.endpoint ?? '/',
        parameter: item.parameter ?? 'id',
        expectedVerdict: item.expectedVerdict,
        category: item.category,
        executable: item.executable,
        identityKind: (item.familyId === 'idor' ? 'idor-research' : 'none') as ComplexIdentityKind,
        allowSensitiveProbing: false,
        allowedPathPrefixes:
          item.category === 'policy-denied' ? ['/__policy-denied__'] : undefined,
        deniedPathPrefixes:
          item.category === 'policy-denied' && item.endpoint
            ? [item.endpoint]
            : undefined,
        callback: item.familyId === 'ssrf',
        techniqueId: item.techniqueId,
        confirmationRule: item.confirmationRule
      }))
    )
  )
}
