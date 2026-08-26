import { describe, expect, it } from 'vitest'
import {
  BenchmarkSuiteManifestSchema,
  EvaluationGroundTruthCaseSchema,
  GroundTruthManifestSchema,
  LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
  LOCAL_FIXTURE_VERSION,
  QualificationRecordSchema,
  type EvaluationGroundTruthCase
} from './evaluation'

const attestation = {
  fixtureId: 'agentgo-local-fixture',
  fixtureVersion: LOCAL_FIXTURE_VERSION,
  bindAddress: '127.0.0.1' as const,
  portPolicy: 'ephemeral' as const,
  outboundPolicy: 'loopback-same-origin-callback-only' as const,
  resetPolicy: 'fixture-namespace-only' as const
}

function evaluationGroundTruthCase(
  overrides: Partial<EvaluationGroundTruthCase> &
    Pick<EvaluationGroundTruthCase, 'caseId' | 'category' | 'expectedVerdict' | 'executable'>
): EvaluationGroundTruthCase {
  return EvaluationGroundTruthCaseSchema.parse({
    name: overrides.name ?? overrides.caseId,
    targetVersion: LOCAL_FIXTURE_VERSION,
    familyId: 'sqli',
    techniqueId: 'sqli.boolean-differential',
    moduleVersion: '1.0.0',
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
    selectorKind: 'query',
    requiredEvidenceRoles: ['baseline', 'test', 'negative-control'],
    identityRequirement: 'single-test-identity',
    workflowRequirement: 'none',
    testObjectRequirement: 'none',
    riskLevel: 'l1',
    maxRequests: 30,
    forbiddenCapabilityIds: ['http.test-object-write'],
    environment: 'attested-fixture',
    confirmationRule: 'sqli-boolean-differential@1.0.0',
    resetProcedure: 'reset the fixture namespace only',
    forbiddenActions: ['destructive writes'],
    source: 'AgentGo self-built fixture',
    license: 'project-internal-test-data',
    reviewer: 'project-team',
    ...overrides
  })
}

describe('evaluation contracts', () => {
  it('keeps the V1 40-case ground-truth schema closed over duplicate IDs and family coverage', () => {
    const caseTemplate = {
      name: 'case',
      targetVersion: LOCAL_FIXTURE_VERSION,
      endpoint: '/cases/sqli/positive/1',
      parameter: 'id',
      identityPlan: {},
      confirmationRule: 'sqli-boolean-differential@1.0.0',
      requiredEvidence: ['baseline'],
      resetProcedure: 'stateless',
      forbiddenActions: ['destructive writes'],
      source: 'fixture',
      license: 'internal',
      reviewer: 'team'
    }
    const cases = ['sqli', 'xss', 'ssrf', 'idor'].flatMap((family) =>
      Array.from({ length: 10 }, (_, index) => ({
        ...caseTemplate,
        caseId: `${family}-${index + 1}`,
        family,
        expectedVerdict: index < 5 ? ('confirmed' as const) : ('not-confirmed' as const)
      }))
    )

    expect(
      GroundTruthManifestSchema.parse({
        schemaVersion: 'agentgo-ground-truth/1.0',
        targetVersion: LOCAL_FIXTURE_VERSION,
        note: 'legacy 40-case contract',
        cases
      }).cases
    ).toHaveLength(40)

    expect(
      GroundTruthManifestSchema.safeParse({
        schemaVersion: 'agentgo-ground-truth/1.0',
        targetVersion: LOCAL_FIXTURE_VERSION,
        note: 'duplicate',
        cases: [...cases.slice(0, 39), cases[0]]
      }).success
    ).toBe(false)
  })

  it('accepts one meta-case for each qualification category and rejects executable cleanup-failure', () => {
    const categories = [
      evaluationGroundTruthCase({
        caseId: 'positive-1',
        category: 'positive',
        expectedVerdict: 'confirmed',
        executable: true
      }),
      evaluationGroundTruthCase({
        caseId: 'negative-1',
        category: 'negative',
        expectedVerdict: 'not-confirmed',
        executable: true
      }),
      evaluationGroundTruthCase({
        caseId: 'inconclusive-1',
        category: 'inconclusive',
        expectedVerdict: 'inconclusive',
        executable: true
      }),
      evaluationGroundTruthCase({
        caseId: 'policy-1',
        category: 'policy-denied',
        expectedVerdict: 'inconclusive',
        expectedReasonCode: 'out-of-scope',
        executable: true
      }),
      evaluationGroundTruthCase({
        caseId: 'version-1',
        category: 'version-mismatch',
        expectedVerdict: 'inconclusive',
        expectedReasonCode: 'fixture-version-mismatch',
        executable: true
      }),
      evaluationGroundTruthCase({
        caseId: 'cleanup-1',
        category: 'cleanup-failure',
        expectedVerdict: 'inconclusive',
        executable: false
      })
    ]

    expect(categories).toHaveLength(6)
    expect(
      EvaluationGroundTruthCaseSchema.safeParse({
        ...categories[5],
        executable: true
      }).success
    ).toBe(false)
  })

  it('rejects duplicate suite IDs, missing evidence roles, unknown techniques, and extra fields', () => {
    const positive = evaluationGroundTruthCase({
      caseId: 'sqli-positive-1',
      category: 'positive',
      expectedVerdict: 'confirmed',
      executable: true
    })
    const negative = evaluationGroundTruthCase({
      caseId: 'sqli-negative-1',
      category: 'negative',
      expectedVerdict: 'not-confirmed',
      executable: true
    })

    const suite = {
      schemaVersion: 'agentgo-benchmark-suite/1.0' as const,
      suiteId: 'legacy-v1',
      suiteVersion: '1.0.0',
      familyId: 'sqli',
      techniqueId: 'sqli.boolean-differential',
      moduleVersion: '1.0.0',
      fixtureVersion: LOCAL_FIXTURE_VERSION,
      protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
      selectorKind: 'query' as const,
      allowedMaturities: ['active-l1' as const],
      environment: 'attested-fixture' as const,
      requiredCaseCategories: ['positive' as const, 'negative' as const],
      attestation,
      cases: [positive, negative]
    }

    expect(BenchmarkSuiteManifestSchema.parse(suite).cases).toHaveLength(2)
    expect(
      BenchmarkSuiteManifestSchema.safeParse({
        ...suite,
        cases: [positive, { ...negative, caseId: positive.caseId }]
      }).success
    ).toBe(false)
    expect(
      EvaluationGroundTruthCaseSchema.safeParse({
        ...positive,
        requiredEvidenceRoles: []
      }).success
    ).toBe(false)
    expect(
      BenchmarkSuiteManifestSchema.safeParse({
        ...suite,
        cases: [
          positive,
          { ...negative, techniqueId: 'sqli.unknown-technique' }
        ]
      }).success
    ).toBe(false)
    expect(
      BenchmarkSuiteManifestSchema.safeParse({
        ...suite,
        qualificationRecordRef: 'must-not-be-authored-here'
      }).success
    ).toBe(false)
  })

  it('keeps qualification records strict and hash-bearing', () => {
    const parsed = QualificationRecordSchema.parse({
      schemaVersion: 'agentgo-qualification-record/1.0',
      familyId: 'sqli',
      techniqueId: 'sqli.boolean-differential',
      techniqueVersion: '1.0.0',
      moduleId: 'sqli.legacy-v1',
      moduleVersion: '1.0.0',
      definitionHash: 'a'.repeat(64),
      definitionSnapshotHash: 'b'.repeat(64),
      buildHash: 'c'.repeat(64),
      suiteId: 'legacy-v1',
      suiteVersion: '1.0.0',
      suiteHash: 'd'.repeat(64),
      fixtureVersion: LOCAL_FIXTURE_VERSION,
      fixtureAttestationHash: 'e'.repeat(64),
      policyCatalogHash: 'f'.repeat(64),
      protocol: LEGACY_V1_HTTP_GET_QUERY_PROTOCOL,
      selectorKind: 'query',
      resultClass: 'self-built-fixture',
      result: 'passed',
      qualifiedEnvironments: ['attested-fixture'],
      issuedAt: '2026-08-20T00:00:00.000Z',
      recordHash: '1'.repeat(64)
    })

    expect(Object.isFrozen(parsed)).toBe(true)
    expect(
      QualificationRecordSchema.safeParse({
        ...parsed,
        fixturePackage: '@agentgo/evaluation'
      }).success
    ).toBe(false)
    expect(
      QualificationRecordSchema.safeParse({
        ...parsed,
        result: 'failed'
      }).success
    ).toBe(false)
  })
})
