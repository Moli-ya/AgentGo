import {
  LOCAL_FIXTURE_VERSION,
  QualificationRecordPayloadSchema,
  QualificationRecordSchema,
  QUALIFICATION_RECORD_ISSUED_AT,
  type BenchmarkSuiteManifest,
  type EvaluationGroundTruthCase,
  type QualificationRecord,
  type QualificationRecordPayload
} from '@agentgo/contracts'
import {
  LEGACY_V1_RUNTIME_BINDINGS,
  type LegacyV1RuntimeBinding
} from '@agentgo/application'
import { canonicalJson, sha256Text } from '@agentgo/domain'
import {
  BenchmarkScoringError,
  assertBenchmarkPredictionsComplete,
  type BenchmarkPrediction
} from './index'
import { localFixtureAttestationHash } from './local-fixture'

export function hashBenchmarkSuite(suite: BenchmarkSuiteManifest): string {
  return sha256Text(canonicalJson(suite))
}

export function computeQualificationBuildHash(input: {
  definitionSnapshotHash: string
  policyCatalogHash: string
  runtimeBindings?: readonly LegacyV1RuntimeBinding[]
}): string {
  return sha256Text(
    canonicalJson({
      definitionSnapshotHash: input.definitionSnapshotHash,
      policyCatalogHash: input.policyCatalogHash,
      runtimeBindings: input.runtimeBindings ?? LEGACY_V1_RUNTIME_BINDINGS
    })
  )
}

export function qualificationRecordPayloadHash(
  payload: QualificationRecordPayload
): string {
  return sha256Text(canonicalJson(payload))
}

export function sealQualificationRecord(
  payload: QualificationRecordPayload
): QualificationRecord {
  const parsed = QualificationRecordPayloadSchema.parse(payload)
  return QualificationRecordSchema.parse({
    ...parsed,
    recordHash: qualificationRecordPayloadHash(parsed)
  })
}

export function assertSuiteVersionsMatch(input: {
  suite: BenchmarkSuiteManifest
  fixtureVersion: string
  moduleVersion: string
}): void {
  if (input.suite.fixtureVersion !== input.fixtureVersion) {
    throw new BenchmarkScoringError(
      'version-mismatch',
      `Suite fixture ${input.suite.fixtureVersion} does not match ${input.fixtureVersion}.`
    )
  }
  if (input.suite.moduleVersion !== input.moduleVersion) {
    throw new BenchmarkScoringError(
      'version-mismatch',
      `Suite module ${input.suite.moduleVersion} does not match ${input.moduleVersion}.`
    )
  }
}

export function assertCleanupCasesNotExecuted(
  cases: readonly EvaluationGroundTruthCase[],
  predictions: readonly BenchmarkPrediction[]
): void {
  const cleanupIds = new Set(
    cases.filter((item) => item.category === 'cleanup-failure').map((item) => item.caseId)
  )
  for (const prediction of predictions) {
    if (!cleanupIds.has(prediction.caseId)) continue
    if (prediction.runStatus !== 'cleanup-failure') {
      throw new BenchmarkScoringError(
        'cleanup-failure-not-executable',
        `cleanup-failure case ${prediction.caseId} cannot be executed or scored as success before L2 cleanup execution is connected.`
      )
    }
  }
}

export function assertRequiredEvidenceRoles(input: {
  cases: readonly EvaluationGroundTruthCase[]
  predictions: readonly BenchmarkPrediction[]
}): void {
  const byId = new Map(input.cases.map((item) => [item.caseId, item]))
  for (const prediction of input.predictions) {
    const groundTruth = byId.get(prediction.caseId)
    if (!groundTruth) continue
    if (prediction.actualVerdict !== 'confirmed' || prediction.runStatus !== 'completed') {
      continue
    }
    const present = new Set(prediction.evidenceRoles)
    const missing = groundTruth.requiredEvidenceRoles.filter((role) => !present.has(role))
    if (missing.length > 0) {
      throw new BenchmarkScoringError(
        'missing-evidence-role',
        `Case ${prediction.caseId} is missing evidence roles: ${missing.join(', ')}.`
      )
    }
  }
}

export function scoreTechniqueSuite(input: {
  suite: BenchmarkSuiteManifest
  predictions: BenchmarkPrediction[]
  fixtureVersion?: string
  knownTechniqueIds?: readonly string[]
}): void {
  assertSuiteVersionsMatch({
    suite: input.suite,
    fixtureVersion: input.fixtureVersion ?? LOCAL_FIXTURE_VERSION,
    moduleVersion: input.suite.moduleVersion
  })
  assertBenchmarkPredictionsComplete({
    cases: input.suite.cases,
    predictions: input.predictions,
    knownTechniqueIds: input.knownTechniqueIds ?? [input.suite.techniqueId]
  })
  assertCleanupCasesNotExecuted(input.suite.cases, input.predictions)
  assertRequiredEvidenceRoles({
    cases: input.suite.cases,
    predictions: input.predictions
  })
}

export function createQualificationRecordForBinding(input: {
  binding: LegacyV1RuntimeBinding
  suite: BenchmarkSuiteManifest
  definitionSnapshotHash: string
  policyCatalogHash: string
  fixtureAttestationHash?: string
  qualifiedEnvironments?: QualificationRecordPayload['qualifiedEnvironments']
}): QualificationRecord {
  if (
    input.suite.suiteId !== 'legacy-v1' ||
    input.suite.techniqueId !== input.binding.techniqueId ||
    input.suite.suiteVersion !== input.binding.techniqueVersion ||
    input.suite.moduleVersion !== input.binding.moduleVersion
  ) {
    throw new BenchmarkScoringError(
      'version-mismatch',
      `Suite ${input.suite.suiteId}@${input.suite.suiteVersion} does not match ${input.binding.techniqueId}.`
    )
  }
  if (input.suite.fixtureVersion !== LOCAL_FIXTURE_VERSION) {
    throw new BenchmarkScoringError(
      'version-mismatch',
      `Suite fixture ${input.suite.fixtureVersion} does not match ${LOCAL_FIXTURE_VERSION}.`
    )
  }

  const payload = QualificationRecordPayloadSchema.parse({
    schemaVersion: 'agentgo-qualification-record/1.0',
    familyId: input.binding.familyId,
    techniqueId: input.binding.techniqueId,
    techniqueVersion: input.binding.techniqueVersion,
    moduleId: input.binding.moduleId,
    moduleVersion: input.binding.moduleVersion,
    definitionHash: input.binding.definitionHash,
    definitionSnapshotHash: input.definitionSnapshotHash,
    buildHash: computeQualificationBuildHash({
      definitionSnapshotHash: input.definitionSnapshotHash,
      policyCatalogHash: input.policyCatalogHash
    }),
    suiteId: input.suite.suiteId,
    suiteVersion: input.suite.suiteVersion,
    suiteHash: hashBenchmarkSuite(input.suite),
    fixtureVersion: LOCAL_FIXTURE_VERSION,
    fixtureAttestationHash:
      input.fixtureAttestationHash ?? localFixtureAttestationHash(),
    policyCatalogHash: input.policyCatalogHash,
    protocol: input.suite.protocol,
    selectorKind: input.suite.selectorKind,
    resultClass: 'self-built-fixture',
    result: 'passed',
    qualifiedEnvironments: input.qualifiedEnvironments ?? [
      'attested-fixture',
      'authorized-test-environment',
      'authorized-real-target'
    ],
    issuedAt: QUALIFICATION_RECORD_ISSUED_AT
  })
  return sealQualificationRecord(payload)
}
