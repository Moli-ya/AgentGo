import {
  QualificationRecordPayloadSchema,
  QualificationRecordSchema,
  type Environment,
  type QualificationRecord,
  type QualificationRecordPayload
} from '@agentgo/contracts'
import { canonicalJson, sha256Text, type DefinitionRegistry } from '@agentgo/domain'
import {
  LEGACY_V1_RUNTIME_BINDINGS,
  type LegacyV1RuntimeBinding
} from './vulnerability-bundles'
import type { ProbeCapabilityCatalog } from '@agentgo/security-policy'

export const LEGACY_V1_POLICY_CAPABILITY_IDS = Object.freeze([
  'browser.offline-replay',
  'http.identity-read-compare',
  'http.reviewed-read',
  'oob.controlled-observe'
] as const)

export function computeLegacyV1PolicyHash(
  catalog: ProbeCapabilityCatalog
): string {
  const descriptors = LEGACY_V1_POLICY_CAPABILITY_IDS.map((capabilityId) => {
    const descriptor = catalog.get(capabilityId)
    if (!descriptor) {
      throw new Error(
        `Legacy V1 qualification is missing capability ${capabilityId}.`
      )
    }
    return {
      description: descriptor.description,
      id: descriptor.id,
      riskFloor: descriptor.riskFloor
    }
  })
  return sha256Text(canonicalJson(descriptors))
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
  return sha256Text(canonicalJson(QualificationRecordPayloadSchema.parse(payload)))
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

export type QualificationRecordValidity =
  | 'valid'
  | 'hash-mismatch'
  | 'expired'
  | 'definition-mismatch'
  | 'environment-undeclared'
  | 'suite-mismatch'
  | 'build-mismatch'

export function evaluateQualificationRecord(input: {
  record: QualificationRecord
  registry: DefinitionRegistry
  now?: Date
  expectedBuildHash: string
}): QualificationRecordValidity {
  const { record, registry } = input
  const { recordHash, ...payload } = record
  if (qualificationRecordPayloadHash(payload) !== recordHash) {
    return 'hash-mismatch'
  }
  if (record.expiresAt && (input.now ?? new Date()).toISOString() >= record.expiresAt) {
    return 'expired'
  }
  if (record.buildHash !== input.expectedBuildHash) {
    return 'build-mismatch'
  }
  const registered = registry.getBundle(record.moduleId, record.moduleVersion)
  const technique = registered?.bundle.manifest.techniques.find(
    (candidate) =>
      candidate.techniqueId === record.techniqueId &&
      candidate.version === record.techniqueVersion
  )
  if (
    !registered ||
    !technique ||
    registered.definitionHash !== record.definitionHash ||
    registered.bundle.manifest.family.familyId !== record.familyId ||
    technique.familyId !== record.familyId
  ) {
    return 'definition-mismatch'
  }
  if (
    technique.expectedSuiteRef &&
    (technique.expectedSuiteRef.id !== record.suiteId ||
      technique.expectedSuiteRef.version !== record.suiteVersion)
  ) {
    return 'suite-mismatch'
  }
  const allowed = new Set(technique.allowedEnvironments)
  if (record.qualifiedEnvironments.some((environment) => !allowed.has(environment))) {
    return 'environment-undeclared'
  }
  return 'valid'
}

export function recordMatchesEnvironment(
  record: QualificationRecord,
  environment: Environment
): boolean {
  return record.qualifiedEnvironments.includes(environment)
}
