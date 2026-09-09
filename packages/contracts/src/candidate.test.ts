import { describe, expect, it } from 'vitest'
import {
  CandidateAttemptSchema,
  CandidateSchema,
  CandidateSeedSchema
} from './candidate'

const uuid = '10000000-0000-4000-8000-000000000001'
const now = '2026-09-02T00:00:00.000Z'

describe('Day 15 candidate contracts', () => {
  it('allows candidates without a parameter id', () => {
    const candidate = CandidateSchema.parse({
      candidateId: uuid,
      familyId: 'security.headers',
      techniqueId: 'security.headers.existing-response-audit',
      moduleVersion: '0.1.0',
      subjectRefs: [{ kind: 'endpoint', id: uuid }],
      variantRefs: [uuid],
      dependencyRefs: [],
      identityRefs: [],
      testObjectRefs: [],
      matrixRefs: [],
      reason: 'Passive response-header audit from frozen inventory.',
      expectedSignal: 'missing-security-headers',
      suggestedStrategy: 'security.headers.existing-response-strategy'
    })
    expect(candidate.parameterId).toBeUndefined()
  })

  it('rejects agent-invented techniques that fail the id format', () => {
    expect(
      CandidateSeedSchema.safeParse({
        familyId: 'sqli',
        techniqueId: 'SQLi Boolean!!!',
        moduleVersion: '1.0.0',
        detectorId: 'sqli.legacy.detector',
        subjectRefs: [],
        variantRefs: [],
        reason: 'forged',
        expectedSignal: 'boolean-diff',
        suggestedStrategy: 'sqli.legacy.strategy',
        confidenceHint: 0.9
      }).success
    ).toBe(false)
  })

  it('persists attempt statuses including awaiting and cleanup-pending', () => {
    const attempt = CandidateAttemptSchema.parse({
      attemptId: uuid,
      scanId: uuid,
      candidateId: uuid,
      candidate: CandidateSchema.parse({
        candidateId: uuid,
        familyId: 'sqli',
        techniqueId: 'sqli.boolean-differential',
        moduleVersion: '1.0.0',
        subjectRefs: [{ kind: 'endpoint', id: uuid }],
        variantRefs: [uuid],
        dependencyRefs: [],
        identityRefs: [],
        testObjectRefs: [],
        matrixRefs: [],
        parameterId: uuid,
        reason: 'Reviewed GET query selector.',
        expectedSignal: 'boolean-differential',
        suggestedStrategy: 'sqli.legacy.strategy'
      }),
      status: 'awaiting-input',
      decision: 'awaiting-user',
      grantRefs: [],
      evidenceRefs: [],
      reason: 'Request variant is unreviewed.',
      createdAt: now,
      updatedAt: now
    })
    expect(attempt.status).toBe('awaiting-input')
  })
})
