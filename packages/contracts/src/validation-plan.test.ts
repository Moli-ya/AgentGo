import { describe, expect, it } from 'vitest'
import {
  InventoryMergeReportSchema,
  ValidationPlanSchema,
  ValidationStepKindSchema
} from './index'

const uuid = '10000000-0000-4000-8000-000000000001'
const hash = 'a'.repeat(64)
const now = '2026-08-30T00:00:00.000Z'

describe('Day 13/14 contracts', () => {
  it('accepts an inventory merge report with producer and capability buckets', () => {
    const report = InventoryMergeReportSchema.parse({
      schemaVersion: 'agentgo.inventory-merge-report.v1',
      reportId: uuid,
      scanId: uuid,
      scopeSnapshotId: uuid,
      totals: {
        created: 1,
        merged: 0,
        conflict: 0,
        rejected: 0,
        outOfScope: 0,
        secretRedacted: 0,
        inventoryOnly: 1,
        awaitingReview: 0,
        unsupported: 0
      },
      byProducer: [
        {
          producer: 'browser.recon',
          counts: {
            created: 1,
            merged: 0,
            conflict: 0,
            rejected: 0,
            outOfScope: 0,
            secretRedacted: 0,
            inventoryOnly: 1,
            awaitingReview: 0,
            unsupported: 0
          }
        }
      ],
      byCapability: [
        {
          capabilityId: 'none',
          counts: {
            created: 1,
            merged: 0,
            conflict: 0,
            rejected: 0,
            outOfScope: 0,
            secretRedacted: 0,
            inventoryOnly: 1,
            awaitingReview: 0,
            unsupported: 0
          }
        }
      ],
      createdAt: now
    })
    expect(report.byProducer[0]?.producer).toBe('browser.recon')
  })

  it('rejects unknown validation step kinds', () => {
    expect(ValidationStepKindSchema.safeParse('raw-protocol-race').success).toBe(false)
    expect(
      ValidationPlanSchema.safeParse({
        schemaVersion: 'agentgo.validation-plan.v1',
        planId: uuid,
        planHash: hash,
        scanId: uuid,
        familyId: 'sqli',
        techniqueId: 'sqli.boolean-differential',
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        environment: 'attested-fixture',
        steps: [
          {
            stepId: 'unknown.step',
            kind: 'invented-callback',
            familyId: 'sqli',
            techniqueId: 'sqli.boolean-differential',
            moduleVersion: '1.0.0',
            strategyVersion: '1.0.0',
            subjectRefs: [],
            capabilityIds: [],
            environment: 'attested-fixture',
            evidenceRoles: [],
            budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
            stopConditions: ['on-step-failure']
          }
        ],
        stopConditions: ['on-step-failure'],
        budget: {
          maxRequests: 1,
          maxBytes: 1024,
          maxDurationMs: 1_000,
          maxFanOut: 1
        },
        createdAt: now
      }).success
    ).toBe(false)
  })
})
