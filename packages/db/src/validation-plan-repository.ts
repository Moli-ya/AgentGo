import { asc, eq } from 'drizzle-orm'
import {
  ValidationEvidenceBindingSchema,
  ValidationObservationSchema,
  ValidationPlanRunSchema,
  ValidationStepRunSchema,
  type ValidationEvidenceBinding,
  type ValidationObservation,
  type ValidationPlanRun,
  type ValidationStepRun
} from '@agentgo/contracts'
import type { AgentGoDatabase } from './database'
import {
  validationEvidenceBindings,
  validationObservations,
  validationPlanRuns,
  validationStepRuns
} from './schema'

function epochMs(iso: string): number {
  const value = Date.parse(iso)
  if (!Number.isFinite(value)) {
    throw new TypeError('Validation-plan timestamp is not a valid ISO-8601 instant.')
  }
  return value
}

export class ValidationPlanRepository {
  constructor(private readonly database: AgentGoDatabase) {}

  async savePlanRun(run: ValidationPlanRun): Promise<ValidationPlanRun> {
    const parsed = ValidationPlanRunSchema.parse(run)
    await this.database.orm.insert(validationPlanRuns).values({
      runId: parsed.runId,
      scanId: parsed.scanId,
      planId: parsed.planId,
      planHash: parsed.planHash,
      status: parsed.status,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt),
      completedAt: parsed.completedAt ? epochMs(parsed.completedAt) : null
    })
    return parsed
  }

  async updatePlanRun(run: ValidationPlanRun): Promise<ValidationPlanRun> {
    const parsed = ValidationPlanRunSchema.parse(run)
    await this.database.orm
      .update(validationPlanRuns)
      .set({
        status: parsed.status,
        payloadJson: parsed,
        completedAt: parsed.completedAt ? epochMs(parsed.completedAt) : null
      })
      .where(eq(validationPlanRuns.runId, parsed.runId))
    return parsed
  }

  async getPlanRun(runId: string): Promise<ValidationPlanRun | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(validationPlanRuns)
      .where(eq(validationPlanRuns.runId, runId))
      .limit(1)
    return row ? ValidationPlanRunSchema.parse(row.payloadJson) : undefined
  }

  async saveStepRun(run: ValidationStepRun): Promise<ValidationStepRun> {
    const parsed = ValidationStepRunSchema.parse(run)
    await this.database.orm.insert(validationStepRuns).values({
      stepRunId: parsed.stepRunId,
      runId: parsed.runId,
      stepId: parsed.stepId,
      kind: parsed.kind,
      status: parsed.status,
      ordinal: parsed.ordinal,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt),
      completedAt: parsed.completedAt ? epochMs(parsed.completedAt) : null
    })
    return parsed
  }

  async updateStepRun(run: ValidationStepRun): Promise<ValidationStepRun> {
    const parsed = ValidationStepRunSchema.parse(run)
    await this.database.orm
      .update(validationStepRuns)
      .set({
        status: parsed.status,
        payloadJson: parsed,
        completedAt: parsed.completedAt ? epochMs(parsed.completedAt) : null
      })
      .where(eq(validationStepRuns.stepRunId, parsed.stepRunId))
    return parsed
  }

  async listStepRuns(runId: string): Promise<ValidationStepRun[]> {
    const rows = await this.database.orm
      .select()
      .from(validationStepRuns)
      .where(eq(validationStepRuns.runId, runId))
      .orderBy(asc(validationStepRuns.ordinal))
    return rows.map((row) => ValidationStepRunSchema.parse(row.payloadJson))
  }

  async saveObservation(
    observation: ValidationObservation
  ): Promise<ValidationObservation> {
    const parsed = ValidationObservationSchema.parse(observation)
    await this.database.orm.insert(validationObservations).values({
      observationId: parsed.observationId,
      runId: parsed.runId,
      stepId: parsed.stepId,
      kind: parsed.kind,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt)
    })
    return parsed
  }

  async listObservations(runId: string): Promise<ValidationObservation[]> {
    const rows = await this.database.orm
      .select()
      .from(validationObservations)
      .where(eq(validationObservations.runId, runId))
      .orderBy(asc(validationObservations.createdAt))
    return rows.map((row) => ValidationObservationSchema.parse(row.payloadJson))
  }

  async saveEvidenceBinding(
    binding: ValidationEvidenceBinding
  ): Promise<ValidationEvidenceBinding> {
    const parsed = ValidationEvidenceBindingSchema.parse(binding)
    await this.database.orm.insert(validationEvidenceBindings).values({
      bindingId: parsed.bindingId,
      runId: parsed.runId,
      stepId: parsed.stepId,
      evidenceRef: parsed.evidenceRef,
      role: parsed.role,
      ordinal: parsed.ordinal,
      profileId: parsed.profileId,
      profileVersion: parsed.profileVersion,
      payloadJson: parsed
    })
    return parsed
  }

  async listEvidenceBindings(runId: string): Promise<ValidationEvidenceBinding[]> {
    const rows = await this.database.orm
      .select()
      .from(validationEvidenceBindings)
      .where(eq(validationEvidenceBindings.runId, runId))
      .orderBy(asc(validationEvidenceBindings.ordinal))
    return rows.map((row) => ValidationEvidenceBindingSchema.parse(row.payloadJson))
  }
}
