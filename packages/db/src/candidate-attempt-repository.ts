import { asc, eq } from 'drizzle-orm'
import {
  CandidateAttemptSchema,
  type CandidateAttempt
} from '@agentgo/contracts'
import type { AgentGoDatabase } from './database'
import { candidateAttempts } from './schema'

function epochMs(iso: string): number {
  const value = Date.parse(iso)
  if (!Number.isFinite(value)) {
    throw new TypeError('Candidate-attempt timestamp is not a valid ISO-8601 instant.')
  }
  return value
}

export class CandidateAttemptRepository {
  constructor(private readonly database: AgentGoDatabase) {}

  async save(attempt: CandidateAttempt): Promise<CandidateAttempt> {
    const parsed = CandidateAttemptSchema.parse(attempt)
    await this.database.orm.insert(candidateAttempts).values({
      attemptId: parsed.attemptId,
      scanId: parsed.scanId,
      candidateId: parsed.candidateId,
      status: parsed.status,
      decision: parsed.decision,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt),
      updatedAt: epochMs(parsed.updatedAt),
      completedAt: parsed.completedAt ? epochMs(parsed.completedAt) : null
    })
    return parsed
  }

  async update(attempt: CandidateAttempt): Promise<CandidateAttempt> {
    const parsed = CandidateAttemptSchema.parse(attempt)
    await this.database.orm
      .update(candidateAttempts)
      .set({
        status: parsed.status,
        decision: parsed.decision,
        payloadJson: parsed,
        updatedAt: epochMs(parsed.updatedAt),
        completedAt: parsed.completedAt ? epochMs(parsed.completedAt) : null
      })
      .where(eq(candidateAttempts.attemptId, parsed.attemptId))
    return parsed
  }

  async get(attemptId: string): Promise<CandidateAttempt | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(candidateAttempts)
      .where(eq(candidateAttempts.attemptId, attemptId))
      .limit(1)
    return row ? CandidateAttemptSchema.parse(row.payloadJson) : undefined
  }

  async listByScan(scanId: string): Promise<CandidateAttempt[]> {
    const rows = await this.database.orm
      .select()
      .from(candidateAttempts)
      .where(eq(candidateAttempts.scanId, scanId))
      .orderBy(asc(candidateAttempts.createdAt))
    return rows.map((row) => CandidateAttemptSchema.parse(row.payloadJson))
  }
}
