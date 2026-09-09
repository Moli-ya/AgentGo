import { and, desc, eq } from 'drizzle-orm'
import {
  ApprovalProposalSchema,
  ApprovalRecordSchema,
  AuthorizationMatrixSchema,
  CsrfBindingSchema,
  IdentityContextSchema,
  type ApprovalProposal,
  type ApprovalRecord,
  type ApprovalRecordView,
  type AuthorizationMatrix,
  type CsrfBinding,
  type IdentityContext
} from '@agentgo/contracts'
import {
  hashIdentitySessionValue,
  unsignedApprovalProposal,
  unsignedApprovalRecord,
  unsignedAuthorizationMatrix,
  unsignedCsrfBinding,
  unsignedIdentityContext
} from '@agentgo/domain'
import type { AgentGoDatabase } from './database'
import {
  approvalProposals,
  approvalRecords,
  authorizationMatrices,
  csrfBindings,
  identityContexts,
  sessionVaultSessions
} from './schema'

export type SessionVaultStatus = 'active' | 'expired' | 'revoked' | 'vault-lost'

export interface SessionVaultRecord {
  readonly sessionId: string
  readonly identityId: string
  readonly targetId: string
  readonly scopeSnapshotId: string
  readonly generation: number
  readonly status: SessionVaultStatus
  readonly createdAt: number
  readonly updatedAt: number
}

export interface CsrfBindingRow {
  readonly binding: CsrfBinding
  readonly useCount: number
  readonly status: 'active' | 'exhausted' | 'expired' | 'revoked'
}

function epochMs(iso: string): number {
  const value = Date.parse(iso)
  if (!Number.isFinite(value)) {
    throw new TypeError('Identity/session timestamp is not a valid ISO-8601 instant.')
  }
  return value
}

function assertIdentityContextIntegrity(context: IdentityContext): IdentityContext {
  const parsed = IdentityContextSchema.parse(context)
  if (parsed.contextHash !== hashIdentitySessionValue(unsignedIdentityContext(parsed))) {
    throw new Error('IdentityContext hash mismatch.')
  }
  return parsed
}

function assertCsrfBindingIntegrity(binding: CsrfBinding): CsrfBinding {
  const parsed = CsrfBindingSchema.parse(binding)
  if (parsed.bindingHash !== hashIdentitySessionValue(unsignedCsrfBinding(parsed))) {
    throw new Error('CSRF binding hash mismatch.')
  }
  return parsed
}

function assertMatrixIntegrity(matrix: AuthorizationMatrix): AuthorizationMatrix {
  const parsed = AuthorizationMatrixSchema.parse(matrix)
  if (parsed.matrixHash !== hashIdentitySessionValue(unsignedAuthorizationMatrix(parsed))) {
    throw new Error('AuthorizationMatrix hash mismatch.')
  }
  return parsed
}

function assertApprovalProposalIntegrity(proposal: ApprovalProposal): ApprovalProposal {
  const parsed = ApprovalProposalSchema.parse(proposal)
  if (parsed.proposalHash !== hashIdentitySessionValue(unsignedApprovalProposal(parsed))) {
    throw new Error('Approval proposal hash mismatch.')
  }
  return parsed
}

function assertApprovalIntegrity(record: ApprovalRecord): ApprovalRecord {
  const parsed = ApprovalRecordSchema.parse(record)
  if (parsed.approvalHash !== hashIdentitySessionValue(unsignedApprovalRecord(parsed))) {
    throw new Error('Approval record hash mismatch.')
  }
  return parsed
}

/**
 * Persistence boundary for Day 9 identity/session/CSRF/matrix metadata and
 * Day 10 approval records. No Cookie, Authorization, token, password, or
 * CSRF plaintext is ever accepted here; payloads are hash-verified on both
 * write and read.
 */
export class IdentitySessionRepository {
  constructor(private readonly database: AgentGoDatabase) {}

  /* ------------------------------------------------ IdentityContext ----- */

  async insertIdentityContext(
    context: IdentityContext,
    options?: { readonly supersedeActive?: boolean }
  ): Promise<IdentityContext> {
    const parsed = assertIdentityContextIntegrity(context)
    const native = this.database.native
    let started = false
    try {
      native.exec('BEGIN IMMEDIATE')
      started = true
      if (options?.supersedeActive !== false) {
        native
          .prepare(
            `UPDATE identity_contexts SET status = 'superseded'
             WHERE identity_id = ? AND status = 'active'`
          )
          .run(parsed.identityId)
      }
      await this.database.orm.insert(identityContexts).values({
        identityContextId: parsed.identityContextId,
        identityContextVersion: parsed.identityContextVersion,
        contextHash: parsed.contextHash,
        identityId: parsed.identityId,
        targetId: parsed.targetId,
        scopeSnapshotId: parsed.scopeSnapshotId,
        status: 'active',
        payloadJson: parsed,
        createdAt: epochMs(parsed.issuedAt)
      })
      native.exec('COMMIT')
      started = false
      return parsed
    } catch (error) {
      if (started) native.exec('ROLLBACK')
      throw error
    }
  }

  async getCurrentIdentityContext(identityId: string): Promise<IdentityContext | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(identityContexts)
      .where(and(eq(identityContexts.identityId, identityId), eq(identityContexts.status, 'active')))
      .orderBy(desc(identityContexts.identityContextVersion))
      .limit(1)
    return row ? assertIdentityContextIntegrity(row.payloadJson) : undefined
  }

  async getIdentityContext(
    identityContextId: string,
    identityContextVersion: number
  ): Promise<IdentityContext | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(identityContexts)
      .where(
        and(
          eq(identityContexts.identityContextId, identityContextId),
          eq(identityContexts.identityContextVersion, identityContextVersion)
        )
      )
      .limit(1)
    return row ? assertIdentityContextIntegrity(row.payloadJson) : undefined
  }

  async getLatestIdentityContextVersion(
    identityContextId: string
  ): Promise<number | undefined> {
    const [row] = await this.database.orm
      .select({ version: identityContexts.identityContextVersion })
      .from(identityContexts)
      .where(eq(identityContexts.identityContextId, identityContextId))
      .orderBy(desc(identityContexts.identityContextVersion))
      .limit(1)
    return row?.version
  }

  async revokeIdentityContextsForIdentity(identityId: string): Promise<void> {
    this.database.native
      .prepare(
        `UPDATE identity_contexts SET status = 'revoked'
         WHERE identity_id = ? AND status = 'active'`
      )
      .run(identityId)
  }

  /* -------------------------------------------------- SessionVault ----- */

  async createSession(input: {
    readonly sessionId: string
    readonly identityId: string
    readonly targetId: string
    readonly scopeSnapshotId: string
    readonly now: number
  }): Promise<SessionVaultRecord> {
    await this.database.orm.insert(sessionVaultSessions).values({
      sessionId: input.sessionId,
      identityId: input.identityId,
      targetId: input.targetId,
      scopeSnapshotId: input.scopeSnapshotId,
      generation: 0,
      status: 'active',
      createdAt: input.now,
      updatedAt: input.now
    })
    const created = await this.getSession(input.sessionId)
    if (!created) throw new Error('Session vault row insert failed.')
    return created
  }

  async getSession(sessionId: string): Promise<SessionVaultRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(sessionVaultSessions)
      .where(eq(sessionVaultSessions.sessionId, sessionId))
      .limit(1)
    return row ? this.mapSessionRow(row) : undefined
  }

  async getSessionForIdentity(
    identityId: string,
    scopeSnapshotId: string
  ): Promise<SessionVaultRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(sessionVaultSessions)
      .where(
        and(
          eq(sessionVaultSessions.identityId, identityId),
          eq(sessionVaultSessions.scopeSnapshotId, scopeSnapshotId)
        )
      )
      .limit(1)
    return row ? this.mapSessionRow(row) : undefined
  }

  /**
   * Atomically advances the generation and moves to the requested status.
   * Returns undefined when the session does not exist. Generation regression
   * and revival without a new generation are rejected by database triggers.
   */
  async advanceSession(
    sessionId: string,
    transition: {
      readonly status: SessionVaultStatus
      readonly incrementGeneration: boolean
    },
    now: number
  ): Promise<SessionVaultRecord | undefined> {
    const native = this.database.native
    const updated = native
      .prepare(
        `UPDATE session_vault_sessions
         SET generation = generation + ?,
             status = ?,
             updated_at = ?
         WHERE session_id = ?`
      )
      .run(transition.incrementGeneration ? 1 : 0, transition.status, now, sessionId)
    if (updated.changes !== 1) return undefined
    return this.getSession(sessionId)
  }

  /**
   * Process restart boundary: in-memory vault content is gone, so every
   * previously active session is marked vault-lost with a bumped generation.
   * Old generations can never be resurrected from persisted state.
   */
  markActiveSessionsVaultLost(now: number): number {
    const result = this.database.native
      .prepare(
        `UPDATE session_vault_sessions
         SET generation = generation + 1,
             status = 'vault-lost',
             updated_at = ?
         WHERE status = 'active'`
      )
      .run(now)
    return Number(result.changes)
  }

  private mapSessionRow(row: typeof sessionVaultSessions.$inferSelect): SessionVaultRecord {
    return {
      sessionId: row.sessionId,
      identityId: row.identityId,
      targetId: row.targetId,
      scopeSnapshotId: row.scopeSnapshotId,
      generation: row.generation,
      status: row.status,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    }
  }

  /* --------------------------------------------------- CSRF bindings --- */

  async insertCsrfBinding(binding: CsrfBinding): Promise<CsrfBindingRow> {
    const parsed = assertCsrfBindingIntegrity(binding)
    await this.database.orm.insert(csrfBindings).values({
      csrfBindingId: parsed.csrfBindingId,
      csrfBindingVersion: parsed.csrfBindingVersion,
      bindingHash: parsed.bindingHash,
      identityId: parsed.identityId,
      sessionId: parsed.sessionId,
      sessionGeneration: parsed.sessionGeneration,
      origin: parsed.origin,
      boundMethod: parsed.boundMethod,
      boundPath: parsed.boundPath,
      tokenHash: parsed.tokenHash,
      useCount: 0,
      status: 'active',
      payloadJson: parsed,
      createdAt: epochMs(parsed.issuedAt)
    })
    const created = await this.getCsrfBinding(parsed.csrfBindingId, parsed.csrfBindingVersion)
    if (!created) throw new Error('CSRF binding insert failed.')
    return created
  }

  async getCsrfBinding(
    csrfBindingId: string,
    csrfBindingVersion: number
  ): Promise<CsrfBindingRow | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(csrfBindings)
      .where(
        and(
          eq(csrfBindings.csrfBindingId, csrfBindingId),
          eq(csrfBindings.csrfBindingVersion, csrfBindingVersion)
        )
      )
      .limit(1)
    return row ? this.mapCsrfRow(row) : undefined
  }

  async getCsrfBindingByHash(bindingHash: string): Promise<CsrfBindingRow | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(csrfBindings)
      .where(eq(csrfBindings.bindingHash, bindingHash))
      .limit(1)
    return row ? this.mapCsrfRow(row) : undefined
  }

  async listActiveCsrfBindingsForSession(
    sessionId: string,
    sessionGeneration: number
  ): Promise<CsrfBindingRow[]> {
    const rows = await this.database.orm
      .select()
      .from(csrfBindings)
      .where(
        and(
          eq(csrfBindings.sessionId, sessionId),
          eq(csrfBindings.sessionGeneration, sessionGeneration),
          eq(csrfBindings.status, 'active')
        )
      )
    return rows.map((row) => this.mapCsrfRow(row))
  }

  /**
   * Atomically records one token use. Returns the updated row, or undefined
   * when the binding is missing, expired, or no longer active. The use-count
   * trigger rejects regression; callers fail closed when the row cannot
   * advance.
   */
  async recordCsrfUse(
    csrfBindingId: string,
    csrfBindingVersion: number,
    now: number
  ): Promise<CsrfBindingRow | undefined> {
    const nowIso = new Date(now).toISOString()
    const native = this.database.native
    const updated = native
      .prepare(
        `UPDATE csrf_bindings
         SET use_count = use_count + 1,
             status = CASE
               WHEN use_count + 1 >= json_extract(payload_json, '$.rule.maxUses')
               THEN 'exhausted' ELSE 'active' END
         WHERE csrf_binding_id = ?
           AND csrf_binding_version = ?
           AND status = 'active'
           AND use_count < json_extract(payload_json, '$.rule.maxUses')
           AND json_extract(payload_json, '$.expiresAt') > ?
           AND EXISTS (
             SELECT 1 FROM session_vault_sessions AS session_row
             WHERE session_row.session_id = csrf_bindings.session_id
               AND session_row.identity_id = csrf_bindings.identity_id
               AND session_row.generation = csrf_bindings.session_generation
               AND session_row.status = 'active'
           )`
      )
      .run(csrfBindingId, csrfBindingVersion, nowIso)
    if (updated.changes !== 1) return undefined
    return this.getCsrfBinding(csrfBindingId, csrfBindingVersion)
  }

  async setCsrfBindingStatus(
    csrfBindingId: string,
    csrfBindingVersion: number,
    status: 'exhausted' | 'expired' | 'revoked'
  ): Promise<void> {
    this.database.native
      .prepare(
        `UPDATE csrf_bindings SET status = ?
         WHERE csrf_binding_id = ? AND csrf_binding_version = ? AND status = 'active'`
      )
      .run(status, csrfBindingId, csrfBindingVersion)
  }

  async revokeCsrfBindingsForSession(sessionId: string): Promise<void> {
    this.database.native
      .prepare(
        `UPDATE csrf_bindings SET status = 'revoked'
         WHERE session_id = ? AND status = 'active'`
      )
      .run(sessionId)
  }

  private mapCsrfRow(row: typeof csrfBindings.$inferSelect): CsrfBindingRow {
    return {
      binding: assertCsrfBindingIntegrity(row.payloadJson),
      useCount: row.useCount,
      status: row.status
    }
  }

  /* ------------------------------------------- Authorization matrices --- */

  async insertAuthorizationMatrix(matrix: AuthorizationMatrix): Promise<AuthorizationMatrix> {
    const parsed = assertMatrixIntegrity(matrix)
    const native = this.database.native
    let started = false
    try {
      native.exec('BEGIN IMMEDIATE')
      started = true
      native
        .prepare(
          `UPDATE authorization_matrices SET status = 'superseded'
           WHERE target_id = ? AND scope_snapshot_id = ? AND status = 'active'`
        )
        .run(parsed.targetId, parsed.scopeSnapshotId)
      await this.database.orm.insert(authorizationMatrices).values({
        matrixId: parsed.matrixId,
        matrixVersion: parsed.matrixVersion,
        matrixHash: parsed.matrixHash,
        targetId: parsed.targetId,
        scopeSnapshotId: parsed.scopeSnapshotId,
        status: 'active',
        payloadJson: parsed,
        createdAt: epochMs(parsed.issuedAt)
      })
      native.exec('COMMIT')
      started = false
      return parsed
    } catch (error) {
      if (started) native.exec('ROLLBACK')
      throw error
    }
  }

  async getCurrentAuthorizationMatrix(
    targetId: string,
    scopeSnapshotId: string
  ): Promise<AuthorizationMatrix | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(authorizationMatrices)
      .where(
        and(
          eq(authorizationMatrices.targetId, targetId),
          eq(authorizationMatrices.scopeSnapshotId, scopeSnapshotId),
          eq(authorizationMatrices.status, 'active')
        )
      )
      .orderBy(desc(authorizationMatrices.matrixVersion))
      .limit(1)
    return row ? assertMatrixIntegrity(row.payloadJson) : undefined
  }

  async getAuthorizationMatrix(
    matrixId: string,
    matrixVersion: number
  ): Promise<AuthorizationMatrix | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(authorizationMatrices)
      .where(
        and(
          eq(authorizationMatrices.matrixId, matrixId),
          eq(authorizationMatrices.matrixVersion, matrixVersion)
        )
      )
      .limit(1)
    return row ? assertMatrixIntegrity(row.payloadJson) : undefined
  }

  async getLatestAuthorizationMatrixVersion(matrixId: string): Promise<number | undefined> {
    const [row] = await this.database.orm
      .select({ version: authorizationMatrices.matrixVersion })
      .from(authorizationMatrices)
      .where(eq(authorizationMatrices.matrixId, matrixId))
      .orderBy(desc(authorizationMatrices.matrixVersion))
      .limit(1)
    return row?.version
  }

  /* ---------------------------------------------- Approval proposals ----- */

  async insertApprovalProposal(proposal: ApprovalProposal): Promise<ApprovalProposal> {
    const parsed = assertApprovalProposalIntegrity(proposal)
    await this.database.orm.insert(approvalProposals).values({
      proposalId: parsed.proposalId,
      proposalHash: parsed.proposalHash,
      bundleId: parsed.bundleId,
      bundleVersion: parsed.bundleVersion,
      bundleHash: parsed.bundleHash,
      payloadJson: parsed,
      createdAt: epochMs(parsed.issuedAt),
      expiresAt: epochMs(parsed.expiresAt)
    })
    return parsed
  }

  async getApprovalProposal(proposalId: string): Promise<ApprovalProposal | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(approvalProposals)
      .where(eq(approvalProposals.proposalId, proposalId))
      .limit(1)
    return row ? assertApprovalProposalIntegrity(row.payloadJson) : undefined
  }

  async getApprovalProposalByHash(proposalHash: string): Promise<ApprovalProposal | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(approvalProposals)
      .where(eq(approvalProposals.proposalHash, proposalHash))
      .limit(1)
    return row ? assertApprovalProposalIntegrity(row.payloadJson) : undefined
  }

  async getLatestApprovalProposalForBundle(
    bundleId: string,
    bundleVersion: number
  ): Promise<ApprovalProposal | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(approvalProposals)
      .where(
        and(
          eq(approvalProposals.bundleId, bundleId),
          eq(approvalProposals.bundleVersion, bundleVersion)
        )
      )
      .orderBy(desc(approvalProposals.createdAt))
      .limit(1)
    return row ? assertApprovalProposalIntegrity(row.payloadJson) : undefined
  }

  /* ------------------------------------------------ Approval records ---- */

  async insertApprovalRecord(
    record: ApprovalRecord,
    initialStatus: 'active' | 'rejected'
  ): Promise<ApprovalRecordView> {
    const parsed = assertApprovalIntegrity(record)
    if (parsed.decision === 'rejected' && initialStatus !== 'rejected') {
      throw new Error('A rejected decision cannot be stored as an active approval.')
    }
    if (parsed.decision === 'approved' && initialStatus !== 'active') {
      throw new Error('An approved decision must start as an active approval.')
    }
    await this.database.orm.insert(approvalRecords).values({
      approvalId: parsed.approvalId,
      approvalHash: parsed.approvalHash,
      proposalHash: parsed.proposalHash,
      bundleId: parsed.bundleId,
      bundleVersion: parsed.bundleVersion,
      bundleHash: parsed.bundleHash,
      decision: parsed.decision,
      approvalMode: parsed.approvalMode,
      actorId: parsed.actorId,
      actorContextHash: parsed.actorContextHash,
      status: initialStatus,
      payloadJson: parsed,
      issuedAt: epochMs(parsed.issuedAt),
      expiresAt: epochMs(parsed.expiresAt),
      consumedAt: null,
      revokedAt: null,
      revocationReason: null
    })
    const view = await this.getApprovalRecord(parsed.approvalId)
    if (!view) throw new Error('Approval record insert failed.')
    return view
  }

  async getApprovalRecord(approvalId: string): Promise<ApprovalRecordView | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(approvalRecords)
      .where(eq(approvalRecords.approvalId, approvalId))
      .limit(1)
    return row ? this.mapApprovalRow(row) : undefined
  }

  async getApprovalRecordByHash(approvalHash: string): Promise<ApprovalRecordView | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(approvalRecords)
      .where(eq(approvalRecords.approvalHash, approvalHash))
      .limit(1)
    return row ? this.mapApprovalRow(row) : undefined
  }

  async getActiveApprovalForBundle(bundleHash: string): Promise<ApprovalRecordView | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(approvalRecords)
      .where(and(eq(approvalRecords.bundleHash, bundleHash), eq(approvalRecords.status, 'active')))
      .limit(1)
    return row ? this.mapApprovalRow(row) : undefined
  }

  async getLatestApprovalForBundle(bundleHash: string): Promise<ApprovalRecordView | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(approvalRecords)
      .where(eq(approvalRecords.bundleHash, bundleHash))
      .orderBy(desc(approvalRecords.issuedAt))
      .limit(1)
    return row ? this.mapApprovalRow(row) : undefined
  }

  /**
   * Single-use consumption: succeeds exactly once for an active, unexpired
   * approved record. The consuming lease/claim is recorded by the caller in
   * the same surrounding transaction boundary.
   */
  async consumeApproval(approvalId: string, now: number): Promise<ApprovalRecordView | undefined> {
    const native = this.database.native
    const updated = native
      .prepare(
        `UPDATE approval_records
         SET status = 'consumed', consumed_at = ?
         WHERE approval_id = ?
           AND status = 'active'
           AND decision = 'approved'
           AND expires_at > ?`
      )
      .run(now, approvalId, now)
    if (updated.changes !== 1) return undefined
    return this.getApprovalRecord(approvalId)
  }

  async revokeApproval(
    approvalId: string,
    input: { readonly now: number; readonly reason: string }
  ): Promise<ApprovalRecordView | undefined> {
    const native = this.database.native
    const updated = native
      .prepare(
        `UPDATE approval_records
         SET status = 'revoked', revoked_at = ?, revocation_reason = ?
         WHERE approval_id = ? AND status = 'active'`
      )
      .run(input.now, input.reason, approvalId)
    if (updated.changes !== 1) return undefined
    return this.getApprovalRecord(approvalId)
  }

  async expireActiveApprovals(now: number): Promise<number> {
    const result = this.database.native
      .prepare(
        `UPDATE approval_records SET status = 'expired'
         WHERE status = 'active' AND expires_at <= ?`
      )
      .run(now)
    return Number(result.changes)
  }

  private mapApprovalRow(row: typeof approvalRecords.$inferSelect): ApprovalRecordView {
    const record = assertApprovalIntegrity(row.payloadJson)
    if (
      record.approvalId !== row.approvalId ||
      record.approvalHash !== row.approvalHash ||
      record.bundleHash !== row.bundleHash
    ) {
      throw new Error('Approval record columns diverge from the sealed payload.')
    }
    return {
      record,
      status: row.status,
      ...(row.consumedAt !== null
        ? { consumedAt: new Date(row.consumedAt).toISOString() }
        : {}),
      ...(row.revokedAt !== null ? { revokedAt: new Date(row.revokedAt).toISOString() } : {}),
      ...(row.revocationReason !== null ? { revocationReason: row.revocationReason } : {})
    }
  }
}
