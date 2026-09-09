import { randomUUID } from 'node:crypto'
import { and, eq, inArray } from 'drizzle-orm'
import {
  CleanupReceiptSchema,
  L2ActionBundleSchema,
  L2ExecutionFreezeSchema,
  TestObjectSchema,
  type CleanupReceipt,
  type L2ActionBundle,
  type L2BundleEventType,
  type L2BundleState,
  type L2ExecutionFreeze,
  type L2ProtocolReasonCode,
  type TestObject
} from '@agentgo/contracts'
import {
  hashL2Value,
  unsignedCleanupReceipt,
  unsignedL2ActionBundle,
  unsignedTestObject
} from '@agentgo/domain'
import type { AgentGoDatabase } from './database'
import {
  cleanupReceipts,
  l2ActionBundles,
  l2BundleEvents,
  l2BundleRuntime,
  l2ExecutionFreezes,
  testObjects
} from './schema'

export type L2PrimarySentProof = 'not-sent' | 'sent' | 'unknown'

export interface L2BundleRuntimeRecord {
  readonly bundleId: string
  readonly bundleVersion: number
  readonly bundleHash: string
  readonly state: L2BundleState
  readonly rowVersion: number
  readonly primaryStarted: boolean
  readonly primarySentProof: L2PrimarySentProof
  readonly freezeId: string | null
  readonly updatedAt: number
}

export interface L2BundleEventRecord {
  readonly eventId: string
  readonly bundleId: string
  readonly bundleVersion: number
  readonly bundleHash: string
  readonly fromState: L2BundleState
  readonly toState: L2BundleState
  readonly eventType: L2BundleEventType | 'create'
  readonly reasonCode: L2ProtocolReasonCode
  readonly rowVersionBefore: number
  readonly rowVersionAfter: number
  readonly createdAt: number
}

export interface PersistL2RuntimeTransitionInput {
  readonly bundleId: string
  readonly bundleVersion: number
  readonly expectedRowVersion: number
  readonly fromState: L2BundleState
  readonly toState: L2BundleState
  readonly eventType: L2BundleEventType | 'create'
  readonly reasonCode: L2ProtocolReasonCode
  readonly primaryStarted: boolean
  readonly primarySentProof: L2PrimarySentProof
  readonly freezeId?: string | null
}

function epochMs(iso: string): number {
  const value = Date.parse(iso)
  if (!Number.isFinite(value)) {
    throw new TypeError('L2 timestamp is not a valid ISO-8601 instant.')
  }
  return value
}

function assertTestObjectIntegrity(object: TestObject): TestObject {
  const parsed = TestObjectSchema.parse(object)
  if (parsed.objectHash !== hashL2Value(unsignedTestObject(parsed))) {
    throw new Error('TestObject hash mismatch.')
  }
  return parsed
}

function assertBundleIntegrity(bundle: L2ActionBundle): L2ActionBundle {
  const parsed = L2ActionBundleSchema.parse(bundle)
  if (parsed.bundleHash !== hashL2Value(unsignedL2ActionBundle(parsed))) {
    throw new Error('L2ActionBundle hash mismatch.')
  }
  return parsed
}

function assertReceiptIntegrity(receipt: CleanupReceipt): CleanupReceipt {
  const parsed = CleanupReceiptSchema.parse(receipt)
  if (parsed.receiptHash !== hashL2Value(unsignedCleanupReceipt(parsed))) {
    throw new Error('CleanupReceipt hash mismatch.')
  }
  return parsed
}

export class L2Repository {
  constructor(private readonly database: AgentGoDatabase) {}

  async insertTestObject(object: TestObject): Promise<TestObject> {
    const parsed = assertTestObjectIntegrity(object)
    const native = this.database.native
    let started = false
    try {
      native.exec('BEGIN IMMEDIATE')
      started = true
      await this.database.orm.insert(testObjects).values({
        testObjectId: parsed.testObjectId,
        objectVersion: parsed.objectVersion,
        objectHash: parsed.objectHash,
        scanId: parsed.scanId,
        targetId: parsed.targetId,
        identityId: parsed.identityId,
        scopeSnapshotId: parsed.scopeSnapshotId,
        tenantRef: parsed.tenantRef ?? null,
        disposable: true,
        createdAt: epochMs(parsed.createdAt),
        expiresAt: epochMs(parsed.expiresAt),
        payloadJson: parsed
      })
      native.exec('COMMIT')
      started = false
      return parsed
    } catch (error) {
      if (started) native.exec('ROLLBACK')
      throw error
    }
  }

  async getTestObject(
    testObjectId: string,
    objectVersion: number
  ): Promise<TestObject | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(testObjects)
      .where(
        and(
          eq(testObjects.testObjectId, testObjectId),
          eq(testObjects.objectVersion, objectVersion)
        )
      )
      .limit(1)
    return row ? assertTestObjectIntegrity(row.payloadJson) : undefined
  }

  async insertBundle(input: {
    bundle: L2ActionBundle
    state: L2BundleState
    now?: number
  }): Promise<L2BundleRuntimeRecord> {
    const parsed = assertBundleIntegrity(input.bundle)
    const now = input.now ?? Date.now()
    const native = this.database.native
    let started = false
    try {
      native.exec('BEGIN IMMEDIATE')
      started = true
      await this.database.orm.insert(l2ActionBundles).values({
        bundleId: parsed.bundleId,
        bundleVersion: parsed.bundleVersion,
        bundleHash: parsed.bundleHash,
        scanId: parsed.scanId,
        targetId: parsed.targetId,
        testObjectId: parsed.testObjectId,
        testObjectVersion: parsed.testObjectVersion,
        identityId: parsed.identityId,
        scopeSnapshotId: parsed.scopeSnapshotId,
        payloadJson: parsed,
        createdAt: epochMs(parsed.createdAt)
      })
      await this.database.orm.insert(l2BundleRuntime).values({
        bundleId: parsed.bundleId,
        bundleVersion: parsed.bundleVersion,
        bundleHash: parsed.bundleHash,
        state: input.state,
        rowVersion: 1,
        primaryStarted: false,
        primarySentProof: 'not-sent',
        freezeId: null,
        updatedAt: now
      })
      await this.database.orm.insert(l2BundleEvents).values({
        eventId: randomUUID(),
        bundleId: parsed.bundleId,
        bundleVersion: parsed.bundleVersion,
        bundleHash: parsed.bundleHash,
        fromState: input.state,
        toState: input.state,
        eventType: 'create',
        reasonCode: 'ok',
        rowVersionBefore: 0,
        rowVersionAfter: 1,
        createdAt: now
      })
      native.exec('COMMIT')
      started = false
      const runtime = await this.getRuntime(parsed.bundleId, parsed.bundleVersion)
      if (!runtime) throw new Error('L2 bundle runtime insert failed.')
      return runtime
    } catch (error) {
      if (started) native.exec('ROLLBACK')
      throw error
    }
  }

  async getBundle(
    bundleId: string,
    bundleVersion: number
  ): Promise<L2ActionBundle | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(l2ActionBundles)
      .where(
        and(
          eq(l2ActionBundles.bundleId, bundleId),
          eq(l2ActionBundles.bundleVersion, bundleVersion)
        )
      )
      .limit(1)
    return row ? assertBundleIntegrity(row.payloadJson) : undefined
  }

  async getRuntime(
    bundleId: string,
    bundleVersion: number
  ): Promise<L2BundleRuntimeRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(l2BundleRuntime)
      .where(
        and(
          eq(l2BundleRuntime.bundleId, bundleId),
          eq(l2BundleRuntime.bundleVersion, bundleVersion)
        )
      )
      .limit(1)
    if (!row) return undefined
    return {
      bundleId: row.bundleId,
      bundleVersion: row.bundleVersion,
      bundleHash: row.bundleHash,
      state: row.state,
      rowVersion: row.rowVersion,
      primaryStarted: row.primaryStarted,
      primarySentProof: row.primarySentProof,
      freezeId: row.freezeId,
      updatedAt: row.updatedAt
    }
  }

  async listRuntimesForTestObject(
    testObjectId: string
  ): Promise<L2BundleRuntimeRecord[]> {
    const rows = await this.database.orm
      .select({
        bundleId: l2BundleRuntime.bundleId,
        bundleVersion: l2BundleRuntime.bundleVersion,
        bundleHash: l2BundleRuntime.bundleHash,
        state: l2BundleRuntime.state,
        rowVersion: l2BundleRuntime.rowVersion,
        primaryStarted: l2BundleRuntime.primaryStarted,
        primarySentProof: l2BundleRuntime.primarySentProof,
        freezeId: l2BundleRuntime.freezeId,
        updatedAt: l2BundleRuntime.updatedAt
      })
      .from(l2BundleRuntime)
      .innerJoin(
        l2ActionBundles,
        and(
          eq(l2ActionBundles.bundleId, l2BundleRuntime.bundleId),
          eq(l2ActionBundles.bundleVersion, l2BundleRuntime.bundleVersion)
        )
      )
      .where(eq(l2ActionBundles.testObjectId, testObjectId))
    return rows
  }

  async applyRuntimeTransition(
    input: PersistL2RuntimeTransitionInput
  ): Promise<L2BundleRuntimeRecord> {
    const now = Date.now()
    const nextVersion = input.expectedRowVersion + 1
    const native = this.database.native
    let started = false
    try {
      native.exec('BEGIN IMMEDIATE')
      started = true
      const updated = native
        .prepare(
          `UPDATE l2_bundle_runtime
           SET state = ?,
               row_version = ?,
               primary_started = ?,
               primary_sent_proof = ?,
               freeze_id = ?,
               updated_at = ?
           WHERE bundle_id = ?
             AND bundle_version = ?
             AND row_version = ?`
        )
        .run(
          input.toState,
          nextVersion,
          input.primaryStarted ? 1 : 0,
          input.primarySentProof,
          input.freezeId ?? null,
          now,
          input.bundleId,
          input.bundleVersion,
          input.expectedRowVersion
        )
      if (updated.changes !== 1) {
        throw new Error('L2 concurrent version conflict.')
      }
      native
        .prepare(
          `INSERT INTO l2_bundle_events (
             event_id, bundle_id, bundle_version, bundle_hash,
             from_state, to_state, event_type, reason_code,
             row_version_before, row_version_after, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          randomUUID(),
          input.bundleId,
          input.bundleVersion,
          (
            native
              .prepare(
                `SELECT bundle_hash AS bundleHash
                   FROM l2_bundle_runtime
                  WHERE bundle_id = ? AND bundle_version = ?`
              )
              .get(input.bundleId, input.bundleVersion) as {
              bundleHash: string
            }
          ).bundleHash,
          input.fromState,
          input.toState,
          input.eventType,
          input.reasonCode,
          input.expectedRowVersion,
          nextVersion,
          now
        )
      native.exec('COMMIT')
      started = false
    } catch (error) {
      if (started) native.exec('ROLLBACK')
      throw error
    }
    const runtime = await this.getRuntime(input.bundleId, input.bundleVersion)
    if (!runtime) throw new Error('L2 runtime disappeared after transition.')
    return runtime
  }

  async insertReceipt(
    receipt: CleanupReceipt,
    bundleVersion: number
  ): Promise<CleanupReceipt> {
    const parsed = assertReceiptIntegrity(receipt)
    const native = this.database.native
    let started = false
    try {
      native.exec('BEGIN IMMEDIATE')
      started = true
      await this.database.orm.insert(cleanupReceipts).values({
        receiptId: parsed.receiptId,
        receiptHash: parsed.receiptHash,
        bundleId: parsed.bundleId,
        bundleVersion,
        bundleHash: parsed.bundleHash,
        testObjectId: parsed.testObjectId,
        testObjectVersion: parsed.testObjectVersion,
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

  async getReceipt(receiptId: string): Promise<CleanupReceipt | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(cleanupReceipts)
      .where(eq(cleanupReceipts.receiptId, receiptId))
      .limit(1)
    return row ? assertReceiptIntegrity(row.payloadJson) : undefined
  }

  async insertFreeze(freeze: L2ExecutionFreeze): Promise<L2ExecutionFreeze> {
    const parsed = L2ExecutionFreezeSchema.parse(freeze)
    const native = this.database.native
    let started = false
    try {
      native.exec('BEGIN IMMEDIATE')
      started = true
      native
        .prepare(
          `INSERT OR IGNORE INTO l2_execution_freezes (
             freeze_id, target_id, test_object_id, bundle_id, bundle_hash,
             reason_code, allows, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          parsed.freezeId,
          parsed.targetId,
          parsed.testObjectId,
          parsed.bundleId,
          parsed.bundleHash,
          parsed.reasonCode,
          parsed.allows,
          epochMs(parsed.createdAt)
        )
      native.exec('COMMIT')
      started = false
    } catch (error) {
      if (started) native.exec('ROLLBACK')
      throw error
    }
    const stored = await this.getActiveFreeze(parsed.targetId, parsed.testObjectId)
    if (!stored) throw new Error('L2 execution freeze insert failed.')
    return stored
  }

  async getActiveFreeze(
    targetId: string,
    testObjectId: string
  ): Promise<L2ExecutionFreeze | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(l2ExecutionFreezes)
      .where(
        and(
          eq(l2ExecutionFreezes.targetId, targetId),
          eq(l2ExecutionFreezes.testObjectId, testObjectId)
        )
      )
      .limit(1)
    return row
      ? L2ExecutionFreezeSchema.parse({
          freezeId: row.freezeId,
          targetId: row.targetId,
          testObjectId: row.testObjectId,
          bundleId: row.bundleId,
          bundleHash: row.bundleHash,
          reasonCode: row.reasonCode,
          allows: row.allows,
          createdAt: new Date(row.createdAt).toISOString()
        })
      : undefined
  }

  async getBundleByHash(bundleHash: string): Promise<L2ActionBundle | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(l2ActionBundles)
      .where(eq(l2ActionBundles.bundleHash, bundleHash))
      .limit(1)
    return row ? assertBundleIntegrity(row.payloadJson) : undefined
  }

  /**
   * Lists every bundle whose runtime is not in a terminal state. Used by the
   * binding service to propagate session/identity/matrix invalidation.
   */
  async listOpenBundles(): Promise<
    { readonly bundle: L2ActionBundle; readonly runtime: L2BundleRuntimeRecord }[]
  > {
    const rows = await this.database.orm
      .select()
      .from(l2BundleRuntime)
      .where(
        inArray(l2BundleRuntime.state, [
          'draft',
          'ineligible',
          'pending-approval',
          'approved',
          'primary-unknown'
        ])
      )
    const result: { bundle: L2ActionBundle; runtime: L2BundleRuntimeRecord }[] = []
    for (const row of rows) {
      const bundle = await this.getBundle(row.bundleId, row.bundleVersion)
      if (!bundle) continue
      result.push({
        bundle,
        runtime: {
          bundleId: row.bundleId,
          bundleVersion: row.bundleVersion,
          bundleHash: row.bundleHash,
          state: row.state,
          rowVersion: row.rowVersion,
          primaryStarted: row.primaryStarted,
          primarySentProof: row.primarySentProof,
          freezeId: row.freezeId,
          updatedAt: row.updatedAt
        }
      })
    }
    return result
  }

  async listEvents(
    bundleId: string,
    bundleVersion: number
  ): Promise<L2BundleEventRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(l2BundleEvents)
      .where(
        and(
          eq(l2BundleEvents.bundleId, bundleId),
          eq(l2BundleEvents.bundleVersion, bundleVersion)
        )
      )
    return rows.map((row) => ({
      eventId: row.eventId,
      bundleId: row.bundleId,
      bundleVersion: row.bundleVersion,
      bundleHash: row.bundleHash,
      fromState: row.fromState,
      toState: row.toState,
      eventType: row.eventType as L2BundleEventRecord['eventType'],
      reasonCode: row.reasonCode as L2ProtocolReasonCode,
      rowVersionBefore: row.rowVersionBefore,
      rowVersionAfter: row.rowVersionAfter,
      createdAt: row.createdAt
    }))
  }
}
