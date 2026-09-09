import type { DatabaseSync } from 'node:sqlite'
import type { DatabaseMigration } from './migrations'

const IDENTITY_CONTEXT_STATES = `'active', 'superseded', 'revoked'`
const SESSION_STATES = `'active', 'expired', 'revoked', 'vault-lost'`
const CSRF_BINDING_STATES = `'active', 'exhausted', 'expired', 'revoked'`
const MATRIX_STATES = `'active', 'superseded', 'revoked'`
const APPROVAL_STATES = `'active', 'consumed', 'rejected', 'revoked', 'expired'`

/**
 * Replaces the Day 7/8 "session/test-object refs must be null" grant/lease
 * guards with authoritative SessionVault and TestObject lookups.
 */
export function executionOpaqueRefSql(grantAlias: 'NEW' | 'grant_row'): string {
  const issuedAt =
    grantAlias === 'NEW' ? 'NEW.issued_at' : `${grantAlias}.issued_at`
  const scanId = grantAlias === 'NEW' ? 'NEW.scan_id' : `${grantAlias}.scan_id`
  const scopeId =
    grantAlias === 'NEW'
      ? 'NEW.scope_snapshot_id'
      : `${grantAlias}.scope_snapshot_id`
  const identityRef =
    grantAlias === 'NEW'
      ? 'NEW.identity_ref_json'
      : `${grantAlias}.identity_ref_json`
  const purpose = grantAlias === 'NEW' ? 'NEW.purpose' : `${grantAlias}.purpose`
  return `
    AND (
      ${grantAlias}.session_ref_json IS NULL
      OR (
        json_extract(${grantAlias}.session_ref_json, '$.statusSummary') = 'active'
        AND EXISTS (
          SELECT 1
          FROM session_vault_sessions AS session_row
          WHERE session_row.session_id = json_extract(${grantAlias}.session_ref_json, '$.id')
            AND session_row.generation = json_extract(${grantAlias}.session_ref_json, '$.generation')
            AND session_row.status = 'active'
            AND session_row.target_id = json_extract(${grantAlias}.session_ref_json, '$.ownerRef')
            AND session_row.scope_snapshot_id = json_extract(${grantAlias}.session_ref_json, '$.scopeSnapshotId')
            AND session_row.scope_snapshot_id = ${scopeId}
            AND session_row.target_id = target_row.id
            AND (
              ${identityRef} IS NULL
              OR session_row.identity_id = json_extract(${identityRef}, '$.id')
            )
        )
      )
    )
    AND (
      ${grantAlias}.test_object_ref_json IS NULL
      OR (
        json_extract(${grantAlias}.test_object_ref_json, '$.statusSummary') IN ('ready', 'in-use')
        AND EXISTS (
          SELECT 1
          FROM test_objects AS object_row
          WHERE object_row.test_object_id = json_extract(${grantAlias}.test_object_ref_json, '$.id')
            AND object_row.object_version = json_extract(${grantAlias}.test_object_ref_json, '$.version')
            AND object_row.target_id = json_extract(${grantAlias}.test_object_ref_json, '$.ownerRef')
            AND object_row.scope_snapshot_id = json_extract(${grantAlias}.test_object_ref_json, '$.scopeSnapshotId')
            AND object_row.scope_snapshot_id = ${scopeId}
            AND object_row.scan_id = ${scanId}
            AND object_row.target_id = target_row.id
            AND object_row.disposable = 1
            AND object_row.expires_at > ${issuedAt}
            AND (
              ${identityRef} IS NULL
              OR object_row.identity_id = json_extract(${identityRef}, '$.id')
            )
            AND (
              ${purpose} = 'cleanup'
              OR NOT EXISTS (
                SELECT 1
                FROM l2_execution_freezes AS freeze_row
                WHERE freeze_row.target_id = object_row.target_id
                  AND freeze_row.test_object_id = object_row.test_object_id
              )
            )
        )
      )
    )`
}

function replaceNullOpaqueRefGuards(
  sql: string,
  grantAlias: 'NEW' | 'grant_row'
): string {
  const pattern = new RegExp(
    `AND\\s+${grantAlias}\\.session_ref_json IS NULL\\s+AND\\s+${grantAlias}\\.test_object_ref_json IS NULL`,
    'gu'
  )
  if (!pattern.test(sql)) {
    throw new Error(
      `Could not locate null opaque-ref guards for ${grantAlias} in an execution trigger.`
    )
  }
  return sql.replace(
    new RegExp(
      `AND\\s+${grantAlias}\\.session_ref_json IS NULL\\s+AND\\s+${grantAlias}\\.test_object_ref_json IS NULL`,
      'gu'
    ),
    executionOpaqueRefSql(grantAlias)
  )
}

function rewriteExecutionOpaqueRefGuards(database: DatabaseSync): void {
  const names = [
    { name: 'execution_grants_insert_guard', alias: 'NEW' as const },
    { name: 'execution_leases_claim_guard', alias: 'grant_row' as const },
    { name: 'execution_leases_delivery_guard', alias: 'grant_row' as const }
  ]
  for (const trigger of names) {
    const row = database
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'trigger'
           AND name = ?
         LIMIT 1`
      )
      .get(trigger.name) as { sql?: unknown } | undefined
    if (typeof row?.sql !== 'string') {
      throw new Error(`Missing execution trigger ${trigger.name} during 0013 rewrite.`)
    }
    const next = replaceNullOpaqueRefGuards(row.sql, trigger.alias)
    database.exec(`DROP TRIGGER ${trigger.name}`)
    database.exec(next)
  }
}

/**
 * Day 9/10 persistence: versioned identity contexts, session vault metadata
 * (no cookie/token/CSRF plaintext ever), CSRF bindings, human-confirmed
 * authorization matrices, and single-use L2 approval records. Payload tables
 * are insert-only; the mutable rows (sessions, binding use counts, approval
 * lifecycle columns) can only move forward.
 */
export const IDENTITY_SESSION_AND_APPROVAL_MIGRATION: DatabaseMigration = {
  id: '0013_identity_session_and_l2_approval',
  sql: `
CREATE TABLE identity_contexts (
  identity_context_id TEXT NOT NULL,
  identity_context_version INTEGER NOT NULL CHECK (identity_context_version >= 1),
  context_hash TEXT NOT NULL CHECK (length(context_hash) = 64),
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN (${IDENTITY_CONTEXT_STATES})),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (identity_context_id, identity_context_version)
);
CREATE UNIQUE INDEX identity_contexts_hash_uq ON identity_contexts(context_hash);
CREATE INDEX identity_contexts_identity_idx
  ON identity_contexts(identity_id, identity_context_version);

CREATE TRIGGER identity_contexts_immutable_update_guard
BEFORE UPDATE ON identity_contexts
WHEN NEW.identity_context_id IS NOT OLD.identity_context_id
  OR NEW.identity_context_version IS NOT OLD.identity_context_version
  OR NEW.context_hash IS NOT OLD.context_hash
  OR NEW.identity_id IS NOT OLD.identity_id
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.scope_snapshot_id IS NOT OLD.scope_snapshot_id
  OR NEW.payload_json IS NOT OLD.payload_json
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'identity context payloads are immutable');
END;

CREATE TABLE session_vault_sessions (
  session_id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  generation INTEGER NOT NULL CHECK (generation >= 0),
  status TEXT NOT NULL CHECK (status IN (${SESSION_STATES})),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (identity_id, scope_snapshot_id)
);

CREATE TRIGGER session_vault_generation_monotonic_guard
BEFORE UPDATE ON session_vault_sessions
WHEN NEW.generation < OLD.generation
BEGIN
  SELECT RAISE(ABORT, 'session generation cannot regress');
END;

CREATE TRIGGER session_vault_no_revival_guard
BEFORE UPDATE ON session_vault_sessions
WHEN OLD.status <> 'active' AND NEW.status = 'active' AND NEW.generation <= OLD.generation
BEGIN
  SELECT RAISE(ABORT, 'a session can only reactivate with a new generation');
END;

CREATE TRIGGER session_vault_identity_columns_guard
BEFORE UPDATE ON session_vault_sessions
WHEN NEW.session_id IS NOT OLD.session_id
  OR NEW.identity_id IS NOT OLD.identity_id
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.scope_snapshot_id IS NOT OLD.scope_snapshot_id
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'session identity columns are immutable');
END;

CREATE TABLE csrf_bindings (
  csrf_binding_id TEXT NOT NULL,
  csrf_binding_version INTEGER NOT NULL CHECK (csrf_binding_version >= 1),
  binding_hash TEXT NOT NULL CHECK (length(binding_hash) = 64),
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES session_vault_sessions(session_id) ON DELETE CASCADE,
  session_generation INTEGER NOT NULL CHECK (session_generation >= 0),
  origin TEXT NOT NULL,
  bound_method TEXT NOT NULL CHECK (bound_method IN ('POST', 'PUT', 'PATCH')),
  bound_path TEXT NOT NULL,
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
  use_count INTEGER NOT NULL CHECK (use_count >= 0),
  status TEXT NOT NULL CHECK (status IN (${CSRF_BINDING_STATES})),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (csrf_binding_id, csrf_binding_version)
);
CREATE UNIQUE INDEX csrf_bindings_hash_uq ON csrf_bindings(binding_hash);
CREATE INDEX csrf_bindings_session_idx
  ON csrf_bindings(session_id, session_generation, status);

CREATE TRIGGER csrf_bindings_immutable_update_guard
BEFORE UPDATE ON csrf_bindings
WHEN NEW.csrf_binding_id IS NOT OLD.csrf_binding_id
  OR NEW.csrf_binding_version IS NOT OLD.csrf_binding_version
  OR NEW.binding_hash IS NOT OLD.binding_hash
  OR NEW.identity_id IS NOT OLD.identity_id
  OR NEW.session_id IS NOT OLD.session_id
  OR NEW.session_generation IS NOT OLD.session_generation
  OR NEW.origin IS NOT OLD.origin
  OR NEW.bound_method IS NOT OLD.bound_method
  OR NEW.bound_path IS NOT OLD.bound_path
  OR NEW.token_hash IS NOT OLD.token_hash
  OR NEW.payload_json IS NOT OLD.payload_json
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'csrf binding payloads are immutable');
END;

CREATE TRIGGER csrf_bindings_use_count_monotonic_guard
BEFORE UPDATE ON csrf_bindings
WHEN NEW.use_count < OLD.use_count
BEGIN
  SELECT RAISE(ABORT, 'csrf binding use count cannot regress');
END;

CREATE TRIGGER csrf_bindings_no_revival_guard
BEFORE UPDATE ON csrf_bindings
WHEN OLD.status <> 'active' AND NEW.status = 'active'
BEGIN
  SELECT RAISE(ABORT, 'a non-active csrf binding cannot be revived');
END;

CREATE TABLE authorization_matrices (
  matrix_id TEXT NOT NULL,
  matrix_version INTEGER NOT NULL CHECK (matrix_version >= 1),
  matrix_hash TEXT NOT NULL CHECK (length(matrix_hash) = 64),
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN (${MATRIX_STATES})),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (matrix_id, matrix_version)
);
CREATE UNIQUE INDEX authorization_matrices_hash_uq
  ON authorization_matrices(matrix_hash);
CREATE INDEX authorization_matrices_target_idx
  ON authorization_matrices(target_id, scope_snapshot_id, matrix_version);

CREATE TRIGGER authorization_matrices_immutable_update_guard
BEFORE UPDATE ON authorization_matrices
WHEN NEW.matrix_id IS NOT OLD.matrix_id
  OR NEW.matrix_version IS NOT OLD.matrix_version
  OR NEW.matrix_hash IS NOT OLD.matrix_hash
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.scope_snapshot_id IS NOT OLD.scope_snapshot_id
  OR NEW.payload_json IS NOT OLD.payload_json
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'authorization matrix payloads are immutable');
END;

CREATE TABLE approval_proposals (
  proposal_id TEXT PRIMARY KEY,
  proposal_hash TEXT NOT NULL CHECK (length(proposal_hash) = 64),
  bundle_id TEXT NOT NULL,
  bundle_version INTEGER NOT NULL,
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) = 64),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  CHECK (expires_at > created_at),
  FOREIGN KEY (bundle_id, bundle_version)
    REFERENCES l2_action_bundles(bundle_id, bundle_version)
    ON DELETE CASCADE
);
CREATE UNIQUE INDEX approval_proposals_hash_uq ON approval_proposals(proposal_hash);
CREATE INDEX approval_proposals_bundle_idx
  ON approval_proposals(bundle_id, bundle_version);

CREATE TRIGGER approval_proposals_immutable_update_guard
BEFORE UPDATE ON approval_proposals
BEGIN
  SELECT RAISE(ABORT, 'approval proposals are immutable');
END;

CREATE TABLE approval_records (
  approval_id TEXT PRIMARY KEY,
  approval_hash TEXT NOT NULL CHECK (length(approval_hash) = 64),
  proposal_hash TEXT NOT NULL CHECK (length(proposal_hash) = 64),
  bundle_id TEXT NOT NULL,
  bundle_version INTEGER NOT NULL,
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) = 64),
  decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
  approval_mode TEXT NOT NULL CHECK (approval_mode IN ('fixture-only', 'trusted-backend')),
  actor_id TEXT NOT NULL,
  actor_context_hash TEXT NOT NULL CHECK (length(actor_context_hash) = 64),
  status TEXT NOT NULL CHECK (status IN (${APPROVAL_STATES})),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  revoked_at INTEGER,
  revocation_reason TEXT,
  CHECK (expires_at > issued_at),
  FOREIGN KEY (bundle_id, bundle_version)
    REFERENCES l2_action_bundles(bundle_id, bundle_version)
    ON DELETE CASCADE
);
CREATE UNIQUE INDEX approval_records_hash_uq ON approval_records(approval_hash);
CREATE INDEX approval_records_bundle_idx
  ON approval_records(bundle_id, bundle_version, status);

CREATE TRIGGER approval_records_immutable_update_guard
BEFORE UPDATE ON approval_records
WHEN NEW.approval_id IS NOT OLD.approval_id
  OR NEW.approval_hash IS NOT OLD.approval_hash
  OR NEW.proposal_hash IS NOT OLD.proposal_hash
  OR NEW.bundle_id IS NOT OLD.bundle_id
  OR NEW.bundle_version IS NOT OLD.bundle_version
  OR NEW.bundle_hash IS NOT OLD.bundle_hash
  OR NEW.decision IS NOT OLD.decision
  OR NEW.approval_mode IS NOT OLD.approval_mode
  OR NEW.actor_id IS NOT OLD.actor_id
  OR NEW.actor_context_hash IS NOT OLD.actor_context_hash
  OR NEW.payload_json IS NOT OLD.payload_json
  OR NEW.issued_at IS NOT OLD.issued_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
  SELECT RAISE(ABORT, 'approval record payloads are immutable');
END;

CREATE TRIGGER approval_records_consume_once_guard
BEFORE UPDATE OF consumed_at ON approval_records
WHEN OLD.consumed_at IS NOT NULL
  AND (NEW.consumed_at IS NULL OR NEW.consumed_at <> OLD.consumed_at)
BEGIN
  SELECT RAISE(ABORT, 'an approval consumption marker cannot change');
END;

CREATE TRIGGER approval_records_consumed_terminal_guard
BEFORE UPDATE ON approval_records
WHEN OLD.status IN ('consumed', 'rejected', 'revoked', 'expired')
  AND NEW.status <> OLD.status
BEGIN
  SELECT RAISE(ABORT, 'a terminal approval status cannot change');
END;
`,
  dataHook: rewriteExecutionOpaqueRefGuards
}
