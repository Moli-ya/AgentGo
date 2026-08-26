import type { DatabaseMigration } from './migrations'

const L2_BUNDLE_STATES = `'draft', 'ineligible', 'pending-approval', 'approved', 'running-pre-read', 'running-primary', 'primary-unknown', 'running-post-read', 'cleanup-pending', 'cleanup-running', 'cleanup-verifying', 'clean', 'cleanup-failed', 'expired', 'revoked', 'interrupted', 'inconclusive'`

/**
 * L2 protocol persistence: immutable TestObject and bundle payloads,
 * optimistic runtime rows, append-only events/receipts, and per
 * (target, test object) cleanup-failure freezes. No network I/O.
 */
export const L2_PROTOCOL_MIGRATION: DatabaseMigration = {
  id: '0012_l2_test_object_and_bundle_state',
  sql: `
CREATE TABLE test_objects (
  test_object_id TEXT NOT NULL,
  object_version INTEGER NOT NULL CHECK (object_version >= 1),
  object_hash TEXT NOT NULL CHECK (length(object_hash) = 64),
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  tenant_ref TEXT,
  disposable INTEGER NOT NULL CHECK (disposable = 1),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  PRIMARY KEY (test_object_id, object_version),
  CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX test_objects_hash_uq ON test_objects(object_hash);
CREATE INDEX test_objects_scan_idx ON test_objects(scan_id, created_at);
CREATE INDEX test_objects_target_idx ON test_objects(target_id, test_object_id);

CREATE TABLE l2_action_bundles (
  bundle_id TEXT NOT NULL,
  bundle_version INTEGER NOT NULL CHECK (bundle_version >= 1),
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) = 64),
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  test_object_id TEXT NOT NULL,
  test_object_version INTEGER NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (bundle_id, bundle_version),
  FOREIGN KEY (test_object_id, test_object_version)
    REFERENCES test_objects(test_object_id, object_version)
    ON DELETE CASCADE
);
CREATE UNIQUE INDEX l2_action_bundles_hash_uq ON l2_action_bundles(bundle_hash);
CREATE INDEX l2_action_bundles_object_idx
  ON l2_action_bundles(test_object_id, test_object_version, created_at);

CREATE TABLE l2_bundle_runtime (
  bundle_id TEXT NOT NULL,
  bundle_version INTEGER NOT NULL,
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) = 64),
  state TEXT NOT NULL CHECK (state IN (${L2_BUNDLE_STATES})),
  row_version INTEGER NOT NULL CHECK (row_version >= 1),
  primary_started INTEGER NOT NULL CHECK (primary_started IN (0, 1)),
  primary_sent_proof TEXT NOT NULL CHECK (
    primary_sent_proof IN ('not-sent', 'sent', 'unknown')
  ),
  freeze_id TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (bundle_id, bundle_version),
  FOREIGN KEY (bundle_id, bundle_version)
    REFERENCES l2_action_bundles(bundle_id, bundle_version)
    ON DELETE CASCADE
);
CREATE INDEX l2_bundle_runtime_state_idx ON l2_bundle_runtime(state, updated_at);
CREATE INDEX l2_bundle_runtime_hash_idx ON l2_bundle_runtime(bundle_hash);

CREATE TABLE l2_bundle_events (
  event_id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL,
  bundle_version INTEGER NOT NULL,
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) = 64),
  from_state TEXT NOT NULL CHECK (from_state IN (${L2_BUNDLE_STATES})),
  to_state TEXT NOT NULL CHECK (to_state IN (${L2_BUNDLE_STATES})),
  event_type TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  row_version_before INTEGER NOT NULL,
  row_version_after INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (bundle_id, bundle_version)
    REFERENCES l2_action_bundles(bundle_id, bundle_version)
    ON DELETE CASCADE
);
CREATE INDEX l2_bundle_events_bundle_idx
  ON l2_bundle_events(bundle_id, bundle_version, created_at);

CREATE TABLE cleanup_receipts (
  receipt_id TEXT PRIMARY KEY,
  receipt_hash TEXT NOT NULL CHECK (length(receipt_hash) = 64),
  bundle_id TEXT NOT NULL,
  bundle_version INTEGER NOT NULL,
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) = 64),
  test_object_id TEXT NOT NULL,
  test_object_version INTEGER NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  FOREIGN KEY (bundle_id, bundle_version)
    REFERENCES l2_action_bundles(bundle_id, bundle_version)
    ON DELETE CASCADE,
  FOREIGN KEY (test_object_id, test_object_version)
    REFERENCES test_objects(test_object_id, object_version)
    ON DELETE CASCADE
);
CREATE UNIQUE INDEX cleanup_receipts_hash_uq ON cleanup_receipts(receipt_hash);
CREATE UNIQUE INDEX cleanup_receipts_bundle_uq
  ON cleanup_receipts(bundle_id, bundle_version);

CREATE TABLE l2_execution_freezes (
  freeze_id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  test_object_id TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  bundle_hash TEXT NOT NULL CHECK (length(bundle_hash) = 64),
  reason_code TEXT NOT NULL CHECK (reason_code = 'cleanup-failed-frozen'),
  allows TEXT NOT NULL CHECK (allows = 'recovery-proposal-or-manual'),
  created_at INTEGER NOT NULL,
  UNIQUE (target_id, test_object_id)
);
CREATE INDEX l2_execution_freezes_object_idx
  ON l2_execution_freezes(test_object_id, target_id);

CREATE TRIGGER test_objects_immutable_update_guard
BEFORE UPDATE ON test_objects
BEGIN
  SELECT RAISE(ABORT, 'test objects are immutable');
END;

CREATE TRIGGER l2_action_bundles_immutable_update_guard
BEFORE UPDATE ON l2_action_bundles
BEGIN
  SELECT RAISE(ABORT, 'l2 action bundles are immutable');
END;

CREATE TRIGGER cleanup_receipts_immutable_update_guard
BEFORE UPDATE ON cleanup_receipts
BEGIN
  SELECT RAISE(ABORT, 'cleanup receipts are immutable');
END;

CREATE TRIGGER l2_bundle_events_immutable_update_guard
BEFORE UPDATE ON l2_bundle_events
BEGIN
  SELECT RAISE(ABORT, 'l2 bundle events are immutable');
END;

CREATE TRIGGER l2_execution_freezes_immutable_update_guard
BEFORE UPDATE ON l2_execution_freezes
BEGIN
  SELECT RAISE(ABORT, 'l2 execution freezes are immutable');
END;
`
}
