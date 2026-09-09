import type { DatabaseMigration } from './migrations'

/**
 * Day 11/12 persistence: offline import preview/commit audit and
 * static-discovery / AssetManifest / ExtractionRule records.
 * Inventory writes continue to go through the existing Inventory port.
 */
export const IMPORT_AND_STATIC_DISCOVERY_MIGRATION: DatabaseMigration = {
  id: '0014_import_and_static_discovery',
  sql: `
CREATE TABLE import_previews (
  preview_id TEXT PRIMARY KEY,
  preview_hash TEXT NOT NULL CHECK (length(preview_hash) = 64),
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  source_bytes_hash TEXT NOT NULL CHECK (length(source_bytes_hash) = 64),
  parser_name TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'committed', 'expired')),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  CHECK (expires_at > created_at)
);
CREATE INDEX import_previews_scan_idx ON import_previews(scan_id, created_at);
CREATE INDEX import_previews_hash_idx ON import_previews(preview_hash);

CREATE TABLE import_commits (
  commit_id TEXT PRIMARY KEY,
  preview_id TEXT NOT NULL REFERENCES import_previews(preview_id) ON DELETE RESTRICT,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  source_bytes_hash TEXT NOT NULL CHECK (length(source_bytes_hash) = 64),
  parser_version TEXT NOT NULL,
  import_actor_ref TEXT NOT NULL,
  accepted_count INTEGER NOT NULL CHECK (accepted_count >= 0),
  source_ids_json TEXT NOT NULL CHECK (json_valid(source_ids_json)),
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX import_commits_idempotency_uq
  ON import_commits(scan_id, source_bytes_hash, parser_version);

CREATE TABLE static_discovery_batches (
  batch_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  artifact_ref TEXT NOT NULL,
  artifact_hash TEXT NOT NULL CHECK (length(artifact_hash) = 64),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX static_discovery_artifact_uq
  ON static_discovery_batches(scan_id, artifact_hash);
CREATE INDEX static_discovery_scan_idx
  ON static_discovery_batches(scan_id, created_at);

CREATE TABLE asset_manifests (
  manifest_id TEXT NOT NULL,
  manifest_version INTEGER NOT NULL CHECK (manifest_version >= 1),
  manifest_hash TEXT NOT NULL CHECK (length(manifest_hash) = 64),
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  frozen INTEGER NOT NULL CHECK (frozen IN (0, 1)),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  frozen_at INTEGER,
  PRIMARY KEY (manifest_id, manifest_version),
  CHECK (frozen = 0 OR frozen_at IS NOT NULL)
);
CREATE UNIQUE INDEX asset_manifests_hash_uq ON asset_manifests(manifest_hash);
CREATE INDEX asset_manifests_scan_idx ON asset_manifests(scan_id, created_at);

CREATE TRIGGER asset_manifests_frozen_update_guard
BEFORE UPDATE ON asset_manifests
WHEN OLD.frozen = 1
BEGIN
  SELECT RAISE(ABORT, 'frozen asset manifests are immutable');
END;

CREATE TABLE extraction_rules (
  rule_id TEXT PRIMARY KEY,
  rule_hash TEXT NOT NULL CHECK (length(rule_hash) = 64),
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  review_status TEXT NOT NULL CHECK (review_status IN ('unreviewed', 'reviewed', 'rejected')),
  frozen INTEGER NOT NULL CHECK (frozen IN (0, 1)),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX extraction_rules_hash_uq ON extraction_rules(rule_hash);
CREATE INDEX extraction_rules_scan_idx ON extraction_rules(scan_id, created_at);

CREATE TRIGGER extraction_rules_frozen_update_guard
BEFORE UPDATE ON extraction_rules
WHEN OLD.frozen = 1
BEGIN
  SELECT RAISE(ABORT, 'frozen extraction rules are immutable');
END;
`
}
