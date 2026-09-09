import type { DatabaseMigration } from './migrations'

/**
 * Day 13 persistence: InventoryMergeReport, DependencyGraph, and
 * BrowserRecon observations. Inventory rows still go through InventoryService.
 */
export const BROWSER_RECON_AND_MERGE_MIGRATION: DatabaseMigration = {
  id: '0015_browser_recon_merge_and_dependency_graph',
  sql: `
CREATE TABLE inventory_merge_reports (
  report_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL
);
CREATE INDEX inventory_merge_reports_scan_idx
  ON inventory_merge_reports(scan_id, created_at);

CREATE TABLE dependency_graphs (
  graph_id TEXT PRIMARY KEY,
  graph_hash TEXT NOT NULL CHECK (length(graph_hash) = 64),
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE RESTRICT,
  frozen INTEGER NOT NULL CHECK (frozen IN (0, 1)),
  paused INTEGER NOT NULL CHECK (paused IN (0, 1)),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX dependency_graphs_hash_uq ON dependency_graphs(graph_hash);
CREATE INDEX dependency_graphs_scan_idx ON dependency_graphs(scan_id, created_at);

CREATE TABLE dependency_edge_candidates (
  candidate_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  review_status TEXT NOT NULL CHECK (review_status IN ('unreviewed', 'reviewed', 'rejected')),
  created_at INTEGER NOT NULL
);
CREATE INDEX dependency_edge_candidates_scan_idx
  ON dependency_edge_candidates(scan_id, created_at);

CREATE TABLE browser_recon_observations (
  observation_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL
);
CREATE INDEX browser_recon_observations_scan_idx
  ON browser_recon_observations(scan_id, created_at);
`
}
