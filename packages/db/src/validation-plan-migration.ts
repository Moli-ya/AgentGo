import type { DatabaseMigration } from './migrations'

/**
 * Day 14 persistence: generic ValidationPlan runs, per-step runs,
 * observations, and Evidence bindings by role/ordinal/profile.
 */
export const VALIDATION_PLAN_MIGRATION: DatabaseMigration = {
  id: '0016_validation_plan_runtime',
  sql: `
CREATE TABLE validation_plan_runs (
  run_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  plan_id TEXT NOT NULL,
  plan_hash TEXT NOT NULL CHECK (length(plan_hash) = 64),
  status TEXT NOT NULL CHECK (
    status IN ('pending', 'running', 'succeeded', 'failed', 'stopped', 'fail-closed')
  ),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX validation_plan_runs_scan_idx
  ON validation_plan_runs(scan_id, created_at);

CREATE TABLE validation_step_runs (
  step_run_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES validation_plan_runs(run_id) ON DELETE CASCADE,
  step_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL CHECK (
    status IN ('pending', 'running', 'succeeded', 'failed', 'stopped', 'fail-closed')
  ),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX validation_step_runs_run_idx
  ON validation_step_runs(run_id, ordinal);

CREATE TABLE validation_observations (
  observation_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES validation_plan_runs(run_id) ON DELETE CASCADE,
  step_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL
);
CREATE INDEX validation_observations_run_idx
  ON validation_observations(run_id, created_at);

CREATE TABLE validation_evidence_bindings (
  binding_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES validation_plan_runs(run_id) ON DELETE CASCADE,
  step_id TEXT NOT NULL,
  evidence_ref TEXT NOT NULL REFERENCES evidence_items(id) ON DELETE RESTRICT,
  role TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  profile_id TEXT NOT NULL,
  profile_version TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json))
);
CREATE UNIQUE INDEX validation_evidence_bindings_role_uq
  ON validation_evidence_bindings(run_id, step_id, role, ordinal);
CREATE INDEX validation_evidence_bindings_run_idx
  ON validation_evidence_bindings(run_id, step_id);
`
}
