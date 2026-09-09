import type { DatabaseMigration } from './migrations'

/**
 * Day 15 persistence: generic CandidateAttempt rows bound to ValidationPlan
 * runs, grants, and Evidence refs. Status is only-forward in application
 * code; the table stores the current attempt snapshot.
 */
export const CANDIDATE_ATTEMPT_MIGRATION: DatabaseMigration = {
  id: '0017_candidate_attempts',
  sql: `
CREATE TABLE candidate_attempts (
  attempt_id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  candidate_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (
    status IN (
      'planned',
      'awaiting-approval',
      'awaiting-session',
      'awaiting-input',
      'running',
      'cleanup-pending',
      'interrupted',
      'cancelled',
      'failed',
      'completed',
      'inconclusive',
      'rejected'
    )
  ),
  decision TEXT NOT NULL CHECK (
    decision IN (
      'executable',
      'inventory-only',
      'awaiting-user',
      'forbidden',
      'rejected'
    )
  ),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX candidate_attempts_scan_idx
  ON candidate_attempts(scan_id, created_at);
CREATE INDEX candidate_attempts_scan_status_idx
  ON candidate_attempts(scan_id, status);
`
}
