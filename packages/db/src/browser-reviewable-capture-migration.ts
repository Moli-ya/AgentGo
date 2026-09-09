import type { DatabaseSync } from 'node:sqlite'
import type { DatabaseMigration } from './migrations'

const REPLACED_TRIGGER_NAMES = new Set([
  'execution_capture_decisions_insert_guard',
  'execution_capture_decisions_immutable_update_guard',
  'execution_capture_decisions_immutable_delete_guard',
  'execution_leases_insert_guard'
])

const TRIGGER_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/

const REBUILD_CAPTURE_TABLE_SQL = `
CREATE TABLE execution_capture_decisions_next (
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES execution_grants(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
  capture_policy_id TEXT NOT NULL,
  capture_policy_version TEXT NOT NULL,
  technique_id TEXT NOT NULL,
  technique_version TEXT NOT NULL,
  step_id TEXT NOT NULL,
  execution_state TEXT NOT NULL CHECK (
    execution_state IN (
      'succeeded', 'failed', 'cancelled', 'timed-out', 'interrupted'
    )
  ),
  source TEXT NOT NULL CHECK (
    source IN (
      'http-request-summary', 'http-response-summary',
      'browser-request-summary', 'browser-result-summary',
      'execution-interruption-summary',
      'dom-snapshot', 'browser-screenshot'
    )
  ),
  role TEXT NOT NULL CHECK (
    length(trim(role)) BETWEEN 1 AND 100 AND role = trim(role)
  ),
  action TEXT NOT NULL CHECK (action IN ('hash-only', 'protected-original')),
  valid_from INTEGER NOT NULL,
  valid_until INTEGER NOT NULL CHECK (valid_until >= valid_from),
  max_source_bytes INTEGER NOT NULL CHECK (
    max_source_bytes BETWEEN 1 AND 16777216
  ),
  max_excerpt_bytes INTEGER NOT NULL CHECK (
    max_excerpt_bytes BETWEEN 32 AND 65536
      AND max_excerpt_bytes <= max_source_bytes
  ),
  json_pointers_json TEXT NOT NULL CHECK (
    json_valid(json_pointers_json)
      AND json_type(json_pointers_json) = 'array'
      AND json_array_length(json_pointers_json) = 0
  ),
  oob_metadata_fields_json TEXT NOT NULL CHECK (
    json_valid(oob_metadata_fields_json)
      AND json_type(oob_metadata_fields_json) = 'array'
      AND json_array_length(oob_metadata_fields_json) = 0
  ),
  oob_commitment_key_ref TEXT,
  oob_commitment_key_version INTEGER,
  decision_json TEXT NOT NULL CHECK (
    json_valid(decision_json)
  ),
  UNIQUE (grant_id, source, execution_state),
  CHECK (
    oob_commitment_key_ref IS NULL AND oob_commitment_key_version IS NULL
  )
);

INSERT INTO execution_capture_decisions_next
SELECT * FROM execution_capture_decisions;

DROP TABLE execution_capture_decisions;
ALTER TABLE execution_capture_decisions_next
  RENAME TO execution_capture_decisions;

CREATE INDEX execution_capture_decisions_grant_idx
  ON execution_capture_decisions(grant_id);
`

const REPLACEMENT_TRIGGER_SQL = `
CREATE TRIGGER execution_capture_decisions_insert_guard
BEFORE INSERT ON execution_capture_decisions
WHEN EXISTS (
  SELECT 1 FROM execution_leases WHERE grant_id = NEW.grant_id
)
OR NOT EXISTS (
  SELECT 1
  FROM execution_grants AS grant_row
  WHERE grant_row.id = NEW.grant_id
    AND grant_row.scan_id = NEW.scan_id
    AND grant_row.policy_decision_id = NEW.policy_decision_id
    AND grant_row.technique_id = NEW.technique_id
    AND grant_row.technique_version = NEW.technique_version
    AND grant_row.step_id = NEW.step_id
    AND grant_row.valid_from = NEW.valid_from
    AND grant_row.valid_until = NEW.valid_until
    AND (
      (
        NEW.action = 'hash-only'
        AND (SELECT COUNT(*) FROM json_each(NEW.decision_json)) = 18
        AND json_type(NEW.decision_json, '$.protectedOriginalPlan') IS NULL
        AND (
          (
            NEW.source = 'execution-interruption-summary'
            AND NEW.execution_state = 'interrupted'
          )
          OR (
            NEW.execution_state <> 'interrupted'
            AND (
              (grant_row.adapter_kind = 'http'
                AND NEW.source IN (
                  'http-request-summary', 'http-response-summary'
                ))
              OR (grant_row.adapter_kind = 'browser-offline'
                AND NEW.source IN (
                  'browser-request-summary', 'browser-result-summary'
                ))
            )
          )
        )
        AND NEW.role = CASE NEW.source
          WHEN 'http-request-summary' THEN 'request-summary'
          WHEN 'http-response-summary' THEN 'response-summary'
          WHEN 'browser-request-summary' THEN 'request-summary'
          WHEN 'browser-result-summary' THEN 'result-summary'
          WHEN 'execution-interruption-summary' THEN 'interruption-summary'
        END
      )
      OR (
        grant_row.adapter_kind = 'browser-offline'
        AND NEW.action = 'protected-original'
        AND (SELECT COUNT(*) FROM json_each(NEW.decision_json)) = 19
        AND NEW.execution_state <> 'interrupted'
        AND NEW.source IN ('dom-snapshot', 'browser-screenshot')
        AND NEW.role = CASE NEW.source
          WHEN 'dom-snapshot' THEN 'dom-snapshot'
          WHEN 'browser-screenshot' THEN 'screenshot'
        END
        AND json_type(NEW.decision_json, '$.protectedOriginalPlan') = 'object'
      )
    )
    AND json_extract(NEW.decision_json, '$.id') = NEW.id
    AND json_extract(NEW.decision_json, '$.scanId') = NEW.scan_id
    AND json_extract(NEW.decision_json, '$.policyDecisionId')
      = NEW.policy_decision_id
    AND json_extract(NEW.decision_json, '$.capturePolicyId')
      = NEW.capture_policy_id
    AND json_extract(NEW.decision_json, '$.capturePolicyVersion')
      = NEW.capture_policy_version
    AND json_extract(NEW.decision_json, '$.techniqueId') = NEW.technique_id
    AND json_extract(NEW.decision_json, '$.techniqueVersion')
      = NEW.technique_version
    AND json_extract(NEW.decision_json, '$.stepId') = NEW.step_id
    AND json_extract(NEW.decision_json, '$.executionState')
      = NEW.execution_state
    AND json_extract(NEW.decision_json, '$.source') = NEW.source
    AND json_extract(NEW.decision_json, '$.role') = NEW.role
    AND json_extract(NEW.decision_json, '$.action') = NEW.action
    AND json_extract(NEW.decision_json, '$.validFrom')
      = strftime('%Y-%m-%dT%H:%M:%fZ', NEW.valid_from / 1000.0, 'unixepoch')
    AND json_extract(NEW.decision_json, '$.validUntil')
      = strftime('%Y-%m-%dT%H:%M:%fZ', NEW.valid_until / 1000.0, 'unixepoch')
    AND json_extract(NEW.decision_json, '$.maxSourceBytes')
      = NEW.max_source_bytes
    AND json_extract(NEW.decision_json, '$.maxExcerptBytes')
      = NEW.max_excerpt_bytes
    AND json(json_extract(NEW.decision_json, '$.jsonPointers'))
      = json(NEW.json_pointers_json)
    AND json(json_extract(NEW.decision_json, '$.oobMetadataFields'))
      = json(NEW.oob_metadata_fields_json)
    AND json_type(NEW.decision_json, '$.oobCommitmentKeyRef') IS NULL
    AND json_type(NEW.decision_json, '$.oobCommitmentKeyVersion') IS NULL
)
BEGIN
  SELECT RAISE(ABORT, 'execution capture decision binding is invalid');
END;

CREATE TRIGGER execution_capture_decisions_immutable_update_guard
BEFORE UPDATE ON execution_capture_decisions
BEGIN
  SELECT RAISE(ABORT, 'execution capture decisions are immutable');
END;

CREATE TRIGGER execution_capture_decisions_immutable_delete_guard
BEFORE DELETE ON execution_capture_decisions
WHEN EXISTS (
  SELECT 1
  FROM execution_grants
  INNER JOIN scans ON scans.id = execution_grants.scan_id
  WHERE execution_grants.id = OLD.grant_id
)
BEGIN
  SELECT RAISE(ABORT, 'execution capture decisions are immutable');
END;

CREATE TRIGGER execution_leases_insert_guard
BEFORE INSERT ON execution_leases
WHEN NOT EXISTS (
  SELECT 1
  FROM execution_grants AS grant_row
  WHERE grant_row.id = NEW.grant_id
    AND NEW.state = 'issued'
    AND (SELECT COUNT(*)
      FROM execution_capture_decisions
      WHERE grant_id = grant_row.id
        AND source = 'execution-interruption-summary'
        AND execution_state = 'interrupted') = 1
    AND (
      (grant_row.adapter_kind = 'http'
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id) = 9
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id
            AND source = 'http-request-summary') = 4
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id
            AND source = 'http-response-summary') = 4)
      OR (grant_row.adapter_kind = 'browser-offline'
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id) = 17
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id
            AND source = 'browser-request-summary') = 4
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id
            AND source = 'browser-result-summary') = 4
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id
            AND source = 'dom-snapshot'
            AND action = 'protected-original') = 4
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id
            AND source = 'browser-screenshot'
            AND action = 'protected-original') = 4)
    )
    AND NEW.issued_at >= grant_row.valid_from
    AND NEW.expires_at <= grant_row.valid_until
    AND NEW.attempt = COALESCE((
      SELECT MAX(existing.attempt) + 1
      FROM execution_leases AS existing
      WHERE existing.grant_id = NEW.grant_id
    ), 1)
    AND (
      (NEW.attempt = 1 AND grant_row.redirect_hop = 0 AND NEW.parent_lease_id IS NULL)
      OR (NEW.attempt = 1 AND grant_row.redirect_hop > 0 AND EXISTS (
        SELECT 1
        FROM execution_leases AS parent_lease
        WHERE parent_lease.id = NEW.parent_lease_id
          AND parent_lease.grant_id = grant_row.parent_grant_id
          AND parent_lease.state = 'completed'
      ))
      OR (NEW.attempt > 1
        AND grant_row.retry_class = 'deterministic-readonly'
        AND grant_row.purpose = 'read'
        AND EXISTS (
          SELECT 1
          FROM execution_leases AS previous_lease
          WHERE previous_lease.id = NEW.parent_lease_id
            AND previous_lease.grant_id = NEW.grant_id
            AND previous_lease.attempt = NEW.attempt - 1
            AND previous_lease.state = 'failed'
            AND previous_lease.delivery_state = 'not-dispatched'
        ))
    )
)
BEGIN
  SELECT RAISE(ABORT, 'execution lease issuance is invalid');
END;
`

function quoteIdent(name: string): string {
  if (!TRIGGER_NAME_PATTERN.test(name)) {
    throw new Error(`Refusing to drop an unsafe trigger name: ${name}`)
  }
  return name
}

function rebuildBrowserReviewableCapture(database: DatabaseSync): void {
  const triggers = database
    .prepare(
      `SELECT name, sql
       FROM sqlite_master
       WHERE type = 'trigger'
         AND sql LIKE '%execution_capture_decisions%'`
    )
    .all() as Array<{ name: string; sql: string | null }>
  for (const trigger of triggers) {
    database.exec(`DROP TRIGGER IF EXISTS ${quoteIdent(trigger.name)}`)
  }

  database.exec(REBUILD_CAPTURE_TABLE_SQL)
  database.exec(REPLACEMENT_TRIGGER_SQL)

  for (const trigger of triggers) {
    if (REPLACED_TRIGGER_NAMES.has(trigger.name) || !trigger.sql) {
      continue
    }
    database.exec(trigger.sql)
  }
}

/**
 * Day 18/20: offline browser grants persist 17 capture decisions.
 * HTTP remains 9 hash-only summaries. Do not edit historical 0007 SQL.
 *
 * Rebuilds only `execution_capture_decisions`. Child lease-evidence rows stay
 * in place; other triggers are snapshotted and restored so 0008/0009 guards
 * are not rolled back. Lease finalize still binds two hash-only summary links.
 */
export const BROWSER_REVIEWABLE_CAPTURE_MIGRATION: DatabaseMigration = {
  id: '0018_browser_reviewable_capture_decisions',
  foreignKeys: 'off',
  sql: 'SELECT 1;',
  dataHook: rebuildBrowserReviewableCapture
}
