import { createHash } from 'node:crypto'
import type { DatabaseSync } from 'node:sqlite'
import { DEFAULT_SCAN_MAX_REQUEST_BYTES, DEFAULT_SCAN_MAX_RESPONSE_BYTES } from '@agentgo/contracts'
import { deriveScopeNetworkEntriesFromOrigins } from '@agentgo/security-policy'
import type { DatabaseMigration } from './migrations'

// Must stay identical to persistableNetworkEntries in ./repository: entry ids
// are scope-qualified so identical origins on different scopes never collide.
function persistableNetworkEntryId(scopeId: string, entryId: string): string {
  return createHash('sha256').update(`${scopeId}:${entryId}`).digest('hex')
}

function backfillScanBudgetsAndNetworkEntries(database: DatabaseSync): void {
  database.exec(`
UPDATE scans
SET budget_json = json_set(
  budget_json,
  '$.maxRequestBytes',
  COALESCE(
    json_extract(budget_json, '$.maxRequestBytes'),
    ${DEFAULT_SCAN_MAX_REQUEST_BYTES}
  ),
  '$.maxResponseBytes',
  COALESCE(
    json_extract(budget_json, '$.maxResponseBytes'),
    ${DEFAULT_SCAN_MAX_RESPONSE_BYTES}
  )
)
WHERE json_valid(budget_json)
  AND (
    json_extract(budget_json, '$.maxRequestBytes') IS NULL
    OR json_extract(budget_json, '$.maxResponseBytes') IS NULL
  );
`)

  const scopes = database
    .prepare(
      `SELECT id, allowed_origins, created_at
       FROM target_scopes`
    )
    .all() as Array<{ id: string; allowed_origins: string; created_at: number }>
  const insert = database.prepare(
    `INSERT OR IGNORE INTO target_scope_network_entries (
       id, scope_id, address_class, host, ip, cidr, ports_json, purpose, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  for (const scope of scopes) {
    let origins: unknown
    try {
      origins = JSON.parse(scope.allowed_origins)
    } catch {
      continue
    }
    if (!Array.isArray(origins) || origins.some((origin) => typeof origin !== 'string')) {
      continue
    }
    for (const entry of deriveScopeNetworkEntriesFromOrigins(origins)) {
      insert.run(
        persistableNetworkEntryId(scope.id, entry.id),
        scope.id,
        entry.addressClass,
        entry.host ?? null,
        entry.ip ?? null,
        entry.cidr ?? null,
        JSON.stringify(entry.ports),
        entry.purpose,
        scope.created_at
      )
    }
  }
}

/**
 * Atomic budget accounts, precise scope network entries, and
 * security counters. Reserve happens in the same BEGIN IMMEDIATE as the
 * lease claim; settle happens at finalize/recovery. Cancel/timeout/crash
 * conservatively consume the reserved request and sent bytes.
 */
export const ATOMIC_BUDGET_AND_NETWORK_GATES_MIGRATION: DatabaseMigration = {
  id: '0011_atomic_budget_and_network_gates',
  sql: `
CREATE TABLE target_scope_network_entries (
  id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL REFERENCES target_scopes(id) ON DELETE CASCADE,
  address_class TEXT NOT NULL CHECK (
    address_class IN ('private', 'loopback', 'link-local', 'reserved')
  ),
  host TEXT,
  ip TEXT,
  cidr TEXT,
  ports_json TEXT NOT NULL CHECK (
    json_valid(ports_json)
      AND json_type(ports_json) = 'array'
      AND json_array_length(ports_json) >= 1
  ),
  purpose TEXT NOT NULL CHECK (purpose IN ('execution', 'ssrf-target')),
  created_at INTEGER NOT NULL,
  CHECK (
    host IS NOT NULL OR ip IS NOT NULL OR cidr IS NOT NULL
  )
);
CREATE INDEX target_scope_network_entries_scope_idx
  ON target_scope_network_entries(scope_id, address_class);

CREATE TRIGGER target_scope_network_entries_ports_guard
BEFORE INSERT ON target_scope_network_entries
BEGIN
  SELECT RAISE(ABORT, 'network-entry-ports-invalid')
  WHERE EXISTS (
    SELECT 1 FROM json_each(NEW.ports_json)
    WHERE json_each.type != 'integer'
      OR json_each.value < 1
      OR json_each.value > 65535
  );
END;

CREATE TABLE scan_budget_ledger (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  execution_lease_id TEXT NOT NULL REFERENCES execution_leases(id),
  identity_id TEXT,
  technique_id TEXT,
  kind TEXT NOT NULL CHECK (
    kind IN ('reserve', 'settle', 'release')
  ),
  request_units INTEGER NOT NULL DEFAULT 0 CHECK (request_units >= 0),
  request_bytes INTEGER NOT NULL DEFAULT 0 CHECK (request_bytes >= 0),
  response_bytes INTEGER NOT NULL DEFAULT 0 CHECK (response_bytes >= 0),
  concurrency_units INTEGER NOT NULL DEFAULT 0 CHECK (concurrency_units >= 0),
  reason TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE (execution_lease_id, kind)
);
CREATE INDEX scan_budget_ledger_scan_created_idx
  ON scan_budget_ledger(scan_id, created_at);
CREATE INDEX scan_budget_ledger_lease_idx
  ON scan_budget_ledger(execution_lease_id);

ALTER TABLE scans
  ADD COLUMN reserved_request_bytes INTEGER NOT NULL DEFAULT 0
    CHECK (reserved_request_bytes >= 0);
ALTER TABLE scans
  ADD COLUMN reserved_response_bytes INTEGER NOT NULL DEFAULT 0
    CHECK (reserved_response_bytes >= 0);
ALTER TABLE scans
  ADD COLUMN active_concurrency INTEGER NOT NULL DEFAULT 0
    CHECK (active_concurrency >= 0);
ALTER TABLE scans
  ADD COLUMN security_counters_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(security_counters_json));
ALTER TABLE scans
  ADD COLUMN oob_poll_count INTEGER NOT NULL DEFAULT 0
    CHECK (oob_poll_count >= 0);
ALTER TABLE scans
  ADD COLUMN browser_action_count INTEGER NOT NULL DEFAULT 0
    CHECK (browser_action_count >= 0);

-- Fail closed before the AFTER reserve trigger mutates counters.
CREATE TRIGGER execution_lease_claim_budget_guard
BEFORE UPDATE OF state ON execution_leases
WHEN NEW.state = 'claimed' AND OLD.state = 'issued'
BEGIN
  SELECT RAISE(ABORT, 'budget-exhausted-concurrency')
  WHERE EXISTS (
    SELECT 1
    FROM execution_grants AS grant_row
    INNER JOIN scans AS scan_row ON scan_row.id = grant_row.scan_id
    INNER JOIN target_scopes AS scope_row
      ON scope_row.id = grant_row.scope_snapshot_id
    WHERE grant_row.id = NEW.grant_id
      AND json_type(scan_row.budget_json, '$.maxConcurrency') = 'integer'
      AND scan_row.active_concurrency + 1 >
          MIN(
            scope_row.max_concurrency,
            json_extract(scan_row.budget_json, '$.maxConcurrency')
          )
  );

  SELECT RAISE(ABORT, 'budget-exhausted-rpm')
  WHERE EXISTS (
    SELECT 1
    FROM execution_grants AS grant_row
    INNER JOIN scans AS scan_row ON scan_row.id = grant_row.scan_id
    INNER JOIN target_scopes AS scope_row
      ON scope_row.id = grant_row.scope_snapshot_id
    WHERE grant_row.id = NEW.grant_id
      AND json_type(scan_row.budget_json, '$.maxRequestsPerMinute') = 'integer'
      AND (
        SELECT COUNT(*)
        FROM scan_budget_ledger AS ledger_row
        WHERE ledger_row.scan_id = scan_row.id
          AND ledger_row.kind = 'reserve'
          AND ledger_row.created_at > NEW.claimed_at - 60000
      ) + 1 >
          MIN(
            scope_row.max_requests_per_minute,
            json_extract(scan_row.budget_json, '$.maxRequestsPerMinute')
          )
  );

  SELECT RAISE(ABORT, 'budget-exhausted-bytes')
  WHERE EXISTS (
    SELECT 1
    FROM execution_grants AS grant_row
    INNER JOIN scans AS scan_row ON scan_row.id = grant_row.scan_id
    WHERE grant_row.id = NEW.grant_id
      AND (
        json_type(scan_row.budget_json, '$.maxRequestBytes') IS NOT 'integer'
        OR json_type(scan_row.budget_json, '$.maxResponseBytes') IS NOT 'integer'
        OR scan_row.reserved_request_bytes
             + COALESCE(json_extract(grant_row.budget_json, '$.requestBytes'), 0)
           > json_extract(scan_row.budget_json, '$.maxRequestBytes')
        OR scan_row.reserved_response_bytes
             + COALESCE(json_extract(grant_row.budget_json, '$.maxResponseBytes'), 0)
           > json_extract(scan_row.budget_json, '$.maxResponseBytes')
      )
  );

  SELECT RAISE(ABORT, 'budget-exhausted-duration')
  WHERE EXISTS (
    SELECT 1
    FROM execution_grants AS grant_row
    INNER JOIN scans AS scan_row ON scan_row.id = grant_row.scan_id
    WHERE grant_row.id = NEW.grant_id
      AND json_type(scan_row.budget_json, '$.maxDurationMinutes') = 'integer'
      AND (
        scan_row.started_at IS NULL
        OR NEW.claimed_at - scan_row.started_at
             >= json_extract(scan_row.budget_json, '$.maxDurationMinutes') * 60 * 1000
      )
  );
END;

CREATE TRIGGER execution_lease_claim_budget_reserve
AFTER UPDATE OF state ON execution_leases
WHEN NEW.state = 'claimed' AND OLD.state = 'issued'
BEGIN
  INSERT INTO scan_budget_ledger (
    id, scan_id, execution_lease_id, identity_id, technique_id, kind,
    request_units, request_bytes, response_bytes, concurrency_units,
    reason, created_at
  )
  SELECT
    lower(hex(randomblob(16))),
    grant_row.scan_id,
    NEW.id,
    json_extract(grant_row.identity_ref_json, '$.id'),
    grant_row.technique_id,
    'reserve',
    json_extract(grant_row.budget_json, '$.requestUnits'),
    json_extract(grant_row.budget_json, '$.requestBytes'),
    json_extract(grant_row.budget_json, '$.maxResponseBytes'),
    1,
    'claim',
    NEW.claimed_at
  FROM execution_grants AS grant_row
  WHERE grant_row.id = NEW.grant_id;

  UPDATE scans
  SET reserved_request_bytes = reserved_request_bytes + (
        SELECT json_extract(grant_row.budget_json, '$.requestBytes')
        FROM execution_grants AS grant_row
        WHERE grant_row.id = NEW.grant_id
      ),
      reserved_response_bytes = reserved_response_bytes + (
        SELECT json_extract(grant_row.budget_json, '$.maxResponseBytes')
        FROM execution_grants AS grant_row
        WHERE grant_row.id = NEW.grant_id
      ),
      active_concurrency = active_concurrency + 1,
      updated_at = NEW.claimed_at
  WHERE id = (SELECT scan_id FROM execution_grants WHERE id = NEW.grant_id);
END;

CREATE TRIGGER execution_lease_final_budget_settle
AFTER UPDATE OF state ON execution_leases
WHEN NEW.state IN ('completed', 'failed') AND OLD.state = 'claimed'
BEGIN
  INSERT INTO scan_budget_ledger (
    id, scan_id, execution_lease_id, identity_id, technique_id, kind,
    request_units, request_bytes, response_bytes, concurrency_units,
    reason, created_at
  )
  SELECT
    lower(hex(randomblob(16))),
    grant_row.scan_id,
    NEW.id,
    json_extract(grant_row.identity_ref_json, '$.id'),
    grant_row.technique_id,
    'settle',
    0,
    COALESCE(json_extract(NEW.outcome_summary_json, '$.requestBytes'), 0),
    COALESCE(json_extract(NEW.outcome_summary_json, '$.responseBytes'), 0),
    1,
    NEW.terminal_reason,
    NEW.terminal_at
  FROM execution_grants AS grant_row
  WHERE grant_row.id = NEW.grant_id;

  UPDATE scans
  SET reserved_request_bytes = MAX(
        0,
        reserved_request_bytes - (
          SELECT json_extract(grant_row.budget_json, '$.requestBytes')
          FROM execution_grants AS grant_row
          WHERE grant_row.id = NEW.grant_id
        ) + COALESCE(
          json_extract(NEW.outcome_summary_json, '$.requestBytes'), 0
        )
      ),
      reserved_response_bytes = MAX(
        0,
        reserved_response_bytes - (
          SELECT json_extract(grant_row.budget_json, '$.maxResponseBytes')
          FROM execution_grants AS grant_row
          WHERE grant_row.id = NEW.grant_id
        ) + COALESCE(
          json_extract(NEW.outcome_summary_json, '$.responseBytes'), 0
        )
      ),
      active_concurrency = MAX(0, active_concurrency - 1),
      updated_at = NEW.terminal_at
  WHERE id = (SELECT scan_id FROM execution_grants WHERE id = NEW.grant_id);
END;
`,
  dataHook: backfillScanBudgetsAndNetworkEntries
}
