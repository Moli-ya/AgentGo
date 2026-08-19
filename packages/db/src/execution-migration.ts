import type { DatabaseSync } from 'node:sqlite'
import type { DatabaseMigration } from './migrations'

/** Day 5 capability grants, single-use leases, and immutable audit bindings. */
export const DAY5_EXECUTION_MIGRATION: DatabaseMigration = {
  id: '0007_execution_grants_and_leases',
  sql: `
ALTER TABLE policy_decisions
  ADD COLUMN authorized_wire_request_hmac_json TEXT
  CHECK (
    authorized_wire_request_hmac_json IS NULL
      OR (
        json_valid(authorized_wire_request_hmac_json)
        AND json_extract(authorized_wire_request_hmac_json, '$.domain')
          = 'agentgo.wire-request.v2'
        AND json_extract(authorized_wire_request_hmac_json, '$.algorithm')
          = 'hmac-sha256'
        AND json_type(authorized_wire_request_hmac_json, '$.keyRef') = 'text'
        AND json_type(authorized_wire_request_hmac_json, '$.keyVersion') = 'integer'
        AND json_extract(authorized_wire_request_hmac_json, '$.keyVersion') >= 0
        AND length(json_extract(authorized_wire_request_hmac_json, '$.digest')) = 64
        AND json_extract(authorized_wire_request_hmac_json, '$.digest')
          NOT GLOB '*[^0-9a-f]*'
      )
  );

DROP INDEX IF EXISTS evidence_items_scan_hash_uq;
CREATE INDEX evidence_items_scan_type_hash_idx
  ON evidence_items(scan_id, type, sha256);

CREATE TABLE execution_grants (
  schema_version TEXT NOT NULL CHECK (schema_version = 'execution-grant.v1'),
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id),
  scope_snapshot_hash TEXT NOT NULL CHECK (
    length(scope_snapshot_hash) = 64
      AND scope_snapshot_hash NOT GLOB '*[^0-9a-f]*'
  ),
  module_snapshot_id TEXT NOT NULL REFERENCES scan_module_snapshots(id),
  module_snapshot_hash TEXT NOT NULL CHECK (
    length(module_snapshot_hash) = 64
      AND module_snapshot_hash NOT GLOB '*[^0-9a-f]*'
  ),
  module_id TEXT NOT NULL,
  module_version TEXT NOT NULL,
  technique_id TEXT NOT NULL,
  technique_version TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  plan_version TEXT NOT NULL CHECK (
    length(plan_version) BETWEEN 1 AND 256
      AND plan_version = trim(plan_version)
      AND plan_version NOT GLOB '*[' || char(0) || '-' || char(31) || char(127) || ']*'
  ),
  plan_hash TEXT NOT NULL CHECK (
    length(plan_hash) = 64 AND plan_hash NOT GLOB '*[^0-9a-f]*'
  ),
  step_id TEXT NOT NULL,
  template_intent_hash_json TEXT NOT NULL CHECK (
    json_valid(template_intent_hash_json)
      AND json_extract(template_intent_hash_json, '$.domain') = 'agentgo.template-intent.v1'
      AND json_extract(template_intent_hash_json, '$.algorithm') = 'sha256'
      AND length(json_extract(template_intent_hash_json, '$.digest')) = 64
      AND json_extract(template_intent_hash_json, '$.digest') NOT GLOB '*[^0-9a-f]*'
  ),
  resolved_intent_hash_json TEXT NOT NULL CHECK (
    json_valid(resolved_intent_hash_json)
      AND json_extract(resolved_intent_hash_json, '$.domain') = 'agentgo.resolved-intent.v1'
      AND json_extract(resolved_intent_hash_json, '$.algorithm') = 'sha256'
      AND json_type(resolved_intent_hash_json, '$.commitmentKeyRef') = 'text'
      AND json_type(resolved_intent_hash_json, '$.commitmentKeyVersion') = 'integer'
      AND json_extract(resolved_intent_hash_json, '$.commitmentKeyVersion') >= 0
      AND length(json_extract(resolved_intent_hash_json, '$.digest')) = 64
      AND json_extract(resolved_intent_hash_json, '$.digest') NOT GLOB '*[^0-9a-f]*'
  ),
  wire_request_hmac_json TEXT NOT NULL CHECK (
    json_valid(wire_request_hmac_json)
      AND json_extract(wire_request_hmac_json, '$.domain') = 'agentgo.wire-request.v2'
      AND json_extract(wire_request_hmac_json, '$.algorithm') = 'hmac-sha256'
      AND json_type(wire_request_hmac_json, '$.keyRef') = 'text'
      AND json_type(wire_request_hmac_json, '$.keyVersion') = 'integer'
      AND json_extract(wire_request_hmac_json, '$.keyVersion') >= 0
      AND length(json_extract(wire_request_hmac_json, '$.digest')) = 64
      AND json_extract(wire_request_hmac_json, '$.digest') NOT GLOB '*[^0-9a-f]*'
  ),
  capture_decision_set_hash_json TEXT NOT NULL CHECK (
    json_valid(capture_decision_set_hash_json)
      AND json_extract(capture_decision_set_hash_json, '$.domain')
        = 'agentgo.execution-capture-decision-set.v1'
      AND json_extract(capture_decision_set_hash_json, '$.algorithm') = 'sha256'
      AND length(json_extract(capture_decision_set_hash_json, '$.digest')) = 64
      AND json_extract(capture_decision_set_hash_json, '$.digest')
        NOT GLOB '*[^0-9a-f]*'
  ),
  integrity_hmac_json TEXT NOT NULL CHECK (
    json_valid(integrity_hmac_json)
      AND json_extract(integrity_hmac_json, '$.domain') = 'agentgo.execution-grant.v1'
      AND json_extract(integrity_hmac_json, '$.algorithm') = 'hmac-sha256'
      AND json_type(integrity_hmac_json, '$.keyRef') = 'text'
      AND json_type(integrity_hmac_json, '$.keyVersion') = 'integer'
      AND json_extract(integrity_hmac_json, '$.keyVersion') >= 0
      AND length(json_extract(integrity_hmac_json, '$.digest')) = 64
      AND json_extract(integrity_hmac_json, '$.digest') NOT GLOB '*[^0-9a-f]*'
  ),
  capability_ids_json TEXT NOT NULL CHECK (
    json_valid(capability_ids_json)
      AND json_type(capability_ids_json) = 'array'
      AND json_array_length(capability_ids_json) BETWEEN 1 AND 128
  ),
  owner_ref TEXT,
  identity_ref_json TEXT CHECK (identity_ref_json IS NULL OR json_valid(identity_ref_json)),
  credential_ref_json TEXT CHECK (
    credential_ref_json IS NULL
      OR (
        json_valid(credential_ref_json)
        AND json_type(credential_ref_json) = 'object'
        AND json_type(credential_ref_json, '$.id') = 'text'
        AND json_extract(credential_ref_json, '$.kind') = 'identity'
        AND json_type(credential_ref_json, '$.generation') = 'integer'
        AND json_extract(credential_ref_json, '$.generation') >= 0
      )
  ),
  session_ref_json TEXT CHECK (session_ref_json IS NULL OR json_valid(session_ref_json)),
  test_object_ref_json TEXT CHECK (test_object_ref_json IS NULL OR json_valid(test_object_ref_json)),
  budget_json TEXT NOT NULL CHECK (
    json_valid(budget_json)
      AND json_extract(budget_json, '$.requestUnits') = 1
      AND json_type(budget_json, '$.requestBytes') = 'integer'
      AND json_extract(budget_json, '$.requestBytes') BETWEEN 0 AND 1146880
      AND json_type(budget_json, '$.maxResponseBytes') = 'integer'
      AND json_extract(budget_json, '$.maxResponseBytes') BETWEEN 1 AND 16777216
      AND json_type(budget_json, '$.timeoutMs') = 'integer'
      AND json_extract(budget_json, '$.timeoutMs') BETWEEN 1 AND 120000
      AND json_type(budget_json, '$.maxRedirects') = 'integer'
      AND json_extract(budget_json, '$.maxRedirects') BETWEEN 0 AND 10
  ),
  purpose TEXT NOT NULL CHECK (purpose IN ('primary', 'read', 'cleanup')),
  adapter_kind TEXT NOT NULL CHECK (
    adapter_kind IN ('http', 'browser-offline', 'browser-network', 'oob-poll', 'cleanup')
  ),
  retry_class TEXT NOT NULL CHECK (
    retry_class IN ('never', 'deterministic-readonly')
      AND (retry_class <> 'deterministic-readonly' OR purpose = 'read')
  ),
  policy_decision_id TEXT NOT NULL UNIQUE REFERENCES policy_decisions(id),
  approval_bundle_ref TEXT,
  parent_grant_id TEXT REFERENCES execution_grants(id),
  redirect_hop INTEGER NOT NULL CHECK (redirect_hop BETWEEN 0 AND 10),
  valid_from INTEGER NOT NULL,
  valid_until INTEGER NOT NULL,
  issued_at INTEGER NOT NULL,
  CHECK (valid_from <= issued_at AND issued_at < valid_until),
  CHECK (
    (redirect_hop = 0 AND parent_grant_id IS NULL)
      OR (redirect_hop > 0 AND parent_grant_id IS NOT NULL)
  ),
  CHECK (
    json_extract(resolved_intent_hash_json, '$.commitmentKeyRef')
      = json_extract(wire_request_hmac_json, '$.keyRef')
    AND json_extract(resolved_intent_hash_json, '$.commitmentKeyVersion')
      = json_extract(wire_request_hmac_json, '$.keyVersion')
    AND json_extract(integrity_hmac_json, '$.keyRef')
      = json_extract(wire_request_hmac_json, '$.keyRef')
    AND json_extract(integrity_hmac_json, '$.keyVersion')
      = json_extract(wire_request_hmac_json, '$.keyVersion')
  )
);
CREATE INDEX execution_grants_scan_idx ON execution_grants(scan_id, issued_at);
CREATE INDEX execution_grants_module_idx ON execution_grants(module_snapshot_id);
CREATE INDEX execution_grants_parent_idx ON execution_grants(parent_grant_id);

CREATE TABLE execution_capture_decisions (
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
      'execution-interruption-summary'
    )
  ),
  role TEXT NOT NULL CHECK (
    length(trim(role)) BETWEEN 1 AND 100 AND role = trim(role)
  ),
  action TEXT NOT NULL CHECK (action = 'hash-only'),
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
CREATE INDEX execution_capture_decisions_grant_idx
  ON execution_capture_decisions(grant_id);

CREATE TABLE execution_leases (
  schema_version TEXT NOT NULL CHECK (schema_version = 'execution-lease.v1'),
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES execution_grants(id) ON DELETE CASCADE,
  parent_lease_id TEXT REFERENCES execution_leases(id),
  attempt INTEGER NOT NULL CHECK (attempt > 0),
  state TEXT NOT NULL CHECK (
    state IN ('issued', 'claimed', 'completed', 'failed', 'expired', 'revoked')
  ),
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
  claimed_at INTEGER,
  claimed_by TEXT,
  claim_token_hash TEXT CHECK (
    claim_token_hash IS NULL
      OR (length(claim_token_hash) = 64 AND claim_token_hash NOT GLOB '*[^0-9a-f]*')
  ),
  delivery_state TEXT NOT NULL CHECK (
    delivery_state IN (
      'not-dispatched', 'possibly-sent', 'response-started', 'completed', 'unknown'
    )
  ),
  terminal_at INTEGER,
  terminal_reason TEXT CHECK (
    terminal_reason IS NULL
      OR terminal_reason IN (
        'completed', 'guard-rejected', 'expired', 'revoked', 'cancelled',
        'timed-out', 'network-failed', 'response-read-failed',
        'redirect-rejected', 'unsupported-adapter', 'interrupted'
      )
  ),
  outcome_summary_json TEXT CHECK (
    outcome_summary_json IS NULL OR json_valid(outcome_summary_json)
  ),
  evidence_refs_json TEXT NOT NULL CHECK (
    json_valid(evidence_refs_json) AND json_type(evidence_refs_json) = 'array'
  ),
  UNIQUE (grant_id, attempt),
  CHECK (
    (state = 'issued'
      AND claimed_at IS NULL AND claimed_by IS NULL AND claim_token_hash IS NULL
      AND delivery_state = 'not-dispatched'
      AND terminal_at IS NULL AND terminal_reason IS NULL AND outcome_summary_json IS NULL)
    OR (state = 'claimed'
      AND claimed_at IS NOT NULL AND claimed_by IS NOT NULL AND claim_token_hash IS NOT NULL
      AND delivery_state IN ('not-dispatched', 'possibly-sent', 'response-started')
      AND terminal_at IS NULL AND terminal_reason IS NULL AND outcome_summary_json IS NULL)
    OR (state = 'completed'
      AND terminal_reason IS NOT NULL
      AND claimed_at IS NOT NULL AND claimed_by IS NOT NULL AND claim_token_hash IS NOT NULL
      AND delivery_state = 'completed'
      AND terminal_at IS NOT NULL AND terminal_reason = 'completed'
      AND outcome_summary_json IS NOT NULL)
    OR (state = 'failed'
      AND terminal_reason IS NOT NULL
      AND claimed_at IS NOT NULL AND claimed_by IS NOT NULL AND claim_token_hash IS NOT NULL
      AND delivery_state <> 'completed'
      AND terminal_at IS NOT NULL
      AND terminal_reason NOT IN ('completed', 'expired', 'revoked')
      AND outcome_summary_json IS NOT NULL)
    OR (state = 'expired'
      AND terminal_reason IS NOT NULL
      AND claimed_at IS NULL AND claimed_by IS NULL AND claim_token_hash IS NULL
      AND delivery_state = 'not-dispatched'
      AND terminal_at IS NOT NULL AND terminal_reason = 'expired'
      AND outcome_summary_json IS NULL)
    OR (state = 'revoked'
      AND terminal_reason IS NOT NULL
      AND claimed_at IS NULL AND claimed_by IS NULL AND claim_token_hash IS NULL
      AND delivery_state = 'not-dispatched'
      AND terminal_at IS NOT NULL
      AND terminal_reason IN ('revoked', 'guard-rejected', 'unsupported-adapter')
      AND outcome_summary_json IS NULL)
  )
);
CREATE INDEX execution_leases_grant_idx ON execution_leases(grant_id);
CREATE INDEX execution_leases_state_expiry_idx ON execution_leases(state, expires_at);
CREATE INDEX execution_leases_parent_idx ON execution_leases(parent_lease_id);
CREATE UNIQUE INDEX execution_leases_active_grant_uq
  ON execution_leases(grant_id)
  WHERE state IN ('issued', 'claimed');

ALTER TABLE tool_calls
  ADD COLUMN execution_lease_id TEXT REFERENCES execution_leases(id);
CREATE UNIQUE INDEX tool_calls_execution_lease_uq
  ON tool_calls(execution_lease_id)
  WHERE execution_lease_id IS NOT NULL;

ALTER TABLE interactions
  ADD COLUMN execution_lease_id TEXT REFERENCES execution_leases(id);
CREATE UNIQUE INDEX interactions_execution_lease_uq
  ON interactions(execution_lease_id)
  WHERE execution_lease_id IS NOT NULL;

CREATE TABLE execution_lease_evidence (
  lease_id TEXT NOT NULL REFERENCES execution_leases(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL UNIQUE REFERENCES evidence_items(id),
  capture_decision_id TEXT NOT NULL REFERENCES execution_capture_decisions(id),
  role TEXT NOT NULL CHECK (length(trim(role)) BETWEEN 1 AND 100 AND role = trim(role)),
  ordinal INTEGER NOT NULL CHECK (ordinal = 0),
  PRIMARY KEY (lease_id, capture_decision_id),
  UNIQUE (lease_id, role, ordinal)
);
CREATE INDEX execution_lease_evidence_evidence_idx
  ON execution_lease_evidence(evidence_id);

CREATE TRIGGER tool_calls_execution_lease_insert_guard
BEFORE INSERT ON tool_calls
WHEN NEW.execution_lease_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM execution_leases AS lease_row
  INNER JOIN execution_grants AS grant_row ON grant_row.id = lease_row.grant_id
  WHERE lease_row.id = NEW.execution_lease_id
    AND lease_row.state = 'issued'
    AND grant_row.scan_id = NEW.scan_id
    AND grant_row.policy_decision_id = NEW.policy_decision_id
    AND NEW.status = 'running'
)
BEGIN
  SELECT RAISE(ABORT, 'tool call execution lease binding is invalid');
END;

CREATE TRIGGER tool_calls_execution_lease_update_guard
BEFORE UPDATE OF scan_id, policy_decision_id, execution_lease_id ON tool_calls
WHEN NEW.execution_lease_id IS NOT OLD.execution_lease_id
  OR (
    OLD.execution_lease_id IS NOT NULL
    AND (
      NEW.scan_id IS NOT OLD.scan_id
      OR NEW.policy_decision_id IS NOT OLD.policy_decision_id
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'tool call execution lease binding is immutable');
END;

CREATE TRIGGER tool_calls_execution_terminal_status_guard
BEFORE UPDATE OF status, error ON tool_calls
WHEN OLD.execution_lease_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM execution_leases AS lease_row
  WHERE lease_row.id = OLD.execution_lease_id
    AND (
      (lease_row.state IN ('issued', 'claimed')
        AND NEW.status = 'running')
      OR (lease_row.state = 'completed'
        AND NEW.status = 'succeeded' AND NEW.error IS NULL)
      OR (lease_row.state = 'failed'
        AND NEW.status = CASE lease_row.terminal_reason
          WHEN 'cancelled' THEN 'cancelled'
          ELSE 'failed'
        END
        AND NEW.error = lease_row.terminal_reason)
      OR (lease_row.state IN ('expired', 'revoked')
        AND NEW.status = 'failed'
        AND NEW.error = lease_row.terminal_reason)
    )
)
BEGIN
  SELECT RAISE(ABORT, 'tool call terminal status must match its execution lease');
END;

CREATE TRIGGER interactions_execution_lease_insert_guard
BEFORE INSERT ON interactions
WHEN NEW.execution_lease_id IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM execution_leases AS lease_row
  INNER JOIN execution_grants AS grant_row ON grant_row.id = lease_row.grant_id
  WHERE lease_row.id = NEW.execution_lease_id
    AND lease_row.state = 'claimed'
    AND grant_row.scan_id = NEW.scan_id
    AND grant_row.policy_decision_id = NEW.policy_decision_id
    AND (
      (grant_row.identity_ref_json IS NULL AND NEW.identity_id IS NULL)
      OR json_extract(grant_row.identity_ref_json, '$.id') = NEW.identity_id
    )
    AND EXISTS (
      SELECT 1
      FROM execution_lease_evidence AS request_link
      INNER JOIN evidence_items AS request_evidence
        ON request_evidence.id = request_link.evidence_id
      WHERE request_link.lease_id = lease_row.id
        AND request_link.evidence_id = NEW.request_ref
        AND request_link.role = 'request-summary'
        AND request_evidence.scan_id = grant_row.scan_id
    )
    AND EXISTS (
      SELECT 1
      FROM execution_lease_evidence AS response_link
      INNER JOIN evidence_items AS response_evidence
        ON response_evidence.id = response_link.evidence_id
      WHERE response_link.lease_id = lease_row.id
        AND response_link.evidence_id = NEW.response_ref
        AND response_link.role IN ('response-summary', 'result-summary')
        AND response_evidence.scan_id = grant_row.scan_id
    )
)
BEGIN
  SELECT RAISE(ABORT, 'interaction execution lease binding is invalid');
END;

CREATE TRIGGER interactions_execution_lease_update_guard
BEFORE UPDATE ON interactions
WHEN OLD.execution_lease_id IS NOT NULL
  OR NEW.execution_lease_id IS NOT OLD.execution_lease_id
BEGIN
  SELECT RAISE(ABORT, 'interaction execution lease binding is immutable');
END;

CREATE TRIGGER execution_grants_insert_guard
BEFORE INSERT ON execution_grants
WHEN NOT EXISTS (
  SELECT 1
  FROM scans AS scan_row
  INNER JOIN targets AS target_row ON target_row.id = scan_row.target_id
  INNER JOIN target_scopes AS scope_row
    ON scope_row.id = NEW.scope_snapshot_id
   AND scope_row.target_id = target_row.id
  INNER JOIN scan_module_snapshots AS module_row
    ON module_row.id = NEW.module_snapshot_id
   AND module_row.scan_id = scan_row.id
  INNER JOIN policy_decisions AS decision_row
    ON decision_row.id = NEW.policy_decision_id
  INNER JOIN probe_proposals AS proposal_row
    ON proposal_row.id = decision_row.proposal_id
   AND proposal_row.scan_id = scan_row.id
  WHERE scan_row.id = NEW.scan_id
    AND scan_row.status = 'running'
    AND scan_row.module_snapshots_sealed = 1
    AND scan_row.scope_snapshot_id = NEW.scope_snapshot_id
    AND scope_row.snapshot_hash = NEW.scope_snapshot_hash
    AND module_row.snapshot_hash = NEW.module_snapshot_hash
    AND module_row.module_id = NEW.module_id
    AND module_row.module_version = NEW.module_version
    AND module_row.technique_id = NEW.technique_id
    AND module_row.technique_version = NEW.technique_version
    AND EXISTS (
      SELECT 1
      FROM json_each(scan_row.config_json, '$.families') AS configured_family
      WHERE configured_family.type = 'text'
        AND configured_family.value = module_row.family_id
    )
    AND scan_row.request_count
          + json_extract(NEW.budget_json, '$.requestUnits')
        <= json_extract(scan_row.budget_json, '$.maxRequests')
    AND NEW.plan_id = scan_row.id
    AND json_type(scan_row.plan_json, '$.version') = 'text'
    AND json_extract(scan_row.plan_json, '$.version') = NEW.plan_version
    AND decision_row.scope_snapshot_id = NEW.scope_snapshot_id
    AND decision_row.allowed = 1
    AND decision_row.requires_approval = 0
    AND decision_row.valid_until IS NOT NULL
    AND decision_row.valid_until >= NEW.valid_until
    AND decision_row.authorized_wire_request_hmac_json IS NOT NULL
    AND (SELECT COUNT(*) FROM json_each(decision_row.authorized_wire_request_hmac_json)) = 5
    AND (SELECT COUNT(*) FROM json_each(NEW.template_intent_hash_json)) = 3
    AND (SELECT COUNT(*) FROM json_each(NEW.resolved_intent_hash_json)) = 5
    AND (SELECT COUNT(*) FROM json_each(NEW.wire_request_hmac_json)) = 5
    AND (SELECT COUNT(*) FROM json_each(NEW.capture_decision_set_hash_json)) = 3
    AND (SELECT COUNT(*) FROM json_each(NEW.integrity_hmac_json)) = 5
    AND (SELECT COUNT(*) FROM json_each(NEW.budget_json)) = 5
    AND (
      NEW.credential_ref_json IS NULL
      OR (SELECT COUNT(*) FROM json_each(NEW.credential_ref_json)) = 3
    )
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.domain')
      = json_extract(NEW.wire_request_hmac_json, '$.domain')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.algorithm')
      = json_extract(NEW.wire_request_hmac_json, '$.algorithm')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.keyRef')
      = json_extract(NEW.wire_request_hmac_json, '$.keyRef')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.keyVersion')
      = json_extract(NEW.wire_request_hmac_json, '$.keyVersion')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.digest')
      = json_extract(NEW.wire_request_hmac_json, '$.digest')
    AND (scope_row.valid_from IS NULL OR scope_row.valid_from <= NEW.valid_from)
    AND (scope_row.valid_until IS NULL OR scope_row.valid_until >= NEW.valid_until)
    AND NEW.session_ref_json IS NULL
    AND NEW.test_object_ref_json IS NULL
    AND (NEW.credential_ref_json IS NULL
      OR NEW.identity_ref_json IS NOT NULL)
    AND (
      (NEW.identity_ref_json IS NULL AND proposal_row.identity_id IS NULL)
      OR (
        NEW.identity_ref_json IS NOT NULL
        AND (SELECT COUNT(*) FROM json_each(NEW.identity_ref_json)) = 5
        AND proposal_row.identity_id = json_extract(NEW.identity_ref_json, '$.id')
        AND NEW.owner_ref = target_row.id
        AND json_extract(NEW.identity_ref_json, '$.ownerRef') = target_row.id
        AND json_extract(NEW.identity_ref_json, '$.scopeSnapshotId')
          = NEW.scope_snapshot_id
        AND json_extract(NEW.identity_ref_json, '$.statusSummary') = 'active'
        AND EXISTS (
          SELECT 1
          FROM identities AS identity_row
          INNER JOIN scan_identities AS scan_identity_row
            ON scan_identity_row.identity_id = identity_row.id
           AND scan_identity_row.scan_id = scan_row.id
          WHERE identity_row.id = json_extract(NEW.identity_ref_json, '$.id')
            AND identity_row.target_id = target_row.id
            AND identity_row.is_test_identity = 1
            AND identity_row.updated_at
              = json_extract(NEW.identity_ref_json, '$.version')
            AND (
              (
                NEW.credential_ref_json IS NULL
                AND (
                  identity_row.credential_id IS NULL
                  OR NEW.parent_grant_id IS NOT NULL
                )
              )
              OR (
                identity_row.credential_id = json_extract(
                  NEW.credential_ref_json,
                  '$.id'
                )
                AND json_extract(
                  NEW.credential_ref_json,
                  '$.kind'
                ) = 'identity'
              )
            )
            AND EXISTS (
              SELECT 1
              FROM json_each(scan_row.config_json, '$.identityIds') AS configured
              WHERE configured.type = 'text'
                AND configured.value = identity_row.id
            )
            AND EXISTS (
              SELECT 1
              FROM json_each(scope_row.allowed_identity_ids) AS allowed
              WHERE allowed.type = 'text'
                AND allowed.value = identity_row.id
            )
        )
      )
    )
    AND (
      (NEW.adapter_kind = 'http' AND EXISTS (
        SELECT 1 FROM json_each(NEW.capability_ids_json)
        WHERE value = 'http.reviewed-read'
      ))
      OR (NEW.adapter_kind = 'browser-offline' AND EXISTS (
        SELECT 1 FROM json_each(NEW.capability_ids_json)
        WHERE value = 'browser.offline-replay'
      ))
    )
    AND NOT EXISTS (
      SELECT 1
      FROM json_each(NEW.capability_ids_json) AS requested
      WHERE requested.type <> 'text'
         OR NOT EXISTS (
           SELECT 1
           FROM json_each(module_row.capability_descriptors_json) AS available
           WHERE json_extract(available.value, '$.id') = requested.value
         )
    )
    AND NOT EXISTS (
      SELECT 1
      FROM json_each(NEW.capability_ids_json) AS left_capability
      INNER JOIN json_each(NEW.capability_ids_json) AS right_capability
        ON CAST(left_capability.key AS INTEGER) < CAST(right_capability.key AS INTEGER)
      WHERE left_capability.value >= right_capability.value
    )
    AND NEW.redirect_hop <= json_extract(NEW.budget_json, '$.maxRedirects')
    AND (
      (NEW.redirect_hop = 0 AND NEW.parent_grant_id IS NULL)
      OR EXISTS (
        SELECT 1 FROM execution_grants AS parent_row
        WHERE parent_row.id = NEW.parent_grant_id
          AND parent_row.scan_id = NEW.scan_id
          AND parent_row.redirect_hop + 1 = NEW.redirect_hop
          AND parent_row.scope_snapshot_id = NEW.scope_snapshot_id
          AND parent_row.scope_snapshot_hash = NEW.scope_snapshot_hash
          AND parent_row.module_snapshot_id = NEW.module_snapshot_id
          AND parent_row.module_snapshot_hash = NEW.module_snapshot_hash
          AND parent_row.module_id = NEW.module_id
          AND parent_row.module_version = NEW.module_version
          AND parent_row.technique_id = NEW.technique_id
          AND parent_row.technique_version = NEW.technique_version
          AND parent_row.plan_id = NEW.plan_id
          AND parent_row.plan_version = NEW.plan_version
          AND parent_row.plan_hash = NEW.plan_hash
          AND parent_row.step_id = NEW.step_id
          AND parent_row.capability_ids_json = NEW.capability_ids_json
          AND parent_row.owner_ref IS NEW.owner_ref
          AND parent_row.identity_ref_json IS NEW.identity_ref_json
          AND (
            NEW.credential_ref_json IS NULL
            OR parent_row.credential_ref_json IS NEW.credential_ref_json
          )
          AND parent_row.session_ref_json IS NEW.session_ref_json
          AND parent_row.test_object_ref_json IS NEW.test_object_ref_json
          AND parent_row.purpose = NEW.purpose
          AND parent_row.adapter_kind = NEW.adapter_kind
          AND parent_row.adapter_kind = 'http'
          AND NEW.adapter_kind = 'http'
          AND parent_row.retry_class = NEW.retry_class
          AND parent_row.approval_bundle_ref IS NEW.approval_bundle_ref
          AND NEW.valid_until <= parent_row.valid_until
          AND json_extract(NEW.budget_json, '$.timeoutMs')
            <= json_extract(parent_row.budget_json, '$.timeoutMs')
          AND json_extract(NEW.budget_json, '$.maxResponseBytes')
            <= json_extract(parent_row.budget_json, '$.maxResponseBytes')
          AND json_extract(NEW.budget_json, '$.maxRedirects')
            <= json_extract(parent_row.budget_json, '$.maxRedirects')
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'execution grant binding is invalid');
END;

CREATE TRIGGER execution_grants_immutable_update_guard
BEFORE UPDATE ON execution_grants
BEGIN
  SELECT RAISE(ABORT, 'execution grants are immutable');
END;

CREATE TRIGGER execution_grants_immutable_delete_guard
BEFORE DELETE ON execution_grants
WHEN EXISTS (SELECT 1 FROM scans WHERE scans.id = OLD.scan_id)
BEGIN
  SELECT RAISE(ABORT, 'execution grants are immutable');
END;

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
    AND NEW.action = 'hash-only'
    AND (SELECT COUNT(*) FROM json_each(NEW.decision_json)) = 18
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
      WHERE grant_id = grant_row.id) = 9
    AND (SELECT COUNT(*)
      FROM execution_capture_decisions
      WHERE grant_id = grant_row.id
        AND source = 'execution-interruption-summary'
        AND execution_state = 'interrupted') = 1
    AND (
      (grant_row.adapter_kind = 'http'
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
          WHERE grant_id = grant_row.id
            AND source = 'browser-request-summary') = 4
        AND (SELECT COUNT(*)
          FROM execution_capture_decisions
          WHERE grant_id = grant_row.id
            AND source = 'browser-result-summary') = 4)
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

CREATE TRIGGER execution_leases_binding_immutable_guard
BEFORE UPDATE OF
  schema_version, grant_id, parent_lease_id, attempt, issued_at, expires_at
ON execution_leases
WHEN NEW.schema_version IS NOT OLD.schema_version
  OR NEW.grant_id IS NOT OLD.grant_id
  OR NEW.parent_lease_id IS NOT OLD.parent_lease_id
  OR NEW.attempt IS NOT OLD.attempt
  OR NEW.issued_at IS NOT OLD.issued_at
  OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
  SELECT RAISE(ABORT, 'execution lease binding is immutable');
END;

CREATE TRIGGER execution_leases_state_transition_guard
BEFORE UPDATE OF state ON execution_leases
WHEN NOT (
  (OLD.state = 'issued' AND NEW.state IN ('claimed', 'expired', 'revoked'))
  OR (OLD.state = 'claimed' AND NEW.state IN ('completed', 'failed'))
)
BEGIN
  SELECT RAISE(ABORT, 'execution lease state transition is invalid');
END;

CREATE TRIGGER execution_leases_claim_guard
BEFORE UPDATE OF state ON execution_leases
WHEN OLD.state = 'issued' AND NEW.state = 'claimed' AND NOT EXISTS (
  SELECT 1
  FROM execution_grants AS grant_row
  INNER JOIN scans AS scan_row ON scan_row.id = grant_row.scan_id
  INNER JOIN targets AS target_row ON target_row.id = scan_row.target_id
  INNER JOIN target_scopes AS scope_row
    ON scope_row.id = grant_row.scope_snapshot_id
   AND scope_row.target_id = target_row.id
  INNER JOIN policy_decisions AS decision_row ON decision_row.id = grant_row.policy_decision_id
  INNER JOIN probe_proposals AS proposal_row
    ON proposal_row.id = decision_row.proposal_id
   AND proposal_row.scan_id = scan_row.id
  WHERE grant_row.id = OLD.grant_id
    AND scan_row.status = 'running'
    AND scan_row.module_snapshots_sealed = 1
    AND EXISTS (
      SELECT 1
      FROM tool_calls AS tool_call_row
      WHERE tool_call_row.execution_lease_id = OLD.id
        AND tool_call_row.status = 'running'
    )
    AND NEW.claimed_at IS NOT NULL
    AND NEW.claimed_by IS NOT NULL
    AND NEW.claim_token_hash IS NOT NULL
    AND grant_row.session_ref_json IS NULL
    AND grant_row.test_object_ref_json IS NULL
    AND (grant_row.credential_ref_json IS NULL
      OR grant_row.identity_ref_json IS NOT NULL)
    AND (
      (grant_row.identity_ref_json IS NULL AND proposal_row.identity_id IS NULL)
      OR (
        grant_row.identity_ref_json IS NOT NULL
        AND proposal_row.identity_id
          = json_extract(grant_row.identity_ref_json, '$.id')
        AND grant_row.owner_ref = target_row.id
        AND json_extract(grant_row.identity_ref_json, '$.ownerRef')
          = target_row.id
        AND json_extract(grant_row.identity_ref_json, '$.scopeSnapshotId')
          = grant_row.scope_snapshot_id
        AND json_extract(grant_row.identity_ref_json, '$.statusSummary')
          = 'active'
        AND EXISTS (
          SELECT 1
          FROM identities AS identity_row
          INNER JOIN scan_identities AS scan_identity_row
            ON scan_identity_row.identity_id = identity_row.id
           AND scan_identity_row.scan_id = scan_row.id
          WHERE identity_row.id
              = json_extract(grant_row.identity_ref_json, '$.id')
            AND identity_row.target_id = target_row.id
            AND identity_row.is_test_identity = 1
            AND identity_row.updated_at
              = json_extract(grant_row.identity_ref_json, '$.version')
            AND (
              (
                grant_row.credential_ref_json IS NULL
                AND (
                  identity_row.credential_id IS NULL
                  OR grant_row.parent_grant_id IS NOT NULL
                )
              )
              OR (
                identity_row.credential_id = json_extract(
                  grant_row.credential_ref_json,
                  '$.id'
                )
                AND json_extract(
                  grant_row.credential_ref_json,
                  '$.kind'
                ) = 'identity'
              )
            )
            AND EXISTS (
              SELECT 1
              FROM json_each(scan_row.config_json, '$.identityIds') AS configured
              WHERE configured.type = 'text'
                AND configured.value = identity_row.id
            )
            AND EXISTS (
              SELECT 1
              FROM json_each(scope_row.allowed_identity_ids) AS allowed
              WHERE allowed.type = 'text'
                AND allowed.value = identity_row.id
            )
        )
      )
    )
    AND NEW.claimed_at < OLD.expires_at
    AND grant_row.valid_from <= NEW.claimed_at
    AND grant_row.valid_until > NEW.claimed_at
    AND decision_row.allowed = 1
    AND decision_row.requires_approval = 0
    AND decision_row.valid_until IS NOT NULL
    AND decision_row.valid_until > NEW.claimed_at
    AND decision_row.authorized_wire_request_hmac_json IS NOT NULL
    AND (SELECT COUNT(*) FROM json_each(decision_row.authorized_wire_request_hmac_json)) = 5
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.domain')
      = json_extract(grant_row.wire_request_hmac_json, '$.domain')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.algorithm')
      = json_extract(grant_row.wire_request_hmac_json, '$.algorithm')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.keyRef')
      = json_extract(grant_row.wire_request_hmac_json, '$.keyRef')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.keyVersion')
      = json_extract(grant_row.wire_request_hmac_json, '$.keyVersion')
    AND json_extract(decision_row.authorized_wire_request_hmac_json, '$.digest')
      = json_extract(grant_row.wire_request_hmac_json, '$.digest')
    AND (scope_row.valid_from IS NULL OR scope_row.valid_from <= NEW.claimed_at)
    AND (scope_row.valid_until IS NULL OR scope_row.valid_until > NEW.claimed_at)
    AND scan_row.request_count
          + json_extract(grant_row.budget_json, '$.requestUnits')
        <= json_extract(scan_row.budget_json, '$.maxRequests')
)
BEGIN
  SELECT RAISE(ABORT, 'execution lease claim is invalid');
END;

CREATE TRIGGER execution_leases_delivery_guard
BEFORE UPDATE OF delivery_state ON execution_leases
WHEN OLD.state = 'claimed' AND NEW.state = 'claimed' AND NOT (
  NEW.delivery_state = OLD.delivery_state
  OR (
    (
      (OLD.delivery_state = 'not-dispatched'
        AND NEW.delivery_state = 'possibly-sent')
      OR (OLD.delivery_state = 'possibly-sent'
        AND NEW.delivery_state = 'response-started')
    )
    AND EXISTS (
      SELECT 1
      FROM execution_grants AS grant_row
      INNER JOIN scans AS scan_row
        ON scan_row.id = grant_row.scan_id
      INNER JOIN targets AS target_row
        ON target_row.id = scan_row.target_id
      INNER JOIN target_scopes AS scope_row
        ON scope_row.id = grant_row.scope_snapshot_id
       AND scope_row.target_id = target_row.id
      INNER JOIN policy_decisions AS decision_row
        ON decision_row.id = grant_row.policy_decision_id
      INNER JOIN probe_proposals AS proposal_row
        ON proposal_row.id = decision_row.proposal_id
       AND proposal_row.scan_id = scan_row.id
      CROSS JOIN (
        SELECT CAST(
          (julianday('now') - 2440587.5) * 86400000
          AS INTEGER
        ) AS now_ms
      ) AS clock
      WHERE grant_row.id = OLD.grant_id
        AND scan_row.status = 'running'
        AND scan_row.module_snapshots_sealed = 1
        AND scan_row.scope_snapshot_id = grant_row.scope_snapshot_id
        AND decision_row.scope_snapshot_id = grant_row.scope_snapshot_id
        AND EXISTS (
          SELECT 1
          FROM tool_calls AS tool_call_row
          WHERE tool_call_row.execution_lease_id = OLD.id
            AND tool_call_row.status = 'running'
        )
        AND grant_row.session_ref_json IS NULL
        AND grant_row.test_object_ref_json IS NULL
        AND (
          (
            grant_row.identity_ref_json IS NULL
            AND proposal_row.identity_id IS NULL
          )
          OR (
            grant_row.identity_ref_json IS NOT NULL
            AND proposal_row.identity_id
              = json_extract(grant_row.identity_ref_json, '$.id')
            AND grant_row.owner_ref = target_row.id
            AND json_extract(
              grant_row.identity_ref_json,
              '$.ownerRef'
            ) = target_row.id
            AND json_extract(
              grant_row.identity_ref_json,
              '$.scopeSnapshotId'
            ) = grant_row.scope_snapshot_id
            AND json_extract(
              grant_row.identity_ref_json,
              '$.statusSummary'
            ) = 'active'
            AND EXISTS (
              SELECT 1
              FROM identities AS identity_row
              INNER JOIN scan_identities AS scan_identity_row
                ON scan_identity_row.identity_id = identity_row.id
               AND scan_identity_row.scan_id = scan_row.id
              WHERE identity_row.id = json_extract(
                  grant_row.identity_ref_json,
                  '$.id'
                )
                AND identity_row.target_id = target_row.id
                AND identity_row.is_test_identity = 1
                AND identity_row.updated_at = json_extract(
                  grant_row.identity_ref_json,
                  '$.version'
                )
                AND (
                  (
                    grant_row.credential_ref_json IS NULL
                    AND (
                      identity_row.credential_id IS NULL
                      OR grant_row.parent_grant_id IS NOT NULL
                    )
                  )
                  OR (
                    identity_row.credential_id = json_extract(
                      grant_row.credential_ref_json,
                      '$.id'
                    )
                    AND json_extract(
                      grant_row.credential_ref_json,
                      '$.kind'
                    ) = 'identity'
                  )
                )
                AND EXISTS (
                  SELECT 1
                  FROM json_each(
                    scan_row.config_json,
                    '$.identityIds'
                  ) AS configured_identity
                  WHERE configured_identity.type = 'text'
                    AND configured_identity.value = identity_row.id
                )
                AND EXISTS (
                  SELECT 1
                  FROM json_each(
                    scope_row.allowed_identity_ids
                  ) AS allowed_identity
                  WHERE allowed_identity.type = 'text'
                    AND allowed_identity.value = identity_row.id
                )
            )
          )
        )
        AND (
          (
            grant_row.adapter_kind = 'http'
            AND EXISTS (
              SELECT 1
              FROM json_each(grant_row.capability_ids_json)
              WHERE value = 'http.reviewed-read'
            )
          )
          OR (
            grant_row.adapter_kind = 'browser-offline'
            AND EXISTS (
              SELECT 1
              FROM json_each(grant_row.capability_ids_json)
              WHERE value = 'browser.offline-replay'
            )
          )
        )
        AND json_valid(scan_row.budget_json)
        AND json_type(scan_row.budget_json, '$.maxRequests') = 'integer'
        AND scan_row.request_count
          <= json_extract(scan_row.budget_json, '$.maxRequests')
        AND OLD.expires_at > clock.now_ms
        AND grant_row.valid_from <= clock.now_ms
        AND grant_row.valid_until > clock.now_ms
        AND decision_row.allowed = 1
        AND decision_row.requires_approval = 0
        AND decision_row.valid_until IS NOT NULL
        AND decision_row.valid_until > clock.now_ms
        AND decision_row.authorized_wire_request_hmac_json IS NOT NULL
        AND (
          SELECT COUNT(*)
          FROM json_each(
            decision_row.authorized_wire_request_hmac_json
          )
        ) = 5
        AND json_extract(
          decision_row.authorized_wire_request_hmac_json,
          '$.domain'
        ) = json_extract(
          grant_row.wire_request_hmac_json,
          '$.domain'
        )
        AND json_extract(
          decision_row.authorized_wire_request_hmac_json,
          '$.algorithm'
        ) = json_extract(
          grant_row.wire_request_hmac_json,
          '$.algorithm'
        )
        AND json_extract(
          decision_row.authorized_wire_request_hmac_json,
          '$.keyRef'
        ) = json_extract(
          grant_row.wire_request_hmac_json,
          '$.keyRef'
        )
        AND json_extract(
          decision_row.authorized_wire_request_hmac_json,
          '$.keyVersion'
        ) = json_extract(
          grant_row.wire_request_hmac_json,
          '$.keyVersion'
        )
        AND json_extract(
          decision_row.authorized_wire_request_hmac_json,
          '$.digest'
        ) = json_extract(
          grant_row.wire_request_hmac_json,
          '$.digest'
        )
        AND (scope_row.valid_from IS NULL
          OR scope_row.valid_from <= clock.now_ms)
        AND (scope_row.valid_until IS NULL
          OR scope_row.valid_until > clock.now_ms)
    )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'execution delivery transition is invalid');
END;

CREATE TRIGGER execution_leases_finalization_proof_guard
BEFORE UPDATE OF state, outcome_summary_json, evidence_refs_json
ON execution_leases
WHEN OLD.state = 'claimed'
  AND NEW.state IN ('completed', 'failed')
  AND NOT EXISTS (
    SELECT 1
    FROM execution_grants AS grant_row
    WHERE grant_row.id = OLD.grant_id
      AND EXISTS (
        SELECT 1
        FROM tool_calls AS tool_call_row
        WHERE tool_call_row.execution_lease_id = OLD.id
          AND tool_call_row.status = 'running'
      )
      AND json_valid(NEW.outcome_summary_json)
      AND json_extract(NEW.outcome_summary_json, '$.deliveryState')
        = NEW.delivery_state
      AND json_extract(NEW.outcome_summary_json, '$.verdictImpact')
        = CASE
          WHEN NEW.delivery_state IN ('not-dispatched', 'completed')
            THEN 'none'
          ELSE 'inconclusive'
        END
      AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.outcome_summary_json) AS outcome_field
        WHERE outcome_field.key NOT IN (
          'executionState',
          'deliveryState',
          'verdictImpact',
          'wireRequestHmacDigest',
          'requestBytes',
          'responseBytes',
          'errorCode'
        )
      )
      AND (
        json_type(NEW.outcome_summary_json, '$.errorCode') IS NULL
        OR json_type(NEW.outcome_summary_json, '$.errorCode') = 'text'
      )
      AND (
        json_type(NEW.outcome_summary_json, '$.wireRequestHmacDigest') IS NULL
        OR json_extract(NEW.outcome_summary_json, '$.wireRequestHmacDigest')
          = json_extract(grant_row.wire_request_hmac_json, '$.digest')
      )
      AND (
        json_type(NEW.outcome_summary_json, '$.requestBytes') IS NULL
        OR json_extract(NEW.outcome_summary_json, '$.requestBytes')
          = json_extract(grant_row.budget_json, '$.requestBytes')
      )
      AND (
        json_type(NEW.outcome_summary_json, '$.responseBytes') IS NULL
        OR (
          json_type(NEW.outcome_summary_json, '$.responseBytes') = 'integer'
          AND json_extract(NEW.outcome_summary_json, '$.responseBytes')
            BETWEEN 0
              AND json_extract(grant_row.budget_json, '$.maxResponseBytes')
        )
      )
      AND NOT EXISTS (
        SELECT 1
        FROM execution_lease_evidence AS terminal_link
        WHERE terminal_link.lease_id = OLD.id
          AND NOT EXISTS (
            SELECT 1
            FROM execution_capture_decisions AS terminal_capture
            INNER JOIN evidence_items AS terminal_evidence
              ON terminal_evidence.id = terminal_link.evidence_id
            WHERE terminal_capture.id
                = terminal_link.capture_decision_id
              AND terminal_capture.grant_id = OLD.grant_id
              AND terminal_capture.scan_id = grant_row.scan_id
              AND terminal_capture.policy_decision_id
                = grant_row.policy_decision_id
              AND terminal_evidence.scan_id = grant_row.scan_id
              AND terminal_evidence.policy_decision_id
                = grant_row.policy_decision_id
              AND terminal_evidence.type
                = 'evidence-capture-hash-only'
              AND terminal_evidence.source = terminal_capture.source
              AND terminal_evidence.redaction_state = 'redacted'
              AND terminal_evidence.integrity_status = 'verified'
          )
      )
      AND (
        (
          NEW.terminal_reason = 'interrupted'
          AND NEW.delivery_state = 'unknown'
          AND json_extract(NEW.outcome_summary_json, '$.executionState')
            = 'interrupted'
          AND json_array_length(NEW.evidence_refs_json) = (
            SELECT COUNT(*)
            FROM execution_lease_evidence
            WHERE lease_id = OLD.id
          )
          AND (
            SELECT COUNT(*)
            FROM execution_lease_evidence AS interruption_link
            INNER JOIN execution_capture_decisions AS interruption_capture
              ON interruption_capture.id
                = interruption_link.capture_decision_id
            WHERE interruption_link.lease_id = OLD.id
              AND interruption_capture.grant_id = OLD.grant_id
              AND interruption_capture.source
                = 'execution-interruption-summary'
              AND interruption_capture.execution_state = 'interrupted'
              AND interruption_link.role = 'interruption-summary'
          ) = 1
          AND NOT EXISTS (
            SELECT 1 FROM execution_lease_evidence AS linked_evidence
            WHERE linked_evidence.lease_id = OLD.id
              AND NOT EXISTS (
                SELECT 1 FROM json_each(NEW.evidence_refs_json) AS requested
                WHERE requested.type = 'text'
                  AND requested.value = linked_evidence.evidence_id
              )
          )
          AND NOT EXISTS (
            SELECT 1 FROM json_each(NEW.evidence_refs_json) AS requested
            WHERE requested.type <> 'text'
              OR NOT EXISTS (
                SELECT 1
                FROM execution_lease_evidence AS linked_evidence
                WHERE linked_evidence.lease_id = OLD.id
                  AND linked_evidence.evidence_id = requested.value
              )
          )
        )
        OR (
          NEW.terminal_reason <> 'interrupted'
          AND json_extract(NEW.outcome_summary_json, '$.executionState')
            = CASE NEW.terminal_reason
              WHEN 'completed' THEN 'succeeded'
              WHEN 'cancelled' THEN 'cancelled'
              WHEN 'timed-out' THEN 'timed-out'
              ELSE 'failed'
            END
          AND (
            NEW.delivery_state = 'not-dispatched'
            OR (
              json_type(
                NEW.outcome_summary_json,
                '$.wireRequestHmacDigest'
              ) = 'text'
              AND json_type(NEW.outcome_summary_json, '$.requestBytes')
                = 'integer'
            )
          )
          AND NOT EXISTS (
            SELECT 1
            FROM execution_lease_evidence AS link_row
            INNER JOIN execution_capture_decisions AS capture_row
              ON capture_row.id = link_row.capture_decision_id
            WHERE link_row.lease_id = OLD.id
              AND capture_row.execution_state
                <> json_extract(
                  NEW.outcome_summary_json,
                  '$.executionState'
                )
          )
          AND (
            NEW.delivery_state = 'not-dispatched'
            OR json_extract(NEW.outcome_summary_json, '$.errorCode')
              = 'execution.audit-persistence-failed'
            OR (
              SELECT COUNT(*)
              FROM execution_lease_evidence AS delivered_link
              INNER JOIN execution_capture_decisions AS delivered_capture
                ON delivered_capture.id
                  = delivered_link.capture_decision_id
              WHERE delivered_link.lease_id = OLD.id
                AND delivered_capture.execution_state = json_extract(
                  NEW.outcome_summary_json,
                  '$.executionState'
                )
            ) = 2
          )
          AND (
            NEW.state <> 'completed'
            OR (
              SELECT COUNT(*)
              FROM execution_lease_evidence AS complete_link
              INNER JOIN execution_capture_decisions AS complete_capture
                ON complete_capture.id = complete_link.capture_decision_id
              WHERE complete_link.lease_id = OLD.id
                AND complete_capture.execution_state = 'succeeded'
            ) = 2
          )
          AND json_array_length(NEW.evidence_refs_json) = (
            SELECT COUNT(*) FROM execution_lease_evidence
            WHERE lease_id = OLD.id
          )
          AND NOT EXISTS (
            SELECT 1
            FROM execution_lease_evidence AS linked_evidence
            WHERE linked_evidence.lease_id = OLD.id
              AND NOT EXISTS (
                SELECT 1
                FROM json_each(NEW.evidence_refs_json) AS requested_evidence
                WHERE requested_evidence.type = 'text'
                  AND requested_evidence.value = linked_evidence.evidence_id
              )
          )
          AND NOT EXISTS (
            SELECT 1
            FROM json_each(NEW.evidence_refs_json) AS requested_evidence
            WHERE requested_evidence.type <> 'text'
              OR NOT EXISTS (
                SELECT 1
                FROM execution_lease_evidence AS linked_evidence
                WHERE linked_evidence.lease_id = OLD.id
                  AND linked_evidence.evidence_id
                    = requested_evidence.value
              )
          )
        )
      )
  )
BEGIN
  SELECT RAISE(ABORT, 'execution finalization proof is invalid');
END;

CREATE TRIGGER execution_leases_terminal_delivery_guard
BEFORE UPDATE OF state, delivery_state ON execution_leases
WHEN OLD.state = 'claimed'
  AND NEW.state IN ('completed', 'failed')
  AND NOT (
    (NEW.state = 'completed'
      AND OLD.delivery_state = 'response-started'
      AND NEW.delivery_state = 'completed')
    OR (NEW.state = 'failed'
      AND NEW.delivery_state = OLD.delivery_state)
    OR (NEW.state = 'failed'
      AND NEW.terminal_reason = 'interrupted'
      AND NEW.delivery_state = 'unknown')
  )
BEGIN
  SELECT RAISE(ABORT, 'execution terminal delivery transition is invalid');
END;

CREATE TRIGGER execution_leases_terminal_immutable_guard
BEFORE UPDATE ON execution_leases
WHEN OLD.state IN ('completed', 'failed', 'expired', 'revoked')
BEGIN
  SELECT RAISE(ABORT, 'terminal execution leases are immutable');
END;

CREATE TRIGGER execution_leases_immutable_delete_guard
BEFORE DELETE ON execution_leases
WHEN EXISTS (
  SELECT 1
  FROM execution_grants
  INNER JOIN scans ON scans.id = execution_grants.scan_id
  WHERE execution_grants.id = OLD.grant_id
)
BEGIN
  SELECT RAISE(ABORT, 'execution leases are immutable');
END;

CREATE TRIGGER execution_lease_evidence_scan_guard
BEFORE INSERT ON execution_lease_evidence
WHEN NOT EXISTS (
  SELECT 1
  FROM execution_leases AS lease_row
  INNER JOIN execution_grants AS grant_row ON grant_row.id = lease_row.grant_id
  INNER JOIN scans AS scan_row ON scan_row.id = grant_row.scan_id
  INNER JOIN targets AS target_row ON target_row.id = scan_row.target_id
  INNER JOIN target_scopes AS scope_row
    ON scope_row.id = grant_row.scope_snapshot_id
   AND scope_row.target_id = target_row.id
  INNER JOIN policy_decisions AS decision_row
    ON decision_row.id = grant_row.policy_decision_id
   AND decision_row.scope_snapshot_id = grant_row.scope_snapshot_id
  INNER JOIN probe_proposals AS proposal_row
    ON proposal_row.id = decision_row.proposal_id
   AND proposal_row.scan_id = scan_row.id
  INNER JOIN execution_capture_decisions AS capture_row
    ON capture_row.id = NEW.capture_decision_id
   AND capture_row.grant_id = grant_row.id
  INNER JOIN evidence_items AS evidence_row ON evidence_row.id = NEW.evidence_id
  WHERE lease_row.id = NEW.lease_id
    AND lease_row.state = 'claimed'
    AND capture_row.role = NEW.role
    AND evidence_row.scan_id = grant_row.scan_id
    AND evidence_row.policy_decision_id = grant_row.policy_decision_id
    AND evidence_row.workspace_id = target_row.workspace_id
    AND evidence_row.type = 'evidence-capture-hash-only'
    AND evidence_row.source = capture_row.source
    AND evidence_row.redaction_state = 'redacted'
    AND evidence_row.integrity_status = 'verified'
    AND capture_row.scan_id = grant_row.scan_id
    AND capture_row.policy_decision_id = grant_row.policy_decision_id
)
BEGIN
  SELECT RAISE(ABORT, 'execution evidence capture binding is invalid');
END;

CREATE TRIGGER evidence_items_execution_binding_immutable_guard
BEFORE UPDATE OF
  id,
  workspace_id,
  scan_id,
  policy_decision_id,
  type,
  mime_type,
  file_path,
  sha256,
  size,
  source,
  created_by,
  capture_tool,
  capture_tool_version,
  derived_from,
  redaction_state,
  retention_until,
  created_at
ON evidence_items
WHEN EXISTS (
  SELECT 1
  FROM execution_lease_evidence AS link_row
  WHERE link_row.evidence_id = OLD.id
)
AND (
  NEW.id IS NOT OLD.id
  OR NEW.workspace_id IS NOT OLD.workspace_id
  OR NEW.scan_id IS NOT OLD.scan_id
  OR NEW.policy_decision_id IS NOT OLD.policy_decision_id
  OR NEW.type IS NOT OLD.type
  OR NEW.mime_type IS NOT OLD.mime_type
  OR NEW.file_path IS NOT OLD.file_path
  OR NEW.sha256 IS NOT OLD.sha256
  OR NEW.size IS NOT OLD.size
  OR NEW.source IS NOT OLD.source
  OR NEW.created_by IS NOT OLD.created_by
  OR NEW.capture_tool IS NOT OLD.capture_tool
  OR NEW.capture_tool_version IS NOT OLD.capture_tool_version
  OR NEW.derived_from IS NOT OLD.derived_from
  OR NEW.redaction_state IS NOT OLD.redaction_state
  OR NEW.retention_until IS NOT OLD.retention_until
  OR NEW.created_at IS NOT OLD.created_at
)
BEGIN
  SELECT RAISE(ABORT, 'execution Evidence binding is immutable');
END;

CREATE TRIGGER evidence_items_execution_interaction_guard
BEFORE UPDATE OF interaction_id ON evidence_items
WHEN EXISTS (
  SELECT 1
  FROM execution_lease_evidence AS link_row
  WHERE link_row.evidence_id = OLD.id
)
AND NOT (
  NEW.interaction_id IS OLD.interaction_id
  OR (
    OLD.interaction_id IS NULL
    AND NEW.interaction_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM execution_lease_evidence AS link_row
      INNER JOIN execution_leases AS lease_row
        ON lease_row.id = link_row.lease_id
       AND lease_row.state = 'claimed'
      INNER JOIN interactions AS interaction_row
        ON interaction_row.id = NEW.interaction_id
       AND interaction_row.execution_lease_id = link_row.lease_id
      WHERE link_row.evidence_id = OLD.id
        AND (
          interaction_row.request_ref = OLD.id
          OR interaction_row.response_ref = OLD.id
        )
    )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'execution Evidence interaction is immutable');
END;

CREATE TRIGGER evidence_items_execution_delete_guard
BEFORE DELETE ON evidence_items
WHEN EXISTS (
  SELECT 1
  FROM execution_lease_evidence AS link_row
  INNER JOIN execution_leases AS lease_row
    ON lease_row.id = link_row.lease_id
  INNER JOIN execution_grants AS grant_row
    ON grant_row.id = lease_row.grant_id
  INNER JOIN scans AS scan_row
    ON scan_row.id = grant_row.scan_id
  WHERE link_row.evidence_id = OLD.id
)
BEGIN
  SELECT RAISE(ABORT, 'execution Evidence is immutable');
END;

CREATE TRIGGER tool_calls_execution_terminal_immutable_guard
BEFORE UPDATE ON tool_calls
WHEN OLD.execution_lease_id IS NOT NULL
  AND EXISTS (
    SELECT 1
    FROM execution_leases AS lease_row
    WHERE lease_row.id = OLD.execution_lease_id
      AND lease_row.state IN (
        'completed', 'failed', 'expired', 'revoked'
      )
  )
  AND NOT (
    OLD.status = 'running'
    AND NEW.id IS OLD.id
    AND NEW.scan_id IS OLD.scan_id
    AND NEW.policy_decision_id IS OLD.policy_decision_id
    AND NEW.execution_lease_id IS OLD.execution_lease_id
    AND NEW.tool_name IS OLD.tool_name
    AND NEW.tool_version IS OLD.tool_version
    AND NEW.argument_hash IS OLD.argument_hash
    AND NEW.duration_ms IS OLD.duration_ms
    AND NEW.output_ref IS OLD.output_ref
    AND NEW.created_at IS OLD.created_at
  )
BEGIN
  SELECT RAISE(ABORT, 'terminal execution ToolCalls are immutable');
END;

CREATE TRIGGER tool_calls_execution_delete_guard
BEFORE DELETE ON tool_calls
WHEN OLD.execution_lease_id IS NOT NULL AND EXISTS (
  SELECT 1
  FROM execution_leases AS lease_row
  INNER JOIN execution_grants AS grant_row
    ON grant_row.id = lease_row.grant_id
  INNER JOIN scans AS scan_row
    ON scan_row.id = grant_row.scan_id
  WHERE lease_row.id = OLD.execution_lease_id
)
BEGIN
  SELECT RAISE(ABORT, 'execution ToolCalls are immutable');
END;

CREATE TRIGGER execution_lease_evidence_immutable_update_guard
BEFORE UPDATE ON execution_lease_evidence
BEGIN
  SELECT RAISE(ABORT, 'execution evidence links are immutable');
END;

CREATE TRIGGER execution_lease_evidence_immutable_delete_guard
BEFORE DELETE ON execution_lease_evidence
WHEN EXISTS (
  SELECT 1
  FROM execution_leases AS lease_row
  INNER JOIN execution_grants AS grant_row ON grant_row.id = lease_row.grant_id
  INNER JOIN scans AS scan_row ON scan_row.id = grant_row.scan_id
  WHERE lease_row.id = OLD.lease_id
)
BEGIN
  SELECT RAISE(ABORT, 'execution evidence links are immutable');
END;
`
}

const REQUIRED_INTERRUPTION_EVIDENCE_CLAUSE = `          ) = 1
          AND NOT EXISTS (
            SELECT 1 FROM execution_lease_evidence AS linked_evidence`

const OPTIONAL_INTERRUPTION_EVIDENCE_CLAUSE = `          ) <= 1
          AND NOT EXISTS (
            SELECT 1 FROM execution_lease_evidence AS linked_evidence`

function interruptionFinalizationTriggerSql(
  evidenceClause: string
): string {
  const startMarker =
    'CREATE TRIGGER execution_leases_finalization_proof_guard'
  const endMarker =
    'CREATE TRIGGER execution_leases_terminal_delivery_guard'
  const start = DAY5_EXECUTION_MIGRATION.sql.indexOf(startMarker)
  const end = DAY5_EXECUTION_MIGRATION.sql.indexOf(endMarker, start)
  if (start < 0 || end <= start) {
    throw new Error(
      'Day 5 recovery migration could not locate the canonical finalization trigger.'
    )
  }
  const required = DAY5_EXECUTION_MIGRATION.sql.slice(start, end).trim()
  if (
    !required.includes(REQUIRED_INTERRUPTION_EVIDENCE_CLAUSE) ||
    required.includes(OPTIONAL_INTERRUPTION_EVIDENCE_CLAUSE)
  ) {
    throw new Error(
      'Day 5 recovery migration canonical finalization trigger is incomplete.'
    )
  }
  const trigger = required.replace(
    REQUIRED_INTERRUPTION_EVIDENCE_CLAUSE,
    evidenceClause
  )
  if (
    evidenceClause !== REQUIRED_INTERRUPTION_EVIDENCE_CLAUSE &&
    trigger.includes(REQUIRED_INTERRUPTION_EVIDENCE_CLAUSE)
  ) {
    throw new Error(
      'Day 5 recovery migration did not produce an exact trigger replacement.'
    )
  }
  return trigger
}

/**
 * Existing Day 5 databases already have the finalization trigger installed,
 * so recovery hardening must be a forward migration rather than an edit to
 * migration 0007. The replacement is deliberately exact-match guarded.
 */
export const DAY5_EXECUTION_RECOVERY_HARDENING_MIGRATION: DatabaseMigration = {
  id: '0008_execution_recovery_without_artifact',
  sql: 'SELECT 1;',
  dataHook: (database: DatabaseSync): void => {
    const row = database
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'trigger'
           AND name = 'execution_leases_finalization_proof_guard'
         LIMIT 1`
      )
      .get() as { sql?: unknown } | undefined
    const currentSql = row?.sql
    const required = interruptionFinalizationTriggerSql(
      REQUIRED_INTERRUPTION_EVIDENCE_CLAUSE
    )
    const optional = interruptionFinalizationTriggerSql(
      OPTIONAL_INTERRUPTION_EVIDENCE_CLAUSE
    )
    if (typeof currentSql !== 'string') {
      throw new Error(
        'Day 5 recovery migration could not verify the finalization trigger.'
      )
    }
    if (
      normalizeTriggerSql(currentSql) === normalizeTriggerSql(optional)
    ) {
      return
    }
    if (
      normalizeTriggerSql(currentSql) !== normalizeTriggerSql(required)
    ) {
      throw new Error(
        'Day 5 recovery migration could not verify the finalization trigger.'
      )
    }
    database.exec('DROP TRIGGER execution_leases_finalization_proof_guard')
    database.exec(optional)
    const installed = database
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'trigger'
           AND name = 'execution_leases_finalization_proof_guard'
         LIMIT 1`
      )
      .get() as { sql?: unknown } | undefined
    if (
      typeof installed?.sql !== 'string' ||
      normalizeTriggerSql(installed.sql) !== normalizeTriggerSql(optional)
    ) {
      throw new Error(
        'Day 5 recovery migration did not install the canonical finalization trigger.'
      )
    }
  }
}

const EXECUTION_DELIVERY_TRIGGER_NAME =
  'execution_leases_delivery_guard'

function normalizeTriggerSql(value: string): string {
  return value
    .replace(/\s+/gu, ' ')
    .replace(/\(\s+/gu, '(')
    .replace(/\s+\)/gu, ')')
    .trim()
    .replace(/;+$/u, '')
}

function hardenedExecutionDeliveryTriggerSql(): string {
  const startMarker =
    `CREATE TRIGGER ${EXECUTION_DELIVERY_TRIGGER_NAME}`
  const endMarker =
    'CREATE TRIGGER execution_leases_finalization_proof_guard'
  const start = DAY5_EXECUTION_MIGRATION.sql.indexOf(startMarker)
  const end = DAY5_EXECUTION_MIGRATION.sql.indexOf(endMarker, start)
  if (start < 0 || end <= start) {
    throw new Error(
      'Day 5 dispatch migration could not locate the canonical delivery trigger.'
    )
  }
  const trigger = DAY5_EXECUTION_MIGRATION.sql.slice(start, end).trim()
  const requiredClauses = [
    "scan_row.status = 'running'",
    'scan_row.module_snapshots_sealed = 1',
    "tool_call_row.status = 'running'",
    'grant_row.session_ref_json IS NULL',
    'grant_row.test_object_ref_json IS NULL',
    'identity_row.updated_at = json_extract',
    'json_each(grant_row.capability_ids_json)',
    'decision_row.authorized_wire_request_hmac_json',
    'scope_row.valid_until'
  ]
  if (requiredClauses.some((clause) => !trigger.includes(clause))) {
    throw new Error(
      'Day 5 dispatch migration canonical trigger is incomplete.'
    )
  }
  return trigger
}

/**
 * Databases that applied an earlier 0007 already recorded that migration and
 * will not observe later trigger hardening in its source text. Replace the
 * known Day 5 delivery guard in a forward migration so dispatch-time
 * identity/scope/capability/budget revalidation also protects upgraded DBs.
 */
export const DAY5_EXECUTION_DISPATCH_HARDENING_MIGRATION: DatabaseMigration = {
  id: '0009_execution_dispatch_revalidation',
  sql: 'SELECT 1;',
  dataHook: (database: DatabaseSync): void => {
    const current = database
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'trigger'
           AND name = ?
         LIMIT 1`
      )
      .get(EXECUTION_DELIVERY_TRIGGER_NAME) as
      | { sql?: unknown }
      | undefined
    const legacyRequiredClauses = [
      `CREATE TRIGGER ${EXECUTION_DELIVERY_TRIGGER_NAME}`,
      'BEFORE UPDATE OF delivery_state ON execution_leases',
      "OLD.state = 'claimed'",
      "NEW.state = 'claimed'",
      "OLD.delivery_state = 'not-dispatched'",
      "NEW.delivery_state = 'possibly-sent'",
      "OLD.delivery_state = 'possibly-sent'",
      "NEW.delivery_state = 'response-started'",
      "RAISE(ABORT, 'execution delivery transition is invalid')"
    ]
    const currentSql = current?.sql
    const normalizedCurrentSql =
      typeof currentSql === 'string'
        ? normalizeTriggerSql(currentSql)
        : ''
    if (
      typeof currentSql !== 'string' ||
      legacyRequiredClauses.some(
        (clause) =>
          !normalizedCurrentSql.includes(normalizeTriggerSql(clause))
      )
    ) {
      throw new Error(
        'Day 5 dispatch migration could not verify the existing delivery trigger.'
      )
    }

    const hardened = hardenedExecutionDeliveryTriggerSql()
    if (
      normalizeTriggerSql(currentSql) !== normalizeTriggerSql(hardened)
    ) {
      database.exec(
        `DROP TRIGGER ${EXECUTION_DELIVERY_TRIGGER_NAME}`
      )
      database.exec(hardened)
    }

    const installed = database
      .prepare(
        `SELECT sql
         FROM sqlite_master
         WHERE type = 'trigger'
           AND name = ?
         LIMIT 1`
      )
      .get(EXECUTION_DELIVERY_TRIGGER_NAME) as
      | { sql?: unknown }
      | undefined
    if (
      typeof installed?.sql !== 'string' ||
      normalizeTriggerSql(installed.sql) !==
        normalizeTriggerSql(hardened)
    ) {
      throw new Error(
        'Day 5 dispatch migration did not install the canonical delivery trigger.'
      )
    }
  }
}
