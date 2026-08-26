import type { DatabaseMigration } from './migrations'

/**
 * Protected Evidence is deliberately additive. Existing rows remain
 * legacy/unprotected; no migration may relabel plaintext as encrypted.
 */
export const PROTECTED_EVIDENCE_ENVELOPE_MIGRATION: DatabaseMigration = {
  id: '0010_protected_evidence_envelopes',
  sql: `
CREATE TABLE protected_evidence_items (
  evidence_id TEXT PRIMARY KEY
    REFERENCES evidence_items(id) ON DELETE CASCADE,
  schema_version TEXT NOT NULL
    CHECK (schema_version = 'protected-evidence-storage.v1'),
  capture_decision_id TEXT NOT NULL,
  evidence_role TEXT NOT NULL
    CHECK (length(trim(evidence_role)) BETWEEN 1 AND 100
      AND evidence_role = trim(evidence_role)),
  derivative_evidence_id TEXT NOT NULL
    REFERENCES evidence_items(id) DEFERRABLE INITIALLY DEFERRED,
  derivative_sha256 TEXT NOT NULL
    CHECK (length(derivative_sha256) = 64
      AND derivative_sha256 NOT GLOB '*[^0-9a-f]*'),
  capture_artifact_json TEXT NOT NULL
    CHECK (COALESCE(
      json_valid(capture_artifact_json)
      AND json_type(capture_artifact_json, '$') = 'object'
      AND json_extract(capture_artifact_json, '$.type')
        = 'evidence-capture-protected-original'
      AND json_extract(capture_artifact_json, '$.redactionState') = 'original'
      AND json_extract(capture_artifact_json, '$.payload.schemaVersion')
        = 'protected-evidence-artifact.v1'
      AND json_extract(capture_artifact_json, '$.payload.kind')
        = 'protected-original-persistence-plan',
      0
    )),
  source_hash_json TEXT NOT NULL
    CHECK (COALESCE(
      json_valid(source_hash_json)
      AND json_type(source_hash_json, '$') = 'object'
      AND json_extract(source_hash_json, '$.domain')
        = 'agentgo.evidence-source.v1'
      AND json_extract(source_hash_json, '$.algorithm') = 'sha256'
      AND json_extract(source_hash_json, '$.basis') = 'source-bytes'
      AND json_extract(source_hash_json, '$.coverage') = 'complete',
      0
    )),
  protection_plan_json TEXT NOT NULL
    CHECK (COALESCE(
      json_valid(protection_plan_json)
      AND json_type(protection_plan_json, '$') = 'object'
      AND json_extract(protection_plan_json, '$.protectionScheme')
        = 'os-wrapped-aes-256-gcm.v1'
      AND json_extract(protection_plan_json, '$.accessPolicyId')
        = 'backend-only-protected-evidence'
      AND json_extract(protection_plan_json, '$.accessPolicyVersion') = '1.0.0'
      AND json_extract(protection_plan_json, '$.derivativePolicyId')
        = 'metadata-only-redacted-derivative'
      AND json_extract(protection_plan_json, '$.derivativePolicyVersion')
        = '1.0.0',
      0
    )),
  original_mime_type TEXT NOT NULL,
  plaintext_sha256 TEXT NOT NULL
    CHECK (length(plaintext_sha256) = 64
      AND plaintext_sha256 NOT GLOB '*[^0-9a-f]*'),
  plaintext_size INTEGER NOT NULL
    CHECK (plaintext_size BETWEEN 1 AND 16777216),
  storage_sha256 TEXT NOT NULL
    CHECK (length(storage_sha256) = 64
      AND storage_sha256 NOT GLOB '*[^0-9a-f]*'),
  storage_size INTEGER NOT NULL CHECK (storage_size > 0),
  encryption_algorithm TEXT NOT NULL
    CHECK (encryption_algorithm = 'aes-256-gcm+os-key-wrap'),
  wrapped_data_key TEXT,
  nonce TEXT,
  auth_tag TEXT,
  availability_state TEXT NOT NULL
    CHECK (availability_state IN ('available', 'expired')),
  retention_until INTEGER NOT NULL,
  expired_at INTEGER,
  created_at INTEGER NOT NULL,
  CHECK (
    (availability_state = 'available'
      AND wrapped_data_key IS NOT NULL
      AND length(wrapped_data_key) > 0
      AND nonce IS NOT NULL
      AND length(nonce) > 0
      AND auth_tag IS NOT NULL
      AND length(auth_tag) > 0
      AND expired_at IS NULL)
    OR
    (availability_state = 'expired'
      AND wrapped_data_key IS NULL
      AND nonce IS NULL
      AND auth_tag IS NULL
      AND expired_at IS NOT NULL
      AND expired_at >= retention_until)
  )
);

CREATE INDEX protected_evidence_retention_idx
  ON protected_evidence_items(availability_state, retention_until);
CREATE UNIQUE INDEX protected_evidence_capture_decision_uq
  ON protected_evidence_items(capture_decision_id);
CREATE UNIQUE INDEX protected_evidence_derivative_uq
  ON protected_evidence_items(derivative_evidence_id);

CREATE TRIGGER protected_evidence_insert_guard
BEFORE INSERT ON protected_evidence_items
WHEN NOT EXISTS (
  SELECT 1
  FROM evidence_items AS evidence_row
  JOIN scans AS scan_row ON scan_row.id = evidence_row.scan_id
  JOIN targets AS target_row
    ON target_row.id = scan_row.target_id
   AND target_row.workspace_id = evidence_row.workspace_id
  JOIN policy_decisions AS decision_row
    ON decision_row.id = evidence_row.policy_decision_id
   AND decision_row.allowed = 1
   AND decision_row.valid_until IS NOT NULL
   AND decision_row.scope_snapshot_id = scan_row.scope_snapshot_id
  JOIN probe_proposals AS proposal_row
    ON proposal_row.id = decision_row.proposal_id
   AND proposal_row.scan_id = evidence_row.scan_id
  WHERE evidence_row.id = NEW.evidence_id
    AND evidence_row.type = 'evidence-capture-protected-original'
    AND evidence_row.redaction_state = 'original'
    AND evidence_row.integrity_status = 'verified'
    AND evidence_row.retention_until = NEW.retention_until
    AND evidence_row.sha256 = NEW.storage_sha256
    AND evidence_row.size = NEW.storage_size
    AND evidence_row.mime_type = NEW.original_mime_type
    AND evidence_row.source
      = json_extract(NEW.capture_artifact_json, '$.source')
    AND evidence_row.scan_id
      = json_extract(NEW.capture_artifact_json, '$.scanId')
    AND evidence_row.policy_decision_id
      = json_extract(NEW.capture_artifact_json, '$.policyDecisionId')
    AND NEW.capture_decision_id
      = json_extract(NEW.capture_artifact_json, '$.captureDecisionId')
    AND NEW.evidence_role
      = json_extract(NEW.capture_artifact_json, '$.role')
    AND NEW.capture_decision_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.id'
        )
    AND (SELECT COUNT(*) FROM json_each(NEW.capture_artifact_json)) = 15
    AND (
      SELECT COUNT(*)
      FROM json_each(NEW.capture_artifact_json, '$.payload')
    ) = 9
    AND (
      SELECT COUNT(*)
      FROM json_each(
        NEW.capture_artifact_json,
        '$.payload.captureContext'
      )
    ) = 10
    AND (
      SELECT COUNT(*)
      FROM json_each(
        NEW.capture_artifact_json,
        '$.payload.captureContext.response'
      )
    ) IN (3, 4)
    AND (
      SELECT COUNT(*)
      FROM json_each(
        NEW.capture_artifact_json,
        '$.payload.captureDecision'
      )
    ) = 19
    AND (
      SELECT COUNT(*)
      FROM json_each(NEW.source_hash_json)
    ) = 7
    AND (
      SELECT COUNT(*)
      FROM json_each(NEW.protection_plan_json)
    ) = 8
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.action'
        ) = 'protected-original'
    AND evidence_row.scan_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.scanId'
        )
    AND evidence_row.policy_decision_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.policyDecisionId'
        )
    AND json_extract(NEW.capture_artifact_json, '$.techniqueId')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.techniqueId'
        )
    AND json_extract(NEW.capture_artifact_json, '$.techniqueVersion')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.techniqueVersion'
        )
    AND json_extract(NEW.capture_artifact_json, '$.stepId')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.stepId'
        )
    AND json_extract(NEW.capture_artifact_json, '$.source')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.source'
        )
    AND json_extract(NEW.capture_artifact_json, '$.role')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.role'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.executionState'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.executionState'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.scanId'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.scanId'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.policyDecisionId'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.policyDecisionId'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.techniqueId'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.techniqueId'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.techniqueVersion'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.techniqueVersion'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.stepId'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.stepId'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.source'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.source'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.role'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.role'
        )
    AND json_extract(NEW.capture_artifact_json, '$.capturePolicyId')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.capturePolicyId'
        )
    AND json_extract(NEW.capture_artifact_json, '$.capturePolicyVersion')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.capturePolicyVersion'
        )
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.occurredAt'
        ) BETWEEN
          json_extract(
            NEW.capture_artifact_json,
            '$.payload.captureDecision.validFrom'
          )
          AND
          json_extract(
            NEW.capture_artifact_json,
            '$.payload.captureDecision.validUntil'
          )
    AND NEW.original_mime_type
      = json_extract(NEW.capture_artifact_json, '$.payload.originalMimeType')
    AND NEW.original_mime_type
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.mediaType'
        )
    AND NEW.plaintext_size <= json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxSourceBytes'
        )
    AND json_array_length(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.jsonPointers'
        ) = 0
    AND json_array_length(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.oobMetadataFields'
        ) = 0
    AND NEW.plaintext_sha256
      = json_extract(NEW.source_hash_json, '$.digest')
    AND NEW.plaintext_size
      = json_extract(NEW.source_hash_json, '$.hashedBytes')
    AND NEW.plaintext_size
      = json_extract(NEW.source_hash_json, '$.knownTotalBytes')
    AND NEW.source_hash_json
      = json_extract(NEW.capture_artifact_json, '$.sourceHash')
    AND NEW.source_hash_json
      = json_extract(NEW.capture_artifact_json, '$.payload.sourceHash')
    AND NEW.protection_plan_json
      = json_extract(NEW.capture_artifact_json, '$.payload.protectionPlan')
    AND NEW.protection_plan_json
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.protectedOriginalPlan'
        )
)
BEGIN
  SELECT RAISE(ABORT, 'protected evidence binding is invalid');
END;

/*
 * COUNT(*) alone does not prove that a strict JSON object contains the
 * expected keys: an attacker could replace a required key with padding.
 * Keep the compact binding trigger above, then independently bind every
 * mandatory envelope field, the persisted policy window, retention math,
 * and either the absent (deferred) or already-valid derivative row.
 */
CREATE TRIGGER protected_evidence_insert_envelope_guard
BEFORE INSERT ON protected_evidence_items
WHEN NOT EXISTS (
  SELECT 1
  FROM evidence_items AS evidence_row
  JOIN scans AS scan_row ON scan_row.id = evidence_row.scan_id
  JOIN targets AS target_row
    ON target_row.id = scan_row.target_id
   AND target_row.workspace_id = evidence_row.workspace_id
  JOIN policy_decisions AS decision_row
    ON decision_row.id = evidence_row.policy_decision_id
   AND decision_row.allowed = 1
   AND decision_row.valid_until IS NOT NULL
   AND decision_row.scope_snapshot_id = scan_row.scope_snapshot_id
  JOIN probe_proposals AS proposal_row
    ON proposal_row.id = decision_row.proposal_id
   AND proposal_row.scan_id = evidence_row.scan_id
  WHERE evidence_row.id = NEW.evidence_id
    AND evidence_row.type = 'evidence-capture-protected-original'
    AND evidence_row.redaction_state = 'original'
    AND evidence_row.integrity_status = 'verified'
    AND evidence_row.retention_until = NEW.retention_until
    AND evidence_row.sha256 = NEW.storage_sha256
    AND evidence_row.size = NEW.storage_size
    AND evidence_row.mime_type = NEW.original_mime_type
    AND NEW.derivative_evidence_id <> NEW.evidence_id

    AND json_valid(NEW.capture_artifact_json)
    AND json_type(NEW.capture_artifact_json, '$') = 'object'
    AND json_type(NEW.capture_artifact_json, '$.type') = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.type')
      = 'evidence-capture-protected-original'
    AND json_type(NEW.capture_artifact_json, '$.mimeType') = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.mimeType')
      = 'application/vnd.agentgo.protected-evidence'
    AND json_type(NEW.capture_artifact_json, '$.source') = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.source') IN (
      'http-response-body',
      'dom-snapshot',
      'browser-screenshot'
    )
    AND evidence_row.source
      = json_extract(NEW.capture_artifact_json, '$.source')
    AND json_type(NEW.capture_artifact_json, '$.role') = 'text'
    AND NEW.evidence_role
      = json_extract(NEW.capture_artifact_json, '$.role')
    AND json_type(
          NEW.capture_artifact_json,
          '$.captureDecisionId'
        ) = 'text'
    AND NEW.capture_decision_id
      = json_extract(NEW.capture_artifact_json, '$.captureDecisionId')
    AND json_type(
          NEW.capture_artifact_json,
          '$.capturePolicyId'
        ) = 'text'
    AND json_type(
          NEW.capture_artifact_json,
          '$.capturePolicyVersion'
        ) = 'text'
    AND json_type(NEW.capture_artifact_json, '$.redactionState') = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.redactionState')
      = 'original'
    AND json_type(NEW.capture_artifact_json, '$.scanId') = 'text'
    AND evidence_row.scan_id
      = json_extract(NEW.capture_artifact_json, '$.scanId')
    AND json_type(
          NEW.capture_artifact_json,
          '$.policyDecisionId'
        ) = 'text'
    AND evidence_row.policy_decision_id
      = json_extract(NEW.capture_artifact_json, '$.policyDecisionId')
    AND json_type(NEW.capture_artifact_json, '$.techniqueId') = 'text'
    AND json_type(
          NEW.capture_artifact_json,
          '$.techniqueVersion'
        ) = 'text'
    AND json_type(NEW.capture_artifact_json, '$.stepId') = 'text'
    AND json_type(NEW.capture_artifact_json, '$.sourceHash') = 'object'
    AND json_type(NEW.capture_artifact_json, '$.payload') = 'object'

    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.schemaVersion'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.schemaVersion'
        ) = 'protected-evidence-artifact.v1'
    AND json_type(NEW.capture_artifact_json, '$.payload.kind') = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.payload.kind')
      = 'protected-original-persistence-plan'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.originalMimeType'
        ) = 'text'
    AND NEW.original_mime_type
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.originalMimeType'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.plaintextSize'
        ) = 'integer'
    AND NEW.plaintext_size
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.plaintextSize'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.retentionUntil'
        ) = 'text'
    AND julianday(
          json_extract(
            NEW.capture_artifact_json,
            '$.payload.retentionUntil'
          )
        ) IS NOT NULL
    AND NEW.retention_until = CAST(ROUND((
          julianday(json_extract(
            NEW.capture_artifact_json,
            '$.payload.retentionUntil'
          )) - 2440587.5
        ) * 86400000) AS INTEGER)
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.protectionPlan'
        ) = 'object'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.sourceHash'
        ) = 'object'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext'
        ) = 'object'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision'
        ) = 'object'

    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.scanId'
        ) = 'text'
    AND evidence_row.scan_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.scanId'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.policyDecisionId'
        ) = 'text'
    AND evidence_row.policy_decision_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.policyDecisionId'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.techniqueId'
        ) = 'text'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.techniqueVersion'
        ) = 'text'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.stepId'
        ) = 'text'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.executionState'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.executionState'
        ) IN (
          'succeeded',
          'failed',
          'cancelled',
          'timed-out',
          'interrupted'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.source'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.source'
        ) IN (
          'http-response-body',
          'dom-snapshot',
          'browser-screenshot'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.role'
        ) = 'text'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.occurredAt'
        ) = 'text'
    AND julianday(json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.occurredAt'
        )) IS NOT NULL
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response'
        ) = 'object'

    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.mediaType'
        ) = 'text'
    AND NEW.original_mime_type
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.mediaType'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.charset'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.charset'
        ) IN ('utf-8', 'non-utf-8', 'unknown', 'not-applicable')
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.contentEncoding'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.contentEncoding'
        ) IN ('identity', 'compressed', 'unknown')
    AND (
      (
        json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.declaredSizeBytes'
        ) IS NULL
        AND (
          SELECT COUNT(*)
          FROM json_each(
            NEW.capture_artifact_json,
            '$.payload.captureContext.response'
          )
        ) = 3
      )
      OR
      (
        json_type(
          NEW.capture_artifact_json,
          '$.payload.captureContext.response.declaredSizeBytes'
        ) = 'integer'
        AND json_extract(
              NEW.capture_artifact_json,
              '$.payload.captureContext.response.declaredSizeBytes'
            ) >= 0
        AND (
          SELECT COUNT(*)
          FROM json_each(
            NEW.capture_artifact_json,
            '$.payload.captureContext.response'
          )
        ) = 4
      )
    )

    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.id'
        ) = 'text'
    AND NEW.capture_decision_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.id'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.scanId'
        ) = 'text'
    AND evidence_row.scan_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.scanId'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.policyDecisionId'
        ) = 'text'
    AND evidence_row.policy_decision_id
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.policyDecisionId'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.capturePolicyId'
        ) = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.capturePolicyId')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.capturePolicyId'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.capturePolicyVersion'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.capturePolicyVersion'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.capturePolicyVersion'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.techniqueId'
        ) = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.techniqueId')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.techniqueId'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.techniqueVersion'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.techniqueVersion'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.techniqueVersion'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.stepId'
        ) = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.stepId')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.stepId'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.executionState'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.executionState'
        ) = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.executionState'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.source'
        ) = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.source')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.source'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.role'
        ) = 'text'
    AND json_extract(NEW.capture_artifact_json, '$.role')
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.role'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.action'
        ) = 'text'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.action'
        ) = 'protected-original'
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.validFrom'
        ) = 'text'
    AND julianday(json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.validFrom'
        )) IS NOT NULL
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.validUntil'
        ) = 'text'
    AND julianday(json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.validUntil'
        )) IS NOT NULL
    AND julianday(json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.validFrom'
        )) <= julianday(json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.validUntil'
        ))
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxSourceBytes'
        ) = 'integer'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxSourceBytes'
        ) BETWEEN 1 AND 16777216
    AND NEW.plaintext_size <= json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxSourceBytes'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxExcerptBytes'
        ) = 'integer'
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxExcerptBytes'
        ) BETWEEN 32 AND 65536
    AND json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxExcerptBytes'
        ) <= json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.maxSourceBytes'
        )
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.jsonPointers'
        ) = 'array'
    AND json_array_length(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.jsonPointers'
        ) = 0
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.oobMetadataFields'
        ) = 'array'
    AND json_array_length(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.oobMetadataFields'
        ) = 0
    AND json_type(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.protectedOriginalPlan'
        ) = 'object'

    AND CAST(ROUND((
          julianday(json_extract(
            NEW.capture_artifact_json,
            '$.payload.captureContext.occurredAt'
          )) - 2440587.5
        ) * 86400000) AS INTEGER)
      BETWEEN decision_row.created_at AND decision_row.valid_until
    AND CAST(ROUND((
          julianday(json_extract(
            NEW.capture_artifact_json,
            '$.payload.captureContext.occurredAt'
          )) - 2440587.5
        ) * 86400000) AS INTEGER)
      BETWEEN
        CAST(ROUND((
          julianday(json_extract(
            NEW.capture_artifact_json,
            '$.payload.captureDecision.validFrom'
          )) - 2440587.5
        ) * 86400000) AS INTEGER)
        AND
        CAST(ROUND((
          julianday(json_extract(
            NEW.capture_artifact_json,
            '$.payload.captureDecision.validUntil'
          )) - 2440587.5
        ) * 86400000) AS INTEGER)

    AND json_valid(NEW.source_hash_json)
    AND json_type(NEW.source_hash_json, '$') = 'object'
    AND json_type(NEW.source_hash_json, '$.domain') = 'text'
    AND json_extract(NEW.source_hash_json, '$.domain')
      = 'agentgo.evidence-source.v1'
    AND json_type(NEW.source_hash_json, '$.algorithm') = 'text'
    AND json_extract(NEW.source_hash_json, '$.algorithm') = 'sha256'
    AND json_type(NEW.source_hash_json, '$.digest') = 'text'
    AND length(json_extract(NEW.source_hash_json, '$.digest')) = 64
    AND json_extract(NEW.source_hash_json, '$.digest')
      NOT GLOB '*[^0-9a-f]*'
    AND NEW.plaintext_sha256
      = json_extract(NEW.source_hash_json, '$.digest')
    AND json_type(NEW.source_hash_json, '$.basis') = 'text'
    AND json_extract(NEW.source_hash_json, '$.basis') = 'source-bytes'
    AND json_type(NEW.source_hash_json, '$.coverage') = 'text'
    AND json_extract(NEW.source_hash_json, '$.coverage') = 'complete'
    AND json_type(NEW.source_hash_json, '$.hashedBytes') = 'integer'
    AND NEW.plaintext_size
      = json_extract(NEW.source_hash_json, '$.hashedBytes')
    AND json_type(
          NEW.source_hash_json,
          '$.knownTotalBytes'
        ) = 'integer'
    AND NEW.plaintext_size
      = json_extract(NEW.source_hash_json, '$.knownTotalBytes')
    AND NEW.source_hash_json
      = json_extract(NEW.capture_artifact_json, '$.sourceHash')
    AND NEW.source_hash_json
      = json_extract(NEW.capture_artifact_json, '$.payload.sourceHash')

    AND json_valid(NEW.protection_plan_json)
    AND json_type(NEW.protection_plan_json, '$') = 'object'
    AND json_type(
          NEW.protection_plan_json,
          '$.protectionScheme'
        ) = 'text'
    AND json_extract(NEW.protection_plan_json, '$.protectionScheme')
      = 'os-wrapped-aes-256-gcm.v1'
    AND json_type(NEW.protection_plan_json, '$.accessPolicyId') = 'text'
    AND json_extract(NEW.protection_plan_json, '$.accessPolicyId')
      = 'backend-only-protected-evidence'
    AND json_type(
          NEW.protection_plan_json,
          '$.accessPolicyVersion'
        ) = 'text'
    AND json_extract(NEW.protection_plan_json, '$.accessPolicyVersion')
      = '1.0.0'
    AND json_type(
          NEW.protection_plan_json,
          '$.derivativePolicyId'
        ) = 'text'
    AND json_extract(NEW.protection_plan_json, '$.derivativePolicyId')
      = 'metadata-only-redacted-derivative'
    AND json_type(
          NEW.protection_plan_json,
          '$.derivativePolicyVersion'
        ) = 'text'
    AND json_extract(
          NEW.protection_plan_json,
          '$.derivativePolicyVersion'
        ) = '1.0.0'
    AND json_type(
          NEW.protection_plan_json,
          '$.retentionSeconds'
        ) = 'integer'
    AND json_extract(
          NEW.protection_plan_json,
          '$.retentionSeconds'
        ) BETWEEN 1 AND 2592000
    AND json_type(
          NEW.protection_plan_json,
          '$.maxScanPlaintextBytes'
        ) = 'integer'
    AND json_extract(
          NEW.protection_plan_json,
          '$.maxScanPlaintextBytes'
        ) BETWEEN 1 AND 1073741824
    AND json_type(
          NEW.protection_plan_json,
          '$.maxWorkspacePlaintextBytes'
        ) = 'integer'
    AND json_extract(
          NEW.protection_plan_json,
          '$.maxWorkspacePlaintextBytes'
        ) BETWEEN 1 AND 1073741824
    AND json_extract(
          NEW.protection_plan_json,
          '$.maxScanPlaintextBytes'
        ) <= json_extract(
          NEW.protection_plan_json,
          '$.maxWorkspacePlaintextBytes'
        )
    AND NEW.plaintext_size <= json_extract(
          NEW.protection_plan_json,
          '$.maxScanPlaintextBytes'
        )
    AND NEW.plaintext_size <= json_extract(
          NEW.protection_plan_json,
          '$.maxWorkspacePlaintextBytes'
        )
    AND NEW.protection_plan_json
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.protectionPlan'
        )
    AND NEW.protection_plan_json
      = json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureDecision.protectedOriginalPlan'
        )
    AND NEW.retention_until = (
      CAST(ROUND((
        julianday(json_extract(
          NEW.capture_artifact_json,
          '$.payload.captureContext.occurredAt'
        )) - 2440587.5
      ) * 86400000) AS INTEGER)
      + json_extract(
          NEW.protection_plan_json,
          '$.retentionSeconds'
        ) * 1000
    )

    AND (
      NOT EXISTS (
        SELECT 1
        FROM evidence_items AS derivative_row
        WHERE derivative_row.id = NEW.derivative_evidence_id
      )
      OR EXISTS (
        SELECT 1
        FROM evidence_items AS derivative_row
        WHERE derivative_row.id = NEW.derivative_evidence_id
          AND derivative_row.type
            = 'evidence-capture-protected-derivative'
          AND derivative_row.workspace_id = evidence_row.workspace_id
          AND derivative_row.scan_id = evidence_row.scan_id
          AND derivative_row.policy_decision_id
            = evidence_row.policy_decision_id
          AND derivative_row.interaction_id IS NULL
          AND derivative_row.mime_type = 'application/json'
          AND derivative_row.sha256 = NEW.derivative_sha256
          AND derivative_row.size > 0
          AND derivative_row.source = 'protected-evidence-derivative'
          AND derivative_row.created_by = 'evidence-store'
          AND derivative_row.capture_tool
            = 'metadata-only-redacted-derivative'
          AND derivative_row.capture_tool_version = '1.0.0'
          AND derivative_row.derived_from = evidence_row.id
          AND derivative_row.redaction_state = 'redacted'
          AND derivative_row.integrity_status = 'verified'
          AND derivative_row.retention_until = NEW.retention_until
      )
    )
)
BEGIN
  SELECT RAISE(
    ABORT,
    'protected evidence envelope binding is invalid'
  );
END;

CREATE TRIGGER protected_evidence_update_guard
BEFORE UPDATE ON protected_evidence_items
WHEN NOT (
  OLD.availability_state = 'available'
  AND NEW.availability_state = 'expired'
  AND NEW.evidence_id IS OLD.evidence_id
  AND NEW.schema_version IS OLD.schema_version
  AND NEW.capture_decision_id IS OLD.capture_decision_id
  AND NEW.evidence_role IS OLD.evidence_role
  AND NEW.derivative_evidence_id IS OLD.derivative_evidence_id
  AND NEW.derivative_sha256 IS OLD.derivative_sha256
  AND NEW.capture_artifact_json IS OLD.capture_artifact_json
  AND NEW.source_hash_json IS OLD.source_hash_json
  AND NEW.protection_plan_json IS OLD.protection_plan_json
  AND NEW.original_mime_type IS OLD.original_mime_type
  AND NEW.plaintext_sha256 IS OLD.plaintext_sha256
  AND NEW.plaintext_size IS OLD.plaintext_size
  AND NEW.storage_sha256 IS OLD.storage_sha256
  AND NEW.storage_size IS OLD.storage_size
  AND NEW.encryption_algorithm IS OLD.encryption_algorithm
  AND NEW.wrapped_data_key IS NULL
  AND NEW.nonce IS NULL
  AND NEW.auth_tag IS NULL
  AND NEW.retention_until IS OLD.retention_until
  AND NEW.expired_at IS NOT NULL
  AND NEW.expired_at >= NEW.retention_until
  AND NEW.created_at IS OLD.created_at
)
BEGIN
  SELECT RAISE(ABORT, 'protected evidence metadata is immutable');
END;

CREATE TRIGGER evidence_reserved_protected_type_update_guard
BEFORE UPDATE ON evidence_items
WHEN NEW.type IN (
  'evidence-capture-protected-original',
  'evidence-capture-protected-derivative'
)
AND NEW.type <> OLD.type
BEGIN
  SELECT RAISE(
    ABORT,
    'ordinary evidence cannot enter a reserved protected type'
  );
END;

CREATE TRIGGER evidence_protected_original_update_guard
BEFORE UPDATE ON evidence_items
WHEN EXISTS (
  SELECT 1 FROM protected_evidence_items
  WHERE protected_evidence_items.evidence_id = OLD.id
)
AND NOT (
  NEW.id IS OLD.id
  AND NEW.workspace_id IS OLD.workspace_id
  AND NEW.scan_id IS OLD.scan_id
  AND NEW.interaction_id IS OLD.interaction_id
  AND NEW.policy_decision_id IS OLD.policy_decision_id
  AND NEW.type IS OLD.type
  AND NEW.mime_type IS OLD.mime_type
  AND NEW.file_path IS OLD.file_path
  AND NEW.sha256 IS OLD.sha256
  AND NEW.size IS OLD.size
  AND NEW.source IS OLD.source
  AND NEW.created_by IS OLD.created_by
  AND NEW.capture_tool IS OLD.capture_tool
  AND NEW.capture_tool_version IS OLD.capture_tool_version
  AND NEW.derived_from IS OLD.derived_from
  AND NEW.redaction_state IS OLD.redaction_state
  AND NEW.retention_until IS OLD.retention_until
  AND NEW.created_at IS OLD.created_at
  AND (
    NEW.integrity_status IS OLD.integrity_status
    OR (OLD.integrity_status = 'verified'
      AND NEW.integrity_status IN ('failed', 'expired'))
    OR (OLD.integrity_status = 'failed'
      AND NEW.integrity_status = 'expired')
  )
)
BEGIN
  SELECT RAISE(ABORT, 'protected evidence item is immutable');
END;

CREATE TRIGGER evidence_protected_derivative_insert_guard
BEFORE INSERT ON evidence_items
WHEN NEW.type = 'evidence-capture-protected-derivative'
AND NOT EXISTS (
  SELECT 1
  FROM evidence_items AS original_row
  JOIN protected_evidence_items AS protected_row
    ON protected_row.evidence_id = original_row.id
  WHERE original_row.id = NEW.derived_from
    AND protected_row.derivative_evidence_id = NEW.id
    AND protected_row.derivative_sha256 = NEW.sha256
    AND original_row.workspace_id = NEW.workspace_id
    AND original_row.scan_id = NEW.scan_id
    AND original_row.policy_decision_id = NEW.policy_decision_id
    AND original_row.retention_until = NEW.retention_until
    AND NEW.redaction_state = 'redacted'
    AND NEW.integrity_status = 'verified'
    AND NEW.mime_type = 'application/json'
    AND NEW.source = 'protected-evidence-derivative'
    AND NEW.created_by = 'evidence-store'
    AND NEW.capture_tool = 'metadata-only-redacted-derivative'
    AND NEW.capture_tool_version = '1.0.0'
)
BEGIN
  SELECT RAISE(ABORT, 'protected evidence derivative binding is invalid');
END;

/*
 * The production transaction inserts the protected child before its
 * derivative so that the derivative FK can remain deferred. Once the child
 * exists, any row claiming its reserved ID must satisfy the complete
 * metadata-only derivative binding, even if it uses an ordinary type.
 */
CREATE TRIGGER evidence_referenced_protected_derivative_insert_guard
BEFORE INSERT ON evidence_items
WHEN EXISTS (
  SELECT 1
  FROM protected_evidence_items AS protected_row
  JOIN evidence_items AS original_row
    ON original_row.id = protected_row.evidence_id
  WHERE protected_row.derivative_evidence_id = NEW.id
    AND NOT (
      NEW.id <> original_row.id
      AND NEW.type = 'evidence-capture-protected-derivative'
      AND NEW.workspace_id = original_row.workspace_id
      AND NEW.scan_id = original_row.scan_id
      AND NEW.policy_decision_id = original_row.policy_decision_id
      AND NEW.interaction_id IS NULL
      AND NEW.mime_type = 'application/json'
      AND NEW.sha256 = protected_row.derivative_sha256
      AND NEW.size > 0
      AND NEW.source = 'protected-evidence-derivative'
      AND NEW.created_by = 'evidence-store'
      AND NEW.capture_tool = 'metadata-only-redacted-derivative'
      AND NEW.capture_tool_version = '1.0.0'
      AND NEW.derived_from = original_row.id
      AND NEW.redaction_state = 'redacted'
      AND NEW.integrity_status = 'verified'
      AND NEW.retention_until = protected_row.retention_until
    )
)
BEGIN
  SELECT RAISE(
    ABORT,
    'referenced protected evidence derivative binding is invalid'
  );
END;

CREATE UNIQUE INDEX protected_evidence_derivative_original_uq
  ON evidence_items(derived_from)
  WHERE type = 'evidence-capture-protected-derivative';

CREATE TRIGGER evidence_protected_derivative_update_guard
BEFORE UPDATE ON evidence_items
WHEN OLD.type = 'evidence-capture-protected-derivative'
AND NOT (
  NEW.id IS OLD.id
  AND NEW.workspace_id IS OLD.workspace_id
  AND NEW.scan_id IS OLD.scan_id
  AND NEW.interaction_id IS OLD.interaction_id
  AND NEW.policy_decision_id IS OLD.policy_decision_id
  AND NEW.type IS OLD.type
  AND NEW.mime_type IS OLD.mime_type
  AND NEW.file_path IS OLD.file_path
  AND NEW.sha256 IS OLD.sha256
  AND NEW.size IS OLD.size
  AND NEW.source IS OLD.source
  AND NEW.created_by IS OLD.created_by
  AND NEW.capture_tool IS OLD.capture_tool
  AND NEW.capture_tool_version IS OLD.capture_tool_version
  AND (
    NEW.derived_from IS OLD.derived_from
    OR (
      OLD.derived_from IS NOT NULL
      AND NEW.derived_from IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM evidence_items
        WHERE evidence_items.id = OLD.derived_from
      )
    )
  )
  AND NEW.redaction_state IS OLD.redaction_state
  AND NEW.retention_until IS OLD.retention_until
  AND NEW.created_at IS OLD.created_at
  AND (
    NEW.integrity_status IS OLD.integrity_status
    OR (
      OLD.integrity_status = 'verified'
      AND NEW.integrity_status = 'failed'
    )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'protected evidence derivative is immutable');
END;

CREATE TRIGGER protected_evidence_direct_delete_guard
BEFORE DELETE ON protected_evidence_items
WHEN EXISTS (
  SELECT 1 FROM evidence_items WHERE id = OLD.evidence_id
)
BEGIN
  SELECT RAISE(ABORT, 'protected evidence metadata requires parent deletion');
END;
`
}
