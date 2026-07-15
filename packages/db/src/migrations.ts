export interface DatabaseMigration {
  id: string
  sql: string
}

export const DATABASE_MIGRATIONS: DatabaseMigration[] = [
  {
    id: '0001_agentgo_v1',
    sql: `
CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  authorization_reference TEXT NOT NULL,
  default_identity_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX targets_workspace_idx ON targets(workspace_id);
CREATE UNIQUE INDEX targets_workspace_base_url_uq ON targets(workspace_id, base_url);

CREATE TABLE target_scopes (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  allowed_origins TEXT NOT NULL,
  allowed_path_prefixes TEXT NOT NULL,
  denied_path_prefixes TEXT NOT NULL,
  allowed_ports TEXT NOT NULL,
  allowed_identity_ids TEXT NOT NULL,
  allow_active_probing INTEGER NOT NULL,
  allow_sensitive_probing INTEGER NOT NULL,
  allow_private_network_targets INTEGER NOT NULL,
  allow_loopback_targets INTEGER NOT NULL,
  max_requests_per_minute INTEGER NOT NULL,
  max_concurrency INTEGER NOT NULL,
  authorization_reference TEXT,
  valid_from INTEGER,
  valid_until INTEGER,
  snapshot_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX target_scopes_target_idx ON target_scopes(target_id);
CREATE UNIQUE INDEX target_scopes_hash_uq ON target_scopes(target_id, snapshot_hash);

CREATE TABLE identities (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  role TEXT NOT NULL,
  auth_type TEXT NOT NULL,
  header_name TEXT,
  credential_id TEXT,
  is_test_identity INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX identities_target_idx ON identities(target_id);
CREATE UNIQUE INDEX identities_target_label_uq ON identities(target_id, label);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id),
  status TEXT NOT NULL,
  phase TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0,
  budget_json TEXT NOT NULL,
  config_json TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  runtime_json TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  model_tokens INTEGER NOT NULL DEFAULT 0,
  estimated_cost_micros INTEGER NOT NULL DEFAULT 0,
  checkpoint_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  started_at INTEGER,
  completed_at INTEGER
);
CREATE INDEX scans_target_idx ON scans(target_id);
CREATE INDEX scans_status_idx ON scans(status);
CREATE INDEX scans_updated_idx ON scans(updated_at);

CREATE TABLE scan_identities (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  PRIMARY KEY (scan_id, identity_id)
);

CREATE TABLE scan_checkpoints (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  state_json TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX scan_checkpoints_scan_idx ON scan_checkpoints(scan_id, created_at);

CREATE TABLE scan_events (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX scan_events_scan_idx ON scan_events(scan_id, created_at);

CREATE TABLE pages (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  title TEXT,
  depth INTEGER NOT NULL,
  discovered_from TEXT,
  state_hash TEXT,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX pages_scan_idx ON pages(scan_id);
CREATE UNIQUE INDEX pages_scan_url_uq ON pages(scan_id, url);

CREATE TABLE endpoints (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  page_id TEXT REFERENCES pages(id) ON DELETE SET NULL,
  method TEXT NOT NULL,
  url_template TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  content_type TEXT,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX endpoints_scan_idx ON endpoints(scan_id);
CREATE UNIQUE INDEX endpoints_scan_method_url_uq ON endpoints(scan_id, method, normalized_url);

CREATE TABLE parameters (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  location TEXT NOT NULL,
  data_type TEXT,
  required INTEGER NOT NULL,
  example_masked TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX parameters_endpoint_idx ON parameters(endpoint_id);
CREATE UNIQUE INDEX parameters_endpoint_name_location_uq ON parameters(endpoint_id, name, location);

CREATE TABLE interactions (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  endpoint_id TEXT REFERENCES endpoints(id) ON DELETE SET NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  policy_decision_id TEXT,
  request_ref TEXT NOT NULL,
  response_ref TEXT NOT NULL,
  request_summary_json TEXT NOT NULL,
  response_summary_json TEXT NOT NULL,
  status_code INTEGER,
  duration_ms INTEGER,
  state_before_hash TEXT,
  state_after_hash TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX interactions_scan_idx ON interactions(scan_id, created_at);

CREATE TABLE model_profiles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  agent_role TEXT NOT NULL,
  provider TEXT NOT NULL,
  base_url TEXT,
  model TEXT NOT NULL,
  credential_id TEXT,
  timeout_ms INTEGER NOT NULL,
  rpm_limit INTEGER NOT NULL,
  tpm_limit INTEGER NOT NULL,
  token_budget INTEGER NOT NULL,
  cost_budget_micros INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX model_profiles_role_idx ON model_profiles(agent_role);
CREATE UNIQUE INDEX model_profiles_name_uq ON model_profiles(name);

CREATE TABLE agent_runs (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  parent_run_id TEXT REFERENCES agent_runs(id) ON DELETE SET NULL,
  role TEXT NOT NULL,
  prompt_id TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  prompt_hash TEXT NOT NULL,
  model_profile_id TEXT NOT NULL,
  status TEXT NOT NULL,
  input_refs TEXT NOT NULL,
  output_refs TEXT NOT NULL,
  error TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX agent_runs_scan_idx ON agent_runs(scan_id, started_at);

CREATE TABLE model_invocations (
  id TEXT PRIMARY KEY,
  agent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL,
  estimated_cost_micros INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  redaction_status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX model_invocations_agent_run_idx ON model_invocations(agent_run_id);

CREATE TABLE probe_proposals (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  agent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  target_url TEXT NOT NULL,
  method TEXT NOT NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  probe_level TEXT NOT NULL,
  side_effect TEXT NOT NULL,
  summary TEXT NOT NULL,
  payload_summary TEXT,
  expected_evidence TEXT NOT NULL,
  requested_requests_per_minute INTEGER,
  requested_concurrency INTEGER,
  max_requests INTEGER NOT NULL,
  timeout_ms INTEGER NOT NULL,
  user_approved INTEGER NOT NULL,
  stop_conditions TEXT NOT NULL,
  cleanup_plan TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX probe_proposals_scan_idx ON probe_proposals(scan_id, created_at);

CREATE TABLE policy_decisions (
  id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL REFERENCES probe_proposals(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id),
  allowed INTEGER NOT NULL,
  requires_approval INTEGER NOT NULL,
  code TEXT NOT NULL,
  reasons TEXT NOT NULL,
  normalized_target TEXT,
  approved_by TEXT,
  approved_at INTEGER,
  valid_until INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX policy_decisions_proposal_idx ON policy_decisions(proposal_id);
CREATE INDEX policy_decisions_scope_idx ON policy_decisions(scope_snapshot_id);

CREATE TABLE tool_calls (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
  tool_name TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  argument_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  duration_ms INTEGER,
  output_ref TEXT,
  error TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX tool_calls_scan_idx ON tool_calls(scan_id, created_at);

CREATE TABLE signals (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  interaction_id TEXT REFERENCES interactions(id) ON DELETE SET NULL,
  family TEXT NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  parameter_id TEXT REFERENCES parameters(id) ON DELETE SET NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  hypothesis TEXT NOT NULL,
  observed_difference TEXT NOT NULL,
  confidence_hint INTEGER NOT NULL,
  evidence_refs TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX signals_scan_family_idx ON signals(scan_id, family);

CREATE TABLE confirmation_rules (
  id TEXT NOT NULL,
  version TEXT NOT NULL,
  family TEXT NOT NULL,
  rule_json TEXT NOT NULL,
  required_checks TEXT NOT NULL,
  source_refs TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (id, version)
);

CREATE TABLE validation_runs (
  id TEXT PRIMARY KEY,
  signal_id TEXT NOT NULL REFERENCES signals(id) ON DELETE CASCADE,
  confirmation_rule_id TEXT NOT NULL,
  confirmation_rule_version TEXT NOT NULL,
  probe_proposal_id TEXT NOT NULL REFERENCES probe_proposals(id),
  policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
  tool_call_id TEXT REFERENCES tool_calls(id) ON DELETE SET NULL,
  baseline_ref TEXT NOT NULL,
  test_ref TEXT NOT NULL,
  negative_control_ref TEXT,
  completed_checks TEXT NOT NULL,
  failed_checks TEXT NOT NULL,
  missing_checks TEXT NOT NULL,
  cleanup_status TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (confirmation_rule_id, confirmation_rule_version)
    REFERENCES confirmation_rules(id, version)
);
CREATE INDEX validation_runs_signal_idx ON validation_runs(signal_id);

CREATE TABLE evidence_items (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  interaction_id TEXT REFERENCES interactions(id) ON DELETE SET NULL,
  policy_decision_id TEXT REFERENCES policy_decisions(id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  file_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  source TEXT NOT NULL,
  created_by TEXT NOT NULL,
  capture_tool TEXT NOT NULL,
  capture_tool_version TEXT NOT NULL,
  derived_from TEXT REFERENCES evidence_items(id) ON DELETE SET NULL,
  redaction_state TEXT NOT NULL,
  integrity_status TEXT NOT NULL,
  retention_until INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX evidence_items_scan_idx ON evidence_items(scan_id, created_at);
CREATE UNIQUE INDEX evidence_items_scan_hash_uq ON evidence_items(scan_id, sha256, type);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  family TEXT NOT NULL,
  title TEXT NOT NULL,
  verdict TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER NOT NULL,
  endpoint_id TEXT REFERENCES endpoints(id) ON DELETE SET NULL,
  parameter_id TEXT REFERENCES parameters(id) ON DELETE SET NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  affected_resource TEXT,
  cwe TEXT,
  owasp TEXT,
  confirmation_rule_id TEXT NOT NULL,
  confirmation_rule_version TEXT NOT NULL,
  reproducibility TEXT NOT NULL,
  remediation_json TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_verified_at INTEGER NOT NULL,
  FOREIGN KEY (confirmation_rule_id, confirmation_rule_version)
    REFERENCES confirmation_rules(id, version)
);
CREATE INDEX findings_scan_idx ON findings(scan_id);
CREATE INDEX findings_family_idx ON findings(family);
CREATE INDEX findings_verdict_idx ON findings(verdict);

CREATE TABLE finding_evidence (
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence_items(id) ON DELETE CASCADE,
  PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE knowledge_docs (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_url TEXT,
  author TEXT,
  license TEXT,
  trust_level TEXT NOT NULL,
  review_status TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  published_at INTEGER,
  ingested_at INTEGER NOT NULL
);

CREATE TABLE knowledge_chunks (
  id TEXT PRIMARY KEY,
  doc_id TEXT NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
  family TEXT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  tags TEXT NOT NULL,
  applicability TEXT NOT NULL,
  token_estimate INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX knowledge_chunks_doc_idx ON knowledge_chunks(doc_id);
CREATE INDEX knowledge_chunks_family_idx ON knowledge_chunks(family);

CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(
  title,
  content,
  tags,
  content='knowledge_chunks',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER knowledge_chunks_ai AFTER INSERT ON knowledge_chunks BEGIN
  INSERT INTO knowledge_chunks_fts(rowid, title, content, tags)
  VALUES (new.rowid, new.title, new.content, new.tags);
END;
CREATE TRIGGER knowledge_chunks_ad AFTER DELETE ON knowledge_chunks BEGIN
  INSERT INTO knowledge_chunks_fts(knowledge_chunks_fts, rowid, title, content, tags)
  VALUES ('delete', old.rowid, old.title, old.content, old.tags);
END;
CREATE TRIGGER knowledge_chunks_au AFTER UPDATE ON knowledge_chunks BEGIN
  INSERT INTO knowledge_chunks_fts(knowledge_chunks_fts, rowid, title, content, tags)
  VALUES ('delete', old.rowid, old.title, old.content, old.tags);
  INSERT INTO knowledge_chunks_fts(rowid, title, content, tags)
  VALUES (new.rowid, new.title, new.content, new.tags);
END;

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  format TEXT NOT NULL,
  file_path TEXT,
  sha256 TEXT NOT NULL,
  redacted INTEGER NOT NULL,
  content_ref TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX reports_scan_idx ON reports(scan_id, created_at);

CREATE TABLE app_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE benchmark_cases (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  target_version TEXT NOT NULL,
  family TEXT NOT NULL,
  expected_verdict TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  parameter TEXT,
  identity_plan_json TEXT NOT NULL,
  required_evidence TEXT NOT NULL,
  reset_procedure TEXT NOT NULL,
  forbidden_actions TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX benchmark_cases_family_idx ON benchmark_cases(family);

CREATE TABLE benchmark_runs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES benchmark_cases(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  expected_verdict TEXT NOT NULL,
  actual_verdict TEXT NOT NULL,
  metrics_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX benchmark_runs_case_idx ON benchmark_runs(case_id, created_at);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  event TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_logs_workspace_idx ON audit_logs(workspace_id, created_at);
`
  },
  {
    id: '0002_identity_owned_resources',
    sql: `
ALTER TABLE identities ADD COLUMN owned_resource_ids TEXT NOT NULL DEFAULT '[]';
`
  },
  {
    id: '0003_mcp_servers_and_token_usage',
    sql: `
CREATE TABLE model_profile_usage_events (
  id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL REFERENCES model_profiles(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX model_profile_usage_profile_idx
  ON model_profile_usage_events(profile_id, created_at);

INSERT INTO model_profile_usage_events (
  id,
  profile_id,
  source,
  prompt_tokens,
  completion_tokens,
  created_at
)
SELECT
  model_invocations.id,
  agent_runs.model_profile_id,
  'agent-run',
  model_invocations.prompt_tokens,
  model_invocations.completion_tokens,
  model_invocations.created_at
FROM model_invocations
INNER JOIN agent_runs ON agent_runs.id = model_invocations.agent_run_id;

CREATE TABLE mcp_servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  transport TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  credential_id TEXT,
  config_json TEXT NOT NULL,
  allowed_agent_roles TEXT NOT NULL,
  risk_labels TEXT NOT NULL,
  status TEXT NOT NULL,
  discovery_json TEXT NOT NULL,
  last_tested_at INTEGER,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX mcp_servers_name_uq ON mcp_servers(name);
CREATE INDEX mcp_servers_status_idx ON mcp_servers(status, updated_at);
`
  },
  {
    id: '0004_knowledge_intelligence_ingestion',
    sql: `
CREATE TABLE knowledge_imports (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
  source_type TEXT NOT NULL,
  raw_content TEXT NOT NULL,
  raw_content_sha256 TEXT NOT NULL,
  vendor_hint TEXT,
  product_hint TEXT,
  instruction_flags TEXT NOT NULL,
  status TEXT NOT NULL,
  extractor_profile_id TEXT REFERENCES model_profiles(id) ON DELETE SET NULL,
  reviewer_profile_id TEXT REFERENCES model_profiles(id) ON DELETE SET NULL,
  review_issues TEXT NOT NULL,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX knowledge_imports_document_uq ON knowledge_imports(document_id);
CREATE INDEX knowledge_imports_status_idx ON knowledge_imports(status, updated_at);

CREATE TABLE knowledge_intelligence (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL REFERENCES knowledge_imports(id) ON DELETE CASCADE,
  schema_version TEXT NOT NULL,
  title TEXT NOT NULL,
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  vulnerability_type TEXT NOT NULL,
  family TEXT,
  identifiers_json TEXT NOT NULL,
  affected_versions TEXT NOT NULL,
  preconditions TEXT NOT NULL,
  affected_endpoints TEXT NOT NULL,
  signals TEXT NOT NULL,
  confirmation_rules TEXT NOT NULL,
  remediation TEXT NOT NULL,
  forbidden_actions TEXT NOT NULL,
  field_evidence TEXT NOT NULL,
  extraction_confidence INTEGER NOT NULL,
  published_chunk_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX knowledge_intelligence_import_uq ON knowledge_intelligence(import_id);
CREATE INDEX knowledge_intelligence_product_idx ON knowledge_intelligence(vendor, product);
CREATE INDEX knowledge_intelligence_family_idx ON knowledge_intelligence(family);

CREATE TABLE knowledge_agent_runs (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL REFERENCES knowledge_imports(id) ON DELETE CASCADE,
  parent_run_id TEXT REFERENCES knowledge_agent_runs(id) ON DELETE SET NULL,
  role TEXT NOT NULL,
  prompt_id TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  prompt_hash TEXT NOT NULL,
  model_profile_id TEXT NOT NULL REFERENCES model_profiles(id),
  provider TEXT,
  model TEXT,
  status TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  error TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX knowledge_agent_runs_import_idx
  ON knowledge_agent_runs(import_id, started_at);
`
  },
  {
    id: '0005_monotonic_scope_revisions',
    sql: `
ALTER TABLE target_scopes
  ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;

WITH ranked_scopes AS (
  SELECT
    rowid AS scope_rowid,
    ROW_NUMBER() OVER (
      PARTITION BY target_id
      ORDER BY created_at ASC, rowid ASC
    ) AS scope_revision
  FROM target_scopes
)
UPDATE target_scopes
SET revision = (
  SELECT ranked_scopes.scope_revision
  FROM ranked_scopes
  WHERE ranked_scopes.scope_rowid = target_scopes.rowid
);

CREATE UNIQUE INDEX target_scopes_target_revision_uq
  ON target_scopes(target_id, revision);

CREATE TRIGGER target_scopes_revision_insert_guard
BEFORE INSERT ON target_scopes
WHEN typeof(NEW.revision) <> 'integer' OR NEW.revision < 1
BEGIN
  SELECT RAISE(ABORT, 'target scope revision must be a positive integer');
END;

CREATE TRIGGER target_scopes_immutable_guard
BEFORE UPDATE ON target_scopes
BEGIN
  SELECT RAISE(ABORT, 'target scope snapshots are immutable');
END;

ALTER TABLE targets
  ADD COLUMN current_scope_id TEXT REFERENCES target_scopes(id);

UPDATE targets
SET current_scope_id = (
  SELECT target_scopes.id
  FROM target_scopes
  WHERE target_scopes.target_id = targets.id
  ORDER BY target_scopes.revision DESC
  LIMIT 1
);

CREATE INDEX targets_current_scope_idx ON targets(current_scope_id);

CREATE TRIGGER targets_current_scope_insert_guard
BEFORE INSERT ON targets
WHEN NEW.current_scope_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM target_scopes
    WHERE target_scopes.id = NEW.current_scope_id
      AND target_scopes.target_id = NEW.id
  )
BEGIN
  SELECT RAISE(ABORT, 'current scope must belong to target');
END;

CREATE TRIGGER targets_current_scope_update_guard
BEFORE UPDATE OF current_scope_id ON targets
WHEN NEW.current_scope_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM target_scopes
    WHERE target_scopes.id = NEW.current_scope_id
      AND target_scopes.target_id = NEW.id
  )
BEGIN
  SELECT RAISE(ABORT, 'current scope must belong to target');
END;

CREATE TRIGGER targets_current_scope_required_guard
BEFORE UPDATE OF current_scope_id ON targets
WHEN OLD.current_scope_id IS NOT NULL
  AND NEW.current_scope_id IS NULL
BEGIN
  SELECT RAISE(ABORT, 'current scope cannot be cleared');
END;
`
  }
]
