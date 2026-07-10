import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text
} from 'drizzle-orm/sqlite-core'

export const workspaces = sqliteTable('workspaces', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull()
})

export const targets = sqliteTable(
  'targets',
  {
    id: text('id').primaryKey(),
    workspaceId: text('workspace_id').notNull(),
    name: text('name').notNull(),
    baseUrl: text('base_url').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [index('targets_workspace_idx').on(table.workspaceId)]
)

export const targetScopes = sqliteTable(
  'target_scopes',
  {
    id: text('id').primaryKey(),
    targetId: text('target_id').notNull(),
    allowedOrigins: text('allowed_origins', { mode: 'json' }).$type<string[]>().notNull(),
    allowedPathPrefixes: text('allowed_path_prefixes', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    allowActiveProbing: integer('allow_active_probing', { mode: 'boolean' }).notNull(),
    allowSensitiveProbing: integer('allow_sensitive_probing', {
      mode: 'boolean'
    }).notNull(),
    maxRequestsPerMinute: integer('max_requests_per_minute').notNull(),
    maxConcurrency: integer('max_concurrency').notNull(),
    validUntil: integer('valid_until'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('target_scopes_target_idx').on(table.targetId)]
)

export const identities = sqliteTable(
  'identities',
  {
    id: text('id').primaryKey(),
    targetId: text('target_id').notNull(),
    label: text('label').notNull(),
    role: text('role').notNull(),
    credentialId: text('credential_id'),
    isTestIdentity: integer('is_test_identity', { mode: 'boolean' }).notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('identities_target_idx').on(table.targetId)]
)

export const scans = sqliteTable(
  'scans',
  {
    id: text('id').primaryKey(),
    targetId: text('target_id').notNull(),
    scopeSnapshotId: text('scope_snapshot_id').notNull(),
    status: text('status').notNull(),
    phase: text('phase').notNull(),
    budgetJson: text('budget_json', { mode: 'json' }).$type<Record<string, number>>().notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    index('scans_target_idx').on(table.targetId),
    index('scans_status_idx').on(table.status)
  ]
)

export const pages = sqliteTable(
  'pages',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    url: text('url').notNull(),
    title: text('title'),
    stateHash: text('state_hash'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('pages_scan_idx').on(table.scanId)]
)

export const endpoints = sqliteTable(
  'endpoints',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    pageId: text('page_id'),
    method: text('method').notNull(),
    urlTemplate: text('url_template').notNull(),
    contentType: text('content_type'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('endpoints_scan_idx').on(table.scanId)]
)

export const parameters = sqliteTable(
  'parameters',
  {
    id: text('id').primaryKey(),
    endpointId: text('endpoint_id').notNull(),
    name: text('name').notNull(),
    location: text('location').notNull(),
    dataType: text('data_type'),
    required: integer('required', { mode: 'boolean' }).notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('parameters_endpoint_idx').on(table.endpointId)]
)

export const interactions = sqliteTable(
  'interactions',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    endpointId: text('endpoint_id'),
    identityId: text('identity_id'),
    requestRef: text('request_ref').notNull(),
    responseRef: text('response_ref').notNull(),
    statusCode: integer('status_code'),
    durationMs: integer('duration_ms'),
    stateBeforeHash: text('state_before_hash'),
    stateAfterHash: text('state_after_hash'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('interactions_scan_idx').on(table.scanId)]
)

export const agentRuns = sqliteTable(
  'agent_runs',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    parentRunId: text('parent_run_id'),
    role: text('role').notNull(),
    promptVersion: text('prompt_version').notNull(),
    modelProfileId: text('model_profile_id').notNull(),
    status: text('status').notNull(),
    inputRefs: text('input_refs', { mode: 'json' }).$type<string[]>().notNull(),
    outputRefs: text('output_refs', { mode: 'json' }).$type<string[]>().notNull(),
    startedAt: integer('started_at').notNull(),
    finishedAt: integer('finished_at')
  },
  (table) => [index('agent_runs_scan_idx').on(table.scanId)]
)

export const modelInvocations = sqliteTable(
  'model_invocations',
  {
    id: text('id').primaryKey(),
    agentRunId: text('agent_run_id').notNull(),
    provider: text('provider').notNull(),
    model: text('model').notNull(),
    promptVersion: text('prompt_version').notNull(),
    promptTokens: integer('prompt_tokens').notNull(),
    completionTokens: integer('completion_tokens').notNull(),
    estimatedCostMicros: integer('estimated_cost_micros').notNull(),
    durationMs: integer('duration_ms').notNull(),
    redactionStatus: text('redaction_status').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('model_invocations_agent_run_idx').on(table.agentRunId)]
)

export const probeProposals = sqliteTable(
  'probe_proposals',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    agentRunId: text('agent_run_id').notNull(),
    targetUrl: text('target_url').notNull(),
    method: text('method').notNull(),
    probeLevel: text('probe_level').notNull(),
    sideEffect: text('side_effect').notNull(),
    summary: text('summary').notNull(),
    cleanupPlan: text('cleanup_plan'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('probe_proposals_scan_idx').on(table.scanId)]
)

export const policyDecisions = sqliteTable(
  'policy_decisions',
  {
    id: text('id').primaryKey(),
    proposalId: text('proposal_id').notNull(),
    scopeSnapshotId: text('scope_snapshot_id').notNull(),
    allowed: integer('allowed', { mode: 'boolean' }).notNull(),
    requiresApproval: integer('requires_approval', { mode: 'boolean' }).notNull(),
    code: text('code').notNull(),
    reasons: text('reasons', { mode: 'json' }).$type<string[]>().notNull(),
    approvedBy: text('approved_by'),
    approvedAt: integer('approved_at'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('policy_decisions_proposal_idx').on(table.proposalId)]
)

export const toolCalls = sqliteTable(
  'tool_calls',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    policyDecisionId: text('policy_decision_id').notNull(),
    toolName: text('tool_name').notNull(),
    argumentHash: text('argument_hash').notNull(),
    status: text('status').notNull(),
    durationMs: integer('duration_ms'),
    outputRef: text('output_ref'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('tool_calls_scan_idx').on(table.scanId)]
)

export const signals = sqliteTable(
  'signals',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    interactionId: text('interaction_id'),
    family: text('family').notNull(),
    endpointId: text('endpoint_id').notNull(),
    parameterId: text('parameter_id'),
    identityId: text('identity_id'),
    hypothesis: text('hypothesis').notNull(),
    observedDifference: text('observed_difference').notNull(),
    evidenceRefs: text('evidence_refs', { mode: 'json' }).$type<string[]>().notNull(),
    status: text('status').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('signals_scan_family_idx').on(table.scanId, table.family)]
)

export const confirmationRules = sqliteTable('confirmation_rules', {
  id: text('id').notNull(),
  version: text('version').notNull(),
  family: text('family').notNull(),
  ruleJson: text('rule_json', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
  sourceRefs: text('source_refs', { mode: 'json' }).$type<string[]>().notNull(),
  createdAt: integer('created_at').notNull()
}, (table) => [
  primaryKey({ columns: [table.id, table.version] })
])

export const validationRuns = sqliteTable(
  'validation_runs',
  {
    id: text('id').primaryKey(),
    signalId: text('signal_id').notNull(),
    confirmationRuleId: text('confirmation_rule_id').notNull(),
    confirmationRuleVersion: text('confirmation_rule_version').notNull(),
    policyDecisionId: text('policy_decision_id').notNull(),
    baselineRef: text('baseline_ref').notNull(),
    testRef: text('test_ref').notNull(),
    negativeControlRef: text('negative_control_ref'),
    cleanupStatus: text('cleanup_status').notNull(),
    result: text('result').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('validation_runs_signal_idx').on(table.signalId)]
)

export const evidenceItems = sqliteTable(
  'evidence_items',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    type: text('type').notNull(),
    mimeType: text('mime_type').notNull(),
    filePath: text('file_path').notNull(),
    sha256: text('sha256').notNull(),
    size: integer('size').notNull(),
    source: text('source').notNull(),
    derivedFrom: text('derived_from'),
    redactionState: text('redaction_state').notNull(),
    integrityStatus: text('integrity_status').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('evidence_items_scan_idx').on(table.scanId)]
)

export const findings = sqliteTable(
  'findings',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    family: text('family').notNull(),
    title: text('title').notNull(),
    verdict: text('verdict').notNull(),
    status: text('status').notNull(),
    severity: text('severity').notNull(),
    confirmationRuleId: text('confirmation_rule_id').notNull(),
    confirmationRuleVersion: text('confirmation_rule_version').notNull(),
    reproducibility: text('reproducibility').notNull(),
    remediationJson: text('remediation_json', { mode: 'json' }).$type<string[]>().notNull(),
    firstSeenAt: integer('first_seen_at').notNull(),
    lastVerifiedAt: integer('last_verified_at').notNull()
  },
  (table) => [
    index('findings_scan_idx').on(table.scanId),
    index('findings_family_idx').on(table.family)
  ]
)

export const findingEvidence = sqliteTable(
  'finding_evidence',
  {
    findingId: text('finding_id').notNull(),
    evidenceId: text('evidence_id').notNull()
  },
  (table) => [
    primaryKey({ columns: [table.findingId, table.evidenceId] })
  ]
)

export const knowledgeDocs = sqliteTable('knowledge_docs', {
  id: text('id').primaryKey(),
  title: text('title').notNull(),
  sourceType: text('source_type').notNull(),
  sourceUrl: text('source_url'),
  license: text('license'),
  trustLevel: text('trust_level').notNull(),
  reviewStatus: text('review_status').notNull(),
  sha256: text('sha256').notNull(),
  publishedAt: integer('published_at'),
  ingestedAt: integer('ingested_at').notNull()
})

export const auditLogs = sqliteTable(
  'audit_logs',
  {
    id: text('id').primaryKey(),
    workspaceId: text('workspace_id').notNull(),
    scanId: text('scan_id'),
    event: text('event').notNull(),
    actor: text('actor').notNull(),
    detailJson: text('detail_json', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('audit_logs_workspace_idx').on(table.workspaceId)]
)
