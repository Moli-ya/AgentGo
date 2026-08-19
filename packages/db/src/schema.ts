import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex
} from 'drizzle-orm/sqlite-core'
import type {
  AgentModelProfileSelection,
  AgentRole,
  AllowedHeaderDescriptor,
  BodyEncoding,
  EvidenceCaptureAction,
  EvidenceCaptureDecision,
  EvidenceCaptureExecutionState,
  EvidenceCaptureSource,
  EvidenceSourceHash,
  ExecutionAdapterKind,
  ExecutionCredentialRef,
  ExecutionCaptureDecisionSetHash,
  ExecutionGrantBudget,
  ExecutionGrantIntegrityHmac,
  ExecutionLeaseDeliveryState,
  ExecutionLeaseOutcomeSummary,
  ExecutionLeaseState,
  ExecutionLeaseTerminalReason,
  ExecutionPurpose,
  ExecutionRetryClass,
  IdentityRef,
  InventoryBodyShape,
  InventoryExecutionClass,
  InventoryLifecycleStatus,
  InventoryReviewStatus,
  KnowledgeFieldEvidence,
  KnowledgeHttpRequestTemplate,
  KnowledgeImportStatus,
  KnowledgeReviewIssue,
  KnowledgeSourceType,
  McpAuthType,
  McpPromptSummary,
  McpResourceSummary,
  McpRiskLabel,
  McpServerStatus,
  McpToolSummary,
  McpTransport,
  RedactedInventoryPreview,
  ResolvedIntentHash,
  ScanBudget,
  ScanModuleAuthorization,
  ScanSnapshotEnvironment,
  ScanSnapshotCapabilityDescriptor,
  SelectorRef,
  SessionGenerationRef,
  TemplateIntentHash,
  TestObjectRef,
  TransportKind,
  VersionedDefinitionRef,
  VulnerabilityFamily,
  WireRequestHmac
} from '@agentgo/contracts'

export const workspaces = sqliteTable('workspaces', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  description: text('description').notNull(),
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
    description: text('description').notNull(),
    authorizationReference: text('authorization_reference').notNull(),
    defaultIdentityId: text('default_identity_id'),
    currentScopeId: text('current_scope_id'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    index('targets_workspace_idx').on(table.workspaceId),
    index('targets_current_scope_idx').on(table.currentScopeId),
    uniqueIndex('targets_workspace_base_url_uq').on(table.workspaceId, table.baseUrl)
  ]
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
    deniedPathPrefixes: text('denied_path_prefixes', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    allowedPorts: text('allowed_ports', { mode: 'json' }).$type<number[]>().notNull(),
    allowedIdentityIds: text('allowed_identity_ids', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    allowActiveProbing: integer('allow_active_probing', { mode: 'boolean' }).notNull(),
    allowSensitiveProbing: integer('allow_sensitive_probing', {
      mode: 'boolean'
    }).notNull(),
    allowPrivateNetworkTargets: integer('allow_private_network_targets', {
      mode: 'boolean'
    }).notNull(),
    allowLoopbackTargets: integer('allow_loopback_targets', {
      mode: 'boolean'
    }).notNull(),
    maxRequestsPerMinute: integer('max_requests_per_minute').notNull(),
    maxConcurrency: integer('max_concurrency').notNull(),
    authorizationReference: text('authorization_reference'),
    validFrom: integer('valid_from'),
    validUntil: integer('valid_until'),
    revision: integer('revision').notNull(),
    snapshotHash: text('snapshot_hash').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('target_scopes_target_idx').on(table.targetId),
    uniqueIndex('target_scopes_target_revision_uq').on(
      table.targetId,
      table.revision
    ),
    uniqueIndex('target_scopes_hash_uq').on(table.targetId, table.snapshotHash)
  ]
)

export const identities = sqliteTable(
  'identities',
  {
    id: text('id').primaryKey(),
    targetId: text('target_id').notNull(),
    label: text('label').notNull(),
    role: text('role').notNull(),
    authType: text('auth_type').notNull(),
    headerName: text('header_name'),
    credentialId: text('credential_id'),
    isTestIdentity: integer('is_test_identity', { mode: 'boolean' }).notNull(),
    ownedResourceIds: text('owned_resource_ids', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    index('identities_target_idx').on(table.targetId),
    uniqueIndex('identities_target_label_uq').on(table.targetId, table.label)
  ]
)

export interface ScanConfiguration {
  description: string
  families: VulnerabilityFamily[]
  identityIds: string[]
  callbackUrl?: string
  modelProfileIds: AgentModelProfileSelection
}

export interface McpServerConfiguration {
  command?: string
  args: string[]
  cwd?: string
  url?: string
  authType: McpAuthType
  authHeaderName?: string
  environmentKeys: string[]
  headerNames: string[]
  timeoutMs: number
  roots: string[]
}

export interface McpServerDiscovery {
  protocolVersion?: string
  serverName?: string
  serverVersion?: string
  tools: McpToolSummary[]
  resources: McpResourceSummary[]
  prompts: McpPromptSummary[]
}

export const scans = sqliteTable(
  'scans',
  {
    id: text('id').primaryKey(),
    targetId: text('target_id').notNull(),
    name: text('name').notNull(),
    scopeSnapshotId: text('scope_snapshot_id').notNull(),
    status: text('status').notNull(),
    phase: text('phase').notNull(),
    progress: integer('progress').notNull(),
    budgetJson: text('budget_json', { mode: 'json' }).$type<ScanBudget>().notNull(),
    configJson: text('config_json', { mode: 'json' }).$type<ScanConfiguration>().notNull(),
    planJson: text('plan_json', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
    runtimeJson: text('runtime_json', { mode: 'json' })
      .$type<Record<string, unknown>>()
      .notNull(),
    requestCount: integer('request_count').notNull(),
    modelTokens: integer('model_tokens').notNull(),
    estimatedCostMicros: integer('estimated_cost_micros').notNull(),
    checkpointCount: integer('checkpoint_count').notNull(),
    lastError: text('last_error'),
    moduleSnapshotsSealed: integer('module_snapshots_sealed', {
      mode: 'boolean'
    }).notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
    startedAt: integer('started_at'),
    completedAt: integer('completed_at')
  },
  (table) => [
    index('scans_target_idx').on(table.targetId),
    index('scans_status_idx').on(table.status),
    index('scans_updated_idx').on(table.updatedAt)
  ]
)

export const scanIdentities = sqliteTable(
  'scan_identities',
  {
    scanId: text('scan_id').notNull(),
    identityId: text('identity_id').notNull()
  },
  (table) => [primaryKey({ columns: [table.scanId, table.identityId] })]
)

export const scanCheckpoints = sqliteTable(
  'scan_checkpoints',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    phase: text('phase').notNull(),
    stateJson: text('state_json', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
    reason: text('reason').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('scan_checkpoints_scan_idx').on(table.scanId, table.createdAt)]
)

export const scanEvents = sqliteTable(
  'scan_events',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    type: text('type').notNull(),
    level: text('level').notNull(),
    message: text('message').notNull(),
    detailJson: text('detail_json', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('scan_events_scan_idx').on(table.scanId, table.createdAt)]
)

export const pages = sqliteTable(
  'pages',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    url: text('url').notNull(),
    title: text('title'),
    depth: integer('depth').notNull(),
    discoveredFrom: text('discovered_from'),
    stateHash: text('state_hash'),
    status: text('status').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    index('pages_scan_idx').on(table.scanId),
    uniqueIndex('pages_scan_url_uq').on(table.scanId, table.url)
  ]
)

export const endpoints = sqliteTable(
  'endpoints',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    pageId: text('page_id'),
    method: text('method').notNull(),
    urlTemplate: text('url_template').notNull(),
    normalizedUrl: text('normalized_url').notNull(),
    canonicalRoute: text('canonical_route').notNull(),
    contentType: text('content_type'),
    source: text('source').notNull(),
    status: text('status').notNull(),
    lifecycleStatus: text('lifecycle_status')
      .$type<InventoryLifecycleStatus>()
      .notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    index('endpoints_scan_idx').on(table.scanId),
    uniqueIndex('endpoints_scan_method_route_uq').on(
      table.scanId,
      table.method,
      table.canonicalRoute
    )
  ]
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
    exampleMasked: text('example_masked'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('parameters_endpoint_idx').on(table.endpointId),
    uniqueIndex('parameters_endpoint_name_location_uq').on(
      table.endpointId,
      table.name,
      table.location
    )
  ]
)

export const requestVariants = sqliteTable(
  'request_variants',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    endpointId: text('endpoint_id').notNull(),
    contentType: text('content_type'),
    bodyShape: text('body_shape_json', { mode: 'json' })
      .$type<InventoryBodyShape>()
      .notNull(),
    codec: text('codec').$type<BodyEncoding>().notNull(),
    transport: text('transport').$type<TransportKind>().notNull(),
    allowedHeaders: text('allowed_headers_json', { mode: 'json' })
      .$type<AllowedHeaderDescriptor[]>()
      .notNull(),
    redactedPreview: text('redacted_preview_json', { mode: 'json' })
      .$type<RedactedInventoryPreview>()
      .notNull(),
    templateVersion: text('template_version').notNull(),
    requiredCapabilityIds: text('required_capability_ids_json', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    reviewStatus: text('review_status')
      .$type<InventoryReviewStatus>()
      .notNull(),
    reviewedBy: text('reviewed_by'),
    reviewedAt: integer('reviewed_at'),
    executionClass: text('execution_class')
      .$type<InventoryExecutionClass>()
      .notNull(),
    lifecycleStatus: text('lifecycle_status')
      .$type<InventoryLifecycleStatus>()
      .notNull(),
    retiredAt: integer('retired_at'),
    structureHash: text('structure_hash').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    index('request_variants_scan_idx').on(table.scanId),
    index('request_variants_endpoint_idx').on(table.endpointId),
    uniqueIndex('request_variants_endpoint_structure_uq').on(
      table.endpointId,
      table.structureHash
    )
  ]
)

export const requestVariantSelectors = sqliteTable(
  'request_variant_selectors',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    requestVariantId: text('request_variant_id').notNull(),
    kind: text('kind').$type<SelectorRef['kind']>().notNull(),
    selectorJson: text('selector_json', { mode: 'json' })
      .$type<SelectorRef>()
      .notNull(),
    structureHash: text('structure_hash').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('request_variant_selectors_scan_idx').on(table.scanId),
    index('request_variant_selectors_variant_idx').on(table.requestVariantId),
    uniqueIndex('request_variant_selectors_variant_structure_uq').on(
      table.requestVariantId,
      table.structureHash
    )
  ]
)

export const inventorySources = sqliteTable(
  'inventory_sources',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    endpointId: text('endpoint_id').notNull(),
    requestVariantId: text('request_variant_id').notNull(),
    type: text('source_type').notNull(),
    sourceHash: text('source_hash').notNull(),
    provenanceHash: text('provenance_hash').notNull(),
    pageId: text('page_id'),
    evidenceRef: text('evidence_ref'),
    initiator: text('initiator'),
    confidencePpm: integer('confidence_ppm').notNull(),
    discoveredAt: integer('discovered_at').notNull(),
    reviewStatus: text('review_status')
      .$type<InventoryReviewStatus>()
      .notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('inventory_sources_scan_idx').on(table.scanId),
    index('inventory_sources_endpoint_idx').on(table.endpointId),
    index('inventory_sources_variant_idx').on(table.requestVariantId),
    uniqueIndex('inventory_sources_scan_provenance_uq').on(
      table.scanId,
      table.provenanceHash
    )
  ]
)

export const scanModuleSnapshots = sqliteTable(
  'scan_module_snapshots',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    familyId: text('family_id').notNull(),
    moduleId: text('module_id').notNull(),
    moduleVersion: text('module_version').notNull(),
    definitionHash: text('definition_hash').notNull(),
    techniqueId: text('technique_id').notNull(),
    techniqueVersion: text('technique_version').notNull(),
    strategyRefs: text('strategy_refs_json', { mode: 'json' })
      .$type<VersionedDefinitionRef[]>()
      .notNull(),
    confirmationRuleRefs: text('confirmation_rule_refs_json', { mode: 'json' })
      .$type<VersionedDefinitionRef[]>()
      .notNull(),
    evidenceProfileRefs: text('evidence_profile_refs_json', { mode: 'json' })
      .$type<VersionedDefinitionRef[]>()
      .notNull(),
    remediationRefs: text('remediation_refs_json', { mode: 'json' })
      .$type<VersionedDefinitionRef[]>()
      .notNull(),
    requiredCapabilityIds: text('required_capability_ids_json', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    capabilityDescriptors: text('capability_descriptors_json', {
      mode: 'json'
    })
      .$type<ScanSnapshotCapabilityDescriptor[]>()
      .notNull(),
    capabilitySnapshotHash: text('capability_snapshot_hash').notNull(),
    selectedCapabilitiesHash: text('selected_capabilities_hash').notNull(),
    selectedDefinitionsHash: text('selected_definitions_hash').notNull(),
    registrySnapshotHash: text('registry_snapshot_hash').notNull(),
    environment: text('environment')
      .$type<ScanSnapshotEnvironment>()
      .notNull(),
    authorization: text('authorization')
      .$type<ScanModuleAuthorization>()
      .notNull(),
    snapshotHash: text('snapshot_hash').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('scan_module_snapshots_scan_idx').on(table.scanId),
    uniqueIndex('scan_module_snapshots_scan_technique_uq').on(
      table.scanId,
      table.familyId,
      table.techniqueId
    )
  ]
)

export const interactions = sqliteTable(
  'interactions',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    endpointId: text('endpoint_id'),
    identityId: text('identity_id'),
    policyDecisionId: text('policy_decision_id'),
    executionLeaseId: text('execution_lease_id'),
    requestRef: text('request_ref').notNull(),
    responseRef: text('response_ref').notNull(),
    requestSummaryJson: text('request_summary_json', { mode: 'json' })
      .$type<Record<string, unknown>>()
      .notNull(),
    responseSummaryJson: text('response_summary_json', { mode: 'json' })
      .$type<Record<string, unknown>>()
      .notNull(),
    statusCode: integer('status_code'),
    durationMs: integer('duration_ms'),
    stateBeforeHash: text('state_before_hash'),
    stateAfterHash: text('state_after_hash'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('interactions_scan_idx').on(table.scanId, table.createdAt),
    uniqueIndex('interactions_execution_lease_uq').on(table.executionLeaseId)
  ]
)

export const agentRuns = sqliteTable(
  'agent_runs',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    parentRunId: text('parent_run_id'),
    role: text('role').notNull(),
    promptId: text('prompt_id').notNull(),
    promptVersion: text('prompt_version').notNull(),
    promptHash: text('prompt_hash').notNull(),
    modelProfileId: text('model_profile_id').notNull(),
    status: text('status').notNull(),
    inputRefs: text('input_refs', { mode: 'json' }).$type<string[]>().notNull(),
    outputRefs: text('output_refs', { mode: 'json' }).$type<string[]>().notNull(),
    error: text('error'),
    startedAt: integer('started_at').notNull(),
    finishedAt: integer('finished_at')
  },
  (table) => [index('agent_runs_scan_idx').on(table.scanId, table.startedAt)]
)

export const modelInvocations = sqliteTable(
  'model_invocations',
  {
    id: text('id').primaryKey(),
    agentRunId: text('agent_run_id').notNull(),
    provider: text('provider').notNull(),
    model: text('model').notNull(),
    promptVersion: text('prompt_version').notNull(),
    inputHash: text('input_hash').notNull(),
    outputHash: text('output_hash').notNull(),
    promptTokens: integer('prompt_tokens').notNull(),
    completionTokens: integer('completion_tokens').notNull(),
    estimatedCostMicros: integer('estimated_cost_micros').notNull(),
    durationMs: integer('duration_ms').notNull(),
    redactionStatus: text('redaction_status').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('model_invocations_agent_run_idx').on(table.agentRunId)]
)

export const modelProfileUsageEvents = sqliteTable(
  'model_profile_usage_events',
  {
    id: text('id').primaryKey(),
    profileId: text('profile_id').notNull(),
    source: text('source').notNull(),
    promptTokens: integer('prompt_tokens').notNull(),
    completionTokens: integer('completion_tokens').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('model_profile_usage_profile_idx').on(table.profileId, table.createdAt)]
)

export const probeProposals = sqliteTable(
  'probe_proposals',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    agentRunId: text('agent_run_id').notNull(),
    kind: text('kind').notNull(),
    targetUrl: text('target_url').notNull(),
    method: text('method').notNull(),
    identityId: text('identity_id'),
    probeLevel: text('probe_level').notNull(),
    sideEffect: text('side_effect').notNull(),
    summary: text('summary').notNull(),
    payloadSummary: text('payload_summary'),
    expectedEvidence: text('expected_evidence').notNull(),
    requestedRequestsPerMinute: integer('requested_requests_per_minute'),
    requestedConcurrency: integer('requested_concurrency'),
    maxRequests: integer('max_requests').notNull(),
    timeoutMs: integer('timeout_ms').notNull(),
    userApproved: integer('user_approved', { mode: 'boolean' }).notNull(),
    stopConditions: text('stop_conditions', { mode: 'json' }).$type<string[]>().notNull(),
    cleanupPlan: text('cleanup_plan'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('probe_proposals_scan_idx').on(table.scanId, table.createdAt)]
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
    normalizedTarget: text('normalized_target'),
    approvedBy: text('approved_by'),
    approvedAt: integer('approved_at'),
    validUntil: integer('valid_until'),
    authorizedWireRequestHmac: text('authorized_wire_request_hmac_json', {
      mode: 'json'
    }).$type<WireRequestHmac>(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('policy_decisions_proposal_idx').on(table.proposalId),
    index('policy_decisions_scope_idx').on(table.scopeSnapshotId)
  ]
)

export const executionGrants = sqliteTable(
  'execution_grants',
  {
    schemaVersion: text('schema_version').$type<'execution-grant.v1'>().notNull(),
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    scopeSnapshotId: text('scope_snapshot_id').notNull(),
    scopeSnapshotHash: text('scope_snapshot_hash').notNull(),
    moduleSnapshotId: text('module_snapshot_id').notNull(),
    moduleSnapshotHash: text('module_snapshot_hash').notNull(),
    moduleId: text('module_id').notNull(),
    moduleVersion: text('module_version').notNull(),
    techniqueId: text('technique_id').notNull(),
    techniqueVersion: text('technique_version').notNull(),
    planId: text('plan_id').notNull(),
    planVersion: text('plan_version').notNull(),
    planHash: text('plan_hash').notNull(),
    stepId: text('step_id').notNull(),
    templateIntentHash: text('template_intent_hash_json', { mode: 'json' })
      .$type<TemplateIntentHash>()
      .notNull(),
    resolvedIntentHash: text('resolved_intent_hash_json', { mode: 'json' })
      .$type<ResolvedIntentHash>()
      .notNull(),
    wireRequestHmac: text('wire_request_hmac_json', { mode: 'json' })
      .$type<WireRequestHmac>()
      .notNull(),
    captureDecisionSetHash: text('capture_decision_set_hash_json', {
      mode: 'json'
    })
      .$type<ExecutionCaptureDecisionSetHash>()
      .notNull(),
    integrityHmac: text('integrity_hmac_json', { mode: 'json' })
      .$type<ExecutionGrantIntegrityHmac>()
      .notNull(),
    capabilityIds: text('capability_ids_json', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    ownerRef: text('owner_ref'),
    identityRef: text('identity_ref_json', { mode: 'json' }).$type<IdentityRef>(),
    credentialRef: text('credential_ref_json', { mode: 'json' }).$type<
      ExecutionCredentialRef
    >(),
    sessionRef: text('session_ref_json', { mode: 'json' })
      .$type<SessionGenerationRef>(),
    testObjectRef: text('test_object_ref_json', { mode: 'json' })
      .$type<TestObjectRef>(),
    budget: text('budget_json', { mode: 'json' })
      .$type<ExecutionGrantBudget>()
      .notNull(),
    purpose: text('purpose').$type<ExecutionPurpose>().notNull(),
    adapterKind: text('adapter_kind').$type<ExecutionAdapterKind>().notNull(),
    retryClass: text('retry_class').$type<ExecutionRetryClass>().notNull(),
    policyDecisionId: text('policy_decision_id').notNull(),
    approvalBundleRef: text('approval_bundle_ref'),
    parentGrantId: text('parent_grant_id'),
    redirectHop: integer('redirect_hop').notNull(),
    validFrom: integer('valid_from').notNull(),
    validUntil: integer('valid_until').notNull(),
    issuedAt: integer('issued_at').notNull()
  },
  (table) => [
    index('execution_grants_scan_idx').on(table.scanId, table.issuedAt),
    index('execution_grants_module_idx').on(table.moduleSnapshotId),
    index('execution_grants_parent_idx').on(table.parentGrantId),
    uniqueIndex('execution_grants_policy_decision_uq').on(table.policyDecisionId)
  ]
)

export const executionCaptureDecisions = sqliteTable(
  'execution_capture_decisions',
  {
    id: text('id').primaryKey(),
    grantId: text('grant_id').notNull(),
    scanId: text('scan_id').notNull(),
    policyDecisionId: text('policy_decision_id').notNull(),
    capturePolicyId: text('capture_policy_id').notNull(),
    capturePolicyVersion: text('capture_policy_version').notNull(),
    techniqueId: text('technique_id').notNull(),
    techniqueVersion: text('technique_version').notNull(),
    stepId: text('step_id').notNull(),
    executionState: text('execution_state')
      .$type<EvidenceCaptureExecutionState>()
      .notNull(),
    source: text('source').$type<EvidenceCaptureSource>().notNull(),
    role: text('role').notNull(),
    action: text('action').$type<EvidenceCaptureAction>().notNull(),
    validFrom: integer('valid_from').notNull(),
    validUntil: integer('valid_until').notNull(),
    maxSourceBytes: integer('max_source_bytes').notNull(),
    maxExcerptBytes: integer('max_excerpt_bytes').notNull(),
    jsonPointers: text('json_pointers_json', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    oobMetadataFields: text('oob_metadata_fields_json', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    oobCommitmentKeyRef: text('oob_commitment_key_ref'),
    oobCommitmentKeyVersion: integer('oob_commitment_key_version'),
    decision: text('decision_json', { mode: 'json' })
      .$type<EvidenceCaptureDecision>()
      .notNull()
  },
  (table) => [
    index('execution_capture_decisions_grant_idx').on(table.grantId),
    uniqueIndex('execution_capture_decisions_grant_source_state_uq').on(
      table.grantId,
      table.source,
      table.executionState
    )
  ]
)

export const executionLeases = sqliteTable(
  'execution_leases',
  {
    schemaVersion: text('schema_version').$type<'execution-lease.v1'>().notNull(),
    id: text('id').primaryKey(),
    grantId: text('grant_id').notNull(),
    parentLeaseId: text('parent_lease_id'),
    attempt: integer('attempt').notNull(),
    state: text('state').$type<ExecutionLeaseState>().notNull(),
    issuedAt: integer('issued_at').notNull(),
    expiresAt: integer('expires_at').notNull(),
    claimedAt: integer('claimed_at'),
    claimedBy: text('claimed_by'),
    claimTokenHash: text('claim_token_hash'),
    deliveryState: text('delivery_state')
      .$type<ExecutionLeaseDeliveryState>()
      .notNull(),
    terminalAt: integer('terminal_at'),
    terminalReason: text('terminal_reason').$type<ExecutionLeaseTerminalReason>(),
    outcomeSummary: text('outcome_summary_json', { mode: 'json' })
      .$type<ExecutionLeaseOutcomeSummary>(),
    evidenceRefs: text('evidence_refs_json', { mode: 'json' })
      .$type<string[]>()
      .notNull()
  },
  (table) => [
    uniqueIndex('execution_leases_grant_attempt_uq').on(table.grantId, table.attempt),
    index('execution_leases_grant_idx').on(table.grantId),
    index('execution_leases_state_expiry_idx').on(table.state, table.expiresAt),
    index('execution_leases_parent_idx').on(table.parentLeaseId)
  ]
)

export const toolCalls = sqliteTable(
  'tool_calls',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    policyDecisionId: text('policy_decision_id').notNull(),
    executionLeaseId: text('execution_lease_id'),
    toolName: text('tool_name').notNull(),
    toolVersion: text('tool_version').notNull(),
    argumentHash: text('argument_hash').notNull(),
    status: text('status').notNull(),
    durationMs: integer('duration_ms'),
    outputRef: text('output_ref'),
    error: text('error'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('tool_calls_scan_idx').on(table.scanId, table.createdAt),
    uniqueIndex('tool_calls_execution_lease_uq').on(table.executionLeaseId)
  ]
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
    confidenceHint: integer('confidence_hint').notNull(),
    evidenceRefs: text('evidence_refs', { mode: 'json' }).$type<string[]>().notNull(),
    status: text('status').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('signals_scan_family_idx').on(table.scanId, table.family)]
)

export const confirmationRules = sqliteTable(
  'confirmation_rules',
  {
    id: text('id').notNull(),
    version: text('version').notNull(),
    family: text('family').notNull(),
    ruleJson: text('rule_json', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
    requiredChecks: text('required_checks', { mode: 'json' }).$type<string[]>().notNull(),
    sourceRefs: text('source_refs', { mode: 'json' }).$type<string[]>().notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [primaryKey({ columns: [table.id, table.version] })]
)

export const validationRuns = sqliteTable(
  'validation_runs',
  {
    id: text('id').primaryKey(),
    signalId: text('signal_id').notNull(),
    confirmationRuleId: text('confirmation_rule_id').notNull(),
    confirmationRuleVersion: text('confirmation_rule_version').notNull(),
    probeProposalId: text('probe_proposal_id').notNull(),
    policyDecisionId: text('policy_decision_id').notNull(),
    toolCallId: text('tool_call_id'),
    baselineRef: text('baseline_ref').notNull(),
    testRef: text('test_ref').notNull(),
    negativeControlRef: text('negative_control_ref'),
    completedChecks: text('completed_checks', { mode: 'json' }).$type<string[]>().notNull(),
    failedChecks: text('failed_checks', { mode: 'json' }).$type<string[]>().notNull(),
    missingChecks: text('missing_checks', { mode: 'json' }).$type<string[]>().notNull(),
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
    workspaceId: text('workspace_id').notNull(),
    scanId: text('scan_id').notNull(),
    interactionId: text('interaction_id'),
    policyDecisionId: text('policy_decision_id'),
    type: text('type').notNull(),
    mimeType: text('mime_type').notNull(),
    filePath: text('file_path').notNull(),
    sha256: text('sha256').notNull(),
    size: integer('size').notNull(),
    source: text('source').notNull(),
    createdBy: text('created_by').notNull(),
    captureTool: text('capture_tool').notNull(),
    captureToolVersion: text('capture_tool_version').notNull(),
    derivedFrom: text('derived_from'),
    redactionState: text('redaction_state').notNull(),
    integrityStatus: text('integrity_status').notNull(),
    retentionUntil: integer('retention_until'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('evidence_items_scan_idx').on(table.scanId, table.createdAt),
    index('evidence_items_scan_type_hash_idx').on(
      table.scanId,
      table.type,
      table.sha256
    )
  ]
)

export const protectedEvidenceItems = sqliteTable(
  'protected_evidence_items',
  {
    evidenceId: text('evidence_id').primaryKey(),
    schemaVersion: text('schema_version')
      .$type<'protected-evidence-storage.v1'>()
      .notNull(),
    captureDecisionId: text('capture_decision_id').notNull(),
    evidenceRole: text('evidence_role').notNull(),
    derivativeEvidenceId: text('derivative_evidence_id').notNull(),
    derivativeSha256: text('derivative_sha256').notNull(),
    captureArtifact: text('capture_artifact_json', { mode: 'json' })
      .$type<Record<string, unknown>>()
      .notNull(),
    sourceHash: text('source_hash_json', { mode: 'json' })
      .$type<EvidenceSourceHash>()
      .notNull(),
    protectionPlan: text('protection_plan_json', { mode: 'json' })
      .$type<Record<string, unknown>>()
      .notNull(),
    originalMimeType: text('original_mime_type').notNull(),
    plaintextSha256: text('plaintext_sha256').notNull(),
    plaintextSize: integer('plaintext_size').notNull(),
    storageSha256: text('storage_sha256').notNull(),
    storageSize: integer('storage_size').notNull(),
    encryptionAlgorithm: text('encryption_algorithm')
      .$type<'aes-256-gcm+os-key-wrap'>()
      .notNull(),
    wrappedDataKey: text('wrapped_data_key'),
    nonce: text('nonce'),
    authTag: text('auth_tag'),
    availabilityState: text('availability_state')
      .$type<'available' | 'expired'>()
      .notNull(),
    retentionUntil: integer('retention_until').notNull(),
    expiredAt: integer('expired_at'),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('protected_evidence_retention_idx').on(
      table.availabilityState,
      table.retentionUntil
    ),
    uniqueIndex('protected_evidence_capture_decision_uq').on(
      table.captureDecisionId
    ),
    uniqueIndex('protected_evidence_derivative_uq').on(
      table.derivativeEvidenceId
    )
  ]
)

export const executionLeaseEvidence = sqliteTable(
  'execution_lease_evidence',
  {
    leaseId: text('lease_id').notNull(),
    evidenceId: text('evidence_id').notNull(),
    captureDecisionId: text('capture_decision_id').notNull(),
    role: text('role').notNull(),
    ordinal: integer('ordinal').notNull()
  },
  (table) => [
    primaryKey({ columns: [table.leaseId, table.captureDecisionId] }),
    uniqueIndex('execution_lease_evidence_evidence_uq').on(table.evidenceId),
    uniqueIndex('execution_lease_evidence_ordinal_uq').on(
      table.leaseId,
      table.role,
      table.ordinal
    ),
    index('execution_lease_evidence_evidence_idx').on(table.evidenceId)
  ]
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
    confidence: integer('confidence').notNull(),
    endpointId: text('endpoint_id'),
    parameterId: text('parameter_id'),
    identityId: text('identity_id'),
    affectedResource: text('affected_resource'),
    cwe: text('cwe'),
    owasp: text('owasp'),
    confirmationRuleId: text('confirmation_rule_id').notNull(),
    confirmationRuleVersion: text('confirmation_rule_version').notNull(),
    reproducibility: text('reproducibility').notNull(),
    remediationJson: text('remediation_json', { mode: 'json' }).$type<string[]>().notNull(),
    firstSeenAt: integer('first_seen_at').notNull(),
    lastVerifiedAt: integer('last_verified_at').notNull()
  },
  (table) => [
    index('findings_scan_idx').on(table.scanId),
    index('findings_family_idx').on(table.family),
    index('findings_verdict_idx').on(table.verdict)
  ]
)

export const findingEvidence = sqliteTable(
  'finding_evidence',
  {
    findingId: text('finding_id').notNull(),
    evidenceId: text('evidence_id').notNull()
  },
  (table) => [primaryKey({ columns: [table.findingId, table.evidenceId] })]
)

export const knowledgeDocs = sqliteTable('knowledge_docs', {
  id: text('id').primaryKey(),
  title: text('title').notNull(),
  sourceType: text('source_type').notNull(),
  sourceUrl: text('source_url'),
  author: text('author'),
  license: text('license'),
  trustLevel: text('trust_level').notNull(),
  reviewStatus: text('review_status').notNull(),
  sha256: text('sha256').notNull(),
  publishedAt: integer('published_at'),
  ingestedAt: integer('ingested_at').notNull()
})

export const knowledgeChunks = sqliteTable(
  'knowledge_chunks',
  {
    id: text('id').primaryKey(),
    docId: text('doc_id').notNull(),
    family: text('family'),
    title: text('title').notNull(),
    content: text('content').notNull(),
    tags: text('tags', { mode: 'json' }).$type<string[]>().notNull(),
    applicability: text('applicability', { mode: 'json' }).$type<string[]>().notNull(),
    tokenEstimate: integer('token_estimate').notNull(),
    contentHash: text('content_hash').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [
    index('knowledge_chunks_doc_idx').on(table.docId),
    index('knowledge_chunks_family_idx').on(table.family)
  ]
)

export const knowledgeImports = sqliteTable(
  'knowledge_imports',
  {
    id: text('id').primaryKey(),
    documentId: text('document_id').notNull(),
    sourceType: text('source_type').$type<KnowledgeSourceType>().notNull(),
    rawContent: text('raw_content').notNull(),
    rawContentSha256: text('raw_content_sha256').notNull(),
    vendorHint: text('vendor_hint'),
    productHint: text('product_hint'),
    instructionFlags: text('instruction_flags', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    status: text('status').$type<KnowledgeImportStatus>().notNull(),
    extractorProfileId: text('extractor_profile_id'),
    reviewerProfileId: text('reviewer_profile_id'),
    reviewIssues: text('review_issues', { mode: 'json' })
      .$type<KnowledgeReviewIssue[]>()
      .notNull(),
    lastError: text('last_error'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    uniqueIndex('knowledge_imports_document_uq').on(table.documentId),
    index('knowledge_imports_status_idx').on(table.status, table.updatedAt)
  ]
)

export const knowledgeIntelligence = sqliteTable(
  'knowledge_intelligence',
  {
    id: text('id').primaryKey(),
    importId: text('import_id').notNull(),
    schemaVersion: text('schema_version').notNull(),
    title: text('title').notNull(),
    vendor: text('vendor').notNull(),
    product: text('product').notNull(),
    vulnerabilityType: text('vulnerability_type').notNull(),
    family: text('family').$type<VulnerabilityFamily>(),
    identifiers: text('identifiers_json', { mode: 'json' })
      .$type<{ cve: string[]; cwe: string[]; other: string[] }>()
      .notNull(),
    affectedVersions: text('affected_versions', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    preconditions: text('preconditions', { mode: 'json' }).$type<string[]>().notNull(),
    affectedEndpoints: text('affected_endpoints', { mode: 'json' })
      .$type<KnowledgeHttpRequestTemplate[]>()
      .notNull(),
    signals: text('signals', { mode: 'json' }).$type<string[]>().notNull(),
    confirmationRules: text('confirmation_rules', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    remediation: text('remediation', { mode: 'json' }).$type<string[]>().notNull(),
    forbiddenActions: text('forbidden_actions', { mode: 'json' })
      .$type<string[]>()
      .notNull(),
    fieldEvidence: text('field_evidence', { mode: 'json' })
      .$type<KnowledgeFieldEvidence[]>()
      .notNull(),
    extractionConfidence: integer('extraction_confidence').notNull(),
    publishedChunkId: text('published_chunk_id'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    uniqueIndex('knowledge_intelligence_import_uq').on(table.importId),
    index('knowledge_intelligence_product_idx').on(table.vendor, table.product),
    index('knowledge_intelligence_family_idx').on(table.family)
  ]
)

export const knowledgeAgentRuns = sqliteTable(
  'knowledge_agent_runs',
  {
    id: text('id').primaryKey(),
    importId: text('import_id').notNull(),
    parentRunId: text('parent_run_id'),
    role: text('role').notNull(),
    promptId: text('prompt_id').notNull(),
    promptVersion: text('prompt_version').notNull(),
    promptHash: text('prompt_hash').notNull(),
    modelProfileId: text('model_profile_id').notNull(),
    provider: text('provider'),
    model: text('model'),
    status: text('status').notNull(),
    inputHash: text('input_hash').notNull(),
    outputHash: text('output_hash'),
    promptTokens: integer('prompt_tokens').notNull(),
    completionTokens: integer('completion_tokens').notNull(),
    durationMs: integer('duration_ms').notNull(),
    error: text('error'),
    startedAt: integer('started_at').notNull(),
    finishedAt: integer('finished_at')
  },
  (table) => [index('knowledge_agent_runs_import_idx').on(table.importId, table.startedAt)]
)

export const reports = sqliteTable(
  'reports',
  {
    id: text('id').primaryKey(),
    scanId: text('scan_id').notNull(),
    title: text('title').notNull(),
    format: text('format').notNull(),
    filePath: text('file_path'),
    sha256: text('sha256').notNull(),
    redacted: integer('redacted', { mode: 'boolean' }).notNull(),
    contentRef: text('content_ref').notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('reports_scan_idx').on(table.scanId, table.createdAt)]
)

export const modelProfiles = sqliteTable(
  'model_profiles',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    agentRole: text('agent_role').notNull(),
    provider: text('provider').notNull(),
    baseUrl: text('base_url'),
    model: text('model').notNull(),
    credentialId: text('credential_id'),
    timeoutMs: integer('timeout_ms').notNull(),
    rpmLimit: integer('rpm_limit').notNull(),
    tpmLimit: integer('tpm_limit').notNull(),
    tokenBudget: integer('token_budget').notNull(),
    costBudgetMicros: integer('cost_budget_micros').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    index('model_profiles_role_idx').on(table.agentRole),
    uniqueIndex('model_profiles_name_uq').on(table.name)
  ]
)

export const mcpServers = sqliteTable(
  'mcp_servers',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    transport: text('transport').$type<McpTransport>().notNull(),
    enabled: integer('enabled', { mode: 'boolean' }).notNull(),
    credentialId: text('credential_id'),
    configJson: text('config_json', { mode: 'json' })
      .$type<McpServerConfiguration>()
      .notNull(),
    allowedAgentRoles: text('allowed_agent_roles', { mode: 'json' })
      .$type<AgentRole[]>()
      .notNull(),
    riskLabels: text('risk_labels', { mode: 'json' })
      .$type<McpRiskLabel[]>()
      .notNull(),
    status: text('status').$type<McpServerStatus>().notNull(),
    discoveryJson: text('discovery_json', { mode: 'json' })
      .$type<McpServerDiscovery>()
      .notNull(),
    lastTestedAt: integer('last_tested_at'),
    lastError: text('last_error'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [
    uniqueIndex('mcp_servers_name_uq').on(table.name),
    index('mcp_servers_status_idx').on(table.status, table.updatedAt)
  ]
)

export const appSettings = sqliteTable('app_settings', {
  key: text('key').primaryKey(),
  valueJson: text('value_json', { mode: 'json' }).$type<unknown>().notNull(),
  updatedAt: integer('updated_at').notNull()
})

export const benchmarkCases = sqliteTable(
  'benchmark_cases',
  {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    targetVersion: text('target_version').notNull(),
    family: text('family').notNull(),
    expectedVerdict: text('expected_verdict').notNull(),
    endpoint: text('endpoint').notNull(),
    parameter: text('parameter'),
    identityPlanJson: text('identity_plan_json', { mode: 'json' })
      .$type<Record<string, unknown>>()
      .notNull(),
    requiredEvidence: text('required_evidence', { mode: 'json' }).$type<string[]>().notNull(),
    resetProcedure: text('reset_procedure').notNull(),
    forbiddenActions: text('forbidden_actions', { mode: 'json' }).$type<string[]>().notNull(),
    source: text('source').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull()
  },
  (table) => [index('benchmark_cases_family_idx').on(table.family)]
)

export const benchmarkRuns = sqliteTable(
  'benchmark_runs',
  {
    id: text('id').primaryKey(),
    caseId: text('case_id').notNull(),
    scanId: text('scan_id').notNull(),
    expectedVerdict: text('expected_verdict').notNull(),
    actualVerdict: text('actual_verdict').notNull(),
    metricsJson: text('metrics_json', { mode: 'json' }).$type<Record<string, number>>().notNull(),
    createdAt: integer('created_at').notNull()
  },
  (table) => [index('benchmark_runs_case_idx').on(table.caseId, table.createdAt)]
)

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
  (table) => [index('audit_logs_workspace_idx').on(table.workspaceId, table.createdAt)]
)
