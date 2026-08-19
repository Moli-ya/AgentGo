import { createHash, randomUUID } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { resolve } from 'node:path'
import { URL } from 'node:url'
import {
  and,
  asc,
  desc,
  eq,
  inArray,
  sql,
  type SQL
} from 'drizzle-orm'
import type {
  AllowedHeaderDescriptor,
  AuditLogRecord,
  AgentRole,
  BodyEncoding,
  CreateKnowledgeImportInput,
  CreateScanInput,
  CreateTargetInput,
  CreateWorkspaceInput,
  DashboardSnapshot,
  ExecutionClaimBinding,
  ExecutionCaptureDecisionSet,
  ExecutionGrant,
  ExecutionLease,
  FindingRecord,
  IdentityRecord,
  InventoryBodyShape,
  InventoryEndpoint,
  InventoryEndpointRecord,
  InventoryExecutionClass,
  InventoryReviewStatus,
  InventorySourceRecord,
  KnowledgeAgentRunRecord,
  KnowledgeImportDetail,
  KnowledgeImportStatus,
  KnowledgeImportSummary,
  KnowledgeIntelligenceCandidate,
  KnowledgeReviewIssue,
  McpConnectionTestResult,
  McpServerRecord,
  ModelProfileRecord,
  ModelProfileUsageRecord,
  PolicyDecision,
  ProbeAction,
  ReportRecord,
  RequestVariantRecord,
  SaveModelProfileInput,
  SaveIdentityInput,
  ScanEvent,
  ScanModuleSnapshotDraft,
  ScanModuleSnapshotRecord,
  ScanRecord,
  SelectorRef,
  TargetRecord,
  TargetScope,
  TargetScopeRecord,
  UpdateTargetInput,
  RedactedInventoryPreview,
  TransportKind,
  UpsertInventoryResult,
  VersionedDefinitionRef,
  WireRequestHmac,
  WorkspaceRecord
} from '@agentgo/contracts'
import {
  InventoryEndpointRecordSchema,
  InventorySourceRecordSchema,
  RequestVariantRecordSchema,
  SelectorRefSchema,
  TargetBaseUrlSchema,
  WireRequestHmacSchema
} from '@agentgo/contracts'
import {
  INVENTORY_REDACTION_MARKER,
  redactInventoryText,
  redactInventoryUrlPreview,
  stableInventoryHash
} from '@agentgo/domain'
import type { AgentGoDatabase } from './database'
import {
  ExecutionLeaseRepository,
  type ClaimedExecutionLease,
  type ExecutionGrantIntegrityKey,
  type ExecutionLeaseEvidenceLink,
  type FinalizeExecutionLeaseInput,
  type InterruptedExecutionRecoveryContext,
  type InterruptedExecutionRecoveryResult,
  type InterruptedExecutionScanRecoveryContext,
  type IssueExecutionGrantInput,
  type RecordExecutionInteractionAuditInput,
  type RecoverInterruptedExecutionLeaseInput,
  type RecoverInterruptedExecutionLeaseWithCleanupInput,
  type RecoverInterruptedExecutionLeaseWithEvidenceInput
} from './execution-repository'
import {
  agentRuns,
  auditLogs,
  confirmationRules,
  endpoints,
  evidenceItems,
  findingEvidence,
  findings,
  identities,
  inventorySources,
  interactions,
  knowledgeAgentRuns,
  knowledgeChunks,
  knowledgeDocs,
  knowledgeImports,
  knowledgeIntelligence,
  modelInvocations,
  modelProfileUsageEvents,
  modelProfiles,
  mcpServers,
  pages,
  parameters,
  policyDecisions,
  probeProposals,
  protectedEvidenceItems,
  reports,
  requestVariantSelectors,
  requestVariants,
  scanCheckpoints,
  scanEvents,
  scanIdentities,
  scanModuleSnapshots,
  scans,
  signals,
  targetScopes,
  targets,
  toolCalls,
  validationRuns,
  workspaces,
  type ScanConfiguration
} from './schema'

type WorkspaceRow = typeof workspaces.$inferSelect
type TargetRow = typeof targets.$inferSelect
type TargetScopeRow = typeof targetScopes.$inferSelect
type IdentityRow = typeof identities.$inferSelect
type KnowledgeImportRow = typeof knowledgeImports.$inferSelect
type KnowledgeDocumentRow = typeof knowledgeDocs.$inferSelect
type KnowledgeIntelligenceRow = typeof knowledgeIntelligence.$inferSelect
type ScanRow = typeof scans.$inferSelect
type ScanEventRow = typeof scanEvents.$inferSelect
type AuditRow = typeof auditLogs.$inferSelect
type CreatePersistedScanInput = Omit<CreateScanInput, 'families'> & {
  families: ScanConfiguration['families']
}

// node:sqlite is synchronous; serialize same-process writers so one connection
// cannot block the event loop while another connection is waiting to commit.
const scopeSnapshotTails = new Map<string, Promise<void>>()
const inventoryWriteTails = new Map<string, Promise<void>>()

function scopeSnapshotLockKey(filePath: string): string {
  if (filePath === ':memory:') return filePath
  const absolutePath = resolve(filePath)
  const canonicalPath = realpathSync.native(absolutePath)
  return process.platform === 'win32' ? canonicalPath.toLowerCase() : canonicalPath
}

export interface InventoryPageRecord {
  id: string
  scanId: string
  url: string
  title?: string
  depth: number
  discoveredFrom?: string
  status: string
  createdAt: string
  updatedAt: string
}

export interface PreparedInventorySelector {
  readonly selector: SelectorRef
  readonly structureHash: string
}

/**
 * Internal persistence shape produced only by Application's InventoryService.
 * Producer-owned inputs deliberately cannot supply review or execution state.
 */
export interface PreparedInventoryWrite {
  readonly scanId: string
  readonly pageId?: string
  readonly method: string
  readonly canonicalRoute: string
  readonly compatibilityUrl: string
  readonly contentType?: string
  readonly bodyShape: InventoryBodyShape
  readonly codec: BodyEncoding
  readonly transport: TransportKind
  readonly allowedHeaders: readonly AllowedHeaderDescriptor[]
  readonly templateVersion: string
  readonly requiredCapabilityIds: readonly string[]
  readonly redactedPreview: RedactedInventoryPreview
  readonly executionClass: InventoryExecutionClass
  readonly structureHash: string
  readonly selectors: readonly PreparedInventorySelector[]
  readonly source: {
    readonly type: string
    readonly sourceHash: string
    readonly provenanceHash: string
    readonly pageId?: string
    readonly evidenceRef?: string
    readonly initiator?: string
    readonly confidencePpm: number
  }
}

const PREPARED_INVENTORY_RECORD_ID = 'prepared-inventory-validation'
const PREPARED_INVENTORY_TIMESTAMP = '1970-01-01T00:00:00.000Z'

/** Validate every derived persistence field before the transaction can mutate state. */
function validatePreparedInventoryWrite(input: PreparedInventoryWrite): void {
  if (input.compatibilityUrl !== input.redactedPreview.url) {
    throw new TypeError('Inventory compatibility URL must equal its redacted preview URL.')
  }
  if (
    input.pageId !== undefined &&
    input.source.pageId !== undefined &&
    input.pageId !== input.source.pageId
  ) {
    throw new TypeError('Inventory endpoint and source page IDs must match.')
  }

  InventoryEndpointRecordSchema.parse({
    id: PREPARED_INVENTORY_RECORD_ID,
    scanId: input.scanId,
    ...(input.pageId ? { pageId: input.pageId } : {}),
    method: input.method,
    canonicalRoute: input.canonicalRoute,
    lifecycleStatus: 'active',
    createdAt: PREPARED_INVENTORY_TIMESTAMP,
    updatedAt: PREPARED_INVENTORY_TIMESTAMP
  })
  RequestVariantRecordSchema.parse({
    id: PREPARED_INVENTORY_RECORD_ID,
    scanId: input.scanId,
    endpointId: PREPARED_INVENTORY_RECORD_ID,
    ...(input.contentType ? { contentType: input.contentType } : {}),
    bodyShape: input.bodyShape,
    codec: input.codec,
    transport: input.transport,
    allowedHeaders: input.allowedHeaders,
    templateVersion: input.templateVersion,
    requiredCapabilityIds: input.requiredCapabilityIds,
    selectors: input.selectors.map(({ selector }) => selector),
    redactedPreview: input.redactedPreview,
    reviewStatus: 'unreviewed',
    executionClass: input.executionClass,
    lifecycleStatus: 'active',
    structureHash: input.structureHash,
    createdAt: PREPARED_INVENTORY_TIMESTAMP,
    updatedAt: PREPARED_INVENTORY_TIMESTAMP
  })
  InventorySourceRecordSchema.parse({
    id: PREPARED_INVENTORY_RECORD_ID,
    scanId: input.scanId,
    endpointId: PREPARED_INVENTORY_RECORD_ID,
    requestVariantId: PREPARED_INVENTORY_RECORD_ID,
    type: input.source.type,
    sourceHash: input.source.sourceHash,
    provenanceHash: input.source.provenanceHash,
    ...(input.source.pageId ? { pageId: input.source.pageId } : {}),
    ...(input.source.evidenceRef
      ? { evidenceRef: input.source.evidenceRef }
      : {}),
    ...(input.source.initiator ? { initiator: input.source.initiator } : {}),
    confidencePpm: input.source.confidencePpm,
    discoveredAt: PREPARED_INVENTORY_TIMESTAMP,
    reviewStatus: 'unreviewed',
    createdAt: PREPARED_INVENTORY_TIMESTAMP
  })

  const selectors = input.selectors.map(({ selector }) => selector)
  const expectedStructureHash = stableInventoryHash({
    contentType: input.contentType ?? null,
    bodyShape: input.bodyShape,
    codec: input.codec,
    transport: input.transport,
    allowedHeaders: input.allowedHeaders,
    templateVersion: input.templateVersion,
    requiredCapabilityIds: input.requiredCapabilityIds,
    selectors
  })
  if (input.structureHash !== expectedStructureHash) {
    throw new TypeError('Inventory structure hash does not match its derived fields.')
  }
  for (const { selector, structureHash } of input.selectors) {
    if (structureHash !== stableInventoryHash(selector)) {
      throw new TypeError('Inventory selector hash does not match its selector.')
    }
  }
  const expectedProvenanceHash = stableInventoryHash({
    scanId: input.scanId,
    method: input.method,
    canonicalRoute: input.canonicalRoute,
    structureHash: input.structureHash,
    type: input.source.type,
    sourceHash: input.source.sourceHash,
    pageId: input.source.pageId ?? null,
    evidenceRef: input.source.evidenceRef ?? null,
    initiator: input.source.initiator ?? null
  })
  if (input.source.provenanceHash !== expectedProvenanceHash) {
    throw new TypeError('Inventory provenance hash does not match its derived fields.')
  }
}

export interface PreparedScanModuleSnapshot {
  readonly draft: ScanModuleSnapshotDraft
  readonly snapshotHash: string
}

export interface KnowledgeIndexEntryInput {
  id: string
  family: string
  title: string
  content: string
  tags: string[]
  applicability: string[]
  sourceUrl?: string
  license?: string
}

export interface PublishedKnowledgeEntryRecord {
  chunkId: string
  candidate: KnowledgeIntelligenceCandidate
  sourceTitle: string
  sourceType: string
}

export interface StoredSignalRecord {
  id: string
  scanId: string
  interactionId?: string
  family: FindingRecord['family']
  endpointId: string
  parameterId?: string
  identityId?: string
  hypothesis: string
  observedDifference: string
  confidenceHint: number
  evidenceRefs: string[]
  status: string
  createdAt: string
}

export interface StoredValidationRun {
  id: string
  signalId: string
  confirmationRuleId: string
  confirmationRuleVersion: string
  probeProposalId: string
  policyDecisionId: string
  toolCallId?: string
  baselineRef: string
  testRef: string
  negativeControlRef?: string
  completedChecks: string[]
  failedChecks: string[]
  missingChecks: string[]
  cleanupStatus: 'not-needed' | 'completed' | 'failed'
  result: FindingRecord['verdict']
  createdAt: string
}

export interface StoredReportRecord extends ReportRecord {
  contentRef: string
}

export interface AgentRunRecord {
  id: string
  scanId: string
  role: AgentRole
  promptId: string
  promptVersion: string
  promptHash: string
  modelProfileId: string
  status: string
  inputRefs: string[]
  outputRefs: string[]
  startedAt: string
  finishedAt?: string
  error?: string
}

export interface ProbeProposalRecord {
  id: string
  scanId: string
  agentRunId: string
  action: ProbeAction
  stopConditions: string[]
  createdAt: string
}

export {
  executionClaimBindingForGrant,
  executionGrantIntegrityBindingForGrant,
  hashExecutionCaptureDecisionSet,
  signExecutionGrantIntegrity,
  verifyExecutionCaptureDecisionSetHash,
  verifyExecutionGrantIntegrity
} from './execution-repository'

export type {
  ClaimedExecutionLease,
  ExecutionGrantIntegrityKey,
  ExecutionLeaseEvidenceLink,
  FinalizeExecutionLeaseInput,
  InterruptedExecutionRecoveryContext,
  InterruptedExecutionRecoveryResult,
  InterruptedExecutionScanRecoveryContext,
  IssueExecutionGrantInput,
  RecordExecutionInteractionAuditInput,
  RecoverInterruptedExecutionLeaseInput,
  RecoverInterruptedExecutionLeaseWithCleanupInput,
  RecoverInterruptedExecutionLeaseWithEvidenceInput
} from './execution-repository'

export interface StoredPolicyDecision extends PolicyDecision {
  id: string
  proposalId: string
  scopeSnapshotId: string
  approvedBy?: string
  approvedAt?: string
  validUntil?: string
  authorizedWireRequestHmac?: WireRequestHmac
  createdAt: string
}

export interface LegacyV1ExecutionBinding {
  endpoint: InventoryEndpoint
  endpointRecord: InventoryEndpointRecord
  requestVariant: RequestVariantRecord
}

export interface ExecutionDecisionContext {
  decision: StoredPolicyDecision
  proposal: ProbeProposalRecord
  scope: TargetScopeRecord
  scanStatus: ScanRecord['status']
  scanBudget: ScanRecord['budget']
  requestCount: number
  scanId: string
  targetId: string
  workspaceId: string
}

function toIso(value: number): string {
  return new Date(value).toISOString()
}

function optionalIso(value: number | null): string | undefined {
  return value === null ? undefined : toIso(value)
}

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableValue)
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => compareBinary(left, right))
        .map(([key, nested]) => [key, stableValue(nested)])
    )
  }

  return value
}

export function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value))
}

export function sha256Text(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function mapWorkspace(row: WorkspaceRow): WorkspaceRecord {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapTarget(row: TargetRow): TargetRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    name: row.name,
    baseUrl: row.baseUrl,
    description: row.description,
    authorizationReference: row.authorizationReference,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapScope(row: TargetScopeRow): TargetScopeRecord {
  return {
    id: row.id,
    targetId: row.targetId,
    revision: row.revision,
    allowedOrigins: row.allowedOrigins,
    allowedPathPrefixes: row.allowedPathPrefixes,
    deniedPathPrefixes: row.deniedPathPrefixes,
    allowedPorts: row.allowedPorts,
    allowedIdentityIds: row.allowedIdentityIds,
    allowActiveProbing: row.allowActiveProbing,
    allowSensitiveProbing: row.allowSensitiveProbing,
    allowPrivateNetworkTargets: row.allowPrivateNetworkTargets,
    allowLoopbackTargets: row.allowLoopbackTargets,
    maxRequestsPerMinute: row.maxRequestsPerMinute,
    maxConcurrency: row.maxConcurrency,
    ...(row.authorizationReference
      ? { authorizationReference: row.authorizationReference }
      : {}),
    ...(row.validFrom !== null ? { validFrom: toIso(row.validFrom) } : {}),
    ...(row.validUntil !== null ? { validUntil: toIso(row.validUntil) } : {}),
    snapshotHash: row.snapshotHash,
    createdAt: toIso(row.createdAt)
  }
}

function mapIdentity(row: IdentityRow): IdentityRecord {
  return {
    id: row.id,
    targetId: row.targetId,
    label: row.label,
    role: row.role,
    authType: row.authType as IdentityRecord['authType'],
    ...(row.headerName ? { headerName: row.headerName } : {}),
    ...(row.credentialId ? { credentialId: row.credentialId } : {}),
    isTestIdentity: row.isTestIdentity,
    ownedResourceIds: row.ownedResourceIds,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapScan(row: ScanRow, targetName: string): ScanRecord {
  return {
    id: row.id,
    targetId: row.targetId,
    targetName,
    name: row.name,
    description: row.configJson.description ?? '',
    scopeSnapshotId: row.scopeSnapshotId,
    status: row.status as ScanRecord['status'],
    phase: row.phase as ScanRecord['phase'],
    progress: row.progress,
    families: row.configJson.families,
    modelProfileIds: row.configJson.modelProfileIds ?? {},
    budget: row.budgetJson,
    requestCount: row.requestCount,
    modelTokens: row.modelTokens,
    estimatedCost: row.estimatedCostMicros / 1_000_000,
    checkpointCount: row.checkpointCount,
    ...(row.lastError ? { lastError: row.lastError } : {}),
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt),
    ...(optionalIso(row.startedAt) ? { startedAt: optionalIso(row.startedAt) } : {}),
    ...(optionalIso(row.completedAt)
      ? { completedAt: optionalIso(row.completedAt) }
      : {})
  }
}

function mapEvent(row: ScanEventRow): ScanEvent {
  return {
    id: row.id,
    scanId: row.scanId,
    type: row.type as ScanEvent['type'],
    level: row.level as ScanEvent['level'],
    message: row.message,
    detail: row.detailJson,
    createdAt: toIso(row.createdAt)
  }
}

function mapAudit(row: AuditRow): AuditLogRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    ...(row.scanId ? { scanId: row.scanId } : {}),
    event: row.event,
    actor: row.actor,
    detail: row.detailJson,
    createdAt: toIso(row.createdAt)
  }
}

function mapKnowledgeCandidate(
  row: KnowledgeIntelligenceRow
): KnowledgeIntelligenceCandidate {
  return {
    schemaVersion: 'vulnerability-intel.v1',
    title: row.title,
    vendor: row.vendor,
    product: row.product,
    vulnerabilityType: row.vulnerabilityType,
    ...(row.family ? { family: row.family } : {}),
    identifiers: row.identifiers,
    affectedVersions: row.affectedVersions,
    preconditions: row.preconditions,
    affectedEndpoints: row.affectedEndpoints,
    signals: row.signals,
    confirmationRules: row.confirmationRules,
    remediation: row.remediation,
    forbiddenActions: row.forbiddenActions,
    fieldEvidence: row.fieldEvidence,
    extractionConfidence: row.extractionConfidence / 10_000
  }
}

function mapKnowledgeImportSummary(
  row: KnowledgeImportRow,
  document: KnowledgeDocumentRow,
  intelligence?: KnowledgeIntelligenceRow
): KnowledgeImportSummary {
  return {
    id: row.id,
    documentId: row.documentId,
    sourceType: row.sourceType,
    title: document.title,
    ...(document.sourceUrl ? { sourceUrl: document.sourceUrl } : {}),
    ...(document.author ? { author: document.author } : {}),
    ...(document.license ? { license: document.license } : {}),
    status: row.status,
    instructionFlags: row.instructionFlags,
    rawContentSha256: row.rawContentSha256,
    sourceExcerpt: row.rawContent.slice(0, 1_200),
    ...(row.extractorProfileId ? { extractorProfileId: row.extractorProfileId } : {}),
    ...(row.reviewerProfileId ? { reviewerProfileId: row.reviewerProfileId } : {}),
    reviewIssues: row.reviewIssues,
    ...(intelligence ? { candidate: mapKnowledgeCandidate(intelligence) } : {}),
    ...(row.lastError ? { lastError: row.lastError } : {}),
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapKnowledgeAgentRun(
  row: typeof knowledgeAgentRuns.$inferSelect
): KnowledgeAgentRunRecord {
  return {
    id: row.id,
    importId: row.importId,
    ...(row.parentRunId ? { parentRunId: row.parentRunId } : {}),
    role: row.role as KnowledgeAgentRunRecord['role'],
    promptId: row.promptId,
    promptVersion: row.promptVersion,
    modelProfileId: row.modelProfileId,
    ...(row.provider ? { provider: row.provider } : {}),
    ...(row.model ? { model: row.model } : {}),
    status: row.status as KnowledgeAgentRunRecord['status'],
    promptTokens: row.promptTokens,
    completionTokens: row.completionTokens,
    durationMs: row.durationMs,
    ...(row.error ? { error: row.error } : {}),
    startedAt: toIso(row.startedAt),
    ...(row.finishedAt !== null ? { finishedAt: toIso(row.finishedAt) } : {})
  }
}

function mapAgentRun(row: typeof agentRuns.$inferSelect): AgentRunRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    role: row.role as AgentRole,
    promptId: row.promptId,
    promptVersion: row.promptVersion,
    promptHash: row.promptHash,
    modelProfileId: row.modelProfileId,
    status: row.status,
    inputRefs: row.inputRefs,
    outputRefs: row.outputRefs,
    startedAt: toIso(row.startedAt),
    ...(row.finishedAt !== null ? { finishedAt: toIso(row.finishedAt) } : {}),
    ...(row.error ? { error: row.error } : {})
  }
}

function mapProposal(row: typeof probeProposals.$inferSelect): ProbeProposalRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    agentRunId: row.agentRunId,
    action: {
      id: row.id,
      kind: row.kind as ProbeAction['kind'],
      targetUrl: row.targetUrl,
      method: row.method,
      ...(row.identityId ? { identityId: row.identityId } : {}),
      probeLevel: row.probeLevel as ProbeAction['probeLevel'],
      sideEffect: row.sideEffect as ProbeAction['sideEffect'],
      summary: row.summary,
      ...(row.payloadSummary ? { payloadSummary: row.payloadSummary } : {}),
      expectedEvidence: row.expectedEvidence,
      ...(row.cleanupPlan ? { cleanupPlan: row.cleanupPlan } : {}),
      ...(row.requestedRequestsPerMinute !== null
        ? { requestedRequestsPerMinute: row.requestedRequestsPerMinute }
        : {}),
      ...(row.requestedConcurrency !== null
        ? { requestedConcurrency: row.requestedConcurrency }
        : {}),
      maxRequests: row.maxRequests,
      timeoutMs: row.timeoutMs,
      userApproved: row.userApproved
    },
    stopConditions: row.stopConditions,
    createdAt: toIso(row.createdAt)
  }
}

function mapPolicyDecision(
  row: typeof policyDecisions.$inferSelect
): StoredPolicyDecision {
  return {
    id: row.id,
    proposalId: row.proposalId,
    scopeSnapshotId: row.scopeSnapshotId,
    allowed: row.allowed,
    requiresApproval: row.requiresApproval,
    code: row.code as PolicyDecision['code'],
    reasons: row.reasons,
    ...(row.normalizedTarget ? { normalizedTarget: row.normalizedTarget } : {}),
    ...(row.approvedBy ? { approvedBy: row.approvedBy } : {}),
    ...(row.approvedAt !== null ? { approvedAt: toIso(row.approvedAt) } : {}),
    ...(row.validUntil !== null ? { validUntil: toIso(row.validUntil) } : {}),
    ...(row.authorizedWireRequestHmac
      ? { authorizedWireRequestHmac: row.authorizedWireRequestHmac }
      : {}),
    createdAt: toIso(row.createdAt)
  }
}

function mapPage(row: typeof pages.$inferSelect): InventoryPageRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    url: row.url,
    ...(row.title ? { title: row.title } : {}),
    depth: row.depth,
    ...(row.discoveredFrom ? { discoveredFrom: row.discoveredFrom } : {}),
    status: row.status,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapInventoryEndpointRecord(
  row: typeof endpoints.$inferSelect
): InventoryEndpointRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    ...(row.pageId ? { pageId: row.pageId } : {}),
    method: row.method,
    canonicalRoute: row.canonicalRoute,
    lifecycleStatus: row.lifecycleStatus as InventoryEndpointRecord['lifecycleStatus'],
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapRequestVariantRecord(
  row: typeof requestVariants.$inferSelect,
  selectors: readonly SelectorRef[]
): RequestVariantRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    endpointId: row.endpointId,
    ...(row.contentType ? { contentType: row.contentType } : {}),
    bodyShape: row.bodyShape as InventoryBodyShape,
    codec: row.codec as BodyEncoding,
    transport: row.transport as TransportKind,
    allowedHeaders: row.allowedHeaders as AllowedHeaderDescriptor[],
    templateVersion: row.templateVersion,
    requiredCapabilityIds: row.requiredCapabilityIds,
    selectors: [...selectors],
    redactedPreview: row.redactedPreview as RedactedInventoryPreview,
    reviewStatus: row.reviewStatus as InventoryReviewStatus,
    ...(row.reviewedBy ? { reviewedBy: row.reviewedBy } : {}),
    ...(row.reviewedAt !== null ? { reviewedAt: toIso(row.reviewedAt) } : {}),
    executionClass: row.executionClass as InventoryExecutionClass,
    lifecycleStatus: row.lifecycleStatus as RequestVariantRecord['lifecycleStatus'],
    ...(row.retiredAt !== null ? { retiredAt: toIso(row.retiredAt) } : {}),
    structureHash: row.structureHash,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapInventorySourceRecord(
  row: typeof inventorySources.$inferSelect
): InventorySourceRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    endpointId: row.endpointId,
    requestVariantId: row.requestVariantId,
    type: row.type,
    sourceHash: row.sourceHash,
    provenanceHash: row.provenanceHash,
    ...(row.pageId ? { pageId: row.pageId } : {}),
    ...(row.evidenceRef ? { evidenceRef: row.evidenceRef } : {}),
    ...(row.initiator ? { initiator: row.initiator } : {}),
    confidencePpm: row.confidencePpm,
    discoveredAt: toIso(row.discoveredAt),
    reviewStatus: row.reviewStatus as InventoryReviewStatus,
    createdAt: toIso(row.createdAt)
  }
}

function mapScanModuleSnapshotRecord(
  row: typeof scanModuleSnapshots.$inferSelect
): ScanModuleSnapshotRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    familyId: row.familyId,
    moduleId: row.moduleId,
    moduleVersion: row.moduleVersion,
    definitionHash: row.definitionHash,
    techniqueId: row.techniqueId,
    techniqueVersion: row.techniqueVersion,
    strategyRefs: row.strategyRefs as VersionedDefinitionRef[],
    confirmationRuleRefs: row.confirmationRuleRefs as VersionedDefinitionRef[],
    evidenceProfileRefs: row.evidenceProfileRefs as VersionedDefinitionRef[],
    remediationRefs: row.remediationRefs as VersionedDefinitionRef[],
    requiredCapabilityIds: row.requiredCapabilityIds,
    capabilityDescriptors: row.capabilityDescriptors as ScanModuleSnapshotRecord['capabilityDescriptors'],
    capabilitySnapshotHash: row.capabilitySnapshotHash,
    selectedCapabilitiesHash: row.selectedCapabilitiesHash,
    selectedDefinitionsHash: row.selectedDefinitionsHash,
    registrySnapshotHash: row.registrySnapshotHash,
    environment: row.environment as ScanModuleSnapshotRecord['environment'],
    authorization: row.authorization as ScanModuleSnapshotRecord['authorization'],
    snapshotHash: row.snapshotHash,
    createdAt: toIso(row.createdAt)
  }
}

function mapSignal(row: typeof signals.$inferSelect): StoredSignalRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    ...(row.interactionId ? { interactionId: row.interactionId } : {}),
    family: row.family as StoredSignalRecord['family'],
    endpointId: row.endpointId,
    ...(row.parameterId ? { parameterId: row.parameterId } : {}),
    ...(row.identityId ? { identityId: row.identityId } : {}),
    hypothesis: row.hypothesis,
    observedDifference: row.observedDifference,
    confidenceHint: row.confidenceHint / 10_000,
    evidenceRefs: row.evidenceRefs,
    status: row.status,
    createdAt: toIso(row.createdAt)
  }
}

function mapValidation(
  row: typeof validationRuns.$inferSelect
): StoredValidationRun {
  return {
    id: row.id,
    signalId: row.signalId,
    confirmationRuleId: row.confirmationRuleId,
    confirmationRuleVersion: row.confirmationRuleVersion,
    probeProposalId: row.probeProposalId,
    policyDecisionId: row.policyDecisionId,
    ...(row.toolCallId ? { toolCallId: row.toolCallId } : {}),
    baselineRef: row.baselineRef,
    testRef: row.testRef,
    ...(row.negativeControlRef
      ? { negativeControlRef: row.negativeControlRef }
      : {}),
    completedChecks: row.completedChecks,
    failedChecks: row.failedChecks,
    missingChecks: row.missingChecks,
    cleanupStatus: row.cleanupStatus as StoredValidationRun['cleanupStatus'],
    result: row.result as StoredValidationRun['result'],
    createdAt: toIso(row.createdAt)
  }
}

function mapModelProfile(row: typeof modelProfiles.$inferSelect): ModelProfileRecord {
  return {
    id: row.id,
    name: row.name,
    agentRole: row.agentRole as ModelProfileRecord['agentRole'],
    provider: row.provider as ModelProfileRecord['provider'],
    ...(row.baseUrl ? { baseUrl: row.baseUrl } : {}),
    model: row.model,
    ...(row.credentialId ? { credentialId: row.credentialId } : {}),
    timeoutMs: row.timeoutMs,
    rpmLimit: row.rpmLimit,
    tpmLimit: row.tpmLimit,
    tokenBudget: row.tokenBudget,
    costBudget: row.costBudgetMicros / 1_000_000,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapMcpServer(row: typeof mcpServers.$inferSelect): McpServerRecord {
  return {
    id: row.id,
    name: row.name,
    transport: row.transport,
    enabled: row.enabled,
    ...(row.configJson.command ? { command: row.configJson.command } : {}),
    args: row.configJson.args,
    ...(row.configJson.cwd ? { cwd: row.configJson.cwd } : {}),
    ...(row.configJson.url ? { url: row.configJson.url } : {}),
    authType: row.configJson.authType,
    ...(row.configJson.authHeaderName
      ? { authHeaderName: row.configJson.authHeaderName }
      : {}),
    ...(row.credentialId ? { credentialId: row.credentialId } : {}),
    environmentKeys: row.configJson.environmentKeys,
    headerNames: row.configJson.headerNames,
    timeoutMs: row.configJson.timeoutMs,
    roots: row.configJson.roots,
    allowedAgentRoles: row.allowedAgentRoles,
    riskLabels: row.riskLabels,
    status: row.status,
    ...(row.discoveryJson.protocolVersion
      ? { protocolVersion: row.discoveryJson.protocolVersion }
      : {}),
    ...(row.discoveryJson.serverName
      ? { serverName: row.discoveryJson.serverName }
      : {}),
    ...(row.discoveryJson.serverVersion
      ? { serverVersion: row.discoveryJson.serverVersion }
      : {}),
    tools: row.discoveryJson.tools,
    resources: row.discoveryJson.resources,
    prompts: row.discoveryJson.prompts,
    ...(optionalIso(row.lastTestedAt) ? { lastTestedAt: optionalIso(row.lastTestedAt) } : {}),
    ...(row.lastError ? { lastError: row.lastError } : {}),
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt)
  }
}

function mapReport(row: typeof reports.$inferSelect): StoredReportRecord {
  return {
    id: row.id,
    scanId: row.scanId,
    title: row.title,
    format: row.format as ReportRecord['format'],
    ...(row.filePath ? { filePath: row.filePath } : {}),
    sha256: row.sha256,
    redacted: row.redacted,
    contentRef: row.contentRef,
    createdAt: toIso(row.createdAt)
  }
}

function normalizedTargetBaseUrl(value: string): string {
  return new URL(TargetBaseUrlSchema.parse(value)).toString()
}

function reviewedLegacyExecutionUrl(
  previewUrl: string,
  queryNames: ReadonlySet<string>
): string {
  const url = new URL(previewUrl)
  const reviewedOccurrences = [...url.searchParams.keys()]
    .filter((name) => queryNames.has(name))
    .sort(compareBinary)
  const representedNames = new Set(reviewedOccurrences)
  if (
    representedNames.size !== queryNames.size ||
    [...queryNames].some((name) => !representedNames.has(name))
  ) {
    throw new Error(
      'Reviewed query selector structure is absent from its redacted preview.'
    )
  }
  url.search = ''
  for (const name of reviewedOccurrences) {
    url.searchParams.append(name, INVENTORY_REDACTION_MARKER)
  }
  return url.toString()
}

function compatibilityParameter(
  selector: SelectorRef
): {
  name: string
  location: InventoryEndpoint['parameters'][number]['location']
  dataType: string
  required: boolean
} | undefined {
  if (
    selector.kind === 'query' ||
    selector.kind === 'path' ||
    selector.kind === 'header' ||
    selector.kind === 'cookie' ||
    selector.kind === 'form'
  ) {
    return {
      name: selector.name,
      location: selector.kind,
      dataType: selector.valueType,
      required: selector.required
    }
  }
  if (selector.kind === 'json-pointer') {
    const encodedName = selector.pointer.split('/').at(-1) ?? selector.pointer
    return {
      name: encodedName.replaceAll('~1', '/').replaceAll('~0', '~') || '/',
      location: 'json',
      dataType: selector.valueType,
      required: selector.required
    }
  }
  return undefined
}

function scopeSnapshotHash(scope: Omit<TargetScope, 'id'>): string {
  return sha256Text(
    stableJson({
      ...scope,
      ...(scope.validFrom
        ? { validFrom: new Date(Date.parse(scope.validFrom)).toISOString() }
        : {}),
      ...(scope.validUntil
        ? { validUntil: new Date(Date.parse(scope.validUntil)).toISOString() }
        : {})
    })
  )
}

export class AgentGoRepository {
  private readonly scopeLockKey: string
  private readonly executionRepository: ExecutionLeaseRepository

  constructor(private readonly database: AgentGoDatabase) {
    this.scopeLockKey = scopeSnapshotLockKey(database.filePath)
    this.executionRepository = new ExecutionLeaseRepository(database)
  }

  private async withScopeSnapshotLock<T>(operation: () => Promise<T>): Promise<T> {
    const lockKey = this.scopeLockKey
    const previous = scopeSnapshotTails.get(lockKey) ?? Promise.resolve()
    let release: (() => void) | undefined
    const current = new Promise<void>((resolve) => {
      release = resolve
    })
    scopeSnapshotTails.set(lockKey, current)

    await previous
    try {
      return await operation()
    } finally {
      release?.()
      if (scopeSnapshotTails.get(lockKey) === current) {
        scopeSnapshotTails.delete(lockKey)
      }
    }
  }

  private async withInventoryWriteLock<T>(operation: () => Promise<T>): Promise<T> {
    const lockKey = this.scopeLockKey
    const previous = inventoryWriteTails.get(lockKey) ?? Promise.resolve()
    let release: (() => void) | undefined
    const current = new Promise<void>((resolve) => {
      release = resolve
    })
    inventoryWriteTails.set(lockKey, current)

    await previous
    try {
      return await operation()
    } finally {
      release?.()
      if (inventoryWriteTails.get(lockKey) === current) {
        inventoryWriteTails.delete(lockKey)
      }
    }
  }

  async initializeDefaults(): Promise<void> {
    const existing = await this.database.orm
      .select({ count: sql<number>`count(*)` })
      .from(workspaces)
    if ((existing[0]?.count ?? 0) > 0) {
      return
    }

    await this.createWorkspace({
      name: '默认工作区',
      description: '用于本地授权测试与研究数据隔离。'
    })
  }

  async upsertKnowledgeEntries(entries: KnowledgeIndexEntryInput[]): Promise<void> {
    const now = Date.now()
    await this.database.orm.transaction(async (transaction) => {
      for (const entry of entries) {
        const documentId = `builtin:${entry.id}`
        const documentHash = sha256Text(
          stableJson({
            id: entry.id,
            family: entry.family,
            title: entry.title,
            content: entry.content,
            tags: entry.tags,
            applicability: entry.applicability,
            sourceUrl: entry.sourceUrl,
            license: entry.license
          })
        )
        await transaction
          .insert(knowledgeDocs)
          .values({
            id: documentId,
            title: entry.title,
            sourceType: 'built-in-curated',
            sourceUrl: entry.sourceUrl ?? null,
            author: 'AgentGo project team',
            license: entry.license ?? null,
            trustLevel: 'built-in',
            reviewStatus: 'approved',
            sha256: documentHash,
            publishedAt: null,
            ingestedAt: now
          })
          .onConflictDoUpdate({
            target: knowledgeDocs.id,
            set: {
              title: entry.title,
              sourceType: 'built-in-curated',
              sourceUrl: entry.sourceUrl ?? null,
              author: 'AgentGo project team',
              license: entry.license ?? null,
              trustLevel: 'built-in',
              reviewStatus: 'approved',
              sha256: documentHash,
              ingestedAt: now
            }
          })
        await transaction
          .insert(knowledgeChunks)
          .values({
            id: entry.id,
            docId: documentId,
            family: entry.family,
            title: entry.title,
            content: entry.content,
            tags: entry.tags,
            applicability: entry.applicability,
            tokenEstimate: Math.max(1, Math.ceil(entry.content.length / 4)),
            contentHash: sha256Text(entry.content),
            createdAt: now
          })
          .onConflictDoUpdate({
            target: knowledgeChunks.id,
            set: {
              docId: documentId,
              family: entry.family,
              title: entry.title,
              content: entry.content,
              tags: entry.tags,
              applicability: entry.applicability,
              tokenEstimate: Math.max(1, Math.ceil(entry.content.length / 4)),
              contentHash: sha256Text(entry.content),
              createdAt: now
            }
          })
      }
    })
  }

  async createKnowledgeImport(
    input: CreateKnowledgeImportInput,
    instructionFlags: string[]
  ): Promise<KnowledgeImportDetail> {
    const id = randomUUID()
    const documentId = `import:${id}`
    const now = Date.now()
    const contentHash = sha256Text(input.rawContent)
    await this.database.orm.transaction(async (transaction) => {
      await transaction.insert(knowledgeDocs).values({
        id: documentId,
        title: input.title,
        sourceType: input.sourceType,
        sourceUrl: input.sourceUrl?.trim() || null,
        author: input.author?.trim() || null,
        license: input.license?.trim() || null,
        trustLevel: 'user-imported',
        reviewStatus: 'draft',
        sha256: contentHash,
        publishedAt: null,
        ingestedAt: now
      })
      await transaction.insert(knowledgeImports).values({
        id,
        documentId,
        sourceType: input.sourceType,
        rawContent: input.rawContent,
        rawContentSha256: contentHash,
        vendorHint: input.vendorHint?.trim() || null,
        productHint: input.productHint?.trim() || null,
        instructionFlags,
        status: instructionFlags.length > 0 ? 'needs-review' : 'draft',
        extractorProfileId: null,
        reviewerProfileId: null,
        reviewIssues: instructionFlags.map((flag) => ({
          severity: flag === 'sensitive-data-redacted' ? 'info' as const : 'warning' as const,
          field: 'rawContent',
          message: flag === 'sensitive-data-redacted'
            ? '原文中的敏感凭据模式已在入库前脱敏。'
            : `检测到不可信命令式内容：${flag}`
        })),
        lastError: null,
        createdAt: now,
        updatedAt: now
      })
    })
    const created = await this.getKnowledgeImport(id)
    if (!created) throw new Error('知识导入记录创建失败。')
    return created
  }

  async listKnowledgeImports(): Promise<KnowledgeImportSummary[]> {
    const rows = await this.database.orm
      .select()
      .from(knowledgeImports)
      .orderBy(desc(knowledgeImports.updatedAt))
    return Promise.all(
      rows.map(async (row) => {
        const [document] = await this.database.orm
          .select()
          .from(knowledgeDocs)
          .where(eq(knowledgeDocs.id, row.documentId))
          .limit(1)
        if (!document) throw new Error(`知识来源文档不存在：${row.documentId}`)
        const [intelligence] = await this.database.orm
          .select()
          .from(knowledgeIntelligence)
          .where(eq(knowledgeIntelligence.importId, row.id))
          .limit(1)
        return mapKnowledgeImportSummary(row, document, intelligence)
      })
    )
  }

  async getKnowledgeImport(id: string): Promise<KnowledgeImportDetail | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(knowledgeImports)
      .where(eq(knowledgeImports.id, id))
      .limit(1)
    if (!row) return undefined
    const [document] = await this.database.orm
      .select()
      .from(knowledgeDocs)
      .where(eq(knowledgeDocs.id, row.documentId))
      .limit(1)
    if (!document) throw new Error(`知识来源文档不存在：${row.documentId}`)
    const [intelligence] = await this.database.orm
      .select()
      .from(knowledgeIntelligence)
      .where(eq(knowledgeIntelligence.importId, row.id))
      .limit(1)
    const runRows = await this.database.orm
      .select()
      .from(knowledgeAgentRuns)
      .where(eq(knowledgeAgentRuns.importId, row.id))
      .orderBy(asc(knowledgeAgentRuns.startedAt))
    return {
      ...mapKnowledgeImportSummary(row, document, intelligence),
      rawContent: row.rawContent,
      runs: runRows.map(mapKnowledgeAgentRun)
    }
  }

  async getKnowledgeImportHints(id: string): Promise<{
    vendorHint?: string
    productHint?: string
  }> {
    const [row] = await this.database.orm
      .select({
        vendorHint: knowledgeImports.vendorHint,
        productHint: knowledgeImports.productHint
      })
      .from(knowledgeImports)
      .where(eq(knowledgeImports.id, id))
      .limit(1)
    if (!row) throw new Error('知识导入记录不存在。')
    return {
      ...(row.vendorHint ? { vendorHint: row.vendorHint } : {}),
      ...(row.productHint ? { productHint: row.productHint } : {})
    }
  }

  async updateKnowledgeImportState(input: {
    id: string
    status: KnowledgeImportStatus
    extractorProfileId?: string
    reviewerProfileId?: string
    reviewIssues?: KnowledgeReviewIssue[]
    lastError?: string | null
  }): Promise<KnowledgeImportDetail> {
    const existing = await this.getKnowledgeImport(input.id)
    if (!existing) throw new Error('知识导入记录不存在。')
    const now = Date.now()
    await this.database.orm.transaction(async (transaction) => {
      await transaction
        .update(knowledgeImports)
        .set({
          status: input.status,
          ...(input.extractorProfileId
            ? { extractorProfileId: input.extractorProfileId }
            : {}),
          ...(input.reviewerProfileId
            ? { reviewerProfileId: input.reviewerProfileId }
            : {}),
          ...(input.reviewIssues ? { reviewIssues: input.reviewIssues } : {}),
          ...(input.lastError !== undefined ? { lastError: input.lastError } : {}),
          updatedAt: now
        })
        .where(eq(knowledgeImports.id, input.id))
      await transaction
        .update(knowledgeDocs)
        .set({ reviewStatus: input.status })
        .where(eq(knowledgeDocs.id, existing.documentId))
    })
    return (await this.getKnowledgeImport(input.id))!
  }

  async saveKnowledgeCandidate(
    importId: string,
    candidate: KnowledgeIntelligenceCandidate,
    reviewIssues: KnowledgeReviewIssue[],
    status: KnowledgeImportStatus
  ): Promise<KnowledgeImportDetail> {
    const existing = await this.getKnowledgeImport(importId)
    if (!existing) throw new Error('知识导入记录不存在。')
    const now = Date.now()
    const values = {
      schemaVersion: candidate.schemaVersion,
      title: candidate.title,
      vendor: candidate.vendor,
      product: candidate.product,
      vulnerabilityType: candidate.vulnerabilityType,
      family: candidate.family ?? null,
      identifiers: candidate.identifiers,
      affectedVersions: candidate.affectedVersions,
      preconditions: candidate.preconditions,
      affectedEndpoints: candidate.affectedEndpoints,
      signals: candidate.signals,
      confirmationRules: candidate.confirmationRules,
      remediation: candidate.remediation,
      forbiddenActions: candidate.forbiddenActions,
      fieldEvidence: candidate.fieldEvidence,
      extractionConfidence: Math.round(candidate.extractionConfidence * 10_000),
      updatedAt: now
    }
    await this.database.orm.transaction(async (transaction) => {
      await transaction
        .insert(knowledgeIntelligence)
        .values({
          id: randomUUID(),
          importId,
          ...values,
          publishedChunkId: null,
          createdAt: now
        })
        .onConflictDoUpdate({
          target: knowledgeIntelligence.importId,
          set: values
        })
      await transaction
        .update(knowledgeImports)
        .set({ status, reviewIssues, lastError: null, updatedAt: now })
        .where(eq(knowledgeImports.id, importId))
      await transaction
        .update(knowledgeDocs)
        .set({ title: candidate.title, reviewStatus: status })
        .where(eq(knowledgeDocs.id, existing.documentId))
    })
    return (await this.getKnowledgeImport(importId))!
  }

  async createKnowledgeAgentRun(input: {
    importId: string
    parentRunId?: string
    role: KnowledgeAgentRunRecord['role']
    promptId: string
    promptVersion: string
    modelProfileId: string
    inputHashSource: string
  }): Promise<KnowledgeAgentRunRecord> {
    const row: typeof knowledgeAgentRuns.$inferSelect = {
      id: randomUUID(),
      importId: input.importId,
      parentRunId: input.parentRunId ?? null,
      role: input.role,
      promptId: input.promptId,
      promptVersion: input.promptVersion,
      promptHash: sha256Text(`${input.promptId}@${input.promptVersion}`),
      modelProfileId: input.modelProfileId,
      provider: null,
      model: null,
      status: 'running',
      inputHash: sha256Text(input.inputHashSource),
      outputHash: null,
      promptTokens: 0,
      completionTokens: 0,
      durationMs: 0,
      error: null,
      startedAt: Date.now(),
      finishedAt: null
    }
    await this.database.orm.insert(knowledgeAgentRuns).values(row)
    return mapKnowledgeAgentRun(row)
  }

  async finishKnowledgeAgentRun(input: {
    id: string
    status: 'completed' | 'failed'
    provider?: string
    model?: string
    outputHashSource?: string
    promptTokens?: number
    completionTokens?: number
    durationMs?: number
    error?: string
  }): Promise<KnowledgeAgentRunRecord> {
    await this.database.orm
      .update(knowledgeAgentRuns)
      .set({
        status: input.status,
        provider: input.provider ?? null,
        model: input.model ?? null,
        outputHash: input.outputHashSource ? sha256Text(input.outputHashSource) : null,
        promptTokens: input.promptTokens ?? 0,
        completionTokens: input.completionTokens ?? 0,
        durationMs: input.durationMs ?? 0,
        error: input.error ?? null,
        finishedAt: Date.now()
      })
      .where(eq(knowledgeAgentRuns.id, input.id))
    const [row] = await this.database.orm
      .select()
      .from(knowledgeAgentRuns)
      .where(eq(knowledgeAgentRuns.id, input.id))
      .limit(1)
    if (!row) throw new Error('知识 Agent 运行记录不存在。')
    return mapKnowledgeAgentRun(row)
  }

  async reviewKnowledgeImport(
    id: string,
    action: 'publish' | 'reject' | 'reopen'
  ): Promise<KnowledgeImportDetail> {
    const existing = await this.getKnowledgeImport(id)
    if (!existing) throw new Error('知识导入记录不存在。')
    if (existing.status === 'published' && action !== 'reopen') {
      throw new Error('已发布知识必须先重新打开审核。')
    }
    const now = Date.now()
    const [intelligence] = await this.database.orm
      .select()
      .from(knowledgeIntelligence)
      .where(eq(knowledgeIntelligence.importId, id))
      .limit(1)

    if (action === 'publish') {
      if (!intelligence) throw new Error('当前导入尚未形成结构化候选。')
      if (existing.reviewIssues.some((issue) => issue.severity === 'error')) {
        throw new Error('当前候选仍有错误级复核问题，不能发布。')
      }
      const candidate = mapKnowledgeCandidate(intelligence)
      const chunkId = `intel:${intelligence.id}`
      const content = [
        `厂商：${candidate.vendor}`,
        `产品：${candidate.product}`,
        `漏洞类型：${candidate.vulnerabilityType}`,
        `标识：${[...candidate.identifiers.cve, ...candidate.identifiers.cwe, ...candidate.identifiers.other].join('、') || '未识别'}`,
        `影响版本：${candidate.affectedVersions.join('；') || '未识别'}`,
        `前置条件：${candidate.preconditions.join('；') || '未识别'}`,
        `影响端点：${candidate.affectedEndpoints.map((endpoint) => `${endpoint.method} ${endpoint.pathTemplate}`).join('；') || '未识别'}`,
        `信号：${candidate.signals.join('；') || '未识别'}`,
        `确认规则：${candidate.confirmationRules.join('；') || '未识别'}`,
        `修复建议：${candidate.remediation.join('；') || '未识别'}`,
        `禁止动作：${candidate.forbiddenActions.join('；') || '无'}`
      ].join('\n')
      await this.database.orm.transaction(async (transaction) => {
        await transaction
          .insert(knowledgeChunks)
          .values({
            id: chunkId,
            docId: existing.documentId,
            family: candidate.family ?? null,
            title: candidate.title,
            content,
            tags: [
              candidate.vendor,
              candidate.product,
              candidate.vulnerabilityType,
              ...candidate.identifiers.cve,
              ...candidate.identifiers.cwe
            ],
            applicability: [...candidate.affectedVersions, ...candidate.preconditions],
            tokenEstimate: Math.max(1, Math.ceil(content.length / 4)),
            contentHash: sha256Text(content),
            createdAt: now
          })
          .onConflictDoUpdate({
            target: knowledgeChunks.id,
            set: {
              family: candidate.family ?? null,
              title: candidate.title,
              content,
              tags: [
                candidate.vendor,
                candidate.product,
                candidate.vulnerabilityType,
                ...candidate.identifiers.cve,
                ...candidate.identifiers.cwe
              ],
              applicability: [...candidate.affectedVersions, ...candidate.preconditions],
              tokenEstimate: Math.max(1, Math.ceil(content.length / 4)),
              contentHash: sha256Text(content),
              createdAt: now
            }
          })
        await transaction
          .update(knowledgeIntelligence)
          .set({ publishedChunkId: chunkId, updatedAt: now })
          .where(eq(knowledgeIntelligence.importId, id))
        await transaction
          .update(knowledgeImports)
          .set({ status: 'published', lastError: null, updatedAt: now })
          .where(eq(knowledgeImports.id, id))
        await transaction
          .update(knowledgeDocs)
          .set({ reviewStatus: 'published', publishedAt: now })
          .where(eq(knowledgeDocs.id, existing.documentId))
      })
    } else {
      await this.database.orm.transaction(async (transaction) => {
        if (action === 'reopen' && intelligence?.publishedChunkId) {
          await transaction
            .delete(knowledgeChunks)
            .where(eq(knowledgeChunks.id, intelligence.publishedChunkId))
          await transaction
            .update(knowledgeIntelligence)
            .set({ publishedChunkId: null, updatedAt: now })
            .where(eq(knowledgeIntelligence.importId, id))
        }
        const status = action === 'reject' ? 'rejected' : 'needs-review'
        await transaction
          .update(knowledgeImports)
          .set({ status, updatedAt: now })
          .where(eq(knowledgeImports.id, id))
        await transaction
          .update(knowledgeDocs)
          .set({ reviewStatus: status, publishedAt: null })
          .where(eq(knowledgeDocs.id, existing.documentId))
      })
    }
    return (await this.getKnowledgeImport(id))!
  }

  async deleteKnowledgeImport(id: string): Promise<boolean> {
    const existing = await this.getKnowledgeImport(id)
    if (!existing) return false
    if (existing.status === 'published') {
      throw new Error('已发布知识必须先重新打开审核，才能删除。')
    }
    const result = await this.database.orm
      .delete(knowledgeDocs)
      .where(eq(knowledgeDocs.id, existing.documentId))
      .returning({ id: knowledgeDocs.id })
    return result.length > 0
  }

  async listPublishedKnowledgeEntries(
    chunkIds: string[]
  ): Promise<PublishedKnowledgeEntryRecord[]> {
    if (chunkIds.length === 0) return []
    const rows = await this.database.orm
      .select()
      .from(knowledgeIntelligence)
      .where(inArray(knowledgeIntelligence.publishedChunkId, chunkIds))
    return Promise.all(
      rows.map(async (row) => {
        const [knowledgeImport] = await this.database.orm
          .select()
          .from(knowledgeImports)
          .where(eq(knowledgeImports.id, row.importId))
          .limit(1)
        if (!knowledgeImport) throw new Error(`知识导入记录不存在：${row.importId}`)
        const [document] = await this.database.orm
          .select()
          .from(knowledgeDocs)
          .where(eq(knowledgeDocs.id, knowledgeImport.documentId))
          .limit(1)
        if (!document) throw new Error(`知识来源文档不存在：${knowledgeImport.documentId}`)
        return {
          chunkId: row.publishedChunkId!,
          candidate: mapKnowledgeCandidate(row),
          sourceTitle: document.title,
          sourceType: document.sourceType
        }
      })
    )
  }

  searchKnowledgeEntryIds(input: {
    query: string
    families: string[]
    limit: number
  }): string[] {
    const familyClause = input.families.length > 0
      ? ` AND kc.family IN (${input.families.map(() => '?').join(', ')})`
      : ''
    const familyParameters = [...input.families]
    const normalizedQuery = input.query.normalize('NFKC').trim()

    if (normalizedQuery) {
      const terms = normalizedQuery.match(/[\p{L}\p{N}_-]+/gu)?.slice(0, 16) ?? []
      const ftsQuery = terms
        .map((term) => `"${term.replaceAll('"', '""')}"*`)
        .join(' AND ')
      if (ftsQuery) {
        const rows = this.database.native
          .prepare(`
            SELECT kc.id AS id
            FROM knowledge_chunks_fts
            JOIN knowledge_chunks kc ON kc.rowid = knowledge_chunks_fts.rowid
            WHERE knowledge_chunks_fts MATCH ?${familyClause}
            ORDER BY bm25(knowledge_chunks_fts), kc.id
            LIMIT ?
          `)
          .all(ftsQuery, ...familyParameters, input.limit) as Array<{ id: string }>
        if (rows.length > 0) return rows.map((row) => row.id)
      }

      const likeValue = `%${normalizedQuery}%`
      const rows = this.database.native
        .prepare(`
          SELECT kc.id AS id
          FROM knowledge_chunks kc
          WHERE (kc.title LIKE ? OR kc.content LIKE ? OR kc.tags LIKE ?)${familyClause}
          ORDER BY kc.id
          LIMIT ?
        `)
        .all(likeValue, likeValue, likeValue, ...familyParameters, input.limit) as Array<{
          id: string
        }>
      if (rows.length > 0) return rows.map((row) => row.id)
    }

    const rows = this.database.native
      .prepare(`
        SELECT kc.id AS id
        FROM knowledge_chunks kc
        WHERE 1 = 1${familyClause}
        ORDER BY kc.id
        LIMIT ?
      `)
      .all(...familyParameters, input.limit) as Array<{ id: string }>
    return rows.map((row) => row.id)
  }

  async listWorkspaces(): Promise<WorkspaceRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(workspaces)
      .orderBy(desc(workspaces.updatedAt))
    return rows.map(mapWorkspace)
  }

  async getWorkspace(id: string): Promise<WorkspaceRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(workspaces)
      .where(eq(workspaces.id, id))
      .limit(1)
    return row ? mapWorkspace(row) : undefined
  }

  async createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceRecord> {
    const now = Date.now()
    const row: typeof workspaces.$inferInsert = {
      id: randomUUID(),
      name: input.name,
      description: input.description,
      createdAt: now,
      updatedAt: now
    }
    await this.database.orm.insert(workspaces).values(row)
    await this.addAuditLog({
      workspaceId: row.id,
      event: 'workspace.created',
      actor: 'user',
      detail: { name: row.name }
    })
    return mapWorkspace(row)
  }

  async deleteWorkspace(id: string): Promise<boolean> {
    const result = await this.database.orm
      .delete(workspaces)
      .where(eq(workspaces.id, id))
      .returning({ id: workspaces.id })
    return result.length > 0
  }

  async listTargets(workspaceId: string): Promise<TargetRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(targets)
      .where(eq(targets.workspaceId, workspaceId))
      .orderBy(desc(targets.updatedAt))
    return rows.map(mapTarget)
  }

  async getTarget(id: string): Promise<TargetRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(targets)
      .where(eq(targets.id, id))
      .limit(1)
    return row ? mapTarget(row) : undefined
  }

  createTarget(input: CreateTargetInput): Promise<{
    target: TargetRecord
    scope: TargetScopeRecord
  }> {
    return this.withScopeSnapshotLock(() =>
      this.createTargetWithInitialScope(input)
    )
  }

  private async createTargetWithInitialScope(input: CreateTargetInput): Promise<{
    target: TargetRecord
    scope: TargetScopeRecord
  }> {
    const now = Date.now()
    const targetId = randomUUID()
    const scopeId = randomUUID()
    const normalizedBaseUrl = normalizedTargetBaseUrl(input.baseUrl)
    const scopeValue: Omit<TargetScope, 'id'> = {
      ...input.scope,
      authorizationReference:
        input.scope.authorizationReference ?? input.authorizationReference
    }
    const snapshotHash = scopeSnapshotHash(scopeValue)

    const targetRow: typeof targets.$inferSelect = {
      id: targetId,
      workspaceId: input.workspaceId,
      name: input.name,
      baseUrl: normalizedBaseUrl,
      description: input.description,
      authorizationReference: input.authorizationReference,
      defaultIdentityId: null,
      currentScopeId: null,
      createdAt: now,
      updatedAt: now
    }
    const scopeRow: typeof targetScopes.$inferSelect = {
      id: scopeId,
      targetId,
      allowedOrigins: scopeValue.allowedOrigins,
      allowedPathPrefixes: scopeValue.allowedPathPrefixes,
      deniedPathPrefixes: scopeValue.deniedPathPrefixes,
      allowedPorts: scopeValue.allowedPorts,
      allowedIdentityIds: scopeValue.allowedIdentityIds,
      allowActiveProbing: scopeValue.allowActiveProbing,
      allowSensitiveProbing: scopeValue.allowSensitiveProbing,
      allowPrivateNetworkTargets: scopeValue.allowPrivateNetworkTargets,
      allowLoopbackTargets: scopeValue.allowLoopbackTargets,
      maxRequestsPerMinute: scopeValue.maxRequestsPerMinute,
      maxConcurrency: scopeValue.maxConcurrency,
      authorizationReference: scopeValue.authorizationReference ?? null,
      validFrom: scopeValue.validFrom ? Date.parse(scopeValue.validFrom) : null,
      validUntil: scopeValue.validUntil ? Date.parse(scopeValue.validUntil) : null,
      revision: 1,
      snapshotHash,
      createdAt: now
    }

    await this.database.orm.transaction(
      async (transaction) => {
        await transaction.insert(targets).values(targetRow)
        await transaction.insert(targetScopes).values(scopeRow)
        await transaction
          .update(targets)
          .set({ currentScopeId: scopeId })
          .where(eq(targets.id, targetId))
      },
      { behavior: 'immediate' }
    )
    await this.addAuditLog({
      workspaceId: input.workspaceId,
      event: 'target.created',
      actor: 'user',
      detail: {
        targetId,
        baseUrl: normalizedBaseUrl,
        scopeSnapshotId: scopeId,
        scopeRevision: 1,
        authorizationReference: input.authorizationReference
      }
    })

    return { target: mapTarget(targetRow), scope: mapScope(scopeRow) }
  }

  updateTarget(input: UpdateTargetInput): Promise<{
    target: TargetRecord
    scope?: TargetScopeRecord
  }> {
    return this.withScopeSnapshotLock(async () => {
      const current = await this.getTarget(input.id)
      if (!current) {
        throw new Error('目标不存在。')
      }

      const now = Date.now()
      const patch: Partial<typeof targets.$inferInsert> = { updatedAt: now }
      if (input.name !== undefined) patch.name = input.name
      if (input.description !== undefined) patch.description = input.description
      if (input.authorizationReference !== undefined) {
        patch.authorizationReference = input.authorizationReference
      }
      if (input.baseUrl !== undefined) {
        patch.baseUrl = normalizedTargetBaseUrl(input.baseUrl)
      }

      let createdScope: TargetScopeRecord | undefined
      await this.database.orm.transaction(
        async (transaction) => {
          if (input.scope) {
            const scopeValue: Omit<TargetScope, 'id'> = {
              ...input.scope,
              authorizationReference:
                input.scope.authorizationReference ??
                input.authorizationReference ??
                current.authorizationReference
            }
            const hash = scopeSnapshotHash(scopeValue)
            const [existing] = await transaction
              .select()
              .from(targetScopes)
              .where(
                and(
                  eq(targetScopes.targetId, input.id),
                  eq(targetScopes.snapshotHash, hash)
                )
              )
              .limit(1)

            if (existing) {
              createdScope = mapScope(existing)
            } else {
              const [latest] = await transaction
                .select({ revision: targetScopes.revision })
                .from(targetScopes)
                .where(eq(targetScopes.targetId, input.id))
                .orderBy(desc(targetScopes.revision))
                .limit(1)
              const row: typeof targetScopes.$inferSelect = {
                id: randomUUID(),
                targetId: input.id,
                allowedOrigins: scopeValue.allowedOrigins,
                allowedPathPrefixes: scopeValue.allowedPathPrefixes,
                deniedPathPrefixes: scopeValue.deniedPathPrefixes,
                allowedPorts: scopeValue.allowedPorts,
                allowedIdentityIds: scopeValue.allowedIdentityIds,
                allowActiveProbing: scopeValue.allowActiveProbing,
                allowSensitiveProbing: scopeValue.allowSensitiveProbing,
                allowPrivateNetworkTargets: scopeValue.allowPrivateNetworkTargets,
                allowLoopbackTargets: scopeValue.allowLoopbackTargets,
                maxRequestsPerMinute: scopeValue.maxRequestsPerMinute,
                maxConcurrency: scopeValue.maxConcurrency,
                authorizationReference: scopeValue.authorizationReference ?? null,
                validFrom: scopeValue.validFrom ? Date.parse(scopeValue.validFrom) : null,
                validUntil: scopeValue.validUntil ? Date.parse(scopeValue.validUntil) : null,
                revision: (latest?.revision ?? 0) + 1,
                snapshotHash: hash,
                createdAt: now
              }
              await transaction.insert(targetScopes).values(row)
              createdScope = mapScope(row)
            }
            patch.currentScopeId = createdScope.id
          }

          await transaction.update(targets).set(patch).where(eq(targets.id, input.id))
        },
        { behavior: 'immediate' }
      )

      const updated = await this.getTarget(input.id)
      if (!updated) {
        throw new Error('目标更新后无法读取。')
      }
      await this.addAuditLog({
        workspaceId: current.workspaceId,
        event: 'target.updated',
        actor: 'user',
        detail: {
          targetId: input.id,
          scopeSnapshotId: createdScope?.id ?? null,
          scopeRevision: createdScope?.revision ?? null
        }
      })
      return { target: updated, ...(createdScope ? { scope: createdScope } : {}) }
    })
  }

  async deleteTarget(id: string): Promise<boolean> {
    const current = await this.getTarget(id)
    if (!current) return false
    const result = await this.database.orm
      .delete(targets)
      .where(eq(targets.id, id))
      .returning({ id: targets.id })
    if (result.length > 0) {
      await this.addAuditLog({
        workspaceId: current.workspaceId,
        event: 'target.deleted',
        actor: 'user',
        detail: { targetId: id, baseUrl: current.baseUrl }
      })
    }
    return result.length > 0
  }

  async getScope(scopeId: string): Promise<TargetScopeRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(targetScopes)
      .where(eq(targetScopes.id, scopeId))
      .limit(1)
    return row ? mapScope(row) : undefined
  }

  async getLatestScope(targetId: string): Promise<TargetScopeRecord | undefined> {
    const [row] = await this.database.orm
      .select({ scope: targetScopes })
      .from(targets)
      .innerJoin(
        targetScopes,
        and(
          eq(targets.currentScopeId, targetScopes.id),
          eq(targetScopes.targetId, targets.id)
        )
      )
      .where(eq(targets.id, targetId))
      .limit(1)
    return row ? mapScope(row.scope) : undefined
  }

  async listIdentities(targetId: string): Promise<IdentityRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(identities)
      .where(eq(identities.targetId, targetId))
      .orderBy(asc(identities.createdAt))
    return rows.map(mapIdentity)
  }

  async getIdentity(id: string): Promise<IdentityRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(identities)
      .where(eq(identities.id, id))
      .limit(1)
    return row ? mapIdentity(row) : undefined
  }

  async saveIdentity(
    input: SaveIdentityInput,
    credentialId?: string | null
  ): Promise<IdentityRecord> {
    const now = Date.now()
    const target = await this.getTarget(input.targetId)
    if (!target) throw new Error('身份所属目标不存在。')

    if (input.id) {
      const [existing] = await this.database.orm
        .select()
        .from(identities)
        .where(eq(identities.id, input.id))
        .limit(1)
      if (!existing || existing.targetId !== input.targetId) {
        throw new Error('要更新的身份不存在。')
      }

      await this.database.orm
        .update(identities)
        .set({
          label: input.label,
          role: input.role,
          authType: input.authType,
          headerName: input.headerName ?? null,
          credentialId:
            credentialId === undefined ? existing.credentialId : credentialId,
          isTestIdentity: input.isTestIdentity,
          ownedResourceIds: input.ownedResourceIds,
          updatedAt: now
        })
        .where(eq(identities.id, input.id))
      const updated = await this.getIdentity(input.id)
      if (!updated) throw new Error('身份更新后无法读取。')
      await this.addAuditLog({
        workspaceId: target.workspaceId,
        event: 'identity.updated',
        actor: 'user',
        detail: { identityId: input.id, targetId: input.targetId, role: input.role }
      })
      return updated
    }

    const row: typeof identities.$inferSelect = {
      id: randomUUID(),
      targetId: input.targetId,
      label: input.label,
      role: input.role,
      authType: input.authType,
      headerName: input.headerName ?? null,
      credentialId: credentialId ?? null,
      isTestIdentity: input.isTestIdentity,
      ownedResourceIds: input.ownedResourceIds,
      createdAt: now,
      updatedAt: now
    }
    await this.database.orm.insert(identities).values(row)
    await this.addAuditLog({
      workspaceId: target.workspaceId,
      event: 'identity.created',
      actor: 'user',
      detail: { identityId: row.id, targetId: input.targetId, role: input.role }
    })
    return mapIdentity(row)
  }

  async deleteIdentity(id: string): Promise<boolean> {
    const identity = await this.getIdentity(id)
    if (!identity) return false
    const target = await this.getTarget(identity.targetId)
    const result = await this.database.orm
      .delete(identities)
      .where(eq(identities.id, id))
      .returning({ id: identities.id })
    if (result.length > 0 && target) {
      await this.addAuditLog({
        workspaceId: target.workspaceId,
        event: 'identity.deleted',
        actor: 'user',
        detail: { identityId: id, targetId: identity.targetId }
      })
    }
    return result.length > 0
  }

  createScan(
    input: CreatePersistedScanInput,
    plan: Record<string, unknown>,
    runtime: Record<string, unknown>,
    moduleSnapshots: readonly PreparedScanModuleSnapshot[] = []
  ): Promise<ScanRecord> {
    return this.withScopeSnapshotLock(() =>
      this.createScanWithFrozenScope(input, plan, runtime, moduleSnapshots)
    )
  }

  private async createScanWithFrozenScope(
    input: CreatePersistedScanInput,
    plan: Record<string, unknown>,
    runtime: Record<string, unknown>,
    moduleSnapshots: readonly PreparedScanModuleSnapshot[]
  ): Promise<ScanRecord> {
    const target = await this.getTarget(input.targetId)
    if (!target) throw new Error('扫描目标不存在。')
    const scope = await this.getLatestScope(input.targetId)
    if (!scope) throw new Error('扫描目标缺少授权范围快照。')

    const validIdentities = await this.listIdentities(input.targetId)
    const validIdentityIds = new Set(validIdentities.map((identity) => identity.id))
    const invalidIdentity = input.identityIds.find((id) => !validIdentityIds.has(id))
    if (invalidIdentity) {
      throw new Error(`扫描身份 ${invalidIdentity} 不属于当前目标。`)
    }
    const nonTestIdentity = validIdentities.find(
      (identity) => input.identityIds.includes(identity.id) && !identity.isTestIdentity
    )
    if (nonTestIdentity) {
      throw new Error(`身份 ${nonTestIdentity.label} 未标记为专用测试身份。`)
    }
    const scopeIdentityIds = new Set(scope.allowedIdentityIds)
    const identityOutsideScope = input.identityIds.find(
      (id) => !scopeIdentityIds.has(id)
    )
    if (identityOutsideScope) {
      throw new Error(`扫描身份 ${identityOutsideScope} 未包含在当前授权范围快照中。`)
    }

    const now = Date.now()
    const id = randomUUID()
    const configuration: ScanConfiguration = {
      description: input.description,
      families: input.families,
      identityIds: input.identityIds,
      ...(input.callbackUrl ? { callbackUrl: input.callbackUrl } : {}),
      modelProfileIds: input.modelProfileIds ?? {}
    }
    const row: typeof scans.$inferSelect = {
      id,
      targetId: input.targetId,
      name: input.name,
      scopeSnapshotId: scope.id,
      status: 'draft',
      phase: 'intake',
      progress: 0,
      budgetJson: input.budget,
      configJson: configuration,
      planJson: plan,
      runtimeJson: runtime,
      requestCount: 0,
      modelTokens: 0,
      estimatedCostMicros: 0,
      checkpointCount: 0,
      lastError: null,
      moduleSnapshotsSealed: false,
      createdAt: now,
      updatedAt: now,
      startedAt: null,
      completedAt: null
    }
    await this.database.orm.transaction(async (transaction) => {
      await transaction.insert(scans).values(row)
      if (input.identityIds.length > 0) {
        await transaction.insert(scanIdentities).values(
          input.identityIds.map((identityId) => ({ scanId: id, identityId }))
        )
      }
      if (moduleSnapshots.length > 0) {
        await transaction.insert(scanModuleSnapshots).values(
          moduleSnapshots.map(({ draft, snapshotHash }) => ({
            id: randomUUID(),
            scanId: id,
            familyId: draft.familyId,
            moduleId: draft.moduleId,
            moduleVersion: draft.moduleVersion,
            definitionHash: draft.definitionHash,
            techniqueId: draft.techniqueId,
            techniqueVersion: draft.techniqueVersion,
            strategyRefs: [...draft.strategyRefs],
            confirmationRuleRefs: [...draft.confirmationRuleRefs],
            evidenceProfileRefs: [...draft.evidenceProfileRefs],
            remediationRefs: [...draft.remediationRefs],
            requiredCapabilityIds: [...draft.requiredCapabilityIds],
            capabilityDescriptors: [...draft.capabilityDescriptors],
            capabilitySnapshotHash: draft.capabilitySnapshotHash,
            selectedCapabilitiesHash: draft.selectedCapabilitiesHash,
            selectedDefinitionsHash: draft.selectedDefinitionsHash,
            registrySnapshotHash: draft.registrySnapshotHash,
            environment: draft.environment,
            authorization: draft.authorization,
            snapshotHash,
            createdAt: now
          }))
        )
      }
      await transaction
        .update(scans)
        .set({ moduleSnapshotsSealed: true })
        .where(eq(scans.id, id))
      await transaction.insert(scanEvents).values({
        id: randomUUID(),
        scanId: id,
        type: 'status',
        level: 'info',
        message: '扫描草稿已创建，等待用户启动。',
        detailJson: {
          scopeSnapshotId: scope.id,
          scopeRevision: scope.revision,
          families: input.families,
          moduleSnapshotHashes: moduleSnapshots.map(({ snapshotHash }) => snapshotHash),
          modelProfileIds: configuration.modelProfileIds
        },
        createdAt: now
      })
    })
    await this.addAuditLog({
      workspaceId: target.workspaceId,
      scanId: id,
      event: 'scan.created',
      actor: 'user',
      detail: {
        targetId: input.targetId,
        scopeSnapshotId: scope.id,
        scopeRevision: scope.revision,
        modelProfileIds: configuration.modelProfileIds
      }
    })
    return mapScan(row, target.name)
  }

  async getScanRow(id: string): Promise<ScanRow | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(scans)
      .where(eq(scans.id, id))
      .limit(1)
    return row
  }

  async listScanModuleSnapshots(scanId: string): Promise<ScanModuleSnapshotRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(scanModuleSnapshots)
      .where(eq(scanModuleSnapshots.scanId, scanId))
      .orderBy(asc(scanModuleSnapshots.familyId), asc(scanModuleSnapshots.techniqueId))
    return rows.map(mapScanModuleSnapshotRecord)
  }

  async getScan(id: string): Promise<ScanRecord | undefined> {
    const [row] = await this.database.orm
      .select({ scan: scans, targetName: targets.name })
      .from(scans)
      .innerJoin(targets, eq(scans.targetId, targets.id))
      .where(eq(scans.id, id))
      .limit(1)
    return row ? mapScan(row.scan, row.targetName) : undefined
  }

  async listScans(filter?: {
    workspaceId?: string
    targetId?: string
    limit?: number
  }): Promise<ScanRecord[]> {
    const conditions: SQL[] = []
    if (filter?.workspaceId) conditions.push(eq(targets.workspaceId, filter.workspaceId))
    if (filter?.targetId) conditions.push(eq(scans.targetId, filter.targetId))

    const where = conditions.length === 0 ? undefined : and(...conditions)
    const query = this.database.orm
      .select({ scan: scans, targetName: targets.name })
      .from(scans)
      .innerJoin(targets, eq(scans.targetId, targets.id))
      .orderBy(desc(scans.updatedAt))
      .limit(filter?.limit ?? 100)
    const rows = where ? await query.where(where) : await query
    return rows.map((row) => mapScan(row.scan, row.targetName))
  }

  async updateScan(
    id: string,
    patch: Partial<{
      status: ScanRecord['status']
      phase: ScanRecord['phase']
      progress: number
      runtimeJson: Record<string, unknown>
      requestCount: number
      modelTokens: number
      estimatedCostMicros: number
      checkpointCount: number
      lastError: string | null
      startedAt: number | null
      completedAt: number | null
    }>
  ): Promise<ScanRecord> {
    await this.database.orm
      .update(scans)
      .set({ ...patch, updatedAt: Date.now() })
      .where(eq(scans.id, id))
    const updated = await this.getScan(id)
    if (!updated) throw new Error('扫描更新后无法读取。')
    return updated
  }

  async addScanEvent(input: Omit<ScanEvent, 'id' | 'createdAt'>): Promise<ScanEvent> {
    const row: typeof scanEvents.$inferInsert = {
      id: randomUUID(),
      scanId: input.scanId,
      type: input.type,
      level: input.level,
      message: input.message,
      detailJson: input.detail,
      createdAt: Date.now()
    }
    await this.database.orm.insert(scanEvents).values(row)
    return mapEvent(row)
  }

  async listScanEvents(scanId: string, limit = 500): Promise<ScanEvent[]> {
    const rows = await this.database.orm
      .select()
      .from(scanEvents)
      .where(eq(scanEvents.scanId, scanId))
      .orderBy(asc(scanEvents.createdAt))
      .limit(limit)
    return rows.map(mapEvent)
  }

  async addCheckpoint(input: {
    scanId: string
    phase: ScanRecord['phase']
    state: Record<string, unknown>
    reason: string
  }): Promise<string> {
    const id = randomUUID()
    await this.database.orm.transaction(async (transaction) => {
      await transaction.insert(scanCheckpoints).values({
        id,
        scanId: input.scanId,
        phase: input.phase,
        stateJson: input.state,
        reason: input.reason,
        createdAt: Date.now()
      })
      await transaction
        .update(scans)
        .set({
          checkpointCount: sql`${scans.checkpointCount} + 1`,
          runtimeJson: input.state,
          updatedAt: Date.now()
        })
        .where(eq(scans.id, input.scanId))
    })
    return id
  }

  async markScanAwaitingUser(input: {
    scanId: string
    phase: ScanRecord['phase']
    runtimeState: Record<string, unknown>
    reason: string
    message: string
    detail: Record<string, unknown>
  }): Promise<ScanRecord> {
    await this.database.orm.transaction(async (transaction) => {
      const [scan] = await transaction
        .select({ id: scans.id })
        .from(scans)
        .where(eq(scans.id, input.scanId))
        .limit(1)
      if (!scan) throw new Error('扫描不存在。')
      const now = Date.now()
      await transaction.insert(scanCheckpoints).values({
        id: randomUUID(),
        scanId: input.scanId,
        phase: input.phase,
        stateJson: input.runtimeState,
        reason: input.reason,
        createdAt: now
      })
      await transaction
        .update(scans)
        .set({
          status: 'awaiting-user',
          runtimeJson: input.runtimeState,
          checkpointCount: sql`${scans.checkpointCount} + 1`,
          lastError: input.message,
          updatedAt: now
        })
        .where(eq(scans.id, input.scanId))
      await transaction.insert(scanEvents).values({
        id: randomUUID(),
        scanId: input.scanId,
        type: 'status',
        level: 'warning',
        message: input.message,
        detailJson: input.detail,
        createdAt: now
      })
    })
    const scan = await this.getScan(input.scanId)
    if (!scan) throw new Error('扫描进入等待状态后无法读取。')
    return scan
  }

  async createAgentRun(input: {
    scanId: string
    parentRunId?: string
    role: AgentRole
    promptId: string
    promptVersion: string
    promptHash: string
    modelProfileId: string
    inputRefs?: string[]
  }): Promise<AgentRunRecord> {
    const row: typeof agentRuns.$inferSelect = {
      id: randomUUID(),
      scanId: input.scanId,
      parentRunId: input.parentRunId ?? null,
      role: input.role,
      promptId: input.promptId,
      promptVersion: input.promptVersion,
      promptHash: input.promptHash,
      modelProfileId: input.modelProfileId,
      status: 'running',
      inputRefs: input.inputRefs ?? [],
      outputRefs: [],
      error: null,
      startedAt: Date.now(),
      finishedAt: null
    }
    await this.database.orm.insert(agentRuns).values(row)
    return mapAgentRun(row)
  }

  async finishAgentRun(input: {
    id: string
    status: 'completed' | 'failed' | 'cancelled'
    outputRefs?: string[]
    error?: string
  }): Promise<AgentRunRecord> {
    await this.database.orm
      .update(agentRuns)
      .set({
        status: input.status,
        outputRefs: input.outputRefs ?? [],
        error: input.error ?? null,
        finishedAt: Date.now()
      })
      .where(eq(agentRuns.id, input.id))
    const [row] = await this.database.orm
      .select()
      .from(agentRuns)
      .where(eq(agentRuns.id, input.id))
      .limit(1)
    if (!row) throw new Error('Agent run does not exist.')
    return mapAgentRun(row)
  }

  async createProbeProposal(input: {
    scanId: string
    agentRunId: string
    action: ProbeAction
    stopConditions: string[]
  }): Promise<ProbeProposalRecord> {
    const now = Date.now()
    const id = input.action.id || randomUUID()
    const row: typeof probeProposals.$inferSelect = {
      id,
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      kind: input.action.kind,
      targetUrl: input.action.targetUrl,
      method: input.action.method,
      identityId: input.action.identityId ?? null,
      probeLevel: input.action.probeLevel,
      sideEffect: input.action.sideEffect,
      summary: input.action.summary,
      payloadSummary: input.action.payloadSummary ?? null,
      expectedEvidence: input.action.expectedEvidence,
      requestedRequestsPerMinute:
        input.action.requestedRequestsPerMinute ?? null,
      requestedConcurrency: input.action.requestedConcurrency ?? null,
      maxRequests: input.action.maxRequests,
      timeoutMs: input.action.timeoutMs,
      userApproved: input.action.userApproved,
      stopConditions: input.stopConditions,
      cleanupPlan: input.action.cleanupPlan ?? null,
      createdAt: now
    }
    await this.database.orm.insert(probeProposals).values(row)
    return mapProposal(row)
  }

  async recordPolicyDecision(input: {
    proposalId: string
    scopeSnapshotId: string
    decision: PolicyDecision
    approvedBy?: string
    validityMs?: number
    authorizedWireRequestHmac?: WireRequestHmac
  }): Promise<StoredPolicyDecision> {
    const now = Date.now()
    const authorizedWireRequestHmac = input.authorizedWireRequestHmac
      ? WireRequestHmacSchema.parse(input.authorizedWireRequestHmac)
      : null
    const row: typeof policyDecisions.$inferSelect = {
      id: randomUUID(),
      proposalId: input.proposalId,
      scopeSnapshotId: input.scopeSnapshotId,
      allowed: input.decision.allowed,
      requiresApproval: input.decision.requiresApproval,
      code: input.decision.code,
      reasons: input.decision.reasons,
      normalizedTarget: input.decision.normalizedTarget ?? null,
      approvedBy: input.approvedBy ?? null,
      approvedAt: input.approvedBy ? now : null,
      validUntil: input.decision.allowed
        ? now + (input.validityMs ?? 5 * 60 * 1_000)
        : null,
      authorizedWireRequestHmac,
      createdAt: now
    }
    await this.database.orm.insert(policyDecisions).values(row)
    return mapPolicyDecision(row)
  }

  getExecutionGrant(id: string): Promise<ExecutionGrant | undefined> {
    return this.executionRepository.getExecutionGrant(id)
  }

  getExecutionLease(id: string): Promise<ExecutionLease | undefined> {
    return this.executionRepository.getExecutionLease(id)
  }

  getExecutionCaptureDecisionSet(
    grantId: string
  ): Promise<ExecutionCaptureDecisionSet | undefined> {
    return this.executionRepository.getExecutionCaptureDecisionSet(grantId)
  }

  getExecutionGrantForLease(
    leaseId: string
  ): Promise<ExecutionGrant | undefined> {
    return this.executionRepository.getExecutionGrantForLease(leaseId)
  }

  issueExecutionGrant(
    input: IssueExecutionGrantInput
  ): Promise<{ grant: ExecutionGrant; lease: ExecutionLease }> {
    return this.executionRepository.issueExecutionGrant(input)
  }

  claimExecutionLease(input: {
    leaseId: string
    runnerInstanceId: string
    binding: ExecutionClaimBinding
    integrityKey: ExecutionGrantIntegrityKey
  }): Promise<ClaimedExecutionLease> {
    return this.executionRepository.claimExecutionLease(input)
  }

  markExecutionLeaseDelivery(input: {
    leaseId: string
    claimToken: string
    deliveryState: 'possibly-sent' | 'response-started'
  }): Promise<ExecutionLease> {
    return this.executionRepository.markExecutionLeaseDelivery(input)
  }

  finalizeExecutionLease(
    input: FinalizeExecutionLeaseInput
  ): Promise<ExecutionLease> {
    return this.executionRepository.finalizeExecutionLease(input)
  }

  revokeExecutionLease(input: {
    leaseId: string
    reason: 'revoked' | 'guard-rejected' | 'unsupported-adapter'
  }): Promise<ExecutionLease> {
    return this.executionRepository.revokeExecutionLease(input)
  }

  expireIssuedExecutionLeases(): Promise<ExecutionLease[]> {
    return this.executionRepository.expireIssuedExecutionLeases()
  }

  listClaimedExecutionLeasesForRecovery(): Promise<
    InterruptedExecutionRecoveryContext[]
  > {
    return this.executionRepository.listClaimedExecutionLeasesForRecovery()
  }

  listInterruptedExecutionLeasesForScanRecovery(): Promise<
    InterruptedExecutionScanRecoveryContext[]
  > {
    return this.executionRepository.listInterruptedExecutionLeasesForScanRecovery()
  }

  recoverInterruptedExecutionLeaseWithEvidence(
    input: RecoverInterruptedExecutionLeaseWithEvidenceInput
  ): Promise<ExecutionLease> {
    return this.executionRepository.recoverInterruptedExecutionLeaseWithEvidence(
      input
    )
  }

  recoverInterruptedExecutionLeaseWithCleanup(
    input: RecoverInterruptedExecutionLeaseWithCleanupInput
  ): Promise<InterruptedExecutionRecoveryResult> {
    return this.executionRepository.recoverInterruptedExecutionLeaseWithCleanup(
      input
    )
  }

  recoverInterruptedExecutionLease(
    input: RecoverInterruptedExecutionLeaseInput
  ): Promise<ExecutionLease> {
    return this.executionRepository.recoverInterruptedExecutionLease(input)
  }

  issueReplacementExecutionLease(input: {
    grantId: string
    previousLeaseId: string
    expiresAt: string
    integrityKey: ExecutionGrantIntegrityKey
  }): Promise<ExecutionLease> {
    return this.executionRepository.issueReplacementExecutionLease(input)
  }

  recordExecutionInteractionAudit(
    input: RecordExecutionInteractionAuditInput
  ): Promise<string> {
    return this.executionRepository.recordExecutionInteractionAudit(input)
  }

  listExecutionLeaseEvidence(
    leaseId: string
  ): Promise<ExecutionLeaseEvidenceLink[]> {
    return this.executionRepository.listExecutionLeaseEvidence(leaseId)
  }

  /** @deprecated Day 4 read compatibility only; it never authorizes new execution. */
  async getExecutionDecision(
    policyDecisionId: string
  ): Promise<ExecutionDecisionContext | undefined> {
    const [row] = await this.database.orm
      .select({
        decision: policyDecisions,
        proposal: probeProposals,
        scope: targetScopes,
        scanStatus: scans.status,
        scanBudget: scans.budgetJson,
        requestCount: scans.requestCount,
        scanId: scans.id,
        targetId: targets.id,
        workspaceId: targets.workspaceId
      })
      .from(policyDecisions)
      .innerJoin(
        probeProposals,
        eq(policyDecisions.proposalId, probeProposals.id)
      )
      .innerJoin(scans, eq(probeProposals.scanId, scans.id))
      .innerJoin(targets, eq(scans.targetId, targets.id))
      .innerJoin(
        targetScopes,
        eq(policyDecisions.scopeSnapshotId, targetScopes.id)
      )
      .where(eq(policyDecisions.id, policyDecisionId))
      .limit(1)
    if (!row) return undefined
    const proposal = mapProposal(row.proposal)
    proposal.action.scopeSnapshotId = row.scope.id
    return {
      decision: mapPolicyDecision(row.decision),
      proposal,
      scope: mapScope(row.scope),
      scanStatus: row.scanStatus as ScanRecord['status'],
      scanBudget: row.scanBudget,
      requestCount: row.requestCount,
      scanId: row.scanId,
      targetId: row.targetId,
      workspaceId: row.workspaceId
    }
  }

  async recordToolCall(input: {
    scanId: string
    policyDecisionId: string
    executionLeaseId?: string
    toolName: string
    toolVersion: string
    argumentHash: string
    status: 'running' | 'succeeded' | 'failed' | 'cancelled'
    durationMs?: number
    outputRef?: string
    error?: string
  }): Promise<string> {
    const id = randomUUID()
    await this.database.orm.insert(toolCalls).values({
      id,
      scanId: input.scanId,
      policyDecisionId: input.policyDecisionId,
      executionLeaseId: input.executionLeaseId ?? null,
      toolName: input.toolName,
      toolVersion: input.toolVersion,
      argumentHash: input.argumentHash,
      status: input.status,
      durationMs: input.durationMs ?? null,
      outputRef: input.outputRef ?? null,
      error: input.error ?? null,
      createdAt: Date.now()
    })
    return id
  }

  async updateToolCall(input: {
    id: string
    status: 'succeeded' | 'failed' | 'cancelled'
    durationMs: number
    outputRef?: string
    error?: string
  }): Promise<void> {
    await this.database.orm
      .update(toolCalls)
      .set({
        status: input.status,
        durationMs: input.durationMs,
        outputRef: input.outputRef ?? null,
        error: input.error ?? null
      })
      .where(eq(toolCalls.id, input.id))
  }

  async recordInteraction(input: {
    id?: string
    scanId: string
    endpointId?: string
    identityId?: string
    policyDecisionId?: string
    executionLeaseId?: string
    requestRef: string
    responseRef: string
    requestSummary: Record<string, unknown>
    responseSummary: Record<string, unknown>
    statusCode?: number
    durationMs?: number
    stateBeforeHash?: string
    stateAfterHash?: string
  }): Promise<string> {
    const id = input.id ?? randomUUID()
    await this.database.orm.insert(interactions).values({
      id,
      scanId: input.scanId,
      endpointId: input.endpointId ?? null,
      identityId: input.identityId ?? null,
      policyDecisionId: input.policyDecisionId ?? null,
      executionLeaseId: input.executionLeaseId ?? null,
      requestRef: input.requestRef,
      responseRef: input.responseRef,
      requestSummaryJson: input.requestSummary,
      responseSummaryJson: input.responseSummary,
      statusCode: input.statusCode ?? null,
      durationMs: input.durationMs ?? null,
      stateBeforeHash: input.stateBeforeHash ?? null,
      stateAfterHash: input.stateAfterHash ?? null,
      createdAt: Date.now()
    })
    return id
  }

  async updateInteraction(input: {
    id: string
    requestRef: string
    responseRef: string
    requestSummary?: Record<string, unknown>
    responseSummary?: Record<string, unknown>
  }): Promise<void> {
    await this.database.orm
      .update(interactions)
      .set({
        requestRef: input.requestRef,
        responseRef: input.responseRef,
        ...(input.requestSummary
          ? { requestSummaryJson: input.requestSummary }
          : {}),
        ...(input.responseSummary
          ? { responseSummaryJson: input.responseSummary }
          : {})
      })
      .where(eq(interactions.id, input.id))
  }

  async incrementScanUsage(input: {
    scanId: string
    requests?: number
    modelTokens?: number
    estimatedCostMicros?: number
  }): Promise<void> {
    await this.database.orm
      .update(scans)
      .set({
        requestCount: sql`${scans.requestCount} + ${input.requests ?? 0}`,
        modelTokens: sql`${scans.modelTokens} + ${input.modelTokens ?? 0}`,
        estimatedCostMicros: sql`${scans.estimatedCostMicros} + ${input.estimatedCostMicros ?? 0}`,
        updatedAt: Date.now()
      })
      .where(eq(scans.id, input.scanId))
  }

  async getLatestCheckpoint(scanId: string): Promise<{
    id: string
    scanId: string
    phase: ScanRecord['phase']
    state: Record<string, unknown>
    reason: string
    createdAt: string
  } | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(scanCheckpoints)
      .where(eq(scanCheckpoints.scanId, scanId))
      .orderBy(desc(scanCheckpoints.createdAt))
      .limit(1)
    return row
      ? {
          id: row.id,
          scanId: row.scanId,
          phase: row.phase as ScanRecord['phase'],
          state: row.stateJson,
          reason: row.reason,
          createdAt: toIso(row.createdAt)
        }
      : undefined
  }

  upsertPage(input: {
    scanId: string
    url: string
    title?: string
    depth: number
    discoveredFrom?: string
    stateHash?: string
    status?: string
  }): Promise<InventoryPageRecord> {
    return this.withInventoryWriteLock(() => this.upsertPageUnlocked(input))
  }

  private async upsertPageUnlocked(input: {
    scanId: string
    url: string
    title?: string
    depth: number
    discoveredFrom?: string
    stateHash?: string
    status?: string
  }): Promise<InventoryPageRecord> {
    const url = redactInventoryUrlPreview(input.url)
    // Browser DOM, importers and future producers are untrusted inputs.  The
    // repository is the final persistence sink, so callers cannot bypass
    // title redaction by writing through a different Application path.
    const title =
      input.title === undefined ? undefined : redactInventoryText(input.title, 512)
    const [existing] = await this.database.orm
      .select()
      .from(pages)
      .where(and(eq(pages.scanId, input.scanId), eq(pages.url, url)))
      .limit(1)
    const now = Date.now()
    if (existing) {
      await this.database.orm
        .update(pages)
        .set({
          title: title ?? existing.title,
          depth: Math.min(existing.depth, input.depth),
          discoveredFrom: input.discoveredFrom ?? existing.discoveredFrom,
          stateHash: input.stateHash ?? existing.stateHash,
          status: input.status ?? existing.status,
          updatedAt: now
        })
        .where(eq(pages.id, existing.id))
      const [updated] = await this.database.orm
        .select()
        .from(pages)
        .where(eq(pages.id, existing.id))
        .limit(1)
      if (!updated) throw new Error('Page disappeared after update.')
      return mapPage(updated)
    }

    const row: typeof pages.$inferSelect = {
      id: randomUUID(),
      scanId: input.scanId,
      url,
      title: title ?? null,
      depth: input.depth,
      discoveredFrom: input.discoveredFrom ?? null,
      stateHash: input.stateHash ?? null,
      status: input.status ?? 'discovered',
      createdAt: now,
      updatedAt: now
    }
    await this.database.orm.insert(pages).values(row)
    return mapPage(row)
  }

  async listPages(scanId: string): Promise<InventoryPageRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(pages)
      .where(eq(pages.scanId, scanId))
      .orderBy(asc(pages.depth), asc(pages.createdAt))
    return rows.map(mapPage)
  }

  /** Atomic persistence sink used only by Application's InventoryService. */
  persistInventory(input: PreparedInventoryWrite): Promise<UpsertInventoryResult> {
    validatePreparedInventoryWrite(input)
    return this.withInventoryWriteLock(() => this.persistInventoryUnlocked(input))
  }

  private async persistInventoryUnlocked(
    input: PreparedInventoryWrite
  ): Promise<UpsertInventoryResult> {
    const identifiers = await this.database.orm.transaction(async (transaction) => {
      const now = Date.now()
      if (input.source.evidenceRef) {
        const [evidence] = await transaction
          .select({ id: evidenceItems.id })
          .from(evidenceItems)
          .where(
            and(
              eq(evidenceItems.id, input.source.evidenceRef),
              eq(evidenceItems.scanId, input.scanId)
            )
          )
          .limit(1)
        if (!evidence) {
          throw new Error('Inventory evidence reference does not belong to this scan.')
        }
      }
      let [endpoint] = await transaction
        .select()
        .from(endpoints)
        .where(
          and(
            eq(endpoints.scanId, input.scanId),
            eq(endpoints.method, input.method),
            eq(endpoints.canonicalRoute, input.canonicalRoute)
          )
        )
        .limit(1)

      if (!endpoint) {
        const endpointId = randomUUID()
        await transaction.insert(endpoints).values({
          id: endpointId,
          scanId: input.scanId,
          pageId: input.pageId ?? null,
          method: input.method,
          urlTemplate: input.canonicalRoute,
          normalizedUrl: input.compatibilityUrl,
          canonicalRoute: input.canonicalRoute,
          contentType: input.contentType ?? null,
          source: input.source.type,
          status: 'discovered',
          lifecycleStatus: 'active',
          createdAt: now,
          updatedAt: now
        })
        ;[endpoint] = await transaction
          .select()
          .from(endpoints)
          .where(eq(endpoints.id, endpointId))
          .limit(1)
      } else {
        const compatibilityUrl =
          compareBinary(input.compatibilityUrl, endpoint.normalizedUrl) < 0
            ? input.compatibilityUrl
            : endpoint.normalizedUrl
        const pageId = endpoint.pageId ?? input.pageId ?? null
        const contentType = endpoint.contentType ?? input.contentType ?? null
        if (
          pageId !== endpoint.pageId ||
          compatibilityUrl !== endpoint.normalizedUrl ||
          contentType !== endpoint.contentType
        ) {
          await transaction
            .update(endpoints)
            .set({
              pageId,
              normalizedUrl: compatibilityUrl,
              contentType,
              updatedAt: now
            })
            .where(eq(endpoints.id, endpoint.id))
        }
      }
      if (!endpoint) throw new Error('Inventory endpoint disappeared during upsert.')

      let [variant] = await transaction
        .select()
        .from(requestVariants)
        .where(
          and(
            eq(requestVariants.endpointId, endpoint.id),
            eq(requestVariants.structureHash, input.structureHash)
          )
        )
        .limit(1)
      if (!variant) {
        const variantId = randomUUID()
        await transaction.insert(requestVariants).values({
          id: variantId,
          scanId: input.scanId,
          endpointId: endpoint.id,
          contentType: input.contentType ?? null,
          bodyShape: input.bodyShape,
          codec: input.codec,
          transport: input.transport,
          allowedHeaders: [...input.allowedHeaders],
          redactedPreview: input.redactedPreview,
          templateVersion: input.templateVersion,
          requiredCapabilityIds: [...input.requiredCapabilityIds],
          reviewStatus: 'unreviewed',
          reviewedBy: null,
          reviewedAt: null,
          executionClass: input.executionClass,
          lifecycleStatus: 'active',
          retiredAt: null,
          structureHash: input.structureHash,
          createdAt: now,
          updatedAt: now
        })
        ;[variant] = await transaction
          .select()
          .from(requestVariants)
          .where(eq(requestVariants.id, variantId))
          .limit(1)
        if (endpoint.lifecycleStatus === 'retired') {
          await transaction
            .update(endpoints)
            .set({ lifecycleStatus: 'active', updatedAt: now })
            .where(eq(endpoints.id, endpoint.id))
        }
      }
      if (!variant) throw new Error('Request variant disappeared during upsert.')
      if (variant.scanId !== input.scanId || variant.endpointId !== endpoint.id) {
        throw new Error('Request variant structure hash collided across inventory scope.')
      }

      for (const prepared of input.selectors) {
        const [existingSelector] = await transaction
          .select({ id: requestVariantSelectors.id })
          .from(requestVariantSelectors)
          .where(
            and(
              eq(requestVariantSelectors.requestVariantId, variant.id),
              eq(requestVariantSelectors.structureHash, prepared.structureHash)
            )
          )
          .limit(1)
        if (!existingSelector) {
          await transaction.insert(requestVariantSelectors).values({
            id: randomUUID(),
            scanId: input.scanId,
            requestVariantId: variant.id,
            kind: prepared.selector.kind,
            selectorJson: prepared.selector,
            structureHash: prepared.structureHash,
            createdAt: now
          })
        }

        const projection = compatibilityParameter(prepared.selector)
        if (!projection) continue
        const [existingParameter] = await transaction
          .select({ id: parameters.id })
          .from(parameters)
          .where(
            and(
              eq(parameters.endpointId, endpoint.id),
              eq(parameters.name, projection.name),
              eq(parameters.location, projection.location)
            )
          )
          .limit(1)
        if (!existingParameter) {
          await transaction.insert(parameters).values({
            id: randomUUID(),
            endpointId: endpoint.id,
            name: projection.name,
            location: projection.location,
            dataType: projection.dataType,
            required: projection.required,
            exampleMasked: null,
            createdAt: now
          })
        }
      }

      let [source] = await transaction
        .select()
        .from(inventorySources)
        .where(
          and(
            eq(inventorySources.scanId, input.scanId),
            eq(inventorySources.provenanceHash, input.source.provenanceHash)
          )
        )
        .limit(1)
      if (!source) {
        const sourceId = randomUUID()
        await transaction.insert(inventorySources).values({
          id: sourceId,
          scanId: input.scanId,
          endpointId: endpoint.id,
          requestVariantId: variant.id,
          type: input.source.type,
          sourceHash: input.source.sourceHash,
          provenanceHash: input.source.provenanceHash,
          pageId: input.source.pageId ?? null,
          evidenceRef: input.source.evidenceRef ?? null,
          initiator: input.source.initiator ?? null,
          confidencePpm: input.source.confidencePpm,
          discoveredAt: now,
          reviewStatus: 'unreviewed',
          createdAt: now
        })
        ;[source] = await transaction
          .select()
          .from(inventorySources)
          .where(eq(inventorySources.id, sourceId))
          .limit(1)
      }
      if (!source) throw new Error('Inventory source disappeared during upsert.')
      if (
        source.endpointId !== endpoint.id ||
        source.requestVariantId !== variant.id ||
        source.sourceHash !== input.source.sourceHash ||
        source.type !== input.source.type
      ) {
        throw new Error('Inventory provenance hash collided with a different source.')
      }
      return { endpointId: endpoint.id, variantId: variant.id, sourceId: source.id }
    })

    const endpoint = await this.getInventoryEndpointRecord(identifiers.endpointId, input.scanId)
    const requestVariant = await this.getInventoryRequestVariant(
      identifiers.variantId,
      input.scanId
    )
    const source = await this.getInventorySource(identifiers.sourceId, input.scanId)
    if (!endpoint || !requestVariant || !source) {
      throw new Error('Inventory records disappeared after atomic upsert.')
    }
    return { endpoint, requestVariant, source }
  }

  async getInventoryEndpointRecord(
    id: string,
    scanId: string
  ): Promise<InventoryEndpointRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(endpoints)
      .where(and(eq(endpoints.id, id), eq(endpoints.scanId, scanId)))
      .limit(1)
    return row ? mapInventoryEndpointRecord(row) : undefined
  }

  async getInventoryRequestVariant(
    id: string,
    scanId: string
  ): Promise<RequestVariantRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(requestVariants)
      .where(and(eq(requestVariants.id, id), eq(requestVariants.scanId, scanId)))
      .limit(1)
    if (!row) return undefined
    const selectorRows = await this.database.orm
      .select()
      .from(requestVariantSelectors)
      .where(
        and(
          eq(requestVariantSelectors.scanId, scanId),
          eq(requestVariantSelectors.requestVariantId, id)
        )
      )
      .orderBy(asc(requestVariantSelectors.structureHash))
    return mapRequestVariantRecord(
      row,
      selectorRows.map(({ selectorJson }) => selectorJson as unknown as SelectorRef)
    )
  }

  async listInventoryRequestVariants(scanId: string): Promise<RequestVariantRecord[]> {
    const rows = await this.database.orm
      .select({ id: requestVariants.id })
      .from(requestVariants)
      .where(eq(requestVariants.scanId, scanId))
      .orderBy(asc(requestVariants.createdAt), asc(requestVariants.id))
    const records = await Promise.all(
      rows.map(({ id }) => this.getInventoryRequestVariant(id, scanId))
    )
    return records.filter((record): record is RequestVariantRecord => Boolean(record))
  }

  async listPendingActiveL1ReviewVariantIds(scanId: string): Promise<string[]> {
    return (await this.listInventoryRequestVariants(scanId))
      .filter(
        (variant) =>
          variant.lifecycleStatus === 'active' &&
          variant.executionClass === 'active-l1' &&
          variant.reviewStatus === 'unreviewed' &&
          variant.transport === 'standard-http' &&
          variant.codec === 'none'
      )
      .map(({ id }) => id)
  }

  async getInventorySource(
    id: string,
    scanId: string
  ): Promise<InventorySourceRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(inventorySources)
      .where(and(eq(inventorySources.id, id), eq(inventorySources.scanId, scanId)))
      .limit(1)
    return row ? mapInventorySourceRecord(row) : undefined
  }

  async listInventorySources(
    scanId: string,
    requestVariantId?: string
  ): Promise<InventorySourceRecord[]> {
    const conditions: SQL[] = [eq(inventorySources.scanId, scanId)]
    if (requestVariantId) {
      conditions.push(eq(inventorySources.requestVariantId, requestVariantId))
    }
    const rows = await this.database.orm
      .select()
      .from(inventorySources)
      .where(and(...conditions))
      .orderBy(asc(inventorySources.discoveredAt), asc(inventorySources.id))
    return rows.map(mapInventorySourceRecord)
  }

  reviewInventoryVariant(input: {
    scanId: string
    requestVariantId: string
    reviewStatus: Exclude<InventoryReviewStatus, 'unreviewed'>
    reviewedBy: string
  }): Promise<RequestVariantRecord> {
    return this.withInventoryWriteLock(() =>
      this.reviewInventoryVariantUnlocked(input)
    )
  }

  private async reviewInventoryVariantUnlocked(input: {
    scanId: string
    requestVariantId: string
    reviewStatus: Exclude<InventoryReviewStatus, 'unreviewed'>
    reviewedBy: string
  }): Promise<RequestVariantRecord> {
    await this.database.orm.transaction(async (transaction) => {
      const [variant] = await transaction
        .select()
        .from(requestVariants)
        .where(
          and(
            eq(requestVariants.id, input.requestVariantId),
            eq(requestVariants.scanId, input.scanId)
          )
        )
        .limit(1)
      if (!variant) throw new Error('Request variant does not exist in this scan.')
      if (variant.lifecycleStatus !== 'active') {
        throw new Error('Retired request variants cannot be reviewed.')
      }
      const now = Date.now()
      await transaction
        .update(requestVariants)
        .set({
          reviewStatus: input.reviewStatus,
          reviewedBy: input.reviewedBy,
          reviewedAt: now,
          updatedAt: now
        })
        .where(eq(requestVariants.id, variant.id))
      await transaction
        .update(inventorySources)
        .set({ reviewStatus: input.reviewStatus })
        .where(
          and(
            eq(inventorySources.scanId, input.scanId),
            eq(inventorySources.requestVariantId, variant.id)
          )
        )
    })
    const record = await this.getInventoryRequestVariant(
      input.requestVariantId,
      input.scanId
    )
    if (!record) throw new Error('Request variant disappeared after review.')
    return record
  }

  retireInventoryVariant(input: {
    scanId: string
    requestVariantId: string
  }): Promise<RequestVariantRecord> {
    return this.withInventoryWriteLock(() =>
      this.retireInventoryVariantUnlocked(input)
    )
  }

  private async retireInventoryVariantUnlocked(input: {
    scanId: string
    requestVariantId: string
  }): Promise<RequestVariantRecord> {
    await this.database.orm.transaction(async (transaction) => {
      const [variant] = await transaction
        .select()
        .from(requestVariants)
        .where(
          and(
            eq(requestVariants.id, input.requestVariantId),
            eq(requestVariants.scanId, input.scanId)
          )
        )
        .limit(1)
      if (!variant) throw new Error('Request variant does not exist in this scan.')
      if (variant.lifecycleStatus === 'retired') return
      const now = Date.now()
      await transaction
        .update(requestVariants)
        .set({ lifecycleStatus: 'retired', retiredAt: now, updatedAt: now })
        .where(eq(requestVariants.id, variant.id))
      const [activeSibling] = await transaction
        .select({ id: requestVariants.id })
        .from(requestVariants)
        .where(
          and(
            eq(requestVariants.endpointId, variant.endpointId),
            eq(requestVariants.lifecycleStatus, 'active')
          )
        )
        .limit(1)
      if (!activeSibling) {
        await transaction
          .update(endpoints)
          .set({ lifecycleStatus: 'retired', updatedAt: now })
          .where(eq(endpoints.id, variant.endpointId))
      }
    })
    const record = await this.getInventoryRequestVariant(
      input.requestVariantId,
      input.scanId
    )
    if (!record) throw new Error('Request variant disappeared after retirement.')
    return record
  }

  async listInventoryEndpoints(scanId: string): Promise<InventoryEndpoint[]> {
    const endpointRows = await this.database.orm
      .select()
      .from(endpoints)
      .where(eq(endpoints.scanId, scanId))
      .orderBy(asc(endpoints.createdAt))
    return Promise.all(
      endpointRows.map(async (endpoint) => {
        const parameterRows = await this.database.orm
          .select()
          .from(parameters)
          .where(eq(parameters.endpointId, endpoint.id))
          .orderBy(asc(parameters.createdAt))
        return {
          id: endpoint.id,
          method: endpoint.method,
          url: endpoint.normalizedUrl,
          ...(endpoint.contentType ? { contentType: endpoint.contentType } : {}),
          source: endpoint.source,
          parameters: parameterRows.map((parameter) => ({
            id: parameter.id,
            name: parameter.name,
            location: parameter.location as InventoryEndpoint['parameters'][number]['location'],
            ...(parameter.dataType ? { dataType: parameter.dataType } : {}),
            required: parameter.required
          }))
        }
      })
    )
  }

  /**
   * Narrow compatibility projection for the fixed legacy-v1 coordinator.
   * Only reviewed L1 variants are eligible. Producer-controlled source labels
   * and fixture environment labels never grant review. Rejected, retired,
   * non-HTTP, non-query, unsupported custom-header, and non-L1 variants never
   * enter the active path.
   */
  private async listLegacyV1ExecutionSelections(
    scanId: string
  ): Promise<LegacyV1ExecutionBinding[]> {
    const candidateVariants = await this.database.orm
      .select()
      .from(requestVariants)
      .where(
        and(
          eq(requestVariants.scanId, scanId),
          eq(requestVariants.lifecycleStatus, 'active'),
          eq(requestVariants.executionClass, 'active-l1'),
          eq(requestVariants.transport, 'standard-http'),
          eq(requestVariants.codec, 'none'),
          eq(requestVariants.reviewStatus, 'reviewed')
        )
      )
      .orderBy(asc(requestVariants.structureHash), asc(requestVariants.id))
    if (candidateVariants.length === 0) return []
    const candidateVariantIds = candidateVariants.map(({ id }) => id)
    const selectorRows = await this.database.orm
      .select({
        requestVariantId: requestVariantSelectors.requestVariantId,
        selectorJson: requestVariantSelectors.selectorJson
      })
      .from(requestVariantSelectors)
      .where(
        and(
          eq(requestVariantSelectors.scanId, scanId),
          inArray(requestVariantSelectors.requestVariantId, candidateVariantIds)
        )
      )
    type ReviewedQuerySelector = Extract<SelectorRef, { kind: 'query' }>
    const querySelectorsByVariant = new Map<
      string,
      Map<string, ReviewedQuerySelector>
    >(
      candidateVariantIds.map((variantId) => [
        variantId,
        new Map<string, ReviewedQuerySelector>()
      ])
    )
    const ineligibleSelectorVariantIds = new Set<string>()
    for (const row of selectorRows) {
      const parsedSelector = SelectorRefSchema.safeParse(row.selectorJson)
      if (!parsedSelector.success || parsedSelector.data.kind !== 'query') {
        ineligibleSelectorVariantIds.add(row.requestVariantId)
        continue
      }
      const selector = parsedSelector.data
      const selectors =
        querySelectorsByVariant.get(row.requestVariantId) ??
        new Map<string, ReviewedQuerySelector>()
      if (selectors.has(selector.name)) {
        ineligibleSelectorVariantIds.add(row.requestVariantId)
        continue
      }
      selectors.set(selector.name, selector)
      querySelectorsByVariant.set(row.requestVariantId, selectors)
    }
    const sourceRows = await this.database.orm
      .select({
        id: inventorySources.id,
        requestVariantId: inventorySources.requestVariantId,
        type: inventorySources.type,
        discoveredAt: inventorySources.discoveredAt
      })
      .from(inventorySources)
      .where(
        and(
          eq(inventorySources.scanId, scanId),
          eq(inventorySources.reviewStatus, 'reviewed'),
          inArray(inventorySources.requestVariantId, candidateVariantIds)
        )
      )
      .orderBy(asc(inventorySources.discoveredAt), asc(inventorySources.id))
    const reviewedSourceTypeByVariant = new Map<string, string>()
    for (const row of sourceRows) {
      if (!reviewedSourceTypeByVariant.has(row.requestVariantId)) {
        reviewedSourceTypeByVariant.set(row.requestVariantId, row.type)
      }
    }

    // The legacy coordinator has one URL slot per Endpoint.  Select one
    // reviewed variant deterministically instead of combining selectors from
    // several variants or reusing the Endpoint's compatibility preview (which
    // also reflects rejected/retired inventory).
    const selectedVariantByEndpoint = new Map<
      string,
      (typeof candidateVariants)[number]
    >()
    // The coordinator always supplies these two headers. Any other declared
    // header would be silently dropped by the legacy DTO and must fail closed.
    const implicitLegacyHeaderNames = new Set(['accept', 'user-agent'])
    for (const variant of candidateVariants) {
      if (ineligibleSelectorVariantIds.has(variant.id)) continue
      if (
        variant.allowedHeaders.some(
          ({ name }) => !implicitLegacyHeaderNames.has(name)
        )
      ) {
        continue
      }
      if (!reviewedSourceTypeByVariant.has(variant.id)) continue
      if (!selectedVariantByEndpoint.has(variant.endpointId)) {
        selectedVariantByEndpoint.set(variant.endpointId, variant)
      }
    }
    const selectedVariants = [...selectedVariantByEndpoint.values()]
    if (selectedVariants.length === 0) return []
    const executableUrlByEndpoint = new Map(
      selectedVariants.map(({ id, endpointId, redactedPreview }) => [
        endpointId,
        reviewedLegacyExecutionUrl(
          redactedPreview.url,
          new Set(querySelectorsByVariant.get(id)!.keys())
        )
      ] as const)
    )
    const querySelectorsByEndpoint = new Map(
      selectedVariants.map(({ id, endpointId }) => [
        endpointId,
        [...querySelectorsByVariant.get(id)!.values()].sort((left, right) =>
          compareBinary(left.name, right.name)
        )
      ] as const)
    )

    const eligibleEndpointIds = [
      ...selectedVariantByEndpoint.keys()
    ]
    const endpointRows = await this.database.orm
      .select()
      .from(endpoints)
      .where(
        and(
          eq(endpoints.scanId, scanId),
          eq(endpoints.method, 'GET'),
          eq(endpoints.lifecycleStatus, 'active'),
          inArray(endpoints.id, eligibleEndpointIds)
        )
      )
      .orderBy(asc(endpoints.createdAt))

    return Promise.all(
      endpointRows.map(async (endpoint) => {
        const selectedVariant = selectedVariantByEndpoint.get(endpoint.id)
        const reviewedSelectors = querySelectorsByEndpoint.get(endpoint.id) ?? []
        const executableUrl = executableUrlByEndpoint.get(endpoint.id)
        const reviewedSourceType = selectedVariant
          ? reviewedSourceTypeByVariant.get(selectedVariant.id)
          : undefined
        if (!selectedVariant || !executableUrl || !reviewedSourceType) {
          throw new Error('Reviewed legacy request variant lost its executable projection inputs.')
        }
        const parameterRows = await this.database.orm
          .select()
          .from(parameters)
          .where(eq(parameters.endpointId, endpoint.id))
          .orderBy(asc(parameters.createdAt))
        const legacyEndpoint: InventoryEndpoint = {
          id: endpoint.id,
          method: endpoint.method,
          url: executableUrl,
          ...(selectedVariant.contentType
            ? { contentType: selectedVariant.contentType }
            : {}),
          source: reviewedSourceType,
          parameters: reviewedSelectors.map((selector) => {
            const compatibilityReference = parameterRows.find(
              (parameter) =>
                parameter.location === 'query' && parameter.name === selector.name
            )
            if (!compatibilityReference) {
              throw new Error(
                'Reviewed request selector lost its legacy parameter reference.'
              )
            }
            return {
              id: compatibilityReference.id,
              name: selector.name,
              location: 'query' as const,
              dataType: selector.valueType,
              required: selector.required
            }
          })
        }
        return {
          endpoint: legacyEndpoint,
          endpointRecord: mapInventoryEndpointRecord(endpoint),
          requestVariant: mapRequestVariantRecord(
            selectedVariant,
            reviewedSelectors
          )
        }
      })
    )
  }

  async listLegacyV1ExecutionEndpoints(
    scanId: string
  ): Promise<InventoryEndpoint[]> {
    const selections = await this.listLegacyV1ExecutionSelections(scanId)
    return selections.map(({ endpoint }) => endpoint)
  }

  async getLegacyV1ExecutionBinding(
    scanId: string,
    endpointId: string
  ): Promise<LegacyV1ExecutionBinding | undefined> {
    const selections = await this.listLegacyV1ExecutionSelections(scanId)
    const matches = selections.filter(
      ({ endpointRecord }) => endpointRecord.id === endpointId
    )
    if (matches.length > 1) {
      throw new Error('Legacy execution selection is not unique for endpoint.')
    }
    return matches[0]
  }

  async createSignal(input: {
    scanId: string
    interactionId?: string
    family: FindingRecord['family']
    endpointId: string
    parameterId?: string
    identityId?: string
    hypothesis: string
    observedDifference: string
    confidenceHint: number
    evidenceRefs: string[]
    status?: string
  }): Promise<StoredSignalRecord> {
    const row: typeof signals.$inferSelect = {
      id: randomUUID(),
      scanId: input.scanId,
      interactionId: input.interactionId ?? null,
      family: input.family,
      endpointId: input.endpointId,
      parameterId: input.parameterId ?? null,
      identityId: input.identityId ?? null,
      hypothesis: input.hypothesis,
      observedDifference: input.observedDifference,
      confidenceHint: Math.round(Math.max(0, Math.min(1, input.confidenceHint)) * 10_000),
      evidenceRefs: input.evidenceRefs,
      status: input.status ?? 'open',
      createdAt: Date.now()
    }
    await this.database.orm.insert(signals).values(row)
    return mapSignal(row)
  }

  async listSignals(scanId: string): Promise<StoredSignalRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(signals)
      .where(eq(signals.scanId, scanId))
      .orderBy(asc(signals.createdAt))
    return rows.map(mapSignal)
  }

  async ensureConfirmationRule(input: {
    id: string
    version: string
    family: FindingRecord['family']
    rule: Record<string, unknown>
    requiredChecks: string[]
    sourceRefs: string[]
  }): Promise<void> {
    const [existing] = await this.database.orm
      .select({ id: confirmationRules.id })
      .from(confirmationRules)
      .where(
        and(
          eq(confirmationRules.id, input.id),
          eq(confirmationRules.version, input.version)
        )
      )
      .limit(1)
    if (existing) return
    await this.database.orm.insert(confirmationRules).values({
      id: input.id,
      version: input.version,
      family: input.family,
      ruleJson: input.rule,
      requiredChecks: input.requiredChecks,
      sourceRefs: input.sourceRefs,
      createdAt: Date.now()
    })
  }

  async createValidationRun(input: Omit<StoredValidationRun, 'id' | 'createdAt'>): Promise<StoredValidationRun> {
    const row: typeof validationRuns.$inferSelect = {
      id: randomUUID(),
      signalId: input.signalId,
      confirmationRuleId: input.confirmationRuleId,
      confirmationRuleVersion: input.confirmationRuleVersion,
      probeProposalId: input.probeProposalId,
      policyDecisionId: input.policyDecisionId,
      toolCallId: input.toolCallId ?? null,
      baselineRef: input.baselineRef,
      testRef: input.testRef,
      negativeControlRef: input.negativeControlRef ?? null,
      completedChecks: input.completedChecks,
      failedChecks: input.failedChecks,
      missingChecks: input.missingChecks,
      cleanupStatus: input.cleanupStatus,
      result: input.result,
      createdAt: Date.now()
    }
    await this.database.orm.insert(validationRuns).values(row)
    return mapValidation(row)
  }

  async createFinding(input: {
    scanId: string
    family: FindingRecord['family']
    title: string
    verdict: FindingRecord['verdict']
    status?: FindingRecord['status']
    severity: FindingRecord['severity']
    confidence: number
    endpointId?: string
    parameterId?: string
    identityId?: string
    affectedResource?: string
    cwe?: string
    owasp?: string
    confirmationRuleId: string
    confirmationRuleVersion: string
    reproducibility: string
    remediation: string[]
    evidenceRefs: string[]
  }): Promise<FindingRecord> {
    const id = randomUUID()
    const now = Date.now()
    await this.database.orm.transaction(async (transaction) => {
      await transaction.insert(findings).values({
        id,
        scanId: input.scanId,
        family: input.family,
        title: input.title,
        verdict: input.verdict,
        status: input.status ?? 'draft',
        severity: input.severity,
        confidence: Math.round(Math.max(0, Math.min(1, input.confidence)) * 10_000),
        endpointId: input.endpointId ?? null,
        parameterId: input.parameterId ?? null,
        identityId: input.identityId ?? null,
        affectedResource: input.affectedResource ?? null,
        cwe: input.cwe ?? null,
        owasp: input.owasp ?? null,
        confirmationRuleId: input.confirmationRuleId,
        confirmationRuleVersion: input.confirmationRuleVersion,
        reproducibility: input.reproducibility,
        remediationJson: input.remediation,
        firstSeenAt: now,
        lastVerifiedAt: now
      })
      if (input.evidenceRefs.length > 0) {
        await transaction.insert(findingEvidence).values(
          [...new Set(input.evidenceRefs)].map((evidenceId) => ({
            findingId: id,
            evidenceId
          }))
        )
      }
    })
    const finding = await this.getFinding(id)
    if (!finding) throw new Error('Finding disappeared after creation.')
    return finding
  }

  async getFinding(id: string): Promise<FindingRecord | undefined> {
    const findingsForId = await this.listFindings({ id })
    return findingsForId[0]
  }

  async listFindings(filter?: {
    id?: string
    workspaceId?: string
    scanId?: string
    verdict?: FindingRecord['verdict']
    family?: FindingRecord['family']
  }): Promise<FindingRecord[]> {
    const conditions: SQL[] = []
    if (filter?.id) conditions.push(eq(findings.id, filter.id))
    if (filter?.workspaceId) conditions.push(eq(targets.workspaceId, filter.workspaceId))
    if (filter?.scanId) conditions.push(eq(findings.scanId, filter.scanId))
    if (filter?.verdict) conditions.push(eq(findings.verdict, filter.verdict))
    if (filter?.family) conditions.push(eq(findings.family, filter.family))
    const query = this.database.orm
      .select({
        finding: findings,
        endpointUrl: endpoints.normalizedUrl,
        parameterName: parameters.name,
        identityLabel: identities.label
      })
      .from(findings)
      .innerJoin(scans, eq(findings.scanId, scans.id))
      .innerJoin(targets, eq(scans.targetId, targets.id))
      .leftJoin(endpoints, eq(findings.endpointId, endpoints.id))
      .leftJoin(parameters, eq(findings.parameterId, parameters.id))
      .leftJoin(identities, eq(findings.identityId, identities.id))
      .orderBy(desc(findings.lastVerifiedAt))
    const rows = conditions.length > 0 ? await query.where(and(...conditions)) : await query
    return Promise.all(
      rows.map(async (row) => {
        const evidenceRows = await this.database.orm
          .select({ evidenceId: findingEvidence.evidenceId })
          .from(findingEvidence)
          .where(eq(findingEvidence.findingId, row.finding.id))
        return {
          id: row.finding.id,
          scanId: row.finding.scanId,
          family: row.finding.family as FindingRecord['family'],
          title: row.finding.title,
          verdict: row.finding.verdict as FindingRecord['verdict'],
          status: row.finding.status as FindingRecord['status'],
          severity: row.finding.severity as FindingRecord['severity'],
          confidence: row.finding.confidence / 10_000,
          ...(row.endpointUrl ? { endpointUrl: row.endpointUrl } : {}),
          ...(row.parameterName ? { parameterName: row.parameterName } : {}),
          ...(row.identityLabel ? { identityLabel: row.identityLabel } : {}),
          ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
          ...(row.finding.owasp ? { owasp: row.finding.owasp } : {}),
          evidenceRefs: evidenceRows.map((item) => item.evidenceId),
          confirmationRuleId: row.finding.confirmationRuleId,
          confirmationRuleVersion: row.finding.confirmationRuleVersion,
          reproducibility: row.finding.reproducibility,
          remediation: row.finding.remediationJson,
          firstSeenAt: toIso(row.finding.firstSeenAt),
          lastVerifiedAt: toIso(row.finding.lastVerifiedAt)
        }
      })
    )
  }

  async recordModelInvocation(input: {
    agentRunId: string
    profileId: string
    provider: string
    model: string
    promptVersion: string
    inputHashSource: string
    outputHashSource: string
    promptTokens: number
    completionTokens: number
    estimatedCost: number
    durationMs: number
    redactionStatus: string
    source?: 'agent-run' | 'knowledge-extraction' | 'knowledge-review'
  }): Promise<void> {
    const id = randomUUID()
    const createdAt = Date.now()
    await this.database.orm.transaction(async (transaction) => {
      await transaction.insert(modelInvocations).values({
        id,
        agentRunId: input.agentRunId,
        provider: input.provider,
        model: input.model,
        promptVersion: input.promptVersion,
        inputHash: sha256Text(input.inputHashSource),
        outputHash: sha256Text(input.outputHashSource),
        promptTokens: input.promptTokens,
        completionTokens: input.completionTokens,
        estimatedCostMicros: 0,
        durationMs: input.durationMs,
        redactionStatus: input.redactionStatus,
        createdAt
      })
      await transaction.insert(modelProfileUsageEvents).values({
        id,
        profileId: input.profileId,
        source: input.source ?? 'agent-run',
        promptTokens: input.promptTokens,
        completionTokens: input.completionTokens,
        createdAt
      })
    })
  }

  async recordKnowledgeModelInvocation(input: {
    runId: string
    profileId: string
    provider: string
    model: string
    outputHashSource: string
    promptTokens: number
    completionTokens: number
    durationMs: number
    source: 'knowledge-extraction' | 'knowledge-review'
  }): Promise<void> {
    const createdAt = Date.now()
    await this.database.orm.transaction(async (transaction) => {
      await transaction
        .update(knowledgeAgentRuns)
        .set({
          provider: input.provider,
          model: input.model,
          outputHash: sha256Text(input.outputHashSource),
          promptTokens: input.promptTokens,
          completionTokens: input.completionTokens,
          durationMs: input.durationMs
        })
        .where(eq(knowledgeAgentRuns.id, input.runId))
      await transaction.insert(modelProfileUsageEvents).values({
        id: randomUUID(),
        profileId: input.profileId,
        source: input.source,
        promptTokens: input.promptTokens,
        completionTokens: input.completionTokens,
        createdAt
      })
    })
  }

  async recordModelProfileUsage(input: {
    profileId: string
    source: 'agent-run' | 'connection-test' | 'knowledge-extraction' | 'knowledge-review'
    promptTokens: number
    completionTokens: number
  }): Promise<void> {
    await this.database.orm.insert(modelProfileUsageEvents).values({
      id: randomUUID(),
      profileId: input.profileId,
      source: input.source,
      promptTokens: input.promptTokens,
      completionTokens: input.completionTokens,
      createdAt: Date.now()
    })
  }

  async listModelProfileUsage(): Promise<ModelProfileUsageRecord[]> {
    const rows = await this.database.orm
      .select({
        profileId: modelProfileUsageEvents.profileId,
        invocationCount: sql<number>`count(*)`,
        promptTokens: sql<number>`coalesce(sum(${modelProfileUsageEvents.promptTokens}), 0)`,
        completionTokens: sql<number>`coalesce(sum(${modelProfileUsageEvents.completionTokens}), 0)`,
        lastUsedAt: sql<number | null>`max(${modelProfileUsageEvents.createdAt})`
      })
      .from(modelProfileUsageEvents)
      .groupBy(modelProfileUsageEvents.profileId)
    return rows.map((row) => {
      const promptTokens = Number(row.promptTokens)
      const completionTokens = Number(row.completionTokens)
      return {
        profileId: row.profileId,
        invocationCount: Number(row.invocationCount),
        promptTokens,
        completionTokens,
        totalTokens: promptTokens + completionTokens,
        ...(row.lastUsedAt ? { lastUsedAt: toIso(Number(row.lastUsedAt)) } : {})
      }
    })
  }

  async listModelProfiles(): Promise<ModelProfileRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(modelProfiles)
      .orderBy(asc(modelProfiles.agentRole), desc(modelProfiles.updatedAt))
    return rows.map(mapModelProfile)
  }

  async getModelProfile(id: string): Promise<ModelProfileRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(modelProfiles)
      .where(eq(modelProfiles.id, id))
      .limit(1)
    return row ? mapModelProfile(row) : undefined
  }

  async getPreferredModelProfile(role: ModelProfileRecord['agentRole']): Promise<ModelProfileRecord | undefined> {
    const rows = await this.listModelProfiles()
    const matching = rows.filter((profile) => profile.agentRole === role)
    return matching.find((profile) => profile.provider === 'openai-compatible') ?? matching[0]
  }

  async saveModelProfile(
    input: SaveModelProfileInput,
    credentialId?: string | null
  ): Promise<ModelProfileRecord> {
    const now = Date.now()
    if (input.id) {
      const [existing] = await this.database.orm
        .select()
        .from(modelProfiles)
        .where(eq(modelProfiles.id, input.id))
        .limit(1)
      if (!existing) throw new Error('模型 Profile 不存在。')
      await this.database.orm
        .update(modelProfiles)
        .set({
          name: input.name,
          agentRole: input.agentRole,
          provider: input.provider,
          baseUrl: input.baseUrl ?? null,
          model: input.model,
          credentialId: credentialId === undefined ? existing.credentialId : credentialId,
          timeoutMs: input.timeoutMs,
          rpmLimit: input.rpmLimit,
          tpmLimit: input.tpmLimit,
          tokenBudget: input.tokenBudget,
          costBudgetMicros: Math.round(input.costBudget * 1_000_000),
          updatedAt: now
        })
        .where(eq(modelProfiles.id, input.id))
      const updated = await this.getModelProfile(input.id)
      if (!updated) throw new Error('模型 Profile 更新后无法读取。')
      return updated
    }

    const id = randomUUID()
    await this.database.orm.insert(modelProfiles).values({
      id,
      name: input.name,
      agentRole: input.agentRole,
      provider: input.provider,
      baseUrl: input.baseUrl ?? null,
      model: input.model,
      credentialId: credentialId ?? null,
      timeoutMs: input.timeoutMs,
      rpmLimit: input.rpmLimit,
      tpmLimit: input.tpmLimit,
      tokenBudget: input.tokenBudget,
      costBudgetMicros: Math.round(input.costBudget * 1_000_000),
      createdAt: now,
      updatedAt: now
    })
    const created = await this.getModelProfile(id)
    if (!created) throw new Error('模型 Profile 创建后无法读取。')
    return created
  }

  async deleteModelProfile(id: string): Promise<boolean> {
    const result = await this.database.orm
      .delete(modelProfiles)
      .where(eq(modelProfiles.id, id))
      .returning({ id: modelProfiles.id })
    return result.length > 0
  }

  async listMcpServers(): Promise<McpServerRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(mcpServers)
      .orderBy(desc(mcpServers.enabled), asc(mcpServers.name))
    return rows.map(mapMcpServer)
  }

  async getMcpServer(id: string): Promise<McpServerRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(mcpServers)
      .where(eq(mcpServers.id, id))
      .limit(1)
    return row ? mapMcpServer(row) : undefined
  }

  async saveMcpServer(
    input: {
      id?: string
      name: string
      transport: McpServerRecord['transport']
      enabled: boolean
      command?: string
      args: string[]
      cwd?: string
      url?: string
      authType: McpServerRecord['authType']
      authHeaderName?: string
      environmentKeys: string[]
      headerNames: string[]
      timeoutMs: number
      roots: string[]
      allowedAgentRoles: AgentRole[]
      riskLabels: McpServerRecord['riskLabels']
    },
    credentialId?: string | null
  ): Promise<McpServerRecord> {
    const now = Date.now()
    const configJson = {
      ...(input.command ? { command: input.command } : {}),
      args: input.args,
      ...(input.cwd ? { cwd: input.cwd } : {}),
      ...(input.url ? { url: input.url } : {}),
      authType: input.authType,
      ...(input.authHeaderName ? { authHeaderName: input.authHeaderName } : {}),
      environmentKeys: input.environmentKeys,
      headerNames: input.headerNames,
      timeoutMs: input.timeoutMs,
      roots: input.roots
    }
    const discoveryJson = { tools: [], resources: [], prompts: [] }
    if (input.id) {
      const [existing] = await this.database.orm
        .select()
        .from(mcpServers)
        .where(eq(mcpServers.id, input.id))
        .limit(1)
      if (!existing) throw new Error('MCP Server 配置不存在。')
      await this.database.orm
        .update(mcpServers)
        .set({
          name: input.name,
          transport: input.transport,
          enabled: input.enabled,
          credentialId: credentialId === undefined ? existing.credentialId : credentialId,
          configJson,
          allowedAgentRoles: input.allowedAgentRoles,
          riskLabels: input.riskLabels,
          status: input.enabled ? 'untested' : 'disabled',
          discoveryJson,
          lastTestedAt: null,
          lastError: null,
          updatedAt: now
        })
        .where(eq(mcpServers.id, input.id))
      const updated = await this.getMcpServer(input.id)
      if (!updated) throw new Error('MCP Server 配置更新后无法读取。')
      return updated
    }

    const id = randomUUID()
    const row: typeof mcpServers.$inferSelect = {
      id,
      name: input.name,
      transport: input.transport,
      enabled: input.enabled,
      credentialId: credentialId ?? null,
      configJson,
      allowedAgentRoles: input.allowedAgentRoles,
      riskLabels: input.riskLabels,
      status: input.enabled ? 'untested' : 'disabled',
      discoveryJson,
      lastTestedAt: null,
      lastError: null,
      createdAt: now,
      updatedAt: now
    }
    await this.database.orm.insert(mcpServers).values(row)
    return mapMcpServer(row)
  }

  async updateMcpServerTestResult(
    id: string,
    result: McpConnectionTestResult
  ): Promise<McpServerRecord> {
    await this.database.orm
      .update(mcpServers)
      .set({
        status: result.ok ? 'ready' : 'error',
        discoveryJson: {
          ...(result.protocolVersion ? { protocolVersion: result.protocolVersion } : {}),
          ...(result.serverName ? { serverName: result.serverName } : {}),
          ...(result.serverVersion ? { serverVersion: result.serverVersion } : {}),
          tools: result.tools,
          resources: result.resources,
          prompts: result.prompts
        },
        lastTestedAt: Date.now(),
        lastError: result.ok ? null : result.message,
        updatedAt: Date.now()
      })
      .where(eq(mcpServers.id, id))
    const updated = await this.getMcpServer(id)
    if (!updated) throw new Error('MCP Server 配置不存在。')
    return updated
  }

  async deleteMcpServer(id: string): Promise<boolean> {
    const result = await this.database.orm
      .delete(mcpServers)
      .where(eq(mcpServers.id, id))
      .returning({ id: mcpServers.id })
    return result.length > 0
  }

  async createReport(input: {
    scanId: string
    title: string
    format: ReportRecord['format']
    sha256: string
    redacted: boolean
    contentRef: string
  }): Promise<StoredReportRecord> {
    const expectedContentByFormat = {
      markdown: {
        type: 'report-markdown',
        mimeType: 'text/markdown'
      },
      json: {
        type: 'report-json',
        mimeType: 'application/json'
      },
      html: {
        type: 'report-html',
        mimeType: 'text/html'
      }
    } as const
    if (
      input.redacted !== true ||
      !['markdown', 'json', 'html'].includes(input.format) ||
      !/^[0-9a-f]{64}$/u.test(input.sha256)
    ) {
      throw new Error('Report persistence requires a redacted valid artifact.')
    }
    return this.database.orm.transaction(
      async (transaction) => {
        const [content] = await transaction
          .select({
            evidence: evidenceItems,
            protectedEvidenceId: protectedEvidenceItems.evidenceId
          })
          .from(evidenceItems)
          .leftJoin(
            protectedEvidenceItems,
            eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
          )
          .where(eq(evidenceItems.id, input.contentRef))
          .limit(1)
        if (
          !content ||
          content.evidence.scanId !== input.scanId ||
          content.protectedEvidenceId !== null ||
          content.evidence.redactionState !== 'redacted' ||
          content.evidence.integrityStatus !== 'verified' ||
          content.evidence.type !==
            expectedContentByFormat[input.format].type ||
          content.evidence.mimeType !==
            expectedContentByFormat[input.format].mimeType ||
          content.evidence.sha256 !== input.sha256
        ) {
          throw new Error(
            'Report content must be an exact redacted, unprotected scan artifact.'
          )
        }
        const row: typeof reports.$inferSelect = {
          id: randomUUID(),
          scanId: input.scanId,
          title: input.title,
          format: input.format,
          filePath: null,
          sha256: input.sha256,
          redacted: true,
          contentRef: input.contentRef,
          createdAt: Date.now()
        }
        await transaction.insert(reports).values(row)
        return mapReport(row)
      },
      { behavior: 'immediate' }
    )
  }

  async listReports(scanId: string): Promise<ReportRecord[]> {
    const rows = await this.database.orm
      .select()
      .from(reports)
      .where(eq(reports.scanId, scanId))
      .orderBy(desc(reports.createdAt))
    return rows.map(mapReport)
  }

  async getReport(id: string): Promise<StoredReportRecord | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(reports)
      .where(eq(reports.id, id))
      .limit(1)
    return row ? mapReport(row) : undefined
  }

  async markReportExported(id: string, filePath: string): Promise<void> {
    await this.database.orm.transaction(
      async (transaction) => {
        const [binding] = await transaction
          .select({
            report: reports,
            evidence: evidenceItems,
            protectedEvidenceId: protectedEvidenceItems.evidenceId
          })
          .from(reports)
          .innerJoin(
            evidenceItems,
            eq(reports.contentRef, evidenceItems.id)
          )
          .leftJoin(
            protectedEvidenceItems,
            eq(protectedEvidenceItems.evidenceId, evidenceItems.id)
          )
          .where(eq(reports.id, id))
          .limit(1)
        const expectedContentByFormat = {
          markdown: {
            type: 'report-markdown',
            mimeType: 'text/markdown'
          },
          json: {
            type: 'report-json',
            mimeType: 'application/json'
          },
          html: {
            type: 'report-html',
            mimeType: 'text/html'
          }
        } as const
        if (
          !binding ||
          binding.report.redacted !== true ||
          !['markdown', 'json', 'html'].includes(
            binding.report.format
          )
        ) {
          throw new Error('Only redacted valid reports can be exported.')
        }
        const format =
          binding.report.format as keyof typeof expectedContentByFormat
        const expected = expectedContentByFormat[format]
        if (
          binding.evidence.scanId !== binding.report.scanId ||
          binding.protectedEvidenceId !== null ||
          binding.evidence.redactionState !== 'redacted' ||
          binding.evidence.integrityStatus !== 'verified' ||
          binding.evidence.type !== expected.type ||
          binding.evidence.mimeType !== expected.mimeType ||
          binding.evidence.sha256 !== binding.report.sha256
        ) {
          throw new Error(
            'Report export requires an exact redacted, unprotected scan artifact.'
          )
        }
        const updated = await transaction
          .update(reports)
          .set({ filePath })
          .where(eq(reports.id, id))
          .returning({ id: reports.id })
        if (updated.length !== 1) {
          throw new Error('Report disappeared before export.')
        }
      },
      { behavior: 'immediate' }
    )
  }

  async addAuditLog(input: {
    workspaceId: string
    scanId?: string
    event: string
    actor: string
    detail: Record<string, unknown>
  }): Promise<AuditLogRecord> {
    const row: typeof auditLogs.$inferSelect = {
      id: randomUUID(),
      workspaceId: input.workspaceId,
      scanId: input.scanId ?? null,
      event: input.event,
      actor: input.actor,
      detailJson: input.detail,
      createdAt: Date.now()
    }
    await this.database.orm.insert(auditLogs).values(row)
    return mapAudit(row)
  }

  async listAuditLogs(input: {
    workspaceId: string
    scanId?: string
    limit?: number
  }): Promise<AuditLogRecord[]> {
    const condition = input.scanId
      ? and(
          eq(auditLogs.workspaceId, input.workspaceId),
          eq(auditLogs.scanId, input.scanId)
        )
      : eq(auditLogs.workspaceId, input.workspaceId)
    const rows = await this.database.orm
      .select()
      .from(auditLogs)
      .where(condition)
      .orderBy(desc(auditLogs.createdAt))
      .limit(input.limit ?? 100)
    return rows.map(mapAudit)
  }

  async getDashboardSnapshot(workspaceId?: string): Promise<DashboardSnapshot> {
    const workspaceCondition = workspaceId ? eq(workspaces.id, workspaceId) : undefined
    const targetCondition = workspaceId ? eq(targets.workspaceId, workspaceId) : undefined
    const scanCondition = workspaceId ? eq(targets.workspaceId, workspaceId) : undefined
    const findingCondition = workspaceId ? eq(targets.workspaceId, workspaceId) : undefined

    const workspaceCountRows = workspaceCondition
      ? await this.database.orm
          .select({ count: sql<number>`count(*)` })
          .from(workspaces)
          .where(workspaceCondition)
      : await this.database.orm.select({ count: sql<number>`count(*)` }).from(workspaces)
    const targetCountRows = targetCondition
      ? await this.database.orm
          .select({ count: sql<number>`count(*)` })
          .from(targets)
          .where(targetCondition)
      : await this.database.orm.select({ count: sql<number>`count(*)` }).from(targets)
    const activeScanRows = await this.database.orm
      .select({ count: sql<number>`count(*)` })
      .from(scans)
      .innerJoin(targets, eq(scans.targetId, targets.id))
      .where(
        and(
          inArray(scans.status, ['queued', 'running', 'paused', 'awaiting-user']),
          ...(scanCondition ? [scanCondition] : [])
        )
      )
    const confirmedRows = await this.database.orm
      .select({ count: sql<number>`count(*)` })
      .from(findings)
      .innerJoin(scans, eq(findings.scanId, scans.id))
      .innerJoin(targets, eq(scans.targetId, targets.id))
      .where(
        and(eq(findings.verdict, 'confirmed'), ...(findingCondition ? [findingCondition] : []))
      )

    const recentScans = await this.listScans({ workspaceId, limit: 5 })
    const recentFindingRows = await this.database.orm
      .select({
        finding: findings,
        endpointUrl: sql<string | null>`(
          SELECT normalized_url FROM endpoints WHERE endpoints.id = findings.endpoint_id
        )`,
        parameterName: sql<string | null>`(
          SELECT name FROM parameters WHERE parameters.id = findings.parameter_id
        )`,
        identityLabel: sql<string | null>`(
          SELECT label FROM identities WHERE identities.id = findings.identity_id
        )`
      })
      .from(findings)
      .innerJoin(scans, eq(findings.scanId, scans.id))
      .innerJoin(targets, eq(scans.targetId, targets.id))
      .where(findingCondition)
      .orderBy(desc(findings.lastVerifiedAt))
      .limit(5)

    const recentFindings = await Promise.all(
      recentFindingRows.map(async (row) => {
        const evidence = await this.database.orm
          .select({ evidenceId: findingEvidence.evidenceId })
          .from(findingEvidence)
          .where(eq(findingEvidence.findingId, row.finding.id))
        return {
          id: row.finding.id,
          scanId: row.finding.scanId,
          family: row.finding.family as DashboardSnapshot['recentFindings'][number]['family'],
          title: row.finding.title,
          verdict: row.finding.verdict as DashboardSnapshot['recentFindings'][number]['verdict'],
          status: row.finding.status as DashboardSnapshot['recentFindings'][number]['status'],
          severity: row.finding.severity as DashboardSnapshot['recentFindings'][number]['severity'],
          confidence: row.finding.confidence / 10_000,
          ...(row.endpointUrl ? { endpointUrl: row.endpointUrl } : {}),
          ...(row.parameterName ? { parameterName: row.parameterName } : {}),
          ...(row.identityLabel ? { identityLabel: row.identityLabel } : {}),
          ...(row.finding.cwe ? { cwe: row.finding.cwe } : {}),
          ...(row.finding.owasp ? { owasp: row.finding.owasp } : {}),
          evidenceRefs: evidence.map((item) => item.evidenceId),
          confirmationRuleId: row.finding.confirmationRuleId,
          confirmationRuleVersion: row.finding.confirmationRuleVersion,
          reproducibility: row.finding.reproducibility,
          remediation: row.finding.remediationJson,
          firstSeenAt: toIso(row.finding.firstSeenAt),
          lastVerifiedAt: toIso(row.finding.lastVerifiedAt)
        }
      })
    )

    return {
      workspaceCount: workspaceCountRows[0]?.count ?? 0,
      targetCount: targetCountRows[0]?.count ?? 0,
      activeScanCount: activeScanRows[0]?.count ?? 0,
      confirmedFindingCount: confirmedRows[0]?.count ?? 0,
      recentScans,
      recentFindings
    }
  }
}
