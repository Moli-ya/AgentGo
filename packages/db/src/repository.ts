import { createHash, randomUUID } from 'node:crypto'
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
  AuditLogRecord,
  AgentRole,
  CreateScanInput,
  CreateTargetInput,
  CreateWorkspaceInput,
  DashboardSnapshot,
  FindingRecord,
  IdentityRecord,
  InventoryEndpoint,
  ModelProfileRecord,
  PolicyDecision,
  ProbeAction,
  ReportRecord,
  SaveModelProfileInput,
  SaveIdentityInput,
  ScanEvent,
  ScanRecord,
  TargetRecord,
  TargetScope,
  TargetScopeRecord,
  UpdateTargetInput,
  WorkspaceRecord
} from '@agentgo/contracts'
import type { AgentGoDatabase } from './database'
import {
  agentRuns,
  auditLogs,
  confirmationRules,
  endpoints,
  findingEvidence,
  findings,
  identities,
  interactions,
  knowledgeChunks,
  knowledgeDocs,
  modelInvocations,
  modelProfiles,
  pages,
  parameters,
  policyDecisions,
  probeProposals,
  reports,
  scanCheckpoints,
  scanEvents,
  scanIdentities,
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
type ScanRow = typeof scans.$inferSelect
type ScanEventRow = typeof scanEvents.$inferSelect
type AuditRow = typeof auditLogs.$inferSelect

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

export interface StoredPolicyDecision extends PolicyDecision {
  id: string
  proposalId: string
  scopeSnapshotId: string
  approvedBy?: string
  approvedAt?: string
  validUntil?: string
  createdAt: string
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

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableValue)
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
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

function normalizedInventoryUrl(value: string): string {
  const url = new URL(value)
  url.hash = ''
  const sorted = [...url.searchParams.entries()].sort(([leftName, leftValue], [rightName, rightValue]) =>
    leftName === rightName
      ? leftValue.localeCompare(rightValue)
      : leftName.localeCompare(rightName)
  )
  url.search = ''
  for (const [name, parameterValue] of sorted) url.searchParams.append(name, parameterValue)
  return url.toString()
}

function scopeSnapshotHash(scope: Omit<TargetScope, 'id'>): string {
  return sha256Text(stableJson(scope))
}

export class AgentGoRepository {
  constructor(private readonly database: AgentGoDatabase) {}

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

  async createTarget(input: CreateTargetInput): Promise<{
    target: TargetRecord
    scope: TargetScopeRecord
  }> {
    const now = Date.now()
    const targetId = randomUUID()
    const scopeId = randomUUID()
    const parsedBaseUrl = new URL(input.baseUrl)
    parsedBaseUrl.hash = ''
    const normalizedBaseUrl = parsedBaseUrl.toString()
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
      snapshotHash,
      createdAt: now
    }

    await this.database.orm.transaction(async (transaction) => {
      await transaction.insert(targets).values(targetRow)
      await transaction.insert(targetScopes).values(scopeRow)
    })
    await this.addAuditLog({
      workspaceId: input.workspaceId,
      event: 'target.created',
      actor: 'user',
      detail: {
        targetId,
        baseUrl: normalizedBaseUrl,
        scopeSnapshotId: scopeId,
        authorizationReference: input.authorizationReference
      }
    })

    return { target: mapTarget(targetRow), scope: mapScope(scopeRow) }
  }

  async updateTarget(input: UpdateTargetInput): Promise<{
    target: TargetRecord
    scope?: TargetScopeRecord
  }> {
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
      const url = new URL(input.baseUrl)
      url.hash = ''
      patch.baseUrl = url.toString()
    }

    await this.database.orm.update(targets).set(patch).where(eq(targets.id, input.id))

    let createdScope: TargetScopeRecord | undefined
    if (input.scope) {
      const scopeValue: Omit<TargetScope, 'id'> = {
        ...input.scope,
        authorizationReference:
          input.scope.authorizationReference ??
          input.authorizationReference ??
          current.authorizationReference
      }
      const hash = scopeSnapshotHash(scopeValue)
      const [existing] = await this.database.orm
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
          snapshotHash: hash,
          createdAt: now
        }
        await this.database.orm.insert(targetScopes).values(row)
        createdScope = mapScope(row)
      }
    }

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
        scopeSnapshotId: createdScope?.id ?? null
      }
    })
    return { target: updated, ...(createdScope ? { scope: createdScope } : {}) }
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
      .select()
      .from(targetScopes)
      .where(eq(targetScopes.targetId, targetId))
      .orderBy(desc(targetScopes.createdAt))
      .limit(1)
    return row ? mapScope(row) : undefined
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

  async createScan(
    input: CreateScanInput,
    plan: Record<string, unknown>,
    runtime: Record<string, unknown>
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
      await transaction.insert(scanEvents).values({
        id: randomUUID(),
        scanId: id,
        type: 'status',
        level: 'info',
        message: '扫描草稿已创建，等待用户启动。',
        detailJson: {
          scopeSnapshotId: scope.id,
          families: input.families,
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
  }): Promise<StoredPolicyDecision> {
    const now = Date.now()
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
      createdAt: now
    }
    await this.database.orm.insert(policyDecisions).values(row)
    return mapPolicyDecision(row)
  }

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

  async upsertPage(input: {
    scanId: string
    url: string
    title?: string
    depth: number
    discoveredFrom?: string
    stateHash?: string
    status?: string
  }): Promise<InventoryPageRecord> {
    const url = normalizedInventoryUrl(input.url)
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
          title: input.title ?? existing.title,
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
      title: input.title ?? null,
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

  async upsertEndpoint(input: {
    scanId: string
    pageId?: string
    method: string
    url: string
    urlTemplate?: string
    contentType?: string
    source: string
    status?: string
  }): Promise<{ id: string; url: string }> {
    const normalizedUrl = normalizedInventoryUrl(input.url)
    const method = input.method.toUpperCase()
    const [existing] = await this.database.orm
      .select()
      .from(endpoints)
      .where(
        and(
          eq(endpoints.scanId, input.scanId),
          eq(endpoints.method, method),
          eq(endpoints.normalizedUrl, normalizedUrl)
        )
      )
      .limit(1)
    const now = Date.now()
    if (existing) {
      await this.database.orm
        .update(endpoints)
        .set({
          pageId: input.pageId ?? existing.pageId,
          contentType: input.contentType ?? existing.contentType,
          source: input.source,
          status: input.status ?? existing.status,
          updatedAt: now
        })
        .where(eq(endpoints.id, existing.id))
      return { id: existing.id, url: normalizedUrl }
    }

    const id = randomUUID()
    await this.database.orm.insert(endpoints).values({
      id,
      scanId: input.scanId,
      pageId: input.pageId ?? null,
      method,
      urlTemplate: input.urlTemplate ?? normalizedUrl,
      normalizedUrl,
      contentType: input.contentType ?? null,
      source: input.source,
      status: input.status ?? 'discovered',
      createdAt: now,
      updatedAt: now
    })
    return { id, url: normalizedUrl }
  }

  async upsertParameter(input: {
    endpointId: string
    name: string
    location: InventoryEndpoint['parameters'][number]['location']
    dataType?: string
    required?: boolean
    exampleMasked?: string
  }): Promise<string> {
    const [existing] = await this.database.orm
      .select()
      .from(parameters)
      .where(
        and(
          eq(parameters.endpointId, input.endpointId),
          eq(parameters.name, input.name),
          eq(parameters.location, input.location)
        )
      )
      .limit(1)
    if (existing) return existing.id
    const id = randomUUID()
    await this.database.orm.insert(parameters).values({
      id,
      endpointId: input.endpointId,
      name: input.name,
      location: input.location,
      dataType: input.dataType ?? null,
      required: input.required ?? false,
      exampleMasked: input.exampleMasked ?? null,
      createdAt: Date.now()
    })
    return id
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
  }): Promise<void> {
    await this.database.orm.insert(modelInvocations).values({
      id: randomUUID(),
      agentRunId: input.agentRunId,
      provider: input.provider,
      model: input.model,
      promptVersion: input.promptVersion,
      inputHash: sha256Text(input.inputHashSource),
      outputHash: sha256Text(input.outputHashSource),
      promptTokens: input.promptTokens,
      completionTokens: input.completionTokens,
      estimatedCostMicros: Math.round(input.estimatedCost * 1_000_000),
      durationMs: input.durationMs,
      redactionStatus: input.redactionStatus,
      createdAt: Date.now()
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

  async createReport(input: {
    scanId: string
    title: string
    format: ReportRecord['format']
    sha256: string
    redacted: boolean
    contentRef: string
  }): Promise<StoredReportRecord> {
    const row: typeof reports.$inferSelect = {
      id: randomUUID(),
      scanId: input.scanId,
      title: input.title,
      format: input.format,
      filePath: null,
      sha256: input.sha256,
      redacted: input.redacted,
      contentRef: input.contentRef,
      createdAt: Date.now()
    }
    await this.database.orm.insert(reports).values(row)
    return mapReport(row)
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
    await this.database.orm
      .update(reports)
      .set({ filePath })
      .where(eq(reports.id, id))
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
