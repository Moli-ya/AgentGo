import { randomUUID } from 'node:crypto'
import { desc, eq } from 'drizzle-orm'
import {
  BrowserReconObservationSchema,
  DependencyEdgeCandidateSchema,
  DependencyGraphSchema,
  InventoryMergeReportSchema,
  type BrowserReconObservation,
  type DependencyEdgeCandidate,
  type DependencyGraph,
  type InventoryMergeReport
} from '@agentgo/contracts'
import type { AgentGoDatabase } from './database'
import {
  browserReconObservations,
  dependencyEdgeCandidates,
  dependencyGraphs,
  inventoryMergeReports
} from './schema'

function epochMs(iso: string): number {
  const value = Date.parse(iso)
  if (!Number.isFinite(value)) {
    throw new TypeError('Discovery-runtime timestamp is not a valid ISO-8601 instant.')
  }
  return value
}

export class DiscoveryRuntimeRepository {
  constructor(private readonly database: AgentGoDatabase) {}

  async saveMergeReport(report: InventoryMergeReport): Promise<InventoryMergeReport> {
    const parsed = InventoryMergeReportSchema.parse(report)
    await this.database.orm.insert(inventoryMergeReports).values({
      reportId: parsed.reportId,
      scanId: parsed.scanId,
      scopeSnapshotId: parsed.scopeSnapshotId,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt)
    })
    return parsed
  }

  async listMergeReports(scanId: string): Promise<InventoryMergeReport[]> {
    const rows = await this.database.orm
      .select()
      .from(inventoryMergeReports)
      .where(eq(inventoryMergeReports.scanId, scanId))
      .orderBy(desc(inventoryMergeReports.createdAt))
    return rows.map((row) => InventoryMergeReportSchema.parse(row.payloadJson))
  }

  async saveDependencyGraph(graph: DependencyGraph): Promise<DependencyGraph> {
    const parsed = DependencyGraphSchema.parse(graph)
    await this.database.orm.insert(dependencyGraphs).values({
      graphId: parsed.graphId,
      graphHash: parsed.graphHash,
      scanId: parsed.scanId,
      scopeSnapshotId: parsed.scopeSnapshotId,
      frozen: parsed.frozen,
      paused: parsed.paused,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt)
    })
    return parsed
  }

  async getLatestDependencyGraph(scanId: string): Promise<DependencyGraph | undefined> {
    const [row] = await this.database.orm
      .select()
      .from(dependencyGraphs)
      .where(eq(dependencyGraphs.scanId, scanId))
      .orderBy(desc(dependencyGraphs.createdAt))
      .limit(1)
    return row ? DependencyGraphSchema.parse(row.payloadJson) : undefined
  }

  async saveDependencyEdgeCandidate(
    candidate: DependencyEdgeCandidate
  ): Promise<DependencyEdgeCandidate> {
    const parsed = DependencyEdgeCandidateSchema.parse(candidate)
    await this.database.orm.insert(dependencyEdgeCandidates).values({
      candidateId: randomUUID(),
      scanId: parsed.scanId,
      payloadJson: parsed,
      reviewStatus: 'unreviewed',
      createdAt: Date.now()
    })
    return parsed
  }

  async listUnreviewedDependencyCandidates(
    scanId: string
  ): Promise<readonly DependencyEdgeCandidate[]> {
    const rows = await this.database.orm
      .select()
      .from(dependencyEdgeCandidates)
      .where(eq(dependencyEdgeCandidates.scanId, scanId))
    return rows
      .filter((row) => row.reviewStatus === 'unreviewed')
      .map((row) => DependencyEdgeCandidateSchema.parse(row.payloadJson))
  }

  async saveBrowserReconObservation(
    observation: BrowserReconObservation
  ): Promise<BrowserReconObservation> {
    const parsed = BrowserReconObservationSchema.parse(observation)
    await this.database.orm.insert(browserReconObservations).values({
      observationId: parsed.observationId,
      scanId: parsed.scanId,
      payloadJson: parsed,
      createdAt: epochMs(parsed.createdAt)
    })
    return parsed
  }

  async listBrowserReconObservations(
    scanId: string
  ): Promise<BrowserReconObservation[]> {
    const rows = await this.database.orm
      .select()
      .from(browserReconObservations)
      .where(eq(browserReconObservations.scanId, scanId))
      .orderBy(desc(browserReconObservations.createdAt))
    return rows.map((row) => BrowserReconObservationSchema.parse(row.payloadJson))
  }
}
