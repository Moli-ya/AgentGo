import { randomUUID } from 'node:crypto'
import {
  DependencyEdgeCandidateSchema,
  DependencyGraphSchema,
  type DependencyEdge,
  type DependencyEdgeCandidate,
  type DependencyGraph,
  type DependencyIssue,
  type DependencyNode,
  type ExtractionRule
} from '@agentgo/contracts'
import { stableInventoryHash } from '@agentgo/domain'
import {
  DiscoveryRuntimeRepository,
  ImportDiscoveryRepository
} from '@agentgo/db'

export class DependencyGraphService {
  constructor(
    private readonly discovery: ImportDiscoveryRepository,
    private readonly runtime: DiscoveryRuntimeRepository
  ) {}

  async buildFromFrozenRules(input: {
    readonly scanId: string
    readonly scopeSnapshotId: string
  }): Promise<DependencyGraph> {
    const rules = await this.discovery.listFrozenExtractionRules(input.scanId)
    return this.persist(this.graphFromRules(input.scanId, input.scopeSnapshotId, rules))
  }

  proposeEdge(candidate: unknown): Promise<DependencyEdgeCandidate> {
    return this.runtime.saveDependencyEdgeCandidate(
      DependencyEdgeCandidateSchema.parse(candidate)
    )
  }

  graphFromRules(
    scanId: string,
    scopeSnapshotId: string,
    rules: readonly ExtractionRule[]
  ): DependencyGraph {
    const nodes = new Map<string, DependencyNode>()
    const edges: DependencyEdge[] = []
    const issues: DependencyIssue[] = []
    const adjacency = new Map<string, string[]>()

    const ensureNode = (node: DependencyNode): void => {
      if (!nodes.has(node.nodeId)) nodes.set(node.nodeId, node)
    }

    for (const rule of rules) {
      if (!rule.frozen || rule.reviewStatus !== 'reviewed') {
        issues.push({
          code: 'unfrozen-rule',
          message: 'Extraction rule is not frozen and reviewed.'
        })
        continue
      }
      const sourceId = `var.${rule.name}`
      const targetId = `var.${rule.targetVariable}`
      ensureNode({
        nodeId: sourceId,
        kind: 'request-variable',
        label: rule.name,
        ruleId: rule.ruleId,
        ...(rule.identityScope ? { identityScope: rule.identityScope } : {}),
        ...(rule.tenantScope ? { tenantScope: rule.tenantScope } : {}),
        secretClassification: rule.secretClassification,
        ...(rule.sourceRef ? { evidenceRef: rule.sourceRef } : {})
      })
      ensureNode({
        nodeId: targetId,
        kind: rule.valueType === 'string' && rule.targetVariable.startsWith('csrf.')
          ? 'csrf'
          : rule.targetVariable.startsWith('session.')
            ? 'identity-session'
            : 'request-variable',
        label: rule.targetVariable,
        ruleId: rule.ruleId,
        ...(rule.identityScope ? { identityScope: rule.identityScope } : {}),
        ...(rule.tenantScope ? { tenantScope: rule.tenantScope } : {}),
        secretClassification: 'none'
      })
      const edge: DependencyEdge = {
        edgeId: `edge.${rule.name}.${rule.targetVariable}`,
        fromNodeId: sourceId,
        toNodeId: targetId,
        ruleId: rule.ruleId,
        ruleHash: rule.ruleHash,
        ruleVersion: rule.version,
        sourceRef: rule.sourceRef
      }
      edges.push(edge)
      adjacency.set(sourceId, [...(adjacency.get(sourceId) ?? []), targetId])
      if (
        rule.secretClassification === 'likely-secret' &&
        !rule.targetVariable.startsWith('session.')
      ) {
        issues.push({
          code: 'secret-sink-mismatch',
          edgeId: edge.edgeId,
          message: 'Secret-classified extraction cannot target a non-secret sink.'
        })
      }
    }

    const identityScopes = new Set(
      rules
        .filter((rule) => rule.frozen && rule.reviewStatus === 'reviewed')
        .map((rule) => rule.identityScope)
        .filter((value): value is string => Boolean(value))
    )
    if (identityScopes.size > 1) {
      issues.push({
        code: 'cross-identity',
        message: 'Dependency graph mixes more than one identity scope.'
      })
    }
    const tenantScopes = new Set(
      rules
        .filter((rule) => rule.frozen && rule.reviewStatus === 'reviewed')
        .map((rule) => rule.tenantScope)
        .filter((value): value is string => Boolean(value))
    )
    if (tenantScopes.size > 1) {
      issues.push({
        code: 'cross-tenant',
        message: 'Dependency graph mixes more than one tenant scope.'
      })
    }

    for (const cycleNode of detectCycles(adjacency)) {
      issues.push({
        code: 'cycle',
        nodeId: cycleNode,
        message: 'Frozen extraction rules form a dependency cycle.'
      })
    }

    const produced = new Set(edges.map((edge) => edge.toNodeId))
    for (const node of nodes.values()) {
      if (node.kind === 'request-variable' && !produced.has(node.nodeId) && !edges.some((edge) => edge.fromNodeId === node.nodeId)) {
        issues.push({
          code: 'missing-value',
          nodeId: node.nodeId,
          message: 'Request variable has no frozen producer.'
        })
      }
    }

    const unsigned = {
      schemaVersion: 'agentgo.dependency-graph.v1' as const,
      graphId: randomUUID(),
      scanId,
      scopeSnapshotId,
      frozen: true,
      nodes: [...nodes.values()],
      edges,
      issues,
      paused: issues.length > 0,
      createdAt: new Date().toISOString()
    }
    return DependencyGraphSchema.parse({
      ...unsigned,
      graphHash: stableInventoryHash(unsigned)
    })
  }

  private persist(graph: DependencyGraph): Promise<DependencyGraph> {
    return this.runtime.saveDependencyGraph(graph)
  }
}

function detectCycles(adjacency: ReadonlyMap<string, readonly string[]>): string[] {
  const visiting = new Set<string>()
  const visited = new Set<string>()
  const cyclic: string[] = []
  const visit = (node: string): void => {
    if (visited.has(node) || cyclic.includes(node)) return
    if (visiting.has(node)) {
      cyclic.push(node)
      return
    }
    visiting.add(node)
    for (const next of adjacency.get(node) ?? []) visit(next)
    visiting.delete(node)
    visited.add(node)
  }
  for (const node of adjacency.keys()) visit(node)
  return cyclic
}
