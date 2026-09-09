import { z } from 'zod'
import { InventoryHashSchema, SystemIssuedOpaqueIdSchema } from './inventory'
import { DefinitionIdSchema, ModuleVersionSchema } from './vulnerability'

const IsoDateSchema = z.string().datetime()
const SafeTextSchema = z
  .string()
  .trim()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value))

export const DependencyNodeKindSchema = z.enum([
  'request-variable',
  'identity-session',
  'csrf',
  'test-object',
  'workflow-prerequisite'
])

export type DependencyNodeKind = z.infer<typeof DependencyNodeKindSchema>

export const DependencyIssueCodeSchema = z.enum([
  'cycle',
  'missing-value',
  'stale-evidence',
  'cross-identity',
  'cross-tenant',
  'secret-sink-mismatch',
  'version-drift',
  'unfrozen-rule',
  'unreviewed-candidate'
])

export type DependencyIssueCode = z.infer<typeof DependencyIssueCodeSchema>

export const DependencyNodeSchema = z
  .strictObject({
    nodeId: DefinitionIdSchema,
    kind: DependencyNodeKindSchema,
    label: SafeTextSchema,
    ruleId: SystemIssuedOpaqueIdSchema.optional(),
    identityScope: SystemIssuedOpaqueIdSchema.optional(),
    tenantScope: z.string().trim().min(1).max(200).optional(),
    secretClassification: z.enum(['none', 'likely-secret']),
    evidenceRef: SystemIssuedOpaqueIdSchema.optional()
  })
  .readonly()

export type DependencyNode = z.infer<typeof DependencyNodeSchema>

export const DependencyEdgeSchema = z
  .strictObject({
    edgeId: DefinitionIdSchema,
    fromNodeId: DefinitionIdSchema,
    toNodeId: DefinitionIdSchema,
    ruleId: SystemIssuedOpaqueIdSchema,
    ruleHash: InventoryHashSchema,
    ruleVersion: ModuleVersionSchema,
    sourceRef: SystemIssuedOpaqueIdSchema
  })
  .readonly()

export type DependencyEdge = z.infer<typeof DependencyEdgeSchema>

export const DependencyIssueSchema = z
  .strictObject({
    code: DependencyIssueCodeSchema,
    nodeId: DefinitionIdSchema.optional(),
    edgeId: DefinitionIdSchema.optional(),
    message: SafeTextSchema
  })
  .readonly()

export type DependencyIssue = z.infer<typeof DependencyIssueSchema>

export const DependencyGraphSchema = z
  .strictObject({
    schemaVersion: z.literal('agentgo.dependency-graph.v1'),
    graphId: SystemIssuedOpaqueIdSchema,
    graphHash: InventoryHashSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    frozen: z.boolean(),
    nodes: z.array(DependencyNodeSchema).max(4_096),
    edges: z.array(DependencyEdgeSchema).max(8_192),
    issues: z.array(DependencyIssueSchema).max(4_096),
    paused: z.boolean(),
    createdAt: IsoDateSchema
  })
  .readonly()

export type DependencyGraph = z.infer<typeof DependencyGraphSchema>

export const DependencyEdgeCandidateSchema = z
  .strictObject({
    scanId: SystemIssuedOpaqueIdSchema,
    fromNodeId: DefinitionIdSchema,
    toNodeId: DefinitionIdSchema,
    ruleId: SystemIssuedOpaqueIdSchema,
    sourceRef: SystemIssuedOpaqueIdSchema,
    proposedBy: DefinitionIdSchema
  })
  .readonly()

export type DependencyEdgeCandidate = z.infer<
  typeof DependencyEdgeCandidateSchema
>
