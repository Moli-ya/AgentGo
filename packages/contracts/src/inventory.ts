import { z } from 'zod'
import {
  BodyEncodingSchema,
  CapabilityIdSchema,
  DefinitionIdSchema,
  EnvironmentSchema,
  ModuleVersionSchema,
  SelectorKindSchema,
  SupportedSubjectKindSchema,
  TransportKindSchema,
  VersionedDefinitionRefSchema,
  VulnerabilityFamilyIdSchema,
  VulnerabilityTechniqueIdSchema
} from './vulnerability'

const RuntimeIdSchema = z
  .string()
  .min(1)
  .max(200)
  .refine((value) => value === value.trim(), 'ID must not contain surrounding whitespace.')
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), 'ID must not contain control characters.')

/**
 * Opaque security references carry AgentGo-issued IDs, never page, model, or
 * tool content. The canonical UUIDv4 shape rejects credential-shaped strings
 * at this contract boundary. Application must still resolve each ID and verify
 * its owner/scope binding before use.
 */
export const SystemIssuedOpaqueIdSchema = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    'Opaque reference IDs must be canonical system-issued UUIDv4 values.'
  )

export type SystemIssuedOpaqueId = z.infer<typeof SystemIssuedOpaqueIdSchema>

const IsoDateSchema = z.string().datetime()
export const InventoryHashSchema = z.string().regex(/^[a-f0-9]{64}$/u)

export type InventoryHash = z.infer<typeof InventoryHashSchema>
const HeaderNameSchema = z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/u)
const CanonicalHeaderNameSchema = HeaderNameSchema.transform((value) => value.toLowerCase())
const SafePathSchema = z
  .string()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), 'Path must not contain control characters.')

export const InventoryReviewStatusSchema = z.enum([
  'unreviewed',
  'reviewed',
  'rejected'
])

export type InventoryReviewStatus = z.infer<typeof InventoryReviewStatusSchema>

export const InventoryExecutionClassSchema = z.enum([
  'inventory-only',
  'active-l1',
  'active-l2',
  'unsupported',
  'forbidden'
])

export type InventoryExecutionClass = z.infer<
  typeof InventoryExecutionClassSchema
>

export const InventoryLifecycleStatusSchema = z.enum(['active', 'retired'])

export type InventoryLifecycleStatus = z.infer<
  typeof InventoryLifecycleStatusSchema
>

export const InventoryValueTypeSchema = z.enum([
  'none',
  'string',
  'number',
  'integer',
  'boolean',
  'object',
  'array',
  'binary',
  'null',
  'unknown'
])

export type InventoryValueType = z.infer<typeof InventoryValueTypeSchema>

const NamedSelectorFields = {
  name: z.string().trim().min(1).max(500),
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
} as const

export const QuerySelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum.query),
  ...NamedSelectorFields
})

export const PathSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum.path),
  ...NamedSelectorFields
})

export const HeaderSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum.header),
  name: CanonicalHeaderNameSchema,
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export const CookieSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum.cookie),
  ...NamedSelectorFields
})

export const FormSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum.form),
  ...NamedSelectorFields
})

export const JsonPointerSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum['json-pointer']),
  pointer: z.string().max(2_048).refine(
    (value) => value === '' || value.startsWith('/'),
    'JSON Pointer must be empty or start with /.'
  ),
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export const MultipartPartSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum['multipart-part']),
  partName: z.string().trim().min(1).max(500),
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export const XmlPathSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum['xml-path']),
  path: SafePathSchema,
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export const GraphqlVariableSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum['graphql-variable']),
  variableName: z.string().regex(/^[_A-Za-z][_0-9A-Za-z]{0,127}$/u),
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export const GraphqlArgumentSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum['graphql-argument']),
  fieldPath: z.array(z.string().regex(/^[_A-Za-z][_0-9A-Za-z]{0,127}$/u)).min(1).max(64),
  argumentName: z.string().regex(/^[_A-Za-z][_0-9A-Za-z]{0,127}$/u),
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export const WebsocketFieldSelectorRefSchema = z.strictObject({
  kind: z.literal(SelectorKindSchema.enum['websocket-field']),
  messagePath: SafePathSchema,
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

/**
 * A selector contains an address and a value type, never an example value.
 * The discriminator literals deliberately mirror vulnerability.ts' closed
 * SelectorKindSchema instead of defining another capability enum.
 */
export const SelectorRefSchema = z.discriminatedUnion('kind', [
  QuerySelectorRefSchema,
  PathSelectorRefSchema,
  HeaderSelectorRefSchema,
  CookieSelectorRefSchema,
  FormSelectorRefSchema,
  JsonPointerSelectorRefSchema,
  MultipartPartSelectorRefSchema,
  XmlPathSelectorRefSchema,
  GraphqlVariableSelectorRefSchema,
  GraphqlArgumentSelectorRefSchema,
  WebsocketFieldSelectorRefSchema
])

export type SelectorRef = z.infer<typeof SelectorRefSchema>

function selectorAddressKey(selector: SelectorRef): string {
  switch (selector.kind) {
    case 'query':
    case 'path':
    case 'header':
    case 'cookie':
    case 'form':
      return `${selector.kind}\u0000${selector.name}`
    case 'json-pointer':
      return `${selector.kind}\u0000${selector.pointer}`
    case 'multipart-part':
      return `${selector.kind}\u0000${selector.partName}`
    case 'xml-path':
      return `${selector.kind}\u0000${selector.path}`
    case 'graphql-variable':
      return `${selector.kind}\u0000${selector.variableName}`
    case 'graphql-argument':
      return `${selector.kind}\u0000${JSON.stringify(selector.fieldPath)}\u0000${selector.argumentName}`
    case 'websocket-field':
      return `${selector.kind}\u0000${selector.messagePath}`
  }
}

export const SelectorRefsSchema = z
  .array(SelectorRefSchema)
  .max(2_048)
  .superRefine((selectors, context) => {
    const seen = new Set<string>()
    for (const [index, selector] of selectors.entries()) {
      const key = selectorAddressKey(selector)
      if (seen.has(key)) {
        context.addIssue({
          code: 'custom',
          message: 'Duplicate selector address.',
          path: [index]
        })
      }
      seen.add(key)
    }
  })

export const EndpointSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum.endpoint),
  endpointId: RuntimeIdSchema
})

export const SelectorSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum.selector),
  requestVariantId: RuntimeIdSchema,
  selector: SelectorRefSchema
})

export const PageDomSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum['page-dom']),
  pageId: RuntimeIdSchema,
  sinkRef: RuntimeIdSchema.optional()
})

export const IdentityPairSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum['identity-pair']),
  firstIdentityId: RuntimeIdSchema,
  secondIdentityId: RuntimeIdSchema
})

export const AuthorizationMatrixSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum['authorization-matrix']),
  matrixId: RuntimeIdSchema,
  version: ModuleVersionSchema
})

export const WorkflowTransitionSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum['workflow-transition']),
  workflowId: RuntimeIdSchema,
  transitionId: RuntimeIdSchema
})

export const ProtocolChannelSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum['protocol-channel']),
  channelId: RuntimeIdSchema,
  protocol: TransportKindSchema
})

export const ComponentSubjectRefSchema = z.strictObject({
  kind: z.literal(SupportedSubjectKindSchema.enum.component),
  componentId: RuntimeIdSchema,
  version: ModuleVersionSchema.optional()
})

/** Structured subjects reuse the module subject-kind and transport vocabulary. */
export const SubjectRefSchema = z.discriminatedUnion('kind', [
  EndpointSubjectRefSchema,
  SelectorSubjectRefSchema,
  PageDomSubjectRefSchema,
  IdentityPairSubjectRefSchema,
  AuthorizationMatrixSubjectRefSchema,
  WorkflowTransitionSubjectRefSchema,
  ProtocolChannelSubjectRefSchema,
  ComponentSubjectRefSchema
])

export type SubjectRef = z.infer<typeof SubjectRefSchema>

export const InventoryBodyShapeFieldSchema = z.strictObject({
  path: SafePathSchema,
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export type InventoryBodyShapeField = z.infer<
  typeof InventoryBodyShapeFieldSchema
>

export const InventoryBodyShapeSchema = z
  .strictObject({
    rootType: InventoryValueTypeSchema,
    fields: z
      .array(InventoryBodyShapeFieldSchema)
      .max(1_024)
      .superRefine((fields, context) => {
        const seen = new Set<string>()
        for (const [index, field] of fields.entries()) {
          if (seen.has(field.path)) {
            context.addIssue({
              code: 'custom',
              message: `Duplicate body-shape path: ${field.path}`,
              path: [index, 'path']
            })
          }
          seen.add(field.path)
        }
      })
  })
  .superRefine((shape, context) => {
    if (shape.rootType === 'none' && shape.fields.length > 0) {
      context.addIssue({
        code: 'custom',
        message: 'A body shape with rootType none cannot contain fields.',
        path: ['fields']
      })
    }
  })

export type InventoryBodyShape = z.infer<typeof InventoryBodyShapeSchema>

export const AllowedHeaderDescriptorSchema = z.strictObject({
  name: CanonicalHeaderNameSchema,
  valueType: InventoryValueTypeSchema,
  required: z.boolean()
})

export type AllowedHeaderDescriptor = z.infer<
  typeof AllowedHeaderDescriptorSchema
>

export const AllowedHeaderDescriptorsSchema = z
  .array(AllowedHeaderDescriptorSchema)
  .max(128)
  .superRefine((descriptors, context) => {
    const seen = new Set<string>()
    for (const [index, descriptor] of descriptors.entries()) {
      if (seen.has(descriptor.name)) {
        context.addIssue({
          code: 'custom',
          message: `Duplicate allowed header: ${descriptor.name}`,
          path: [index, 'name']
        })
      }
      seen.add(descriptor.name)
    }
  })

export const InventoryPreviewInputSchema = z.strictObject({
  url: z.string().url().max(16_384),
  headers: z.record(HeaderNameSchema, z.string().max(65_536)).optional(),
  body: z.string().max(262_144).optional()
})

export type InventoryPreviewInput = z.infer<
  typeof InventoryPreviewInputSchema
>

export const SanitizedInventoryPreviewUrlSchema = z
  .string()
  .url()
  .max(16_384)
  .superRefine((value, context) => {
    const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/u.exec(value)?.[1] ?? ''
    if (authority.includes('@') || value.includes('#')) {
      context.addIssue({
        code: 'custom',
        message: 'Sanitized preview URL cannot contain userinfo or a fragment.'
      })
    }
    const query = value.includes('?') ? value.slice(value.indexOf('?') + 1) : ''
    for (const pair of query === '' ? [] : query.split('&')) {
      const separator = pair.indexOf('=')
      const rawValue = separator === -1 ? '' : pair.slice(separator + 1)
      let queryValue = rawValue
      try {
        queryValue = decodeURIComponent(rawValue.replace(/\+/gu, ' '))
      } catch {
        queryValue = ''
      }
      if (queryValue !== '[REDACTED]') {
        context.addIssue({
          code: 'custom',
          message: 'Every sanitized preview query value must be redacted.'
        })
        break
      }
    }
  })

export const RedactedInventoryPreviewSchema = z
  .strictObject({
    url: SanitizedInventoryPreviewUrlSchema,
    headers: z.record(HeaderNameSchema, z.string().max(8_192)).optional(),
    body: z.string().max(16_384).optional()
  })
  .superRefine((preview, context) => {
    for (const [name, value] of Object.entries(preview.headers ?? {})) {
      if (
        /(?:authorization|proxy-authorization|cookie|set-cookie|password|secret|token|api[-_.]?key|csrf|xsrf|session)/iu.test(name) &&
        value !== '[REDACTED]'
      ) {
        context.addIssue({
          code: 'custom',
          message: `Sensitive preview header ${name} must be fully redacted.`,
          path: ['headers', name]
        })
      }
    }
  })

export type RedactedInventoryPreview = z.infer<
  typeof RedactedInventoryPreviewSchema
>

export const InventorySourceDraftSchema = z.strictObject({
  type: DefinitionIdSchema,
  sourceHash: InventoryHashSchema,
  pageId: RuntimeIdSchema.optional(),
  evidenceRef: SystemIssuedOpaqueIdSchema.optional(),
  initiator: z.string().trim().min(1).max(2_048).optional(),
  confidence: z.number().min(0).max(1)
})

export type InventorySourceDraft = z.infer<typeof InventorySourceDraftSchema>

export const InventoryCapabilityIdsSchema = z
  .array(CapabilityIdSchema)
  .max(128)
  .superRefine((ids, context) => {
    const seen = new Set<string>()
    for (const [index, id] of ids.entries()) {
      if (seen.has(id)) {
        context.addIssue({
          code: 'custom',
          message: `Duplicate capability ID: ${id}`,
          path: [index]
        })
      }
      seen.add(id)
    }
  })

export const UpsertInventoryInputSchema = z
  .strictObject({
    scanId: RuntimeIdSchema,
    pageId: RuntimeIdSchema.optional(),
    method: z.string().regex(/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u),
    url: z.string().url().max(16_384),
    contentType: z.string().trim().min(1).max(500).optional(),
    bodyShape: InventoryBodyShapeSchema,
    codec: BodyEncodingSchema,
    transport: TransportKindSchema,
    allowedHeaders: AllowedHeaderDescriptorsSchema,
    templateVersion: ModuleVersionSchema,
    requiredCapabilityIds: InventoryCapabilityIdsSchema,
    selectors: SelectorRefsSchema,
    preview: InventoryPreviewInputSchema,
    source: InventorySourceDraftSchema
  })
  .superRefine((input, context) => {
    if ((input.codec === 'none') !== (input.bodyShape.rootType === 'none')) {
      context.addIssue({
        code: 'custom',
        message: 'Codec none and body-shape rootType none must be used together.',
        path: ['bodyShape', 'rootType']
      })
    }
    if (input.preview.url !== input.url) {
      context.addIssue({
        code: 'custom',
        message: 'Preview URL must match the discovered URL.',
        path: ['preview', 'url']
      })
    }
    if (
      input.pageId !== undefined &&
      input.source.pageId !== undefined &&
      input.pageId !== input.source.pageId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Endpoint and source page IDs must match when both are present.',
        path: ['source', 'pageId']
      })
    }
  })

export type UpsertInventoryInput = z.infer<typeof UpsertInventoryInputSchema>

const RequestVariantRecordFields = {
  id: RuntimeIdSchema,
  scanId: RuntimeIdSchema,
  endpointId: RuntimeIdSchema,
  contentType: z.string().trim().min(1).max(500).optional(),
  bodyShape: InventoryBodyShapeSchema,
  codec: BodyEncodingSchema,
  transport: TransportKindSchema,
  allowedHeaders: AllowedHeaderDescriptorsSchema,
  templateVersion: ModuleVersionSchema,
  requiredCapabilityIds: InventoryCapabilityIdsSchema,
  selectors: SelectorRefsSchema,
  redactedPreview: RedactedInventoryPreviewSchema,
  reviewStatus: InventoryReviewStatusSchema,
  reviewedBy: RuntimeIdSchema.optional(),
  reviewedAt: IsoDateSchema.optional(),
  executionClass: InventoryExecutionClassSchema,
  lifecycleStatus: InventoryLifecycleStatusSchema,
  retiredAt: IsoDateSchema.optional(),
  structureHash: InventoryHashSchema,
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
} as const

export const RequestVariantRecordSchema = z
  .strictObject(RequestVariantRecordFields)
  .superRefine((record, context) => {
    const hasReviewAudit = record.reviewedBy !== undefined && record.reviewedAt !== undefined
    if (record.reviewStatus === 'unreviewed' && (record.reviewedBy || record.reviewedAt)) {
      context.addIssue({
        code: 'custom',
        message: 'Unreviewed variants cannot contain review audit fields.',
        path: ['reviewStatus']
      })
    }
    if (record.reviewStatus !== 'unreviewed' && !hasReviewAudit) {
      context.addIssue({
        code: 'custom',
        message: 'Reviewed or rejected variants require reviewedBy and reviewedAt.',
        path: ['reviewStatus']
      })
    }
    if (record.lifecycleStatus === 'active' && record.retiredAt !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Active variants cannot contain retiredAt.',
        path: ['lifecycleStatus']
      })
    }
    if (record.lifecycleStatus === 'retired' && record.retiredAt === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Retired variants require retiredAt.',
        path: ['lifecycleStatus']
      })
    }
    if ((record.codec === 'none') !== (record.bodyShape.rootType === 'none')) {
      context.addIssue({
        code: 'custom',
        message: 'Codec none and body-shape rootType none must be used together.',
        path: ['bodyShape', 'rootType']
      })
    }
  })

export type RequestVariantRecord = z.infer<typeof RequestVariantRecordSchema>

export const CanonicalInventoryRouteSchema = z
  .string()
  .url()
  .max(16_384)
  .refine(
    (value) => /^(?:http|https|ws|wss):\/\//u.test(value),
    'Canonical route must use a supported Web transport protocol.'
  )
  .refine((value) => !/[?#]/u.test(value), 'Canonical route cannot contain query or fragment.')
  .refine((value) => {
    const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/u.exec(value)?.[1] ?? ''
    return !authority.includes('@')
  }, 'Canonical route cannot contain userinfo.')

export const InventoryEndpointRecordSchema = z.strictObject({
  id: RuntimeIdSchema,
  scanId: RuntimeIdSchema,
  pageId: RuntimeIdSchema.optional(),
  method: z.string().regex(/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u),
  canonicalRoute: CanonicalInventoryRouteSchema,
  lifecycleStatus: InventoryLifecycleStatusSchema,
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema
})

export type InventoryEndpointRecord = z.infer<
  typeof InventoryEndpointRecordSchema
>

export const InventorySourceRecordSchema = z.strictObject({
  id: RuntimeIdSchema,
  scanId: RuntimeIdSchema,
  endpointId: RuntimeIdSchema,
  requestVariantId: RuntimeIdSchema,
  type: DefinitionIdSchema,
  sourceHash: InventoryHashSchema,
  provenanceHash: InventoryHashSchema,
  pageId: RuntimeIdSchema.optional(),
  evidenceRef: SystemIssuedOpaqueIdSchema.optional(),
  initiator: z.string().trim().min(1).max(2_048).optional(),
  confidencePpm: z.number().int().min(0).max(1_000_000),
  discoveredAt: IsoDateSchema,
  reviewStatus: InventoryReviewStatusSchema,
  createdAt: IsoDateSchema
})

export type InventorySourceRecord = z.infer<typeof InventorySourceRecordSchema>

export const UpsertInventoryResultSchema = z.strictObject({
  endpoint: InventoryEndpointRecordSchema,
  requestVariant: RequestVariantRecordSchema,
  source: InventorySourceRecordSchema
})

export type UpsertInventoryResult = z.infer<
  typeof UpsertInventoryResultSchema
>

export const ReviewVariantInputSchema = z.strictObject({
  scanId: RuntimeIdSchema,
  requestVariantId: RuntimeIdSchema,
  reviewStatus: z.enum(['reviewed', 'rejected']),
  reviewedBy: RuntimeIdSchema
})

export type ReviewVariantInput = z.infer<typeof ReviewVariantInputSchema>

export const RetireVariantInputSchema = z.strictObject({
  scanId: RuntimeIdSchema,
  requestVariantId: RuntimeIdSchema
})

export type RetireVariantInput = z.infer<typeof RetireVariantInputSchema>

export const IdentityRefStatusSchema = z.enum(['active', 'disabled', 'revoked'])
export const SessionGenerationRefStatusSchema = z.enum([
  'active',
  'expired',
  'revoked'
])
export const TestObjectRefStatusSchema = z.enum([
  'ready',
  'in-use',
  'cleanup-required',
  'retired'
])

/** Closed union for consumers that handle more than one opaque-ref kind. */
export const OpaqueRefStatusSchema = z.enum([
  'active',
  'disabled',
  'expired',
  'revoked',
  'ready',
  'in-use',
  'cleanup-required',
  'retired'
])

export type OpaqueRefStatus = z.infer<typeof OpaqueRefStatusSchema>

export const IdentityRefSchema = z
  .strictObject({
    id: SystemIssuedOpaqueIdSchema,
    version: z.number().int().nonnegative(),
    ownerRef: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    statusSummary: IdentityRefStatusSchema
  })
  .readonly()

export type IdentityRef = z.infer<typeof IdentityRefSchema>

export const SessionGenerationRefSchema = z
  .strictObject({
    id: SystemIssuedOpaqueIdSchema,
    generation: z.number().int().nonnegative(),
    ownerRef: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    statusSummary: SessionGenerationRefStatusSchema
  })
  .readonly()

export type SessionGenerationRef = z.infer<typeof SessionGenerationRefSchema>

export const TestObjectRefSchema = z
  .strictObject({
    id: SystemIssuedOpaqueIdSchema,
    version: z.number().int().nonnegative(),
    ownerRef: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    statusSummary: TestObjectRefStatusSchema
  })
  .readonly()

export type TestObjectRef = z.infer<typeof TestObjectRefSchema>

export const CapabilityRiskFloorSchema = z.enum(['l0', 'l1', 'l2'])

export type CapabilityRiskFloor = z.infer<typeof CapabilityRiskFloorSchema>

export const ScanSnapshotCapabilityDescriptorSchema = z.strictObject({
  id: CapabilityIdSchema,
  riskFloor: CapabilityRiskFloorSchema,
  descriptorHash: InventoryHashSchema
}).readonly()

export type ScanSnapshotCapabilityDescriptor = z.infer<
  typeof ScanSnapshotCapabilityDescriptorSchema
>

export const ScanSnapshotEnvironmentSchema = z.union([
  EnvironmentSchema,
  z.literal('legacy-unknown')
])

export type ScanSnapshotEnvironment = z.infer<
  typeof ScanSnapshotEnvironmentSchema
>

export const ScanModuleAuthorizationSchema = z.enum([
  'qualified',
  'legacy-v1-compatibility'
])

export type ScanModuleAuthorization = z.infer<
  typeof ScanModuleAuthorizationSchema
>

const ScanModuleSnapshotDraftFields = {
  familyId: VulnerabilityFamilyIdSchema,
  moduleId: DefinitionIdSchema,
  moduleVersion: ModuleVersionSchema,
  definitionHash: InventoryHashSchema,
  techniqueId: VulnerabilityTechniqueIdSchema,
  techniqueVersion: ModuleVersionSchema,
  strategyRefs: z.array(VersionedDefinitionRefSchema.readonly()).min(1).max(128).readonly(),
  confirmationRuleRefs: z
    .array(VersionedDefinitionRefSchema.readonly())
    .min(1)
    .max(128)
    .readonly(),
  evidenceProfileRefs: z
    .array(VersionedDefinitionRefSchema.readonly())
    .min(1)
    .max(128)
    .readonly(),
  remediationRefs: z
    .array(VersionedDefinitionRefSchema.readonly())
    .min(1)
    .max(128)
    .readonly(),
  requiredCapabilityIds: z.array(CapabilityIdSchema).max(128).readonly(),
  capabilityDescriptors: z
    .array(ScanSnapshotCapabilityDescriptorSchema)
    .max(128)
    .readonly(),
  capabilitySnapshotHash: InventoryHashSchema,
  selectedCapabilitiesHash: InventoryHashSchema,
  selectedDefinitionsHash: InventoryHashSchema,
  registrySnapshotHash: InventoryHashSchema,
  environment: ScanSnapshotEnvironmentSchema,
  authorization: ScanModuleAuthorizationSchema
} as const

export const ScanModuleSnapshotDraftSchema = z
  .strictObject(ScanModuleSnapshotDraftFields)
  .readonly()

export type ScanModuleSnapshotDraft = z.infer<
  typeof ScanModuleSnapshotDraftSchema
>

export const ScanModuleSnapshotRecordSchema = z
  .strictObject({
    id: RuntimeIdSchema,
    scanId: RuntimeIdSchema,
    ...ScanModuleSnapshotDraftFields,
    snapshotHash: InventoryHashSchema,
    createdAt: IsoDateSchema
  })
  .readonly()

export type ScanModuleSnapshotRecord = z.infer<
  typeof ScanModuleSnapshotRecordSchema
>
