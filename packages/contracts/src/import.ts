import { z } from 'zod'
import {
  InventoryHashSchema,
  InventoryValueTypeSchema,
  SystemIssuedOpaqueIdSchema,
  type InventoryHash,
  type SystemIssuedOpaqueId
} from './inventory'
import {
  BodyEncodingSchema,
  DefinitionIdSchema,
  ModuleVersionSchema,
  TransportKindSchema
} from './vulnerability'

const IsoDateSchema = z.string().datetime()
const LocationSchema = z
  .string()
  .trim()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), 'Location must not contain control characters.')

export const ImportFormatSchema = z.enum([
  'openapi-3.0',
  'openapi-3.1',
  'swagger-2.0',
  'har-1.2',
  'postman-2.1',
  'graphql-sdl',
  'graphql-introspection',
  'asyncapi',
  'wsdl',
  'protobuf',
  'grpc-reflection',
  'websocket',
  'sse',
  'callback-webhook',
  'unknown'
])

export type ImportFormat = z.infer<typeof ImportFormatSchema>

export const ImportAdapterStatusSchema = z.enum([
  'fully-parsed',
  'partial-inventory',
  'unsupported'
])

export type ImportAdapterStatus = z.infer<typeof ImportAdapterStatusSchema>

export const ImportWarningCodeSchema = z.enum([
  'remote-ref-forbidden',
  'yaml-alias-limit',
  'yaml-merge-forbidden',
  'yaml-tag-forbidden',
  'document-too-large',
  'document-too-deep',
  'too-many-operations',
  'too-many-objects',
  'string-too-long',
  'parse-timeout',
  'malformed-document',
  'unsupported-format',
  'unsupported-keyword',
  'unsupported-protocol',
  'unresolved-base',
  'out-of-scope',
  'secret-redacted',
  'lossy-mapping',
  'callback-inventory-only',
  'vendor-extension-ignored'
])

export type ImportWarningCode = z.infer<typeof ImportWarningCodeSchema>

export const ImportWarningSchema = z
  .strictObject({
    code: ImportWarningCodeSchema,
    location: LocationSchema,
    message: z.string().trim().min(1).max(2_048)
  })
  .readonly()

export type ImportWarning = z.infer<typeof ImportWarningSchema>

export const ImportParserLimitsSchema = z
  .strictObject({
    maxFileBytes: z.number().int().positive().max(8_388_608),
    maxDocumentDepth: z.number().int().positive().max(64),
    maxObjectCount: z.number().int().positive().max(200_000),
    maxOperations: z.number().int().positive().max(8_192),
    maxStringLength: z.number().int().positive().max(65_536),
    maxYamlAliases: z.number().int().nonnegative().max(256),
    maxParseTimeMs: z.number().int().positive().max(30_000)
  })
  .readonly()

export type ImportParserLimits = z.infer<typeof ImportParserLimitsSchema>

export const DEFAULT_IMPORT_PARSER_LIMITS: ImportParserLimits = Object.freeze({
  maxFileBytes: 2_097_152,
  maxDocumentDepth: 32,
  maxObjectCount: 50_000,
  maxOperations: 2_048,
  maxStringLength: 16_384,
  maxYamlAliases: 32,
  maxParseTimeMs: 5_000
})

export const ImportAdapterProfileSchema = z
  .strictObject({
    format: ImportFormatSchema,
    parserName: DefinitionIdSchema,
    parserVersion: ModuleVersionSchema,
    status: ImportAdapterStatusSchema,
    replayable: z.literal(false),
    executable: z.literal(false),
    supportedMediaTypes: z.array(z.string().min(1).max(200)).min(1).max(16),
    supportedKeywords: z.array(DefinitionIdSchema).max(256),
    unsupportedKeywords: z.array(DefinitionIdSchema).max(256),
    notes: z.array(z.string().trim().min(1).max(2_048)).max(32)
  })
  .readonly()

export type ImportAdapterProfile = z.infer<typeof ImportAdapterProfileSchema>

export const ImportScopeVerdictSchema = z.enum([
  'in-scope',
  'out-of-scope',
  'unresolved'
])

export type ImportScopeVerdict = z.infer<typeof ImportScopeVerdictSchema>

export const ImportParameterSchema = z
  .strictObject({
    name: z.string().trim().min(1).max(200),
    location: z.enum(['query', 'path', 'header', 'cookie', 'form', 'body']),
    valueType: InventoryValueTypeSchema,
    format: z.string().trim().min(1).max(64).optional(),
    required: z.boolean(),
    resourceKind: z.enum(['resource-id', 'owner', 'tenant', 'opaque']).optional(),
    ownerField: z.string().trim().min(1).max(200).optional(),
    responseIdentityField: z.string().trim().min(1).max(200).optional()
  })
  .readonly()

export type ImportParameter = z.infer<typeof ImportParameterSchema>

export const ImportPreviewOperationSchema = z
  .strictObject({
    operationRef: z.string().trim().min(1).max(1_024),
    method: z.string().regex(/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u),
    url: z.string().max(16_384),
    scopeVerdict: ImportScopeVerdictSchema,
    contentType: z.string().trim().min(1).max(500).optional(),
    codec: BodyEncodingSchema,
    transport: TransportKindSchema,
    parameterLocations: z.array(z.enum(['query', 'path', 'header', 'cookie', 'form', 'body'])).max(
      64
    ),
    parameters: z.array(ImportParameterSchema).max(128).optional(),
    securitySchemes: z.array(z.string().trim().min(1).max(200)).max(32),
    warnings: z.array(ImportWarningSchema).max(64)
  })
  .readonly()

export type ImportPreviewOperation = z.infer<typeof ImportPreviewOperationSchema>

export const ImportPreviewStatsSchema = z
  .strictObject({
    accepted: z.number().int().nonnegative(),
    rejectedOutOfScope: z.number().int().nonnegative(),
    unresolved: z.number().int().nonnegative(),
    unsupported: z.number().int().nonnegative()
  })
  .readonly()

export type ImportPreviewStats = z.infer<typeof ImportPreviewStatsSchema>

export const ImportPreviewSchema = z
  .strictObject({
    previewId: SystemIssuedOpaqueIdSchema,
    previewHash: InventoryHashSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    workspaceId: SystemIssuedOpaqueIdSchema,
    scopeSnapshotId: SystemIssuedOpaqueIdSchema,
    sourceBytesHash: InventoryHashSchema,
    mediaType: z.string().trim().min(1).max(200),
    format: ImportFormatSchema,
    parserName: DefinitionIdSchema,
    parserVersion: ModuleVersionSchema,
    adapterStatus: ImportAdapterStatusSchema,
    operations: z.array(ImportPreviewOperationSchema).max(8_192),
    rejectedOperations: z.array(ImportPreviewOperationSchema).max(8_192),
    warnings: z.array(ImportWarningSchema).max(4_096),
    stats: ImportPreviewStatsSchema,
    createdAt: IsoDateSchema,
    expiresAt: IsoDateSchema
  })
  .readonly()

export type ImportPreview = z.infer<typeof ImportPreviewSchema>

export const CreateImportPreviewInputSchema = z
  .strictObject({
    scanId: SystemIssuedOpaqueIdSchema,
    importActorRef: DefinitionIdSchema,
    mediaType: z.string().trim().min(1).max(200).optional(),
    bytes: z.instanceof(Uint8Array).optional(),
    evidenceRef: SystemIssuedOpaqueIdSchema.optional(),
    expectedHash: InventoryHashSchema.optional(),
    limits: ImportParserLimitsSchema.optional()
  })
  .superRefine((input, context) => {
    if ((input.bytes === undefined) === (input.evidenceRef === undefined)) {
      context.addIssue({
        code: 'custom',
        message: 'Preview requires exactly one of bytes or evidenceRef.',
        path: ['bytes']
      })
    }
    if (input.evidenceRef !== undefined && input.expectedHash === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Evidence-backed preview requires an expected content hash.',
        path: ['expectedHash']
      })
    }
  })

export type CreateImportPreviewInput = z.infer<typeof CreateImportPreviewInputSchema>

export const CommitImportPreviewInputSchema = z
  .strictObject({
    previewId: SystemIssuedOpaqueIdSchema,
    previewHash: InventoryHashSchema,
    sourceBytesHash: InventoryHashSchema,
    parserVersion: ModuleVersionSchema,
    importActorRef: DefinitionIdSchema
  })
  .readonly()

export type CommitImportPreviewInput = z.infer<typeof CommitImportPreviewInputSchema>

export const ImportCommitResultSchema = z
  .strictObject({
    commitId: SystemIssuedOpaqueIdSchema,
    previewId: SystemIssuedOpaqueIdSchema,
    idempotentReplay: z.boolean(),
    acceptedCount: z.number().int().nonnegative(),
    sourceIds: z.array(SystemIssuedOpaqueIdSchema).max(8_192)
  })
  .readonly()

export type ImportCommitResult = z.infer<typeof ImportCommitResultSchema>

export type { InventoryHash, SystemIssuedOpaqueId }
