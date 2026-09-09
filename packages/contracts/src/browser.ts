import { z } from 'zod'
import { InventoryHashSchema, SystemIssuedOpaqueIdSchema } from './inventory'

const IsoDateSchema = z.string().datetime()
const SafeTextSchema = z
  .string()
  .trim()
  .min(1)
  .max(2_048)
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value))

export const BrowserResourceTypeSchema = z.enum([
  'document',
  'script',
  'stylesheet',
  'image',
  'font',
  'fetch',
  'xhr',
  'ping',
  'websocket',
  'eventsource',
  'manifest',
  'other'
])

export type BrowserResourceType = z.infer<typeof BrowserResourceTypeSchema>

export const BrowserNetworkIntentKindSchema = z.enum([
  'navigation',
  'subresource',
  'fetch',
  'xhr',
  'beacon',
  'form-submit',
  'websocket',
  'sse',
  'unknown'
])

export type BrowserNetworkIntentKind = z.infer<
  typeof BrowserNetworkIntentKindSchema
>

export const BrowserNetworkVerdictSchema = z.enum([
  'fulfill',
  'inventory-only',
  'awaiting-review',
  'unsupported',
  'blocked',
  'fail-closed'
])

export type BrowserNetworkVerdict = z.infer<typeof BrowserNetworkVerdictSchema>

export const BrowserNetworkIntentSchema = z
  .strictObject({
    kind: BrowserNetworkIntentKindSchema,
    method: z.string().regex(/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u),
    url: z.string().url().max(16_384),
    resourceType: BrowserResourceTypeSchema,
    isNavigation: z.boolean(),
    pageUrl: z.string().url().max(16_384).optional(),
    frameUrl: z.string().url().max(16_384).optional(),
    initiator: SafeTextSchema.optional(),
    bodyShape: SafeTextSchema.optional(),
    contentType: z.string().trim().min(1).max(500).optional()
  })
  .readonly()

export type BrowserNetworkIntent = z.infer<typeof BrowserNetworkIntentSchema>

export const BrowserReconObservationSchema = z
  .strictObject({
    observationId: SystemIssuedOpaqueIdSchema,
    scanId: SystemIssuedOpaqueIdSchema,
    method: z.string().regex(/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u),
    sanitizedUrl: z.string().max(16_384),
    resourceType: BrowserResourceTypeSchema,
    intentKind: BrowserNetworkIntentKindSchema,
    verdict: BrowserNetworkVerdictSchema,
    pageUrl: z.string().max(16_384).optional(),
    frameUrl: z.string().max(16_384).optional(),
    initiator: SafeTextSchema.optional(),
    bodyShape: SafeTextSchema.optional(),
    responseContentType: z.string().trim().min(1).max(500).optional(),
    statusCode: z.number().int().min(0).max(599).optional(),
    capabilityVerdict: z.enum([
      'inventory-only',
      'active-l1',
      'unsupported',
      'forbidden'
    ]),
    sourceRefs: z.array(SystemIssuedOpaqueIdSchema).max(32),
    policyDecisionId: SystemIssuedOpaqueIdSchema.optional(),
    leaseId: SystemIssuedOpaqueIdSchema.optional(),
    evidenceRef: SystemIssuedOpaqueIdSchema.optional(),
    requestHash: InventoryHashSchema.optional(),
    createdAt: IsoDateSchema
  })
  .readonly()

export type BrowserReconObservation = z.infer<
  typeof BrowserReconObservationSchema
>
