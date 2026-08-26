import { z } from 'zod'
import { SystemIssuedOpaqueIdSchema } from './inventory'
import {
  DefinitionIdSchema,
  ModuleVersionSchema
} from './vulnerability'

const SHA256_DIGEST_PATTERN = /^[a-f0-9]{64}$/u
const HTTP_FIELD_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u
const COOKIE_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/u
const MAX_JSON_TEMPLATE_DEPTH = 64

function compareCanonicalText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return false
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) return false
      index += 1
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false
    }
  }
  return true
}

const Sha256DigestSchema = z.string().regex(SHA256_DIGEST_PATTERN)
const ZeroBasedOccurrenceSchema = z.union([
  z.number().int().nonnegative(),
  z.literal('all')
])
const MutationOnMissingSchema = z.enum(['reject', 'append'])
const ExactSlotNameSchema = z
  .string()
  .min(1)
  .max(500)
  .refine(
    (value) => value === value.trim(),
    'Mutation target names must not contain surrounding whitespace.'
  )
  .refine(
    (value) => value === value.normalize('NFC'),
    'Mutation target names must use Unicode NFC normalization.'
  )
  .refine(
    isWellFormedUnicode,
    'Mutation target names must contain well-formed Unicode.'
  )
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    'Mutation target names must not contain control characters.'
  )

export const TEMPLATE_INTENT_HASH_DOMAIN =
  'agentgo.template-intent.v1' as const
export const RESOLVED_INTENT_HASH_DOMAIN =
  'agentgo.resolved-intent.v1' as const
export const WIRE_REQUEST_HMAC_DOMAIN = 'agentgo.wire-request.v2' as const

/**
 * Template and resolved digests are deliberately domain tagged. A digest from
 * one compiler phase therefore cannot be parsed as the other phase's proof.
 */
export const TemplateIntentHashSchema = z
  .strictObject({
    domain: z.literal(TEMPLATE_INTENT_HASH_DOMAIN),
    algorithm: z.literal('sha256'),
    digest: Sha256DigestSchema
  })
  .readonly()

export type TemplateIntentHash = z.infer<typeof TemplateIntentHashSchema>

export const ResolvedIntentHashSchema = z
  .strictObject({
    domain: z.literal(RESOLVED_INTENT_HASH_DOMAIN),
    algorithm: z.literal('sha256'),
    commitmentKeyRef: SystemIssuedOpaqueIdSchema,
    commitmentKeyVersion: z.number().int().nonnegative(),
    digest: Sha256DigestSchema
  })
  .readonly()

export type ResolvedIntentHash = z.infer<typeof ResolvedIntentHashSchema>

/**
 * The wire proof is an HMAC, not a reusable plain request digest. keyRef is an
 * opaque system-issued identifier; key material must never cross this boundary.
 */
export const WireRequestHmacSchema = z
  .strictObject({
    domain: z.literal(WIRE_REQUEST_HMAC_DOMAIN),
    algorithm: z.literal('hmac-sha256'),
    keyRef: SystemIssuedOpaqueIdSchema,
    keyVersion: z.number().int().nonnegative(),
    digest: Sha256DigestSchema
  })
  .readonly()

export type WireRequestHmac = z.infer<typeof WireRequestHmacSchema>

/** Query, form, and cookie names may repeat, so occurrence is mandatory. */
export const QueryMutationTargetSchema = z
  .strictObject({
    kind: z.literal('query'),
    name: ExactSlotNameSchema,
    occurrence: ZeroBasedOccurrenceSchema,
    onMissing: MutationOnMissingSchema
  })
  .readonly()

export const FormMutationTargetSchema = z
  .strictObject({
    kind: z.literal('form'),
    name: ExactSlotNameSchema,
    occurrence: ZeroBasedOccurrenceSchema,
    onMissing: MutationOnMissingSchema
  })
  .readonly()

export const CookieMutationTargetSchema = z
  .strictObject({
    kind: z.literal('cookie'),
    name: z.string().regex(COOKIE_NAME_PATTERN),
    occurrence: ZeroBasedOccurrenceSchema,
    onMissing: MutationOnMissingSchema
  })
  .readonly()

/** Path addresses bind a reviewed selector name to a zero-based segment. */
export const PathMutationTargetSchema = z
  .strictObject({
    kind: z.literal('path'),
    selectorName: ExactSlotNameSchema,
    segmentIndex: z.number().int().nonnegative()
  })
  .readonly()

/** Executable header addresses are already canonical lower-case field names. */
export const HeaderMutationTargetSchema = z
  .strictObject({
    kind: z.literal('header'),
    name: z.string().regex(HTTP_FIELD_NAME_PATTERN)
  })
  .readonly()

/** RFC 6901 syntax, including the empty pointer for the document root. */
export const JsonPointerMutationTargetSchema = z
  .strictObject({
    kind: z.literal('json-pointer'),
    pointer: z
      .string()
      .max(2_048)
      .regex(/^(?:\/(?:[^~/\u0000-\u001f\u007f]|~[01])*)*$/u)
      .refine(
        (value) => value === value.normalize('NFC'),
        'JSON Pointer must use Unicode NFC normalization.'
      )
      .refine(
        isWellFormedUnicode,
        'JSON Pointer must contain well-formed Unicode.'
      )
  })
  .readonly()

export const RequestMutationTargetSchema = z.discriminatedUnion('kind', [
  QueryMutationTargetSchema,
  PathMutationTargetSchema,
  HeaderMutationTargetSchema,
  CookieMutationTargetSchema,
  FormMutationTargetSchema,
  JsonPointerMutationTargetSchema
])

export type RequestMutationTarget = z.infer<
  typeof RequestMutationTargetSchema
>

/** Raw sensitive values never belong in a serializable request template. */
export const RequestValueSensitivitySchema = z.literal('public')

export type RequestValueSensitivity = z.infer<
  typeof RequestValueSensitivitySchema
>

export const DynamicValueResolverRefSchema = z
  .strictObject({
    kind: z.literal('dynamic-value-resolver'),
    resolverId: DefinitionIdSchema,
    version: ModuleVersionSchema
  })
  .readonly()

export type DynamicValueResolverRef = z.infer<
  typeof DynamicValueResolverRefSchema
>

export const SecretRefResolverRefSchema = z
  .strictObject({
    kind: z.literal('secret-ref-resolver'),
    resolverId: DefinitionIdSchema,
    version: ModuleVersionSchema
  })
  .readonly()

export type SecretRefResolverRef = z.infer<
  typeof SecretRefResolverRefSchema
>

const DynamicRequestValueSourceFields = {
  kind: z.literal('dynamic'),
  slotId: DefinitionIdSchema,
  resolver: DynamicValueResolverRefSchema
} as const

const SecretRequestValueSourceFields = {
  kind: z.literal('secret-ref'),
  secretRef: SystemIssuedOpaqueIdSchema,
  generation: z.number().int().nonnegative(),
  resolver: SecretRefResolverRefSchema
} as const

export const FormLiteralValueSourceSchema = z
  .strictObject({
    kind: z.literal('literal'),
    sensitivity: RequestValueSensitivitySchema,
    value: z
      .string()
      .max(262_144)
      .refine(
        (value) => value === value.normalize('NFC'),
        'Literal form values must use Unicode NFC normalization.'
      )
      .refine(
        isWellFormedUnicode,
        'Literal form values must contain well-formed Unicode.'
      )
  })
  .readonly()

export const DynamicRequestValueSourceSchema = z
  .strictObject(DynamicRequestValueSourceFields)
  .readonly()

export const SecretRequestValueSourceSchema = z
  .strictObject(SecretRequestValueSourceFields)
  .readonly()

export const FormValueSourceSchema = z.discriminatedUnion('kind', [
  FormLiteralValueSourceSchema,
  DynamicRequestValueSourceSchema,
  SecretRequestValueSourceSchema
])

export type FormValueSource = z.infer<typeof FormValueSourceSchema>

export const JsonLiteralValueSourceSchema = z
  .strictObject({
    kind: z.literal('literal'),
    sensitivity: RequestValueSensitivitySchema,
    value: z.union([
      z.string().max(262_144).refine(
        (value) => value === value.normalize('NFC'),
        'Literal JSON strings must use Unicode NFC normalization.'
      ).refine(
        isWellFormedUnicode,
        'Literal JSON strings must contain well-formed Unicode.'
      ),
      z.number().finite(),
      z.boolean(),
      z.null()
    ])
  })
  .readonly()

export const JsonValueSourceSchema = z.discriminatedUnion('kind', [
  JsonLiteralValueSourceSchema,
  DynamicRequestValueSourceSchema,
  SecretRequestValueSourceSchema
])

export type JsonValueSource = z.infer<typeof JsonValueSourceSchema>

export type JsonValueTemplate =
  | JsonValueSource
  | Readonly<{
      kind: 'array'
      items: readonly JsonValueTemplate[]
    }>
  | Readonly<{
      kind: 'object'
      entries: readonly Readonly<{
        key: string
        value: JsonValueTemplate
      }>[]
    }>

const JsonObjectKeySchema = z
  .string()
  .max(2_048)
  .refine(
    (value) => value === value.normalize('NFC'),
    'JSON object keys must use Unicode NFC normalization.'
  )
  .refine(
    isWellFormedUnicode,
    'JSON object keys must contain well-formed Unicode.'
  )
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    'JSON object keys must not contain control characters.'
  )

function createJsonValueTemplateSchema(
  remainingDepth: number
): z.ZodType<JsonValueTemplate> {
  if (remainingDepth === 0) {
    return JsonValueSourceSchema as z.ZodType<JsonValueTemplate>
  }

  const childSchema = createJsonValueTemplateSchema(remainingDepth - 1)
  return z.union([
    JsonValueSourceSchema,
    z
      .strictObject({
        kind: z.literal('array'),
        items: z.array(childSchema).max(4_096).readonly()
      })
      .readonly(),
    z
      .strictObject({
        kind: z.literal('object'),
        entries: z
          .array(
            z
              .strictObject({
                key: JsonObjectKeySchema,
                value: childSchema
              })
              .readonly()
          )
          .max(4_096)
          .superRefine((entries, context) => {
            const seen = new Set<string>()
            for (const [index, entry] of entries.entries()) {
              if (seen.has(entry.key)) {
                context.addIssue({
                  code: 'custom',
                  message: 'Duplicate JSON object key.',
                  path: [index, 'key']
                })
              }
              seen.add(entry.key)
            }
          })
          .transform((entries) =>
            [...entries].sort((left, right) =>
              compareCanonicalText(left.key, right.key)
            )
          )
          .readonly()
      })
      .readonly()
  ]) as z.ZodType<JsonValueTemplate>
}

/** A finite schema prevents hostile recursive input from overflowing Zod. */
export const JsonValueTemplateSchema = createJsonValueTemplateSchema(
  MAX_JSON_TEMPLATE_DEPTH
)

export const NoRequestBodyTemplateSchema = z
  .strictObject({
    encoding: z.literal('none')
  })
  .readonly()

export const FormBodyEntryTemplateSchema = z
  .strictObject({
    name: ExactSlotNameSchema,
    value: FormValueSourceSchema
  })
  .readonly()

export const FormRequestBodyTemplateSchema = z
  .strictObject({
    encoding: z.literal('form'),
    entries: z.array(FormBodyEntryTemplateSchema).max(4_096).readonly()
  })
  .readonly()

export const JsonRequestBodyTemplateSchema = z
  .strictObject({
    encoding: z.literal('json'),
    value: JsonValueTemplateSchema
  })
  .readonly()

export const RequestBodyTemplateSchema = z.discriminatedUnion('encoding', [
  NoRequestBodyTemplateSchema,
  FormRequestBodyTemplateSchema,
  JsonRequestBodyTemplateSchema
])

export type RequestBodyTemplate = z.infer<typeof RequestBodyTemplateSchema>

export const ProbeLevelSchema = z.enum([
  'passive',
  'active-safe',
  'active-sensitive',
  'destructive'
])

export type ProbeLevel = z.infer<typeof ProbeLevelSchema>

export const SideEffectSchema = z.enum([
  'none',
  'reversible',
  'destructive',
  'unknown'
])

export type SideEffect = z.infer<typeof SideEffectSchema>

export const NetworkAddressClassSchema = z.enum([
  'private',
  'loopback',
  'link-local',
  'reserved'
])

export type ScopeNetworkAddressClass = z.infer<typeof NetworkAddressClassSchema>

export const NetworkEntryPurposeSchema = z.enum(['execution', 'ssrf-target'])

export type NetworkEntryPurpose = z.infer<typeof NetworkEntryPurposeSchema>

export const ScopeNetworkEntrySchema = z
  .object({
    id: z.string().min(1),
    addressClass: NetworkAddressClassSchema,
    host: z.string().min(1).optional(),
    ip: z.string().min(1).optional(),
    cidr: z.string().min(1).optional(),
    ports: z.array(z.number().int().positive().max(65_535)).min(1),
    purpose: NetworkEntryPurposeSchema
  })
  .refine(
    (entry) =>
      entry.host !== undefined ||
      entry.ip !== undefined ||
      entry.cidr !== undefined,
    'A network entry must pin at least one of host, ip, or cidr.'
  )

export type ScopeNetworkEntry = z.infer<typeof ScopeNetworkEntrySchema>

export const TargetScopeSchema = z.object({
  id: z.string().min(1),
  allowedOrigins: z.array(z.string().min(1)).min(1),
  allowedPathPrefixes: z.array(z.string().min(1)).default(['/']),
  deniedPathPrefixes: z.array(z.string().min(1)).default([]),
  allowedPorts: z.array(z.number().int().positive().max(65_535)).default([]),
  allowedIdentityIds: z.array(z.string().min(1)).default([]),
  allowActiveProbing: z.boolean().default(true),
  allowSensitiveProbing: z.boolean().default(false),
  allowPrivateNetworkTargets: z.boolean().default(false),
  allowLoopbackTargets: z.boolean().default(false),
  networkEntries: z.array(ScopeNetworkEntrySchema).default([]),
  maxRequestsPerMinute: z.number().int().positive().max(600),
  maxConcurrency: z.number().int().positive().max(32),
  authorizationReference: z.string().max(500).optional(),
  validFrom: z.string().datetime().optional(),
  validUntil: z.string().datetime().optional()
})

export type TargetScope = z.infer<typeof TargetScopeSchema>

export const ProbeActionSchema = z.object({
  id: z.string().min(1),
  kind: z.enum(['http-request', 'browser-action', 'tool-call']),
  targetUrl: z.string().url(),
  method: z.string().min(1).default('GET'),
  identityId: z.string().min(1).optional(),
  scopeSnapshotId: z.string().min(1).optional(),
  probeLevel: ProbeLevelSchema,
  sideEffect: SideEffectSchema,
  summary: z.string().min(1),
  payloadSummary: z.string().optional(),
  expectedEvidence: z.string().min(1),
  cleanupPlan: z.string().optional(),
  requestedRequestsPerMinute: z.number().int().positive().optional(),
  requestedConcurrency: z.number().int().positive().optional(),
  maxRequests: z.number().int().positive().max(100).default(1),
  timeoutMs: z.number().int().positive().max(120_000).default(15_000),
  maxRequestBytes: z.number().int().positive().max(1_146_880).optional(),
  maxResponseBytes: z.number().int().positive().max(16_777_216).optional(),
  maxRedirects: z.number().int().nonnegative().max(10).optional(),
  maxRepeats: z.number().int().nonnegative().max(100).optional(),
  userApproved: z.boolean().default(false)
})

export type ProbeAction = z.infer<typeof ProbeActionSchema>

export const PolicyCodeSchema = z.enum([
  'allowed',
  'invalid-target',
  'scope-expired',
  'scope-not-yet-valid',
  'out-of-scope',
  'identity-out-of-scope',
  'network-address-blocked',
  'redirect-out-of-scope',
  'active-probing-disabled',
  'sensitive-probing-disabled',
  'approval-required',
  'destructive-action',
  'unknown-side-effect',
  'http-method-blocked',
  'mutating-method-requires-l2',
  'rate-limit-exceeded',
  'concurrency-limit-exceeded',
  'url-canonicalization-failed',
  'network-target-not-authorized',
  'budget-exhausted-rpm',
  'budget-exhausted-concurrency',
  'budget-exhausted-bytes',
  'budget-exhausted-duration',
  'response-header-too-large',
  'response-decompressed-too-large',
  'response-compression-bomb',
  'response-decompression-failed',
  'response-slow-read',
  'redirect-protocol-downgraded'
])

export type PolicyCode = z.infer<typeof PolicyCodeSchema>

export const PolicyDecisionSchema = z.object({
  allowed: z.boolean(),
  requiresApproval: z.boolean(),
  code: PolicyCodeSchema,
  reasons: z.array(z.string()),
  normalizedTarget: z.string().url().optional()
})

export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>
