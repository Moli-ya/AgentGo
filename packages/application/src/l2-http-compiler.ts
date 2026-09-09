import {
  InventoryEndpointRecordSchema,
  RequestVariantRecordSchema,
  type CapabilityId,
  type IdentityRef,
  type InventoryEndpointRecord,
  type RequestVariantRecord,
  type SessionGenerationRef,
  type TestObjectRef
} from '@agentgo/contracts'
import {
  canonicalizeAllowedHeaderDescriptors,
  canonicalizeInventoryBodyShape,
  canonicalizeInventoryUrl,
  canonicalizeSelectorRefs,
  compareText,
  stableInventoryHash
} from '@agentgo/domain'
import { DEFAULT_PROBE_CAPABILITY_CATALOG } from '@agentgo/security-policy'
import { CsrfBindingService } from './csrf-binding-service'
import {
  ProbeRequestCompiler,
  type CompiledProbeRequest,
  type ProbeRequestTemplate,
  type RequestHashKeyProvider,
  type RequestHashKeyRef,
  type SecretRefResolver,
  type WireRequestExecutionBinding
} from './request-compiler'
import { SessionVault } from './session-vault'

const COOKIE_NAME = 'sid'
const CSRF_HEADER = 'x-csrf-token'
const TEMPLATE_VERSION = '1.0.0'
const NOW_ISO = () => new Date().toISOString()

export interface L2HttpCompileInput {
  readonly scanId: string
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  readonly url: string
  readonly identityRef: IdentityRef
  readonly sessionRef: SessionGenerationRef
  readonly testObjectRef: TestObjectRef
  readonly ownerRef: string
  readonly scopeSnapshotId: string
  readonly sessionId: string
  readonly csrfBindingHash?: string
  readonly jsonBody?: Readonly<Record<string, string | number | boolean | null>>
  readonly hashKey: RequestHashKeyRef
  readonly hashKeyProvider: RequestHashKeyProvider
  readonly sessionVault: SessionVault
  readonly csrfBindingService?: CsrfBindingService
  readonly executionBinding: WireRequestExecutionBinding
}

export async function compileL2HttpRequest(
  input: L2HttpCompileInput
): Promise<CompiledProbeRequest> {
  const mutating = input.method !== 'GET'
  if (mutating && !input.csrfBindingHash) {
    throw new Error('L2 mutating requests require a CSRF binding.')
  }
  if (mutating && !input.csrfBindingService) {
    throw new Error('L2 mutating requests require a CSRF binding service.')
  }

  const canonical = canonicalizeInventoryUrl(input.url)
  const endpoint = InventoryEndpointRecordSchema.parse({
    id: `l2-${input.executionBinding.stepId}`,
    scanId: input.scanId,
    method: input.method,
    canonicalRoute: canonical,
    lifecycleStatus: 'active',
    createdAt: NOW_ISO(),
    updatedAt: NOW_ISO()
  })

  const cookieResolver = await input.sessionVault.namedCookieSecretResolverFor(
    input.sessionId,
    COOKIE_NAME,
    input.url
  )
  if (cookieResolver.cookieValue === undefined) {
    throw new Error('L2 request has no session cookie for the bound URL.')
  }
  if (
    cookieResolver.sessionRef.id !== input.sessionRef.id ||
    cookieResolver.sessionRef.generation !== input.sessionRef.generation
  ) {
    throw new Error('Session generation drifted before L2 compilation.')
  }

  const secretResolvers: SecretRefResolver[] = [cookieResolver.resolver]
  let csrfHeader: ProbeRequestTemplate['headers'][number] | undefined
  if (mutating && input.csrfBindingHash && input.csrfBindingService) {
    const csrf = await input.csrfBindingService.tokenSecretResolverFor({
      bindingHash: input.csrfBindingHash,
      request: {
        identityId: input.identityRef.id,
        url: input.url,
        method: input.method
      }
    })
    secretResolvers.push(csrf.resolver)
    csrfHeader = {
      name: CSRF_HEADER,
      value: {
        kind: 'secret-ref',
        secretRef: csrf.binding.csrfBindingId,
        generation: csrf.binding.csrfBindingVersion,
        resolver: {
          kind: 'secret-ref-resolver',
          resolverId: CsrfBindingService.TOKEN_RESOLVER_ID,
          version: '1.0.0'
        }
      }
    }
  }

  const capabilityIds = mutating
    ? (['http.reviewed-read', 'http.test-object-write'] as const)
    : (['http.reviewed-read'] as const)
  const variant = createL2Variant({
    endpoint,
    mutating,
    capabilityIds,
    jsonBody: input.jsonBody
  })
  const template = createL2Template({
    url: input.url,
    mutating,
    jsonBody: input.jsonBody,
    sessionId: input.sessionId,
    sessionGeneration: input.sessionRef.generation,
    csrfHeader
  })

  const compiler = new ProbeRequestCompiler({
    mutationGenerators: [],
    dynamicValueResolvers: [],
    secretRefResolvers: secretResolvers,
    knownCapabilityIds: DEFAULT_PROBE_CAPABILITY_CATALOG.list().map(
      (descriptor) => descriptor.id as CapabilityId
    ),
    hashKeyProvider: input.hashKeyProvider
  })

  return compiler.compile({
    scanId: input.scanId,
    endpoint,
    requestVariant: variant,
    requestTemplate: template,
    enabledCapabilityIds: [...capabilityIds],
    hashKey: input.hashKey,
    ownerRef: input.ownerRef,
    scopeSnapshotId: input.scopeSnapshotId,
    identityRef: input.identityRef,
    sessionRef: input.sessionRef,
    testObjectRef: input.testObjectRef,
    executionBinding: input.executionBinding
  })
}

function jsonPointerToken(value: string): string {
  return value.replace(/~/gu, '~0').replace(/\//gu, '~1')
}

function jsonLiteralValueType(
  value: string | number | boolean | null
): 'string' | 'number' | 'integer' | 'boolean' | 'null' {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return 'boolean'
  if (typeof value === 'string') return 'string'
  return Number.isInteger(value) ? 'integer' : 'number'
}

export function l2JsonBodyFields(
  jsonBody: Readonly<Record<string, string | number | boolean | null>> | undefined
): Array<{
  readonly path: string
  readonly valueType: 'string' | 'number' | 'integer' | 'boolean' | 'null'
  readonly required: boolean
}> {
  return Object.entries(jsonBody ?? {}).map(([key, value]) => ({
    path: `/${jsonPointerToken(key)}`,
    valueType: jsonLiteralValueType(value),
    required: true
  }))
}

function createL2Variant(input: {
  readonly endpoint: InventoryEndpointRecord
  readonly mutating: boolean
  readonly capabilityIds: readonly CapabilityId[]
  readonly jsonBody?: Readonly<Record<string, string | number | boolean | null>>
}): RequestVariantRecord {
  const codec = input.mutating ? 'json' : 'none'
  const bodyShape = canonicalizeInventoryBodyShape(
    input.mutating
      ? { rootType: 'object', fields: l2JsonBodyFields(input.jsonBody) }
      : { rootType: 'none', fields: [] }
  )
  const allowedHeaders = canonicalizeAllowedHeaderDescriptors(
    input.mutating
      ? [{ name: CSRF_HEADER, valueType: 'string', required: true }]
      : []
  )
  const selectors = canonicalizeSelectorRefs([
    { kind: 'cookie', name: COOKIE_NAME, valueType: 'string', required: true },
    ...(input.mutating
      ? [
          {
            kind: 'header' as const,
            name: CSRF_HEADER,
            valueType: 'string' as const,
            required: true
          }
        ]
      : [])
  ])
  const requiredCapabilityIds = [...input.capabilityIds].sort(compareText)
  const structuralValue = {
    contentType: input.mutating ? 'application/json' : null,
    bodyShape,
    codec,
    transport: 'standard-http' as const,
    allowedHeaders,
    templateVersion: TEMPLATE_VERSION,
    requiredCapabilityIds,
    selectors
  }
  return RequestVariantRecordSchema.parse({
    id: `${input.endpoint.id}-variant`,
    scanId: input.endpoint.scanId,
    endpointId: input.endpoint.id,
    ...(input.mutating ? { contentType: 'application/json' } : {}),
    bodyShape,
    codec,
    transport: 'standard-http',
    allowedHeaders,
    templateVersion: TEMPLATE_VERSION,
    requiredCapabilityIds,
    selectors,
    redactedPreview: { url: input.endpoint.canonicalRoute },
    reviewStatus: 'reviewed',
    reviewedBy: 'l2-http-compiler',
    reviewedAt: NOW_ISO(),
    executionClass: 'active-l2',
    lifecycleStatus: 'active',
    structureHash: stableInventoryHash(structuralValue),
    createdAt: NOW_ISO(),
    updatedAt: NOW_ISO()
  })
}

function createL2Template(input: {
  readonly url: string
  readonly mutating: boolean
  readonly jsonBody?: Readonly<Record<string, string | number | boolean | null>>
  readonly sessionId: string
  readonly sessionGeneration: number
  readonly csrfHeader?: ProbeRequestTemplate['headers'][number]
}): ProbeRequestTemplate {
  const parsed = new URL(input.url)
  const pathSegments =
    parsed.pathname === '/'
      ? []
      : parsed.pathname
          .slice(1)
          .split('/')
          .map((segment) => ({
            value: {
              kind: 'literal' as const,
              sensitivity: 'public' as const,
              value: decodeURIComponent(segment)
            }
          }))
  return {
    url: {
      origin: {
        kind: 'literal',
        sensitivity: 'public',
        value: parsed.origin
      },
      pathSegments
    },
    query: [],
    headers: input.csrfHeader ? [input.csrfHeader] : [],
    cookies: [
      {
        name: COOKIE_NAME,
        value: {
          kind: 'secret-ref',
          secretRef: input.sessionId,
          generation: input.sessionGeneration,
          resolver: {
            kind: 'secret-ref-resolver',
            resolverId: SessionVault.COOKIE_RESOLVER_ID,
            version: '1.0.0'
          }
        }
      }
    ],
    body: input.mutating
      ? {
          encoding: 'json',
          value: {
            kind: 'object',
            entries: Object.entries(input.jsonBody ?? {}).map(([key, value]) => ({
              key,
              value: { kind: 'literal' as const, sensitivity: 'public' as const, value }
            }))
          }
        }
      : { encoding: 'none' }
  }
}
