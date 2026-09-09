import {
  InventoryEndpointRecordSchema,
  RequestVariantRecordSchema,
  type CapabilityId,
  type IdentityRef,
  type RequestVariantRecord,
  type SessionGenerationRef
} from '@agentgo/contracts'
import {
  canonicalizeInventoryBodyShape,
  canonicalizeInventoryUrl,
  compareText
} from '@agentgo/domain'
import { DEFAULT_PROBE_CAPABILITY_CATALOG } from '@agentgo/security-policy'
import type { AgentGoRepository } from '@agentgo/db'
import {
  ProbeRequestCompiler,
  type CompiledProbeRequest,
  type NamedRequestValueTemplate,
  type ProbeRequestTemplate,
  type RequestHashKeyProvider,
  type RequestHashKeyRef,
  type SecretRefResolver,
  type WireRequestExecutionBinding
} from './request-compiler'
import { SessionVault } from './session-vault'

const TEMPLATE_VERSION = '1.0.0'
const COOKIE_NAME = 'sid'
const READ_CAPABILITY = 'http.reviewed-read' as const

export interface MediatedReadCompileInput {
  readonly scanId: string
  readonly endpointId: string
  readonly requestVariantId: string
  readonly desiredUrl: string
  readonly method: 'GET' | 'HEAD'
  readonly ownerRef: string
  readonly scopeSnapshotId: string
  readonly hashKey: RequestHashKeyRef
  readonly hashKeyProvider: RequestHashKeyProvider
  readonly executionBinding: WireRequestExecutionBinding
  readonly identityRef?: IdentityRef
  readonly sessionRef?: SessionGenerationRef
  readonly sessionId?: string
  readonly sessionVault?: SessionVault
}

export async function compileMediatedRead(
  repository: AgentGoRepository,
  input: MediatedReadCompileInput
): Promise<CompiledProbeRequest> {
  const endpointRecord = await repository.getInventoryEndpointRecord(
    input.endpointId,
    input.scanId
  )
  const variantRecord = await repository.getInventoryRequestVariant(
    input.requestVariantId,
    input.scanId
  )
  if (!endpointRecord || !variantRecord) {
    throw new Error('Mediated-read inventory binding is missing.')
  }
  if (endpointRecord.method !== input.method) {
    throw new Error('Mediated-read method does not match the reviewed endpoint.')
  }
  const canonical = canonicalizeInventoryUrl(input.desiredUrl)
  if (endpointRecord.canonicalRoute !== canonical) {
    throw new Error('Mediated-read URL does not match the reviewed canonical route.')
  }
  if (
    variantRecord.reviewStatus !== 'reviewed' ||
    variantRecord.executionClass !== 'active-l1' ||
    variantRecord.codec !== 'none' ||
    variantRecord.transport !== 'standard-http' ||
    !variantRecord.requiredCapabilityIds.includes(READ_CAPABILITY)
  ) {
    throw new Error('Mediated-read variant is not a reviewed L1 HTTP read.')
  }

  const endpoint = InventoryEndpointRecordSchema.parse(endpointRecord)
  const variant = RequestVariantRecordSchema.parse(variantRecord)
  const secretResolvers: SecretRefResolver[] = []
  const cookies: NamedRequestValueTemplate[] = []
  const hasCookieSelector = variant.selectors.some(
    (selector) => selector.kind === 'cookie' && selector.name === COOKIE_NAME
  )
  if (
    hasCookieSelector &&
    input.sessionId &&
    input.sessionRef &&
    input.sessionVault
  ) {
    const cookieResolver = await input.sessionVault.namedCookieSecretResolverFor(
      input.sessionId,
      COOKIE_NAME,
      input.desiredUrl
    )
    if (cookieResolver.cookieValue !== undefined) {
      secretResolvers.push(cookieResolver.resolver)
      cookies.push({
        name: COOKIE_NAME,
        value: {
          kind: 'secret-ref',
          secretRef: input.sessionId,
          generation: input.sessionRef.generation,
          resolver: {
            kind: 'secret-ref-resolver',
            resolverId: SessionVault.COOKIE_RESOLVER_ID,
            version: '1.0.0'
          }
        }
      })
    }
  }

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
    requestTemplate: createReadTemplate(input.desiredUrl, cookies),
    enabledCapabilityIds: [...variant.requiredCapabilityIds].sort(compareText),
    hashKey: input.hashKey,
    ownerRef: input.ownerRef,
    scopeSnapshotId: input.scopeSnapshotId,
    ...(input.identityRef ? { identityRef: input.identityRef } : {}),
    ...(input.sessionRef ? { sessionRef: input.sessionRef } : {}),
    executionBinding: input.executionBinding
  })
}

export function createEmptyHttpBodyShape(): RequestVariantRecord['bodyShape'] {
  return canonicalizeInventoryBodyShape({ rootType: 'none', fields: [] })
}

export function createMediatedReadTemplateVersion(): string {
  return TEMPLATE_VERSION
}

function createReadTemplate(
  url: string,
  cookies: ProbeRequestTemplate['cookies']
): ProbeRequestTemplate {
  const parsed = new URL(url)
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
    headers: [],
    cookies,
    body: { encoding: 'none' }
  }
}
