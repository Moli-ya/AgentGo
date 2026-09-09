import {
  CandidateSeedSchema,
  isLegacyV1VulnerabilityFamily,
  type CandidateSeed,
  type ImportPreviewOperation,
  type InventoryEndpoint,
  type VulnerabilityFamily
} from '@agentgo/contracts'
import type { DefinitionRegistry } from '@agentgo/domain'
import { LEGACY_PARAMETER_HINTS } from './legacy-parameter-hints'
import {
  IDOR_V2_TECHNIQUE_IDS,
  SECURITY_HEADERS_TECHNIQUE_IDS,
  SQLI_V2_TECHNIQUE_IDS,
  SSRF_V2_TECHNIQUE_IDS,
  XSS_V2_TECHNIQUE_IDS
} from './vulnerability-bundles'

export interface DetectorInventorySurface {
  readonly endpoint: InventoryEndpoint
  readonly variantIds: readonly string[]
  readonly method: string
  readonly reviewStatus?: string
  readonly codec?: string
  readonly executionClass?: string
  readonly contentType?: string
  readonly schemaHints?: Readonly<Record<string, DetectorSchemaHint>>
  readonly sinkHints?: Readonly<Record<string, DetectorSinkHint>>
  readonly producer?: string
}

export interface DetectorIdentityHint {
  readonly id: string
  readonly role: string
  readonly isTestIdentity: boolean
  readonly ownedResourceIds: readonly string[]
}

export interface DetectorSchemaHint {
  readonly format?: string
  readonly resourceKind?: 'resource-id' | 'owner' | 'tenant' | 'opaque'
  readonly ownerField?: string
  readonly responseIdentityField?: string
  readonly operation?: 'read' | 'write'
}

export interface DetectorSinkHint {
  readonly context: 'html' | 'attribute' | 'url' | 'script' | 'json' | 'dom' | 'text'
  readonly encoding?: string
  readonly csp?: string
  readonly source?: string
}

export interface DetectorServiceInput {
  readonly families: readonly VulnerabilityFamily[]
  readonly surfaces: readonly DetectorInventorySurface[]
  readonly registry: DefinitionRegistry
  readonly identities?: readonly DetectorIdentityHint[]
  readonly matrixId?: string
}

const SQLI_TIME_NAME =
  /(?:^|_)(?:wait|sleep|delay|latency|timeout)(?:$|_)/i
const SQLI_ERROR_NAME =
  /(?:^|_)(?:error|errmsg|sql|debug|exception|stack|msg)(?:$|_)/i
const BOLA_RESOURCE_NAME =
  /(?:^|_)(?:order|document|file|object|record|item)(?:_?id)?(?:$|_)/i
const RANDOM_ID_NAME = /^(?:uuid|guid|token|nonce|utm_[a-z0-9]+)$/i
const FROZEN_TWO_IDENTITY_QUERY =
  /^(?:id|uid|user_id|account_id|resource_id)$/i
const XSS_DOM_NAME = /(?:hash|fragment|sink|dom)/i
const FROZEN_SSRF_QUERY = /^url$/i
const SSRF_OOB_NAME = /(?:callback|webhook)/i
const SSRF_FETCH_NAME =
  /(?:^|_)(?:uri|target|endpoint|fetch|image|avatar|src)(?:$|_)/i
const CLIENT_URL_NAME =
  /^(?:next|redirect|return|return_url|returnurl|website|homepage|link|href)$/i

function parameterType(parameter: InventoryEndpoint['parameters'][number]): string {
  return (parameter.dataType ?? '').toLowerCase()
}

function isNumericType(parameter: InventoryEndpoint['parameters'][number]): boolean {
  const type = parameterType(parameter)
  return type === 'number' || type === 'integer'
}

/**
 * One SQLi technique per parameter. Query `id` (legacy 10-case) always stays
 * on boolean-differential so Day 16 cannot triple-probe the frozen suite.
 */
export function selectSqliTechnique(input: {
  readonly parameter: InventoryEndpoint['parameters'][number]
  readonly method: string
  readonly codec?: string
}): (typeof SQLI_V2_TECHNIQUE_IDS)[keyof typeof SQLI_V2_TECHNIQUE_IDS] | undefined {
  const { parameter } = input
  const location = parameter.location
  if (location === 'header' || location === 'cookie') {
    return SQLI_V2_TECHNIQUE_IDS.booleanDifferential
  }
  if (location === 'form' || location === 'json') {
    return SQLI_V2_TECHNIQUE_IDS.booleanDifferential
  }
  if (location !== 'query' && location !== 'path') return undefined

  if (location === 'query' && SQLI_TIME_NAME.test(parameter.name)) {
    return SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential
  }
  if (SQLI_ERROR_NAME.test(parameter.name)) {
    return SQLI_V2_TECHNIQUE_IDS.errorSignal
  }
  if (
    isNumericType(parameter) ||
    LEGACY_PARAMETER_HINTS.sqli.test(parameter.name) ||
    location === 'path'
  ) {
    return SQLI_V2_TECHNIQUE_IDS.booleanDifferential
  }
  return undefined
}

/**
 * One IDOR technique per parameter. Query names like item_id/order_id use
 * BOLA; legacy 40-case names (id, resource_id, user_id) stay on the
 * qualified two-identity technique so that suite is not double-probed.
 */
export function selectIdorTechnique(input: {
  readonly parameter: InventoryEndpoint['parameters'][number]
  readonly method: string
  readonly identities?: readonly DetectorIdentityHint[]
  readonly schemaHint?: DetectorSchemaHint
}): (typeof IDOR_V2_TECHNIQUE_IDS)[keyof typeof IDOR_V2_TECHNIQUE_IDS] | undefined {
  const { parameter, schemaHint } = input
  const format = (schemaHint?.format ?? parameterType(parameter)).toLowerCase()
  if (schemaHint?.resourceKind === 'opaque') {
    return undefined
  }
  if (
    (RANDOM_ID_NAME.test(parameter.name) || format === 'uuid' || format === 'guid') &&
    !isNumericType(parameter) &&
    schemaHint?.resourceKind !== 'resource-id'
  ) {
    return undefined
  }
  const location = parameter.location
  if (location === 'header' || location === 'cookie') {
    return IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly
  }
  if (location === 'query' && FROZEN_TWO_IDENTITY_QUERY.test(parameter.name)) {
    return IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly
  }
  if (schemaHint?.resourceKind === 'resource-id' || schemaHint?.ownerField) {
    return IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential
  }
  if (location === 'form' || location === 'json' || location === 'path') {
    return IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential
  }
  if (location !== 'query') return undefined
  if (BOLA_RESOURCE_NAME.test(parameter.name)) {
    return IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential
  }
  if (LEGACY_PARAMETER_HINTS.idor.test(parameter.name)) {
    return IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly
  }
  return undefined
}

export function selectXssTechnique(input: {
  readonly parameter: InventoryEndpoint['parameters'][number]
  readonly method: string
  readonly sinkHint?: DetectorSinkHint
}): (typeof XSS_V2_TECHNIQUE_IDS)[keyof typeof XSS_V2_TECHNIQUE_IDS] | undefined {
  const { parameter, sinkHint } = input
  const location = parameter.location
  if (location === 'header' || location === 'cookie') {
    return XSS_V2_TECHNIQUE_IDS.reflectedInertMarker
  }
  if (location === 'form' || location === 'json' || sinkHint?.context === 'json') {
    return XSS_V2_TECHNIQUE_IDS.storedTestObject
  }
  if (
    location === 'path' ||
    XSS_DOM_NAME.test(parameter.name) ||
    sinkHint?.context === 'dom' ||
    sinkHint?.context === 'script'
  ) {
    return XSS_V2_TECHNIQUE_IDS.domOfflineReplay
  }
  if (location === 'query' && LEGACY_PARAMETER_HINTS.xss.test(parameter.name)) {
    return XSS_V2_TECHNIQUE_IDS.reflectedInertMarker
  }
  return undefined
}

/**
 * One SSRF technique per parameter. Frozen 40-case query `url` stays on the
 * qualified controlled-proof technique. Ordinary client-navigation URL
 * fields do not become candidates.
 */
export function selectSsrfTechnique(input: {
  readonly parameter: InventoryEndpoint['parameters'][number]
  readonly method: string
  readonly schemaHint?: DetectorSchemaHint
}): (typeof SSRF_V2_TECHNIQUE_IDS)[keyof typeof SSRF_V2_TECHNIQUE_IDS] | undefined {
  const { parameter, schemaHint } = input
  const location = parameter.location
  if (location === 'header' || location === 'cookie') {
    return SSRF_V2_TECHNIQUE_IDS.controlledProofResponse
  }
  if (location === 'form' || location === 'json') {
    return SSRF_V2_TECHNIQUE_IDS.reflectedProof
  }
  if (location !== 'query' && location !== 'path') return undefined
  if (location === 'query' && FROZEN_SSRF_QUERY.test(parameter.name)) {
    return SSRF_V2_TECHNIQUE_IDS.controlledProofResponse
  }
  if (CLIENT_URL_NAME.test(parameter.name)) {
    return undefined
  }
  if (SSRF_OOB_NAME.test(parameter.name)) {
    return SSRF_V2_TECHNIQUE_IDS.oobCallback
  }
  const format = (schemaHint?.format ?? parameterType(parameter)).toLowerCase()
  const fetchSemantic =
    SSRF_FETCH_NAME.test(parameter.name) ||
    schemaHint?.operation === 'read' &&
      (format === 'uri' || format === 'url') &&
      !CLIENT_URL_NAME.test(parameter.name)
  if (fetchSemantic || LEGACY_PARAMETER_HINTS.ssrf.test(parameter.name)) {
    if (FROZEN_SSRF_QUERY.test(parameter.name)) {
      return SSRF_V2_TECHNIQUE_IDS.controlledProofResponse
    }
    return SSRF_V2_TECHNIQUE_IDS.reflectedProof
  }
  return undefined
}

export function importOperationKey(method: string, url: string): string {
  try {
    const parsed = new URL(url)
    return `${method.toUpperCase()} ${parsed.origin}${parsed.pathname}`
  } catch {
    return `${method.toUpperCase()} ${url.split(/[?#]/u)[0] ?? url}`
  }
}

export function schemaHintsFromImportOperations(
  endpoint: InventoryEndpoint,
  operations: readonly ImportPreviewOperation[]
): Readonly<Record<string, DetectorSchemaHint>> {
  const key = importOperationKey(endpoint.method, endpoint.url)
  const operation = operations.find(
    (item) => importOperationKey(item.method, item.url) === key
  )
  if (!operation?.parameters?.length) return {}
  const hints: Record<string, DetectorSchemaHint> = {}
  for (const parameter of endpoint.parameters) {
    const imported = operation.parameters.find(
      (item) =>
        item.name === parameter.name &&
        (item.location === parameter.location ||
          (item.location === 'body' && parameter.location === 'json'))
    )
    if (!imported) continue
    hints[parameter.id] = {
      format: imported.format ?? imported.valueType,
      operation:
        imported.location === 'form' || imported.location === 'body'
          ? 'write'
          : 'read',
      ...(imported.resourceKind ? { resourceKind: imported.resourceKind } : {}),
      ...(imported.ownerField ? { ownerField: imported.ownerField } : {}),
      ...(imported.responseIdentityField
        ? { responseIdentityField: imported.responseIdentityField }
        : {})
    }
  }
  return hints
}

/**
 * Pure detector: frozen inventory only. No I/O, no Agent, no risk promotion.
 */
export class DetectorService {
  detect(input: DetectorServiceInput): CandidateSeed[] {
    const seeds: CandidateSeed[] = []
    for (const familyId of input.families) {
      const family = input.registry.getFamily(familyId)
      if (!family) continue
      for (const bundle of input.registry.listBundles()) {
        if (bundle.bundle.manifest.family.familyId !== familyId) continue
        for (const technique of bundle.bundle.manifest.techniques) {
          const detector = bundle.bundle.detectors.find(
            (item) => item.techniqueId === technique.techniqueId
          )
          if (!detector) continue
          seeds.push(
            ...this.seedsForTechnique({
              familyId,
              techniqueId: technique.techniqueId,
              moduleVersion: technique.version,
              detectorId: detector.detectorId,
              declaredMode: technique.declaredMode,
              surfaces: input.surfaces,
              identities: input.identities ?? [],
              strategyId: technique.strategyRefs[0]?.id ?? `${familyId}.legacy.strategy`,
              ...(input.matrixId ? { matrixId: input.matrixId } : {})
            })
          )
        }
      }
    }
    return seeds.map((seed) => CandidateSeedSchema.parse(seed))
  }

  private seedsForTechnique(input: {
    readonly familyId: string
    readonly techniqueId: string
    readonly moduleVersion: string
    readonly detectorId: string
    readonly declaredMode: string
    readonly surfaces: readonly DetectorInventorySurface[]
      readonly identities: readonly DetectorIdentityHint[]
      readonly strategyId: string
      readonly matrixId?: string
    }): CandidateSeed[] {
    if (input.declaredMode === 'signal-only' || input.declaredMode === 'inventory-only') {
      const surface = input.surfaces[0]
      if (!surface) return []
      return [
        {
          familyId: input.familyId,
          techniqueId: input.techniqueId,
          moduleVersion: input.moduleVersion,
          detectorId: input.detectorId,
          subjectRefs: [{ kind: 'endpoint', id: surface.endpoint.id }],
          variantRefs: [...surface.variantIds],
          dependencyRefs: [],
          identityRefs: input.identities.filter((item) => item.isTestIdentity).map((item) => item.id),
          testObjectRefs: [],
          matrixRefs: [],
          reason: `${input.techniqueId} observed on frozen inventory; no active I/O.`,
          expectedSignal: input.techniqueId,
          suggestedStrategy: input.strategyId,
          confidenceHint: 0.4
        }
      ]
    }
    if (input.familyId === 'sqli') {
      return this.parameterSeeds(input, (surface, parameter) =>
        selectSqliTechnique({
          parameter,
          method: surface.method,
          ...(surface.codec ? { codec: surface.codec } : {})
        })
      )
    }
    if (input.familyId === 'idor') {
      return this.parameterSeeds(input, (surface, parameter) =>
        selectIdorTechnique({
          parameter,
          method: surface.method,
          identities: input.identities,
          ...(surface.schemaHints?.[parameter.id]
            ? { schemaHint: surface.schemaHints[parameter.id] }
            : {})
        })
      )
    }
    if (input.familyId === 'xss') {
      return this.parameterSeeds(input, (surface, parameter) =>
        selectXssTechnique({
          parameter,
          method: surface.method,
          ...(surface.sinkHints?.[parameter.id]
            ? { sinkHint: surface.sinkHints[parameter.id] }
            : {})
        })
      )
    }
    if (input.familyId === 'ssrf') {
      return this.parameterSeeds(input, (surface, parameter) =>
        selectSsrfTechnique({
          parameter,
          method: surface.method,
          ...(surface.schemaHints?.[parameter.id]
            ? { schemaHint: surface.schemaHints[parameter.id] }
            : {})
        })
      )
    }
    if (
      input.familyId === 'security.headers' &&
      input.techniqueId === SECURITY_HEADERS_TECHNIQUE_IDS.baseline
    ) {
      return input.surfaces.map((surface) => ({
        familyId: input.familyId,
        techniqueId: input.techniqueId,
        moduleVersion: input.moduleVersion,
        detectorId: input.detectorId,
        subjectRefs: [{ kind: 'endpoint' as const, id: surface.endpoint.id }],
        variantRefs: [...surface.variantIds],
        dependencyRefs: [],
        identityRefs: [],
        testObjectRefs: [],
        matrixRefs: [],
        reason: `${input.techniqueId} analyzes already-captured response headers; zero new network.`,
        expectedSignal: input.techniqueId,
        suggestedStrategy: input.strategyId,
        confidenceHint: 0.55
      }))
    }
    if (!isLegacyV1VulnerabilityFamily(input.familyId)) return []
    const hint = LEGACY_PARAMETER_HINTS[input.familyId]
    const seeds: CandidateSeed[] = []
    for (const surface of input.surfaces) {
      if (surface.method.toUpperCase() !== 'GET') continue
      for (const parameter of surface.endpoint.parameters) {
        if (parameter.location !== 'query' || !hint.test(parameter.name)) continue
        seeds.push(
          this.seedFrom(
            input,
            surface,
            parameter,
            0.7,
            `参数 ${parameter.name} 的语义符合 ${input.familyId} 安全验证候选。`
          )
        )
      }
    }
    return seeds
  }

  private parameterSeeds(
    input: {
      readonly familyId: string
      readonly techniqueId: string
      readonly moduleVersion: string
      readonly detectorId: string
      readonly surfaces: readonly DetectorInventorySurface[]
      readonly identities: readonly DetectorIdentityHint[]
      readonly strategyId: string
      readonly matrixId?: string
    },
    select: (
      surface: DetectorInventorySurface,
      parameter: InventoryEndpoint['parameters'][number]
    ) => string | undefined
  ): CandidateSeed[] {
    const seeds: CandidateSeed[] = []
    const owners = input.identities.filter(
      (item) => item.isTestIdentity && item.ownedResourceIds.length > 0
    )
    const identityRefs = owners.map((item) => item.id)
    for (const surface of input.surfaces) {
      const method = surface.method.toUpperCase()
      for (const parameter of surface.endpoint.parameters) {
        const selected = select(surface, parameter)
        if (selected !== input.techniqueId) continue
        const location = parameter.location
        if (
          method !== 'GET' &&
          location !== 'form' &&
          location !== 'json'
        ) {
          continue
        }
        const type = parameterType(parameter) || 'unknown'
        const codec = surface.codec ?? 'none'
        const reviewed = surface.reviewStatus ?? 'unspecified'
        const schema = surface.schemaHints?.[parameter.id]
        const sink = surface.sinkHints?.[parameter.id]
        const ownership = owners
          .map((item) => `${item.role}:${item.ownedResourceIds.length}`)
          .join(',')
        const reason = [
          `reviewed=${reviewed}`,
          `method=${method}`,
          `selector=${location}:${parameter.name}`,
          `type=${type}`,
          `codec=${codec}`,
          `contentType=${surface.contentType ?? 'unknown'}`,
          `operation=${schema?.operation ?? 'read'}`,
          `ownership=${ownership || 'none'}`,
          schema?.resourceKind ? `resourceKind=${schema.resourceKind}` : undefined,
          schema?.ownerField ? `ownerField=${schema.ownerField}` : undefined,
          schema?.responseIdentityField
            ? `responseIdentityField=${schema.responseIdentityField}`
            : undefined,
          sink
            ? `sink=${sink.context};encoding=${sink.encoding ?? 'unknown'};csp=${sink.csp ? 'present' : 'absent'};source=${sink.source ?? surface.producer ?? 'inventory'}`
            : undefined,
          `selected ${selected}.`
        ]
          .filter((part): part is string => Boolean(part))
          .join(' ')
        seeds.push(
          this.seedFrom(
            input,
            surface,
            parameter,
            0.7,
            reason.slice(0, 2_048),
            identityRefs
          )
        )
      }
    }
    return seeds
  }

  private seedFrom(
    input: {
      readonly familyId: string
      readonly techniqueId: string
      readonly moduleVersion: string
      readonly detectorId: string
      readonly strategyId: string
      readonly matrixId?: string
    },
    surface: DetectorInventorySurface,
    parameter: InventoryEndpoint['parameters'][number],
    confidenceHint: number,
    reason: string,
    identityRefs: readonly string[] = []
  ): CandidateSeed {
    const identitySubjects = identityRefs.slice(0, 8).map((id) => ({
      kind: 'identity' as const,
      id
    }))
    return {
      familyId: input.familyId,
      techniqueId: input.techniqueId,
      moduleVersion: input.moduleVersion,
      detectorId: input.detectorId,
      subjectRefs: [
        { kind: 'endpoint', id: surface.endpoint.id },
        ...identitySubjects
      ],
      variantRefs: [...surface.variantIds],
      dependencyRefs: [],
      identityRefs: [...identityRefs],
      testObjectRefs: [],
      matrixRefs: input.matrixId ? [input.matrixId] : [],
      parameterId: parameter.id,
      reason,
      expectedSignal: input.techniqueId,
      suggestedStrategy: input.strategyId,
      confidenceHint
    }
  }
}
