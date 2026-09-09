import {
  DefinitionIdSchema,
  ExecutionCredentialRefSchema,
  ExecutionPurposeSchema,
  IdentityRefSchema,
  IdentitySchema,
  LegacyV1VulnerabilityFamilySchema,
  MutationGeneratorMetadataSchema,
  SystemIssuedOpaqueIdSchema,
  type CapabilityId,
  type ExecutionCredentialRef,
  type IdentityRecord,
  type LegacyV1VulnerabilityFamily,
  type IdentityRef,
  type InventoryEndpointRecord,
  type RequestVariantRecord,
  type TargetScopeRecord
} from '@agentgo/contracts'
import type {
  AgentGoRepository,
  CredentialMetadata,
  FileCredentialStore,
  LegacyV1ExecutionBinding
} from '@agentgo/db'
import {
  ProbeRequestCompiler,
  type CompiledProbeRequest,
  type DynamicValueResolver,
  type DynamicValueResolverInput,
  type MutationGenerator,
  type MutationGeneratorInput,
  type NamedRequestValueTemplate,
  type ProbeRequestCompilerInput,
  type ProbeRequestTemplate,
  type RequestHashKeyProvider,
  type RequestHashKeyRef,
  type SecretRefResolver,
  type SecretRefResolverInput,
  type WireRequestExecutionBinding
} from './request-compiler'

const QUERY_VALUE_RESOLVER_ID = 'legacy.v1.query-value'
const PATH_VALUE_RESOLVER_ID = 'legacy.v1.path-value'
const CREDENTIAL_RESOLVER_ID = 'legacy.v1.identity-credential'
const QUERY_MUTATION_GENERATOR_ID = 'legacy.v1.fixed-query-mutation'
const PATH_MUTATION_GENERATOR_ID = 'legacy.v1.fixed-path-mutation'
const ADAPTER_COMPONENT_VERSION = '1.0.0'
const REVIEWED_LEGACY_HEADER_VALUES = Object.freeze({
  accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
  'user-agent': 'AgentGo/0.1 Authorized Security Validation'
})

export type LegacyV1RequestCompilerAdapterErrorCode =
  | 'invalid-input'
  | 'binding-not-found'
  | 'binding-rejected'
  | 'identity-rejected'
  | 'credential-unavailable'
  | 'compile-rejected'
  | 'raw-target-mismatch'

const SAFE_ERROR_MESSAGES: Record<
  LegacyV1RequestCompilerAdapterErrorCode,
  string
> = {
  'invalid-input': 'The legacy request compiler adapter input is invalid.',
  'binding-not-found': 'No reviewed legacy request binding is available.',
  'binding-rejected': 'The reviewed legacy request binding is inconsistent.',
  'identity-rejected': 'The legacy execution identity is not authorized.',
  'credential-unavailable': 'The legacy execution credential is unavailable.',
  'compile-rejected': 'The reviewed legacy request could not be compiled.',
  'raw-target-mismatch': 'The compiled request does not match the desired target.'
}

export class LegacyV1RequestCompilerAdapterError extends Error {
  readonly code: LegacyV1RequestCompilerAdapterErrorCode

  constructor(code: LegacyV1RequestCompilerAdapterErrorCode) {
    super(SAFE_ERROR_MESSAGES[code])
    this.name = 'LegacyV1RequestCompilerAdapterError'
    this.code = code
  }
}

export interface LegacyV1QueryMutation {
  readonly kind?: 'query'
  readonly name: string
  readonly occurrence: number | 'all'
  readonly value: string
}

export interface LegacyV1PathMutation {
  readonly selectorName: string
  readonly segmentIndex: number
  readonly value: string
}

export interface LegacyV1RequestCompilerAdapterInput {
  readonly scanId: string
  readonly endpointId: string
  readonly desiredTargetUrl: string
  readonly familyId?: LegacyV1VulnerabilityFamily
  readonly identityId?: string
  readonly credentialMode?: 'include' | 'omit'
  readonly queryMutation?: LegacyV1QueryMutation
  readonly pathMutation?: LegacyV1PathMutation
  readonly executionBinding?: WireRequestExecutionBinding
}

type SnapshotLegacyV1RequestCompilerAdapterInput = Omit<
  LegacyV1RequestCompilerAdapterInput,
  'credentialMode'
> & Readonly<{ credentialMode: 'include' | 'omit' }>

export interface LegacyV1RequestCompilerAdapterOutput {
  readonly endpoint: InventoryEndpointRecord
  readonly requestVariant: RequestVariantRecord
  readonly compiledRequest: CompiledProbeRequest
  readonly capabilityIds: readonly CapabilityId[]
  readonly scopeSnapshotId: string
  readonly ownerRef: string
  readonly identityRef?: IdentityRef
  readonly credentialRef: ExecutionCredentialRef | null
  readonly requestBytes: number
}

type LegacyRepositoryPort = Pick<
  AgentGoRepository,
  'getIdentity' | 'getLegacyV1ExecutionBinding' | 'getScanRow' | 'getScope'
>

type LegacyCredentialStorePort = Pick<
  FileCredentialStore,
  'get' | 'isAvailable' | 'list'
>

export interface LegacyV1RequestCompilerAdapterDependencies {
  readonly repository: LegacyRepositoryPort
  readonly credentialStore: LegacyCredentialStorePort
  readonly hashKeyProvider: RequestHashKeyProvider
  readonly hashKey: RequestHashKeyRef
}

interface PreparedIdentity {
  readonly ownerRef: string
  readonly identityRef?: IdentityRef
  readonly credentialRef: ExecutionCredentialRef | null
  readonly authorizedIdentityHeaders: readonly NamedRequestValueTemplate[]
  readonly secretResolver?: SecretRefResolver
}

interface PreparedCredential {
  readonly secret: string
  readonly generation: number
}

function fail(code: LegacyV1RequestCompilerAdapterErrorCode): never {
  throw new LegacyV1RequestCompilerAdapterError(code)
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function timestampVersion(
  value: string,
  errorCode: 'identity-rejected' | 'credential-unavailable'
): number {
  const version = Date.parse(value)
  if (!Number.isSafeInteger(version) || version < 0) fail(errorCode)
  return version
}

function credentialGeneration(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail('credential-unavailable')
  }
  return value as number
}

function snapshotInput(
  input: LegacyV1RequestCompilerAdapterInput
): SnapshotLegacyV1RequestCompilerAdapterInput {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('invalid-input')
  }
  const allowedKeys = new Set([
    'credentialMode',
    'desiredTargetUrl',
    'endpointId',
    'executionBinding',
    'familyId',
    'identityId',
    'pathMutation',
    'queryMutation',
    'scanId'
  ])
  if (Object.keys(input).some((key) => !allowedKeys.has(key))) {
    fail('invalid-input')
  }
  if (
    typeof input.scanId !== 'string' ||
    input.scanId.length === 0 ||
    typeof input.endpointId !== 'string' ||
    input.endpointId.length === 0 ||
    typeof input.desiredTargetUrl !== 'string' ||
    input.desiredTargetUrl.length === 0
  ) {
    fail('invalid-input')
  }

  let familyId: LegacyV1VulnerabilityFamily | undefined
  if (input.familyId !== undefined) {
    const parsedFamilyId = LegacyV1VulnerabilityFamilySchema.safeParse(
      input.familyId
    )
    if (!parsedFamilyId.success) fail('invalid-input')
    familyId = parsedFamilyId.data
  }

  let identityId: string | undefined
  if (input.identityId !== undefined) {
    const parsedIdentityId = SystemIssuedOpaqueIdSchema.safeParse(
      input.identityId
    )
    if (!parsedIdentityId.success) fail('invalid-input')
    identityId = parsedIdentityId.data
  }
  if (
    input.credentialMode !== undefined &&
    input.credentialMode !== 'include' &&
    input.credentialMode !== 'omit'
  ) {
    fail('invalid-input')
  }

  let queryMutation: LegacyV1QueryMutation | undefined
  if (input.queryMutation !== undefined) {
    const value = input.queryMutation as unknown
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      fail('invalid-input')
    }
    const record = value as Record<string, unknown>
    const mutationKeys = new Set(['kind', 'name', 'occurrence', 'value'])
    if (Object.keys(record).some((key) => !mutationKeys.has(key))) {
      fail('invalid-input')
    }
    if (
      (record.kind !== undefined && record.kind !== 'query') ||
      typeof record.name !== 'string' ||
      record.name.length === 0 ||
      (record.occurrence !== 'all' &&
        (!Number.isInteger(record.occurrence) ||
          (record.occurrence as number) < 0)) ||
      typeof record.value !== 'string'
    ) {
      fail('invalid-input')
    }
    queryMutation = Object.freeze({
      ...(record.kind === 'query' ? { kind: 'query' as const } : {}),
      name: record.name,
      occurrence: record.occurrence as number | 'all',
      value: record.value
    })
  }

  let pathMutation: LegacyV1PathMutation | undefined
  if (input.pathMutation !== undefined) {
    if (queryMutation) fail('invalid-input')
    const value = input.pathMutation as unknown
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      fail('invalid-input')
    }
    const record = value as Record<string, unknown>
    const mutationKeys = new Set(['selectorName', 'segmentIndex', 'value'])
    if (Object.keys(record).some((key) => !mutationKeys.has(key))) {
      fail('invalid-input')
    }
    if (
      typeof record.selectorName !== 'string' ||
      record.selectorName.length === 0 ||
      !Number.isInteger(record.segmentIndex) ||
      (record.segmentIndex as number) < 0 ||
      typeof record.value !== 'string'
    ) {
      fail('invalid-input')
    }
    pathMutation = Object.freeze({
      selectorName: record.selectorName,
      segmentIndex: record.segmentIndex as number,
      value: record.value
    })
  }

  let executionBinding: WireRequestExecutionBinding | undefined
  if (input.executionBinding !== undefined) {
    const value = input.executionBinding as unknown
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      Object.keys(value).sort(compareText).join('\u0000') !==
        ['adapterKind', 'purpose', 'stepId'].join('\u0000')
    ) {
      fail('invalid-input')
    }
    const record = value as Record<string, unknown>
    const stepId = DefinitionIdSchema.safeParse(record.stepId)
    const purpose = ExecutionPurposeSchema.safeParse(record.purpose)
    if (
      !stepId.success ||
      !purpose.success ||
      record.adapterKind !== 'http'
    ) {
      fail('invalid-input')
    }
    executionBinding = Object.freeze({
      stepId: stepId.data,
      purpose: purpose.data,
      adapterKind: 'http'
    })
  }

  return Object.freeze({
    scanId: input.scanId,
    endpointId: input.endpointId,
    desiredTargetUrl: input.desiredTargetUrl,
    ...(familyId ? { familyId } : {}),
    ...(identityId ? { identityId } : {}),
    credentialMode: input.credentialMode ?? 'include',
    ...(queryMutation ? { queryMutation } : {}),
    ...(pathMutation ? { pathMutation } : {}),
    ...(executionBinding
      ? { executionBinding }
      : {})
  })
}

function parseDesiredTarget(value: string): URL {
  if (value.includes('#')) fail('invalid-input')
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    fail('invalid-input')
  }
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== ''
  ) {
    fail('invalid-input')
  }
  return parsed
}

function pathSegments(url: URL): readonly string[] {
  try {
    return Object.freeze(
      url.pathname
        .slice(1)
        .split('/')
        .map((segment) => decodeURIComponent(segment))
    )
  } catch {
    fail('invalid-input')
  }
}

function validateBinding(
  binding: LegacyV1ExecutionBinding,
  scanId: string,
  endpointId: string
): void {
  const { endpoint, endpointRecord, requestVariant } = binding
  if (
    endpoint.id !== endpointId ||
    endpointRecord.id !== endpointId ||
    endpointRecord.scanId !== scanId ||
    requestVariant.scanId !== scanId ||
    requestVariant.endpointId !== endpointId ||
    endpoint.method !== 'GET' ||
    endpointRecord.method !== 'GET' ||
    endpointRecord.lifecycleStatus !== 'active' ||
    requestVariant.lifecycleStatus !== 'active' ||
    requestVariant.reviewStatus !== 'reviewed' ||
    requestVariant.executionClass !== 'active-l1' ||
    requestVariant.transport !== 'standard-http' ||
    requestVariant.codec !== 'none' ||
    requestVariant.selectors.some(
      (selector) => selector.kind !== 'query' && selector.kind !== 'path'
    ) ||
    endpoint.parameters.some(
      (parameter) => parameter.location !== 'query' && parameter.location !== 'path'
    ) ||
    requestVariant.allowedHeaders.some(
      ({ name }) =>
        !Object.prototype.hasOwnProperty.call(
          REVIEWED_LEGACY_HEADER_VALUES,
          name
        )
    )
  ) {
    fail('binding-rejected')
  }
  const selectorNames = [...requestVariant.selectors]
    .map((selector) => {
      if (selector.kind !== 'query' && selector.kind !== 'path') {
        fail('binding-rejected')
      }
      return selector.name
    })
    .sort(compareText)
  const parameterNames = endpoint.parameters.map(({ name }) => name)
  const reviewedParameterNames = [...new Set(parameterNames)].sort(
    compareText
  )
  if (
    selectorNames.length !== reviewedParameterNames.length ||
    selectorNames.some((name, index) => name !== reviewedParameterNames[index])
  ) {
    fail('binding-rejected')
  }
}

function validateDesiredQueryShape(
  url: URL,
  endpoint: LegacyV1ExecutionBinding['endpoint']
): void {
  const desiredNames = [...url.searchParams.keys()]
  const reviewedNames = endpoint.parameters
    .filter((parameter) => parameter.location === 'query')
    .map(({ name }) => name)
  if (
    desiredNames.length !== reviewedNames.length ||
    desiredNames.some((name, index) => name !== reviewedNames[index])
  ) {
    fail('raw-target-mismatch')
  }
}

function reviewedHeaderTemplates(
  requestVariant: RequestVariantRecord
): readonly NamedRequestValueTemplate[] {
  return Object.freeze(
    requestVariant.allowedHeaders.map(({ name }) => {
      const value = REVIEWED_LEGACY_HEADER_VALUES[
        name as keyof typeof REVIEWED_LEGACY_HEADER_VALUES
      ]
      if (value === undefined) fail('binding-rejected')
      return Object.freeze({
        name,
        value: Object.freeze({
          kind: 'literal' as const,
          sensitivity: 'public' as const,
          value
        })
      })
    })
  )
}

function buildTemplate(
  desiredUrl: URL,
  requestVariant: RequestVariantRecord,
  pathMutation?: LegacyV1PathMutation & { originalPathUrl: URL }
): Readonly<{
  template: ProbeRequestTemplate
  resolvers: readonly DynamicValueResolver[]
}> {
  const queryValues = new Map<string, string>()
  const query = [...desiredUrl.searchParams.entries()].map(([name, value], index) => {
    const slotId = `legacy.query.${index}`
    queryValues.set(slotId, value)
    return Object.freeze({
      name,
      value: Object.freeze({
        kind: 'dynamic' as const,
        slotId,
        resolver: Object.freeze({
          kind: 'dynamic-value-resolver' as const,
          resolverId: QUERY_VALUE_RESOLVER_ID,
          version: ADAPTER_COMPONENT_VERSION
        })
      })
    })
  })
  const queryResolver: DynamicValueResolver = Object.freeze({
    resolverId: QUERY_VALUE_RESOLVER_ID,
    version: ADAPTER_COMPONENT_VERSION,
    resolve: ({ slotId }: DynamicValueResolverInput) => {
      if (!queryValues.has(slotId)) throw new Error('Unknown legacy query slot.')
      return queryValues.get(slotId)
    }
  })
  const pathSource = pathMutation?.originalPathUrl ?? desiredUrl
  const pathValues = new Map<string, string>()
  const pathSegmentTemplates = pathSegments(pathSource).map((value, index) => {
    if (pathMutation && index === pathMutation.segmentIndex) {
      const slotId = `legacy.path.${index}`
      pathValues.set(slotId, value)
      return Object.freeze({
        selectorName: pathMutation.selectorName,
        value: Object.freeze({
          kind: 'dynamic' as const,
          slotId,
          resolver: Object.freeze({
            kind: 'dynamic-value-resolver' as const,
            resolverId: PATH_VALUE_RESOLVER_ID,
            version: ADAPTER_COMPONENT_VERSION
          })
        })
      })
    }
    return Object.freeze({
      value: Object.freeze({
        kind: 'literal' as const,
        sensitivity: 'public' as const,
        value
      })
    })
  })
  const resolvers: DynamicValueResolver[] = [queryResolver]
  if (pathMutation) {
    resolvers.push(
      Object.freeze({
        resolverId: PATH_VALUE_RESOLVER_ID,
        version: ADAPTER_COMPONENT_VERSION,
        resolve: ({ slotId }: DynamicValueResolverInput) => {
          if (!pathValues.has(slotId)) throw new Error('Unknown legacy path slot.')
          return pathValues.get(slotId)
        }
      })
    )
  }
  const template: ProbeRequestTemplate = Object.freeze({
    url: Object.freeze({
      origin: Object.freeze({
        kind: 'literal' as const,
        sensitivity: 'public' as const,
        value: desiredUrl.origin
      }),
      pathSegments: Object.freeze(pathSegmentTemplates)
    }),
    query: Object.freeze(query),
    headers: reviewedHeaderTemplates(requestVariant),
    cookies: Object.freeze([]),
    body: Object.freeze({ encoding: 'none' as const })
  })
  return Object.freeze({ template, resolvers: Object.freeze(resolvers) })
}

function queryMutationMetadata(
  familyId: LegacyV1VulnerabilityFamily | undefined
) {
  const controlledOob = familyId === 'ssrf'
  return MutationGeneratorMetadataSchema.parse({
    generatorId: QUERY_MUTATION_GENERATOR_ID,
    version: ADAPTER_COMPONENT_VERSION,
    deterministic: true,
    unicodeNormalization: 'NFC',
    safety: {
      sideEffect: 'none',
      dataAccess: 'input-only',
      networkTarget: controlledOob ? 'controlled-oob' : 'request-target',
      mayExecuteInTargetContext: false
    },
    requiredCapabilityIds: controlledOob
      ? ['oob.controlled-observe']
      : [],
    forbiddenCapabilityIds: [],
    maxOutputBytes: 262_144,
    supportedSelectorKinds: ['query'],
    supportedBodyEncodings: ['none']
  })
}

function pathMutationMetadata() {
  return MutationGeneratorMetadataSchema.parse({
    generatorId: PATH_MUTATION_GENERATOR_ID,
    version: ADAPTER_COMPONENT_VERSION,
    deterministic: true,
    unicodeNormalization: 'NFC',
    safety: {
      sideEffect: 'none',
      dataAccess: 'input-only',
      networkTarget: 'request-target',
      mayExecuteInTargetContext: false
    },
    requiredCapabilityIds: [],
    forbiddenCapabilityIds: [],
    maxOutputBytes: 262_144,
    supportedSelectorKinds: ['path'],
    supportedBodyEncodings: ['none']
  })
}

function pathMutationGenerator(mutation: LegacyV1PathMutation): MutationGenerator {
  return Object.freeze({
    metadata: pathMutationMetadata(),
    generate: ({ target }: MutationGeneratorInput) => {
      if (
        target.kind !== 'path' ||
        target.selectorName !== mutation.selectorName ||
        target.segmentIndex !== mutation.segmentIndex
      ) {
        throw new Error('Legacy path mutation binding changed.')
      }
      return mutation.value
    }
  })
}

function mutationGenerator(
  mutation: LegacyV1QueryMutation,
  familyId: LegacyV1VulnerabilityFamily | undefined
): MutationGenerator {
  return Object.freeze({
    metadata: queryMutationMetadata(familyId),
    generate: ({ target }: MutationGeneratorInput) => {
      if (
        target.kind !== 'query' ||
        target.name !== mutation.name ||
        target.occurrence !== mutation.occurrence
      ) {
        throw new Error('Legacy query mutation binding changed.')
      }
      return mutation.value
    }
  })
}

function requestByteLength(
  request: ReturnType<CompiledProbeRequest['request']['materialize']>
): number {
  let bytes =
    Buffer.byteLength(request.method, 'ascii') +
    Buffer.byteLength(request.url, 'utf8')
  for (const header of request.headers) {
    bytes +=
      Buffer.byteLength(header.name, 'ascii') +
      Buffer.byteLength(header.value, 'ascii') +
      4
  }
  bytes += request.bodyBytes?.length ?? 0
  return bytes
}

export class LegacyV1RequestCompilerAdapter {
  readonly #repository: LegacyRepositoryPort
  readonly #credentialStore: LegacyCredentialStorePort
  readonly #hashKeyProvider: RequestHashKeyProvider
  readonly #hashKey: RequestHashKeyRef

  constructor(dependencies: LegacyV1RequestCompilerAdapterDependencies) {
    this.#repository = dependencies.repository
    this.#credentialStore = dependencies.credentialStore
    this.#hashKeyProvider = dependencies.hashKeyProvider
    this.#hashKey = Object.freeze({ ...dependencies.hashKey })
  }

  async compile(
    rawInput: LegacyV1RequestCompilerAdapterInput
  ): Promise<LegacyV1RequestCompilerAdapterOutput> {
    const input = snapshotInput(rawInput)
    const binding = await this.#repository.getLegacyV1ExecutionBinding(
      input.scanId,
      input.endpointId
    )
    if (!binding) fail('binding-not-found')
    validateBinding(binding, input.scanId, input.endpointId)

    const scanRow = await this.#repository.getScanRow(input.scanId)
    if (
      !scanRow ||
      scanRow.id !== input.scanId ||
      !Array.isArray(scanRow.configJson.identityIds)
    ) {
      fail('binding-rejected')
    }
    const scope = await this.#repository.getScope(scanRow.scopeSnapshotId)
    if (
      !scope ||
      scope.id !== scanRow.scopeSnapshotId ||
      scope.targetId !== scanRow.targetId
    ) {
      fail('binding-rejected')
    }

    const desiredUrl = parseDesiredTarget(input.desiredTargetUrl)
    validateDesiredQueryShape(desiredUrl, binding.endpoint)
    const originalPathUrl = parseDesiredTarget(binding.endpoint.url)
    let identity: IdentityRecord | undefined
    if (input.identityId) {
      let storedIdentity: IdentityRecord | undefined
      try {
        storedIdentity = await this.#repository.getIdentity(input.identityId)
      } catch {
        fail('identity-rejected')
      }
      const parsedIdentity = IdentitySchema.safeParse(storedIdentity)
      if (
        !parsedIdentity.success ||
        parsedIdentity.data.id !== input.identityId
      ) {
        fail('identity-rejected')
      }
      identity = parsedIdentity.data
    }
    const preparedIdentity = this.#prepareIdentity(
      identity,
      input.credentialMode,
      scanRow.targetId,
      scanRow.scopeSnapshotId,
      scanRow.configJson.identityIds,
      scope
    )
    const { template, resolvers } = buildTemplate(
      desiredUrl,
      binding.requestVariant,
      input.pathMutation
        ? { ...input.pathMutation, originalPathUrl }
        : undefined
    )
    const capabilityIds = Object.freeze(
      [
        ...binding.requestVariant.requiredCapabilityIds,
        ...(input.familyId === 'idor'
          ? ['http.identity-read-compare' as const]
          : []),
        ...(input.familyId === 'ssrf' && input.queryMutation
          ? ['oob.controlled-observe' as const]
          : [])
      ].filter((id, index, values) => values.indexOf(id) === index)
        .sort(compareText)
    )
    const generator = input.queryMutation
      ? mutationGenerator(input.queryMutation, input.familyId)
      : input.pathMutation
        ? pathMutationGenerator(input.pathMutation)
        : undefined
    const compiler = new ProbeRequestCompiler({
      mutationGenerators: generator ? [generator] : [],
      dynamicValueResolvers: [...resolvers],
      secretRefResolvers: preparedIdentity.secretResolver
        ? [preparedIdentity.secretResolver]
        : [],
      knownCapabilityIds: capabilityIds,
      hashKeyProvider: this.#hashKeyProvider
    })
    const compilerInput: ProbeRequestCompilerInput = {
      scanId: input.scanId,
      endpoint: binding.endpointRecord,
      requestVariant: binding.requestVariant,
      requestTemplate: template,
      ...(input.queryMutation
        ? {
            mutationTarget: {
              kind: 'query' as const,
              name: input.queryMutation.name,
              occurrence: input.queryMutation.occurrence,
              onMissing: 'reject' as const
            },
            mutationGenerator: {
              generatorId: QUERY_MUTATION_GENERATOR_ID,
              version: ADAPTER_COMPONENT_VERSION
            }
          }
        : input.pathMutation
          ? {
              mutationTarget: {
                kind: 'path' as const,
                selectorName: input.pathMutation.selectorName,
                segmentIndex: input.pathMutation.segmentIndex
              },
              mutationGenerator: {
                generatorId: PATH_MUTATION_GENERATOR_ID,
                version: ADAPTER_COMPONENT_VERSION
              }
            }
          : {}),
      authorizedIdentityHeaders:
        preparedIdentity.authorizedIdentityHeaders,
      enabledCapabilityIds: capabilityIds,
      hashKey: this.#hashKey,
      scopeSnapshotId: scanRow.scopeSnapshotId,
      ownerRef: preparedIdentity.ownerRef,
      ...(preparedIdentity.identityRef
        ? { identityRef: preparedIdentity.identityRef }
        : {}),
      ...(preparedIdentity.credentialRef
        ? { credentialRef: preparedIdentity.credentialRef }
        : {}),
      ...(input.executionBinding
        ? { executionBinding: input.executionBinding }
        : {})
    }

    let compiledRequest: CompiledProbeRequest
    try {
      compiledRequest = compiler.compile(compilerInput)
    } catch {
      fail('compile-rejected')
    }
    const materialized = compiledRequest.request.materialize()
    const expectedHeaderNames = [
      ...binding.requestVariant.allowedHeaders.map(({ name }) => name),
      ...preparedIdentity.authorizedIdentityHeaders.map(({ name }) =>
        name.toLowerCase()
      )
    ].sort(compareText)
    if (
      materialized.method !== binding.endpointRecord.method ||
      materialized.method !== binding.endpoint.method ||
      materialized.url !== input.desiredTargetUrl ||
      Object.prototype.hasOwnProperty.call(materialized, 'bodyBytes') ||
      materialized.headers.length !== expectedHeaderNames.length ||
      materialized.headers.some(
        ({ name }, index) => name !== expectedHeaderNames[index]
      )
    ) {
      fail('raw-target-mismatch')
    }

    return Object.freeze({
      endpoint: binding.endpointRecord,
      requestVariant: binding.requestVariant,
      compiledRequest,
      capabilityIds,
      scopeSnapshotId: scanRow.scopeSnapshotId,
      ownerRef: preparedIdentity.ownerRef,
      ...(preparedIdentity.identityRef
        ? { identityRef: preparedIdentity.identityRef }
        : {}),
      credentialRef: preparedIdentity.credentialRef,
      requestBytes: requestByteLength(materialized)
    })
  }

  #credentialMetadata(credentialId: string): CredentialMetadata {
    let entries: readonly CredentialMetadata[]
    try {
      entries = this.#credentialStore.list()
    } catch {
      fail('credential-unavailable')
    }
    if (!Array.isArray(entries)) fail('credential-unavailable')
    const matches = entries.filter(
      (entry) =>
        entry !== null &&
        typeof entry === 'object' &&
        entry.id === credentialId
    )
    const metadata = matches[0]
    if (
      matches.length !== 1 ||
      !metadata ||
      metadata.kind !== 'identity' ||
      typeof metadata.updatedAt !== 'string'
    ) {
      fail('credential-unavailable')
    }
    return metadata
  }

  #readIdentityCredential(credentialId: string): PreparedCredential {
    let available: boolean
    try {
      available = this.#credentialStore.isAvailable()
    } catch {
      fail('credential-unavailable')
    }
    if (!available) fail('credential-unavailable')

    const before = this.#credentialMetadata(credentialId)
    const generation = credentialGeneration(before.generation)
    let secret: string | undefined
    try {
      secret = this.#credentialStore.get(credentialId)
    } catch {
      fail('credential-unavailable')
    }
    if (typeof secret !== 'string' || secret.length === 0) {
      fail('credential-unavailable')
    }
    const after = this.#credentialMetadata(credentialId)
    let stillAvailable: boolean
    try {
      stillAvailable = this.#credentialStore.isAvailable()
    } catch {
      fail('credential-unavailable')
    }
    const afterGeneration = credentialGeneration(after.generation)
    if (
      !stillAvailable ||
      afterGeneration !== generation
    ) {
      fail('credential-unavailable')
    }
    return Object.freeze({ secret, generation })
  }

  #prepareIdentity(
    identity: IdentityRecord | undefined,
    credentialMode: 'include' | 'omit',
    targetId: string,
    scopeSnapshotId: string,
    scanIdentityIds: readonly string[],
    scope: TargetScopeRecord
  ): PreparedIdentity {
    if (!identity) {
      return Object.freeze({
        ownerRef: targetId,
        credentialRef: null,
        authorizedIdentityHeaders: Object.freeze([])
      })
    }
    if (
      identity.targetId !== targetId ||
      !identity.isTestIdentity ||
      !scanIdentityIds.includes(identity.id) ||
      !scope.allowedIdentityIds.includes(identity.id)
    ) {
      fail('identity-rejected')
    }
    const parsedIdentityRef = IdentityRefSchema.safeParse({
      id: identity.id,
      version: timestampVersion(identity.updatedAt, 'identity-rejected'),
      ownerRef: targetId,
      scopeSnapshotId,
      statusSummary: 'active'
    })
    if (!parsedIdentityRef.success) fail('identity-rejected')
    const identityRef = parsedIdentityRef.data
    if (identity.authType === 'none' || credentialMode === 'omit') {
      return Object.freeze({
        ownerRef: targetId,
        identityRef,
        credentialRef: null,
        authorizedIdentityHeaders: Object.freeze([])
      })
    }
    if (!identity.credentialId) fail('credential-unavailable')
    const parsedCredentialRef = SystemIssuedOpaqueIdSchema.safeParse(
      identity.credentialId
    )
    if (!parsedCredentialRef.success) fail('credential-unavailable')

    let name: string
    if (identity.authType === 'bearer' || identity.authType === 'basic') {
      name = 'authorization'
    } else if (identity.authType === 'cookie') {
      name = 'cookie'
    } else if (identity.authType === 'header' && identity.headerName) {
      name = identity.headerName
    } else {
      fail('identity-rejected')
    }
    const { secret, generation } = this.#readIdentityCredential(
      identity.credentialId
    )
    const value = identity.authType === 'bearer'
      ? `Bearer ${secret}`
      : identity.authType === 'basic'
        ? `Basic ${Buffer.from(secret, 'utf8').toString('base64')}`
        : secret

    const credentialRef = ExecutionCredentialRefSchema.parse({
      id: parsedCredentialRef.data,
      kind: 'identity',
      generation
    })
    const secretRef = credentialRef.id
    const secretResolver: SecretRefResolver = Object.freeze({
      resolverId: CREDENTIAL_RESOLVER_ID,
      version: ADAPTER_COMPONENT_VERSION,
      resolve: (resolverInput: SecretRefResolverInput) => {
        if (
          resolverInput.secretRef !== secretRef ||
          resolverInput.generation !== generation ||
          resolverInput.identityRef?.id !== identityRef.id
        ) {
          throw new Error('Legacy credential binding changed.')
        }
        return value
      }
    })
    const authorizedIdentityHeaders = Object.freeze([
      Object.freeze({
        name,
        value: Object.freeze({
          kind: 'secret-ref' as const,
          secretRef,
          generation,
          resolver: Object.freeze({
            kind: 'secret-ref-resolver' as const,
            resolverId: CREDENTIAL_RESOLVER_ID,
            version: ADAPTER_COMPONENT_VERSION
          })
        })
      })
    ])
    return Object.freeze({
      ownerRef: targetId,
      identityRef,
      credentialRef,
      authorizedIdentityHeaders,
      secretResolver
    })
  }
}
