import {
  type ImportFormat,
  type ImportParameter,
  type ImportParserLimits,
  type ImportPreviewOperation,
  type ImportScopeVerdict,
  type ImportWarning,
  type InventoryValueType,
  type TargetScope
} from '@agentgo/contracts'
import { evaluateUrlScope } from '@agentgo/security-policy'
import { OfflineParseError } from './bounded-document'
import { OPENAPI_31_UNSUPPORTED_KEYWORDS } from './profiles'

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const

export interface AdapterResult {
  readonly format: ImportFormat
  readonly operations: ImportPreviewOperation[]
  readonly warnings: ImportWarning[]
}

export function extractOpenApi(
  document: unknown,
  scope: TargetScope,
  limits: ImportParserLimits
): AdapterResult {
  const root = asRecord(document)
  const warnings: ImportWarning[] = []
  const format = detectOpenApiFormat(root, warnings)
  rejectRemoteRefs(root, 'document', warnings, 0, limits.maxDocumentDepth)
  if (format === 'openapi-3.1') {
    warnUnsupportedKeywords(root, 'document', warnings, 0, limits.maxDocumentDepth)
  }
  const bases = resolveServers(root, format, warnings)
  const paths = asRecord(root.paths)
  const operations: ImportPreviewOperation[] = []
  for (const [path, item] of Object.entries(paths)) {
    const pathItem = asRecord(item)
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method.toLowerCase()]
      if (!operation || typeof operation !== 'object') continue
      if (operations.length >= limits.maxOperations) {
        warnings.push({
          code: 'too-many-operations',
          location: `paths.${path}`,
          message: 'Operation budget reached; remaining paths are omitted.'
        })
        return { format, operations, warnings }
      }
      const op = asRecord(operation)
      const contentType = firstContentType(op)
      const codec = codecFromContentType(contentType)
      const collected = collectOpenApiParameters(root, pathItem, op)
      for (const base of bases.length > 0 ? bases : [undefined]) {
        operations.push(
          toOperation({
            operationRef: `${method} ${path}`,
            method,
            path,
            base,
            scope,
            contentType,
            codec,
            parameterLocations: collected.locations,
            parameters: collected.parameters,
            security: collectSecurity(root, op),
            warnings
          })
        )
      }
    }
    if (pathItem.callbacks || pathItem['x-amazon-apigateway-any-method']) {
      warnings.push({
        code: 'callback-inventory-only',
        location: `paths.${path}`,
        message: 'Callbacks and vendor any-method extensions are inventory-only.'
      })
    }
  }
  if (root.webhooks && typeof root.webhooks === 'object') {
    warnings.push({
      code: 'callback-inventory-only',
      location: 'webhooks',
      message: 'OpenAPI webhooks are inventoried as unsupported protocol hints only.'
    })
  }
  return { format, operations, warnings }
}

export function extractSwagger(
  document: unknown,
  scope: TargetScope,
  limits: ImportParserLimits
): AdapterResult {
  const root = asRecord(document)
  const warnings: ImportWarning[] = []
  rejectRemoteRefs(root, 'document', warnings, 0, limits.maxDocumentDepth)
  const host = typeof root.host === 'string' ? root.host : undefined
  const basePath = typeof root.basePath === 'string' ? root.basePath : ''
  const schemes = Array.isArray(root.schemes)
    ? root.schemes.filter((item): item is string => typeof item === 'string')
    : ['https']
  const bases: string[] = []
  if (host) {
    for (const scheme of schemes.length > 0 ? schemes : ['https']) {
      bases.push(`${scheme}://${host}${basePath}`)
    }
  } else {
    warnings.push({
      code: 'unresolved-base',
      location: 'host',
      message: 'Swagger 2.0 host is missing; relative paths stay unresolved.'
    })
  }
  const paths = asRecord(root.paths)
  const operations: ImportPreviewOperation[] = []
  for (const [path, item] of Object.entries(paths)) {
    const pathItem = asRecord(item)
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method.toLowerCase()]
      if (!operation || typeof operation !== 'object') continue
      if (operations.length >= limits.maxOperations) break
      const op = asRecord(operation)
      const consumes = firstString(op.consumes) ?? firstString(root.consumes)
      const collected = collectSwaggerParameters(root, pathItem, op)
      operations.push(
        toOperation({
          operationRef: `${method} ${path}`,
          method,
          path,
          base: bases[0],
          scope,
          contentType: consumes,
          codec: codecFromContentType(consumes),
          parameterLocations: collected.locations,
          parameters: collected.parameters,
          security: Object.keys(asRecord(root.securityDefinitions)),
          warnings
        })
      )
    }
  }
  return { format: 'swagger-2.0', operations, warnings }
}

function detectOpenApiFormat(
  root: Record<string, unknown>,
  warnings: ImportWarning[]
): ImportFormat {
  const version = typeof root.openapi === 'string' ? root.openapi : ''
  if (version.startsWith('3.1')) return 'openapi-3.1'
  if (version.startsWith('3.0')) return 'openapi-3.0'
  warnings.push({
    code: 'lossy-mapping',
    location: 'openapi',
    message: 'OpenAPI version is missing or unofficial; treated as 3.0 inventory.'
  })
  return 'openapi-3.0'
}

function resolveServers(
  root: Record<string, unknown>,
  _format: ImportFormat,
  warnings: ImportWarning[]
): string[] {
  const servers = Array.isArray(root.servers) ? root.servers : []
  const urls: string[] = []
  for (const [index, server] of servers.entries()) {
    const url = asRecord(server).url
    if (typeof url !== 'string' || url.includes('{')) {
      warnings.push({
        code: 'unresolved-base',
        location: `servers[${index}]`,
        message: 'Templated or missing server URL cannot be used as a trusted base.'
      })
      continue
    }
    urls.push(url)
  }
  return urls
}

function toOperation(input: {
  readonly operationRef: string
  readonly method: string
  readonly path: string
  readonly base: string | undefined
  readonly scope: TargetScope
  readonly contentType: string | undefined
  readonly codec: ImportPreviewOperation['codec']
  readonly parameterLocations: ImportPreviewOperation['parameterLocations']
  readonly parameters?: readonly ImportParameter[]
  readonly security: string[]
  readonly warnings: ImportWarning[]
}): ImportPreviewOperation {
  const joined = input.base ? joinUrl(input.base, input.path) : input.path
  const verdict = scopeVerdict(joined, input.scope, input.base)
  if (verdict !== 'in-scope') {
    input.warnings.push({
      code: verdict === 'unresolved' ? 'unresolved-base' : 'out-of-scope',
      location: input.operationRef,
      message: `Operation ${input.operationRef} is ${verdict}.`
    })
  }
  return {
    operationRef: input.operationRef,
    method: input.method,
    url: joined,
    scopeVerdict: verdict,
    ...(input.contentType ? { contentType: input.contentType } : {}),
    codec: input.codec,
    transport: 'standard-http',
    parameterLocations: input.parameterLocations,
    ...(input.parameters && input.parameters.length > 0
      ? { parameters: [...input.parameters] }
      : {}),
    securitySchemes: input.security,
    warnings: []
  }
}

export function scopeVerdict(
  url: string,
  scope: TargetScope,
  base?: string
): ImportScopeVerdict {
  const result = evaluateUrlScope(url, scope, base)
  if (result.ok) return 'in-scope'
  if (result.reason === 'unresolved' || result.reason === 'canonicalization-failed') {
    return 'unresolved'
  }
  return 'out-of-scope'
}

export function joinUrl(base: string, path: string): string {
  if (/^[a-z][a-z0-9+.-]*:/iu.test(path)) return path
  const templated = path.replace(/\{([^}]+)\}/gu, ':$1')
  try {
    const origin = new URL(base.endsWith('/') ? base : `${base}/`)
    const relative = templated.startsWith('/') ? templated.slice(1) : templated
    origin.pathname = `${origin.pathname.replace(/\/$/u, '')}/${relative}`
    origin.search = ''
    origin.hash = ''
    return origin.href
  } catch {
    return `${base.replace(/\/$/u, '')}/${templated.replace(/^\//u, '')}`
  }
}

function firstContentType(operation: Record<string, unknown>): string | undefined {
  const requestBody = asRecord(operation.requestBody)
  const content = asRecord(requestBody.content)
  return Object.keys(content)[0]
}

function codecFromContentType(contentType: string | undefined): ImportPreviewOperation['codec'] {
  if (!contentType) return 'none'
  if (contentType.includes('json')) return 'json'
  if (contentType.includes('xml')) return 'xml'
  if (contentType.includes('graphql')) return 'graphql'
  if (contentType.includes('form-urlencoded')) return 'form'
  if (contentType.includes('multipart')) return 'multipart'
  return 'raw'
}

interface CollectedParameters {
  readonly locations: ImportPreviewOperation['parameterLocations']
  readonly parameters: ImportParameter[]
}

function collectOpenApiParameters(
  root: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>
): CollectedParameters {
  const locations = new Set<ImportPreviewOperation['parameterLocations'][number]>()
  const parameters: ImportParameter[] = []
  const hints = responseIdentityHints(root, operation)
  const list = [...asArray(pathItem.parameters), ...asArray(operation.parameters)]
  for (const item of list) {
    const resolved = resolveLocalRef(item, root)
    const location = resolved.in
    const name = typeof resolved.name === 'string' ? resolved.name : undefined
    if (
      location !== 'query' &&
      location !== 'path' &&
      location !== 'header' &&
      location !== 'cookie'
    ) {
      continue
    }
    locations.add(location)
    if (!name) continue
    const schema = resolveLocalRef(resolved.schema, root)
    parameters.push(
      toImportParameter({
        name,
        location,
        schema,
        required: resolved.required === true || location === 'path',
        hints
      })
    )
  }
  const requestBody = resolveLocalRef(operation.requestBody, root)
  const content = asRecord(requestBody.content)
  const jsonSchema = resolveLocalRef(
    asRecord(content['application/json']).schema ??
      asRecord(Object.values(content)[0]).schema,
    root
  )
  if (operation.requestBody) {
    locations.add('body')
    const properties = asRecord(jsonSchema.properties)
    const required = new Set(
      Array.isArray(jsonSchema.required)
        ? jsonSchema.required.filter((item): item is string => typeof item === 'string')
        : []
    )
    for (const [name, raw] of Object.entries(properties)) {
      parameters.push(
        toImportParameter({
          name,
          location: 'body',
          schema: resolveLocalRef(raw, root),
          required: required.has(name),
          hints
        })
      )
    }
  }
  return { locations: [...locations], parameters: parameters.slice(0, 128) }
}

function collectSwaggerParameters(
  root: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>
): CollectedParameters {
  const locations = new Set<ImportPreviewOperation['parameterLocations'][number]>()
  const parameters: ImportParameter[] = []
  const hints = responseIdentityHints(root, operation)
  const list = [...asArray(pathItem.parameters), ...asArray(operation.parameters)]
  for (const item of list) {
    const resolved = resolveLocalRef(item, root)
    const rawLocation = resolved.in
    const name = typeof resolved.name === 'string' ? resolved.name : undefined
    const location =
      rawLocation === 'formData'
        ? 'form'
        : rawLocation === 'query' ||
            rawLocation === 'path' ||
            rawLocation === 'header' ||
            rawLocation === 'body'
          ? rawLocation
          : undefined
    if (!location) continue
    locations.add(location)
    if (!name) continue
    const schema =
      location === 'body'
        ? resolveLocalRef(resolved.schema, root)
        : resolved
    parameters.push(
      toImportParameter({
        name,
        location,
        schema,
        required: resolved.required === true || location === 'path',
        hints
      })
    )
  }
  return { locations: [...locations], parameters: parameters.slice(0, 128) }
}

function toImportParameter(input: {
  readonly name: string
  readonly location: ImportParameter['location']
  readonly schema: Record<string, unknown>
  readonly required: boolean
  readonly hints: ResponseIdentityHints
}): ImportParameter {
  const format =
    typeof input.schema.format === 'string' ? input.schema.format.toLowerCase() : undefined
  const valueType = valueTypeFromSchema(input.schema)
  const resourceKind = resourceKindFromSchema(input.schema, input.hints)
  return {
    name: input.name.slice(0, 200),
    location: input.location,
    valueType,
    required: input.required,
    ...(format ? { format: format.slice(0, 64) } : {}),
    ...(resourceKind ? { resourceKind } : {}),
    ...(input.hints.ownerField ? { ownerField: input.hints.ownerField } : {}),
    ...(input.hints.responseIdentityField
      ? { responseIdentityField: input.hints.responseIdentityField }
      : {})
  }
}

function valueTypeFromSchema(schema: Record<string, unknown>): InventoryValueType {
  const type = schema.type
  if (
    type === 'string' ||
    type === 'number' ||
    type === 'integer' ||
    type === 'boolean' ||
    type === 'object' ||
    type === 'array'
  ) {
    return type
  }
  return 'unknown'
}

function resourceKindFromSchema(
  schema: Record<string, unknown>,
  hints: ResponseIdentityHints
): ImportParameter['resourceKind'] | undefined {
  const format = typeof schema.format === 'string' ? schema.format.toLowerCase() : ''
  if (format === 'uuid' || format === 'guid') {
    return hints.responseIdentityField ? 'resource-id' : 'opaque'
  }
  if (
    hints.responseIdentityField &&
    (schema.type === 'integer' || schema.type === 'string' || schema.type === 'number')
  ) {
    return 'resource-id'
  }
  return undefined
}

interface ResponseIdentityHints {
  readonly ownerField?: string
  readonly responseIdentityField?: string
}

function responseIdentityHints(
  root: Record<string, unknown>,
  operation: Record<string, unknown>
): ResponseIdentityHints {
  const responses = asRecord(operation.responses)
  const success = asRecord(
    responses['200'] ?? responses['201'] ?? responses.default
  )
  const content = asRecord(success.content)
  const schema = resolveLocalRef(
    asRecord(content['application/json']).schema ??
      asRecord(success.schema).schema ??
      success.schema,
    root
  )
  const properties = asRecord(schema.properties)
  let responseIdentityField: string | undefined
  let ownerField: string | undefined
  for (const name of Object.keys(properties)) {
    if (!responseIdentityField && /^(?:id|resourceId|resource_id)$/u.test(name)) {
      responseIdentityField = name
    }
    if (!ownerField && /^(?:ownerId|owner_id|userId|user_id)$/u.test(name)) {
      ownerField = name
    }
  }
  return {
    ...(responseIdentityField ? { responseIdentityField } : {}),
    ...(ownerField ? { ownerField } : {})
  }
}

function resolveLocalRef(
  value: unknown,
  root: Record<string, unknown>
): Record<string, unknown> {
  const record = asRecord(value)
  const ref = record.$ref
  if (typeof ref !== 'string' || !ref.startsWith('#/')) return record
  let current: unknown = root
  for (const part of ref.slice(2).split('/')) {
    const decoded = part.replace(/~1/gu, '/').replace(/~0/gu, '~')
    current = asRecord(current)[decoded]
  }
  return asRecord(current)
}

function collectSecurity(
  root: Record<string, unknown>,
  operation: Record<string, unknown>
): string[] {
  const components = asRecord(root.components)
  const schemes = Object.keys(asRecord(components.securitySchemes))
  if (operation.security !== undefined) return schemes
  return schemes
}

function rejectRemoteRefs(
  value: unknown,
  location: string,
  warnings: ImportWarning[],
  depth: number,
  maxDepth: number
): void {
  if (depth > maxDepth || value === null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      rejectRemoteRefs(entry, `${location}[${index}]`, warnings, depth + 1, maxDepth)
    )
    return
  }
  const record = value as Record<string, unknown>
  const ref = record.$ref
  if (typeof ref === 'string' && /^[a-z][a-z0-9+.-]*:/iu.test(ref)) {
    throw new OfflineParseError('remote-ref-forbidden', 'Remote $ref is forbidden.')
  }
  for (const [key, entry] of Object.entries(record)) {
    rejectRemoteRefs(entry, `${location}.${key}`, warnings, depth + 1, maxDepth)
  }
}

function warnUnsupportedKeywords(
  value: unknown,
  location: string,
  warnings: ImportWarning[],
  depth: number,
  maxDepth: number
): void {
  if (depth > maxDepth || value === null || typeof value !== 'object') return
  const record = Array.isArray(value) ? undefined : (value as Record<string, unknown>)
  if (record) {
    for (const keyword of [
      '$dynamicRef',
      '$dynamicAnchor',
      'unevaluatedProperties',
      'unevaluatedItems',
      'dependentSchemas',
      'prefixItems',
      'if',
      'then',
      'else'
    ]) {
      if (keyword in record) {
        const mapped =
          OPENAPI_31_UNSUPPORTED_KEYWORDS.find((item) =>
            keyword.toLowerCase().includes(item.replace(/-/gu, ''))
          ) ?? 'if-then-else'
        warnings.push({
          code: 'unsupported-keyword',
          location: `${location}.${keyword}`,
          message: `OpenAPI 3.1 keyword ${keyword} (${mapped}) is not in the supported JSON Schema subset.`
        })
      }
    }
    for (const [key, entry] of Object.entries(record)) {
      warnUnsupportedKeywords(entry, `${location}.${key}`, warnings, depth + 1, maxDepth)
    }
  } else if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      warnUnsupportedKeywords(entry, `${location}[${index}]`, warnings, depth + 1, maxDepth)
    )
  }
}

export function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function firstString(value: unknown): string | undefined {
  return Array.isArray(value) && typeof value[0] === 'string' ? value[0] : undefined
}
