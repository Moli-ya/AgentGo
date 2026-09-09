import { createHash } from 'node:crypto'
import type { HttpObservation } from './validation-engine'

export const IDOR_NORMALIZER_VERSION = 'idor.normalize@1.1.0' as const

const UUID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi
const TIME_PATTERN = /\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+\b/g

export interface IdorNormalizedResourceView {
  readonly normalizerVersion: typeof IDOR_NORMALIZER_VERSION
  readonly statusCode: number | undefined
  readonly resourceId?: string
  readonly ownerId?: string
  readonly tenantId?: string
  readonly parentId?: string
  readonly selectedFieldHash?: string
  readonly jsonShapeHash?: string
  readonly cacheControl: string
  readonly etag: string
  readonly authorizationError: boolean
  readonly gatewayOrWaf: boolean
}

function headerValue(
  headers: Readonly<Record<string, string>> | undefined,
  name: string
): string {
  if (!headers) return ''
  const exact = headers[name]
  if (typeof exact === 'string') return exact
  const lower = name.toLowerCase()
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value
  }
  return ''
}

function observationBodyText(observation: HttpObservation): string {
  return observation.result.responseBody
    ? Buffer.from(observation.result.responseBody).toString('utf8')
    : ''
}

function readString(value: unknown): string | undefined {
  if (typeof value === 'string' && value.length > 0 && value.length <= 500) {
    return value
  }
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return undefined
}

function firstString(
  record: Record<string, unknown>,
  keys: readonly string[]
): string | undefined {
  for (const key of keys) {
    const value = readString(record[key])
    if (value) return value
  }
  return undefined
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return undefined
}

export function parseIdorResourceFields(body: string): {
  readonly resourceId?: string
  readonly ownerId?: string
  readonly tenantId?: string
  readonly parentId?: string
  readonly visibility?: string
} {
  try {
    const parsed: unknown = JSON.parse(body)
    const root = asRecord(parsed)
    const nested = root ? asRecord(root.data) ?? asRecord(root.resource) ?? root : undefined
    if (!nested) return {}
    return {
      ...(firstString(nested, ['id', 'resourceId', 'objectId', 'documentId'])
        ? { resourceId: firstString(nested, ['id', 'resourceId', 'objectId', 'documentId']) }
        : {}),
      ...(firstString(nested, ['ownerId', 'owner', 'userId', 'accountId'])
        ? { ownerId: firstString(nested, ['ownerId', 'owner', 'userId', 'accountId']) }
        : {}),
      ...(firstString(nested, ['tenantId', 'tenant', 'orgId'])
        ? { tenantId: firstString(nested, ['tenantId', 'tenant', 'orgId']) }
        : {}),
      ...(firstString(nested, ['parentId', 'parent', 'folderId'])
        ? { parentId: firstString(nested, ['parentId', 'parent', 'folderId']) }
        : {}),
      ...(firstString(nested, ['visibility', 'access', 'acl'])
        ? { visibility: firstString(nested, ['visibility', 'access', 'acl']) }
        : {})
    }
  } catch {
    return {}
  }
}

function jsonShapeHash(value: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(value)
    return createHash('sha256').update(stableShape(parsed), 'utf8').digest('hex')
  } catch {
    return undefined
  }
}

function stableShape(value: unknown): string {
  if (value === null || typeof value === 'object') {
    if (value === null) return 'null'
    if (Array.isArray(value)) {
      return `[${value.slice(0, 8).map((item) => stableShape(item)).join(',')}]`
    }
    const keys = Object.keys(value as Record<string, unknown>).sort()
    return `{${keys
      .slice(0, 32)
      .map((key) => `${key}:${stableShape((value as Record<string, unknown>)[key])}`)
      .join(',')}}`
  }
  return typeof value
}

function selectedFieldHash(fields: {
  readonly resourceId?: string
  readonly ownerId?: string
  readonly tenantId?: string
  readonly parentId?: string
}): string | undefined {
  if (!fields.resourceId && !fields.ownerId) return undefined
  return createHash('sha256')
    .update(
      JSON.stringify({
        resourceId: fields.resourceId ?? null,
        ownerId: fields.ownerId ?? null,
        tenantId: fields.tenantId ?? null,
        parentId: fields.parentId ?? null
      }),
      'utf8'
    )
    .digest('hex')
}

const AUTH_ERROR_BODY =
  /(?:forbidden|unauthorized|access denied|not allowed|permission)/i
const WAF_BODY =
  /(?:web application firewall|request blocked|waf|cloudflare|access denied by gateway)/i

export function normalizeIdorObservation(
  observation: HttpObservation
): IdorNormalizedResourceView {
  const body = observationBodyText(observation)
  const fields = parseIdorResourceFields(body)
  const statusCode = observation.result.statusCode
  const headers = observation.result.responseHeaders
  const authorizationError =
    statusCode === 401 ||
    statusCode === 403 ||
    statusCode === 404 ||
    AUTH_ERROR_BODY.test(body)
  const gatewayOrWaf =
    statusCode === 429 ||
    statusCode === 403 && WAF_BODY.test(body) ||
    WAF_BODY.test(body)
  return {
    normalizerVersion: IDOR_NORMALIZER_VERSION,
    statusCode,
    ...fields,
    ...(selectedFieldHash(fields) ? { selectedFieldHash: selectedFieldHash(fields) } : {}),
    ...(jsonShapeHash(body) ? { jsonShapeHash: jsonShapeHash(body) } : {}),
    cacheControl: headerValue(headers, 'cache-control'),
    etag: headerValue(headers, 'etag'),
    authorizationError,
    gatewayOrWaf
  }
}

export function stripIdorVolatileText(value: string): string {
  return value
    .slice(0, 1_000_000)
    .replace(UUID_PATTERN, '<uuid>')
    .replace(TIME_PATTERN, '<time>')
    .replace(/\s+/g, ' ')
    .trim()
}
