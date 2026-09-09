import type { ImportPreviewOperation, ImportWarning, TargetScope } from '@agentgo/contracts'
import { redactInventoryText } from '@agentgo/domain'
import { asRecord, scopeVerdict, type AdapterResult } from './openapi'

export function extractHar(
  document: unknown,
  scope: TargetScope,
  maxOperations: number
): AdapterResult {
  const log = asRecord(asRecord(document).log)
  const entries = Array.isArray(log.entries) ? log.entries : []
  const warnings: ImportWarning[] = []
  const operations: ImportPreviewOperation[] = []
  for (const [index, entry] of entries.entries()) {
    if (operations.length >= maxOperations) {
      warnings.push({
        code: 'too-many-operations',
        location: `log.entries[${index}]`,
        message: 'HAR operation budget reached.'
      })
      break
    }
    const request = asRecord(asRecord(entry).request)
    const url = typeof request.url === 'string' ? request.url : ''
    const method = typeof request.method === 'string' ? request.method.toUpperCase() : 'GET'
    const initiator = redactInventoryText(String(asRecord(entry).initiator ?? 'har-entry'), 256)
    const mime = firstHeader(request, 'content-type')
    const verdict = scopeVerdict(url, scope)
    operations.push({
      operationRef: `har:${index}:${method}`,
      method,
      url,
      scopeVerdict: verdict,
      ...(mime ? { contentType: mime } : {}),
      codec: mime?.includes('json') ? 'json' : mime?.includes('form') ? 'form' : 'none',
      transport: 'standard-http',
      parameterLocations: queryLocations(url),
      securitySchemes: hasAuth(request) ? ['har-auth-redacted'] : [],
      warnings: [
        {
          code: 'secret-redacted',
          location: `log.entries[${index}]`,
          message: `Initiator ${initiator} stored as sanitized metadata only.`
        }
      ]
    })
  }
  return { format: 'har-1.2', operations, warnings }
}

export function extractPostman(
  document: unknown,
  scope: TargetScope,
  maxOperations: number
): AdapterResult {
  const root = asRecord(document)
  const warnings: ImportWarning[] = []
  const variables = collectVariables(root)
  const operations: ImportPreviewOperation[] = []
  walkItems(asArray(root.item), '', variables, scope, operations, warnings, maxOperations)
  return { format: 'postman-2.1', operations, warnings }
}

function walkItems(
  items: unknown[],
  prefix: string,
  variables: Map<string, string>,
  scope: TargetScope,
  operations: ImportPreviewOperation[],
  warnings: ImportWarning[],
  maxOperations: number
): void {
  for (const [index, item] of items.entries()) {
    const record = asRecord(item)
    const name = typeof record.name === 'string' ? record.name : `${index}`
    const path = prefix ? `${prefix}/${name}` : name
    if (Array.isArray(record.item)) {
      walkItems(record.item, path, variables, scope, operations, warnings, maxOperations)
      continue
    }
    if (operations.length >= maxOperations) return
    const request = asRecord(record.request)
    const method = String(request.method ?? 'GET').toUpperCase()
    const rawUrl = rawPostmanUrl(request.url)
    const substituted = substitute(rawUrl, variables)
    const unresolved = substituted.includes('{{')
    if (unresolved) {
      warnings.push({
        code: 'unresolved-base',
        location: path,
        message: 'Postman variables remain unresolved without an in-document value.'
      })
    }
    const verdict = unresolved ? 'unresolved' : scopeVerdict(substituted, scope)
    operations.push({
      operationRef: path,
      method,
      url: substituted,
      scopeVerdict: verdict,
      codec: 'none',
      transport: 'standard-http',
      parameterLocations: queryLocations(substituted),
      securitySchemes: [],
      warnings: []
    })
  }
}

function collectVariables(root: Record<string, unknown>): Map<string, string> {
  const map = new Map<string, string>()
  const list = Array.isArray(root.variable) ? root.variable : []
  for (const item of list) {
    const record = asRecord(item)
    if (typeof record.key === 'string' && typeof record.value === 'string') {
      if (!looksSecret(record.key) && !looksSecret(record.value)) {
        map.set(record.key, record.value)
      }
    }
  }
  return map
}

function rawPostmanUrl(value: unknown): string {
  if (typeof value === 'string') return value
  const record = asRecord(value)
  if (typeof record.raw === 'string') return record.raw
  const host = Array.isArray(record.host) ? record.host.join('.') : String(record.host ?? '')
  const path = Array.isArray(record.path) ? `/${record.path.join('/')}` : ''
  const protocol = typeof record.protocol === 'string' ? record.protocol : 'https'
  return host ? `${protocol}://${host}${path}` : path
}

function substitute(value: string, variables: Map<string, string>): string {
  return value.replace(/\{\{([^}]+)\}\}/gu, (match, name: string) => variables.get(name) ?? match)
}

function queryLocations(url: string): ImportPreviewOperation['parameterLocations'] {
  return url.includes('?') ? ['query'] : []
}

function firstHeader(request: Record<string, unknown>, name: string): string | undefined {
  const headers = Array.isArray(request.headers) ? request.headers : []
  for (const header of headers) {
    const record = asRecord(header)
    if (String(record.name).toLowerCase() === name) return String(record.value ?? '')
  }
  return undefined
}

function hasAuth(request: Record<string, unknown>): boolean {
  if (request.headers && JSON.stringify(request.headers).toLowerCase().includes('authorization')) {
    return true
  }
  return Boolean(asRecord(request).cookies)
}

function looksSecret(value: string): boolean {
  return /(?:password|secret|token|authorization|apikey|api[-_]?key|cookie)/iu.test(value)
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}
