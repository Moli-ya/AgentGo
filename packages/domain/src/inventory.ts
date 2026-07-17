import {
  AllowedHeaderDescriptorSchema,
  InventoryBodyShapeSchema,
  SelectorRefSchema,
  SelectorRefsSchema,
  type AllowedHeaderDescriptor,
  type InventoryBodyShape,
  type InventoryPreviewInput,
  type RedactedInventoryPreview,
  type SelectorRef
} from '@agentgo/contracts'
import { canonicalJson, compareText, sha256Text } from './vulnerabilities/canonical'

export const INVENTORY_REDACTION_MARKER = '[REDACTED]'
export const INVENTORY_TRUNCATION_MARKER = '[TRUNCATED]'
export const MAX_REDACTED_INVENTORY_URL_LENGTH = 16_384

const SUPPORTED_INVENTORY_PROTOCOLS = new Set(['http:', 'https:', 'ws:', 'wss:'])
const SENSITIVE_FIELD_NAME_PATTERN =
  /(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[-_.]?key|credential|csrf|xsrf|session)/iu
const SENTINEL_SECRET_DETECTION_PATTERN =
  /(?:day\d*[-_ ]*)?sentinel(?:[-_ ]*(?:secret|token|password|credential))?|must[-_ ]?not[-_ ]?leak|do[-_ ]?not[-_ ]?store|super[-_ ]?secret/iu
const SENTINEL_SECRET_REPLACEMENT_PATTERN =
  /(?:day\d*[-_ ]*)?sentinel(?:[-_ ]*(?:secret|token|password|credential))?|must[-_ ]?not[-_ ]?leak|do[-_ ]?not[-_ ]?store|super[-_ ]?secret/giu
const JWT_DETECTION_PATTERN = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u
const JWT_REPLACEMENT_PATTERN = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu
const BEARER_PATTERN = /\bbearer\s+[A-Za-z0-9._~+\/-]+={0,2}/giu
const TOKEN_CANDIDATE_PATTERN = /[A-Za-z0-9._~+\/-]{20,}={0,2}/gu
const TOKEN_PREFIX_PATTERN = /^(?:sk|pk|api|key|token|secret|ghp|github_pat|xox[baprs])[-_]/iu

interface ParsedInventoryUrl {
  readonly protocol: string
  readonly origin: string
  hostname: string
  pathname: string
  username: string
  password: string
  hash: string
  search: string
  readonly searchParams: {
    keys(): IterableIterator<string>
    append(name: string, value: string): void
  }
  toString(): string
}

const InventoryUrl = (globalThis as unknown as {
  URL: new (value: string) => ParsedInventoryUrl
}).URL

function parseInventoryUrl(value: string): ParsedInventoryUrl {
  let url: ParsedInventoryUrl
  try {
    url = new InventoryUrl(value)
  } catch {
    throw new TypeError('Inventory URL must be an absolute URL.')
  }
  if (!SUPPORTED_INVENTORY_PROTOCOLS.has(url.protocol)) {
    throw new TypeError(`Unsupported inventory URL protocol: ${url.protocol}`)
  }
  return url
}

function isSecretShapedStructuralValue(value: string): boolean {
  return (
    SENTINEL_SECRET_DETECTION_PATTERN.test(value) ||
    JWT_DETECTION_PATTERN.test(value) ||
    /^bearer(?:\s|%20)+/iu.test(value) ||
    isHighEntropySecret(value)
  )
}

function canonicalizePathSegment(value: string): string {
  let decoded: string
  try {
    decoded = decodeURIComponent(value)
  } catch {
    return ':redacted'
  }
  if (isSecretShapedStructuralValue(decoded)) return ':redacted'
  return encodeURIComponent(decoded).replace(/%3A/giu, ':')
}

function canonicalizeInventoryPathname(pathname: string): string {
  return pathname.split('/').map(canonicalizePathSegment).join('/')
}

function canonicalizeInventoryHostname(hostname: string): string {
  return hostname
    .split('.')
    .map((label) =>
      isSecretShapedStructuralValue(label)
        ? `redacted-${sha256Text(label).slice(0, 16)}`
        : label
    )
    .join('.')
}

/**
 * Returns the endpoint identity. Query names and values, userinfo, and the
 * fragment are intentionally absent; selector structure belongs to a variant.
 */
export function canonicalizeInventoryUrl(value: string): string {
  const url = parseInventoryUrl(value)
  url.hostname = canonicalizeInventoryHostname(url.hostname)
  const pathname = canonicalizeInventoryPathname(url.pathname)
  const route = `${url.origin}${pathname}`
  return route.length <= MAX_REDACTED_INVENTORY_URL_LENGTH
    ? route
    : `${url.origin}/_redacted-path-${sha256Text(pathname).slice(0, 16)}`
}

/**
 * Produces a useful URL preview while ensuring no original query value or
 * userinfo can survive. Repeated query names remain visible as structure.
 */
export function redactInventoryUrlPreview(value: string): string {
  const url = parseInventoryUrl(value)
  const queryNames = [...url.searchParams.keys()].sort(compareText)
  url.username = ''
  url.password = ''
  url.hash = ''
  url.hostname = canonicalizeInventoryHostname(url.hostname)
  url.pathname = canonicalizeInventoryPathname(url.pathname)
  url.search = ''

  if (url.toString().length > MAX_REDACTED_INVENTORY_URL_LENGTH) {
    url.pathname = `/_redacted-path-${sha256Text(url.pathname).slice(0, 16)}`
  }

  for (const name of queryNames) {
    const safeName = isSecretShapedStructuralValue(name) ? 'redacted-name' : name.trim()
    url.searchParams.append(safeName, INVENTORY_REDACTION_MARKER)
    if (url.toString().length > MAX_REDACTED_INVENTORY_URL_LENGTH) {
      const acceptedEntries = [...url.searchParams.keys()].slice(0, -1)
      url.search = ''
      for (const acceptedName of acceptedEntries) {
        url.searchParams.append(acceptedName, INVENTORY_REDACTION_MARKER)
      }
      break
    }
  }
  return url.toString()
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>()
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1)
  }
  let entropy = 0
  for (const count of counts.values()) {
    const probability = count / value.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

/** Conservative detector for token-like values; it is not an authorization decision. */
export function isHighEntropySecret(value: string): boolean {
  const candidate = value.trim()
  if (candidate.length === 0) return false
  if (/^bearer\s+/iu.test(candidate)) return true
  if (JWT_DETECTION_PATTERN.test(candidate)) return true
  if (SENTINEL_SECRET_DETECTION_PATTERN.test(candidate)) return true
  if (TOKEN_PREFIX_PATTERN.test(candidate) && candidate.length >= 16) return true
  if (candidate.length < 20 || /\s/u.test(candidate)) return false
  if (!/^[A-Za-z0-9._~+\/-]+={0,2}$/u.test(candidate)) return false

  const uniqueRatio = new Set(candidate).size / candidate.length
  const minimumEntropy = /^[a-f0-9-]+$/iu.test(candidate) ? 3.2 : 3.6
  return uniqueRatio >= 0.25 && shannonEntropy(candidate) >= minimumEntropy
}

function isSensitiveFieldName(value: string): boolean {
  return SENSITIVE_FIELD_NAME_PATTERN.test(value)
}

function truncatePreview(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value
  return `${value.slice(0, Math.max(0, maxLength - INVENTORY_TRUNCATION_MARKER.length))}${INVENTORY_TRUNCATION_MARKER}`
}

/** Redacts secret-shaped fragments in non-structured preview text. */
export function redactInventoryText(value: string, maxLength = 4_096): string {
  if (!Number.isInteger(maxLength) || maxLength < INVENTORY_TRUNCATION_MARKER.length) {
    throw new RangeError('Inventory preview maxLength is too small.')
  }

  let redacted = value
    .replace(BEARER_PATTERN, `Bearer ${INVENTORY_REDACTION_MARKER}`)
    .replace(JWT_REPLACEMENT_PATTERN, INVENTORY_REDACTION_MARKER)
    .replace(
      /((?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[-_.]?key|credential|csrf|xsrf|session)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s&,;}]+)/giu,
      `$1${INVENTORY_REDACTION_MARKER}`
    )
    .replace(SENTINEL_SECRET_REPLACEMENT_PATTERN, INVENTORY_REDACTION_MARKER)
    .replace(TOKEN_CANDIDATE_PATTERN, (candidate) =>
      isHighEntropySecret(candidate) ? INVENTORY_REDACTION_MARKER : candidate
    )

  if (isHighEntropySecret(redacted)) redacted = INVENTORY_REDACTION_MARKER
  return truncatePreview(redacted, maxLength)
}

interface JsonSanitizationBudget {
  remainingNodes: number
}

function sanitizeJsonValue(
  value: unknown,
  budget: JsonSanitizationBudget,
  depth: number,
  fieldName?: string
): unknown {
  if (budget.remainingNodes <= 0 || depth > 16) return INVENTORY_TRUNCATION_MARKER
  budget.remainingNodes -= 1
  if (fieldName !== undefined && isSensitiveFieldName(fieldName)) {
    return INVENTORY_REDACTION_MARKER
  }
  if (typeof value === 'string') return redactInventoryText(value)
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value
  if (Array.isArray(value)) {
    return value.slice(0, 1_024).map((entry) => sanitizeJsonValue(entry, budget, depth + 1))
  }
  if (typeof value === 'object') {
    const output = Object.create(null) as Record<string, unknown>
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => compareText(left, right))
      .slice(0, 1_024)
    for (const [key, entry] of entries) {
      const safeKey = redactInventoryText(key, 512)
      output[safeKey] = sanitizeJsonValue(entry, budget, depth + 1, key)
    }
    return output
  }
  return INVENTORY_REDACTION_MARKER
}

function redactBodyPreview(value: string): string {
  try {
    const parsed: unknown = JSON.parse(value)
    return truncatePreview(
      canonicalJson(sanitizeJsonValue(parsed, { remainingNodes: 4_096 }, 0)),
      16_384
    )
  } catch {
    return redactInventoryText(value, 16_384)
  }
}

/**
 * Canonicalizes header names, removes sensitive header values, sanitizes the
 * URL, and applies structured JSON/body redaction without mutating the input.
 */
export function redactInventoryPreview(
  input: Readonly<InventoryPreviewInput>
): RedactedInventoryPreview {
  const output: RedactedInventoryPreview = {
    url: redactInventoryUrlPreview(input.url)
  }

  if (input.headers !== undefined) {
    const grouped = new Map<string, string[]>()
    for (const [rawName, rawValue] of Object.entries(input.headers)) {
      const name = rawName.trim().toLowerCase()
      const values = grouped.get(name) ?? []
      values.push(rawValue)
      grouped.set(name, values)
    }
    const headers = Object.create(null) as Record<string, string>
    for (const name of [...grouped.keys()].sort(compareText)) {
      const values = grouped.get(name) ?? []
      headers[name] = isSensitiveFieldName(name)
        ? INVENTORY_REDACTION_MARKER
        : truncatePreview(values.map((value) => redactInventoryText(value, 8_192)).join(', '), 8_192)
    }
    output.headers = headers
  }

  if (input.body !== undefined) output.body = redactBodyPreview(input.body)
  return output
}

function canonicalizeName(value: string, fallback: string): string {
  const trimmed = value.trim()
  return isSecretShapedStructuralValue(trimmed) ? fallback : trimmed
}

/** Canonicalizes and deterministically orders value-free allowed-header descriptors. */
export function canonicalizeAllowedHeaderDescriptors(
  descriptors: readonly AllowedHeaderDescriptor[]
): AllowedHeaderDescriptor[] {
  const byName = new Map<string, AllowedHeaderDescriptor>()
  for (const descriptor of descriptors) {
    const normalized = AllowedHeaderDescriptorSchema.parse({
      ...descriptor,
      name: canonicalizeName(descriptor.name, 'x-redacted').toLowerCase()
    })
    const existing = byName.get(normalized.name)
    if (
      existing &&
      (existing.valueType !== normalized.valueType || existing.required !== normalized.required)
    ) {
      throw new TypeError(`Conflicting allowed-header descriptors for ${normalized.name}.`)
    }
    byName.set(normalized.name, normalized)
  }
  return [...byName.values()].sort((left, right) =>
    compareText(
      `${left.name}\u0000${left.valueType}\u0000${left.required ? '1' : '0'}`,
      `${right.name}\u0000${right.valueType}\u0000${right.required ? '1' : '0'}`
    )
  )
}

function canonicalizePointer(value: string): string {
  const hasLeadingSlash = value.startsWith('/')
  return value
    .split('/')
    .map((segment, index) =>
      index === 0 && hasLeadingSlash
        ? segment
        : canonicalizeName(segment, ':redacted')
    )
    .join('/')
}

/** Removes secret-shaped selector addresses and canonicalizes header casing. */
export function canonicalizeSelectorRef(selector: Readonly<SelectorRef>): SelectorRef {
  let normalized: SelectorRef
  switch (selector.kind) {
    case 'query':
    case 'path':
    case 'cookie':
    case 'form':
      normalized = { ...selector, name: canonicalizeName(selector.name, ':redacted') }
      break
    case 'header':
      normalized = {
        ...selector,
        name: canonicalizeName(selector.name, 'x-redacted').toLowerCase()
      }
      break
    case 'json-pointer':
      normalized = { ...selector, pointer: canonicalizePointer(selector.pointer) }
      break
    case 'multipart-part':
      normalized = {
        ...selector,
        partName: canonicalizeName(selector.partName, ':redacted')
      }
      break
    case 'xml-path':
      normalized = { ...selector, path: canonicalizePointer(selector.path) }
      break
    case 'graphql-variable':
      normalized = {
        ...selector,
        variableName: canonicalizeName(selector.variableName, 'redacted')
      }
      break
    case 'graphql-argument':
      normalized = {
        ...selector,
        fieldPath: selector.fieldPath.map((field) => canonicalizeName(field, 'redacted')),
        argumentName: canonicalizeName(selector.argumentName, 'redacted')
      }
      break
    case 'websocket-field':
      normalized = {
        ...selector,
        messagePath: canonicalizePointer(selector.messagePath)
      }
      break
  }
  return SelectorRefSchema.parse(normalized)
}

/** Canonicalizes, validates uniqueness after redaction, and orders selectors. */
export function canonicalizeSelectorRefs(
  selectors: readonly SelectorRef[]
): SelectorRef[] {
  const normalized = selectors
    .map(canonicalizeSelectorRef)
    .sort((left, right) => compareText(canonicalJson(left), canonicalJson(right)))
  return SelectorRefsSchema.parse(normalized)
}

/** Canonicalizes value-free body paths while preserving only type metadata. */
export function canonicalizeInventoryBodyShape(
  shape: Readonly<InventoryBodyShape>
): InventoryBodyShape {
  return InventoryBodyShapeSchema.parse({
    rootType: shape.rootType,
    fields: shape.fields
      .map((field) => ({
        path: canonicalizePointer(field.path),
        valueType: field.valueType,
        required: field.required
      }))
      .sort((left, right) =>
        compareText(
          `${left.path}\u0000${left.valueType}\u0000${left.required ? '1' : '0'}`,
          `${right.path}\u0000${right.valueType}\u0000${right.required ? '1' : '0'}`
        )
      )
  })
}

/** Canonical object-key ordering plus UTF-8 SHA-256. Arrays remain ordered. */
export function stableInventoryHash(value: unknown): string {
  return sha256Text(canonicalJson(value))
}
