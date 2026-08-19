import { createHash } from 'node:crypto'
import type { DatabaseSync } from 'node:sqlite'
import { TargetBaseUrlSchema } from '@agentgo/contracts'
import { redactInventoryText } from '@agentgo/domain'
import {
  DAY5_EXECUTION_DISPATCH_HARDENING_MIGRATION,
  DAY5_EXECUTION_MIGRATION,
  DAY5_EXECUTION_RECOVERY_HARDENING_MIGRATION
} from './execution-migration'
import { DAY4_PROTECTED_EVIDENCE_MIGRATION } from './protected-evidence-migration'

export interface DatabaseMigration {
  id: string
  sql: string
  /**
   * A deterministic, network-free data rewrite executed after `sql` and
   * before `finalizeSql` in the migration runner's same transaction.
   */
  dataHook?: (database: DatabaseSync) => void
  /** SQL that depends on the data hook having resolved legacy collisions. */
  finalizeSql?: string
}

interface LegacyEndpointRow {
  id: string
  scan_id: string
  page_id: string | null
  method: string
  url_template: string
  normalized_url: string
  content_type: string | null
  source: string
  status: string
  created_at: number
  updated_at: number
  base_url: string
}

interface LegacyParameterRow {
  id: string
  endpoint_id: string
  name: string
  location: string
  data_type: string | null
  required: number
  created_at: number
}

interface LegacyPageRow {
  id: string
  scan_id: string
  url: string
  title: string | null
  base_url: string
}

interface LegacyTargetRow {
  id: string
  workspace_id: string
  base_url: string
}

interface LegacyScanRow {
  id: string
  config_json: string
  created_at: number
}

interface LegacySnapshotDescriptor {
  familyId: 'sqli' | 'xss' | 'ssrf' | 'idor'
  moduleId: string
  definitionHash: string
  techniqueId: string
  strategyId: string
  confirmationRuleId: string
  evidenceProfileId: string
  remediationId: string
  requiredCapabilityIds: string[]
}

const LEGACY_MODULE_VERSION = '1.0.0'
const LEGACY_CAPABILITY_SNAPSHOT_HASH =
  'd7f3aa70efd0b55c981e7d5a105e097b32c95d558eeb5e7b7645f17e490a2792'
const LEGACY_REGISTRY_SNAPSHOT_HASH =
  'd4c45f8c27463729e01d60ab1a1ddfea03039e9dc2967e6ebb52f8c5f17cd9e9'
const LEGACY_SENTINEL_SECRET_PATTERN =
  /(?:day\d*[-_ ]*)?sentinel(?:[-_ ]*(?:secret|token|password|credential))?|must[-_ ]?not[-_ ]?leak|do[-_ ]?not[-_ ]?store|super[-_ ]?secret/iu
const LEGACY_JWT_PATTERN = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u
const LEGACY_TOKEN_PREFIX_PATTERN =
  /^(?:sk|pk|api|key|token|secret|ghp|github_pat|xox[baprs])[-_]/iu
const LEGACY_REDACTED_MARKER = '[REDACTED]'
const LEGACY_TARGET_REVIEW_URL =
  'https://legacy-target-review.invalid/reconfigure/required'
const MAX_LEGACY_REDACTED_URL_LENGTH = 16_384
const MAX_LEGACY_NAMED_SELECTOR_LENGTH = 500
const MAX_LEGACY_SAFE_PATH_LENGTH = 2_048
const MAX_LEGACY_SELECTORS = 2_048
const MAX_LEGACY_BODY_FIELDS = 1_024
const MAX_LEGACY_ALLOWED_HEADERS = 128

const LEGACY_CAPABILITY_DESCRIPTORS = Object.freeze({
  'http.reviewed-read': Object.freeze({
    id: 'http.reviewed-read',
    riskFloor: 'l1',
    description: 'Issue a reviewed, bounded, read-only HTTP request.'
  }),
  'http.identity-read-compare': Object.freeze({
    id: 'http.identity-read-compare',
    riskFloor: 'l1',
    description: 'Compare bounded read-only HTTP responses between authorized test identities.'
  }),
  'browser.offline-replay': Object.freeze({
    id: 'browser.offline-replay',
    riskFloor: 'l1',
    description: 'Replay captured content in an isolated browser with external network access disabled.'
  }),
  'oob.controlled-observe': Object.freeze({
    id: 'oob.controlled-observe',
    riskFloor: 'l1',
    description: 'Observe a bounded callback through an AgentGo-controlled out-of-band service.'
  })
})

const LEGACY_SNAPSHOT_DESCRIPTORS = Object.freeze({
  sqli: Object.freeze({
    familyId: 'sqli',
    moduleId: 'sqli.legacy-v1',
    definitionHash:
      '42061d63b40babd5b62d2c6f5c5fef692b9189fe854f5d76e0dc101c01acaf5b',
    techniqueId: 'sqli.boolean-differential',
    strategyId: 'sqli.legacy.strategy',
    confirmationRuleId: 'sqli-boolean-differential',
    evidenceProfileId: 'sqli.legacy.evidence',
    remediationId: 'sqli.legacy.remediation',
    requiredCapabilityIds: ['http.reviewed-read']
  }),
  xss: Object.freeze({
    familyId: 'xss',
    moduleId: 'xss.legacy-v1',
    definitionHash:
      '89b2f50d1780bf5f53a2f2f0a8e5ae449a18346e076e2dbe5e69f00e29dfe4b6',
    techniqueId: 'xss.reflected-inert-marker',
    strategyId: 'xss.legacy.strategy',
    confirmationRuleId: 'xss-inert-marker-execution',
    evidenceProfileId: 'xss.legacy.evidence',
    remediationId: 'xss.legacy.remediation',
    requiredCapabilityIds: ['browser.offline-replay', 'http.reviewed-read']
  }),
  ssrf: Object.freeze({
    familyId: 'ssrf',
    moduleId: 'ssrf.legacy-v1',
    definitionHash:
      '490de422192857b8be83125ab74acde2c53212dac8bdf68b879a5904089d4a7f',
    techniqueId: 'ssrf.controlled-proof-response',
    strategyId: 'ssrf.legacy.strategy',
    confirmationRuleId: 'ssrf-controlled-proof-response',
    evidenceProfileId: 'ssrf.legacy.evidence',
    remediationId: 'ssrf.legacy.remediation',
    requiredCapabilityIds: ['http.reviewed-read', 'oob.controlled-observe']
  }),
  idor: Object.freeze({
    familyId: 'idor',
    moduleId: 'idor.legacy-v1',
    definitionHash:
      '67da31d42bdd9144e6c114f20ea1b7eb2348337481a4dc931cd9557d5efe0d02',
    techniqueId: 'idor.two-test-identities-readonly',
    strategyId: 'idor.legacy.strategy',
    confirmationRuleId: 'idor-two-test-identities-readonly',
    evidenceProfileId: 'idor.legacy.evidence',
    remediationId: 'idor.legacy.remediation',
    requiredCapabilityIds: ['http.identity-read-compare']
  })
} as const satisfies Record<string, Readonly<LegacySnapshotDescriptor>>)

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function canonicalJson(value: unknown): string {
  function normalize(input: unknown): unknown {
    if (Array.isArray(input)) return input.map(normalize)
    if (input !== null && typeof input === 'object') {
      return Object.fromEntries(
        Object.entries(input as Record<string, unknown>)
          .sort(([left], [right]) => compareBinary(left, right))
          .map(([key, item]) => [key, normalize(item)])
      )
    }
    return input
  }
  return JSON.stringify(normalize(value))
}

function migrationHash(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex')
}

function deterministicId(namespace: string, value: unknown): string {
  return `${namespace}-${migrationHash(value).slice(0, 32)}`
}

function legacyShannonEntropy(value: string): number {
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

function isLegacySecretShaped(value: string): boolean {
  const candidate = value.trim()
  if (candidate.length === 0) return false
  if (/^bearer\s+/iu.test(candidate)) return true
  if (LEGACY_JWT_PATTERN.test(candidate)) return true
  if (LEGACY_SENTINEL_SECRET_PATTERN.test(candidate)) return true
  if (LEGACY_TOKEN_PREFIX_PATTERN.test(candidate) && candidate.length >= 16) return true
  if (candidate.length < 20 || /\s/u.test(candidate)) return false
  if (!/^[A-Za-z0-9._~+\/-]+={0,2}$/u.test(candidate)) return false
  const uniqueRatio = new Set(candidate).size / candidate.length
  const minimumEntropy = /^[a-f0-9-]+$/iu.test(candidate) ? 3.2 : 3.6
  return uniqueRatio >= 0.25 && legacyShannonEntropy(candidate) >= minimumEntropy
}

function canonicalizeLegacyStructuralName(value: string, fallback: string): string {
  const trimmed = value.trim()
  return !trimmed || isLegacySecretShaped(trimmed) ? fallback : trimmed
}

function boundedLegacyText(value: string, fallback: string, maxLength: number): string {
  const canonical = canonicalizeLegacyStructuralName(value, fallback)
    .replace(/[\u0000-\u001f\u007f]/gu, '-')
    .trim()
  const candidate = canonical || fallback
  if (candidate.length <= maxLength) return candidate
  const suffix = `-legacy-${migrationHash(value).slice(0, 16)}`
  return `${candidate.slice(0, Math.max(0, maxLength - suffix.length))}${suffix}`
}

function canonicalLegacyNamedSelector(value: string, fallback = ':redacted'): string {
  return boundedLegacyText(value, fallback, MAX_LEGACY_NAMED_SELECTOR_LENGTH)
}

function canonicalLegacyHeaderName(value: string): string {
  const candidate = canonicalizeLegacyStructuralName(value, 'x-redacted')
    .toLowerCase()
    .replace(/[^!#$%&'*+.^_`|~0-9a-z-]/gu, '-')
    .replace(/-+/gu, '-')
  return boundedLegacyText(candidate, 'x-redacted', 128)
}

function canonicalLegacyGraphqlName(value: string): string {
  const candidate = canonicalizeLegacyStructuralName(value, 'redacted')
  return /^[_A-Za-z][_0-9A-Za-z]{0,127}$/u.test(candidate)
    ? candidate
    : `legacy_${migrationHash(value).slice(0, 32)}`
}

function canonicalLegacyJsonPointer(value: string): string {
  const name = canonicalLegacyNamedSelector(value)
  const escaped = name.replaceAll('~', '~0').replaceAll('/', '~1')
  return escaped.length + 1 <= MAX_LEGACY_SAFE_PATH_LENGTH
    ? `/${escaped}`
    : `/legacy-${migrationHash(value).slice(0, 32)}`
}

function canonicalLegacySafePath(value: string): string {
  return boundedLegacyText(value, ':redacted', MAX_LEGACY_SAFE_PATH_LENGTH)
}

function canonicalLegacyMethod(value: string): string {
  const candidate = value.trim().toUpperCase()
  return /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u.test(candidate)
    ? candidate
    : `LEGACY-${migrationHash(value).slice(0, 16).toUpperCase()}`
}

function canonicalizeLegacyPathSegment(value: string): string {
  let decoded: string
  try {
    decoded = decodeURIComponent(value)
  } catch {
    return ':redacted'
  }
  if (isLegacySecretShaped(decoded)) return ':redacted'
  return encodeURIComponent(decoded).replace(/%3A/giu, ':')
}

function canonicalizeLegacyPathname(pathname: string): string {
  return pathname.split('/').map(canonicalizeLegacyPathSegment).join('/')
}

function canonicalizeLegacyHostname(hostname: string): string {
  return hostname
    .split('.')
    .map((label) =>
      isLegacySecretShaped(label)
        ? `redacted-${migrationHash(label).slice(0, 16)}`
        : label
    )
    .join('.')
}

function legacyBaseUrl(value: string): URL {
  try {
    const url = new URL(value)
    if (
      ['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) &&
      url.origin !== 'null'
    ) {
      return url
    }
  } catch {
    // Fall through to a deterministic, non-secret migration origin.
  }
  return new URL('https://legacy-unparseable.invalid/')
}

function redactLegacyUrl(value: string, baseUrl: string): string {
  const base = legacyBaseUrl(baseUrl)
  let url: URL
  try {
    url = new URL(value, base)
  } catch {
    const fallback = new URL(base)
    fallback.username = ''
    fallback.password = ''
    fallback.hash = ''
    fallback.search = ''
    fallback.hostname = canonicalizeLegacyHostname(fallback.hostname)
    fallback.pathname = `/_legacy-unparseable/${migrationHash(value).slice(0, 32)}`
    return fallback.toString()
  }
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) {
    const fallback = new URL(base)
    fallback.username = ''
    fallback.password = ''
    fallback.hash = ''
    fallback.search = ''
    fallback.hostname = canonicalizeLegacyHostname(fallback.hostname)
    fallback.pathname = `/_legacy-unparseable/${migrationHash(value).slice(0, 32)}`
    return fallback.toString()
  }

  const queryNames = [...url.searchParams.keys()].sort(compareBinary)
  url.username = ''
  url.password = ''
  url.hash = ''
  url.hostname = canonicalizeLegacyHostname(url.hostname)
  url.pathname = canonicalizeLegacyPathname(url.pathname)
  url.search = ''
  if (url.toString().length > MAX_LEGACY_REDACTED_URL_LENGTH) {
    url.pathname = `/_legacy-redacted-path/${migrationHash(url.pathname).slice(0, 32)}`
  }
  for (const name of queryNames) {
    const safeName = canonicalizeLegacyStructuralName(name, 'redacted-name')
    url.searchParams.append(safeName, LEGACY_REDACTED_MARKER)
    if (url.toString().length > MAX_LEGACY_REDACTED_URL_LENGTH) {
      const acceptedNames = [...url.searchParams.keys()].slice(0, -1)
      url.search = ''
      for (const acceptedName of acceptedNames) {
        url.searchParams.append(acceptedName, LEGACY_REDACTED_MARKER)
      }
      break
    }
  }
  return url.toString()
}

function distinguishLegacyPageUrl(page: LegacyPageRow, redactedUrl: string): string {
  const url = new URL(redactedUrl)
  const discriminator = migrationHash({
    scanId: page.scan_id,
    pageId: page.id,
    originalUrlHash: migrationHash(page.url)
  }).slice(0, 32)
  url.searchParams.append(
    `__agentgo_legacy_ref_${discriminator}`,
    LEGACY_REDACTED_MARKER
  )
  if (url.toString().length > MAX_LEGACY_REDACTED_URL_LENGTH) {
    url.search = ''
    url.pathname = `/_legacy-page/${discriminator}`
  }
  return url.toString()
}

function redactLegacyPages(database: DatabaseSync): void {
  const pages = database
    .prepare(
      `SELECT pages.id, pages.scan_id, pages.url, pages.title, targets.base_url
       FROM pages
       INNER JOIN scans ON scans.id = pages.scan_id
       INNER JOIN targets ON targets.id = scans.target_id
       ORDER BY pages.scan_id ASC, pages.created_at ASC, pages.id ASC`
    )
    .all() as unknown as LegacyPageRow[]
  const groups = new Map<string, LegacyPageRow[]>()
  const redactedById = new Map<string, string>()
  for (const page of pages) {
    const redacted = redactLegacyUrl(page.url, page.base_url)
    redactedById.set(page.id, redacted)
    const key = canonicalJson([page.scan_id, redacted])
    const group = groups.get(key) ?? []
    group.push(page)
    groups.set(key, group)
  }
  const finalById = new Map<string, string>()
  for (const group of groups.values()) {
    for (const page of group) {
      const redacted = redactedById.get(page.id)!
      finalById.set(
        page.id,
        group.length === 1 ? redacted : distinguishLegacyPageUrl(page, redacted)
      )
    }
  }
  const temporarilyMovePage = database.prepare('UPDATE pages SET url = ? WHERE id = ?')
  const updatePage = database.prepare(
    'UPDATE pages SET url = ?, title = ? WHERE id = ?'
  )
  for (const page of pages) {
    temporarilyMovePage.run(
      `https://legacy-page-migration.invalid/${migrationHash({ scanId: page.scan_id, id: page.id }).slice(0, 32)}`,
      page.id
    )
  }
  for (const page of pages) {
    updatePage.run(
      finalById.get(page.id)!,
      page.title === null ? null : redactInventoryText(page.title, 512),
      page.id
    )
  }
}

function canonicalLegacyTargetBaseUrl(value: string): string {
  try {
    const parsed = TargetBaseUrlSchema.safeParse(value)
    if (!parsed.success) return LEGACY_TARGET_REVIEW_URL

    // A contract-valid seed is already credential-free. Preserve its full request
    // semantics, including benign query names and values, while matching the
    // repository's URL normalization at the persistence boundary.
    return new URL(parsed.data).toString()
  } catch {
    // The current contract's refinement constructs URL eagerly, so malformed
    // historical TEXT can throw before safeParse returns a failure result.
    return LEGACY_TARGET_REVIEW_URL
  }
}

function distinguishLegacyTargetBaseUrl(
  redactedUrl: string,
  ordinal: number
): string {
  const candidate = new URL(redactedUrl)
  const requiresReview = candidate.origin === new URL(LEGACY_TARGET_REVIEW_URL).origin
  const url = requiresReview
    ? candidate
    : new URL('https://legacy-target-review.invalid/reconfigure/normalized-collision')
  url.pathname = requiresReview
    ? `/reconfigure/required/instance-${ordinal}`
    : `/reconfigure/normalized-collision/instance-${ordinal}`
  return url.toString()
}

function redactLegacyTargets(database: DatabaseSync): void {
  const targets = database
    .prepare(
      `SELECT id, workspace_id, base_url
       FROM targets
       ORDER BY workspace_id ASC, created_at ASC, id ASC`
    )
    .all() as unknown as LegacyTargetRow[]
  const groups = new Map<string, LegacyTargetRow[]>()
  const redactedById = new Map<string, string>()
  for (const target of targets) {
    const redacted = canonicalLegacyTargetBaseUrl(target.base_url)
    redactedById.set(target.id, redacted)
    const key = canonicalJson([target.workspace_id, redacted])
    const group = groups.get(key) ?? []
    group.push(target)
    groups.set(key, group)
  }
  const finalById = new Map<string, string>()
  for (const group of groups.values()) {
    for (const [index, target] of group.entries()) {
      const redacted = redactedById.get(target.id)!
      finalById.set(
        target.id,
        group.length === 1
          ? redacted
          : distinguishLegacyTargetBaseUrl(redacted, index + 1)
      )
    }
  }

  const updateTarget = database.prepare('UPDATE targets SET base_url = ? WHERE id = ?')
  for (const target of targets) {
    updateTarget.run(
      `https://legacy-target-migration.invalid/${migrationHash({
        id: target.id,
        workspaceId: target.workspace_id
      }).slice(0, 32)}`,
      target.id
    )
  }
  for (const target of targets) {
    updateTarget.run(finalById.get(target.id)!, target.id)
  }

  const auditRows = database
    .prepare(
      `SELECT id, detail_json
       FROM audit_logs
       WHERE event IN ('target.created', 'target.updated', 'target.deleted')`
    )
    .all() as unknown as Array<{ id: string; detail_json: string }>
  const updateAudit = database.prepare(
    'UPDATE audit_logs SET detail_json = ? WHERE id = ?'
  )
  for (const row of auditRows) {
    try {
      const detail = JSON.parse(row.detail_json) as Record<string, unknown>
      if (typeof detail.baseUrl !== 'string') continue
      const targetId =
        typeof detail.targetId === 'string' ? detail.targetId : undefined
      updateAudit.run(
        canonicalJson({
          ...detail,
          baseUrl:
            (targetId ? finalById.get(targetId) : undefined) ??
            canonicalLegacyTargetBaseUrl(detail.baseUrl)
        }),
        row.id
      )
    } catch {
      updateAudit.run(
        canonicalJson({ migrationState: 'legacy-unparseable-redacted' }),
        row.id
      )
    }
  }
}

function canonicalLegacyRoute(endpoint: LegacyEndpointRow): string {
  const base = legacyBaseUrl(endpoint.base_url)

  for (const candidate of [endpoint.url_template, endpoint.normalized_url]) {
    try {
      const url = new URL(candidate, base)
      if (
        (url.protocol === 'http:' ||
          url.protocol === 'https:' ||
          url.protocol === 'ws:' ||
          url.protocol === 'wss:') &&
        url.origin !== 'null'
      ) {
        url.hostname = canonicalizeLegacyHostname(url.hostname)
        const route = `${url.origin}${canonicalizeLegacyPathname(url.pathname || '/')}`
        if (route.length <= MAX_LEGACY_REDACTED_URL_LENGTH) return route
        url.pathname = `/_legacy-redacted-path/${migrationHash(route).slice(0, 32)}`
        return `${url.origin}${url.pathname}`
      }
    } catch {
      // Try the next historical representation before using a non-secret marker.
    }
  }

  const pathOnly = (endpoint.url_template || endpoint.normalized_url)
    .split(/[?#]/u, 1)[0]
    ?.trim()
  const structuralPath = (pathOnly || '/')
    .split('/')
    .map(canonicalizeLegacyPathSegment)
    .join('/')
  return `${base.origin}/_legacy-unparseable/${migrationHash(structuralPath).slice(0, 32)}`
}

function normalizedContentType(value: string | null): string | null {
  const mediaType = value?.split(';', 1)[0]?.trim().toLowerCase()
  return mediaType &&
    mediaType.length <= 500 &&
    /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(mediaType)
    ? mediaType
    : null
}

function legacyCodec(method: string, contentType: string | null): string {
  const mediaType = contentType?.split(';', 1)[0]?.trim() ?? ''
  if (mediaType.includes('x-www-form-urlencoded')) return 'form'
  if (mediaType.includes('json')) return 'json'
  if (mediaType.includes('xml')) return 'xml'
  if (mediaType.includes('multipart')) return 'multipart'
  if (mediaType.includes('graphql')) return 'graphql'
  if (method === 'GET' || method === 'HEAD') return 'none'
  return 'raw'
}

function legacyValueType(value: string | null): string {
  const normalized = value?.trim().toLowerCase()
  if (
    normalized === 'string' ||
    normalized === 'number' ||
    normalized === 'integer' ||
    normalized === 'boolean' ||
    normalized === 'object' ||
    normalized === 'array' ||
    normalized === 'binary' ||
    normalized === 'null' ||
    normalized === 'none'
  ) {
    return normalized
  }
  return 'unknown'
}

function legacySelector(parameter: LegacyParameterRow, codec: string): Record<string, unknown> {
  const location = parameter.location.trim().toLowerCase()
  const common = {
    valueType: legacyValueType(parameter.data_type),
    required: parameter.required === 1
  }
  if (location === 'json' || (location === 'form' && codec === 'json')) {
    return {
      kind: 'json-pointer',
      pointer: canonicalLegacyJsonPointer(parameter.name),
      ...common
    }
  }
  if (location === 'form' && codec === 'xml') {
    return { kind: 'xml-path', path: canonicalLegacySafePath(parameter.name), ...common }
  }
  if (location === 'form' && codec === 'multipart') {
    return {
      kind: 'multipart-part',
      partName: canonicalLegacyNamedSelector(parameter.name),
      ...common
    }
  }
  if (location === 'form' && codec === 'graphql') {
    return {
      kind: 'graphql-variable',
      variableName: canonicalLegacyGraphqlName(parameter.name),
      ...common
    }
  }
  if (location === 'header') {
    return { kind: 'header', name: canonicalLegacyHeaderName(parameter.name), ...common }
  }
  if (
    location === 'query' ||
    location === 'path' ||
    location === 'cookie' ||
    location === 'form'
  ) {
    return {
      kind: location,
      name: canonicalLegacyNamedSelector(parameter.name),
      ...common
    }
  }
  return {
    kind: 'form',
    name: canonicalLegacyNamedSelector(
      `${parameter.location}:${parameter.name}`,
      'legacy-field'
    ),
    ...common
  }
}

interface LegacySelectorEntry {
  readonly selector: Record<string, unknown>
  readonly createdAt: number
}

function legacySelectorAddressKey(selector: Record<string, unknown>): string {
  const kind = String(selector.kind)
  if (
    kind === 'query' ||
    kind === 'path' ||
    kind === 'header' ||
    kind === 'cookie' ||
    kind === 'form'
  ) {
    return `${kind}\u0000${String(selector.name)}`
  }
  if (kind === 'json-pointer') {
    return `${kind}\u0000${String(selector.pointer)}`
  }
  if (kind === 'multipart-part') {
    return `${kind}\u0000${String(selector.partName)}`
  }
  if (kind === 'xml-path') {
    return `${kind}\u0000${String(selector.path)}`
  }
  if (kind === 'graphql-variable') {
    return `${kind}\u0000${String(selector.variableName)}`
  }
  return canonicalJson(selector)
}

function legacySelectorEntries(
  parameters: readonly LegacyParameterRow[],
  codec: string
): LegacySelectorEntry[] {
  const byAddress = new Map<string, LegacySelectorEntry>()
  for (const parameter of parameters) {
    const selector = legacySelector(parameter, codec)
    const key = legacySelectorAddressKey(selector)
    const existing = byAddress.get(key)
    if (!existing) {
      byAddress.set(key, { selector, createdAt: parameter.created_at })
      continue
    }
    byAddress.set(key, {
      selector: {
        ...existing.selector,
        valueType:
          existing.selector.valueType === selector.valueType
            ? existing.selector.valueType
            : 'unknown',
        required: Boolean(existing.selector.required || selector.required)
      },
      createdAt: Math.min(existing.createdAt, parameter.created_at)
    })
  }
  return [...byAddress.values()]
    .sort((left, right) =>
      compareBinary(canonicalJson(left.selector), canonicalJson(right.selector))
    )
    .slice(0, MAX_LEGACY_SELECTORS)
}

function legacyBodyShape(
  parameters: readonly LegacyParameterRow[],
  codec: string
): { rootType: string; fields: Array<Record<string, unknown>> } {
  if (codec === 'none') return { rootType: 'none', fields: [] }
  const bodyParameters = parameters.filter(
    ({ location }) =>
      location.trim().toLowerCase() === 'form' ||
      location.trim().toLowerCase() === 'json'
  )
  if (bodyParameters.length === 0) {
    return { rootType: 'unknown', fields: [] }
  }
  const byPath = new Map<string, Record<string, unknown>>()
  for (const parameter of bodyParameters) {
    const selector = legacySelector(parameter, codec)
    const path =
      typeof selector.pointer === 'string'
        ? selector.pointer
        : typeof selector.path === 'string'
          ? selector.path
          : typeof selector.partName === 'string'
            ? selector.partName
            : typeof selector.variableName === 'string'
              ? selector.variableName
              : canonicalizeLegacyStructuralName(parameter.name, ':redacted')
    const valueType = legacyValueType(parameter.data_type)
    const required = parameter.required === 1
    const existing = byPath.get(path)
    byPath.set(path, {
      path,
      valueType:
        existing?.valueType === undefined || existing.valueType === valueType
          ? valueType
          : 'unknown',
      required: Boolean(existing?.required || required)
    })
  }
  const fields = [...byPath.values()]
    .sort((left, right) => compareBinary(String(left.path), String(right.path)))
    .slice(0, MAX_LEGACY_BODY_FIELDS)
  return { rootType: 'object', fields }
}

function legacyAllowedHeaders(
  parameters: readonly LegacyParameterRow[]
): Array<{ name: string; valueType: string; required: boolean }> {
  const byName = new Map<
    string,
    { name: string; valueType: string; required: boolean }
  >()
  for (const parameter of parameters.filter(
    ({ location }) => location.trim().toLowerCase() === 'header'
  )) {
    const name = canonicalLegacyHeaderName(parameter.name)
    const valueType = legacyValueType(parameter.data_type)
    const required = parameter.required === 1
    const existing = byName.get(name)
    byName.set(name, {
      name,
      valueType:
        existing === undefined || existing.valueType === valueType
          ? valueType
          : 'unknown',
      required: Boolean(existing?.required || required)
    })
  }
  return [...byName.values()]
    .sort((left, right) => compareBinary(left.name, right.name))
    .slice(0, MAX_LEGACY_ALLOWED_HEADERS)
}

function canonicalLegacyParameterName(parameter: LegacyParameterRow): string {
  return parameter.location.trim().toLowerCase() === 'header'
    ? canonicalLegacyHeaderName(parameter.name)
    : canonicalLegacyNamedSelector(parameter.name)
}

function canonicalLegacySourceType(value: string): string {
  const candidate = canonicalizeLegacyStructuralName(
    value.trim().toLowerCase(),
    'legacy-unknown'
  )
  return /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/u.test(candidate) &&
    candidate.length <= 200
    ? candidate
    : 'legacy-unknown'
}

function readLegacyFamilies(configJson: string): string[] {
  try {
    const value = JSON.parse(configJson) as { families?: unknown }
    if (!Array.isArray(value.families)) return []
    return [...new Set(value.families.filter((family): family is string => typeof family === 'string'))]
      .sort(compareBinary)
  } catch {
    return []
  }
}

function migrateDay3Inventory(database: DatabaseSync): void {
  redactLegacyPages(database)
  const endpoints = database
    .prepare(
      `SELECT endpoints.id, endpoints.scan_id, endpoints.page_id,
              endpoints.method, endpoints.url_template, endpoints.normalized_url,
              endpoints.content_type, endpoints.source, endpoints.status,
              endpoints.created_at, endpoints.updated_at, targets.base_url
       FROM endpoints
       INNER JOIN scans ON scans.id = endpoints.scan_id
       INNER JOIN targets ON targets.id = scans.target_id
       ORDER BY endpoints.created_at ASC, endpoints.id ASC`
    )
    .all() as unknown as LegacyEndpointRow[]
  const parameters = database
    .prepare(
      `SELECT id, endpoint_id, name, location, data_type, required, created_at
       FROM parameters
       ORDER BY created_at ASC, id ASC`
    )
    .all() as unknown as LegacyParameterRow[]
  const pageScans = new Map(
    (
      database.prepare('SELECT id, scan_id FROM pages').all() as unknown as Array<{
        id: string
        scan_id: string
      }>
    ).map(({ id, scan_id }) => [id, scan_id] as const)
  )

  const endpointGroups = new Map<string, LegacyEndpointRow[]>()
  const canonicalRoutes = new Map<string, string>()
  for (const endpoint of endpoints) {
    const method = canonicalLegacyMethod(endpoint.method)
    const canonicalRoute = canonicalLegacyRoute(endpoint)
    canonicalRoutes.set(endpoint.id, canonicalRoute)
    const key = canonicalJson([endpoint.scan_id, method, canonicalRoute])
    const group = endpointGroups.get(key) ?? []
    group.push(endpoint)
    endpointGroups.set(key, group)
  }

  const endpointSurvivors = new Map<string, LegacyEndpointRow>()
  for (const group of endpointGroups.values()) {
    const survivor = group[0]!
    for (const endpoint of group) endpointSurvivors.set(endpoint.id, survivor)
  }

  const insertVariant = database.prepare(
    `INSERT OR IGNORE INTO request_variants (
       id, scan_id, endpoint_id, content_type, body_shape_json, codec, transport,
       allowed_headers_json, redacted_preview_json, template_version,
       required_capability_ids_json, review_status, reviewed_by, reviewed_at, execution_class,
       lifecycle_status, retired_at, structure_hash, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  const insertSelector = database.prepare(
    `INSERT OR IGNORE INTO request_variant_selectors (
       id, scan_id, request_variant_id, kind, selector_json,
       structure_hash, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
  const insertSource = database.prepare(
    `INSERT OR IGNORE INTO inventory_sources (
       id, scan_id, endpoint_id, request_variant_id, source_type, source_hash,
       provenance_hash, page_id, evidence_ref, initiator, confidence_ppm, discovered_at,
       review_status, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  const parametersByEndpoint = new Map<string, LegacyParameterRow[]>()
  for (const parameter of parameters) {
    const rows = parametersByEndpoint.get(parameter.endpoint_id) ?? []
    rows.push(parameter)
    parametersByEndpoint.set(parameter.endpoint_id, rows)
  }

  for (const endpoint of endpoints) {
    const survivor = endpointSurvivors.get(endpoint.id)!
    const method = canonicalLegacyMethod(endpoint.method)
    const contentType = normalizedContentType(endpoint.content_type)
    const codec = legacyCodec(method, contentType)
    const legacyParameters = parametersByEndpoint.get(endpoint.id) ?? []
    const bodyShape = legacyBodyShape(legacyParameters, codec)
    const allowedHeaders = legacyAllowedHeaders(legacyParameters)
    const selectorEntries = legacySelectorEntries(legacyParameters, codec)
    const selectors = selectorEntries.map(({ selector }) => selector)
    const canonicalRoute = canonicalRoutes.get(endpoint.id)!
    const variantStructure = {
      contentType,
      bodyShape,
      codec,
      transport: 'standard-http',
      allowedHeaders,
      templateVersion: LEGACY_MODULE_VERSION,
      requiredCapabilityIds: [],
      selectors
    }
    const structureHash = migrationHash(variantStructure)
    const variantId = deterministicId('legacy-variant', {
      endpointId: survivor.id,
      structureHash
    })
    insertVariant.run(
      variantId,
      endpoint.scan_id,
      survivor.id,
      contentType,
      canonicalJson(bodyShape),
      codec,
      'standard-http',
      canonicalJson(allowedHeaders),
      canonicalJson({ url: canonicalRoute }),
      LEGACY_MODULE_VERSION,
      '[]',
      'unreviewed',
      null,
      null,
      'inventory-only',
      'active',
      null,
      structureHash,
      endpoint.created_at,
      endpoint.updated_at
    )

    for (const { selector, createdAt } of selectorEntries) {
      const selectorHash = migrationHash(selector)
      insertSelector.run(
        deterministicId('legacy-selector', { variantId, selectorHash }),
        endpoint.scan_id,
        variantId,
        String(selector.kind),
        canonicalJson(selector),
        selectorHash,
        createdAt
      )
    }

    const sourceType = canonicalLegacySourceType(endpoint.source)
    const sourceHash = migrationHash({
      legacyEndpointId: endpoint.id,
      sourceType
    })
    const pageId =
      endpoint.page_id && pageScans.get(endpoint.page_id) === endpoint.scan_id
        ? endpoint.page_id
        : null
    const provenanceHash = migrationHash({
      scanId: endpoint.scan_id,
      endpointId: survivor.id,
      requestVariantId: variantId,
      sourceType,
      sourceHash,
      pageId
    })
    insertSource.run(
      deterministicId('legacy-source', {
        scanId: endpoint.scan_id,
        provenanceHash
      }),
      endpoint.scan_id,
      survivor.id,
      variantId,
      sourceType,
      sourceHash,
      provenanceHash,
      pageId,
      null,
      null,
      0,
      endpoint.created_at,
      'unreviewed',
      endpoint.created_at
    )
  }

  const updateParameterReference = [
    database.prepare('UPDATE signals SET parameter_id = ? WHERE parameter_id = ?'),
    database.prepare('UPDATE findings SET parameter_id = ? WHERE parameter_id = ?')
  ]
  const updateEndpointReference = [
    database.prepare('UPDATE interactions SET endpoint_id = ? WHERE endpoint_id = ?'),
    database.prepare('UPDATE signals SET endpoint_id = ? WHERE endpoint_id = ?'),
    database.prepare('UPDATE findings SET endpoint_id = ? WHERE endpoint_id = ?')
  ]
  const deleteParameter = database.prepare('DELETE FROM parameters WHERE id = ?')
  const moveParameter = database.prepare(
    'UPDATE parameters SET endpoint_id = ?, name = ? WHERE id = ?'
  )
  const deleteEndpoint = database.prepare('DELETE FROM endpoints WHERE id = ?')
  const updateEndpoint = database.prepare(
    `UPDATE endpoints
     SET method = ?, url_template = ?, normalized_url = ?,
         canonical_route = ?, content_type = ?, page_id = ?, source = ?
     WHERE id = ?`
  )

  database.exec('UPDATE parameters SET example_masked = NULL;')

  for (const group of endpointGroups.values()) {
    const survivor = group[0]!
    const groupIds = new Set(group.map(({ id }) => id))
    const groupParameters = parameters.filter((parameter) => groupIds.has(parameter.endpoint_id))
    const parameterGroups = new Map<string, LegacyParameterRow[]>()
    for (const parameter of groupParameters) {
      const key = canonicalJson([
        canonicalLegacyParameterName(parameter),
        parameter.location
      ])
      const rows = parameterGroups.get(key) ?? []
      rows.push(parameter)
      parameterGroups.set(key, rows)
    }

    for (const rows of parameterGroups.values()) {
      const parameterSurvivor = rows[0]!
      for (const duplicate of rows.slice(1)) {
        for (const statement of updateParameterReference) {
          statement.run(parameterSurvivor.id, duplicate.id)
        }
        deleteParameter.run(duplicate.id)
      }
      moveParameter.run(
        survivor.id,
        canonicalLegacyParameterName(parameterSurvivor),
        parameterSurvivor.id
      )
    }

    for (const duplicate of group.slice(1)) {
      for (const statement of updateEndpointReference) {
        statement.run(survivor.id, duplicate.id)
      }
      deleteEndpoint.run(duplicate.id)
    }
    const survivorPageId = group
      .map(({ page_id }) => page_id)
      .find((pageId) => pageId !== null && pageScans.get(pageId) === survivor.scan_id)
    updateEndpoint.run(
      canonicalLegacyMethod(survivor.method),
      canonicalRoutes.get(survivor.id)!,
      canonicalRoutes.get(survivor.id)!,
      canonicalRoutes.get(survivor.id)!,
      normalizedContentType(survivor.content_type),
      survivorPageId ?? null,
      canonicalLegacySourceType(survivor.source),
      survivor.id
    )
  }

  // Endpoint and page resolution above needs the original base. Once their
  // value-free routes are frozen, preserve contract-valid target semantics and
  // fail closed any unsafe legacy seed in targets and lifecycle audit details.
  redactLegacyTargets(database)

  const scans = database
    .prepare('SELECT id, config_json, created_at FROM scans ORDER BY created_at ASC, id ASC')
    .all() as unknown as LegacyScanRow[]
  const insertSnapshot = database.prepare(
    `INSERT OR IGNORE INTO scan_module_snapshots (
       id, scan_id, family_id, module_id, module_version,
       definition_hash, technique_id, technique_version,
       strategy_refs_json, confirmation_rule_refs_json,
       evidence_profile_refs_json, remediation_refs_json,
       required_capability_ids_json, capability_descriptors_json,
       capability_snapshot_hash, selected_capabilities_hash,
       selected_definitions_hash, registry_snapshot_hash, environment,
       authorization, snapshot_hash, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )

  for (const scan of scans) {
    for (const family of readLegacyFamilies(scan.config_json)) {
      const descriptor = LEGACY_SNAPSHOT_DESCRIPTORS[
        family as keyof typeof LEGACY_SNAPSHOT_DESCRIPTORS
      ]
      if (!descriptor) continue
      const ref = (id: string) => [{ id, version: LEGACY_MODULE_VERSION }]
      const strategyRefs = ref(descriptor.strategyId)
      const confirmationRuleRefs = ref(descriptor.confirmationRuleId)
      const evidenceProfileRefs = ref(descriptor.evidenceProfileId)
      const remediationRefs = ref(descriptor.remediationId)
      const requiredCapabilityIds = [...descriptor.requiredCapabilityIds].sort(compareBinary)
      const requiredCapabilityDescriptors = requiredCapabilityIds.map((id) => {
        const capability =
          LEGACY_CAPABILITY_DESCRIPTORS[
            id as keyof typeof LEGACY_CAPABILITY_DESCRIPTORS
          ]
        return {
          id: capability.id,
          riskFloor: capability.riskFloor,
          descriptorHash: migrationHash({
            description: capability.description,
            id: capability.id,
            riskFloor: capability.riskFloor
          })
        }
      })
      const selectedCapabilitiesHash = migrationHash({
        descriptors: requiredCapabilityDescriptors
      })
      const selectedDefinitions = {
        familyId: descriptor.familyId,
        moduleId: descriptor.moduleId,
        moduleVersion: LEGACY_MODULE_VERSION,
        moduleDefinitionHash: descriptor.definitionHash,
        techniqueId: descriptor.techniqueId,
        techniqueVersion: LEGACY_MODULE_VERSION,
        strategyRefs,
        confirmationRuleRefs,
        evidenceProfileRefs,
        remediationRefs
      }
      const selectedDefinitionsHash = migrationHash(selectedDefinitions)
      const snapshot = {
        familyId: descriptor.familyId,
        moduleId: descriptor.moduleId,
        moduleVersion: LEGACY_MODULE_VERSION,
        definitionHash: descriptor.definitionHash,
        techniqueId: descriptor.techniqueId,
        techniqueVersion: LEGACY_MODULE_VERSION,
        strategyRefs,
        confirmationRuleRefs,
        evidenceProfileRefs,
        remediationRefs,
        requiredCapabilityIds,
        capabilityDescriptors: requiredCapabilityDescriptors,
        capabilitySnapshotHash: LEGACY_CAPABILITY_SNAPSHOT_HASH,
        selectedCapabilitiesHash,
        selectedDefinitionsHash,
        registrySnapshotHash: LEGACY_REGISTRY_SNAPSHOT_HASH,
        environment: 'legacy-unknown',
        authorization: 'legacy-v1-compatibility'
      }
      const snapshotHash = migrationHash(snapshot)
      insertSnapshot.run(
        deterministicId('legacy-module-snapshot', {
          scanId: scan.id,
          familyId: descriptor.familyId,
          techniqueId: descriptor.techniqueId
        }),
        scan.id,
        descriptor.familyId,
        descriptor.moduleId,
        LEGACY_MODULE_VERSION,
        descriptor.definitionHash,
        descriptor.techniqueId,
        LEGACY_MODULE_VERSION,
        canonicalJson(strategyRefs),
        canonicalJson(confirmationRuleRefs),
        canonicalJson(evidenceProfileRefs),
        canonicalJson(remediationRefs),
        canonicalJson(requiredCapabilityIds),
        canonicalJson(requiredCapabilityDescriptors),
        LEGACY_CAPABILITY_SNAPSHOT_HASH,
        selectedCapabilitiesHash,
        selectedDefinitionsHash,
        LEGACY_REGISTRY_SNAPSHOT_HASH,
        'legacy-unknown',
        'legacy-v1-compatibility',
        snapshotHash,
        scan.created_at
      )
    }
  }
}

export const DATABASE_MIGRATIONS: DatabaseMigration[] = [
  {
    id: '0001_agentgo_v1',
    sql: `
CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  authorization_reference TEXT NOT NULL,
  default_identity_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX targets_workspace_idx ON targets(workspace_id);
CREATE UNIQUE INDEX targets_workspace_base_url_uq ON targets(workspace_id, base_url);

CREATE TABLE target_scopes (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  allowed_origins TEXT NOT NULL,
  allowed_path_prefixes TEXT NOT NULL,
  denied_path_prefixes TEXT NOT NULL,
  allowed_ports TEXT NOT NULL,
  allowed_identity_ids TEXT NOT NULL,
  allow_active_probing INTEGER NOT NULL,
  allow_sensitive_probing INTEGER NOT NULL,
  allow_private_network_targets INTEGER NOT NULL,
  allow_loopback_targets INTEGER NOT NULL,
  max_requests_per_minute INTEGER NOT NULL,
  max_concurrency INTEGER NOT NULL,
  authorization_reference TEXT,
  valid_from INTEGER,
  valid_until INTEGER,
  snapshot_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX target_scopes_target_idx ON target_scopes(target_id);
CREATE UNIQUE INDEX target_scopes_hash_uq ON target_scopes(target_id, snapshot_hash);

CREATE TABLE identities (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  role TEXT NOT NULL,
  auth_type TEXT NOT NULL,
  header_name TEXT,
  credential_id TEXT,
  is_test_identity INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX identities_target_idx ON identities(target_id);
CREATE UNIQUE INDEX identities_target_label_uq ON identities(target_id, label);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id),
  status TEXT NOT NULL,
  phase TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0,
  budget_json TEXT NOT NULL,
  config_json TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  runtime_json TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  model_tokens INTEGER NOT NULL DEFAULT 0,
  estimated_cost_micros INTEGER NOT NULL DEFAULT 0,
  checkpoint_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  started_at INTEGER,
  completed_at INTEGER
);
CREATE INDEX scans_target_idx ON scans(target_id);
CREATE INDEX scans_status_idx ON scans(status);
CREATE INDEX scans_updated_idx ON scans(updated_at);

CREATE TABLE scan_identities (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  PRIMARY KEY (scan_id, identity_id)
);

CREATE TABLE scan_checkpoints (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  phase TEXT NOT NULL,
  state_json TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX scan_checkpoints_scan_idx ON scan_checkpoints(scan_id, created_at);

CREATE TABLE scan_events (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX scan_events_scan_idx ON scan_events(scan_id, created_at);

CREATE TABLE pages (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  title TEXT,
  depth INTEGER NOT NULL,
  discovered_from TEXT,
  state_hash TEXT,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX pages_scan_idx ON pages(scan_id);
CREATE UNIQUE INDEX pages_scan_url_uq ON pages(scan_id, url);

CREATE TABLE endpoints (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  page_id TEXT REFERENCES pages(id) ON DELETE SET NULL,
  method TEXT NOT NULL,
  url_template TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  content_type TEXT,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX endpoints_scan_idx ON endpoints(scan_id);
CREATE UNIQUE INDEX endpoints_scan_method_url_uq ON endpoints(scan_id, method, normalized_url);

CREATE TABLE parameters (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  location TEXT NOT NULL,
  data_type TEXT,
  required INTEGER NOT NULL,
  example_masked TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX parameters_endpoint_idx ON parameters(endpoint_id);
CREATE UNIQUE INDEX parameters_endpoint_name_location_uq ON parameters(endpoint_id, name, location);

CREATE TABLE interactions (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  endpoint_id TEXT REFERENCES endpoints(id) ON DELETE SET NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  policy_decision_id TEXT,
  request_ref TEXT NOT NULL,
  response_ref TEXT NOT NULL,
  request_summary_json TEXT NOT NULL,
  response_summary_json TEXT NOT NULL,
  status_code INTEGER,
  duration_ms INTEGER,
  state_before_hash TEXT,
  state_after_hash TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX interactions_scan_idx ON interactions(scan_id, created_at);

CREATE TABLE model_profiles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  agent_role TEXT NOT NULL,
  provider TEXT NOT NULL,
  base_url TEXT,
  model TEXT NOT NULL,
  credential_id TEXT,
  timeout_ms INTEGER NOT NULL,
  rpm_limit INTEGER NOT NULL,
  tpm_limit INTEGER NOT NULL,
  token_budget INTEGER NOT NULL,
  cost_budget_micros INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX model_profiles_role_idx ON model_profiles(agent_role);
CREATE UNIQUE INDEX model_profiles_name_uq ON model_profiles(name);

CREATE TABLE agent_runs (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  parent_run_id TEXT REFERENCES agent_runs(id) ON DELETE SET NULL,
  role TEXT NOT NULL,
  prompt_id TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  prompt_hash TEXT NOT NULL,
  model_profile_id TEXT NOT NULL,
  status TEXT NOT NULL,
  input_refs TEXT NOT NULL,
  output_refs TEXT NOT NULL,
  error TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX agent_runs_scan_idx ON agent_runs(scan_id, started_at);

CREATE TABLE model_invocations (
  id TEXT PRIMARY KEY,
  agent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL,
  estimated_cost_micros INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  redaction_status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX model_invocations_agent_run_idx ON model_invocations(agent_run_id);

CREATE TABLE probe_proposals (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  agent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  target_url TEXT NOT NULL,
  method TEXT NOT NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  probe_level TEXT NOT NULL,
  side_effect TEXT NOT NULL,
  summary TEXT NOT NULL,
  payload_summary TEXT,
  expected_evidence TEXT NOT NULL,
  requested_requests_per_minute INTEGER,
  requested_concurrency INTEGER,
  max_requests INTEGER NOT NULL,
  timeout_ms INTEGER NOT NULL,
  user_approved INTEGER NOT NULL,
  stop_conditions TEXT NOT NULL,
  cleanup_plan TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX probe_proposals_scan_idx ON probe_proposals(scan_id, created_at);

CREATE TABLE policy_decisions (
  id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL REFERENCES probe_proposals(id) ON DELETE CASCADE,
  scope_snapshot_id TEXT NOT NULL REFERENCES target_scopes(id),
  allowed INTEGER NOT NULL,
  requires_approval INTEGER NOT NULL,
  code TEXT NOT NULL,
  reasons TEXT NOT NULL,
  normalized_target TEXT,
  approved_by TEXT,
  approved_at INTEGER,
  valid_until INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX policy_decisions_proposal_idx ON policy_decisions(proposal_id);
CREATE INDEX policy_decisions_scope_idx ON policy_decisions(scope_snapshot_id);

CREATE TABLE tool_calls (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
  tool_name TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  argument_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  duration_ms INTEGER,
  output_ref TEXT,
  error TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX tool_calls_scan_idx ON tool_calls(scan_id, created_at);

CREATE TABLE signals (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  interaction_id TEXT REFERENCES interactions(id) ON DELETE SET NULL,
  family TEXT NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  parameter_id TEXT REFERENCES parameters(id) ON DELETE SET NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  hypothesis TEXT NOT NULL,
  observed_difference TEXT NOT NULL,
  confidence_hint INTEGER NOT NULL,
  evidence_refs TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX signals_scan_family_idx ON signals(scan_id, family);

CREATE TABLE confirmation_rules (
  id TEXT NOT NULL,
  version TEXT NOT NULL,
  family TEXT NOT NULL,
  rule_json TEXT NOT NULL,
  required_checks TEXT NOT NULL,
  source_refs TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (id, version)
);

CREATE TABLE validation_runs (
  id TEXT PRIMARY KEY,
  signal_id TEXT NOT NULL REFERENCES signals(id) ON DELETE CASCADE,
  confirmation_rule_id TEXT NOT NULL,
  confirmation_rule_version TEXT NOT NULL,
  probe_proposal_id TEXT NOT NULL REFERENCES probe_proposals(id),
  policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
  tool_call_id TEXT REFERENCES tool_calls(id) ON DELETE SET NULL,
  baseline_ref TEXT NOT NULL,
  test_ref TEXT NOT NULL,
  negative_control_ref TEXT,
  completed_checks TEXT NOT NULL,
  failed_checks TEXT NOT NULL,
  missing_checks TEXT NOT NULL,
  cleanup_status TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (confirmation_rule_id, confirmation_rule_version)
    REFERENCES confirmation_rules(id, version)
);
CREATE INDEX validation_runs_signal_idx ON validation_runs(signal_id);

CREATE TABLE evidence_items (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  interaction_id TEXT REFERENCES interactions(id) ON DELETE SET NULL,
  policy_decision_id TEXT REFERENCES policy_decisions(id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  file_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  source TEXT NOT NULL,
  created_by TEXT NOT NULL,
  capture_tool TEXT NOT NULL,
  capture_tool_version TEXT NOT NULL,
  derived_from TEXT REFERENCES evidence_items(id) ON DELETE SET NULL,
  redaction_state TEXT NOT NULL,
  integrity_status TEXT NOT NULL,
  retention_until INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX evidence_items_scan_idx ON evidence_items(scan_id, created_at);
CREATE UNIQUE INDEX evidence_items_scan_hash_uq ON evidence_items(scan_id, sha256, type);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  family TEXT NOT NULL,
  title TEXT NOT NULL,
  verdict TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER NOT NULL,
  endpoint_id TEXT REFERENCES endpoints(id) ON DELETE SET NULL,
  parameter_id TEXT REFERENCES parameters(id) ON DELETE SET NULL,
  identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL,
  affected_resource TEXT,
  cwe TEXT,
  owasp TEXT,
  confirmation_rule_id TEXT NOT NULL,
  confirmation_rule_version TEXT NOT NULL,
  reproducibility TEXT NOT NULL,
  remediation_json TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_verified_at INTEGER NOT NULL,
  FOREIGN KEY (confirmation_rule_id, confirmation_rule_version)
    REFERENCES confirmation_rules(id, version)
);
CREATE INDEX findings_scan_idx ON findings(scan_id);
CREATE INDEX findings_family_idx ON findings(family);
CREATE INDEX findings_verdict_idx ON findings(verdict);

CREATE TABLE finding_evidence (
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence_items(id) ON DELETE CASCADE,
  PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE knowledge_docs (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_url TEXT,
  author TEXT,
  license TEXT,
  trust_level TEXT NOT NULL,
  review_status TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  published_at INTEGER,
  ingested_at INTEGER NOT NULL
);

CREATE TABLE knowledge_chunks (
  id TEXT PRIMARY KEY,
  doc_id TEXT NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
  family TEXT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  tags TEXT NOT NULL,
  applicability TEXT NOT NULL,
  token_estimate INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX knowledge_chunks_doc_idx ON knowledge_chunks(doc_id);
CREATE INDEX knowledge_chunks_family_idx ON knowledge_chunks(family);

CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(
  title,
  content,
  tags,
  content='knowledge_chunks',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER knowledge_chunks_ai AFTER INSERT ON knowledge_chunks BEGIN
  INSERT INTO knowledge_chunks_fts(rowid, title, content, tags)
  VALUES (new.rowid, new.title, new.content, new.tags);
END;
CREATE TRIGGER knowledge_chunks_ad AFTER DELETE ON knowledge_chunks BEGIN
  INSERT INTO knowledge_chunks_fts(knowledge_chunks_fts, rowid, title, content, tags)
  VALUES ('delete', old.rowid, old.title, old.content, old.tags);
END;
CREATE TRIGGER knowledge_chunks_au AFTER UPDATE ON knowledge_chunks BEGIN
  INSERT INTO knowledge_chunks_fts(knowledge_chunks_fts, rowid, title, content, tags)
  VALUES ('delete', old.rowid, old.title, old.content, old.tags);
  INSERT INTO knowledge_chunks_fts(rowid, title, content, tags)
  VALUES (new.rowid, new.title, new.content, new.tags);
END;

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  format TEXT NOT NULL,
  file_path TEXT,
  sha256 TEXT NOT NULL,
  redacted INTEGER NOT NULL,
  content_ref TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX reports_scan_idx ON reports(scan_id, created_at);

CREATE TABLE app_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE benchmark_cases (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  target_version TEXT NOT NULL,
  family TEXT NOT NULL,
  expected_verdict TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  parameter TEXT,
  identity_plan_json TEXT NOT NULL,
  required_evidence TEXT NOT NULL,
  reset_procedure TEXT NOT NULL,
  forbidden_actions TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX benchmark_cases_family_idx ON benchmark_cases(family);

CREATE TABLE benchmark_runs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES benchmark_cases(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  expected_verdict TEXT NOT NULL,
  actual_verdict TEXT NOT NULL,
  metrics_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX benchmark_runs_case_idx ON benchmark_runs(case_id, created_at);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
  event TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_logs_workspace_idx ON audit_logs(workspace_id, created_at);
`
  },
  {
    id: '0002_identity_owned_resources',
    sql: `
ALTER TABLE identities ADD COLUMN owned_resource_ids TEXT NOT NULL DEFAULT '[]';
`
  },
  {
    id: '0003_mcp_servers_and_token_usage',
    sql: `
CREATE TABLE model_profile_usage_events (
  id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL REFERENCES model_profiles(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX model_profile_usage_profile_idx
  ON model_profile_usage_events(profile_id, created_at);

INSERT INTO model_profile_usage_events (
  id,
  profile_id,
  source,
  prompt_tokens,
  completion_tokens,
  created_at
)
SELECT
  model_invocations.id,
  agent_runs.model_profile_id,
  'agent-run',
  model_invocations.prompt_tokens,
  model_invocations.completion_tokens,
  model_invocations.created_at
FROM model_invocations
INNER JOIN agent_runs ON agent_runs.id = model_invocations.agent_run_id;

CREATE TABLE mcp_servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  transport TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  credential_id TEXT,
  config_json TEXT NOT NULL,
  allowed_agent_roles TEXT NOT NULL,
  risk_labels TEXT NOT NULL,
  status TEXT NOT NULL,
  discovery_json TEXT NOT NULL,
  last_tested_at INTEGER,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX mcp_servers_name_uq ON mcp_servers(name);
CREATE INDEX mcp_servers_status_idx ON mcp_servers(status, updated_at);
`
  },
  {
    id: '0004_knowledge_intelligence_ingestion',
    sql: `
CREATE TABLE knowledge_imports (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
  source_type TEXT NOT NULL,
  raw_content TEXT NOT NULL,
  raw_content_sha256 TEXT NOT NULL,
  vendor_hint TEXT,
  product_hint TEXT,
  instruction_flags TEXT NOT NULL,
  status TEXT NOT NULL,
  extractor_profile_id TEXT REFERENCES model_profiles(id) ON DELETE SET NULL,
  reviewer_profile_id TEXT REFERENCES model_profiles(id) ON DELETE SET NULL,
  review_issues TEXT NOT NULL,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX knowledge_imports_document_uq ON knowledge_imports(document_id);
CREATE INDEX knowledge_imports_status_idx ON knowledge_imports(status, updated_at);

CREATE TABLE knowledge_intelligence (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL REFERENCES knowledge_imports(id) ON DELETE CASCADE,
  schema_version TEXT NOT NULL,
  title TEXT NOT NULL,
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  vulnerability_type TEXT NOT NULL,
  family TEXT,
  identifiers_json TEXT NOT NULL,
  affected_versions TEXT NOT NULL,
  preconditions TEXT NOT NULL,
  affected_endpoints TEXT NOT NULL,
  signals TEXT NOT NULL,
  confirmation_rules TEXT NOT NULL,
  remediation TEXT NOT NULL,
  forbidden_actions TEXT NOT NULL,
  field_evidence TEXT NOT NULL,
  extraction_confidence INTEGER NOT NULL,
  published_chunk_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX knowledge_intelligence_import_uq ON knowledge_intelligence(import_id);
CREATE INDEX knowledge_intelligence_product_idx ON knowledge_intelligence(vendor, product);
CREATE INDEX knowledge_intelligence_family_idx ON knowledge_intelligence(family);

CREATE TABLE knowledge_agent_runs (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL REFERENCES knowledge_imports(id) ON DELETE CASCADE,
  parent_run_id TEXT REFERENCES knowledge_agent_runs(id) ON DELETE SET NULL,
  role TEXT NOT NULL,
  prompt_id TEXT NOT NULL,
  prompt_version TEXT NOT NULL,
  prompt_hash TEXT NOT NULL,
  model_profile_id TEXT NOT NULL REFERENCES model_profiles(id),
  provider TEXT,
  model TEXT,
  status TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  error TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX knowledge_agent_runs_import_idx
  ON knowledge_agent_runs(import_id, started_at);
`
  },
  {
    id: '0005_monotonic_scope_revisions',
    sql: `
ALTER TABLE target_scopes
  ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;

WITH ranked_scopes AS (
  SELECT
    rowid AS scope_rowid,
    ROW_NUMBER() OVER (
      PARTITION BY target_id
      ORDER BY created_at ASC, rowid ASC
    ) AS scope_revision
  FROM target_scopes
)
UPDATE target_scopes
SET revision = (
  SELECT ranked_scopes.scope_revision
  FROM ranked_scopes
  WHERE ranked_scopes.scope_rowid = target_scopes.rowid
);

CREATE UNIQUE INDEX target_scopes_target_revision_uq
  ON target_scopes(target_id, revision);

CREATE TRIGGER target_scopes_revision_insert_guard
BEFORE INSERT ON target_scopes
WHEN typeof(NEW.revision) <> 'integer' OR NEW.revision < 1
BEGIN
  SELECT RAISE(ABORT, 'target scope revision must be a positive integer');
END;

CREATE TRIGGER target_scopes_immutable_guard
BEFORE UPDATE ON target_scopes
BEGIN
  SELECT RAISE(ABORT, 'target scope snapshots are immutable');
END;

ALTER TABLE targets
  ADD COLUMN current_scope_id TEXT REFERENCES target_scopes(id);

UPDATE targets
SET current_scope_id = (
  SELECT target_scopes.id
  FROM target_scopes
  WHERE target_scopes.target_id = targets.id
  ORDER BY target_scopes.revision DESC
  LIMIT 1
);

CREATE INDEX targets_current_scope_idx ON targets(current_scope_id);

CREATE TRIGGER targets_current_scope_insert_guard
BEFORE INSERT ON targets
WHEN NEW.current_scope_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM target_scopes
    WHERE target_scopes.id = NEW.current_scope_id
      AND target_scopes.target_id = NEW.id
  )
BEGIN
  SELECT RAISE(ABORT, 'current scope must belong to target');
END;

CREATE TRIGGER targets_current_scope_update_guard
BEFORE UPDATE OF current_scope_id ON targets
WHEN NEW.current_scope_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM target_scopes
    WHERE target_scopes.id = NEW.current_scope_id
      AND target_scopes.target_id = NEW.id
  )
BEGIN
  SELECT RAISE(ABORT, 'current scope must belong to target');
END;

CREATE TRIGGER targets_current_scope_required_guard
BEFORE UPDATE OF current_scope_id ON targets
WHEN OLD.current_scope_id IS NOT NULL
  AND NEW.current_scope_id IS NULL
BEGIN
  SELECT RAISE(ABORT, 'current scope cannot be cleared');
END;
`
  },
  {
    id: '0006_unified_inventory_and_module_snapshots',
    sql: `
ALTER TABLE scans
  ADD COLUMN module_snapshots_sealed INTEGER NOT NULL DEFAULT 0
  CHECK (module_snapshots_sealed IN (0, 1));
ALTER TABLE endpoints
  ADD COLUMN canonical_route TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints
  ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'active';
DROP INDEX endpoints_scan_method_url_uq;

CREATE TABLE request_variants (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  content_type TEXT,
  body_shape_json TEXT NOT NULL CHECK (json_valid(body_shape_json)),
  codec TEXT NOT NULL CHECK (
    codec IN ('none', 'form', 'json', 'xml', 'multipart', 'graphql', 'raw')
  ),
  transport TEXT NOT NULL CHECK (
    transport IN (
      'standard-http', 'browser', 'controlled-oob-http',
      'controlled-oob-dns', 'websocket', 'sse', 'raw-http1', 'http2'
    )
  ),
  allowed_headers_json TEXT NOT NULL CHECK (json_valid(allowed_headers_json)),
  redacted_preview_json TEXT NOT NULL CHECK (json_valid(redacted_preview_json)),
  template_version TEXT NOT NULL,
  required_capability_ids_json TEXT NOT NULL CHECK (json_valid(required_capability_ids_json)),
  review_status TEXT NOT NULL CHECK (
    review_status IN ('unreviewed', 'reviewed', 'rejected')
  ),
  reviewed_by TEXT,
  reviewed_at INTEGER,
  execution_class TEXT NOT NULL CHECK (
    execution_class IN (
      'inventory-only', 'active-l1', 'active-l2', 'unsupported', 'forbidden'
    )
  ),
  lifecycle_status TEXT NOT NULL CHECK (
    lifecycle_status IN ('active', 'retired')
  ),
  retired_at INTEGER,
  structure_hash TEXT NOT NULL CHECK (
    length(structure_hash) = 64 AND structure_hash NOT GLOB '*[^0-9a-f]*'
  ),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (
    (review_status = 'unreviewed' AND reviewed_by IS NULL AND reviewed_at IS NULL)
      OR (review_status <> 'unreviewed' AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)
  ),
  CHECK (
    (lifecycle_status = 'active' AND retired_at IS NULL)
      OR (lifecycle_status = 'retired' AND retired_at IS NOT NULL)
  ),
  UNIQUE (endpoint_id, structure_hash)
);
CREATE INDEX request_variants_scan_idx ON request_variants(scan_id);
CREATE INDEX request_variants_endpoint_idx ON request_variants(endpoint_id);

CREATE TABLE request_variant_selectors (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  request_variant_id TEXT NOT NULL REFERENCES request_variants(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (
    kind IN (
      'query', 'path', 'header', 'cookie', 'form', 'json-pointer',
      'xml-path', 'multipart-part', 'graphql-variable', 'graphql-argument',
      'websocket-field'
    )
  ),
  selector_json TEXT NOT NULL CHECK (json_valid(selector_json)),
  structure_hash TEXT NOT NULL CHECK (
    length(structure_hash) = 64 AND structure_hash NOT GLOB '*[^0-9a-f]*'
  ),
  created_at INTEGER NOT NULL,
  UNIQUE (request_variant_id, structure_hash)
);
CREATE INDEX request_variant_selectors_scan_idx
  ON request_variant_selectors(scan_id);
CREATE INDEX request_variant_selectors_variant_idx
  ON request_variant_selectors(request_variant_id);

CREATE TABLE inventory_sources (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  request_variant_id TEXT NOT NULL REFERENCES request_variants(id) ON DELETE CASCADE,
  source_type TEXT NOT NULL,
  source_hash TEXT NOT NULL CHECK (
    length(source_hash) = 64 AND source_hash NOT GLOB '*[^0-9a-f]*'
  ),
  provenance_hash TEXT NOT NULL CHECK (
    length(provenance_hash) = 64 AND provenance_hash NOT GLOB '*[^0-9a-f]*'
  ),
  page_id TEXT REFERENCES pages(id) ON DELETE SET NULL,
  evidence_ref TEXT,
  initiator TEXT,
  confidence_ppm INTEGER NOT NULL CHECK (
    confidence_ppm BETWEEN 0 AND 1000000
  ),
  discovered_at INTEGER NOT NULL,
  review_status TEXT NOT NULL CHECK (
    review_status IN ('unreviewed', 'reviewed', 'rejected')
  ),
  created_at INTEGER NOT NULL,
  UNIQUE (scan_id, provenance_hash)
);
CREATE INDEX inventory_sources_scan_idx ON inventory_sources(scan_id);
CREATE INDEX inventory_sources_endpoint_idx ON inventory_sources(endpoint_id);
CREATE INDEX inventory_sources_variant_idx ON inventory_sources(request_variant_id);

CREATE TABLE scan_module_snapshots (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  family_id TEXT NOT NULL,
  module_id TEXT NOT NULL,
  module_version TEXT NOT NULL,
  definition_hash TEXT NOT NULL CHECK (
    length(definition_hash) = 64
      AND definition_hash NOT GLOB '*[^0-9a-f]*'
  ),
  technique_id TEXT NOT NULL,
  technique_version TEXT NOT NULL,
  strategy_refs_json TEXT NOT NULL CHECK (json_valid(strategy_refs_json)),
  confirmation_rule_refs_json TEXT NOT NULL CHECK (json_valid(confirmation_rule_refs_json)),
  evidence_profile_refs_json TEXT NOT NULL CHECK (json_valid(evidence_profile_refs_json)),
  remediation_refs_json TEXT NOT NULL CHECK (json_valid(remediation_refs_json)),
  required_capability_ids_json TEXT NOT NULL CHECK (json_valid(required_capability_ids_json)),
  capability_descriptors_json TEXT NOT NULL CHECK (json_valid(capability_descriptors_json)),
  capability_snapshot_hash TEXT NOT NULL CHECK (
    length(capability_snapshot_hash) = 64
      AND capability_snapshot_hash NOT GLOB '*[^0-9a-f]*'
  ),
  selected_capabilities_hash TEXT NOT NULL CHECK (
    length(selected_capabilities_hash) = 64
      AND selected_capabilities_hash NOT GLOB '*[^0-9a-f]*'
  ),
  selected_definitions_hash TEXT NOT NULL CHECK (
    length(selected_definitions_hash) = 64
      AND selected_definitions_hash NOT GLOB '*[^0-9a-f]*'
  ),
  registry_snapshot_hash TEXT NOT NULL CHECK (
    length(registry_snapshot_hash) = 64
      AND registry_snapshot_hash NOT GLOB '*[^0-9a-f]*'
  ),
  environment TEXT NOT NULL,
  authorization TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL CHECK (
    length(snapshot_hash) = 64 AND snapshot_hash NOT GLOB '*[^0-9a-f]*'
  ),
  created_at INTEGER NOT NULL,
  UNIQUE (scan_id, family_id, technique_id)
);
CREATE INDEX scan_module_snapshots_scan_idx ON scan_module_snapshots(scan_id);
`,
    dataHook: migrateDay3Inventory,
    finalizeSql: `
UPDATE scans SET module_snapshots_sealed = 1;

CREATE UNIQUE INDEX endpoints_scan_method_route_uq
  ON endpoints(scan_id, method, canonical_route);

CREATE TRIGGER pages_scan_immutable_guard
BEFORE UPDATE OF scan_id ON pages
WHEN NEW.scan_id <> OLD.scan_id
BEGIN
  SELECT RAISE(ABORT, 'page scan binding is immutable');
END;

CREATE TRIGGER endpoints_scan_immutable_guard
BEFORE UPDATE OF scan_id ON endpoints
WHEN NEW.scan_id <> OLD.scan_id
BEGIN
  SELECT RAISE(ABORT, 'endpoint scan binding is immutable');
END;

CREATE TRIGGER endpoints_method_insert_guard
BEFORE INSERT ON endpoints
WHEN trim(NEW.method) = '' OR NEW.method <> upper(trim(NEW.method))
BEGIN
  SELECT RAISE(ABORT, 'endpoint method must be canonical uppercase');
END;

CREATE TRIGGER endpoints_method_update_guard
BEFORE UPDATE OF method ON endpoints
WHEN trim(NEW.method) = '' OR NEW.method <> upper(trim(NEW.method))
BEGIN
  SELECT RAISE(ABORT, 'endpoint method must be canonical uppercase');
END;

CREATE TRIGGER endpoints_canonical_route_insert_guard
BEFORE INSERT ON endpoints
WHEN NEW.canonical_route IS NULL
  OR trim(NEW.canonical_route) = ''
  OR instr(NEW.canonical_route, '?') > 0
  OR instr(NEW.canonical_route, '#') > 0
BEGIN
  SELECT RAISE(ABORT, 'endpoint canonical route must be a query-free origin and path');
END;

CREATE TRIGGER endpoints_canonical_route_update_guard
BEFORE UPDATE OF canonical_route ON endpoints
WHEN NEW.canonical_route IS NULL
  OR trim(NEW.canonical_route) = ''
  OR instr(NEW.canonical_route, '?') > 0
  OR instr(NEW.canonical_route, '#') > 0
BEGIN
  SELECT RAISE(ABORT, 'endpoint canonical route must be a query-free origin and path');
END;

CREATE TRIGGER endpoints_lifecycle_insert_guard
BEFORE INSERT ON endpoints
WHEN NEW.lifecycle_status NOT IN ('active', 'retired')
BEGIN
  SELECT RAISE(ABORT, 'endpoint lifecycle status is invalid');
END;

CREATE TRIGGER endpoints_lifecycle_update_guard
BEFORE UPDATE OF lifecycle_status ON endpoints
WHEN NEW.lifecycle_status NOT IN ('active', 'retired')
BEGIN
  SELECT RAISE(ABORT, 'endpoint lifecycle status is invalid');
END;

CREATE TRIGGER endpoints_page_scan_insert_guard
BEFORE INSERT ON endpoints
WHEN NEW.page_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM pages
    WHERE pages.id = NEW.page_id
      AND pages.scan_id = NEW.scan_id
  )
BEGIN
  SELECT RAISE(ABORT, 'endpoint page must belong to scan');
END;

CREATE TRIGGER endpoints_page_scan_update_guard
BEFORE UPDATE OF scan_id, page_id ON endpoints
WHEN NEW.page_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM pages
    WHERE pages.id = NEW.page_id
      AND pages.scan_id = NEW.scan_id
  )
BEGIN
  SELECT RAISE(ABORT, 'endpoint page must belong to scan');
END;

CREATE TRIGGER request_variants_scan_insert_guard
BEFORE INSERT ON request_variants
WHEN NOT EXISTS (
  SELECT 1 FROM endpoints
  WHERE endpoints.id = NEW.endpoint_id
    AND endpoints.scan_id = NEW.scan_id
)
BEGIN
  SELECT RAISE(ABORT, 'request variant endpoint must belong to scan');
END;

CREATE TRIGGER request_variants_scan_update_guard
BEFORE UPDATE OF scan_id, endpoint_id ON request_variants
WHEN NOT EXISTS (
  SELECT 1 FROM endpoints
  WHERE endpoints.id = NEW.endpoint_id
    AND endpoints.scan_id = NEW.scan_id
)
BEGIN
  SELECT RAISE(ABORT, 'request variant endpoint must belong to scan');
END;

CREATE TRIGGER request_variants_binding_immutable_guard
BEFORE UPDATE OF scan_id, endpoint_id ON request_variants
WHEN NEW.scan_id <> OLD.scan_id OR NEW.endpoint_id <> OLD.endpoint_id
BEGIN
  SELECT RAISE(ABORT, 'request variant scan and endpoint binding is immutable');
END;

CREATE TRIGGER request_variant_selectors_scan_insert_guard
BEFORE INSERT ON request_variant_selectors
WHEN NOT EXISTS (
  SELECT 1 FROM request_variants
  WHERE request_variants.id = NEW.request_variant_id
    AND request_variants.scan_id = NEW.scan_id
)
BEGIN
  SELECT RAISE(ABORT, 'request selector variant must belong to scan');
END;

CREATE TRIGGER request_variant_selectors_scan_update_guard
BEFORE UPDATE OF scan_id, request_variant_id ON request_variant_selectors
WHEN NOT EXISTS (
  SELECT 1 FROM request_variants
  WHERE request_variants.id = NEW.request_variant_id
    AND request_variants.scan_id = NEW.scan_id
)
BEGIN
  SELECT RAISE(ABORT, 'request selector variant must belong to scan');
END;

CREATE TRIGGER request_variant_selectors_binding_immutable_guard
BEFORE UPDATE OF scan_id, request_variant_id ON request_variant_selectors
WHEN NEW.scan_id <> OLD.scan_id
  OR NEW.request_variant_id <> OLD.request_variant_id
BEGIN
  SELECT RAISE(ABORT, 'request selector scan and variant binding is immutable');
END;

CREATE TRIGGER inventory_sources_scan_insert_guard
BEFORE INSERT ON inventory_sources
WHEN NOT EXISTS (
    SELECT 1 FROM endpoints
    WHERE endpoints.id = NEW.endpoint_id
      AND endpoints.scan_id = NEW.scan_id
  )
  OR NOT EXISTS (
    SELECT 1 FROM request_variants
    WHERE request_variants.id = NEW.request_variant_id
      AND request_variants.endpoint_id = NEW.endpoint_id
      AND request_variants.scan_id = NEW.scan_id
  )
  OR (
    NEW.page_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM pages
      WHERE pages.id = NEW.page_id
        AND pages.scan_id = NEW.scan_id
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'inventory source references must belong to one scan');
END;

CREATE TRIGGER inventory_sources_scan_update_guard
BEFORE UPDATE OF scan_id, endpoint_id, request_variant_id, page_id ON inventory_sources
WHEN NOT EXISTS (
    SELECT 1 FROM endpoints
    WHERE endpoints.id = NEW.endpoint_id
      AND endpoints.scan_id = NEW.scan_id
  )
  OR NOT EXISTS (
    SELECT 1 FROM request_variants
    WHERE request_variants.id = NEW.request_variant_id
      AND request_variants.endpoint_id = NEW.endpoint_id
      AND request_variants.scan_id = NEW.scan_id
  )
  OR (
    NEW.page_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM pages
      WHERE pages.id = NEW.page_id
        AND pages.scan_id = NEW.scan_id
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'inventory source references must belong to one scan');
END;

CREATE TRIGGER scan_module_snapshots_immutable_update_guard
BEFORE UPDATE ON scan_module_snapshots
BEGIN
  SELECT RAISE(ABORT, 'scan module snapshots are immutable');
END;

CREATE TRIGGER scan_module_snapshots_sealed_insert_guard
BEFORE INSERT ON scan_module_snapshots
WHEN COALESCE((
  SELECT scans.module_snapshots_sealed
  FROM scans
  WHERE scans.id = NEW.scan_id
), 1) <> 0
BEGIN
  SELECT RAISE(ABORT, 'scan module snapshot set is sealed');
END;

CREATE TRIGGER scans_module_snapshots_seal_guard
BEFORE UPDATE OF module_snapshots_sealed ON scans
WHEN OLD.module_snapshots_sealed = 1 AND NEW.module_snapshots_sealed <> 1
BEGIN
  SELECT RAISE(ABORT, 'scan module snapshot seal is immutable');
END;

CREATE TRIGGER scans_unsealed_execution_insert_guard
BEFORE INSERT ON scans
WHEN NEW.status IN ('queued', 'running')
  AND NEW.module_snapshots_sealed <> 1
BEGIN
  SELECT RAISE(ABORT, 'scan module snapshot set must be sealed before execution');
END;

CREATE TRIGGER scans_unsealed_execution_update_guard
BEFORE UPDATE OF status ON scans
WHEN NEW.status IN ('queued', 'running')
  AND NEW.module_snapshots_sealed <> 1
BEGIN
  SELECT RAISE(ABORT, 'scan module snapshot set must be sealed before execution');
END;

CREATE TRIGGER scan_module_snapshots_immutable_delete_guard
BEFORE DELETE ON scan_module_snapshots
WHEN EXISTS (
  SELECT 1 FROM scans WHERE scans.id = OLD.scan_id
)
BEGIN
  SELECT RAISE(ABORT, 'scan module snapshots are immutable');
END;
`
  },
  DAY5_EXECUTION_MIGRATION,
  DAY5_EXECUTION_RECOVERY_HARDENING_MIGRATION,
  DAY5_EXECUTION_DISPATCH_HARDENING_MIGRATION,
  DAY4_PROTECTED_EVIDENCE_MIGRATION
]
