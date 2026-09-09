import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import {
  ProbeActionSchema,
  TargetScopeSchema,
  type PolicyDecision,
  type ProbeAction,
  type ScopeNetworkEntry,
  type TargetScope
} from '@agentgo/contracts'
import { canonicalizeTargetUrl } from './canonicalize-url'

export {
  canonicalizeTargetUrl,
  type CanonicalTargetUrl,
  type CanonicalTargetUrlResult
} from './canonicalize-url'

export {
  BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS,
  DEFAULT_PROBE_CAPABILITY_CATALOG,
  ProbeCapabilityCatalog,
  isProbeCapabilityId,
  type ProbeCapabilityCatalogSnapshot,
  type ProbeCapabilityDescriptor,
  type ProbeCapabilityRiskFloor
} from './probe-capability-catalog'

export const NETWORK_ENTRY_PURPOSE_EXECUTION = 'execution'
export const NETWORK_ENTRY_PURPOSE_SSRF_TARGET = 'ssrf-target'

export type NetworkAuthorizationPurpose =
  | typeof NETWORK_ENTRY_PURPOSE_EXECUTION
  | typeof NETWORK_ENTRY_PURPOSE_SSRF_TARGET

const destructiveIndicators = [
  /\b(?:drop|truncate|alter)\s+(?:database|schema|table)\b/i,
  /\bdelete\s+from\b/i,
  /\bupdate\s+[\w.[\]"]+\s+set\b/i,
  /\binsert\s+into\b/i,
  /\bunion\b[\s\S]*\bselect\b/i,
  /;\s*(?:select|drop|truncate|alter|insert|update|delete|create|grant|exec|execute|waitfor|copy|load)\b/i,
  /\b(?:load_file|into\s+(?:out|dump)file)\b/i,
  /\bcopy\s+[\s\S]*\bfrom\b/i,
  /\bshutdown\b/i,
  /\bxp_cmdshell\b/i,
  /\brm\s+-rf\b/i,
  /\bremove-item\b.*\b-recurse\b/i,
  /\b(?:mkfs|format\s+[a-z]:|del\s+\/s)\b/i,
  /\b(?:webshell|reverse shell|credential spray|password spray)\b/i
]

const ACTIVE_SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const L2_HTTP_METHODS = new Set(['POST', 'PUT', 'PATCH'])
const PERMANENTLY_BLOCKED_HTTP_METHODS = new Set(['DELETE', 'TRACE', 'CONNECT'])

function deny(
  code: PolicyDecision['code'],
  reason: string,
  normalizedTarget?: string,
  requiresApproval = false
): PolicyDecision {
  return {
    allowed: false,
    requiresApproval,
    code,
    reasons: [reason],
    ...(normalizedTarget ? { normalizedTarget } : {})
  }
}

function matchesOrigin(target: URL, pattern: string): boolean {
  const wildcard = pattern.match(/^([a-z][a-z0-9+.-]*):\/\/\*\.([^/:]+)(?::(\d+))?$/i)

  if (wildcard) {
    const [, protocol, baseHost, port] = wildcard
    const targetPort = target.port || (target.protocol === 'https:' ? '443' : '80')
    const expectedPort = port || (protocol?.toLowerCase() === 'https' ? '443' : '80')
    const hostname = target.hostname.toLowerCase()
    const normalizedBase = baseHost?.toLowerCase()

    return Boolean(
      protocol &&
        normalizedBase &&
        target.protocol === `${protocol.toLowerCase()}:` &&
        hostname.endsWith(`.${normalizedBase}`) &&
        hostname !== normalizedBase &&
        targetPort === expectedPort
    )
  }

  try {
    const allowed = new URL(pattern)
    return target.origin === allowed.origin
  } catch {
    return false
  }
}

export type UrlScopeVerdict =
  | { readonly ok: true; readonly href: string }
  | {
      readonly ok: false
      readonly reason: 'unresolved' | 'out-of-scope' | 'canonicalization-failed'
    }

/**
 * Offline origin/path/port Scope check. Does not perform DNS or HTTP.
 * Relative URLs require an absolute base; otherwise they stay unresolved.
 */
export function evaluateUrlScope(
  url: string,
  scope: TargetScope,
  baseUrl?: string
): UrlScopeVerdict {
  let absolute = url.trim()
  if (!/^[a-z][a-z0-9+.-]*:/iu.test(absolute)) {
    if (!baseUrl) return { ok: false, reason: 'unresolved' }
    try {
      absolute = new URL(absolute, baseUrl).href
    } catch {
      return { ok: false, reason: 'unresolved' }
    }
  }
  const canonical = canonicalizeTargetUrl(absolute)
  if (!canonical.ok) {
    return { ok: false, reason: 'canonicalization-failed' }
  }
  if (!isInScope(canonical.value.url, scope)) {
    return { ok: false, reason: 'out-of-scope' }
  }
  return { ok: true, href: canonical.value.href }
}

function isInScope(target: URL, scope: TargetScope): boolean {
  const originAllowed = scope.allowedOrigins.some((origin) => matchesOrigin(target, origin))
  const pathAllowed = scope.allowedPathPrefixes.some((prefix) => {
    if (prefix === '/') {
      return true
    }

    const normalizedPrefix = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix
    return (
      target.pathname === normalizedPrefix ||
      target.pathname.startsWith(`${normalizedPrefix}/`)
    )
  })

  const pathDenied = scope.deniedPathPrefixes.some((prefix) => {
    const normalizedPrefix = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix
    return (
      target.pathname === normalizedPrefix ||
      target.pathname.startsWith(`${normalizedPrefix}/`)
    )
  })

  const effectivePort = Number(
    target.port || (target.protocol === 'https:' ? '443' : '80')
  )
  const portAllowed =
    scope.allowedPorts.length === 0 || scope.allowedPorts.includes(effectivePort)

  return originAllowed && pathAllowed && !pathDenied && portAllowed
}

function containsDestructiveContent(action: ProbeAction): boolean {
  const candidate = [action.summary, action.payloadSummary ?? ''].join('\n')
  return destructiveIndicators.some((indicator) => indicator.test(candidate))
}

/**
 * Backend-only trust signal for L2. `ProbeAction.userApproved` is never an
 * authorization input. Only Application composition (ApprovalService /
 * integrity-bound Grant) may set this.
 */
export interface ProbeEvaluationTrust {
  readonly backendTrustedApproval?: boolean
}

export function evaluateProbe(
  actionInput: unknown,
  scopeInput: unknown,
  trust?: ProbeEvaluationTrust
): PolicyDecision {
  const actionResult = ProbeActionSchema.safeParse(actionInput)
  if (!actionResult.success) {
    return deny('invalid-target', '动作结构或目标 URL 无效。')
  }

  const scopeResult = TargetScopeSchema.safeParse(scopeInput)
  if (!scopeResult.success) {
    return deny('out-of-scope', '授权范围配置无效。')
  }

  const action: ProbeAction = actionResult.data
  const scope: TargetScope = scopeResult.data

  const canonical = canonicalizeTargetUrl(action.targetUrl)
  if (!canonical.ok) {
    return deny('url-canonicalization-failed', canonical.reason)
  }

  const target = canonical.value.url
  const normalizedTarget = canonical.value.href

  if (scope.validFrom && Date.parse(scope.validFrom) > Date.now()) {
    return deny('scope-not-yet-valid', '授权范围尚未生效。', normalizedTarget)
  }

  if (scope.validUntil && Date.parse(scope.validUntil) <= Date.now()) {
    return deny('scope-expired', '授权范围已过期。', normalizedTarget)
  }

  if (!isInScope(target, scope)) {
    return deny(
      'out-of-scope',
      '目标 origin、port 或 path 不在授权范围内，或命中明确排除路径。',
      normalizedTarget
    )
  }

  if (action.scopeSnapshotId && action.scopeSnapshotId !== scope.id) {
    return deny('out-of-scope', '动作引用的 scope 快照与当前快照不一致。', normalizedTarget)
  }

  if (
    action.identityId &&
    !scope.allowedIdentityIds.includes(action.identityId)
  ) {
    return deny('identity-out-of-scope', '当前测试身份未包含在授权范围内。', normalizedTarget)
  }

  if (
    action.requestedRequestsPerMinute &&
    action.requestedRequestsPerMinute > scope.maxRequestsPerMinute
  ) {
    return deny('rate-limit-exceeded', '请求速率超过授权预算。', normalizedTarget)
  }

  if (action.requestedConcurrency && action.requestedConcurrency > scope.maxConcurrency) {
    return deny('concurrency-limit-exceeded', '请求并发超过授权预算。', normalizedTarget)
  }

  const method = action.method.toUpperCase()

  if (PERMANENTLY_BLOCKED_HTTP_METHODS.has(method)) {
    return deny(
      'http-method-blocked',
      `HTTP ${method} 在默认策略中永久禁止。`,
      normalizedTarget
    )
  }

  if (!ACTIVE_SAFE_HTTP_METHODS.has(method) && !L2_HTTP_METHODS.has(method)) {
    return deny(
      'http-method-blocked',
      `HTTP ${method} 没有经审查的执行语义，已失败关闭。`,
      normalizedTarget
    )
  }

  if (
    action.probeLevel === 'destructive' ||
    action.sideEffect === 'destructive' ||
    containsDestructiveContent(action)
  ) {
    return deny('destructive-action', '检测到破坏性或数据写入动作。', normalizedTarget)
  }

  if (action.sideEffect === 'unknown') {
    return deny('unknown-side-effect', '副作用未知，不能自动执行。', normalizedTarget)
  }

  if (
    action.sideEffect === 'reversible' &&
    action.probeLevel !== 'active-sensitive'
  ) {
    return deny(
      'mutating-method-requires-l2',
      '声明了可回退副作用的动作必须进入 L2 审批流程。',
      normalizedTarget,
      true
    )
  }

  // V1 automatic validation is limited to the reviewed GET/HEAD/OPTIONS
  // allowlist. Known mutating methods require L2; unknown methods were rejected
  // above because the policy has no reviewed semantics for them.
  if (
    L2_HTTP_METHODS.has(method) &&
    action.probeLevel !== 'active-sensitive'
  ) {
    return deny(
      'mutating-method-requires-l2',
      '可能改变状态的方法必须声明为 L2 敏感探测。',
      normalizedTarget,
      true
    )
  }

  if (action.probeLevel === 'active-safe' && !scope.allowActiveProbing) {
    return deny('active-probing-disabled', '当前 scope 未启用主动探测。', normalizedTarget)
  }

  if (action.probeLevel === 'active-sensitive') {
    if (!scope.allowSensitiveProbing) {
      return deny(
        'sensitive-probing-disabled',
        '当前 scope 未启用 L2 敏感探测。',
        normalizedTarget
      )
    }

    const ignoredUserApproved = action.userApproved === true
    if (trust?.backendTrustedApproval !== true) {
      return deny(
        'approval-required',
        ignoredUserApproved
          ? 'L2 敏感探测需要可信批准记录；userApproved 布尔字段已被忽略，不能授权执行。'
          : 'L2 敏感探测需要逐次人工批准。',
        normalizedTarget,
        true
      )
    }

    if (action.sideEffect !== 'reversible' || !action.cleanupPlan) {
      return deny(
        'approval-required',
        'L2 动作必须声明可回退副作用和清理方案。',
        normalizedTarget,
        true
      )
    }
  }

  return {
    allowed: true,
    requiresApproval: false,
    code: 'allowed',
    reasons: [
      '动作位于授权范围内，且符合当前主动探测等级。',
      ...(action.probeLevel === 'active-sensitive' && action.userApproved
        ? [
            'legacy userApproved boolean was ignored and is not an authorization signal.'
          ]
        : [])
    ],
    normalizedTarget
  }
}

export type NetworkAddressClass =
  | 'public'
  | 'private'
  | 'loopback'
  | 'link-local'
  | 'metadata'
  | 'unspecified'
  | 'multicast'
  | 'reserved'
  | 'invalid'

function classifyIpv4(address: string): NetworkAddressClass {
  const parts = address.split('.').map(Number)
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return 'invalid'
  }
  const [a = 0, b = 0, c = 0, d = 0] = parts

  if (
    (a === 169 && b === 254 && c === 169 && d === 254) ||
    (a === 100 && b === 100 && c === 100 && d === 200)
  ) {
    return 'metadata'
  }
  if (a === 127) return 'loopback'
  if (a === 169 && b === 254) return 'link-local'
  if (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  ) {
    return 'private'
  }
  if (a === 0) return 'unspecified'
  if (a >= 224 && a <= 239) return 'multicast'
  if (
    a >= 240 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  ) {
    return 'reserved'
  }
  return 'public'
}

function parseIpv6Section(section: string): number[] | undefined {
  if (!section) return []

  const words: number[] = []
  for (const token of section.split(':')) {
    if (token.includes('.')) {
      const octets = token.split('.').map(Number)
      if (
        octets.length !== 4 ||
        octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
      ) {
        return undefined
      }
      words.push((octets[0]! << 8) | octets[1]!, (octets[2]! << 8) | octets[3]!)
      continue
    }

    if (!/^[0-9a-f]{1,4}$/i.test(token)) return undefined
    words.push(Number.parseInt(token, 16))
  }
  return words
}

function expandIpv6(address: string): number[] | undefined {
  const sections = address.split('::')
  if (sections.length > 2) return undefined

  const head = parseIpv6Section(sections[0] ?? '')
  const tail = parseIpv6Section(sections[1] ?? '')
  if (!head || !tail) return undefined

  if (sections.length === 1) {
    return head.length === 8 ? head : undefined
  }

  const omittedWordCount = 8 - head.length - tail.length
  if (omittedWordCount < 1) return undefined
  return [...head, ...Array<number>(omittedWordCount).fill(0), ...tail]
}

function extractMappedIpv4Address(address: string): string | undefined {
  const words = expandIpv6(address)
  if (
    !words ||
    words.length !== 8 ||
    words.slice(0, 5).some((word) => word !== 0) ||
    words[5] !== 0xffff
  ) {
    return undefined
  }

  const high = words[6]!
  const low = words[7]!
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`
}

export function classifyNetworkAddress(address: string): NetworkAddressClass {
  const version = isIP(address)
  if (version === 4) return classifyIpv4(address)
  if (version !== 6) return 'invalid'

  const normalized = address.toLowerCase().split('%')[0] ?? address.toLowerCase()
  const words = expandIpv6(normalized)
  if (
    words &&
    words.length === 8 &&
    words.slice(0, 7).every((word) => word === 0) &&
    words[7] === 1
  ) {
    return 'loopback'
  }
  if (
    words &&
    words.length === 8 &&
    words.every((word) => word === 0)
  ) {
    return 'unspecified'
  }
  const mappedIpv4Address = extractMappedIpv4Address(normalized)
  if (mappedIpv4Address) return classifyIpv4(mappedIpv4Address)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return 'private'
  if (/^fe[89ab]/.test(normalized)) return 'link-local'
  if (normalized.startsWith('ff')) return 'multicast'
  if (normalized.startsWith('2001:db8:')) return 'reserved'
  return 'public'
}

const PERMANENTLY_DENIED_ADDRESS_CLASSES = new Set<NetworkAddressClass>([
  'metadata',
  'invalid',
  'unspecified',
  'multicast'
])

const ENTRY_GATED_ADDRESS_CLASSES = new Set<NetworkAddressClass>([
  'private',
  'loopback',
  'link-local',
  'reserved'
])

export interface ResolvedAddressAuthorizationInput {
  readonly hostname: string
  readonly port: number
  readonly addresses: readonly string[]
}

function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '')
}

function ipv4ToInt(address: string): number | undefined {
  const parts = address.split('.').map(Number)
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return undefined
  }
  const [a = 0, b = 0, c = 0, d = 0] = parts
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0
}

function ipEquals(left: string, right: string): boolean {
  const leftVersion = isIP(left)
  const rightVersion = isIP(right)
  if (leftVersion === 0 || leftVersion !== rightVersion) return false
  if (leftVersion === 4) return ipv4ToInt(left) === ipv4ToInt(right)
  const leftWords = expandIpv6(left.toLowerCase().split('%')[0] ?? left)
  const rightWords = expandIpv6(right.toLowerCase().split('%')[0] ?? right)
  return Boolean(
    leftWords &&
      rightWords &&
      leftWords.length === 8 &&
      rightWords.length === 8 &&
      leftWords.every((word, index) => word === rightWords[index])
  )
}

function ipInCidr(address: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split('/')
  const bits = Number(bitsRaw)
  if (!base || !Number.isInteger(bits) || bits < 0) return false
  if (isIP(base) === 4 && isIP(address) === 4) {
    if (bits > 32) return false
    const addressInt = ipv4ToInt(address)
    const baseInt = ipv4ToInt(base)
    if (addressInt === undefined || baseInt === undefined) return false
    if (bits === 0) return true
    const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0
    return (addressInt & mask) === (baseInt & mask)
  }
  if (isIP(base) === 6 && isIP(address) === 6) {
    if (bits > 128) return false
    const addressWords = expandIpv6(
      address.toLowerCase().split('%')[0] ?? address
    )
    const baseWords = expandIpv6(base.toLowerCase().split('%')[0] ?? base)
    if (!addressWords || !baseWords) return false
    if (bits === 0) return true
    let remaining = bits
    for (let index = 0; index < 8; index += 1) {
      const take = Math.min(16, remaining)
      if (take === 0) return true
      const mask = (0xffff << (16 - take)) & 0xffff
      if ((addressWords[index]! & mask) !== (baseWords[index]! & mask)) {
        return false
      }
      remaining -= take
    }
    return true
  }
  return false
}

function entryMatchesHop(
  entry: ScopeNetworkEntry,
  hostname: string,
  port: number,
  address: string,
  classification: NetworkAddressClass
): boolean {
  if (entry.addressClass !== classification) return false
  if (!entry.ports.includes(port)) return false
  const normalizedHost = normalizeHostname(hostname)
  if (entry.host && normalizeHostname(entry.host) !== normalizedHost) {
    return false
  }
  if (entry.ip && !ipEquals(entry.ip, address)) {
    return false
  }
  if (entry.cidr && !ipInCidr(address, entry.cidr)) {
    return false
  }
  return Boolean(entry.host || entry.ip || entry.cidr)
}

function evaluateAddressesForPurpose(
  input: ResolvedAddressAuthorizationInput,
  scopeInput: unknown,
  purpose: NetworkAuthorizationPurpose
): PolicyDecision {
  const scopeResult = TargetScopeSchema.safeParse(scopeInput)
  if (!scopeResult.success) {
    return deny('out-of-scope', '授权范围配置无效。')
  }
  if (
    typeof input.hostname !== 'string' ||
    input.hostname.trim() === '' ||
    !Number.isInteger(input.port) ||
    input.port < 1 ||
    input.port > 65_535 ||
    !Array.isArray(input.addresses) ||
    input.addresses.length === 0
  ) {
    return deny('invalid-target', '目标主机未解析到可验证地址。')
  }

  const scope = scopeResult.data
  const hostname = normalizeHostname(input.hostname)
  for (const address of input.addresses) {
    const classification = classifyNetworkAddress(address)
    if (classification === 'metadata') {
      return deny(
        'network-address-blocked',
        `地址 ${address} 属于云元数据端点，永久禁止访问。`
      )
    }
    if (PERMANENTLY_DENIED_ADDRESS_CLASSES.has(classification)) {
      return deny(
        'network-address-blocked',
        `地址 ${address} 的网络类别为 ${classification}，默认永久禁止访问。`
      )
    }
    if (classification === 'public') {
      continue
    }
    if (!ENTRY_GATED_ADDRESS_CLASSES.has(classification)) {
      return deny(
        'network-address-blocked',
        `地址 ${address} 的网络类别为 ${classification}，默认永久禁止访问。`
      )
    }
    const authorized = scope.networkEntries.some(
      (entry) =>
        entry.purpose === purpose &&
        entryMatchesHop(entry, hostname, input.port, address, classification)
    )
    if (!authorized) {
      return deny(
        'network-target-not-authorized',
        `地址 ${address} 的网络类别为 ${classification}，当前 scope 未列出精确的 host/IP/CIDR、端口与用途授权。`
      )
    }
  }

  return {
    allowed: true,
    requiresApproval: false,
    code: 'allowed',
    reasons: ['目标解析地址符合当前 scope 的网络边界。']
  }
}

export function evaluateExecutionAddresses(
  input: ResolvedAddressAuthorizationInput,
  scopeInput: unknown
): PolicyDecision {
  return evaluateAddressesForPurpose(
    input,
    scopeInput,
    NETWORK_ENTRY_PURPOSE_EXECUTION
  )
}

export function evaluateSsrfTargetAddresses(
  input: ResolvedAddressAuthorizationInput,
  scopeInput: unknown
): PolicyDecision {
  return evaluateAddressesForPurpose(
    input,
    scopeInput,
    NETWORK_ENTRY_PURPOSE_SSRF_TARGET
  )
}

export function evaluateResolvedAddresses(
  addresses: string[],
  scopeInput: unknown,
  context?: { hostname: string; port: number }
): PolicyDecision {
  if (!context) {
    const scopeResult = TargetScopeSchema.safeParse(scopeInput)
    if (!scopeResult.success) {
      return deny('out-of-scope', '授权范围配置无效。')
    }
    if (addresses.length === 0) {
      return deny('invalid-target', '目标主机未解析到可验证地址。')
    }
    for (const address of addresses) {
      const classification = classifyNetworkAddress(address)
      if (classification !== 'public') {
        return deny(
          classification === 'metadata' ||
            PERMANENTLY_DENIED_ADDRESS_CLASSES.has(classification)
            ? 'network-address-blocked'
            : 'network-target-not-authorized',
          `地址 ${address} 的网络类别为 ${classification}，缺少精确网络条目授权。`
        )
      }
    }
    return {
      allowed: true,
      requiresApproval: false,
      code: 'allowed',
      reasons: ['目标解析地址符合当前 scope 的网络边界。']
    }
  }
  return evaluateExecutionAddresses(
    {
      hostname: context.hostname,
      port: context.port,
      addresses
    },
    scopeInput
  )
}

function networkEntryId(entry: Omit<ScopeNetworkEntry, 'id'>): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        addressClass: entry.addressClass,
        host: entry.host ?? null,
        ip: entry.ip ?? null,
        cidr: entry.cidr ?? null,
        ports: [...entry.ports].sort((left, right) => left - right),
        purpose: entry.purpose
      })
    )
    .digest('hex')
    .slice(0, 32)
}

const DERIVED_NETWORK_ENTRY_PURPOSES = [
  NETWORK_ENTRY_PURPOSE_EXECUTION,
  NETWORK_ENTRY_PURPOSE_SSRF_TARGET
] as const

function rememberDerivedEntry(
  derived: Map<string, ScopeNetworkEntry>,
  entry: Omit<ScopeNetworkEntry, 'id'>
): void {
  const id = networkEntryId(entry)
  derived.set(id, { id, ...entry })
}

export function deriveScopeNetworkEntriesFromOrigins(
  origins: readonly string[]
): ScopeNetworkEntry[] {
  const derived = new Map<string, ScopeNetworkEntry>()
  for (const origin of origins) {
    let url: URL
    try {
      url = new URL(origin)
    } catch {
      continue
    }
    const port = Number(
      url.port || (url.protocol === 'https:' ? '443' : '80')
    )
    if (!Number.isInteger(port) || port < 1 || port > 65_535) continue
    const host = normalizeHostname(url.hostname)
    if (host === 'localhost' || host.endsWith('.localhost')) {
      for (const purpose of DERIVED_NETWORK_ENTRY_PURPOSES) {
        rememberDerivedEntry(derived, {
          addressClass: 'loopback',
          host,
          ports: [port],
          purpose
        })
      }
      continue
    }
    if (isIP(host) === 0) continue
    const classification = classifyNetworkAddress(host)
    if (
      classification !== 'private' &&
      classification !== 'loopback' &&
      classification !== 'link-local' &&
      classification !== 'reserved'
    ) {
      continue
    }
    for (const purpose of DERIVED_NETWORK_ENTRY_PURPOSES) {
      rememberDerivedEntry(derived, {
        addressClass: classification,
        ip: host,
        ports: [port],
        purpose
      })
    }
  }
  return [...derived.values()].sort((left, right) => left.id.localeCompare(right.id))
}

export function stabilizeScopeNetworkEntries(
  scope: Omit<TargetScope, 'id'>
): Omit<TargetScope, 'id'> {
  if (scope.networkEntries.length > 0) {
    return scope
  }
  return {
    ...scope,
    networkEntries: deriveScopeNetworkEntriesFromOrigins(scope.allowedOrigins)
  }
}
