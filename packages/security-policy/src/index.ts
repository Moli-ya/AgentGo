import {
  ProbeActionSchema,
  TargetScopeSchema,
  type PolicyDecision,
  type ProbeAction,
  type TargetScope
} from '@agentgo/contracts'
import { isIP } from 'node:net'

export {
  BUILT_IN_PROBE_CAPABILITY_DESCRIPTORS,
  DEFAULT_PROBE_CAPABILITY_CATALOG,
  ProbeCapabilityCatalog,
  isProbeCapabilityId,
  type ProbeCapabilityDescriptor,
  type ProbeCapabilityRiskFloor
} from './probe-capability-catalog'

const destructiveIndicators = [
  /\b(?:drop|truncate|alter)\s+(?:database|schema|table)\b/i,
  /\bdelete\s+from\b/i,
  /\bupdate\s+[\w.[\]"]+\s+set\b/i,
  /\binsert\s+into\b/i,
  /\bshutdown\b/i,
  /\bxp_cmdshell\b/i,
  /\brm\s+-rf\b/i,
  /\bremove-item\b.*\b-recurse\b/i,
  /\b(?:mkfs|format\s+[a-z]:|del\s+\/s)\b/i,
  /\b(?:webshell|reverse shell|credential spray|password spray)\b/i
]

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

export function evaluateProbe(
  actionInput: unknown,
  scopeInput: unknown
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

  let target: URL
  try {
    target = new URL(action.targetUrl)
  } catch {
    return deny('invalid-target', '目标 URL 无法解析。')
  }

  const normalizedTarget = target.toString()

  if (!['http:', 'https:'].includes(target.protocol)) {
    return deny('invalid-target', '只允许 HTTP 或 HTTPS Web 目标。', normalizedTarget)
  }

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
    scope.allowedIdentityIds.length > 0 &&
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

  if (['DELETE', 'TRACE', 'CONNECT'].includes(method)) {
    return deny(
      'http-method-blocked',
      `HTTP ${method} 在默认策略中永久禁止。`,
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

  // POST is not inherently destructive at the HTTP layer, but on a real Web
  // application it commonly creates state.  Treat it like PUT/PATCH unless an
  // explicitly approved L2 proposal declares a reversible test object and a
  // cleanup plan.  V1 automatic validation stays on the safer GET/HEAD path.
  if (
    ['POST', 'PUT', 'PATCH'].includes(method) &&
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

    if (!action.userApproved) {
      return deny(
        'approval-required',
        'L2 敏感探测需要逐次人工批准。',
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
    reasons: ['动作位于授权范围内，且符合当前主动探测等级。'],
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

export function classifyNetworkAddress(address: string): NetworkAddressClass {
  const version = isIP(address)
  if (version === 4) return classifyIpv4(address)
  if (version !== 6) return 'invalid'

  const normalized = address.toLowerCase().split('%')[0] ?? address.toLowerCase()
  if (normalized === '::1') return 'loopback'
  if (normalized === '::') return 'unspecified'
  if (normalized.startsWith('::ffff:')) {
    return classifyIpv4(normalized.slice('::ffff:'.length))
  }
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return 'private'
  if (/^fe[89ab]/.test(normalized)) return 'link-local'
  if (normalized.startsWith('ff')) return 'multicast'
  if (normalized.startsWith('2001:db8:')) return 'reserved'
  return 'public'
}

export function evaluateResolvedAddresses(
  addresses: string[],
  scopeInput: unknown
): PolicyDecision {
  const scopeResult = TargetScopeSchema.safeParse(scopeInput)
  if (!scopeResult.success) {
    return deny('out-of-scope', '授权范围配置无效。')
  }
  if (addresses.length === 0) {
    return deny('invalid-target', '目标主机未解析到可验证地址。')
  }

  const scope = scopeResult.data
  for (const address of addresses) {
    const classification = classifyNetworkAddress(address)
    if (classification === 'metadata') {
      return deny(
        'network-address-blocked',
        `地址 ${address} 属于云元数据端点，永久禁止访问。`
      )
    }
    if (classification === 'loopback' && !scope.allowLoopbackTargets) {
      return deny(
        'network-address-blocked',
        `地址 ${address} 属于回环网络，当前 scope 未显式授权。`
      )
    }
    if (
      [
        'private',
        'link-local',
        'reserved',
        'unspecified',
        'multicast',
        'invalid'
      ].includes(classification) &&
      !scope.allowPrivateNetworkTargets
    ) {
      return deny(
        'network-address-blocked',
        `地址 ${address} 的网络类别为 ${classification}，当前 scope 未显式授权。`
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
