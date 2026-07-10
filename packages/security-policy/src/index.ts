import {
  ProbeActionSchema,
  TargetScopeSchema,
  type PolicyDecision,
  type ProbeAction,
  type TargetScope
} from '@agentgo/contracts'

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

  return originAllowed && pathAllowed
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

  if (scope.validUntil && Date.parse(scope.validUntil) <= Date.now()) {
    return deny('scope-expired', '授权范围已过期。', normalizedTarget)
  }

  if (!isInScope(target, scope)) {
    return deny('out-of-scope', '目标 origin 或 path 不在授权范围内。', normalizedTarget)
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

  if (
    ['PUT', 'PATCH'].includes(method) &&
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
