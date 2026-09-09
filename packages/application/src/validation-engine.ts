import type {
  LegacyV1VulnerabilityFamily,
  Verdict
} from '@agentgo/contracts'
import type {
  BrowserExecutionResultView,
  HttpExecutionResultView
} from './execution-port'
import {
  normalizeHttpObservation,
  SQLI_NORMALIZER_THRESHOLDS,
  SQLI_NORMALIZER_VERSION
} from './sqli-response-normalizer'
import {
  IDOR_NORMALIZER_VERSION,
  normalizeIdorObservation,
  parseIdorResourceFields
} from './idor-response-normalizer'

export interface HttpObservation {
  result: HttpExecutionResultLike
  evidenceRefs: string[]
  interactionId?: string
  toolCallId: string
  proposalId: string
  policyDecisionId: string
}

export type HttpExecutionResultLike = Pick<
  HttpExecutionResultView,
  | 'status'
  | 'statusCode'
  | 'responseBody'
  | 'responseBodySha256'
  | 'responseBytes'
  | 'durationMs'
  | 'responseHeaders'
  | 'errorCode'
  | 'errorMessage'
>

export interface BrowserObservation {
  result: BrowserExecutionResultView
  evidenceRefs: string[]
  toolCallId: string
  proposalId: string
  policyDecisionId: string
  reviewableDomOrScreenshotEvidence?: boolean
}

export interface ValidationAssessment {
  family: LegacyV1VulnerabilityFamily | 'security.headers'
  verdict: Verdict
  signalSummary: string
  explanation: string
  confidence: number
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  completedChecks: string[]
  failedChecks: string[]
  missingChecks: string[]
  confirmationRuleId: string
  confirmationRuleVersion: string
  cwe: string
  owasp: string
  remediation: string[]
}

export interface ConfirmationRuleDefinition {
  id: string
  version: string
  family: LegacyV1VulnerabilityFamily
  requiredChecks: string[]
  rule: Record<string, unknown>
  sourceRefs: string[]
  severity: ValidationAssessment['severity']
  cwe: string
  owasp: string
  remediation: string[]
}

export const V1_CONFIRMATION_RULES: Record<
  LegacyV1VulnerabilityFamily,
  ConfirmationRuleDefinition
> = {
  sqli: {
    id: 'sqli-boolean-differential',
    version: '1.0.0',
    family: 'sqli',
    requiredChecks: [
      'all-requests-succeeded',
      'true-condition-repeatable',
      'baseline-matches-true-condition',
      'negative-control-differs',
      'no-waf-or-generic-error'
    ],
    rule: {
      technique: 'read-only boolean differential',
      minimumExecutions: 4,
      trueRepeatSimilarity: 0.98,
      baselineTrueSimilarity: 0.9,
      maximumFalseSimilarity: 0.75
    },
    sourceRefs: ['sqli-safe-validation', 'agentgo-policy'],
    severity: 'high',
    cwe: 'CWE-89',
    owasp: 'A03:2021 Injection',
    remediation: [
      '使用参数化查询或预编译语句，不拼接用户输入。',
      '对无法参数化的动态标识符采用严格允许列表。',
      '统一数据库错误处理，并增加查询层安全测试。'
    ]
  },
  xss: {
    id: 'xss-inert-marker-execution',
    version: '1.1.0',
    family: 'xss',
    requiredChecks: [
      'http-probe-succeeded',
      'marker-reflected',
      'marker-executed-in-isolated-browser',
      'browser-network-blocked',
      'dom-or-screenshot-evidence-present'
    ],
    rule: {
      technique: 'inert random marker in isolated browser',
      exfiltration: false,
      browserNetwork: 'blocked',
      cspBypass: false
    },
    sourceRefs: ['xss-inert-marker', 'agentgo-policy'],
    severity: 'medium',
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    remediation: [
      '按 HTML、属性、URL 或 JavaScript 的实际输出上下文编码。',
      '避免 innerHTML、document.write 等危险 DOM sink。',
      '部署严格 CSP 作为纵深防御，并保留服务端输出编码。'
    ]
  },
  ssrf: {
    id: 'ssrf-controlled-proof-response',
    version: '1.0.0',
    family: 'ssrf',
    requiredChecks: [
      'controlled-callback-proof-available',
      'target-request-succeeded',
      'proof-returned-by-target',
      'negative-control-does-not-contain-proof',
      'callback-and-target-in-scope'
    ],
    rule: {
      technique: 'controlled callback proof relayed by target',
      cloudMetadata: 'forbidden',
      privateNetwork: 'scope-required',
      redirectRevalidation: true
    },
    sourceRefs: ['ssrf-controlled-callback', 'agentgo-policy'],
    severity: 'high',
    cwe: 'CWE-918',
    owasp: 'A10:2021 SSRF',
    remediation: [
      '对服务端可访问 URL 使用协议、主机、端口和路径允许列表。',
      '解析 DNS 后阻断回环、私网、链路本地和云元数据地址，并检查每次重定向。',
      '采用受控代理或出站网络策略限制服务端访问范围。'
    ]
  },
  idor: {
    id: 'idor-two-test-identities-readonly',
    version: '1.1.0',
    family: 'idor',
    requiredChecks: [
      'owner-resource-known',
      'both-identities-are-authorized-tests',
      'owner-read-succeeded',
      'second-identity-own-resource-read-succeeded',
      'second-identity-read-owner-resource',
      'cross-identity-response-matches-owner',
      'not-public-or-shared-visibility'
    ],
    rule: {
      technique: 'two authorized identities, read-only resource comparison',
      mutation: false,
      enumeration: false,
      stopAfterMinimumEvidence: true
    },
    sourceRefs: ['idor-two-identity-readonly', 'agentgo-policy'],
    severity: 'high',
    cwe: 'CWE-639',
    owasp: 'A01:2021 Broken Access Control',
    remediation: [
      '在每次资源请求中执行服务端对象级授权校验。',
      '授权判断同时绑定当前身份、租户和资源归属，不能只依赖客户端隐藏。',
      '为跨身份资源访问增加自动化正反例测试。'
    ]
  }
}

export const SQLI_V2_CONFIRMATION_RULES = Object.freeze({
  'sqli.error-signal': {
    id: 'sqli-error-signal',
    version: '1.0.0',
    family: 'sqli',
    requiredChecks: [
      'all-requests-succeeded',
      'sql-error-fingerprint-repeatable',
      'baseline-lacks-sql-error',
      'negative-control-lacks-sql-error',
      'no-waf-or-generic-error'
    ],
    rule: {
      technique: 'constrained SQL error fingerprint',
      genericHttp500: 'inconclusive',
      minimumExecutions: 4
    },
    sourceRefs: ['sqli-safe-validation', 'agentgo-policy'],
    severity: 'high' as const,
    cwe: 'CWE-89',
    owasp: 'A03:2021 Injection',
    remediation: [
      '使用参数化查询或预编译语句，不拼接用户输入。',
      '通过 ORM 绑定参数，而不是拼接标识符或 SQL 片段。',
      '数据库账户使用最小权限，禁止文件读写和命令执行。',
      '统一错误处理，不向客户端返回数据库引擎细节。',
      '用正例、负例和 Inconclusive 样例复测，不能把 WAF 当作根因修复。'
    ]
  },
  'sqli.bounded-time-differential': {
    id: 'sqli-bounded-time-differential',
    version: '1.1.0',
    family: 'sqli',
    requiredChecks: [
      'all-requests-succeeded',
      'true-condition-delay-repeatable',
      'delay-exceeds-baseline',
      'negative-control-not-delayed',
      'no-waf-or-generic-error'
    ],
    rule: {
      technique: 'bounded time differential',
      environments: ['attested-fixture'],
      minDeltaMs: 1_500,
      maximumConcurrency: 1
    },
    sourceRefs: ['sqli-safe-validation', 'agentgo-policy'],
    severity: 'high' as const,
    cwe: 'CWE-89',
    owasp: 'A03:2021 Injection',
    remediation: [
      '使用参数化查询或预编译语句，不拼接用户输入。',
      '通过 ORM 绑定参数，而不是拼接标识符或 SQL 片段。',
      '数据库账户使用最小权限，禁止文件读写和命令执行。',
      '统一错误处理，并限制语句超时。',
      '用正例、负例和 Inconclusive 样例复测，不能把 WAF 当作根因修复。'
    ]
  }
} as const satisfies Record<string, ConfirmationRuleDefinition>)

export const IDOR_V2_CONFIRMATION_RULES = Object.freeze({
  'idor.v2-bola-read-differential': {
    id: 'idor-v2-bola-read-differential',
    version: '1.0.0',
    family: 'idor',
    requiredChecks: [
      'owner-resource-known',
      'both-identities-are-authorized-tests',
      'matrix-denies-cross-read',
      'owner-read-succeeded',
      'second-identity-own-resource-read-succeeded',
      'cross-response-contains-target-resource-identity',
      'selected-owner-or-shape-matches-owner-baseline',
      'public-shared-admin-tenant-parent-excluded'
    ],
    rule: {
      technique: 'authorization-matrix read differential',
      lengthSimilarityInsufficient: true,
      enumeration: false,
      stopAfterMinimumEvidence: true
    },
    sourceRefs: ['idor-two-identity-readonly', 'agentgo-policy'],
    severity: 'high' as const,
    cwe: 'CWE-639',
    owasp: 'A01:2021 Broken Access Control',
    remediation: [
      '在每次资源请求中执行服务端对象级授权校验。',
      '授权判断同时绑定当前身份、租户和资源归属，默认拒绝。',
      '集中策略并维护跨身份、跨租户、parent-child 回归矩阵。',
      '不以不可猜 ID 作为根本修复。'
    ]
  }
} as const satisfies Record<string, ConfirmationRuleDefinition>)

export const XSS_V2_CONFIRMATION_RULES = Object.freeze({
  'xss.replay-dom-offline': {
    id: 'xss-replay-dom-offline',
    version: '1.0.0',
    family: 'xss',
    requiredChecks: [
      'frozen-source-replayed',
      'marker-executed-in-isolated-browser',
      'browser-network-blocked',
      'dom-or-screenshot-evidence-present'
    ],
    rule: {
      technique: 'offline DOM replay of a frozen asset or captured bundle',
      liveNavigation: false,
      exfiltration: false,
      browserNetwork: 'blocked'
    },
    sourceRefs: ['xss-inert-marker', 'agentgo-policy'],
    severity: 'medium' as const,
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    remediation: [
      '按输出上下文编码，并避免把不可信数据送入危险 DOM sink。',
      '使用 safe DOM API 或 Trusted Types，并以 CSP 作为纵深防御。',
      '用正例、负例和 Inconclusive 样例复测。'
    ]
  },
  'xss.stored-test-object': {
    id: 'xss-stored-test-object',
    version: '1.0.0',
    family: 'xss',
    requiredChecks: [
      'l2-test-object-approved',
      'stored-marker-executed',
      'cleanup-verified',
      'browser-network-blocked'
    ],
    rule: {
      technique: 'L2 stored marker on a disposable test object',
      realUserTrigger: false,
      cleanupRequired: true
    },
    sourceRefs: ['xss-inert-marker', 'agentgo-policy'],
    severity: 'medium' as const,
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    remediation: [
      '存储输出也必须按上下文编码，并在专用测试对象上复测 cleanup。',
      '使用模板 auto-escape、sanitization 和 Trusted Types/CSP 纵深防御。'
    ]
  }
} as const satisfies Record<string, ConfirmationRuleDefinition>)

export const SSRF_V2_CONFIRMATION_RULES = Object.freeze({
  'ssrf.reflected-proof': {
    id: 'ssrf-reflected-proof',
    version: '1.0.0',
    family: 'ssrf',
    requiredChecks: [
      'baseline-lacks-controlled-proof',
      'controlled-destination-in-scope',
      'proof-returned-by-target',
      'negative-control-does-not-contain-proof',
      'redirect-and-dns-policy-enforced'
    ],
    rule: {
      technique: 'reflected controlled destination proof',
      cloudMetadata: 'forbidden',
      privateNetwork: 'scope-required',
      redirectRevalidation: true
    },
    sourceRefs: ['ssrf-controlled-callback', 'agentgo-policy'],
    severity: 'high' as const,
    cwe: 'CWE-918',
    owasp: 'A10:2021 SSRF',
    remediation: [
      '对服务端可访问 URL 使用协议、主机、端口和路径允许列表。',
      '解析 DNS 后阻断回环、私网、链路本地和云元数据地址，并检查每次重定向。',
      '采用受控代理或出站网络策略限制服务端访问范围。'
    ]
  },
  'ssrf.oob-callback': {
    id: 'ssrf-oob-callback',
    version: '1.0.0',
    family: 'ssrf',
    requiredChecks: [
      'server-side-attributed-event',
      'not-client-browser-or-broker',
      'not-health-check-or-stale-replay',
      'token-bound-to-scan-step',
      'negative-control-has-no-event'
    ],
    rule: {
      technique: 'controlled OOB callback event',
      clientFetch: 'excluded',
      remoteCollector: 'not-run',
      loopbackOnly: true
    },
    sourceRefs: ['ssrf-controlled-callback', 'agentgo-policy'],
    severity: 'high' as const,
    cwe: 'CWE-918',
    owasp: 'A10:2021 SSRF',
    remediation: [
      '对服务端可访问 URL 使用协议、主机、端口和路径允许列表。',
      '阻断未授权回连，并记录服务端出站与目标关联。',
      '不得把浏览器预取或健康检查计为 SSRF。'
    ]
  }
} as const satisfies Record<string, ConfirmationRuleDefinition>)

export const SECURITY_HEADERS_CONFIRMATION_RULE = Object.freeze({
  id: 'security-headers-baseline',
  version: '1.0.0',
  family: 'security.headers' as const,
  requiredChecks: [
    'existing-response-headers-present',
    'zero-new-network-requests',
    'header-applicability-considered'
  ],
  rule: {
    technique: 'passive existing-response header audit',
    newNetworkRequests: 0
  },
  sourceRefs: ['docs/security/active-probing-policy.md', 'agentgo-policy'],
  severity: 'low' as const,
  cwe: 'CWE-693',
  owasp: 'Security Misconfiguration',
  remediation: [
    '按资源类型配置 HSTS、CSP、frame 隔离、content-type、referrer 与 cache/cookie 属性。',
    '缺失头在非浏览器或经网关改写的场景应表述为适用性限制，而不是一律 Critical。',
    '用既有响应样例复测，不新增目标请求。'
  ]
})

function bodyText(observation: HttpObservation): string {
  return observation.result.responseBody
    ? Buffer.from(observation.result.responseBody).toString('utf8')
    : ''
}

function normalizedBody(value: string): string {
  return value
    .slice(0, 1_000_000)
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, '<uuid>')
    .replace(/\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+\b/g, '<time>')
    .replace(/\b\d{7,}\b/g, '<number>')
    .replace(/\s+/g, ' ')
    .trim()
}

function bigrams(value: string): Map<string, number> {
  const result = new Map<string, number>()
  if (value.length < 2) {
    result.set(value, 1)
    return result
  }
  for (let index = 0; index < value.length - 1; index += 1) {
    const pair = value.slice(index, index + 2)
    result.set(pair, (result.get(pair) ?? 0) + 1)
  }
  return result
}

export function responseSimilarity(left: HttpObservation, right: HttpObservation): number {
  if (left.result.statusCode !== right.result.statusCode) return 0
  const leftText = normalizedBody(bodyText(left))
  const rightText = normalizedBody(bodyText(right))
  if (leftText === rightText) return 1
  if (!leftText || !rightText) return 0
  const leftPairs = bigrams(leftText)
  const rightPairs = bigrams(rightText)
  let overlap = 0
  for (const [pair, count] of leftPairs) {
    overlap += Math.min(count, rightPairs.get(pair) ?? 0)
  }
  const leftTotal = [...leftPairs.values()].reduce((sum, value) => sum + value, 0)
  const rightTotal = [...rightPairs.values()].reduce((sum, value) => sum + value, 0)
  return (2 * overlap) / (leftTotal + rightTotal)
}

function normalizedViewSimilarity(left: ReturnType<typeof normalizeHttpObservation>, right: ReturnType<typeof normalizeHttpObservation>): number {
  if (left.statusCode !== right.statusCode) return 0
  if (left.bodyText === right.bodyText) return 1
  if (!left.bodyText || !right.bodyText) return 0
  const leftPairs = bigrams(left.bodyText)
  const rightPairs = bigrams(right.bodyText)
  let overlap = 0
  for (const [pair, count] of leftPairs) {
    overlap += Math.min(count, rightPairs.get(pair) ?? 0)
  }
  const leftTotal = [...leftPairs.values()].reduce((sum, value) => sum + value, 0)
  const rightTotal = [...rightPairs.values()].reduce((sum, value) => sum + value, 0)
  return (2 * overlap) / (leftTotal + rightTotal)
}

function succeeded(observation: HttpObservation): boolean {
  return observation.result.status === 'succeeded' && observation.result.statusCode !== undefined
}

function looksBlocked(observation: HttpObservation): boolean {
  const status = observation.result.statusCode
  const body = bodyText(observation)
  return (
    status === 403 ||
    status === 429 ||
    /(?:web application firewall|request blocked|access denied|captcha|安全防护|请求被拦截)/i.test(
      body
    )
  )
}

function assessment(
  family: LegacyV1VulnerabilityFamily,
  input: Omit<
    ValidationAssessment,
    | 'family'
    | 'confirmationRuleId'
    | 'confirmationRuleVersion'
    | 'severity'
    | 'cwe'
    | 'owasp'
    | 'remediation'
  >
): ValidationAssessment {
  const rule = V1_CONFIRMATION_RULES[family]
  return {
    family,
    confirmationRuleId: rule.id,
    confirmationRuleVersion: rule.version,
    severity: rule.severity,
    cwe: rule.cwe,
    owasp: rule.owasp,
    remediation: rule.remediation,
    ...input
  }
}

export function assessSqli(input: {
  baseline: HttpObservation
  trueFirst: HttpObservation
  falseControl: HttpObservation
  trueRepeat: HttpObservation
}): ValidationAssessment {
  const observations = [input.baseline, input.trueFirst, input.falseControl, input.trueRepeat]
  const normalized = observations.map(normalizeHttpObservation)
  const allSucceeded = observations.every(succeeded)
  const blocked = observations.some(looksBlocked)
  const trueRepeatSimilarity = normalizedViewSimilarity(normalized[1]!, normalized[3]!)
  const baselineTrueSimilarity = normalizedViewSimilarity(normalized[0]!, normalized[1]!)
  const trueFalseSimilarity = normalizedViewSimilarity(normalized[1]!, normalized[2]!)
  const checks = {
    'all-requests-succeeded': allSucceeded,
    'true-condition-repeatable': trueRepeatSimilarity >= 0.98,
    'baseline-matches-true-condition': baselineTrueSimilarity >= 0.9,
    'negative-control-differs': trueFalseSimilarity <= 0.75,
    'no-waf-or-generic-error': !blocked
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const verdict: Verdict = !allSucceeded || blocked
    ? 'inconclusive'
    : failedChecks.length === 0
      ? 'confirmed'
      : 'not-confirmed'
  return assessment('sqli', {
    verdict,
    signalSummary: `${SQLI_NORMALIZER_VERSION}；布尔真条件重复相似度 ${trueRepeatSimilarity.toFixed(3)}，基线/真条件 ${baselineTrueSimilarity.toFixed(3)}，真/负对照 ${trueFalseSimilarity.toFixed(3)}。`,
    explanation:
      verdict === 'confirmed'
        ? '只读布尔条件产生了可重复且由负对照区分的响应差异。'
        : verdict === 'inconclusive'
          ? '请求失败或受到防护阻断，当前证据不足。'
          : '已完成差异验证，但没有同时满足可重复性和负对照要求。',
    confidence: verdict === 'confirmed' ? 0.96 : verdict === 'not-confirmed' ? 0.2 : 0.35,
    completedChecks,
    failedChecks,
    missingChecks: []
  })
}

const SQL_ERROR_FINGERPRINT =
  /(?:sql syntax|you have an error in your sql|mysql|mariadb|postgresql|postgres|sqlite|ora-\d{5}|sqlstate|unclosed quotation|quoted string not properly terminated|odbc sql|jdbc|sql exception|unterminated quoted|syntax error at or near)/i

export function hasSqlErrorFingerprint(observation: HttpObservation): boolean {
  return SQL_ERROR_FINGERPRINT.test(bodyText(observation))
}

function sqliTechniqueAssessment(
  techniqueId: keyof typeof SQLI_V2_CONFIRMATION_RULES,
  input: Omit<
    ValidationAssessment,
    | 'family'
    | 'confirmationRuleId'
    | 'confirmationRuleVersion'
    | 'severity'
    | 'cwe'
    | 'owasp'
    | 'remediation'
  >
): ValidationAssessment {
  const rule = SQLI_V2_CONFIRMATION_RULES[techniqueId]
  return {
    family: 'sqli',
    confirmationRuleId: rule.id,
    confirmationRuleVersion: rule.version,
    severity: rule.severity,
    cwe: rule.cwe,
    owasp: rule.owasp,
    remediation: [...rule.remediation],
    ...input
  }
}

export function assessSqliErrorSignal(input: {
  baseline: HttpObservation
  errorFirst: HttpObservation
  negativeControl: HttpObservation
  errorRepeat: HttpObservation
}): ValidationAssessment {
  const observations = [
    input.baseline,
    input.errorFirst,
    input.negativeControl,
    input.errorRepeat
  ]
  const allSucceeded = observations.every(succeeded)
  const blocked = observations.some(looksBlocked)
  const genericFailure = observations.some((item) => {
    const status = item.result.statusCode
    return status !== undefined && status >= 500 && !hasSqlErrorFingerprint(item)
  })
  const fingerprint = hasSqlErrorFingerprint(input.errorFirst)
  const repeatable =
    fingerprint &&
    hasSqlErrorFingerprint(input.errorRepeat) &&
    responseSimilarity(input.errorFirst, input.errorRepeat) >= 0.98
  const checks = {
    'all-requests-succeeded': allSucceeded,
    'sql-error-fingerprint-repeatable': Boolean(repeatable),
    'baseline-lacks-sql-error': !hasSqlErrorFingerprint(input.baseline),
    'negative-control-lacks-sql-error': !hasSqlErrorFingerprint(
      input.negativeControl
    ),
    'no-waf-or-generic-error': !blocked && !genericFailure
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const verdict: Verdict =
    !allSucceeded || blocked || genericFailure
      ? 'inconclusive'
      : failedChecks.length === 0
        ? 'confirmed'
        : 'not-confirmed'
  return sqliTechniqueAssessment('sqli.error-signal', {
    verdict,
    signalSummary: `SQL 错误指纹 test=${fingerprint} repeat=${hasSqlErrorFingerprint(input.errorRepeat)} baseline=${hasSqlErrorFingerprint(input.baseline)} negative=${hasSqlErrorFingerprint(input.negativeControl)}；${SQLI_NORMALIZER_VERSION}。`,
    explanation:
      verdict === 'confirmed'
        ? '受限错误信号可重复出现，且基线与负对照不含同类数据库错误指纹。'
        : verdict === 'inconclusive'
          ? '请求失败、防护阻断或仅为普通异常，当前证据不足。'
          : '已完成错误信号对照，但没有同时满足指纹、可重复性和负对照要求。',
    confidence: verdict === 'confirmed' ? 0.9 : verdict === 'not-confirmed' ? 0.2 : 0.35,
    completedChecks,
    failedChecks,
    missingChecks: []
  })
}

export function assessSqliBoundedTime(input: {
  baseline: HttpObservation
  delayedFirst: HttpObservation
  negativeControl: HttpObservation
  delayedRepeat: HttpObservation
}): ValidationAssessment {
  const observations = [
    input.baseline,
    input.delayedFirst,
    input.negativeControl,
    input.delayedRepeat
  ]
  const allSucceeded = observations.every(succeeded)
  const blocked = observations.some(looksBlocked)
  const baselineMs = input.baseline.result.durationMs
  const delayedMs = input.delayedFirst.result.durationMs
  const repeatMs = input.delayedRepeat.result.durationMs
  const negativeMs = input.negativeControl.result.durationMs
  const delayDelta = delayedMs - baselineMs
  const repeatDelta = Math.abs(repeatMs - delayedMs)
  const negativeDelta = Math.abs(negativeMs - baselineMs)
  const checks = {
    'all-requests-succeeded': allSucceeded,
    'true-condition-delay-repeatable':
      delayDelta >= SQLI_NORMALIZER_THRESHOLDS.boundedTimeMinDeltaMs &&
      repeatDelta <= SQLI_NORMALIZER_THRESHOLDS.boundedTimeRepeatDeltaToleranceMs,
    'delay-exceeds-baseline': delayDelta >= SQLI_NORMALIZER_THRESHOLDS.boundedTimeMinDeltaMs,
    'negative-control-not-delayed':
      negativeDelta <= SQLI_NORMALIZER_THRESHOLDS.boundedTimeFalseMaxDeltaMs,
    'no-waf-or-generic-error': !blocked
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const verdict: Verdict =
    !allSucceeded || blocked
      ? 'inconclusive'
      : failedChecks.length === 0
        ? 'confirmed'
        : 'not-confirmed'
  return sqliTechniqueAssessment('sqli.bounded-time-differential', {
    verdict,
    signalSummary: `时间差异 baseline=${baselineMs}ms delayed=${delayedMs}ms repeat=${repeatMs}ms negative=${negativeMs}ms；${SQLI_NORMALIZER_VERSION} 阈值 ${SQLI_NORMALIZER_THRESHOLDS.boundedTimeMinDeltaMs}/${SQLI_NORMALIZER_THRESHOLDS.boundedTimeRepeatDeltaToleranceMs}/${SQLI_NORMALIZER_THRESHOLDS.boundedTimeFalseMaxDeltaMs}。`,
    explanation:
      verdict === 'confirmed'
        ? '有界时间差异可重复，且负对照未出现同等延迟。'
        : verdict === 'inconclusive'
          ? '请求失败或防护阻断，当前证据不能确认时间注入。'
          : '已完成时间对照，但延迟未超过阈值，或重复性/负对照不满足确认规则。',
    confidence: verdict === 'confirmed' ? 0.88 : verdict === 'not-confirmed' ? 0.2 : 0.35,
    completedChecks,
    failedChecks,
    missingChecks: []
  })
}

export function assessXss(input: {
  marker: string
  http: HttpObservation
  browser?: BrowserObservation
}): ValidationAssessment {
  const reflected = bodyText(input.http).includes(input.marker)
  const httpSucceeded = succeeded(input.http)
  const browserSucceeded = input.browser?.result.status === 'succeeded'
  const markerExecuted = input.browser?.result.markerExecuted === true
  const evidencePresent =
    input.browser?.reviewableDomOrScreenshotEvidence === true
  const checks = {
    'http-probe-succeeded': httpSucceeded,
    'marker-reflected': reflected,
    'marker-executed-in-isolated-browser': markerExecuted,
    'browser-network-blocked': browserSucceeded,
    'dom-or-screenshot-evidence-present': evidencePresent
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const missingChecks = [
    ...(!input.browser ? ['isolated-browser-result'] : []),
    ...(input.browser && markerExecuted && !evidencePresent
      ? ['reviewable-dom-or-screenshot-evidence']
      : [])
  ]
  const csp = input.http.result.responseHeaders?.['content-security-policy'] ?? ''
  const cspBlocksScripts = /default-src\s+'none'|script-src\s+'none'/i.test(csp)
  const dynamicNonce = /(?:data-nonce|[\s:]nonce)=/i.test(bodyText(input.http))
  const blockedByPolicy = !markerExecuted && (cspBlocksScripts || dynamicNonce)
  const verdict: Verdict = !httpSucceeded || !input.browser || !browserSucceeded
    ? 'inconclusive'
    : markerExecuted
      ? evidencePresent
        ? 'confirmed'
        : 'inconclusive'
      : blockedByPolicy
        ? 'inconclusive'
        : 'not-confirmed'
  return assessment('xss', {
    verdict,
    signalSummary: reflected
      ? `随机惰性标记 ${input.marker} 被响应反射；隔离浏览器执行=${markerExecuted}。`
      : `响应未反射随机惰性标记 ${input.marker}。`,
    explanation:
      verdict === 'confirmed'
        ? '随机惰性标记在阻断网络的隔离浏览器中实际执行，并保存了 DOM/截图证据。'
        : verdict === 'inconclusive'
          ? markerExecuted && !evidencePresent
            ? '标记已在隔离浏览器中执行，但缺少可审阅的 DOM/截图证据。'
            : blockedByPolicy
              ? 'CSP 或动态 nonce 阻断了标记执行，当前证据记为 Inconclusive。'
              : 'HTTP 或隔离浏览器验证未成功完成。'
          : reflected
            ? '输入仅被反射但未在隔离浏览器中执行，因此不能确认 XSS。'
            : '未观察到反射或执行证据。',
    confidence: verdict === 'confirmed' ? 0.98 : verdict === 'not-confirmed' ? 0.15 : 0.3,
    completedChecks,
    failedChecks,
    missingChecks
  })
}

export function extractControlledCallbackProof(observation: HttpObservation): string | undefined {
  const body = bodyText(observation)
  const direct = /AGENTGO_CALLBACK_PROOF_[A-Za-z0-9_-]{8,128}/.exec(body)?.[0]
  if (direct) return direct
  try {
    const json = JSON.parse(body) as { agentgoProof?: unknown }
    return typeof json.agentgoProof === 'string' && /^AGENTGO_CALLBACK_PROOF_/.test(json.agentgoProof)
      ? json.agentgoProof
      : undefined
  } catch {
    return undefined
  }
}

export function assessSsrf(input: {
  callbackBaseline: HttpObservation
  targetProbe: HttpObservation
  negativeControl: HttpObservation
}): ValidationAssessment {
  const proof = extractControlledCallbackProof(input.callbackBaseline)
  const targetBody = bodyText(input.targetProbe)
  const negativeBody = bodyText(input.negativeControl)
  const checks = {
    'controlled-callback-proof-available': Boolean(proof),
    'target-request-succeeded': succeeded(input.targetProbe),
    'proof-returned-by-target': Boolean(proof && targetBody.includes(proof)),
    'negative-control-does-not-contain-proof': Boolean(proof && !negativeBody.includes(proof)),
    'callback-and-target-in-scope':
      succeeded(input.callbackBaseline) && succeeded(input.targetProbe)
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const verdict: Verdict = !proof || !succeeded(input.targetProbe)
    ? 'inconclusive'
    : failedChecks.length === 0
      ? 'confirmed'
      : 'not-confirmed'
  return assessment('ssrf', {
    verdict,
    signalSummary: proof
      ? `受控回调证明 ${proof} 在目标响应中出现=${targetBody.includes(proof)}，负对照出现=${negativeBody.includes(proof)}。`
      : '回调端点没有返回 AgentGo 可识别的唯一证明标记。',
    explanation:
      verdict === 'confirmed'
        ? '目标服务返回了仅由受控回调端点生成的证明，且负对照不包含该证明。'
        : verdict === 'inconclusive'
          ? '缺少受控回调证明或目标请求未成功，不能判断服务端取回行为。'
          : '目标响应没有通过受控证明和负对照规则。',
    confidence: verdict === 'confirmed' ? 0.97 : verdict === 'not-confirmed' ? 0.15 : 0.25,
    completedChecks,
    failedChecks,
    missingChecks: proof ? [] : ['controlled-callback-proof']
  })
}

function ssrfTechniqueAssessment(
  techniqueId: keyof typeof SSRF_V2_CONFIRMATION_RULES,
  input: Omit<
    ValidationAssessment,
    | 'family'
    | 'confirmationRuleId'
    | 'confirmationRuleVersion'
    | 'severity'
    | 'cwe'
    | 'owasp'
    | 'remediation'
  >
): ValidationAssessment {
  const rule = SSRF_V2_CONFIRMATION_RULES[techniqueId]
  return {
    family: 'ssrf',
    confirmationRuleId: rule.id,
    confirmationRuleVersion: rule.version,
    severity: rule.severity,
    cwe: rule.cwe,
    owasp: rule.owasp,
    remediation: [...rule.remediation],
    ...input
  }
}

export function assessSsrfReflected(input: {
  baseline: HttpObservation
  targetProbe: HttpObservation
  negativeControl: HttpObservation
  destinationInScope: boolean
  redirectPolicyEnforced: boolean
}): ValidationAssessment {
  const proof = extractControlledCallbackProof(input.targetProbe)
  const baselineBody = bodyText(input.baseline)
  const negativeBody = bodyText(input.negativeControl)
  const wafOrTimeout =
    /waf|blocked|timeout/i.test(input.targetProbe.result.errorCode ?? '') ||
    input.targetProbe.result.status === 'failed'
  const redirected = [301, 302, 303, 307, 308].includes(
    input.targetProbe.result.statusCode ?? 0
  )
  const checks = {
    'baseline-lacks-controlled-proof': !extractControlledCallbackProof(input.baseline),
    'controlled-destination-in-scope': input.destinationInScope,
    'proof-returned-by-target': Boolean(proof && bodyText(input.targetProbe).includes(proof)),
    'negative-control-does-not-contain-proof': Boolean(
      proof && !negativeBody.includes(proof) && !baselineBody.includes(proof)
    ),
    'redirect-and-dns-policy-enforced': input.redirectPolicyEnforced
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const verdict: Verdict =
    wafOrTimeout || !succeeded(input.targetProbe) || redirected
      ? 'inconclusive'
      : failedChecks.length === 0
        ? 'confirmed'
        : 'not-confirmed'
  return ssrfTechniqueAssessment('ssrf.reflected-proof', {
    verdict,
    signalSummary: proof
      ? `回显证明 ${proof}；负对照含证明=${negativeBody.includes(proof)}。`
      : '受控目的地响应没有返回可识别证明。',
    explanation:
      verdict === 'confirmed'
        ? '目标把仅由受控目的地生成的证明回显到响应，且基线与负对照不含该证明。'
        : verdict === 'inconclusive'
          ? redirected
            ? '目标返回了重定向，不能判断受控目的地是否被服务端取回。'
            : 'WAF、超时或目标请求失败，不能判断服务端取回。'
          : '响应没有通过回显证明与负对照规则。',
    confidence: verdict === 'confirmed' ? 0.96 : verdict === 'not-confirmed' ? 0.15 : 0.3,
    completedChecks,
    failedChecks,
    missingChecks: proof ? [] : ['controlled-callback-proof']
  })
}

export function assessSsrfOob(input: {
  serverSideEvent: boolean
  clientOrBrokerOrHealth: boolean
  staleOrReplay: boolean
  tokenBound: boolean
  negativeHasEvent: boolean
  collectorAvailable: boolean
  timedOutOrWaf: boolean
}): ValidationAssessment {
  const checks = {
    'server-side-attributed-event': input.serverSideEvent,
    'not-client-browser-or-broker': !input.clientOrBrokerOrHealth,
    'not-health-check-or-stale-replay': !input.staleOrReplay,
    'token-bound-to-scan-step': input.tokenBound,
    'negative-control-has-no-event': !input.negativeHasEvent
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const verdict: Verdict =
    !input.collectorAvailable || input.timedOutOrWaf
      ? 'inconclusive'
      : failedChecks.length === 0
        ? 'confirmed'
        : 'not-confirmed'
  return ssrfTechniqueAssessment('ssrf.oob-callback', {
    verdict,
    signalSummary: `服务端回连事件=${input.serverSideEvent}；客户端/Broker=${input.clientOrBrokerOrHealth}；重放/过期=${input.staleOrReplay}。`,
    explanation:
      verdict === 'confirmed'
        ? 'Collector 记录了与当前 token/step 关联的服务端事件，且排除客户端与重放。'
        : verdict === 'inconclusive'
          ? 'Collector 不可用、超时或 WAF 使 OOB 无法确认。远程生产 Collector 仍为 not-run。'
          : '事件不能归因到当前目标的服务端取回。',
    confidence: verdict === 'confirmed' ? 0.95 : verdict === 'not-confirmed' ? 0.15 : 0.3,
    completedChecks,
    failedChecks,
    missingChecks: input.collectorAvailable ? [] : ['callback-collector']
  })
}

export function assessSecurityHeaders(input: {
  headers: Readonly<Record<string, string>>
  newRequestCount: number
  https: boolean
}): ValidationAssessment {
  const normalized = Object.fromEntries(
    Object.entries(input.headers).map(([name, value]) => [name.toLowerCase(), value])
  )
  const present = Object.keys(normalized).length > 0
  const missing: string[] = []
  if (!normalized['strict-transport-security'] && input.https) missing.push('hsts')
  if (!normalized['content-security-policy']) missing.push('csp')
  if (!normalized['x-frame-options'] && !/frame-ancestors/i.test(normalized['content-security-policy'] ?? '')) {
    missing.push('frame')
  }
  if (!normalized['x-content-type-options']) missing.push('content-type-nosniff')
  if (!normalized['referrer-policy']) missing.push('referrer')
  const setCookie = normalized['set-cookie'] ?? ''
  const cookieWeak =
    setCookie.length > 0 &&
    (!/;\s*httponly/i.test(setCookie) || (input.https && !/;\s*secure/i.test(setCookie)))
  if (cookieWeak) missing.push('cookie-flags')
  const checks = {
    'existing-response-headers-present': present,
    'zero-new-network-requests': input.newRequestCount === 0,
    'header-applicability-considered': true
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const verdict: Verdict = !present || input.newRequestCount > 0
    ? 'inconclusive'
    : missing.length > 0
      ? 'confirmed'
      : 'not-confirmed'
  const rule = SECURITY_HEADERS_CONFIRMATION_RULE
  return {
    family: 'security.headers',
    confirmationRuleId: rule.id,
    confirmationRuleVersion: rule.version,
    severity: rule.severity,
    cwe: rule.cwe,
    owasp: rule.owasp,
    remediation: [...rule.remediation],
    verdict,
    signalSummary: present
      ? `已分析既有响应头；缺失或弱化项=${missing.join(',') || 'none'}；HTTPS=${input.https}。`
      : '没有既有响应头可供被动分析。',
    explanation:
      verdict === 'confirmed'
        ? `既有响应缺少适用于该资源的防护头或 cookie 属性：${missing.join('、')}。`
        : verdict === 'inconclusive'
          ? '缺少既有响应或分析阶段新增了网络请求，不能形成被动结论。'
          : '既有响应已包含本次检查的基线防护头，或该上下文不适用某项浏览器头。',
    confidence: verdict === 'confirmed' ? 0.7 : verdict === 'not-confirmed' ? 0.6 : 0.3,
    completedChecks,
    failedChecks,
    missingChecks: present ? [] : ['response-headers']
  }
}

export function assessIdor(input: {
  ownerResourceId: string
  secondIdentityResourceId: string
  ownerRead: HttpObservation
  secondIdentityOwnRead: HttpObservation
  secondIdentityOwnerRead: HttpObservation
  identitiesAuthorized: boolean
}): ValidationAssessment {
  const ownerBody = bodyText(input.ownerRead)
  const crossBody = bodyText(input.secondIdentityOwnerRead)
  const similarity = responseSimilarity(input.ownerRead, input.secondIdentityOwnerRead)
  const ownerFields = parseIdorResourceFields(ownerBody)
  const crossFields = parseIdorResourceFields(crossBody)
  const visibility = (
    crossFields.visibility ??
    ownerFields.visibility ??
    ''
  ).toLowerCase()
  const publicOrSharedVisibility = visibility === 'public' || visibility === 'shared'
  const ownerView = normalizeIdorObservation(input.ownerRead)
  const crossView = normalizeIdorObservation(input.secondIdentityOwnerRead)
  const crossContainsOwnerResource =
    input.ownerResourceId.length > 0 && crossBody.includes(input.ownerResourceId)
  const checks = {
    'owner-resource-known': Boolean(input.ownerResourceId),
    'both-identities-are-authorized-tests': input.identitiesAuthorized,
    'owner-read-succeeded': succeeded(input.ownerRead),
    'second-identity-own-resource-read-succeeded': succeeded(input.secondIdentityOwnRead),
    'second-identity-read-owner-resource':
      succeeded(input.secondIdentityOwnerRead) &&
      ![401, 403, 404].includes(input.secondIdentityOwnerRead.result.statusCode ?? 0) &&
      crossContainsOwnerResource,
    'cross-identity-response-matches-owner': similarity >= 0.95 && ownerBody.length > 0,
    'not-public-or-shared-visibility': !publicOrSharedVisibility
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const anyFailedExecution = [
    input.ownerRead,
    input.secondIdentityOwnRead,
    input.secondIdentityOwnerRead
  ].some((item) => item.result.status === 'failed')
  const sessionExpired =
    ownerView.statusCode === 401 ||
    crossView.statusCode === 401
  const cached =
    /public|max-age/i.test(crossView.cacheControl) ||
    /public|max-age/i.test(ownerView.cacheControl)
  const sameResourceIdentity =
    Boolean(ownerView.resourceId) &&
    ownerView.resourceId === crossView.resourceId &&
    Boolean(ownerView.ownerId) &&
    ownerView.ownerId === crossView.ownerId
  const unstableDynamicBody = sameResourceIdentity && similarity < 0.95
  const verdict: Verdict =
    !input.identitiesAuthorized ||
    anyFailedExecution ||
    sessionExpired ||
    cached ||
    unstableDynamicBody
      ? 'inconclusive'
      : failedChecks.length === 0
        ? 'confirmed'
        : 'not-confirmed'
  return assessment('idor', {
    verdict,
    signalSummary: `身份 B 读取身份 A 资源的响应与 A 自身读取相似度为 ${similarity.toFixed(3)}，响应包含已知资源标识=${crossContainsOwnerResource}。`,
    explanation:
      verdict === 'confirmed'
        ? '两个授权测试身份完成了只读对照，第二身份获得了与资源所有者一致的最小资源证据。'
        : verdict === 'inconclusive'
          ? sessionExpired || cached || unstableDynamicBody
            ? '会话过期、缓存或动态内容使对象级授权无法确认。'
            : '身份授权或请求执行条件不足，不能判断对象级授权。'
          : publicOrSharedVisibility
            ? '公开或共享可见性排除了对象级越权误报。'
            : '跨身份请求被拒绝或响应没有满足资源归属与相似性确认规则。',
    confidence: verdict === 'confirmed' ? 0.98 : verdict === 'not-confirmed' ? 0.2 : 0.3,
    completedChecks,
    failedChecks,
    missingChecks:
      input.secondIdentityResourceId.length > 0 ? [] : ['second-identity-owned-resource']
  })
}

export type AuthorizationVisibility = 'visible' | 'not-visible'

function idorTechniqueAssessment(
  input: Omit<
    ValidationAssessment,
    | 'family'
    | 'confirmationRuleId'
    | 'confirmationRuleVersion'
    | 'severity'
    | 'cwe'
    | 'owasp'
    | 'remediation'
  >
): ValidationAssessment {
  const rule = IDOR_V2_CONFIRMATION_RULES['idor.v2-bola-read-differential']
  return {
    family: 'idor',
    confirmationRuleId: rule.id,
    confirmationRuleVersion: rule.version,
    severity: rule.severity,
    cwe: rule.cwe,
    owasp: rule.owasp,
    remediation: [...rule.remediation],
    ...input
  }
}

function controlSharesTargetResource(
  observation: HttpObservation | undefined,
  ownerResourceId: string
): boolean {
  if (!observation) return false
  const view = normalizeIdorObservation(observation)
  return (
    succeeded(observation) &&
    view.statusCode === 200 &&
    (view.resourceId === ownerResourceId ||
      bodyText(observation).includes(ownerResourceId))
  )
}

/**
 * Matrix-backed BOLA confirmation. Two similar 200 lengths are never enough.
 */
export function assessBola(input: {
  ownerResourceId: string
  secondIdentityResourceId: string
  ownerRead: HttpObservation
  secondIdentityOwnRead: HttpObservation
  secondIdentityOwnerRead: HttpObservation
  identitiesAuthorized: boolean
  matrixCrossExpected: AuthorizationVisibility | 'missing'
  crossIdentityRole?: string
  publicControl?: HttpObservation
  sharedControl?: HttpObservation
  adminControl?: HttpObservation
  tenantControl?: HttpObservation
  parentControl?: HttpObservation
}): ValidationAssessment {
  const ownerView = normalizeIdorObservation(input.ownerRead)
  const crossView = normalizeIdorObservation(input.secondIdentityOwnerRead)
  const ownerIdentityPresent =
    ownerView.resourceId === input.ownerResourceId ||
    (Boolean(input.ownerResourceId) &&
      bodyText(input.ownerRead).includes(input.ownerResourceId))
  const selectedMatch =
    Boolean(ownerView.selectedFieldHash) &&
    ownerView.selectedFieldHash === crossView.selectedFieldHash
  const ownerFieldMatch =
    Boolean(ownerView.ownerId) && ownerView.ownerId === crossView.ownerId
  const publicOrShared =
    controlSharesTargetResource(input.publicControl, input.ownerResourceId) ||
    controlSharesTargetResource(input.sharedControl, input.ownerResourceId)
  const adminVisible =
    input.crossIdentityRole === 'admin' ||
    controlSharesTargetResource(input.adminControl, input.ownerResourceId)
  const cachedOrDynamic =
    /public|max-age/i.test(crossView.cacheControl) ||
    /public|max-age/i.test(ownerView.cacheControl)
  const sessionOrGateway =
    ownerView.statusCode === 401 ||
    crossView.gatewayOrWaf ||
    ownerView.gatewayOrWaf
  const genericFailure = [
    input.ownerRead,
    input.secondIdentityOwnRead,
    input.secondIdentityOwnerRead
  ].some(
    (item) =>
      item.result.status === 'failed' || item.result.statusCode === 500
  )
  const matrixDenies = input.matrixCrossExpected === 'not-visible'
  const crossSuccess =
    succeeded(input.secondIdentityOwnerRead) &&
    ![401, 403, 404].includes(input.secondIdentityOwnerRead.result.statusCode ?? 0)
  const checks = {
    'owner-resource-known': Boolean(input.ownerResourceId) && ownerIdentityPresent,
    'both-identities-are-authorized-tests': input.identitiesAuthorized,
    'matrix-denies-cross-read': matrixDenies,
    'owner-read-succeeded': succeeded(input.ownerRead),
    'second-identity-own-resource-read-succeeded': succeeded(
      input.secondIdentityOwnRead
    ),
    'cross-response-contains-target-resource-identity':
      crossSuccess &&
      Boolean(crossView.resourceId) &&
      crossView.resourceId === input.ownerResourceId,
    'selected-owner-or-shape-matches-owner-baseline':
      selectedMatch || ownerFieldMatch,
    'public-shared-admin-tenant-parent-excluded': !publicOrShared && !adminVisible
  }
  const completedChecks = Object.entries(checks)
    .filter(([, passed]) => passed)
    .map(([name]) => name)
  const failedChecks = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name)
  const inconclusive =
    !input.identitiesAuthorized ||
    input.matrixCrossExpected === 'missing' ||
    genericFailure ||
    sessionOrGateway ||
    cachedOrDynamic
  const verdict: Verdict = inconclusive
    ? 'inconclusive'
    : failedChecks.length === 0
      ? 'confirmed'
      : 'not-confirmed'
  return idorTechniqueAssessment({
    verdict,
    signalSummary: `${IDOR_NORMALIZER_VERSION} cross status=${crossView.statusCode} resource=${crossView.resourceId ?? 'missing'} ownerField=${crossView.ownerId ?? 'missing'} matrix=${input.matrixCrossExpected}.`,
    explanation:
      verdict === 'confirmed'
        ? '授权矩阵禁止跨身份读取，但非拥有者响应包含目标资源 identity，且与所有者基线的选定字段一致。'
        : verdict === 'inconclusive'
          ? '身份不足、矩阵缺失、会话过期、网关/WAF、缓存或动态内容使对象级授权无法确认。'
          : publicOrShared || adminVisible || input.matrixCrossExpected === 'visible'
            ? '公开、共享、管理员或矩阵允许的可见性排除了对象级越权误报。'
            : '跨身份响应缺少稳定资源 identity，或未通过负对照与矩阵一致性。',
    confidence: verdict === 'confirmed' ? 0.97 : verdict === 'not-confirmed' ? 0.2 : 0.3,
    completedChecks,
    failedChecks,
    missingChecks:
      input.matrixCrossExpected === 'missing' ? ['authorization-matrix-entry'] : []
  })
}

function xssTechniqueAssessment(
  techniqueId: keyof typeof XSS_V2_CONFIRMATION_RULES,
  input: Omit<
    ValidationAssessment,
    | 'family'
    | 'confirmationRuleId'
    | 'confirmationRuleVersion'
    | 'severity'
    | 'cwe'
    | 'owasp'
    | 'remediation'
  >
): ValidationAssessment {
  const rule = XSS_V2_CONFIRMATION_RULES[techniqueId]
  return {
    family: 'xss',
    confirmationRuleId: rule.id,
    confirmationRuleVersion: rule.version,
    severity: rule.severity,
    cwe: rule.cwe,
    owasp: rule.owasp,
    remediation: [...rule.remediation],
    ...input
  }
}

export function assessXssDomOffline(input: {
  marker: string
  http: HttpObservation
  browser?: BrowserObservation
  frozenSource: boolean
}): ValidationAssessment {
  const base = assessXss(input)
  const csp = input.http.result.responseHeaders?.['content-security-policy'] ?? ''
  const cspBlocked = /default-src\s+'none'|script-src\s+'none'/i.test(csp)
  if (!input.frozenSource) {
    return xssTechniqueAssessment('xss.replay-dom-offline', {
      verdict: 'inconclusive',
      signalSummary: base.signalSummary,
      explanation: '缺少冻结 AssetManifest 或 Broker 捕获的固定 DOM，不能做离线 DOM 重放确认。',
      confidence: 0.2,
      completedChecks: [],
      failedChecks: ['frozen-source-replayed'],
      missingChecks: ['frozen-asset-manifest']
    })
  }
  if (cspBlocked && base.verdict !== 'confirmed') {
    return xssTechniqueAssessment('xss.replay-dom-offline', {
      verdict: 'inconclusive',
      signalSummary: `${base.signalSummary} CSP blocked.`,
      explanation: 'CSP 阻断了标记执行；该结论按 xss-replay-dom-offline@1.0.0 记为 Inconclusive，不是 Confirmed 绕过。',
      confidence: 0.3,
      completedChecks: ['frozen-source-replayed', 'browser-network-blocked'],
      failedChecks: ['marker-executed-in-isolated-browser'],
      missingChecks: []
    })
  }
  return xssTechniqueAssessment('xss.replay-dom-offline', {
    verdict: base.verdict,
    signalSummary: base.signalSummary,
    explanation: base.explanation,
    confidence: base.confidence,
    completedChecks: [
      'frozen-source-replayed',
      ...base.completedChecks.filter((item) => item !== 'http-probe-succeeded' && item !== 'marker-reflected')
    ],
    failedChecks: base.failedChecks.filter(
      (item) => item !== 'http-probe-succeeded' && item !== 'marker-reflected'
    ),
    missingChecks: base.missingChecks
  })
}

export function assessXssStored(input: {
  marker: string
  http: HttpObservation
  browser?: BrowserObservation
  approved: boolean
  cleanupVerified: boolean
}): ValidationAssessment {
  if (!input.approved) {
    return xssTechniqueAssessment('xss.stored-test-object', {
      verdict: 'inconclusive',
      signalSummary: 'Stored XSS was not approved as an L2 test object action.',
      explanation: '未批准的存储型测试对象不能确认，产品 L2 保持禁用。',
      confidence: 0.1,
      completedChecks: [],
      failedChecks: ['l2-test-object-approved'],
      missingChecks: ['trusted-approval']
    })
  }
  if (!input.cleanupVerified) {
    return xssTechniqueAssessment('xss.stored-test-object', {
      verdict: 'inconclusive',
      signalSummary: 'Stored XSS cleanup did not return to baseline.',
      explanation: 'cleanup 失败后对象队列冻结，不能把存储执行写成 Confirmed。',
      confidence: 0.2,
      completedChecks: ['l2-test-object-approved'],
      failedChecks: ['cleanup-verified'],
      missingChecks: []
    })
  }
  const executed = assessXss(input)
  return xssTechniqueAssessment('xss.stored-test-object', {
    verdict: executed.verdict,
    signalSummary: executed.signalSummary,
    explanation: executed.explanation,
    confidence: executed.confidence,
    completedChecks: [
      'l2-test-object-approved',
      'cleanup-verified',
      ...executed.completedChecks
    ],
    failedChecks: executed.failedChecks,
    missingChecks: executed.missingChecks
  })
}
