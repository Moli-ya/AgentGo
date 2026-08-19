import type {
  LegacyV1VulnerabilityFamily,
  Verdict
} from '@agentgo/contracts'
import type {
  BrowserExecutionResultView,
  HttpExecutionResultView
} from './execution-port'

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
  family: LegacyV1VulnerabilityFamily
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
    version: '1.0.0',
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
    version: '1.0.0',
    family: 'idor',
    requiredChecks: [
      'owner-resource-known',
      'both-identities-are-authorized-tests',
      'owner-read-succeeded',
      'second-identity-own-resource-read-succeeded',
      'second-identity-read-owner-resource',
      'cross-identity-response-matches-owner'
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
  const allSucceeded = observations.every(succeeded)
  const blocked = observations.some(looksBlocked)
  const trueRepeatSimilarity = responseSimilarity(input.trueFirst, input.trueRepeat)
  const baselineTrueSimilarity = responseSimilarity(input.baseline, input.trueFirst)
  const trueFalseSimilarity = responseSimilarity(input.trueFirst, input.falseControl)
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
    signalSummary: `布尔真条件重复相似度 ${trueRepeatSimilarity.toFixed(3)}，基线/真条件 ${baselineTrueSimilarity.toFixed(3)}，真/负对照 ${trueFalseSimilarity.toFixed(3)}。`,
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
  const verdict: Verdict = !httpSucceeded || !input.browser || !browserSucceeded
    ? 'inconclusive'
    : markerExecuted
      ? evidencePresent
        ? 'confirmed'
        : 'inconclusive'
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
    'cross-identity-response-matches-owner': similarity >= 0.95 && ownerBody.length > 0
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
  const verdict: Verdict = !input.identitiesAuthorized || anyFailedExecution
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
          ? '身份授权或请求执行条件不足，不能判断对象级授权。'
          : '跨身份请求被拒绝或响应没有满足资源归属与相似性确认规则。',
    confidence: verdict === 'confirmed' ? 0.98 : verdict === 'not-confirmed' ? 0.2 : 0.3,
    completedChecks,
    failedChecks,
    missingChecks:
      input.secondIdentityResourceId.length > 0 ? [] : ['second-identity-owned-resource']
  })
}
