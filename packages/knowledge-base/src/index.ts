import type { VulnerabilityFamily } from '@agentgo/contracts'

export interface KnowledgeSource {
  id: string
  title: string
  url: string
  license: string
  trustLevel: 'built-in' | 'official' | 'reviewed-public'
  updatedAt: string
}

export interface KnowledgeEntry {
  id: string
  version: string
  family: VulnerabilityFamily
  title: string
  applicability: string[]
  signals: string[]
  safeProbePrinciples: string[]
  confirmationRules: string[]
  falsePositivePatterns: string[]
  remediationHints: string[]
  forbiddenActions: string[]
  sourceRefs: string[]
}

export interface KnowledgeQuery {
  families: VulnerabilityFamily[]
  techTags: string[]
  signalTerms: string[]
  tokenBudget: number
}

export interface KnowledgePack {
  query: KnowledgeQuery
  matchedEntryIds: string[]
  vulnerabilityFamilies: VulnerabilityFamily[]
  applicability: string[]
  hypotheses: Array<{
    family: VulnerabilityFamily
    statement: string
    evidenceNeeded: string[]
  }>
  safeProbePrinciples: string[]
  confirmationRules: string[]
  falsePositivePatterns: string[]
  remediationHints: string[]
  policyConstraints: string[]
  sourceRefs: KnowledgeSource[]
  freshness: string
  confidence: number
  tokenEstimate: number
}

export interface KnowledgeContentInspection {
  safeForAutomaticIndexing: boolean
  flags: string[]
}

export const KNOWLEDGE_SOURCES: KnowledgeSource[] = [
  {
    id: 'owasp-wstg',
    title: 'OWASP Web Security Testing Guide',
    url: 'https://owasp.org/www-project-web-security-testing-guide/',
    license: 'CC BY-SA 4.0',
    trustLevel: 'official',
    updatedAt: '2026-07-10'
  },
  {
    id: 'cwe',
    title: 'Common Weakness Enumeration',
    url: 'https://cwe.mitre.org/',
    license: 'CWE Terms of Use',
    trustLevel: 'official',
    updatedAt: '2026-07-10'
  },
  {
    id: 'agentgo-policy',
    title: 'AgentGo Active Probing Policy',
    url: 'docs/security/active-probing-policy.md',
    license: 'project-internal documentation',
    trustLevel: 'built-in',
    updatedAt: '2026-07-10'
  }
]

export const V1_KNOWLEDGE_ENTRIES: KnowledgeEntry[] = [
  {
    id: 'sqli-safe-validation',
    version: '1.0.0',
    family: 'sqli',
    title: 'SQL 注入非写入式差异验证',
    applicability: ['用户输入影响服务端数据库查询', '存在可重复请求基线'],
    signals: ['布尔条件导致稳定差异', '受限时间差异', '数据库相关错误特征'],
    safeProbePrinciples: ['只使用非写入式差异验证', '设置超时和重复次数', '始终加入负对照'],
    confirmationRules: ['差异可重复', '负对照不出现同等差异', '排除缓存和网络抖动'],
    falsePositivePatterns: ['通用 500 页面', '缓存命中差异', '后端随机延迟'],
    remediationHints: ['使用参数化查询', '对动态标识符使用允许列表', '增加数据库错误处理'],
    forbiddenActions: ['DROP/TRUNCATE/ALTER', 'DELETE/UPDATE/INSERT', '读取真实敏感数据'],
    sourceRefs: ['owasp-wstg', 'cwe', 'agentgo-policy']
  },
  {
    id: 'xss-inert-marker',
    version: '1.0.0',
    family: 'xss',
    title: 'XSS 惰性标记与隔离浏览器验证',
    applicability: ['用户输入进入 HTML、属性、URL 或 JavaScript 上下文'],
    signals: ['输入被反射', 'DOM sink 接收可控值', '上下文编码不完整'],
    safeProbePrinciples: ['使用无外传能力的随机标记', '在隔离浏览器中观察', '存储场景使用测试对象并清理'],
    confirmationRules: ['标记在目标上下文实际执行', '执行与输入存在直接因果关系', '证据包含 DOM 和截图'],
    falsePositivePatterns: ['只反射未执行', '浏览器扩展注入', '安全转义后的文本展示'],
    remediationHints: ['按输出上下文编码', '避免危险 DOM sink', '部署严格 CSP 作为纵深防御'],
    forbiddenActions: ['窃取 Cookie/Token', '影响真实用户', '植入持久恶意内容'],
    sourceRefs: ['owasp-wstg', 'cwe', 'agentgo-policy']
  },
  {
    id: 'ssrf-controlled-callback',
    version: '1.0.0',
    family: 'ssrf',
    title: 'SSRF 受控回连验证',
    applicability: ['服务端根据用户输入获取 URL 或资源'],
    signals: ['受控端点收到服务端请求', '目标返回远端内容特征', '重定向后发生服务端访问'],
    safeProbePrinciples: ['仅使用项目控制回连端点', '每次重定向与 DNS 解析重新检查 scope', '限制协议和地址'],
    confirmationRules: ['回连记录与测试请求具有唯一关联', '排除浏览器端请求', '重复验证仍可观察'],
    falsePositivePatterns: ['客户端浏览器直接请求', '第三方预取服务', '缓存的历史回连'],
    remediationHints: ['服务端 URL allowlist', '阻断私网和元数据地址', '限制协议并固定 DNS/重定向策略'],
    forbiddenActions: ['云元数据访问', '未授权内网扫描', '访问回环或越界地址'],
    sourceRefs: ['owasp-wstg', 'cwe', 'agentgo-policy']
  },
  {
    id: 'idor-two-identity-readonly',
    version: '1.0.0',
    family: 'idor',
    title: '越权双身份只读对照',
    applicability: ['接口通过对象标识符访问资源', '存在两个授权测试身份'],
    signals: ['身份 B 可读取身份 A 的测试资源', '服务端只校验登录未校验对象归属'],
    safeProbePrinciples: ['只使用专用测试账号和资源', '优先只读访问', '确认后停止扩大枚举'],
    confirmationRules: ['资源归属已知', '两个身份请求仅授权上下文不同', '越权响应包含最小必要证据'],
    falsePositivePatterns: ['资源本来公开', '共享团队资源', '测试账号具有合法管理员权限'],
    remediationHints: ['每次请求执行对象级授权', '避免只依赖客户端隐藏', '为资源访问增加策略测试'],
    forbiddenActions: ['修改或删除其他身份资源', '批量枚举真实用户数据', '真实账号接管'],
    sourceRefs: ['owasp-wstg', 'cwe', 'agentgo-policy']
  }
]

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function scoreEntry(entry: KnowledgeEntry, query: KnowledgeQuery): number {
  const searchable = [
    entry.title,
    ...entry.applicability,
    ...entry.signals,
    ...entry.falsePositivePatterns,
    ...entry.remediationHints
  ]
    .join(' ')
    .toLowerCase()

  const signalScore = query.signalTerms.reduce(
    (score, term) => score + (searchable.includes(term.toLowerCase()) ? 2 : 0),
    0
  )
  const techScore = query.techTags.reduce(
    (score, tag) => score + (searchable.includes(tag.toLowerCase()) ? 1 : 0),
    0
  )

  return 10 + signalScore + techScore
}

export function inspectKnowledgeContent(content: string): KnowledgeContentInspection {
  const rules = [
    {
      label: 'instruction-override',
      pattern: /ignore\s+(?:all\s+)?previous\s+instructions?/i
    },
    {
      label: 'system-prompt-request',
      pattern: /(?:reveal|print|return).{0,24}system\s+prompt/i
    },
    {
      label: 'tool-execution-instruction',
      pattern: /(?:call|execute|run).{0,24}(?:tool|shell|command)/i
    },
    {
      label: 'chinese-instruction-override',
      pattern: /忽略.{0,12}(?:此前|之前|系统).{0,12}(?:指令|规则)/
    }
  ]
  const flags = rules
    .filter((rule) => rule.pattern.test(content))
    .map((rule) => rule.label)

  return {
    safeForAutomaticIndexing: flags.length === 0,
    flags
  }
}

export function buildKnowledgePack(query: KnowledgeQuery): KnowledgePack {
  const entries = V1_KNOWLEDGE_ENTRIES
    .filter((entry) => query.families.includes(entry.family))
    .sort((left, right) => scoreEntry(right, query) - scoreEntry(left, query))
  const sourceIds = unique(entries.flatMap((entry) => entry.sourceRefs))
  const maximumScore = entries[0] ? scoreEntry(entries[0], query) : 0

  return {
    query,
    matchedEntryIds: entries.map((entry) => entry.id),
    vulnerabilityFamilies: unique(entries.map((entry) => entry.family)),
    applicability: unique(entries.flatMap((entry) => entry.applicability)),
    hypotheses: entries.map((entry) => ({
      family: entry.family,
      statement: `目标特征可能符合“${entry.title}”的适用条件，需要按规则验证。`,
      evidenceNeeded: entry.confirmationRules
    })),
    safeProbePrinciples: unique(entries.flatMap((entry) => entry.safeProbePrinciples)),
    confirmationRules: unique(entries.flatMap((entry) => entry.confirmationRules)),
    falsePositivePatterns: unique(entries.flatMap((entry) => entry.falsePositivePatterns)),
    remediationHints: unique(entries.flatMap((entry) => entry.remediationHints)),
    policyConstraints: unique(entries.flatMap((entry) => entry.forbiddenActions)),
    sourceRefs: KNOWLEDGE_SOURCES.filter((source) => sourceIds.includes(source.id)),
    freshness: '2026-07-10',
    confidence: entries.length > 0 ? Math.min(0.95, 0.55 + maximumScore / 50) : 0,
    tokenEstimate: Math.min(query.tokenBudget, entries.length * 320)
  }
}
