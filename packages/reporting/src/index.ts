import { createHash } from 'node:crypto'
import { isLegacyV1VulnerabilityFamily } from '@agentgo/contracts'
import type {
  AgentRole,
  EvidenceSummary,
  FindingRecord,
  LegacyV1VulnerabilityFamily,
  ScanRecord,
  TargetRecord,
  TargetScopeRecord,
  VulnerabilityFamily
} from '@agentgo/contracts'
import type { Finding } from '@agentgo/domain'

export interface ReportOutline {
  confirmed: Finding[]
  inconclusive: Finding[]
  notConfirmed: Finding[]
  safetyStatement: string
}

export interface ReportContext {
  scan: ScanRecord
  target: TargetRecord
  scope: TargetScopeRecord
  findings: FindingRecord[]
  evidence: EvidenceSummary[]
  generatedAt?: string
}

export interface RenderedReport {
  title: string
  format: 'markdown' | 'json' | 'html'
  mimeType: string
  extension: '.md' | '.json' | '.html'
  content: string
  sha256: string
}

const legacyFamilyLabels: Record<LegacyV1VulnerabilityFamily, string> = {
  sqli: 'SQL 注入',
  xss: '跨站脚本（XSS）',
  ssrf: '服务端请求伪造（SSRF）',
  idor: '对象级越权（IDOR）'
}

function familyLabel(familyId: VulnerabilityFamily): string {
  const label = isLegacyV1VulnerabilityFamily(familyId)
    ? legacyFamilyLabels[familyId]
    : undefined
  return label ?? familyId
}

const verdictLabels: Record<FindingRecord['verdict'], string> = {
  confirmed: 'Confirmed',
  'not-confirmed': 'Not Confirmed',
  inconclusive: 'Inconclusive'
}

const reportAgentRoles: AgentRole[] = [
  'planner',
  'knowledge',
  'strategy',
  'analysis',
  'verifier'
]

const agentRoleLabels: Record<AgentRole, string> = {
  planner: 'PlannerAgent',
  knowledge: 'KnowledgeAgent',
  strategy: 'StrategyAgent',
  analysis: 'AnalysisAgent',
  verifier: 'VerifierAgent'
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function markdownText(value: string): string {
  return value.replace(/[\\`*_{}\[\]()#+.!|>-]/g, '\\$&')
}

function htmlText(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function findingJson(finding: FindingRecord): Record<string, unknown> {
  return {
    id: finding.id,
    family: finding.family,
    verdict: finding.verdict,
    severity: finding.severity,
    confidence: finding.confidence,
    title: finding.title,
    endpointUrl: finding.endpointUrl,
    parameterName: finding.parameterName,
    identityLabel: finding.identityLabel,
    cwe: finding.cwe,
    owasp: finding.owasp,
    confirmationRule: {
      id: finding.confirmationRuleId,
      version: finding.confirmationRuleVersion
    },
    reproducibility: finding.reproducibility,
    evidenceRefs: finding.evidenceRefs,
    remediation: finding.remediation,
    firstSeenAt: finding.firstSeenAt,
    lastVerifiedAt: finding.lastVerifiedAt
  }
}

function renderJson(context: ReportContext, generatedAt: string): string {
  return JSON.stringify(
    {
      schemaVersion: 'agentgo-report/1.0',
      generatedAt,
      safetyStatement:
        '本报告仅记录明确授权范围内的低影响、非破坏验证；系统永久禁止破坏性数据操作和越界访问。',
      target: {
        id: context.target.id,
        name: context.target.name,
        baseUrl: context.target.baseUrl,
        authorizationReference: context.target.authorizationReference,
        scopeSnapshotId: context.scope.id,
        allowedOrigins: context.scope.allowedOrigins,
        allowedPathPrefixes: context.scope.allowedPathPrefixes,
        deniedPathPrefixes: context.scope.deniedPathPrefixes
      },
      scan: {
        id: context.scan.id,
        name: context.scan.name,
        description: context.scan.description,
        status: context.scan.status,
        phase: context.scan.phase,
        families: context.scan.families,
        modelProfileIds: context.scan.modelProfileIds,
        requestCount: context.scan.requestCount,
        modelTokens: context.scan.modelTokens,
        startedAt: context.scan.startedAt,
        completedAt: context.scan.completedAt
      },
      summary: {
        confirmed: context.findings.filter((item) => item.verdict === 'confirmed').length,
        inconclusive: context.findings.filter((item) => item.verdict === 'inconclusive').length,
        notConfirmed: context.findings.filter((item) => item.verdict === 'not-confirmed').length,
        evidenceItems: context.evidence.length
      },
      findings: context.findings.map(findingJson),
      evidence: context.evidence
    },
    null,
    2
  )
}

function renderMarkdown(context: ReportContext, generatedAt: string): string {
  const sections = context.findings.map((finding, index) => {
    const location = [finding.endpointUrl, finding.parameterName, finding.identityLabel]
      .filter(Boolean)
      .join(' / ')
    const evidence = finding.evidenceRefs.length
      ? finding.evidenceRefs.map((ref) => `- \`${ref}\``).join('\n')
      : '- 无（因此不得作为 Confirmed 结论）'
    const remediation = finding.remediation.length
      ? finding.remediation.map((item) => `- ${markdownText(item)}`).join('\n')
      : '- 结合实际代码路径补充修复方案。'
    return `## ${index + 1}. ${markdownText(finding.title)}

- 漏洞族：${familyLabel(finding.family)}
- Verdict：${verdictLabels[finding.verdict]}
- 严重度：${finding.severity}
- 置信度：${Math.round(finding.confidence * 100)}%
- 位置：${location ? markdownText(location) : '未定位到单一参数'}
- 规则：\`${finding.confirmationRuleId}@${finding.confirmationRuleVersion}\`
- CWE / OWASP：${markdownText([finding.cwe, finding.owasp].filter(Boolean).join(' / ') || '待映射')}

### 复现与结论边界

${markdownText(finding.reproducibility)}

### 证据引用

${evidence}

### 修复建议

${remediation}`
  })

  return `# ${markdownText(context.scan.name)} — AgentGo 授权安全验证报告

生成时间：${generatedAt}

## 安全与授权声明

本报告仅记录明确授权范围内的低影响、非破坏验证；系统未执行 DROP/TRUNCATE、生产数据增删改、持久化、横向移动、凭据喷洒、高强度 DoS、云元数据访问或越界访问。

## 目标与 Scope

- 目标：${markdownText(context.target.name)}
- Base URL：${markdownText(context.target.baseUrl)}
- 授权依据：${markdownText(context.target.authorizationReference)}
- Scope 快照：\`${context.scope.id}\`
- 允许 Origin：${context.scope.allowedOrigins.map(markdownText).join('、')}
- 允许路径：${context.scope.allowedPathPrefixes.map(markdownText).join('、')}
- 拒绝路径：${context.scope.deniedPathPrefixes.length ? context.scope.deniedPathPrefixes.map(markdownText).join('、') : '无额外路径'}

## 任务与 Agent 路由

${markdownText(context.scan.description || '旧任务未记录任务与授权背景。')}

${reportAgentRoles.map((role) => `- ${agentRoleLabels[role]} Profile：${context.scan.modelProfileIds[role] ? `\`${context.scan.modelProfileIds[role]}\`` : '未记录'}`).join('\n')}

## 扫描摘要

- 状态：${context.scan.status} / ${context.scan.phase}
- 漏洞族：${context.scan.families.map((family) => familyLabel(family)).join('、')}
- 请求数：${context.scan.requestCount}
- 模型 Token：${context.scan.modelTokens}
- Finding：Confirmed ${context.findings.filter((item) => item.verdict === 'confirmed').length}，Inconclusive ${context.findings.filter((item) => item.verdict === 'inconclusive').length}，Not Confirmed ${context.findings.filter((item) => item.verdict === 'not-confirmed').length}
- 证据项：${context.evidence.length}

${sections.length ? sections.join('\n\n---\n\n') : '## Findings\n\n本次扫描没有生成 Finding。'}
`
}

function renderHtml(context: ReportContext, generatedAt: string): string {
  const findingSections = context.findings
    .map(
      (finding) => `<section class="finding">
  <h2>${htmlText(finding.title)}</h2>
  <dl>
    <dt>漏洞族</dt><dd>${htmlText(familyLabel(finding.family))}</dd>
    <dt>Verdict</dt><dd>${htmlText(verdictLabels[finding.verdict])}</dd>
    <dt>严重度</dt><dd>${htmlText(finding.severity)}</dd>
    <dt>位置</dt><dd>${htmlText([finding.endpointUrl, finding.parameterName, finding.identityLabel].filter(Boolean).join(' / ') || '未定位到单一参数')}</dd>
    <dt>确认规则</dt><dd><code>${htmlText(`${finding.confirmationRuleId}@${finding.confirmationRuleVersion}`)}</code></dd>
  </dl>
  <h3>复现与结论边界</h3><p>${htmlText(finding.reproducibility)}</p>
  <h3>证据引用</h3><ul>${finding.evidenceRefs.map((ref) => `<li><code>${htmlText(ref)}</code></li>`).join('')}</ul>
  <h3>修复建议</h3><ul>${finding.remediation.map((item) => `<li>${htmlText(item)}</li>`).join('')}</ul>
</section>`
    )
    .join('\n')
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${htmlText(context.scan.name)} — AgentGo 报告</title>
<style>body{max-width:960px;margin:40px auto;padding:0 24px;color:#18212f;background:#fff;font:15px/1.65 system-ui,sans-serif}h1,h2,h3{line-height:1.25}section{border-top:1px solid #d8dee8;padding:24px 0}dl{display:grid;grid-template-columns:110px 1fr;gap:6px 16px}dt{font-weight:700}dd{margin:0}code{overflow-wrap:anywhere}.notice{padding:14px 16px;background:#f3f6fa;border-left:4px solid #315d8a}</style></head>
<body><h1>${htmlText(context.scan.name)} — AgentGo 授权安全验证报告</h1>
<p>生成时间：${htmlText(generatedAt)}</p>
<p class="notice">本报告仅记录明确授权范围内的低影响、非破坏验证；系统永久禁止破坏性数据操作和越界访问。</p>
<h2>目标与 Scope</h2><p>${htmlText(context.target.name)} · ${htmlText(context.target.baseUrl)}</p>
<p>授权依据：${htmlText(context.target.authorizationReference)}；Scope 快照：<code>${htmlText(context.scope.id)}</code></p>
<h2>任务与 Agent 路由</h2><p>${htmlText(context.scan.description || '旧任务未记录任务与授权背景。')}</p>
<ul>${reportAgentRoles.map((role) => `<li>${htmlText(agentRoleLabels[role])} Profile：${context.scan.modelProfileIds[role] ? `<code>${htmlText(context.scan.modelProfileIds[role]!)}</code>` : '未记录'}</li>`).join('')}</ul>
<h2>扫描摘要</h2><p>状态 ${htmlText(context.scan.status)}；请求 ${context.scan.requestCount}；证据 ${context.evidence.length}；Finding ${context.findings.length}。</p>
${findingSections || '<h2>Findings</h2><p>本次扫描没有生成 Finding。</p>'}</body></html>`
}

export function renderReport(
  context: ReportContext,
  format: RenderedReport['format']
): RenderedReport {
  const generatedAt = context.generatedAt ?? new Date().toISOString()
  const title = `${context.scan.name} — AgentGo 授权安全验证报告`
  const content =
    format === 'json'
      ? renderJson(context, generatedAt)
      : format === 'html'
        ? renderHtml(context, generatedAt)
        : renderMarkdown(context, generatedAt)
  return {
    title,
    format,
    mimeType:
      format === 'json'
        ? 'application/json'
        : format === 'html'
          ? 'text/html'
          : 'text/markdown',
    extension: format === 'json' ? '.json' : format === 'html' ? '.html' : '.md',
    content,
    sha256: sha256(content)
  }
}

export function buildReportOutline(findings: Finding[]): ReportOutline {
  return {
    confirmed: findings.filter((finding) => finding.verdict === 'confirmed'),
    inconclusive: findings.filter((finding) => finding.verdict === 'inconclusive'),
    notConfirmed: findings.filter((finding) => finding.verdict === 'not-confirmed'),
    safetyStatement:
      '本报告仅记录授权范围内的低影响验证，未执行破坏性数据操作。'
  }
}
