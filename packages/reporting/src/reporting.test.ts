import { describe, expect, it } from 'vitest'
import { renderReport, type ReportContext } from './index'

const context: ReportContext = {
  scan: {
    id: 'scan-1',
    targetId: 'target-1',
    targetName: 'Local fixture',
    name: 'V1 scan',
    description: '验证搜索页的授权 XSS 测试背景。',
    scopeSnapshotId: 'scope-1',
    status: 'completed',
    phase: 'report',
    progress: 100,
    families: ['xss'],
    modelProfileIds: {
      planner: 'planner-profile',
      knowledge: 'knowledge-profile',
      strategy: 'strategy-profile',
      analysis: 'analysis-profile',
      verifier: 'verifier-profile'
    },
    budget: {
      maxRequests: 20,
      maxRequestsPerMinute: 10,
      maxConcurrency: 1,
      maxPlanRevisions: 1,
      maxDurationMinutes: 10,
      maxModelTokens: 1_000,
      maxEstimatedCost: 1,
      maxRequestBytes: 20 * 1_146_880,
      maxResponseBytes: 20 * 16_777_216
    },
    requestCount: 3,
    modelTokens: 10,
    estimatedCost: 0,
    checkpointCount: 7,
    createdAt: '2026-07-10T00:00:00.000Z',
    updatedAt: '2026-07-10T00:01:00.000Z'
  },
  target: {
    id: 'target-1',
    workspaceId: 'workspace-1',
    name: '<script>alert(1)</script>',
    baseUrl: 'https://lab.example.test/',
    description: '',
    authorizationReference: 'owner approval',
    createdAt: '2026-07-10T00:00:00.000Z',
    updatedAt: '2026-07-10T00:00:00.000Z'
  },
  scope: {
    id: 'scope-1',
    targetId: 'target-1',
    revision: 1,
    allowedOrigins: ['https://lab.example.test'],
    allowedPathPrefixes: ['/'],
    deniedPathPrefixes: [],
    allowedPorts: [443],
    allowedIdentityIds: [],
    allowActiveProbing: true,
    allowSensitiveProbing: false,
    allowPrivateNetworkTargets: false,
    allowLoopbackTargets: false,
    networkEntries: [],
    maxRequestsPerMinute: 10,
    maxConcurrency: 1,
    snapshotHash: 'hash',
    createdAt: '2026-07-10T00:00:00.000Z'
  },
  findings: [],
  evidence: [],
  generatedAt: '2026-07-10T00:02:00.000Z'
}

describe('report rendering', () => {
  it('escapes untrusted HTML and includes a restrictive CSP', () => {
    const report = renderReport(context, 'html')

    expect(report.content).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
    expect(report.content).not.toContain('<script>alert(1)</script>')
    expect(report.content).toContain("default-src 'none'")
    expect(report.content).toContain('验证搜索页的授权 XSS 测试背景。')
    expect(report.content).toContain('planner-profile')
    expect(report.sha256).toHaveLength(64)
  })

  it('records the engagement description and frozen model routing in JSON reports', () => {
    const report = renderReport(context, 'json')
    const parsed = JSON.parse(report.content) as {
      scan: { description: string; modelProfileIds: Record<string, string> }
    }

    expect(parsed.scan.description).toBe('验证搜索页的授权 XSS 测试背景。')
    expect(parsed.scan.modelProfileIds.verifier).toBe('verifier-profile')
  })

  it('falls back to an open family ID when no display label is available', () => {
    const openFamilyContext: ReportContext = {
      ...context,
      scan: {
        ...context.scan,
        families: ['security.headers']
      },
      findings: [{
        id: 'finding-security-headers',
        scanId: context.scan.id,
        family: 'security.headers',
        title: 'Security header review',
        verdict: 'not-confirmed',
        status: 'reviewed',
        severity: 'info',
        confidence: 1,
        evidenceRefs: [],
        confirmationRuleId: 'security.headers.rule',
        confirmationRuleVersion: '1.0.0',
        reproducibility: 'Existing response headers were reviewed without network execution.',
        remediation: [],
        firstSeenAt: '2026-07-10T00:00:00.000Z',
        lastVerifiedAt: '2026-07-10T00:01:00.000Z'
      }]
    }

    expect(renderReport(openFamilyContext, 'markdown').content).toContain(
      '- 漏洞族：security.headers'
    )
    expect(renderReport(openFamilyContext, 'html').content).toContain(
      '<dt>漏洞族</dt><dd>security.headers</dd>'
    )
  })
})
