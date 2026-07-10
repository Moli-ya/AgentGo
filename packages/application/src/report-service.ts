import type { GenerateReportInput, ReportRecord } from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  redactEvidenceText
} from '@agentgo/db'
import { renderReport } from '@agentgo/reporting'

export interface ReportContent {
  report: ReportRecord
  content: Buffer
  extension: '.md' | '.json' | '.html'
}

export class ReportService {
  constructor(
    private readonly repository: AgentGoRepository,
    private readonly evidenceStore: EvidenceStore
  ) {}

  async generate(input: GenerateReportInput): Promise<ReportRecord> {
    const scan = await this.repository.getScan(input.scanId)
    if (!scan) throw new Error('扫描不存在。')
    const target = await this.repository.getTarget(scan.targetId)
    if (!target) throw new Error('扫描目标不存在。')
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!scope) throw new Error('扫描 Scope 快照不存在。')
    const findings = await this.repository.listFindings({ scanId: input.scanId })
    const evidence = await this.evidenceStore.list(input.scanId)
    const rendered = renderReport(
      { scan, target, scope, findings, evidence },
      input.format
    )
    const content = input.redacted
      ? redactEvidenceText(rendered.content)
      : rendered.content
    const stored = await this.evidenceStore.save({
      workspaceId: target.workspaceId,
      scanId: input.scanId,
      type: `report-${input.format}`,
      mimeType: rendered.mimeType,
      content,
      source: 'reporting',
      createdBy: 'report-service',
      captureTool: 'agentgo-reporting',
      captureToolVersion: '1.0.0',
      redactionState: input.redacted ? 'redacted' : 'original'
    })
    const report = await this.repository.createReport({
      scanId: input.scanId,
      title: rendered.title,
      format: input.format,
      sha256: stored.sha256,
      redacted: input.redacted,
      contentRef: stored.id
    })
    await this.repository.addAuditLog({
      workspaceId: target.workspaceId,
      scanId: input.scanId,
      event: 'report.generated',
      actor: 'system',
      detail: {
        reportId: report.id,
        format: report.format,
        redacted: report.redacted,
        contentRef: stored.id
      }
    })
    return report
  }

  list(scanId: string): Promise<ReportRecord[]> {
    return this.repository.listReports(scanId)
  }

  async read(reportId: string): Promise<ReportContent> {
    const report = await this.repository.getReport(reportId)
    if (!report) throw new Error('报告不存在。')
    const evidence = await this.evidenceStore.read(report.contentRef)
    return {
      report,
      content: evidence.content,
      extension:
        report.format === 'json'
          ? '.json'
          : report.format === 'html'
            ? '.html'
            : '.md'
    }
  }

  async markExported(reportId: string, filePath: string): Promise<void> {
    const report = await this.repository.getReport(reportId)
    if (!report) throw new Error('报告不存在。')
    const scan = await this.repository.getScan(report.scanId)
    if (!scan) throw new Error('报告所属扫描不存在。')
    const target = await this.repository.getTarget(scan.targetId)
    if (!target) throw new Error('报告所属目标不存在。')
    await this.repository.markReportExported(reportId, filePath)
    await this.repository.addAuditLog({
      workspaceId: target.workspaceId,
      scanId: scan.id,
      event: 'report.exported',
      actor: 'user',
      detail: { reportId, filePath, redacted: report.redacted }
    })
  }
}
