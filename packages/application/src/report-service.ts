import {
  EvidenceSummarySchema,
  type EvidenceSummary,
  type GenerateReportInput,
  type ReportRecord
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  redactEvidenceText,
  type EvidenceItemRecord,
  type EvidenceReadResult,
  type StoredReportRecord
} from '@agentgo/db'
import { renderReport } from '@agentgo/reporting'

export interface ReportContent {
  report: ReportRecord
  content: Buffer
  extension: '.md' | '.json' | '.html'
}

const REPORT_CONTENT_BINDINGS = Object.freeze({
  markdown: Object.freeze({
    type: 'report-markdown',
    mimeType: 'text/markdown'
  }),
  json: Object.freeze({
    type: 'report-json',
    mimeType: 'application/json'
  }),
  html: Object.freeze({
    type: 'report-html',
    mimeType: 'text/html'
  })
} satisfies Readonly<
  Record<
    ReportRecord['format'],
    Readonly<{ type: string; mimeType: string }>
  >
>)

/**
 * Convert backend Evidence metadata into the exact cross-process contract.
 * File paths, workspace internals, capture tooling, plaintext commitments and
 * every other backend-only field are intentionally absent.
 */
export function projectEvidenceSummary(
  evidence: EvidenceItemRecord
): EvidenceSummary {
  const common = {
    id: evidence.id,
    scanId: evidence.scanId,
    type: evidence.type,
    mimeType: evidence.mimeType,
    sha256: evidence.sha256,
    size: evidence.size,
    integrityStatus: evidence.integrityStatus,
    createdAt: evidence.createdAt
  }
  const summary =
    evidence.protectionState === 'protected-original'
      ? {
          ...common,
          redactionState: 'original' as const,
          protectionState: 'protected-original' as const,
          availabilityState: evidence.availabilityState,
          retentionUntil: evidence.retentionUntil
        }
      : {
          ...common,
          redactionState: evidence.redactionState,
          protectionState: 'unprotected' as const,
          ...(evidence.derivedFrom
            ? { derivedFrom: evidence.derivedFrom }
            : {}),
          ...(evidence.retentionUntil
            ? { retentionUntil: evidence.retentionUntil }
            : {})
        }
  return Object.freeze(EvidenceSummarySchema.parse(summary))
}

export function projectReportEvidenceSummaries(
  evidence: readonly EvidenceItemRecord[]
): EvidenceSummary[] {
  return evidence
    .filter(
      (item) =>
        item.protectionState === 'unprotected' &&
        item.redactionState === 'redacted'
    )
    .map(projectEvidenceSummary)
}

function assertReportContentBinding(
  report: StoredReportRecord,
  evidence: EvidenceItemRecord
): void {
  const expected = REPORT_CONTENT_BINDINGS[report.format]
  if (
    report.redacted !== true ||
    evidence.id !== report.contentRef ||
    evidence.scanId !== report.scanId ||
    evidence.protectionState !== 'unprotected' ||
    evidence.redactionState !== 'redacted' ||
    evidence.type !== expected.type ||
    evidence.mimeType !== expected.mimeType ||
    evidence.sha256 !== report.sha256 ||
    evidence.integrityStatus !== 'verified'
  ) {
    throw new Error(
      'Report content is not an exact redacted, unprotected scan artifact.'
    )
  }
}

export interface ReportServiceOptions {
  readonly familyDisplayNames?: Readonly<Record<string, string>>
}

export class ReportService {
  private readonly familyDisplayNames: Readonly<Record<string, string>>

  constructor(
    private readonly repository: AgentGoRepository,
    private readonly evidenceStore: EvidenceStore,
    options: ReportServiceOptions = {}
  ) {
    this.familyDisplayNames = options.familyDisplayNames ?? {}
  }

  async generate(input: GenerateReportInput): Promise<ReportRecord> {
    if (input.redacted !== true) {
      throw new Error('Reports must be redacted before persistence or export.')
    }
    const scan = await this.repository.getScan(input.scanId)
    if (!scan) throw new Error('扫描不存在。')
    const target = await this.repository.getTarget(scan.targetId)
    if (!target) throw new Error('扫描目标不存在。')
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!scope) throw new Error('扫描 Scope 快照不存在。')
    const findings = await this.repository.listFindings({ scanId: input.scanId })
    const evidence = projectReportEvidenceSummaries(
      await this.evidenceStore.list(input.scanId)
    )
    const rendered = renderReport(
      {
        scan,
        target,
        scope,
        findings,
        evidence,
        familyDisplayNames: this.familyDisplayNames
      },
      input.format
    )
    const content = redactEvidenceText(rendered.content)
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
      redactionState: 'redacted'
    })
    const report = await this.repository.createReport({
      scanId: input.scanId,
      title: rendered.title,
      format: input.format,
      sha256: stored.sha256,
      redacted: true,
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
    const evidence = await this.#readValidatedContent(report)
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
    await this.#readValidatedContent(report)
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

  async #readValidatedContent(
    report: StoredReportRecord
  ): Promise<EvidenceReadResult> {
    if (report.redacted !== true) {
      throw new Error('Unredacted reports cannot be read or exported.')
    }
    const metadata = await this.evidenceStore.getMetadata(report.contentRef)
    if (!metadata) {
      throw new Error('Report content Evidence does not exist.')
    }
    assertReportContentBinding(report, metadata)
    const evidence = await this.evidenceStore.read(report.contentRef)
    assertReportContentBinding(report, evidence.metadata)
    return evidence
  }
}
