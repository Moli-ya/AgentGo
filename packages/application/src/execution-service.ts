import { randomUUID } from 'node:crypto'
import type {
  BrowserExecutionRequest,
  BrowserExecutionResult,
  BrowserRunner
} from '@agentgo/browser-runner'
import type {
  HttpExecutionRequest,
  HttpExecutionResult,
  HttpRunner
} from '@agentgo/http-runner'
import {
  redactInventoryPreview,
  redactInventoryText,
  redactInventoryUrlPreview
} from '@agentgo/domain'
import {
  AgentGoRepository,
  EvidenceStore,
  isTextualEvidenceMimeType,
  sha256Text,
  stableJson
} from '@agentgo/db'

export interface StoredExecutionResult<TResult> {
  result: TResult
  interactionId?: string
  evidenceRefs: string[]
  toolCallId: string
}

function redactedExecutionUrl(value: string): string {
  try {
    return redactInventoryUrlPreview(value)
  } catch {
    return 'https://redacted.invalid/'
  }
}

function redactedExecutionHeaders(
  targetUrl: string,
  headers: Record<string, string>
): Record<string, string> {
  return redactInventoryPreview({ url: targetUrl, headers }).headers ?? {}
}

export class ExecutionService {
  constructor(
    private readonly repository: AgentGoRepository,
    private readonly evidenceStore: EvidenceStore,
    private readonly httpRunner: HttpRunner,
    private readonly browserRunner: BrowserRunner
  ) {}

  async executeHttp(input: {
    scanId: string
    policyDecisionId: string
    endpointId?: string
    signal?: AbortSignal
    request: Omit<HttpExecutionRequest, 'requestId' | 'policyDecisionId'>
  }): Promise<StoredExecutionResult<HttpExecutionResult>> {
    const context = await this.repository.getExecutionDecision(input.policyDecisionId)
    if (!context || context.scanId !== input.scanId) {
      throw new Error('HTTP execution is not bound to this scan and policy decision.')
    }
    const requestId = randomUUID()
    const request: HttpExecutionRequest = {
      ...input.request,
      requestId,
      policyDecisionId: input.policyDecisionId
    }
    if (input.signal?.aborted) throw new Error('HTTP execution was cancelled before start.')
    const requestBodyHash =
      request.body === undefined
        ? undefined
        : sha256Text(
            typeof request.body === 'string'
              ? request.body
              : Buffer.from(request.body).toString('base64')
          )
    const argumentSummary = {
      targetUrl: redactedExecutionUrl(request.targetUrl),
      targetUrlHash: sha256Text(request.targetUrl),
      method: request.method,
      headerNames: Object.keys(request.headers ?? {}).map((name) => name.toLowerCase()),
      requestBodyHash,
      timeoutMs: request.timeoutMs,
      maxResponseBytes: request.maxResponseBytes,
      maxRedirects: request.maxRedirects
    }
    const toolCallId = await this.repository.recordToolCall({
      scanId: input.scanId,
      policyDecisionId: input.policyDecisionId,
      toolName: 'http-runner',
      toolVersion: '1.0.0',
      argumentHash: sha256Text(stableJson(argumentSummary)),
      status: 'running'
    })

    const abort = (): void => {
      void this.httpRunner.cancel(requestId)
    }
    const executionStartedAt = Date.now()
    input.signal?.addEventListener('abort', abort, { once: true })
    let result: HttpExecutionResult
    try {
      result = await this.httpRunner.execute(request)
    } catch (error) {
      const durationMs = Date.now() - executionStartedAt
      const status = input.signal?.aborted ? 'cancelled' : 'failed'
      const message = redactInventoryText(
        error instanceof Error ? error.message : 'HTTP runner threw an unknown error.'
      )
      await this.repository.updateToolCall({
        id: toolCallId,
        status,
        durationMs,
        error: message
      })
      await this.repository.incrementScanUsage({ scanId: input.scanId, requests: 1 })
      await this.repository.addScanEvent({
        scanId: input.scanId,
        type: 'execution',
        level: 'error',
        message: `HTTP 执行器异常终止：${message}`,
        detail: {
          requestId,
          toolCallId,
          policyDecisionId: input.policyDecisionId,
          endState: status
        }
      })
      throw new Error(`HTTP runner failed: ${message}`)
    } finally {
      input.signal?.removeEventListener('abort', abort)
    }
    const interactionId = randomUUID()
    const responseSummary = {
      requestId,
      status: result.status,
      statusCode: result.statusCode,
      headers: redactedExecutionHeaders(request.targetUrl, result.responseHeaders),
      responseBodySha256: result.responseBodySha256,
      responseBytes: result.responseBytes,
      durationMs: result.durationMs,
      redirectChain: result.redirectChain.map((redirect) => ({
        ...redirect,
        from: redactedExecutionUrl(redirect.from),
        to: redactedExecutionUrl(redirect.to)
      })),
      resolvedAddresses: result.resolvedAddresses,
      errorCode: result.errorCode,
      errorMessage: result.errorMessage
        ? redactInventoryText(result.errorMessage)
        : undefined
    }
    await this.repository.recordInteraction({
      id: interactionId,
      scanId: input.scanId,
      ...(input.endpointId ? { endpointId: input.endpointId } : {}),
      ...(context.proposal.action.identityId
        ? { identityId: context.proposal.action.identityId }
        : {}),
      policyDecisionId: input.policyDecisionId,
      requestRef: 'pending-evidence',
      responseRef: 'pending-evidence',
      requestSummary: argumentSummary,
      responseSummary,
      ...(result.statusCode !== undefined ? { statusCode: result.statusCode } : {}),
      durationMs: result.durationMs
    })
    const requestEvidence = await this.evidenceStore.save({
      workspaceId: context.workspaceId,
      scanId: input.scanId,
      interactionId,
      policyDecisionId: input.policyDecisionId,
      type: 'http-request-summary',
      mimeType: 'application/json',
      content: JSON.stringify(
        {
          requestId,
          targetUrl: redactedExecutionUrl(request.targetUrl),
          targetUrlHash: sha256Text(request.targetUrl),
          finalUrl: redactedExecutionUrl(result.finalUrl),
          method: request.method,
          headers: redactedExecutionHeaders(request.targetUrl, result.requestHeaders),
          requestBodySha256: result.requestBodySha256,
          policyDecisionId: input.policyDecisionId
        },
        null,
        2
      ),
      source: 'http-runner',
      createdBy: 'execution-service',
      captureTool: 'undici',
      captureToolVersion: '7.16.0',
      redactionState: 'redacted'
    })

    const responseSummaryEvidence = await this.evidenceStore.save({
      workspaceId: context.workspaceId,
      scanId: input.scanId,
      interactionId,
      policyDecisionId: input.policyDecisionId,
      type: 'http-response-summary',
      mimeType: 'application/json',
      content: JSON.stringify(responseSummary, null, 2),
      source: 'http-runner',
      createdBy: 'execution-service',
      captureTool: 'undici',
      captureToolVersion: '7.16.0',
      redactionState: 'redacted'
    })
    const evidenceRefs = [requestEvidence.id, responseSummaryEvidence.id]
    let responseRef = responseSummaryEvidence.id

    if (result.responseBody) {
      const rawResponse = await this.evidenceStore.save({
        workspaceId: context.workspaceId,
        scanId: input.scanId,
        interactionId,
        policyDecisionId: input.policyDecisionId,
        type: 'http-response-body',
        mimeType:
          result.responseHeaders['content-type']?.split(';', 1)[0]?.trim() ||
          'application/octet-stream',
        content: result.responseBody,
        source: 'http-runner',
        createdBy: 'execution-service',
        captureTool: 'undici',
        captureToolVersion: '7.16.0',
        redactionState: 'original'
      })
      responseRef = rawResponse.id
      evidenceRefs.push(rawResponse.id)
      if (isTextualEvidenceMimeType(rawResponse.mimeType)) {
        const redacted = await this.evidenceStore.createRedactedTextDerivative(
          rawResponse.id,
          'execution-service'
        )
        evidenceRefs.push(redacted.id)
      }
    }

    await this.repository.updateInteraction({
      id: interactionId,
      requestRef: requestEvidence.id,
      responseRef,
      requestSummary: argumentSummary,
      responseSummary
    })
    await this.repository.updateToolCall({
      id: toolCallId,
      status: result.status,
      durationMs: result.durationMs,
      outputRef: responseRef,
      ...(result.errorMessage
        ? { error: redactInventoryText(result.errorMessage) }
        : {})
    })
    await this.repository.incrementScanUsage({ scanId: input.scanId, requests: 1 })
    await this.repository.addScanEvent({
      scanId: input.scanId,
      type: 'execution',
      level: result.status === 'succeeded' ? 'info' : 'warning',
      message:
        result.status === 'succeeded'
          ? `HTTP ${request.method.toUpperCase()} ${redactedExecutionUrl(result.finalUrl)} -> ${result.statusCode}`
          : `HTTP 执行未完成：${result.errorMessage ? redactInventoryText(result.errorMessage) : result.errorCode ?? 'unknown'}`,
      detail: {
        requestId,
        toolCallId,
        policyDecisionId: input.policyDecisionId,
        evidenceRefs
      }
    })
    return { result, interactionId, evidenceRefs, toolCallId }
  }

  async executeBrowser(input: {
    scanId: string
    policyDecisionId: string
    signal?: AbortSignal
    request: Omit<BrowserExecutionRequest, 'requestId' | 'policyDecisionId'>
  }): Promise<StoredExecutionResult<BrowserExecutionResult>> {
    const context = await this.repository.getExecutionDecision(input.policyDecisionId)
    if (!context || context.scanId !== input.scanId) {
      throw new Error('Browser execution is not bound to this scan and policy decision.')
    }
    const requestId = randomUUID()
    const request: BrowserExecutionRequest = {
      ...input.request,
      requestId,
      policyDecisionId: input.policyDecisionId
    }
    if (input.signal?.aborted) throw new Error('Browser execution was cancelled before start.')
    const toolCallId = await this.repository.recordToolCall({
      scanId: input.scanId,
      policyDecisionId: input.policyDecisionId,
      toolName: 'browser-runner',
      toolVersion: '1.0.0',
      argumentHash: sha256Text(
        stableJson({
          baseUrl: request.baseUrl,
          action: request.action,
          marker: request.marker,
          htmlSha256: sha256Text(request.html)
        })
      ),
      status: 'running'
    })
    const abort = (): void => {
      void this.browserRunner.cancel(requestId)
    }
    const executionStartedAt = Date.now()
    input.signal?.addEventListener('abort', abort, { once: true })
    let result: BrowserExecutionResult
    try {
      result = await this.browserRunner.execute(request)
    } catch (error) {
      const durationMs = Date.now() - executionStartedAt
      const status = input.signal?.aborted ? 'cancelled' : 'failed'
      const message = redactInventoryText(
        error instanceof Error ? error.message : 'Browser runner threw an unknown error.'
      )
      await this.repository.updateToolCall({
        id: toolCallId,
        status,
        durationMs,
        error: message
      })
      await this.repository.addScanEvent({
        scanId: input.scanId,
        type: 'execution',
        level: 'error',
        message: `隔离浏览器异常终止：${message}`,
        detail: {
          requestId,
          toolCallId,
          policyDecisionId: input.policyDecisionId,
          endState: status
        }
      })
      throw new Error(`Browser runner failed: ${message}`)
    } finally {
      input.signal?.removeEventListener('abort', abort)
    }
    const evidenceRefs: string[] = []
    let outputRef: string | undefined

    const summary = await this.evidenceStore.save({
      workspaceId: context.workspaceId,
      scanId: input.scanId,
      policyDecisionId: input.policyDecisionId,
      type: 'browser-execution-summary',
      mimeType: 'application/json',
      content: JSON.stringify(
        {
          requestId,
          status: result.status,
          finalUrl: redactedExecutionUrl(result.finalUrl),
          title: result.pageTitle
            ? redactInventoryText(result.pageTitle)
            : undefined,
          links: result.links.map(redactedExecutionUrl),
          forms: result.forms.map((form) => ({
            ...form,
            action: redactedExecutionUrl(form.action),
            fields: form.fields.map((field) => ({
              ...field,
              name: redactInventoryText(field.name, 500)
            }))
          })),
          markerExecuted: result.markerExecuted,
          networkRequestsBlocked: result.networkRequestsBlocked,
          durationMs: result.durationMs,
          errorCode: result.errorCode,
          errorMessage: result.errorMessage
            ? redactInventoryText(result.errorMessage)
            : undefined
        },
        null,
        2
      ),
      source: 'browser-runner',
      createdBy: 'execution-service',
      captureTool: 'playwright-core',
      captureToolVersion: '1.61.1',
      redactionState: 'redacted'
    })
    evidenceRefs.push(summary.id)
    outputRef = summary.id

    if (result.domSnapshot) {
      const dom = await this.evidenceStore.save({
        workspaceId: context.workspaceId,
        scanId: input.scanId,
        policyDecisionId: input.policyDecisionId,
        type: 'dom-snapshot',
        mimeType: 'text/html',
        content: result.domSnapshot,
        source: 'browser-runner',
        createdBy: 'execution-service',
        captureTool: 'playwright-core',
        captureToolVersion: '1.61.1',
        redactionState: 'original'
      })
      evidenceRefs.push(dom.id)
      const redacted = await this.evidenceStore.createRedactedTextDerivative(
        dom.id,
        'execution-service'
      )
      evidenceRefs.push(redacted.id)
    }
    if (result.screenshot) {
      const screenshot = await this.evidenceStore.save({
        workspaceId: context.workspaceId,
        scanId: input.scanId,
        policyDecisionId: input.policyDecisionId,
        type: 'browser-screenshot',
        mimeType: 'image/png',
        content: result.screenshot,
        source: 'browser-runner',
        createdBy: 'execution-service',
        captureTool: 'playwright-core',
        captureToolVersion: '1.61.1',
        redactionState: 'original'
      })
      evidenceRefs.push(screenshot.id)
    }

    await this.repository.updateToolCall({
      id: toolCallId,
      status: result.status,
      durationMs: result.durationMs,
      outputRef,
      ...(result.errorMessage
        ? { error: redactInventoryText(result.errorMessage) }
        : {})
    })
    await this.repository.addScanEvent({
      scanId: input.scanId,
      type: 'execution',
      level: result.status === 'succeeded' ? 'info' : 'warning',
      message:
        result.status === 'succeeded'
          ? `隔离浏览器完成 ${request.action}，阻断 ${result.networkRequestsBlocked} 个网络请求。`
          : `隔离浏览器执行未完成：${result.errorMessage ? redactInventoryText(result.errorMessage) : result.errorCode ?? 'unknown'}`,
      detail: { requestId, toolCallId, evidenceRefs }
    })
    return { result, evidenceRefs, toolCallId }
  }
}
