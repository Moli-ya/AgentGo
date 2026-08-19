import { createHash, randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createDefaultScanPlan } from '@agentgo/agent-runtime'
import type { LegacyV1VulnerabilityFamily } from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  openAgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { DefaultModelGateway } from '@agentgo/model-gateway'
import { AgentPromptCatalog } from './agent-prompts'
import type {
  BrowserExecutionResultView,
  BrowserOfflineExecutionStepInput,
  ExecutionPort,
  ExecutionPortInput,
  HttpExecutionResultView,
  HttpExecutionStepInput,
  StoredExecutionResult,
  UnsupportedExecutionStepInput
} from './execution-port'
import {
  AgentGoApplicationService,
  createDay2VulnerabilityPlatform
} from './index'
import { PolicyBroker } from './execution-policy'
import { ReportService } from './report-service'
import { DefaultScanCoordinator } from './scan-coordinator'

const directories: string[] = []

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

const protector: SecretProtector = {
  isAvailable: () => true,
  protect: (value) => Buffer.from(value, 'utf8'),
  unprotect: (value) => value.toString('utf8')
}

const expectedStepIds = new Set([
  'inventory.target-base.read',
  'inventory.target-base.offline-inspect',
  'sqli.baseline',
  'sqli.true',
  'sqli.false',
  'sqli.repeat',
  'xss.baseline',
  'xss.reflection',
  'xss.offline-verify',
  'ssrf.callback-read',
  'ssrf.primary',
  'ssrf.negative',
  'idor.owner',
  'idor.second-own',
  'idor.cross-read'
])

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function isHttpInput(input: ExecutionPortInput): input is HttpExecutionStepInput {
  return input.adapterKind === 'http'
}

class StrictExecutionPort implements ExecutionPort {
  readonly inputs: ExecutionPortInput[] = []
  readonly #baseUrl: string
  readonly #repository: AgentGoRepository
  readonly #evidenceStore: EvidenceStore
  readonly #policyBroker: PolicyBroker

  constructor(
    baseUrl: string,
    repository: AgentGoRepository,
    evidenceStore: EvidenceStore
  ) {
    this.#baseUrl = baseUrl
    this.#repository = repository
    this.#evidenceStore = evidenceStore
    this.#policyBroker = new PolicyBroker(repository)
  }

  execute(
    input: HttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>>
  execute(
    input: BrowserOfflineExecutionStepInput
  ): Promise<StoredExecutionResult<BrowserExecutionResultView>>
  execute(input: UnsupportedExecutionStepInput): Promise<never>
  async execute(
    input: ExecutionPortInput
  ): Promise<
    | StoredExecutionResult<HttpExecutionResultView>
    | StoredExecutionResult<BrowserExecutionResultView>
  > {
    this.#assertEnvelope(input)
    this.inputs.push(input)
    const trace = await this.#persistTrace(input)
    if (input.adapterKind === 'http') {
      return this.#stored(this.#httpResult(input), trace)
    }
    if (input.adapterKind === 'browser-offline') {
      return this.#stored(this.#browserResult(input), trace)
    }
    throw new Error(`StrictExecutionPort rejected unsupported adapter ${input.adapterKind}.`)
  }

  #assertEnvelope(input: ExecutionPortInput): void {
    if (
      !input.scanId ||
      !input.agentRunId ||
      !input.familyId ||
      !expectedStepIds.has(input.stepId) ||
      input.purpose !== 'read' ||
      !input.summary ||
      !input.expectedEvidence ||
      input.signal?.aborted
    ) {
      throw new Error('StrictExecutionPort rejected an incomplete execution envelope.')
    }
    if (input.adapterKind === 'http') {
      if (
        !input.endpointId ||
        input.timeoutMs !== 10_000 ||
        input.maxResponseBytes !== 2 * 1024 * 1024 ||
        input.maxRedirects !== 5
      ) {
        throw new Error('StrictExecutionPort rejected HTTP limits or endpoint binding.')
      }
      if (input.mutation) {
        const values = new URL(input.desiredUrl).searchParams.getAll(
          input.mutation.name
        )
        if (
          input.mutation.kind !== 'query' ||
          input.mutation.occurrence !== 0 ||
          values[0] !== input.mutation.value
        ) {
          throw new Error('StrictExecutionPort rejected an inexact query mutation.')
        }
      }
      return
    }
    if (input.adapterKind === 'browser-offline') {
      if (
        input.timeoutMs !== 10_000 ||
        input.maxDomBytes !== 1024 * 1024
      ) {
        throw new Error('StrictExecutionPort rejected browser limits.')
      }
      return
    }
    throw new Error(`StrictExecutionPort rejected unsupported adapter ${input.adapterKind}.`)
  }

  #httpResult(input: HttpExecutionStepInput): HttpExecutionResultView {
    const { body, contentType } = this.#httpBody(input)
    const responseBody = Buffer.from(body, 'utf8')
    return {
      requestId: randomUUID(),
      status: 'succeeded',
      finalUrl: input.desiredUrl,
      method: 'GET',
      statusCode: 200,
      requestHeaders: [],
      responseHeaders: { 'content-type': contentType },
      responseBody,
      responseBodySha256: sha256(responseBody),
      responseBytes: responseBody.byteLength,
      durationMs: 1,
      resolvedAddresses: ['203.0.113.10'],
      redirectChain: []
    }
  }

  #httpBody(input: HttpExecutionStepInput): {
    body: string
    contentType: string
  } {
    if (input.stepId === 'inventory.target-base.read') {
      return {
        body: '<!doctype html><html><head><title>AgentGo Fixture</title></head><body>fixture</body></html>',
        contentType: 'text/html; charset=utf-8'
      }
    }
    if (input.stepId.startsWith('sqli.')) {
      return {
        body:
          input.stepId === 'sqli.false'
            ? '<html><body>no rows</body></html>'
            : '<html><body>product: visible</body></html>',
        contentType: 'text/html; charset=utf-8'
      }
    }
    if (input.stepId === 'xss.baseline') {
      return {
        body: '<html><body>Search: baseline</body></html>',
        contentType: 'text/html; charset=utf-8'
      }
    }
    if (input.stepId === 'xss.reflection') {
      return {
        body: `<html><body>Search: ${input.mutation?.value ?? ''}</body></html>`,
        contentType: 'text/html; charset=utf-8'
      }
    }
    if (input.stepId === 'ssrf.callback-read') {
      const token = new URL(input.desiredUrl).searchParams.get('agentgo_token')
      if (!token) throw new Error('Controlled callback token was not compiled.')
      return {
        body: `AGENTGO_CALLBACK_PROOF_${token}`,
        contentType: 'text/plain; charset=utf-8'
      }
    }
    if (input.stepId === 'ssrf.primary') {
      const callbackUrl = input.mutation?.value
      const token = callbackUrl
        ? new URL(callbackUrl).searchParams.get('agentgo_token')
        : undefined
      if (!token) throw new Error('SSRF primary mutation omitted the callback token.')
      return {
        body: `AGENTGO_CALLBACK_PROOF_${token}`,
        contentType: 'text/plain; charset=utf-8'
      }
    }
    if (input.stepId === 'ssrf.negative') {
      return {
        body: 'invalid url',
        contentType: 'text/plain; charset=utf-8'
      }
    }
    if (input.stepId.startsWith('idor.')) {
      const resourceId = input.mutation?.value
      if (!resourceId) throw new Error('IDOR mutation omitted the test resource.')
      return {
        body: JSON.stringify({ id: resourceId, value: `test-only-${resourceId}` }),
        contentType: 'application/json'
      }
    }
    throw new Error(`StrictExecutionPort has no HTTP fixture for ${input.stepId}.`)
  }

  #browserResult(
    input: BrowserOfflineExecutionStepInput
  ): BrowserExecutionResultView {
    if (input.stepId === 'inventory.target-base.offline-inspect') {
      return {
        requestId: randomUUID(),
        status: 'succeeded',
        finalUrl: input.baseUrl,
        pageTitle: 'AgentGo Fixture',
        links: [
          `${this.#baseUrl}/sqli?filter=1&filter=shadow`,
          `${this.#baseUrl}/xss?message=hello&message=shadow`,
          `${this.#baseUrl}/ssrf?url=none&url=shadow`,
          `${this.#baseUrl}/resource?resource_id=resource-a&resource_id=shadow`
        ],
        forms: [],
        domSnapshot: '<html><body>fixture</body></html>',
        networkRequestsBlocked: 0,
        resultBytes: Buffer.byteLength(
          '<html><body>fixture</body></html>',
          'utf8'
        ),
        durationMs: 1
      }
    }
    if (input.stepId === 'xss.offline-verify') {
      if (!input.marker || !input.html.includes(input.marker)) {
        throw new Error('Offline XSS verification lost its marker.')
      }
      return {
        requestId: randomUUID(),
        status: 'succeeded',
        finalUrl: input.baseUrl,
        links: [],
        forms: [],
        domSnapshot: `<html data-agentgo-xss="${input.marker}"></html>`,
        markerExecuted: true,
        screenshot: new Uint8Array([1, 2, 3]),
        networkRequestsBlocked: 0,
        resultBytes:
          Buffer.byteLength(
            `<html data-agentgo-xss="${input.marker}"></html>`,
            'utf8'
          ) + 3,
        durationMs: 1
      }
    }
    throw new Error(`StrictExecutionPort has no browser fixture for ${input.stepId}.`)
  }

  async #persistTrace(input: ExecutionPortInput): Promise<{
    proposalId: string
    policyDecisionId: string
    toolCallId: string
    evidenceRefs: string[]
  }> {
    if (
      input.adapterKind !== 'http' &&
      input.adapterKind !== 'browser-offline'
    ) {
      throw new Error('StrictExecutionPort cannot persist an unsupported trace.')
    }
    const targetUrl =
      input.adapterKind === 'http' ? input.desiredUrl : input.baseUrl
    const evaluated = await this.#policyBroker.evaluate({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action: {
        kind:
          input.adapterKind === 'http'
            ? 'http-request'
            : 'browser-action',
        targetUrl,
        method: 'GET',
        ...(input.adapterKind === 'http' && input.identityId
          ? { identityId: input.identityId }
          : {}),
        probeLevel: 'active-safe',
        sideEffect: 'none',
        summary: input.summary,
        ...(input.payloadSummary
          ? { payloadSummary: input.payloadSummary }
          : {}),
        expectedEvidence: input.expectedEvidence,
        maxRequests: 1,
        timeoutMs: input.timeoutMs,
        userApproved: false
      },
      stopConditions: ['Stop after this strict fixture execution.']
    })
    if (
      !evaluated.decision.allowed ||
      evaluated.decision.requiresApproval
    ) {
      throw new Error('StrictExecutionPort fixture policy rejected execution.')
    }
    const toolCallId = await this.#repository.recordToolCall({
      scanId: input.scanId,
      policyDecisionId: evaluated.decision.id,
      toolName:
        input.adapterKind === 'http'
          ? 'strict-http-fixture'
          : 'strict-browser-fixture',
      toolVersion: '1.0.0',
      argumentHash: sha256(
        Buffer.from(
          JSON.stringify({
            adapterKind: input.adapterKind,
            stepId: input.stepId,
            targetUrl
          }),
          'utf8'
        )
      ),
      status: 'succeeded',
      durationMs: 1
    })
    const context = await this.#repository.getExecutionDecision(
      evaluated.decision.id
    )
    if (!context) {
      throw new Error('StrictExecutionPort fixture lost its policy context.')
    }
    const evidenceRefs: string[] = []
    for (const role of ['request-summary', 'result-summary'] as const) {
      const evidence = await this.#evidenceStore.save({
        workspaceId: context.workspaceId,
        scanId: input.scanId,
        policyDecisionId: evaluated.decision.id,
        type: 'strict-execution-summary',
        mimeType: 'application/json',
        content: JSON.stringify({
          schemaVersion: 'strict-execution-summary.v1',
          adapterKind: input.adapterKind,
          stepId: input.stepId,
          role
        }),
        source: role,
        createdBy: 'strict-execution-port-fixture',
        captureTool: 'strict-execution-port-fixture',
        captureToolVersion: '1.0.0',
        redactionState: 'redacted'
      })
      evidenceRefs.push(evidence.id)
    }
    return {
      proposalId: evaluated.proposal.id,
      policyDecisionId: evaluated.decision.id,
      toolCallId,
      evidenceRefs
    }
  }

  #stored<TResult>(
    result: TResult,
    trace: {
      proposalId: string
      policyDecisionId: string
      toolCallId: string
      evidenceRefs: string[]
    }
  ): StoredExecutionResult<TResult> {
    return {
      result,
      interactionIds: [],
      evidenceRefs: trace.evidenceRefs,
      toolCallId: trace.toolCallId,
      toolCallIds: [trace.toolCallId],
      proposalIds: [trace.proposalId],
      policyDecisionIds: [trace.policyDecisionId],
      grantIds: [randomUUID()],
      leaseIds: [randomUUID()]
    }
  }
}

async function createHarness(
  families: readonly LegacyV1VulnerabilityFamily[] = [
    'sqli',
    'xss',
    'ssrf',
    'idor'
  ]
) {
  const baseUrl = 'https://fixture.agentgo.test'
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-coordinator-'))
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  const repository = new AgentGoRepository(database)
  const evidenceStore = new EvidenceStore(database, join(directory, 'artifacts'))
  const credentialStore = new FileCredentialStore(
    join(directory, 'credentials.json'),
    protector
  )
  const modelGateway = new DefaultModelGateway({
    profiles: repository,
    credentials: credentialStore,
    prompts: new AgentPromptCatalog(),
    invocations: repository
  })
  const reportService = new ReportService(repository, evidenceStore)
  const vulnerabilityPlatform = createDay2VulnerabilityPlatform()
  const executionPort = new StrictExecutionPort(
    baseUrl,
    repository,
    evidenceStore
  )
  const application = new AgentGoApplicationService({
    repository,
    credentialStore,
    evidenceStore,
    modelGateway,
    reportService,
    vulnerabilityPlatform,
    vulnerabilityExecutionEnvironment: 'attested-fixture'
  })
  const coordinator = new DefaultScanCoordinator({
    repository,
    evidenceStore,
    executionPort,
    modelGateway,
    reportService,
    vulnerabilityPlatform,
    vulnerabilityExecutionEnvironment: 'attested-fixture'
  })
  application.setScanCoordinator(coordinator)
  await application.initialize()

  const workspace = await application.createWorkspace({
    name: 'Coordinator fixture',
    description: 'Authorized synthetic ExecutionPort fixture'
  })
  const target = await application.createTarget({
    workspaceId: workspace.id,
    name: 'Authorized synthetic fixture',
    baseUrl,
    description: '',
    authorizationReference: 'coordinator-test-owner',
    scope: {
      allowedOrigins: [baseUrl],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [443],
      allowedIdentityIds: [],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      maxRequestsPerMinute: 120,
      maxConcurrency: 1
    }
  })
  const owner = await application.saveIdentity({
    targetId: target.target.id,
    label: 'Owner',
    role: 'owner',
    authType: 'bearer',
    secret: 'owner-secret-must-not-cross-the-port',
    isTestIdentity: true,
    ownedResourceIds: ['resource-a']
  })
  const second = await application.saveIdentity({
    targetId: target.target.id,
    label: 'Second',
    role: 'member',
    authType: 'bearer',
    secret: 'second-secret-must-not-cross-the-port',
    isTestIdentity: true,
    ownedResourceIds: ['resource-b']
  })
  await application.updateTarget({
    id: target.target.id,
    scope: {
      allowedOrigins: [baseUrl],
      allowedPathPrefixes: ['/'],
      deniedPathPrefixes: [],
      allowedPorts: [443],
      allowedIdentityIds: [owner.id, second.id],
      allowActiveProbing: true,
      allowSensitiveProbing: false,
      allowPrivateNetworkTargets: false,
      allowLoopbackTargets: false,
      maxRequestsPerMinute: 120,
      maxConcurrency: 1,
      authorizationReference: 'coordinator-test-owner'
    }
  })
  const plan = createDefaultScanPlan()
  const scan = await application.createScan({
    targetId: target.target.id,
    name: 'Strict ExecutionPort scan',
    description: 'Validate exact Coordinator execution envelopes.',
    families: [...families],
    identityIds: [owner.id, second.id],
    ...(families.includes('ssrf')
      ? { callbackUrl: `${baseUrl}/callback?tenant=fixture` }
      : {}),
    budget: {
      ...plan.budget,
      maxRequests: 100,
      maxRequestsPerMinute: 120,
      maxConcurrency: 1,
      maxDurationMinutes: 5
    }
  })

  return {
    application,
    baseUrl,
    coordinator,
    database,
    executionPort,
    owner,
    repository,
    scan,
    second
  }
}

describe('DefaultScanCoordinator ExecutionPort boundary', () => {
  it('routes enumeration and all V1 validation steps through exact reviewed envelopes', async () => {
    const harness = await createHarness()
    try {
      await harness.application.controlScan(harness.scan.id, 'start')
      let current = await harness.coordinator.waitForScan(harness.scan.id)

      expect(current).toMatchObject({ status: 'awaiting-user', phase: 'intake' })
      expect(harness.executionPort.inputs).toHaveLength(0)
      expect(
        (await harness.repository.listInventorySources(harness.scan.id))
          .map((source) => source.type)
          .sort()
      ).toEqual(['controlled-callback', 'target-base'])

      let reviewRounds = 0
      while (current.status === 'awaiting-user' && reviewRounds < 4) {
        const pending =
          await harness.repository.listPendingActiveL1ReviewVariantIds(
            harness.scan.id
          )
        expect(pending.length).toBeGreaterThan(0)
        for (const requestVariantId of pending) {
          await harness.application.reviewVariant({
            scanId: harness.scan.id,
            requestVariantId,
            reviewStatus: 'reviewed',
            reviewedBy: 'fixture-manifest:strict-execution-port'
          })
        }
        reviewRounds += 1
        await harness.application.controlScan(harness.scan.id, 'resume')
        current = await harness.coordinator.waitForScan(harness.scan.id)
      }

      expect(current.status).toBe('completed')
      expect(reviewRounds).toBe(2)
      expect(
        new Set(harness.executionPort.inputs.map((input) => input.stepId))
      ).toEqual(expectedStepIds)
      expect(
        JSON.stringify(harness.executionPort.inputs)
      ).not.toContain('secret-must-not-cross-the-port')

      for (const input of harness.executionPort.inputs) {
        expect(input.purpose).toBe('read')
        if (input.stepId === 'inventory.target-base.read') {
          expect(input).toMatchObject({
            adapterKind: 'http',
            familyId: 'sqli',
            identityId: harness.owner.id
          })
        } else if (input.stepId === 'inventory.target-base.offline-inspect') {
          expect(input).toMatchObject({
            adapterKind: 'browser-offline',
            familyId: 'xss'
          })
        } else {
          expect(input.familyId).toBe(input.stepId.split('.')[0])
        }
      }

      const browserInputs = harness.executionPort.inputs.filter(
        (input): input is BrowserOfflineExecutionStepInput =>
          input.adapterKind === 'browser-offline'
      )
      expect(
        browserInputs.every(
          (input) =>
            input.timeoutMs === 10_000 && input.maxDomBytes === 1024 * 1024
        )
      ).toBe(true)

      const httpInputs = harness.executionPort.inputs.filter(isHttpInput)
      expect(
        httpInputs.every(
          (input) =>
            input.timeoutMs === 10_000 &&
            input.maxResponseBytes === 2 * 1024 * 1024 &&
            input.maxRedirects === 5 &&
            Boolean(input.endpointId)
        )
      ).toBe(true)

      for (const input of httpInputs.filter((candidate) => candidate.mutation)) {
        expect(input.mutation).toMatchObject({
          kind: 'query',
          occurrence: 0
        })
        const values = new URL(input.desiredUrl).searchParams.getAll(
          input.mutation!.name
        )
        expect(values[0]).toBe(input.mutation!.value)
        if (input.stepId !== 'ssrf.callback-read') {
          expect(values[1], input.stepId).toBe('[REDACTED]')
        }
      }

      for (const input of httpInputs.filter((candidate) =>
        candidate.stepId.startsWith('sqli.')
      )) {
        expect(input.identityId).toBe(harness.owner.id)
      }
      for (const input of httpInputs.filter((candidate) =>
        candidate.stepId.startsWith('xss.')
      )) {
        expect(input.identityId).toBe(harness.owner.id)
      }
      expect(
        httpInputs.find((input) => input.stepId === 'ssrf.callback-read')
      ).not.toHaveProperty('identityId')
      for (const stepId of ['ssrf.primary', 'ssrf.negative']) {
        expect(
          httpInputs.find((input) => input.stepId === stepId)?.identityId
        ).toBe(harness.owner.id)
      }
      expect(
        httpInputs.find((input) => input.stepId === 'idor.owner')?.identityId
      ).toBe(harness.owner.id)
      for (const stepId of ['idor.second-own', 'idor.cross-read']) {
        expect(
          httpInputs.find((input) => input.stepId === stepId)?.identityId
        ).toBe(harness.second.id)
      }

      const findings = await harness.application.listFindings({
        scanId: harness.scan.id
      })
      const confirmedFamilies = new Set(
        findings
          .filter((finding) => finding.verdict === 'confirmed')
          .map((finding) => finding.family)
      )
      const errors = (
        await harness.repository.listScanEvents(harness.scan.id)
      )
        .filter(({ level }) => level === 'error')
        .map(({ message }) => message)
      expect(errors).toEqual([])
      expect(confirmedFamilies).toEqual(
        new Set(['sqli', 'ssrf', 'idor'])
      )
      expect(
        findings.find(({ family }) => family === 'xss')
      ).toMatchObject({
        verdict: 'inconclusive'
      })
      expect(
        (await harness.application.listReports(harness.scan.id)).some(
          (report) => report.redacted
        )
      ).toBe(true)
    } finally {
      await harness.coordinator.shutdown()
      harness.database.close()
    }
  })

  it('blocks unknown interrupted execution before inventory or execution I/O', async () => {
    const harness = await createHarness(['sqli'])
    try {
      const row = await harness.repository.getScanRow(harness.scan.id)
      if (!row) throw new Error('Fixture scan disappeared.')
      const pausedState = {
        ...row.runtimeJson,
        status: 'paused'
      }
      await harness.repository.updateScan(harness.scan.id, {
        status: 'paused',
        runtimeJson: pausedState
      })
      await harness.repository.addCheckpoint({
        scanId: harness.scan.id,
        phase: harness.scan.phase,
        state: pausedState,
        reason: 'execution-interrupted-unknown'
      })

      await expect(
        harness.coordinator.control(harness.scan.id, 'resume')
      ).rejects.toThrow('automatic resume is forbidden')
      expect(harness.executionPort.inputs).toHaveLength(0)
      expect(
        await harness.repository.listInventorySources(harness.scan.id)
      ).toHaveLength(0)
    } finally {
      await harness.coordinator.shutdown()
      harness.database.close()
    }
  })
})
