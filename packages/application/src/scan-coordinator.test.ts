import { createServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createDefaultScanPlan } from '@agentgo/agent-runtime'
import { PlaywrightBrowserRunner } from '@agentgo/browser-runner'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  agentRuns,
  openAgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { UndiciHttpRunner } from '@agentgo/http-runner'
import { DefaultModelGateway } from '@agentgo/model-gateway'
import { AgentPromptCatalog } from './agent-prompts'
import {
  AgentGoApplicationService,
  createDay2VulnerabilityPlatform
} from './index'
import { PolicyBroker, PolicyExecutionGuard } from './execution-policy'
import { ExecutionService } from './execution-service'
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

describe('DefaultScanCoordinator V1 vertical loop', () => {
  it('completes SQLi, XSS, SSRF and IDOR signal-to-report flows on an authorized local fixture', async () => {
    let baseUrl = ''
    let fixtureRequestCount = 0
    const server = createServer(async (request, response) => {
      fixtureRequestCount += 1
      const url = new URL(request.url ?? '/', baseUrl)
      if (url.pathname === '/') {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        response.end(`<!doctype html><html><head><title>AgentGo Lab</title></head><body>
          <a href="/sqli?id=1">SQLi</a>
          <a href="/xss?q=hello">XSS</a>
          <a href="/ssrf?url=none">SSRF</a>
          <a href="/resource?id=resource-a">Resource</a>
          <form action="/sqli" method="get"><input name="id" required></form>
        </body></html>`)
        return
      }
      if (url.pathname === '/sqli') {
        const value = url.searchParams.get('id') ?? ''
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        response.end(
          /AND\s+1=2|AND\s+'1'='2'/i.test(value)
            ? '<html><body>no rows</body></html>'
            : '<html><body>product: visible</body></html>'
        )
        return
      }
      if (url.pathname === '/xss') {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        response.end(`<html><body>Search: ${url.searchParams.get('q') ?? ''}</body></html>`)
        return
      }
      if (url.pathname === '/callback') {
        const token = url.searchParams.get('agentgo_token') ?? 'missing'
        response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
        response.end(`AGENTGO_CALLBACK_PROOF_${token}`)
        return
      }
      if (url.pathname === '/ssrf') {
        const target = url.searchParams.get('url') ?? ''
        if (!target.startsWith(baseUrl)) {
          response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
          response.end('invalid url')
          return
        }
        const fetched = await fetch(target)
        response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
        response.end(await fetched.text())
        return
      }
      if (url.pathname === '/resource') {
        const authorization = request.headers.authorization
        if (!['Bearer owner-token', 'Bearer second-token'].includes(authorization ?? '')) {
          response.writeHead(401, { 'content-type': 'application/json' })
          response.end('{"error":"unauthorized"}')
          return
        }
        const id = url.searchParams.get('id') ?? ''
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(JSON.stringify({ id, value: `test-only-${id}` }))
        return
      }
      response.writeHead(404, { 'content-type': 'text/plain' })
      response.end('not found')
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as AddressInfo
    baseUrl = `http://127.0.0.1:${address.port}`

    const directory = mkdtempSync(join(tmpdir(), 'agentgo-coordinator-'))
    directories.push(directory)
    const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
    const repository = new AgentGoRepository(database)
    const evidenceStore = new EvidenceStore(database, join(directory, 'artifacts'))
    const credentialStore = new FileCredentialStore(
      join(directory, 'credentials.json'),
      protector
    )
    const guard = new PolicyExecutionGuard(repository)
    const executionService = new ExecutionService(
      repository,
      evidenceStore,
      new UndiciHttpRunner(guard),
      new PlaywrightBrowserRunner(guard, { headless: true })
    )
    const reportService = new ReportService(repository, evidenceStore)
    let plannerRequestUrl = ''
    let plannerRequestBody = ''
    let plannerInvocationCount = 0
    const modelGateway = new DefaultModelGateway({
      profiles: repository,
      credentials: credentialStore,
      prompts: new AgentPromptCatalog(),
      invocations: repository,
      fetchImplementation: async (input, init) => {
        plannerInvocationCount += 1
        plannerRequestUrl = String(input)
        plannerRequestBody = String(init?.body ?? '')
        return new Response(
          JSON.stringify({
            model: 'planner-integration-model',
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    phaseObjectives: [
                      { phase: 'intake', objective: '确认授权、范围和预算。' },
                      { phase: 'hypothesis', objective: '形成低影响验证候选。' },
                      { phase: 'report', objective: '输出证据化三态结论。' }
                    ],
                    candidateFamilies: ['sqli', 'xss', 'ssrf', 'idor'],
                    stopConditions: ['达到确认规则或预算后停止。']
                  })
                }
              }
            ],
            usage: { prompt_tokens: 120, completion_tokens: 60 }
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
      }
    })
    const vulnerabilityPlatform = createDay2VulnerabilityPlatform()
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
      credentialStore,
      evidenceStore,
      executionService,
      policyBroker: new PolicyBroker(repository),
      modelGateway,
      reportService,
      vulnerabilityPlatform,
      vulnerabilityExecutionEnvironment: 'attested-fixture'
    })
    application.setScanCoordinator(coordinator)

    try {
      await application.initialize()
      const externalPlannerProfile = await application.saveModelProfile({
        name: 'Planner integration provider',
        agentRole: 'planner',
        provider: 'openai-compatible',
        baseUrl: 'https://planner.example.test/v1/',
        model: 'planner-integration-model',
        apiKey: 'planner-integration-key',
        timeoutMs: 5_000,
        rpmLimit: 30,
        tpmLimit: 100_000,
        tokenBudget: 1_000_000,
        costBudget: 1
      })
      const workspace = await application.createWorkspace({
        name: 'V1 fixture',
        description: 'Authorized local test'
      })
      const target = await application.createTarget({
        workspaceId: workspace.id,
        name: 'Authorized local fixture',
        baseUrl,
        description: '',
        authorizationReference: 'automated-test-owner',
        scope: {
          allowedOrigins: [baseUrl],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [address.port],
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          maxRequestsPerMinute: 120,
          maxConcurrency: 1
        }
      })
      const owner = await application.saveIdentity({
        targetId: target.target.id,
        label: 'Owner',
        role: 'owner',
        authType: 'bearer',
        secret: 'owner-token',
        isTestIdentity: true,
        ownedResourceIds: ['resource-a']
      })
      const second = await application.saveIdentity({
        targetId: target.target.id,
        label: 'Second',
        role: 'member',
        authType: 'bearer',
        secret: 'second-token',
        isTestIdentity: true,
        ownedResourceIds: ['resource-b']
      })
      await application.updateTarget({
        id: target.target.id,
        scope: {
          allowedOrigins: [baseUrl],
          allowedPathPrefixes: ['/'],
          deniedPathPrefixes: [],
          allowedPorts: [address.port],
          allowedIdentityIds: [owner.id, second.id],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          maxRequestsPerMinute: 120,
          maxConcurrency: 1,
          authorizationReference: 'automated-test-owner'
        }
      })
      const plan = createDefaultScanPlan()
      const scan = await application.createScan({
        targetId: target.target.id,
        name: 'Four-family vertical test',
        description: '验证授权本地靶场的四类漏洞，并优先关注只读、低影响证据链。',
        families: ['sqli', 'xss', 'ssrf', 'idor'],
        identityIds: [owner.id, second.id],
        modelProfileIds: { planner: externalPlannerProfile.id },
        callbackUrl: `${baseUrl}/callback`,
        budget: {
          ...plan.budget,
          maxRequests: 100,
          maxRequestsPerMinute: 120,
          maxConcurrency: 1,
          maxDurationMinutes: 5
        }
      })

      await application.controlScan(scan.id, 'start')
      let completed = await coordinator.waitForScan(scan.id)
      expect(completed.status).toBe('awaiting-user')
      expect(completed.phase).toBe('intake')
      expect(fixtureRequestCount).toBe(0)
      expect(plannerInvocationCount).toBe(0)
      expect(await database.orm.select().from(agentRuns)).toHaveLength(0)
      const targetBaseReviewVariantIds =
        await repository.listPendingActiveL1ReviewVariantIds(scan.id)
      expect(targetBaseReviewVariantIds).toHaveLength(1)
      expect(
        (await repository.listInventorySources(scan.id)).map((source) => source.type)
      ).toEqual(['target-base'])
      await expect(application.controlScan(scan.id, 'resume')).resolves.toMatchObject({
        status: 'awaiting-user'
      })
      expect(fixtureRequestCount).toBe(0)
      expect(plannerInvocationCount).toBe(0)

      const reviewedVariantIds = new Set<string>()
      let reviewRounds = 0
      while (completed.status === 'awaiting-user' && reviewRounds < 4) {
        const pendingReviewVariantIds =
          await repository.listPendingActiveL1ReviewVariantIds(scan.id)
        expect(pendingReviewVariantIds.length).toBeGreaterThan(0)
        for (const requestVariantId of pendingReviewVariantIds) {
          await application.reviewVariant({
            scanId: scan.id,
            requestVariantId,
            reviewStatus: 'reviewed',
            reviewedBy: 'fixture-manifest:scan-coordinator-test'
          })
          reviewedVariantIds.add(requestVariantId)
        }
        reviewRounds += 1
        await application.controlScan(scan.id, 'resume')
        completed = await coordinator.waitForScan(scan.id)
        if (reviewRounds === 1) {
          expect(completed.status).toBe('awaiting-user')
          expect(fixtureRequestCount).toBeGreaterThan(0)
          expect(plannerInvocationCount).toBe(1)
          expect(
            new Set(
              (await repository.listInventorySources(scan.id)).map((source) => source.type)
            )
          ).toEqual(new Set(['target-base', 'link', 'form']))
        }
      }
      expect(reviewRounds).toBeGreaterThanOrEqual(2)
      const findings = await application.listFindings({ scanId: scan.id })
      const confirmedFamilies = new Set(
        findings
          .filter((finding) => finding.verdict === 'confirmed')
          .map((finding) => finding.family)
      )

      expect(completed.status).toBe('completed')
      expect(confirmedFamilies).toEqual(new Set(['sqli', 'xss', 'ssrf', 'idor']))
      expect(findings.every((finding) => finding.evidenceRefs.length > 0)).toBe(true)
      expect((await application.listReports(scan.id)).some((report) => report.redacted)).toBe(true)
      const detail = await application.getScanDetail(scan.id)
      expect(detail.endpoints.length).toBeGreaterThanOrEqual(4)
      const variants = await repository.listInventoryRequestVariants(scan.id)
      const sources = await repository.listInventorySources(scan.id)
      expect(
        variants.some(
          (variant) => variant.reviewStatus === 'reviewed'
        )
      ).toBe(true)
      expect(
        variants
          .filter((variant) => variant.reviewStatus === 'reviewed')
          .every((variant) => variant.executionClass === 'active-l1')
      ).toBe(true)
      expect(
        sources
          .filter((source) => source.reviewStatus === 'reviewed')
          .every((source) =>
            reviewedVariantIds.has(source.requestVariantId)
          )
      ).toBe(true)
      expect(
        (await repository.listScanModuleSnapshots(scan.id)).every(
          (snapshot) =>
            snapshot.environment === 'attested-fixture' &&
            snapshot.authorization === 'legacy-v1-compatibility'
        )
      ).toBe(true)
      expect(scan.modelProfileIds.planner).toBe(externalPlannerProfile.id)
      expect(plannerRequestUrl).toBe('https://planner.example.test/v1/chat/completions')
      const plannerPayload = JSON.parse(plannerRequestBody) as {
        messages: Array<{ role: string; content: string }>
      }
      const plannerInput = plannerPayload.messages.find((message) => message.role === 'user')
      expect(plannerInput?.content).toContain(
        '验证授权本地靶场的四类漏洞，并优先关注只读、低影响证据链。'
      )
      const plannerUsage = (await application.listModelProfileUsage()).find(
        (item) => item.profileId === externalPlannerProfile.id
      )
      expect(plannerUsage?.promptTokens).toBe(120)
      expect(plannerUsage?.completionTokens).toBe(60)
      expect(plannerUsage?.totalTokens).toBe(180)

      const runs = await database.orm.select().from(agentRuns)
      const plannerRun = runs.find((run) => run.role === 'planner')
      const knowledgeRun = runs.find((run) => run.role === 'knowledge')
      const strategyRun = runs.find((run) => run.role === 'strategy')
      expect(plannerRun?.modelProfileId).toBe(externalPlannerProfile.id)
      expect(knowledgeRun?.parentRunId).toBe(plannerRun?.id)
      expect(knowledgeRun?.inputRefs).toContain(plannerRun?.outputRefs[0])
      expect(strategyRun?.parentRunId).toBe(knowledgeRun?.id)
      expect(strategyRun?.inputRefs).toContain(knowledgeRun?.outputRefs[0])
      const analysisRuns = runs.filter((run) => run.role === 'analysis')
      const verifierRuns = runs.filter((run) => run.role === 'verifier')
      expect(analysisRuns.length).toBeGreaterThan(0)
      expect(analysisRuns.every((run) => run.parentRunId === strategyRun?.id)).toBe(true)
      expect(verifierRuns.length).toBe(analysisRuns.length)
      expect(
        verifierRuns.every((run) =>
          analysisRuns.some(
            (analysisRun) =>
              run.parentRunId === analysisRun.id &&
              run.inputRefs.includes(analysisRun.outputRefs[0]!)
          )
        )
      ).toBe(true)
    } finally {
      await coordinator.shutdown()
      database.close()
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  }, 60_000)
})
