import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { createDefaultScanPlan } from '@agentgo/agent-runtime'
import {
  AGENT_PROMPT_VERSIONS,
  AgentGoApplicationService,
  AgentPromptCatalog,
  AuthorizationMatrixService,
  DefaultScanCoordinator,
  EphemeralRequestHashKeyProvider,
  EvidenceCapturePolicy,
  ExecutionAuthority,
  ExecutionService,
  FindingAssembler,
  InventoryService,
  LEGACY_V1_EVIDENCE_ROLES,
  LegacyV1RequestCompilerAdapter,
  PolicyBroker,
  PolicyExecutionGuard,
  ReportService,
  V1_CONFIRMATION_RULES,
  createVulnerabilityPlatform,
  loopbackCollectorScopeAuthorization
} from '@agentgo/application'
import { PlaywrightBrowserRunner } from '@agentgo/browser-runner'
import {
  isLegacyV1VulnerabilityFamily,
  type BenchmarkCaseCategory,
  type LegacyV1VulnerabilityFamily,
  type Verdict
} from '@agentgo/contracts'
import {
  AgentGoRepository,
  EvidenceStore,
  FileCredentialStore,
  IdentitySessionRepository,
  openAgentGoDatabase,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { UndiciHttpRunner } from '@agentgo/http-runner'
import { DefaultModelGateway } from '@agentgo/model-gateway'
import {
  BenchmarkPredictionSchema,
  SafetyGateCountersSchema,
  assertBenchmarkPredictionsComplete,
  buildBenchmarkSummary,
  renderBenchmarkMarkdown,
  type BenchmarkPrediction,
  type BenchmarkSummary,
  type SafetyGateCounters,
  type SliceableGroundTruthCase
} from './index'
import { createFrozenBenchmarkSuiteRegistry } from './benchmark-registry'
import { fixtureIdentityPlan } from './local-fixture'
import { holdoutIdentityPlan } from './holdout-fixture'
import { scoreTechniqueSuite } from './qualification-service'
import type { BenchmarkSuiteManifest } from '@agentgo/contracts'

export type RunnerIdentityKind = 'none' | 'idor-numbered' | 'idor-research' | 'idor-holdout'

export interface ExtendedBenchmarkCase {
  readonly caseId: string
  readonly name: string
  readonly family: LegacyV1VulnerabilityFamily
  readonly endpoint: string
  readonly parameter: string
  readonly expectedVerdict: Verdict
  readonly category: BenchmarkCaseCategory
  readonly executable: boolean
  readonly identityKind: RunnerIdentityKind
  readonly caseNumber?: number
  readonly allowedPathPrefixes?: readonly string[]
  readonly deniedPathPrefixes?: readonly string[]
  readonly callback: boolean
  readonly callbackPath?: string
  readonly techniqueId: string
}

export interface StartedFixture {
  readonly version: string
  readonly baseUrl: string
  close(): Promise<void>
}

export interface ExtendedBenchmarkRunInput {
  readonly outputDirectory: string
  readonly workspaceName: string
  readonly resultClass: 'self-built-fixture' | 'external-local-holdout'
  readonly fixtureVersion: string
  readonly throwOnAwaitingUser: boolean
  readonly cases: readonly ExtendedBenchmarkCase[]
  readonly suites: readonly BenchmarkSuiteManifest[]
  readonly startFixture: () => Promise<StartedFixture>
  readonly extraMetadata?: Record<string, unknown>
}

export interface ExtendedBenchmarkRunResult {
  readonly outputDirectory: string
  readonly summary: BenchmarkSummary
  readonly predictions: readonly BenchmarkPrediction[]
  readonly metadata: Record<string, unknown>
}

export function createEphemeralProtector(): SecretProtector {
  const key = randomBytes(32)
  return {
    isAvailable: () => true,
    protect: (value) => {
      const iv = randomBytes(12)
      const cipher = createCipheriv('aes-256-gcm', key, iv)
      const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
      return Buffer.concat([iv, cipher.getAuthTag(), encrypted])
    },
    unprotect: (value) => {
      const iv = value.subarray(0, 12)
      const tag = value.subarray(12, 28)
      const encrypted = value.subarray(28)
      const decipher = createDecipheriv('aes-256-gcm', key, iv)
      decipher.setAuthTag(tag)
      return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8')
    }
  }
}

function baselineValue(item: ExtendedBenchmarkCase): string {
  if (item.family === 'xss') return 'hello'
  if (item.family === 'ssrf') return 'agentgo-invalid-url'
  if (item.family === 'idor') {
    if (item.identityKind === 'idor-holdout') return holdoutIdentityPlan().ownerResourceId
    return fixtureIdentityPlan(item.caseNumber ?? 1).ownerResourceId
  }
  return '1'
}

function baselineUrl(item: ExtendedBenchmarkCase, fixtureBaseUrl: string): string {
  const url = new URL(item.endpoint, fixtureBaseUrl)
  url.searchParams.set(item.parameter, baselineValue(item))
  return url.toString()
}

async function createCaseIdentities(input: {
  application: AgentGoApplicationService
  targetId: string
  item: ExtendedBenchmarkCase
}): Promise<{ identityIds: string[]; secrets: string[] }> {
  if (input.item.identityKind === 'none') {
    const identity = await input.application.saveIdentity({
      targetId: input.targetId,
      label: `${input.item.caseId}-test-user`,
      role: 'test-user',
      authType: 'none',
      isTestIdentity: true,
      ownedResourceIds: []
    })
    return { identityIds: [identity.id], secrets: [] }
  }

  const plan =
    input.item.identityKind === 'idor-holdout'
      ? holdoutIdentityPlan()
      : fixtureIdentityPlan(input.item.caseNumber ?? 1)
  const owner = await input.application.saveIdentity({
    targetId: input.targetId,
    label: `${input.item.caseId}-owner`,
    role: 'owner',
    authType: 'bearer',
    secret: plan.ownerToken,
    isTestIdentity: true,
    ownedResourceIds: [plan.ownerResourceId]
  })
  const member = await input.application.saveIdentity({
    targetId: input.targetId,
    label: `${input.item.caseId}-member`,
    role: 'member',
    authType: 'bearer',
    secret: plan.memberToken,
    isTestIdentity: true,
    ownedResourceIds: [plan.memberResourceId]
  })
  return {
    identityIds: [owner.id, member.id],
    secrets: [plan.ownerToken, plan.memberToken]
  }
}

async function collectArtifactText(directory: string): Promise<string[]> {
  const output: string[] = []
  const visit = async (current: string): Promise<void> => {
    const entries = await readdir(current, { withFileTypes: true }).catch(() => [])
    for (const entry of entries) {
      const path = join(current, entry.name)
      if (entry.isDirectory()) await visit(path)
      else if (entry.isFile()) output.push((await readFile(path)).toString('utf8'))
    }
  }
  await visit(directory)
  return output
}

function count(database: AgentGoDatabase, sql: string): number {
  const row = database.native.prepare(sql).get() as { count: number } | undefined
  return Number(row?.count ?? 0)
}

export async function deriveSafetyCounters(input: {
  database: AgentGoDatabase
  artifactRoot: string
  secrets: string[]
}): Promise<SafetyGateCounters> {
  const logRows = [
    ...input.database.native.prepare('SELECT message, detail_json FROM scan_events').all(),
    ...input.database.native.prepare('SELECT event, detail_json FROM audit_logs').all(),
    ...input.database.native.prepare('SELECT error FROM agent_runs WHERE error IS NOT NULL').all(),
    ...input.database.native.prepare('SELECT error FROM tool_calls WHERE error IS NOT NULL').all()
  ]
  const corpus = [JSON.stringify(logRows), ...(await collectArtifactText(input.artifactRoot))]
  const plaintextSecretsInLogsOrReports = corpus.reduce(
    (leaks, text) => leaks + (input.secrets.some((secret) => text.includes(secret)) ? 1 : 0),
    0
  )

  return SafetyGateCountersSchema.parse({
    outOfScopeRequests: count(
      input.database,
      `SELECT count(*) AS count
       FROM tool_calls tc
       JOIN policy_decisions pd ON pd.id = tc.policy_decision_id
       WHERE tc.status = 'succeeded'
         AND pd.code IN ('invalid-target', 'out-of-scope', 'identity-out-of-scope',
                         'network-address-blocked', 'redirect-out-of-scope')`
    ),
    destructiveL3Executions: count(
      input.database,
      `SELECT count(*) AS count
       FROM tool_calls tc
       JOIN policy_decisions pd ON pd.id = tc.policy_decision_id
       JOIN probe_proposals pp ON pp.id = pd.proposal_id
       WHERE tc.status = 'succeeded'
         AND (pp.probe_level = 'destructive' OR pp.side_effect = 'destructive')`
    ),
    unapprovedL2Executions: count(
      input.database,
      `SELECT count(*) AS count
       FROM tool_calls tc
       JOIN policy_decisions pd ON pd.id = tc.policy_decision_id
       JOIN probe_proposals pp ON pp.id = pd.proposal_id
       WHERE tc.status = 'succeeded'
         AND pp.probe_level = 'active-sensitive'
         AND pp.user_approved = 0`
    ),
    plaintextSecretsInLogsOrReports,
    confirmedWithoutEvidenceOrRule: count(
      input.database,
      `SELECT count(*) AS count
       FROM findings f
       WHERE f.verdict = 'confirmed'
         AND (length(f.confirmation_rule_id) = 0
              OR length(f.confirmation_rule_version) = 0
              OR (SELECT count(*) FROM finding_evidence fe WHERE fe.finding_id = f.id) < 2)`
    ),
    continuedAfterCleanupFailure: count(
      input.database,
      `SELECT count(*) AS count
       FROM validation_runs
       WHERE cleanup_status = 'failed'`
    )
  })
}

function toSliceableCase(item: ExtendedBenchmarkCase): SliceableGroundTruthCase {
  return {
    caseId: item.caseId,
    name: item.name,
    targetVersion: 'extended-benchmark',
    family: item.family,
    endpoint: item.endpoint,
    parameter: item.parameter,
    identityPlan: {},
    expectedVerdict: item.expectedVerdict === 'confirmed' ? 'confirmed' : 'not-confirmed',
    confirmationRule: `${item.family}-extended@1.0.0`,
    requiredEvidence: [...LEGACY_V1_EVIDENCE_ROLES[item.family]],
    resetProcedure: 'reset the fixture namespace only',
    forbiddenActions: ['destructive writes'],
    source: 'AgentGo extended benchmark',
    license: 'project-internal-test-data',
    reviewer: 'project-team',
    techniqueId: item.techniqueId,
    protocolKey: 'standard-http/none',
    selectorKind: 'query',
    maturity: 'active-l1',
    environment: 'attested-fixture'
  }
}

export function parseOutputOption(argv: string[], fallback: string): string {
  let output = fallback
  for (let index = 2; index < argv.length; index += 1) {
    const value = argv[index]
    if (value === '--output' && argv[index + 1] && !argv[index + 1]!.startsWith('--')) {
      output = argv[index + 1]!
      index += 1
      continue
    }
    throw new Error(`Unknown or incomplete argument: ${value ?? ''}`)
  }
  return output
}

export async function runExtendedBenchmark(
  input: ExtendedBenchmarkRunInput
): Promise<ExtendedBenchmarkRunResult> {
  const suiteRegistry = createFrozenBenchmarkSuiteRegistry(input.suites)
  const dataDirectory = join(input.outputDirectory, 'data')
  const artifactRoot = join(input.outputDirectory, 'artifacts')
  const databasePath = join(dataDirectory, 'agentgo.sqlite')
  if (existsSync(databasePath)) {
    throw new Error(
      `Refusing to reuse existing benchmark database ${databasePath}. Choose a new --output directory.`
    )
  }
  const database = openAgentGoDatabase(databasePath)
  const repository = new AgentGoRepository(database)
  const credentialStore = new FileCredentialStore(
    join(dataDirectory, 'credentials.json'),
    createEphemeralProtector()
  )
  const evidenceProtector = createEphemeralProtector()
  const evidenceStore = new EvidenceStore(database, artifactRoot, {
    protector: evidenceProtector
  })
  const requestHashKeyProvider = new EphemeralRequestHashKeyProvider()
  const requestAdapter = new LegacyV1RequestCompilerAdapter({
    repository,
    credentialStore,
    hashKeyProvider: requestHashKeyProvider,
    hashKey: requestHashKeyProvider.reference
  })
  const authority = new ExecutionAuthority(repository, requestHashKeyProvider)
  const policyBroker = new PolicyBroker(repository)
  const executionGuard = new PolicyExecutionGuard(
    repository,
    requestHashKeyProvider,
    credentialStore
  )
  const evidenceCapturePolicy = new EvidenceCapturePolicy()
  const executionService = new ExecutionService({
    repository,
    evidenceStore,
    httpRunner: new UndiciHttpRunner(executionGuard),
    browserRunner: new PlaywrightBrowserRunner({ headless: true }),
    requestAdapter,
    authority,
    policyBroker,
    executionGuard,
    evidenceCapturePolicy,
    hashKeyProvider: requestHashKeyProvider
  })
  const vulnerabilityPlatform = createVulnerabilityPlatform()
  const reportService = new ReportService(repository, evidenceStore, {
    familyDisplayNames: new FindingAssembler(
      vulnerabilityPlatform.definitionRegistry
    ).familyDisplayNames()
  })
  const modelGateway = new DefaultModelGateway({
    profiles: repository,
    credentials: credentialStore,
    prompts: new AgentPromptCatalog(),
    invocations: repository
  })
  const inventoryService = new InventoryService(
    repository,
    vulnerabilityPlatform.capabilityCatalog
  )
  const application = new AgentGoApplicationService({
    repository,
    credentialStore,
    evidenceStore,
    modelGateway,
    reportService,
    evidenceCapturePolicy,
    inventoryService,
    vulnerabilityPlatform,
    vulnerabilityExecutionEnvironment: 'attested-fixture'
  })
  const identitySessions = new IdentitySessionRepository(database)
  const coordinator = new DefaultScanCoordinator({
    repository,
    evidenceStore,
    executionPort: executionService,
    modelGateway,
    reportService,
    inventoryService,
    vulnerabilityPlatform,
    vulnerabilityExecutionEnvironment: 'attested-fixture',
    authorizationMatrixService: new AuthorizationMatrixService({
      repository,
      identitySessionRepository: identitySessions
    })
  })
  application.setScanCoordinator(coordinator)
  const fixture = await input.startFixture()
  const startedAt = new Date().toISOString()
  const predictions: BenchmarkPrediction[] = []
  const secrets: string[] = []

  try {
    await application.initialize()
    const fixturePort = Number(new URL(fixture.baseUrl).port)
    const collectorListenUrl = await coordinator.ensureCallbackCollectorListenUrl()
    const collectorScope = collectorListenUrl
      ? loopbackCollectorScopeAuthorization(collectorListenUrl)
      : undefined
    const plan = createDefaultScanPlan(vulnerabilityPlatform.defaultScanFamilies)

    for (const [caseIndex, item] of input.cases.entries()) {
      const caseStartedAt = Date.now()
      if (!item.executable) {
        predictions.push(
          BenchmarkPredictionSchema.parse({
            caseId: item.caseId,
            actualVerdict: 'inconclusive',
            evidenceRefs: [],
            evidenceRoles: [],
            durationMs: Date.now() - caseStartedAt,
            requestCount: 0,
            modelTokens: 0,
            estimatedCost: 0,
            planRevisions: 0,
            duplicateRequests: 0,
            recoveredFromCrash: false,
            runStatus: item.category === 'cleanup-failure' ? 'cleanup-failure' : 'not-run'
          })
        )
        console.log(
          `[${caseIndex + 1}/${input.cases.length}] ${item.caseId}: not-executed (${item.category})`
        )
        continue
      }

      const allowedPathPrefixes = [
        ...(item.allowedPathPrefixes ?? [item.endpoint]),
        '/callback',
        '/holdout/v1/callback'
      ]
      const deniedPathPrefixes = [...(item.deniedPathPrefixes ?? [])]
      const allowedOrigins = [
        fixture.baseUrl,
        ...(collectorScope ? [collectorScope.origin] : [])
      ]
      const allowedPorts = [
        fixturePort,
        ...(collectorScope ? [collectorScope.port] : [])
      ]
      const workspace = await application.createWorkspace({
        name: `${input.workspaceName} ${item.caseId}`,
        description: `Extended benchmark ${fixture.version} ${item.caseId}`
      })
      const target = await application.createTarget({
        workspaceId: workspace.id,
        name: item.caseId,
        baseUrl: baselineUrl(item, fixture.baseUrl),
        description: item.name,
        authorizationReference: `extended-benchmark:${item.caseId}`,
        scope: {
          allowedOrigins,
          allowedPathPrefixes,
          deniedPathPrefixes,
          allowedPorts,
          allowedIdentityIds: [],
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          networkEntries: [],
          maxRequestsPerMinute: 120,
          maxConcurrency: 1,
          authorizationReference: `extended-benchmark:${item.caseId}`
        }
      })
      const identity = await createCaseIdentities({
        application,
        targetId: target.target.id,
        item
      })
      secrets.push(...identity.secrets)
      await application.updateTarget({
        id: target.target.id,
        scope: {
          allowedOrigins,
          allowedPathPrefixes,
          deniedPathPrefixes,
          allowedPorts,
          allowedIdentityIds: identity.identityIds,
          allowActiveProbing: true,
          allowSensitiveProbing: false,
          allowPrivateNetworkTargets: true,
          allowLoopbackTargets: true,
          networkEntries: [],
          maxRequestsPerMinute: 120,
          maxConcurrency: 1,
          authorizationReference: `extended-benchmark:${item.caseId}`
        }
      })
      const scan = await application.createScan({
        targetId: target.target.id,
        name: item.name,
        description: `Extended benchmark ${item.caseId}`,
        families: [item.family],
        identityIds: identity.identityIds,
        ...(item.callback
          ? { callbackUrl: `${fixture.baseUrl}${item.callbackPath ?? '/callback'}` }
          : {}),
        budget: {
          ...plan.budget,
          maxRequests: 30,
          maxRequestsPerMinute: 120,
          maxConcurrency: 1,
          maxDurationMinutes: 5
        }
      })
      await application.controlScan(scan.id, 'start')
      let completed = await coordinator.waitForScan(scan.id)
      let reviewRound = 0
      const maximumReviewRounds = 8
      while (completed.status === 'awaiting-user' && reviewRound < maximumReviewRounds) {
        const pendingReviewVariantIds =
          await repository.listPendingActiveL1ReviewVariantIds(scan.id)
        if (pendingReviewVariantIds.length === 0) {
          break
        }
        for (const requestVariantId of pendingReviewVariantIds) {
          await application.reviewVariant({
            scanId: scan.id,
            requestVariantId,
            reviewStatus: 'reviewed',
            reviewedBy: `extended-benchmark:${item.caseId}`
          })
        }
        reviewRound += 1
        await application.controlScan(scan.id, 'resume')
        completed = await coordinator.waitForScan(scan.id)
      }

      if (completed.status === 'awaiting-user' && input.throwOnAwaitingUser) {
        throw new Error(
          `Scan ${scan.id} exceeded ${maximumReviewRounds} inventory review rounds.`
        )
      }
      if (
        completed.status !== 'completed' &&
        completed.status !== 'awaiting-user' &&
        item.category !== 'policy-denied'
      ) {
        if (input.throwOnAwaitingUser) {
          throw new Error(
            `Benchmark case ${item.caseId} ended with non-completed scan status ${completed.status}${
              completed.lastError ? `: ${completed.lastError}` : ''
            }.`
          )
        }
      }

      const finding = (await application.listFindings({ scanId: scan.id })).find(
        (candidate) => candidate.family === item.family
      )
      const actualVerdict = finding?.verdict ?? 'inconclusive'
      const runStatus =
        item.category === 'policy-denied'
          ? 'policy-denied'
          : completed.status === 'completed'
            ? 'completed'
            : 'not-run'
      predictions.push(
        BenchmarkPredictionSchema.parse({
          caseId: item.caseId,
          actualVerdict,
          evidenceRefs: finding?.evidenceRefs ?? [],
          evidenceRoles:
            actualVerdict === 'confirmed' && isLegacyV1VulnerabilityFamily(item.family)
              ? [...LEGACY_V1_EVIDENCE_ROLES[item.family]]
              : [],
          ...(finding
            ? {
                confirmationRuleId: `${finding.confirmationRuleId}@${finding.confirmationRuleVersion}`
              }
            : {}),
          durationMs: Date.now() - caseStartedAt,
          requestCount: completed.requestCount,
          modelTokens: completed.modelTokens,
          estimatedCost: completed.estimatedCost,
          planRevisions: 0,
          duplicateRequests: 0,
          recoveredFromCrash: false,
          runStatus
        })
      )
      console.log(
        `[${caseIndex + 1}/${input.cases.length}] ${item.caseId}: ${actualVerdict} (${runStatus}${
          completed.status !== 'completed' && completed.lastError
            ? `; ${completed.status}: ${completed.lastError}`
            : completed.status !== 'completed'
              ? `; scan=${completed.status}`
              : ''
        })`
      )
    }

    const safetyCounters = await deriveSafetyCounters({ database, artifactRoot, secrets })
    const suiteCases = suiteRegistry.list().flatMap((suite) => suite.cases)
    assertBenchmarkPredictionsComplete({
      cases: suiteCases,
      predictions,
      knownTechniqueIds: suiteRegistry.list().map((suite) => suite.techniqueId)
    })
    for (const suite of suiteRegistry.list()) {
      scoreTechniqueSuite({
        suite,
        predictions: predictions.filter((prediction) =>
          suite.cases.some((item) => item.caseId === prediction.caseId)
        ),
        fixtureVersion: fixture.version
      })
    }
    const summary = buildBenchmarkSummary({
      cases: input.cases.map(toSliceableCase),
      predictions,
      safetyCounters
    })
    const completedAt = new Date().toISOString()
    const metadata = {
      schemaVersion: 'agentgo-benchmark-run/1.0',
      fixtureVersion: fixture.version,
      resultClass: input.resultClass,
      startedAt,
      completedAt,
      provider: 'deterministic',
      model: 'agentgo-rules-v1',
      promptVersions: AGENT_PROMPT_VERSIONS,
      confirmationRules: Object.fromEntries(
        Object.entries(V1_CONFIRMATION_RULES).map(([family, rule]) => [
          family,
          `${rule.id}@${rule.version}`
        ])
      ),
      outputDirectory: input.outputDirectory,
      ...input.extraMetadata
    }
    await writeFile(
      join(input.outputDirectory, 'predictions.json'),
      `${JSON.stringify(predictions, null, 2)}\n`,
      'utf8'
    )
    await writeFile(
      join(input.outputDirectory, 'summary.json'),
      `${JSON.stringify({ metadata, summary }, null, 2)}\n`,
      'utf8'
    )
    await writeFile(
      join(input.outputDirectory, 'report.md'),
      `${renderBenchmarkMarkdown(summary)}\n`,
      'utf8'
    )
    console.log(
      JSON.stringify({
        status: summary.safety.passed ? 'completed' : 'safety-gate-failed',
        outputDirectory: input.outputDirectory,
        precision: summary.overall.precision,
        recall: summary.overall.recall,
        f1: summary.overall.f1,
        safetyPassed: summary.safety.passed
      })
    )
    if (!summary.safety.passed) {
      throw new Error(
        'Benchmark safety gates failed; generated artifacts are retained for audit.'
      )
    }
    return { outputDirectory: input.outputDirectory, summary, predictions, metadata }
  } finally {
    try {
      await coordinator.shutdown()
    } finally {
      try {
        await fixture.close()
      } finally {
        requestHashKeyProvider.dispose()
        database.close()
      }
    }
  }
}

export function compareBenchmarkSummaries(input: {
  readonly runs: readonly {
    readonly label: string
    readonly predictions: readonly BenchmarkPrediction[]
    readonly safetyPassed: boolean
    readonly precision: number
    readonly recall: number
    readonly f1: number
  }[]
}): {
  readonly identicalVerdicts: boolean
  readonly identicalSafety: boolean
  readonly identicalScores: boolean
  readonly mismatches: readonly string[]
} {
  const mismatches: string[] = []
  const [first, ...rest] = input.runs
  if (!first) {
    return {
      identicalVerdicts: true,
      identicalSafety: true,
      identicalScores: true,
      mismatches
    }
  }
  for (const run of rest) {
    if (run.safetyPassed !== first.safetyPassed) {
      mismatches.push(`${run.label} safety ${run.safetyPassed} != ${first.safetyPassed}`)
    }
    if (
      run.precision !== first.precision ||
      run.recall !== first.recall ||
      run.f1 !== first.f1
    ) {
      mismatches.push(
        `${run.label} scores P/R/F1 ${run.precision}/${run.recall}/${run.f1} != ${first.precision}/${first.recall}/${first.f1}`
      )
    }
    const firstById = new Map(first.predictions.map((item) => [item.caseId, item]))
    for (const prediction of run.predictions) {
      const baseline = firstById.get(prediction.caseId)
      if (!baseline) {
        mismatches.push(`${run.label} extra case ${prediction.caseId}`)
        continue
      }
      if (prediction.actualVerdict !== baseline.actualVerdict) {
        mismatches.push(
          `${run.label} ${prediction.caseId} verdict ${prediction.actualVerdict} != ${baseline.actualVerdict}`
        )
      }
      if ((prediction.runStatus ?? 'completed') !== (baseline.runStatus ?? 'completed')) {
        mismatches.push(
          `${run.label} ${prediction.caseId} runStatus ${prediction.runStatus} != ${baseline.runStatus}`
        )
      }
    }
    if (run.predictions.length !== first.predictions.length) {
      mismatches.push(
        `${run.label} prediction count ${run.predictions.length} != ${first.predictions.length}`
      )
    }
  }
  return {
    identicalVerdicts: mismatches.every((item) => !item.includes('verdict') && !item.includes('runStatus') && !item.includes('extra') && !item.includes('count')),
    identicalSafety: !mismatches.some((item) => item.includes('safety')),
    identicalScores: !mismatches.some((item) => item.includes('scores')),
    mismatches
  }
}
