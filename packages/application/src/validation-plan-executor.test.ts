import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { createDefaultScanPlan, createRuntimeState } from '@agentgo/agent-runtime'
import {
  AgentGoRepository,
  FileCredentialStore,
  IdentitySessionRepository,
  openAgentGoDatabase,
  ValidationPlanRepository,
  type AgentGoDatabase,
  type SecretProtector
} from '@agentgo/db'
import { SessionVault } from './session-vault'
import {
  compileValidationPlan,
  ValidationPlanCompileError,
  type ValidationPlanDraft
} from './validation-plan-compiler'
import { ValidationPlanExecutor, type CallbackCollectorPort } from './validation-plan-executor'
import {
  compileLegacyIdorPlan,
  compileLegacySqliPlan,
  compileLegacySsrfPlan,
  compileLegacyXssPlan
} from './legacy-validation-plans'
import type {
  BrowserExecutionResultView,
  BrowserOfflineExecutionStepInput,
  ExecutionPort,
  ExecutionPortInput,
  HttpExecutionResultView,
  HttpExecutionStepInput,
  MediatedHttpExecutionStepInput,
  StoredExecutionResult,
  UnsupportedExecutionStepInput
} from './execution-port'

const directories: string[] = []
const openDatabases: AgentGoDatabase[] = []

afterEach(() => {
  for (const database of openDatabases.splice(0)) database.close()
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

class FakePort implements ExecutionPort {
  readonly http: HttpExecutionStepInput[] = []
  readonly browser: BrowserOfflineExecutionStepInput[] = []
  readonly mediated: MediatedHttpExecutionStepInput[] = []
  readonly identities: Array<string | undefined> = []
  readonly sessions: Array<string | undefined> = []

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
    if (input.adapterKind === 'http') {
      this.http.push(input)
      this.identities.push(input.identityId)
      this.sessions.push(input.sessionId)
      const body = new TextEncoder().encode(`${input.stepId}:${input.identityId ?? 'none'}`)
      return this.storedHttp({
        requestId: randomUUID(),
        status: 'succeeded',
        finalUrl: input.desiredUrl,
        method: 'GET',
        statusCode: 200,
        requestHeaders: [],
        responseHeaders: {},
        responseBody: body,
        responseBodySha256: 'ab'.repeat(32),
        responseBytes: body.byteLength,
        durationMs: 1,
        resolvedAddresses: ['127.0.0.1'],
        redirectChain: []
      })
    }
    if (input.adapterKind === 'browser-offline') {
      this.browser.push(input)
      return this.storedBrowser({
        requestId: randomUUID(),
        status: 'succeeded',
        finalUrl: input.baseUrl,
        links: [],
        forms: [],
        networkRequestsBlocked: 0,
        resultBytes: 0,
        durationMs: 1
      })
    }
    throw new Error('unsupported')
  }

  executeL2Http(): never {
    throw new Error('no l2')
  }

  async executeMediatedHttp(
    input: MediatedHttpExecutionStepInput
  ): Promise<StoredExecutionResult<HttpExecutionResultView>> {
    this.mediated.push(input)
    return this.storedHttp({
      requestId: randomUUID(),
      status: 'succeeded',
      finalUrl: input.desiredUrl,
      method: 'GET',
      statusCode: 200,
      requestHeaders: [],
      responseHeaders: {},
      responseBytes: 0,
      durationMs: 1,
      resolvedAddresses: ['127.0.0.1'],
      redirectChain: []
    })
  }

  private storedHttp(
    result: HttpExecutionResultView
  ): StoredExecutionResult<HttpExecutionResultView> {
    return {
      result,
      interactionIds: [],
      evidenceRefs: [],
      toolCallId: randomUUID(),
      toolCallIds: [randomUUID()],
      proposalIds: [randomUUID()],
      policyDecisionIds: [randomUUID()],
      grantIds: [randomUUID()],
      leaseIds: [randomUUID()]
    }
  }

  private storedBrowser(
    result: BrowserExecutionResultView
  ): StoredExecutionResult<BrowserExecutionResultView> {
    return {
      result,
      interactionIds: [],
      evidenceRefs: [],
      toolCallId: randomUUID(),
      toolCallIds: [randomUUID()],
      proposalIds: [randomUUID()],
      policyDecisionIds: [randomUUID()],
      grantIds: [randomUUID()],
      leaseIds: [randomUUID()]
    }
  }
}

async function openScan(): Promise<{
  scanId: string
  plans: ValidationPlanRepository
  repository: AgentGoRepository
  database: AgentGoDatabase
  targetId: string
  scopeSnapshotId: string
}> {
  const directory = mkdtempSync(join(tmpdir(), 'agentgo-plan-'))
  directories.push(directory)
  const database = openAgentGoDatabase(join(directory, 'agentgo.sqlite'))
  openDatabases.push(database)
  const repository = new AgentGoRepository(database)
  const workspace = await repository.createWorkspace({ name: 'plan', description: '' })
  const created = await repository.createTarget({
    workspaceId: workspace.id,
    name: 'lab',
    baseUrl: 'https://lab.example.test',
    description: '',
    authorizationReference: 'plan',
    scope: {
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
      maxConcurrency: 1
    }
  })
  const plan = createDefaultScanPlan(['sqli'])
  const scan = await repository.createScan(
    {
      targetId: created.target.id,
      name: 'plan',
      description: '',
      families: ['sqli'],
      identityIds: [],
      budget: plan.budget
    },
    { ...plan },
    { ...createRuntimeState() }
  )
  return {
    scanId: scan.id,
    plans: new ValidationPlanRepository(database),
    repository,
    database,
    targetId: created.target.id,
    scopeSnapshotId: created.scope.id
  }
}

const STEP_BUDGET = {
  maxRequests: 1,
  maxResponseBytes: 1024,
  timeoutMs: 1_000
} as const

function httpDraft(input: {
  readonly scanId: string
  readonly endpointId: string
  readonly capabilityIds?: string[]
  readonly left?: string
  readonly right?: string
  readonly extraSteps?: ValidationPlanDraft['steps']
  readonly maxRequests?: number
}): ValidationPlanDraft {
  return {
    scanId: input.scanId,
    familyId: 'sqli',
    techniqueId: 'sqli.boolean-differential',
    moduleVersion: '1.0.0',
    strategyVersion: '1.0.0',
    environment: 'attested-fixture',
    stopConditions: ['on-step-failure'],
    budget: {
      maxRequests: input.maxRequests ?? 4,
      maxBytes: 8_000_000,
      maxDurationMs: 10_000,
      maxFanOut: 2
    },
    steps: [
      {
        stepId: 'sqli.probe',
        kind: 'http-request',
        familyId: 'sqli',
        techniqueId: 'sqli.boolean-differential',
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        subjectRefs: [{ kind: 'endpoint', id: input.endpointId }],
        capabilityIds: input.capabilityIds ?? ['http.reviewed-read'],
        environment: 'attested-fixture',
        evidenceRoles: ['baseline'],
        budget: STEP_BUDGET,
        stopConditions: ['on-step-failure'],
        endpointId: input.endpointId,
        desiredUrl: 'https://lab.example.test/',
        purpose: 'read'
      },
      ...(input.left
        ? [
            {
              stepId: 'sqli.compare',
              kind: 'compare' as const,
              familyId: 'sqli' as const,
              techniqueId: 'sqli.boolean-differential',
              moduleVersion: '1.0.0',
              strategyVersion: '1.0.0',
              subjectRefs: [],
              capabilityIds: [],
              environment: 'attested-fixture' as const,
              evidenceRoles: [],
              budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
              stopConditions: ['on-step-failure' as const],
              leftStepId: input.left,
              rightStepId: input.right ?? 'sqli.probe',
              comparator: 'status-diff' as const
            }
          ]
        : []),
      ...(input.extraSteps ?? [])
    ]
  }
}

describe('ValidationPlan compiler', () => {
  it('rejects unknown capabilities', () => {
    expect(() =>
      compileValidationPlan(
        httpDraft({
          scanId: randomUUID(),
          endpointId: randomUUID(),
          capabilityIds: ['not.a.real.capability']
        })
      )
    ).toThrow(ValidationPlanCompileError)
    try {
      compileValidationPlan(
        httpDraft({
          scanId: randomUUID(),
          endpointId: randomUUID(),
          capabilityIds: ['not.a.real.capability']
        })
      )
    } catch (error) {
      expect(error).toBeInstanceOf(ValidationPlanCompileError)
      expect((error as ValidationPlanCompileError).code).toBe('unknown-capability')
    }
  })

  it('rejects unknown step kinds', () => {
    expect(() =>
      compileValidationPlan({
        ...httpDraft({ scanId: randomUUID(), endpointId: randomUUID() }),
        steps: [
          {
            stepId: 'sqli.invented',
            kind: 'invented-callback',
            familyId: 'sqli',
            techniqueId: 'sqli.boolean-differential',
            moduleVersion: '1.0.0',
            strategyVersion: '1.0.0',
            subjectRefs: [],
            capabilityIds: [],
            environment: 'attested-fixture',
            evidenceRoles: [],
            budget: STEP_BUDGET,
            stopConditions: ['on-step-failure']
          }
        ]
      } as unknown as ValidationPlanDraft)
    ).toThrow(/step kind|invalid/i)
  })

  it('rejects dangling compare references and budget overflow', () => {
    const scanId = randomUUID()
    const endpointId = randomUUID()
    expect(() =>
      compileValidationPlan(
        httpDraft({
          scanId,
          endpointId,
          left: 'sqli.missing',
          right: 'sqli.also-missing'
        })
      )
    ).toThrow(ValidationPlanCompileError)
    try {
      compileValidationPlan(
        httpDraft({
          scanId,
          endpointId,
          left: 'sqli.missing',
          right: 'sqli.also-missing'
        })
      )
    } catch (error) {
      expect((error as ValidationPlanCompileError).code).toBe('dangling-ref')
    }
    expect(() =>
      compileValidationPlan(
        httpDraft({
          scanId,
          endpointId,
          maxRequests: 1,
          extraSteps: [
            {
              stepId: 'sqli.second',
              kind: 'http-request',
              familyId: 'sqli',
              techniqueId: 'sqli.boolean-differential',
              moduleVersion: '1.0.0',
              strategyVersion: '1.0.0',
              subjectRefs: [{ kind: 'endpoint', id: endpointId }],
              capabilityIds: ['http.reviewed-read'],
              environment: 'attested-fixture',
              evidenceRoles: ['test'],
              budget: STEP_BUDGET,
              stopConditions: ['on-step-failure'],
              endpointId,
              desiredUrl: 'https://lab.example.test/b',
              purpose: 'read'
            }
          ]
        })
      )
    ).toThrow(/budget/i)
  })

  it('rejects a redirect allowance that the request budget cannot cover', () => {
    const draft = httpDraft({ scanId: randomUUID(), endpointId: randomUUID() })
    const [step] = draft.steps
    expect(step?.kind).toBe('http-request')
    expect(() =>
      compileValidationPlan({
        ...draft,
        steps: [
          {
            ...(step as Extract<ValidationPlanDraft['steps'][number], { kind: 'http-request' }>),
            maxRedirects: 1
          }
        ]
      })
    ).toThrow(/initial request and every permitted redirect hop/i)
  })

  it('rejects a callback consumer that does not depend on a register step', () => {
    const scanId = randomUUID()
    expect(() =>
      compileValidationPlan({
        scanId,
        familyId: 'ssrf',
        techniqueId: 'ssrf.controlled-proof-response',
        moduleVersion: '1.0.0',
        strategyVersion: '1.0.0',
        environment: 'attested-fixture',
        stopConditions: ['on-step-failure'],
        budget: {
          maxRequests: 1,
          maxBytes: 1024,
          maxDurationMs: 5_000,
          maxFanOut: 1
        },
        steps: [
          {
            stepId: 'ssrf.consume',
            kind: 'callback-consume',
            familyId: 'ssrf',
            techniqueId: 'ssrf.controlled-proof-response',
            moduleVersion: '1.0.0',
            strategyVersion: '1.0.0',
            subjectRefs: [],
            capabilityIds: ['oob.controlled-observe'],
            environment: 'attested-fixture',
            evidenceRoles: ['callback-proof'],
            budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
            stopConditions: ['on-step-failure'],
            collectorFromStepId: 'ssrf.consume'
          }
        ]
      })
    ).toThrow(/callback-register source/i)
  })
})

describe('ValidationPlan executor', () => {
  it('runs the four legacy adapter shapes and fail-closes OOB without a collector', async () => {
    const { scanId, plans } = await openScan()
    const endpointId = randomUUID()
    const ownerId = randomUUID()
    const otherId = randomUUID()
    const url = 'https://lab.example.test/search'
    expect(compileLegacySqliPlan({ scanId, endpointId, desiredUrl: url }).steps).toHaveLength(4)
    expect(compileLegacyXssPlan({ scanId, endpointId, desiredUrl: url }).steps).toHaveLength(3)
    expect(compileLegacySsrfPlan({ scanId, endpointId, desiredUrl: url }).steps[0]?.kind).toBe(
      'callback-register'
    )
    expect(
      compileLegacyIdorPlan({
        scanId,
        endpointId,
        desiredUrl: url,
        ownerId,
        otherId
      }).steps.some((step) => step.kind === 'identity-switch')
    ).toBe(true)

    const port = new FakePort()
    const executor = new ValidationPlanExecutor({
      plans,
      execution: port,
      agentRunId: randomUUID()
    })
    const ssrf = await executor.run(compileLegacySsrfPlan({ scanId, endpointId, desiredUrl: url }))
    expect(ssrf.status).toBe('fail-closed')
    expect(port.http).toHaveLength(0)

    const sqli = await executor.run(
      compileLegacySqliPlan({ scanId, endpointId, desiredUrl: url })
    )
    expect(sqli.status).toBe('succeeded')
    expect(port.http).toHaveLength(3)

    const xss = await executor.run(compileLegacyXssPlan({ scanId, endpointId, desiredUrl: url }))
    expect(xss.status).toBe('succeeded')
    expect(port.browser).toHaveLength(1)

    const idor = await executor.run(
      compileLegacyIdorPlan({
        scanId,
        endpointId,
        desiredUrl: url,
        ownerId,
        otherId
      })
    )
    expect(idor.status).toBe('succeeded')
    expect(port.identities.filter(Boolean)).toEqual([
      ownerId,
      ownerId,
      otherId
    ])
    const stepRuns = await plans.listStepRuns(idor.runId)
    expect(
      stepRuns.filter((step) => step.kind === 'http-request').every((step) => step.leaseId)
    ).toBe(true)
  })

  it('runs bounded parallel groups and fails closed when a required callback collector is unavailable', async () => {
    const { scanId, plans } = await openScan()
    const endpointId = randomUUID()
    const port = new FakePort()
    const missingCollector = new ValidationPlanExecutor({
      plans,
      execution: port,
      agentRunId: randomUUID()
    })
    const callbackPlan = {
      scanId,
      familyId: 'ssrf',
      techniqueId: 'ssrf.controlled-proof-response',
      moduleVersion: '1.0.0',
      strategyVersion: '1.0.0',
      environment: 'attested-fixture',
      stopConditions: ['on-step-failure'],
      budget: {
        maxRequests: 1,
        maxBytes: 2,
        maxDurationMs: 5_000,
        maxFanOut: 1
      },
      steps: [
        {
          stepId: 'ssrf.register',
          kind: 'callback-register',
          familyId: 'ssrf',
          techniqueId: 'ssrf.controlled-proof-response',
          moduleVersion: '1.0.0',
          strategyVersion: '1.0.0',
          subjectRefs: [],
          capabilityIds: ['oob.controlled-observe'],
          environment: 'attested-fixture',
          evidenceRoles: ['callback-proof'],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
          stopConditions: ['on-step-failure'],
          tokenSlot: 'ssrf.token'
        },
        {
          stepId: 'ssrf.consume',
          kind: 'callback-consume',
          familyId: 'ssrf',
          techniqueId: 'ssrf.controlled-proof-response',
          moduleVersion: '1.0.0',
          strategyVersion: '1.0.0',
          subjectRefs: [],
          capabilityIds: ['oob.controlled-observe'],
          environment: 'attested-fixture',
          evidenceRoles: ['callback-proof'],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
          stopConditions: ['on-step-failure'],
          collectorFromStepId: 'ssrf.register'
        }
      ]
    } satisfies ValidationPlanDraft
    const callbackRun = await missingCollector.run(callbackPlan)
    expect(callbackRun.status).toBe('fail-closed')

    const collector: CallbackCollectorPort = {
      async register() {
        return { collectorId: 'collector-1' }
      },
      async poll() {
        return { received: true }
      },
      async consume() {
        return {}
      }
    }
    const executor = new ValidationPlanExecutor({
      plans,
      execution: port,
      callbackCollector: collector,
      agentRunId: randomUUID()
    })
    const run = await executor.run({
      scanId,
      familyId: 'sqli',
      techniqueId: 'sqli.boolean-differential',
      moduleVersion: '1.0.0',
      strategyVersion: '1.0.0',
      environment: 'attested-fixture',
      stopConditions: ['on-step-failure'],
      budget: {
        maxRequests: 4,
        maxBytes: 8_000_000,
        maxDurationMs: 10_000,
        maxFanOut: 2
      },
      steps: [
        {
          stepId: 'sqli.group',
          kind: 'bounded-parallel-group',
          familyId: 'sqli',
          techniqueId: 'sqli.boolean-differential',
          moduleVersion: '1.0.0',
          strategyVersion: '1.0.0',
          subjectRefs: [],
          capabilityIds: [],
          environment: 'attested-fixture',
          evidenceRoles: [],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
          stopConditions: ['on-step-failure'],
          childStepIds: ['sqli.left', 'sqli.right'],
          maxFanOut: 2,
          fixtureOnly: true
        },
        {
          stepId: 'sqli.left',
          kind: 'http-request',
          familyId: 'sqli',
          techniqueId: 'sqli.boolean-differential',
          moduleVersion: '1.0.0',
          strategyVersion: '1.0.0',
          subjectRefs: [{ kind: 'endpoint', id: endpointId }],
          capabilityIds: ['http.reviewed-read'],
          environment: 'attested-fixture',
          evidenceRoles: ['baseline'],
          budget: STEP_BUDGET,
          stopConditions: ['on-step-failure'],
          endpointId,
          desiredUrl: 'https://lab.example.test/a',
          purpose: 'read'
        },
        {
          stepId: 'sqli.right',
          kind: 'http-request',
          familyId: 'sqli',
          techniqueId: 'sqli.boolean-differential',
          moduleVersion: '1.0.0',
          strategyVersion: '1.0.0',
          subjectRefs: [{ kind: 'endpoint', id: endpointId }],
          capabilityIds: ['http.reviewed-read'],
          environment: 'attested-fixture',
          evidenceRoles: ['test'],
          budget: STEP_BUDGET,
          stopConditions: ['on-step-failure'],
          endpointId,
          desiredUrl: 'https://lab.example.test/b',
          purpose: 'read'
        }
      ]
    })
    expect(run.status).toBe('succeeded')
    expect(port.http.length).toBeGreaterThanOrEqual(2)
  })

  it('fail-closes cleanup without product L2 and runs mediated reads with a variant id', async () => {
    const { scanId, plans } = await openScan()
    const endpointId = randomUUID()
    const variantId = randomUUID()
    const port = new FakePort()
    const executor = new ValidationPlanExecutor({
      plans,
      execution: port,
      agentRunId: randomUUID()
    })
    const cleanup = await executor.run({
      scanId,
      familyId: 'sqli',
      techniqueId: 'sqli.boolean-differential',
      moduleVersion: '1.0.0',
      strategyVersion: '1.0.0',
      environment: 'attested-fixture',
      stopConditions: ['on-step-failure'],
      budget: {
        maxRequests: 1,
        maxBytes: 1024,
        maxDurationMs: 5_000,
        maxFanOut: 1
      },
      steps: [
        {
          stepId: 'sqli.cleanup',
          kind: 'cleanup',
          familyId: 'sqli',
          techniqueId: 'sqli.boolean-differential',
          moduleVersion: '1.0.0',
          strategyVersion: '1.0.0',
          subjectRefs: [],
          capabilityIds: ['http.test-object-write'],
          environment: 'attested-fixture',
          evidenceRoles: ['cleanup-proof'],
          budget: { maxRequests: 0, maxResponseBytes: 1, timeoutMs: 1_000 },
          stopConditions: ['on-step-failure'],
          testObjectRef: {
            id: randomUUID(),
            version: 1,
            ownerRef: randomUUID(),
            scopeSnapshotId: randomUUID(),
            statusSummary: 'ready'
          },
          approvalBundleRef: randomUUID()
        }
      ]
    })
    expect(cleanup.status).toBe('fail-closed')

    const mediated = await executor.run({
      scanId,
      familyId: 'xss',
      techniqueId: 'xss.reflected-inert-marker',
      moduleVersion: '1.0.0',
      strategyVersion: '1.0.0',
      environment: 'attested-fixture',
      stopConditions: ['on-step-failure'],
      budget: {
        maxRequests: 1,
        maxBytes: 1024,
        maxDurationMs: 5_000,
        maxFanOut: 1
      },
      steps: [
        {
          stepId: 'xss.mediated',
          kind: 'browser-mediated-read',
          familyId: 'xss',
          techniqueId: 'xss.reflected-inert-marker',
          moduleVersion: '1.0.0',
          strategyVersion: '1.0.0',
          subjectRefs: [{ kind: 'endpoint', id: endpointId }],
          capabilityIds: ['http.reviewed-read'],
          environment: 'attested-fixture',
          evidenceRoles: ['browser-observation'],
          budget: STEP_BUDGET,
          stopConditions: ['on-step-failure'],
          endpointId,
          requestVariantId: variantId,
          desiredUrl: 'https://lab.example.test/'
        }
      ]
    })
    expect(mediated.status).toBe('succeeded')
    expect(port.mediated[0]?.requestVariantId).toBe(variantId)
  })

  it('binds a distinct SessionVault generation on each identity-switch', async () => {
    const { scanId, plans, repository, database, targetId } = await openScan()
    const owner = await repository.saveIdentity({
      targetId,
      label: 'Owner',
      role: 'owner',
      authType: 'bearer',
      isTestIdentity: true,
      ownedResourceIds: ['res-a']
    })
    const other = await repository.saveIdentity({
      targetId,
      label: 'Other',
      role: 'member',
      authType: 'bearer',
      isTestIdentity: true,
      ownedResourceIds: ['res-b']
    })
    const mask = 0x5a
    const transform = (value: Buffer): Buffer =>
      Buffer.from(value.map((byte) => byte ^ mask))
    const protector: SecretProtector = {
      isAvailable: () => true,
      protect: (value) => transform(Buffer.from(value, 'utf8')),
      unprotect: (value) => transform(value).toString('utf8')
    }
    const vault = new SessionVault({
      identitySessionRepository: new IdentitySessionRepository(database),
      repository,
      credentialStore: new FileCredentialStore(
        join(directories[directories.length - 1]!, 'credentials.json'),
        protector
      )
    })
    const port = new FakePort()
    const executor = new ValidationPlanExecutor({
      plans,
      execution: port,
      agentRunId: randomUUID(),
      sessionVault: vault,
      repository
    })
    const run = await executor.run(
      compileLegacyIdorPlan({
        scanId,
        endpointId: randomUUID(),
        desiredUrl: 'https://lab.example.test/resource',
        ownerId: owner.id,
        otherId: other.id
      })
    )
    expect(run.status).toBe('succeeded')
    expect(port.sessions.filter(Boolean)).toHaveLength(3)
    expect(new Set(port.sessions.filter(Boolean)).size).toBe(2)
    const observations = await plans.listObservations(run.runId)
    const switches = observations.filter((item) => item.kind === 'identity')
    expect(switches).toHaveLength(2)
    expect(
      switches.every(
        (item) =>
          typeof item.payloadJson.sessionGeneration === 'number' &&
          typeof item.payloadJson.sessionHash === 'string'
      )
    ).toBe(true)
    const serialized = JSON.stringify(switches)
    expect(serialized).not.toMatch(/cookie|authorization|bearer|token=/i)
  })
})
