import { randomUUID } from 'node:crypto'
import type { BrowserExecutionGuard } from '@agentgo/browser-runner'
import type { PolicyDecision, ProbeAction } from '@agentgo/contracts'
import type {
  HttpExecutionAuthorizationInput,
  HttpExecutionGuard
} from '@agentgo/http-runner'
import {
  AgentGoRepository,
  type ProbeProposalRecord,
  type StoredPolicyDecision
} from '@agentgo/db'
import {
  evaluateProbe,
  evaluateResolvedAddresses
} from '@agentgo/security-policy'

export interface PolicyBrokerResult {
  proposal: ProbeProposalRecord
  decision: StoredPolicyDecision
}

export class PolicyBroker {
  constructor(private readonly repository: AgentGoRepository) {}

  async evaluate(input: {
    scanId: string
    agentRunId: string
    action: Omit<ProbeAction, 'id'> & { id?: string }
    stopConditions: string[]
    approvedBy?: string
  }): Promise<PolicyBrokerResult> {
    const scan = await this.repository.getScanRow(input.scanId)
    if (!scan) throw new Error('Cannot evaluate a proposal for a missing scan.')
    const scope = await this.repository.getScope(scan.scopeSnapshotId)
    if (!scope) throw new Error('The scan scope snapshot is missing.')
    const action: ProbeAction = {
      ...input.action,
      id: input.action.id ?? randomUUID(),
      scopeSnapshotId: scope.id
    }
    const proposal = await this.repository.createProbeProposal({
      scanId: input.scanId,
      agentRunId: input.agentRunId,
      action,
      stopConditions: input.stopConditions
    })
    const evaluated: PolicyDecision = evaluateProbe(action, scope)
    const decision = await this.repository.recordPolicyDecision({
      proposalId: proposal.id,
      scopeSnapshotId: scope.id,
      decision: evaluated,
      ...(input.approvedBy ? { approvedBy: input.approvedBy } : {})
    })
    await this.repository.addScanEvent({
      scanId: input.scanId,
      type: 'policy',
      level: decision.allowed ? 'info' : 'warning',
      message: decision.allowed
        ? `SecurityPolicy 已批准：${action.summary}`
        : `SecurityPolicy 已拒绝：${decision.reasons.join('；')}`,
      detail: {
        proposalId: proposal.id,
        policyDecisionId: decision.id,
        code: decision.code,
        targetUrl: decision.normalizedTarget ?? action.targetUrl
      }
    })
    return { proposal, decision }
  }
}

type BrowserAuthorizationInput = Parameters<BrowserExecutionGuard['authorize']>[0]

export class PolicyExecutionGuard
  implements HttpExecutionGuard, BrowserExecutionGuard
{
  constructor(private readonly repository: AgentGoRepository) {}

  async authorize(
    input: HttpExecutionAuthorizationInput | BrowserAuthorizationInput
  ): Promise<void> {
    const context = await this.repository.getExecutionDecision(input.policyDecisionId)
    if (!context) throw new Error('Policy decision does not exist.')
    if (!context.decision.allowed || context.decision.requiresApproval) {
      throw new Error('Policy decision does not authorize execution.')
    }
    if (
      context.decision.validUntil &&
      Date.parse(context.decision.validUntil) <= Date.now()
    ) {
      throw new Error('Policy decision expired before execution.')
    }
    if (context.scanStatus !== 'running') {
      throw new Error(`Scan status ${context.scanStatus} does not allow execution.`)
    }
    if (context.requestCount >= context.scanBudget.maxRequests) {
      throw new Error('Scan request budget is exhausted.')
    }

    const url = 'url' in input ? input.url : input.baseUrl
    const method = 'method' in input ? input.method : context.proposal.action.method
    const revalidation = evaluateProbe(
      {
        ...context.proposal.action,
        targetUrl: url,
        method,
        scopeSnapshotId: context.scope.id
      },
      context.scope
    )
    if (!revalidation.allowed) {
      throw new Error(
        `${'redirectFrom' in input && input.redirectFrom ? 'Redirect' : 'Execution'} revalidation failed: ${revalidation.reasons.join('; ')}`
      )
    }

    if ('addresses' in input) {
      const networkDecision = evaluateResolvedAddresses(
        input.addresses.map((address) => address.address),
        context.scope
      )
      if (!networkDecision.allowed) {
        throw new Error(networkDecision.reasons.join('; '))
      }
    }
  }
}
