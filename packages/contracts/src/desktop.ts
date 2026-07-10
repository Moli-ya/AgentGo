import type { AgentRole, ScanPhase, VulnerabilityFamily } from './workflow'
import type { PolicyDecision } from './security'

export interface BootstrapState {
  appVersion: string
  milestone: string
  projectStatus: string
  agents: AgentRole[]
  phases: ScanPhase[]
  vulnerabilityFamilies: VulnerabilityFamily[]
  safeguards: string[]
}

export interface PolicySelfCheckResult {
  safeProbe: PolicyDecision
  destructiveProbe: PolicyDecision
  note: string
}

export interface AgentGoDesktopApi {
  getBootstrapState: () => Promise<BootstrapState>
  runPolicySelfCheck: () => Promise<PolicySelfCheckResult>
  notifyRendererReady: () => void
}

export const IPC_CHANNELS = {
  getBootstrapState: 'agentgo:get-bootstrap-state',
  runPolicySelfCheck: 'agentgo:run-policy-self-check',
  rendererReady: 'agentgo:renderer-ready'
} as const
