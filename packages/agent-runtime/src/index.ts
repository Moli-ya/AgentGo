import type {
  AgentRole,
  ProbeLevel,
  ScanBudget,
  ScanPhase,
  VulnerabilityFamily
} from '@agentgo/contracts'

export const V1_AGENT_ROLES: AgentRole[] = [
  'planner',
  'knowledge',
  'strategy',
  'analysis',
  'verifier'
]

export interface PhaseDefinition {
  id: ScanPhase
  label: string
  checkpoint: string
  allowedProbeLevels: ProbeLevel[]
}

export const SRC_PHASES: PhaseDefinition[] = [
  {
    id: 'intake',
    label: '授权与范围',
    checkpoint: 'Scope、身份、预算和禁止动作已确认',
    allowedProbeLevels: ['passive']
  },
  {
    id: 'passive-recon',
    label: '被动侦察',
    checkpoint: '目标入口、技术栈假设和来源已记录',
    allowedProbeLevels: ['passive']
  },
  {
    id: 'active-enum',
    label: '安全主动枚举',
    checkpoint: '页面、接口、参数、身份和基线矩阵已形成',
    allowedProbeLevels: ['active-safe']
  },
  {
    id: 'hypothesis',
    label: '假设与知识检索',
    checkpoint: '候选漏洞、KnowledgePack 和验证预算已形成',
    allowedProbeLevels: ['passive']
  },
  {
    id: 'validation',
    label: '策略批准的主动验证',
    checkpoint: '基线、测试、负对照和清理结果已保存',
    allowedProbeLevels: ['active-safe', 'active-sensitive']
  },
  {
    id: 'verification',
    label: '独立复核',
    checkpoint: '确认规则已给出三态 Verdict',
    allowedProbeLevels: ['passive']
  },
  {
    id: 'report',
    label: '证据与修复报告',
    checkpoint: '结论、证据、修复和复测步骤已归档',
    allowedProbeLevels: ['passive']
  }
]

export interface ScanPlan {
  version: string
  phases: ScanPhase[]
  families: VulnerabilityFamily[]
  budget: ScanBudget
  stopConditions: string[]
}

export type RuntimeStatus =
  | 'running'
  | 'paused'
  | 'awaiting-user'
  | 'completed'
  | 'failed'
  | 'cancelled'

export interface ScanRuntimeState {
  phase: ScanPhase
  status: RuntimeStatus
  checkpointRefs: string[]
  actionFingerprints: string[]
  planRevisions: number
  noEvidenceStreak: number
}

export type RuntimeEvent =
  | { type: 'phase-completed'; checkpointRef: string }
  | { type: 'pause' }
  | { type: 'resume' }
  | { type: 'await-user' }
  | { type: 'fail' }
  | { type: 'cancel' }

export function createDefaultScanPlan(
  families: readonly VulnerabilityFamily[] = []
): ScanPlan {
  return {
    version: '2026-07-10',
    phases: SRC_PHASES.map((phase) => phase.id),
    families: [...families],
    budget: {
      maxRequests: 300,
      maxRequestsPerMinute: 30,
      maxConcurrency: 2,
      maxPlanRevisions: 3,
      maxDurationMinutes: 60,
      maxModelTokens: 80_000,
      maxEstimatedCost: 10
    },
    stopConditions: [
      '获得满足确认规则的最小证据',
      '离开授权范围',
      '出现非预期副作用',
      '达到请求、时间或费用预算',
      '连续重复且无新证据'
    ]
  }
}

export function nextPhase(current: ScanPhase): ScanPhase | undefined {
  const index = SRC_PHASES.findIndex((phase) => phase.id === current)
  return SRC_PHASES[index + 1]?.id
}

export function isProbeLevelAllowed(phase: ScanPhase, level: ProbeLevel): boolean {
  return (
    SRC_PHASES.find((definition) => definition.id === phase)?.allowedProbeLevels.includes(
      level
    ) ?? false
  )
}

export function createRuntimeState(): ScanRuntimeState {
  return {
    phase: 'intake',
    status: 'running',
    checkpointRefs: [],
    actionFingerprints: [],
    planRevisions: 0,
    noEvidenceStreak: 0
  }
}

export function transitionRuntime(
  state: ScanRuntimeState,
  event: RuntimeEvent
): ScanRuntimeState {
  if (['completed', 'failed', 'cancelled'].includes(state.status)) {
    throw new Error(`Cannot transition a terminal runtime in status ${state.status}.`)
  }

  if (event.type === 'pause') {
    return { ...state, status: 'paused' }
  }

  if (event.type === 'await-user') {
    return { ...state, status: 'awaiting-user' }
  }

  if (event.type === 'resume') {
    if (!['paused', 'awaiting-user'].includes(state.status)) {
      throw new Error('Only paused or awaiting-user runtimes can resume.')
    }
    return { ...state, status: 'running' }
  }

  if (event.type === 'fail') {
    return { ...state, status: 'failed' }
  }

  if (event.type === 'cancel') {
    return { ...state, status: 'cancelled' }
  }

  if (state.status !== 'running') {
    throw new Error('A phase can only complete while the runtime is running.')
  }

  const followingPhase = nextPhase(state.phase)
  return {
    ...state,
    phase: followingPhase ?? state.phase,
    status: followingPhase ? 'running' : 'completed',
    checkpointRefs: [...state.checkpointRefs, event.checkpointRef]
  }
}

export function registerActionResult(
  state: ScanRuntimeState,
  fingerprint: string,
  producedNewEvidence: boolean
): { state: ScanRuntimeState; duplicate: boolean } {
  const duplicate = state.actionFingerprints.includes(fingerprint)

  return {
    duplicate,
    state: {
      ...state,
      actionFingerprints: duplicate
        ? state.actionFingerprints
        : [...state.actionFingerprints, fingerprint],
      noEvidenceStreak: producedNewEvidence ? 0 : state.noEvidenceStreak + 1
    }
  }
}

export function registerPlanRevision(
  state: ScanRuntimeState,
  plan: ScanPlan
): ScanRuntimeState {
  if (state.planRevisions >= plan.budget.maxPlanRevisions) {
    throw new Error('Plan revision budget exhausted.')
  }

  return {
    ...state,
    planRevisions: state.planRevisions + 1
  }
}

export function shouldStopForStagnation(
  state: ScanRuntimeState,
  maximumNoEvidenceStreak = 3
): boolean {
  return state.noEvidenceStreak >= maximumNoEvidenceStreak
}
