import type {
  AgentGoDesktopApi,
  BootstrapState,
  PolicySelfCheckResult
} from '@agentgo/contracts'

const previewState: BootstrapState = {
  appVersion: '0.1.0-preview',
  milestone: 'M0',
  projectStatus: '浅色桌面工作台与安全主动探测骨架已建立',
  agents: ['planner', 'knowledge', 'strategy', 'analysis', 'verifier'],
  phases: [
    'intake',
    'passive-recon',
    'active-enum',
    'hypothesis',
    'validation',
    'verification',
    'report'
  ],
  vulnerabilityFamilies: ['sqli', 'xss', 'ssrf', 'idor'],
  safeguards: [
    '所有主动动作经过确定性 SecurityPolicy',
    'L1 低影响探测允许，L2 逐次批准',
    'DROP/DELETE/持久化/越界等 L3 动作永久拒绝',
    'Confirmed 结论必须绑定规则和证据'
  ]
}

const previewSelfCheck: PolicySelfCheckResult = {
  safeProbe: {
    allowed: true,
    requiresApproval: false,
    code: 'allowed',
    reasons: ['动作位于授权范围内，且符合当前主动探测等级。'],
    normalizedTarget: 'https://lab.example.test/search?q=agentgo-marker'
  },
  destructiveProbe: {
    allowed: false,
    requiresApproval: false,
    code: 'destructive-action',
    reasons: ['检测到破坏性或数据写入动作。'],
    normalizedTarget: 'https://lab.example.test/api/query'
  },
  note: 'Renderer 预览模式使用静态策略结果，不发送网络请求。'
}

const previewApi: AgentGoDesktopApi = {
  getBootstrapState: async () => previewState,
  runPolicySelfCheck: async () => previewSelfCheck,
  notifyRendererReady: () => undefined
}

export function getDesktopApi(): AgentGoDesktopApi {
  if (window.agentGo) {
    return window.agentGo
  }

  if (import.meta.env.DEV) {
    return previewApi
  }

  throw new Error('AgentGo Preload bridge is unavailable.')
}
