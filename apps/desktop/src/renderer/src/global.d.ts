import type { AgentGoDesktopApi } from '@agentgo/contracts'

declare global {
  interface Window {
    agentGo?: AgentGoDesktopApi
  }
}

export {}
