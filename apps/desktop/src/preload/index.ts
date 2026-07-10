import { contextBridge, ipcRenderer } from 'electron'
import {
  IPC_CHANNELS,
  type AgentGoDesktopApi,
  type BootstrapState,
  type PolicySelfCheckResult
} from '@agentgo/contracts'

const api: AgentGoDesktopApi = {
  getBootstrapState: () =>
    ipcRenderer.invoke(IPC_CHANNELS.getBootstrapState) as Promise<BootstrapState>,
  runPolicySelfCheck: () =>
    ipcRenderer.invoke(IPC_CHANNELS.runPolicySelfCheck) as Promise<PolicySelfCheckResult>,
  notifyRendererReady: () => {
    ipcRenderer.send(IPC_CHANNELS.rendererReady)
  }
}

contextBridge.exposeInMainWorld('agentGo', api)
