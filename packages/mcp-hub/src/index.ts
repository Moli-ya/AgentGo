export type McpHubStatus = 'deferred' | 'disabled' | 'ready'

export interface McpHubCapability {
  name: string
  riskLabels: Array<'file-access' | 'command-execution' | 'network-access'>
}

export const MCP_V1_STATUS: McpHubStatus = 'deferred'
