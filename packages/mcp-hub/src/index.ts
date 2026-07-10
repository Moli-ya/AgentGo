import { URL } from 'node:url'
import { lookup } from 'node:dns/promises'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import {
  StdioClientTransport,
  getDefaultEnvironment
} from '@modelcontextprotocol/sdk/client/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import type {
  McpConnectionTestResult,
  McpPromptSummary,
  McpResourceSummary,
  McpServerRecord,
  McpToolSummary
} from '@agentgo/contracts'

export interface McpConnectionSecrets {
  token?: string
  environment?: Record<string, string>
  headers?: Record<string, string>
}

export interface McpHub {
  testConnection(
    server: McpServerRecord,
    secrets?: McpConnectionSecrets
  ): Promise<McpConnectionTestResult>
}

const MAX_DISCOVERY_ITEMS = 500
const blockedMetadataHosts = new Set([
  '169.254.169.254',
  '169.254.170.2',
  '100.100.100.200',
  'metadata.google.internal'
])

function isMetadataAddress(address: string): boolean {
  const normalized = address.toLowerCase()
  return (
    normalized.startsWith('169.254.') ||
    normalized === '100.100.100.200' ||
    normalized.startsWith('fe80:') ||
    normalized === 'fd00:ec2::254'
  )
}

async function assertSafeRemoteUrl(url: URL): Promise<void> {
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('MCP Server URL 只允许 HTTP 或 HTTPS。')
  }
  if (url.username || url.password) {
    throw new Error('MCP Server URL 不得内嵌用户名或密码。')
  }
  if (blockedMetadataHosts.has(url.hostname.toLowerCase())) {
    throw new Error('禁止连接云元数据地址。')
  }
  const addresses = await lookup(url.hostname, { all: true, verbatim: true })
  if (addresses.some((entry) => isMetadataAddress(entry.address))) {
    throw new Error('禁止连接解析到云元数据或链路本地地址的 MCP Server。')
  }
}

function errorMessage(error: unknown, secrets: McpConnectionSecrets): string {
  let message = error instanceof Error ? error.message : '未知 MCP 连接错误。'
  const sensitiveValues = [
    secrets.token,
    ...Object.values(secrets.environment ?? {}),
    ...Object.values(secrets.headers ?? {})
  ].filter((value): value is string => Boolean(value))
  for (const value of sensitiveValues) message = message.replaceAll(value, '[REDACTED]')
  return message.slice(0, 3_000)
}

function optionalText(value: unknown, maxLength: number): string | undefined {
  return typeof value === 'string' && value.trim()
    ? value.trim().slice(0, maxLength)
    : undefined
}

async function discoverTools(client: Client, timeout: number): Promise<McpToolSummary[]> {
  const tools: McpToolSummary[] = []
  let cursor: string | undefined
  do {
    const page = await client.listTools(
      cursor ? { cursor } : undefined,
      { timeout, maxTotalTimeout: timeout }
    )
    for (const tool of page.tools) {
      if (tools.length >= MAX_DISCOVERY_ITEMS) break
      const description = optionalText(tool.description, 2_000)
      tools.push({
        name: tool.name.slice(0, 300),
        ...(description ? { description } : {})
      })
    }
    cursor = tools.length < MAX_DISCOVERY_ITEMS ? page.nextCursor : undefined
  } while (cursor)
  return tools
}

async function discoverResources(
  client: Client,
  timeout: number
): Promise<McpResourceSummary[]> {
  const resources: McpResourceSummary[] = []
  let cursor: string | undefined
  do {
    const page = await client.listResources(
      cursor ? { cursor } : undefined,
      { timeout, maxTotalTimeout: timeout }
    )
    for (const resource of page.resources) {
      if (resources.length >= MAX_DISCOVERY_ITEMS) break
      const name = optionalText(resource.name, 300)
      resources.push({
        uri: resource.uri.slice(0, 4_000),
        ...(name ? { name } : {})
      })
    }
    cursor = resources.length < MAX_DISCOVERY_ITEMS ? page.nextCursor : undefined
  } while (cursor)
  return resources
}

async function discoverPrompts(
  client: Client,
  timeout: number
): Promise<McpPromptSummary[]> {
  const prompts: McpPromptSummary[] = []
  let cursor: string | undefined
  do {
    const page = await client.listPrompts(
      cursor ? { cursor } : undefined,
      { timeout, maxTotalTimeout: timeout }
    )
    for (const prompt of page.prompts) {
      if (prompts.length >= MAX_DISCOVERY_ITEMS) break
      const description = optionalText(prompt.description, 2_000)
      prompts.push({
        name: prompt.name.slice(0, 300),
        ...(description ? { description } : {})
      })
    }
    cursor = prompts.length < MAX_DISCOVERY_ITEMS ? page.nextCursor : undefined
  } while (cursor)
  return prompts
}

export class DefaultMcpHub implements McpHub {
  async testConnection(
    server: McpServerRecord,
    secrets: McpConnectionSecrets = {}
  ): Promise<McpConnectionTestResult> {
    const startedAt = Date.now()
    const client = new Client(
      { name: 'agentgo-mcp-hub', version: '0.1.0' },
      { capabilities: {} }
    )
    let protocolVersion: string | undefined

    try {
      if (server.transport === 'stdio') {
        if (!server.command) throw new Error('STDIO MCP Server 缺少启动命令。')
        const transport = new StdioClientTransport({
          command: server.command,
          args: server.args,
          ...(server.cwd ? { cwd: server.cwd } : {}),
          ...(secrets.environment
            ? { env: { ...getDefaultEnvironment(), ...secrets.environment } }
            : {}),
          stderr: 'pipe'
        })
        await client.connect(transport, {
          timeout: server.timeoutMs,
          maxTotalTimeout: server.timeoutMs
        })
      } else {
        if (!server.url) throw new Error('Streamable HTTP MCP Server 缺少 URL。')
        const url = new URL(server.url)
        await assertSafeRemoteUrl(url)
        const headers: Record<string, string> = { ...(secrets.headers ?? {}) }
        if (server.authType === 'bearer') {
          if (!secrets.token) throw new Error('远程 MCP Server 缺少 Bearer Token。')
          headers.Authorization = `Bearer ${secrets.token}`
        } else if (server.authType === 'header') {
          if (!server.authHeaderName || !secrets.token) {
            throw new Error('远程 MCP Server 缺少自定义 Header 或 Token。')
          }
          headers[server.authHeaderName] = secrets.token
        }
        const transport = new StreamableHTTPClientTransport(url, {
          requestInit: { headers },
          fetch: async (input, init) => {
            const requestUrl = new URL(
              input instanceof Request ? input.url : String(input)
            )
            await assertSafeRemoteUrl(requestUrl)
            return fetch(input, { ...init, redirect: 'manual' })
          },
          reconnectionOptions: {
            maxReconnectionDelay: 2_000,
            initialReconnectionDelay: 250,
            reconnectionDelayGrowFactor: 1.5,
            maxRetries: 0
          }
        })
        await client.connect(transport, {
          timeout: server.timeoutMs,
          maxTotalTimeout: server.timeoutMs
        })
        protocolVersion = transport.protocolVersion
      }

      const capabilities = client.getServerCapabilities()
      const [tools, resources, prompts] = await Promise.all([
        capabilities?.tools ? discoverTools(client, server.timeoutMs) : [],
        capabilities?.resources ? discoverResources(client, server.timeoutMs) : [],
        capabilities?.prompts ? discoverPrompts(client, server.timeoutMs) : []
      ])
      const implementation = client.getServerVersion()
      const serverName = optionalText(implementation?.name, 300)
      const serverVersion = optionalText(implementation?.version, 100)
      return {
        ok: true,
        message: `MCP 初始化与能力发现成功：${tools.length} tools、${resources.length} resources、${prompts.length} prompts。`,
        durationMs: Date.now() - startedAt,
        ...(protocolVersion ? { protocolVersion } : {}),
        ...(serverName ? { serverName } : {}),
        ...(serverVersion ? { serverVersion } : {}),
        tools,
        resources,
        prompts
      }
    } catch (error) {
      return {
        ok: false,
        message: errorMessage(error, secrets),
        durationMs: Date.now() - startedAt,
        tools: [],
        resources: [],
        prompts: []
      }
    } finally {
      await client.close().catch(() => undefined)
    }
  }
}
