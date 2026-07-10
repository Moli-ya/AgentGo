import { createServer, type Server as HttpServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import type { McpServerRecord } from '@agentgo/contracts'
import { DefaultMcpHub } from './index'

const activeServers: HttpServer[] = []

afterEach(async () => {
  await Promise.all(
    activeServers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve()))
    )
  )
})

function remoteRecord(url: string): McpServerRecord {
  const now = new Date().toISOString()
  return {
    id: 'mcp-test',
    name: 'HTTP fixture',
    transport: 'streamable-http',
    enabled: false,
    args: [],
    url,
    authType: 'bearer',
    credentialId: 'credential',
    environmentKeys: [],
    headerNames: [],
    timeoutMs: 5_000,
    roots: [],
    allowedAgentRoles: [],
    riskLabels: ['network-access'],
    status: 'untested',
    tools: [],
    resources: [],
    prompts: [],
    createdAt: now,
    updatedAt: now
  }
}

describe('DefaultMcpHub', () => {
  it('performs a real Streamable HTTP handshake and discovers capabilities', async () => {
    const httpServer = createServer(async (request, response) => {
      if (request.url !== '/mcp') {
        response.writeHead(404).end()
        return
      }
      if (request.headers.authorization !== 'Bearer fixture-token') {
        response.writeHead(401).end()
        return
      }
      if (request.method !== 'POST') {
        response.writeHead(405).end()
        return
      }

      const server = new McpServer({ name: 'agentgo-test-mcp', version: '1.2.3' })
      server.registerTool(
        'ping',
        { description: 'Safe fixture tool', inputSchema: {} },
        async () => ({ content: [{ type: 'text', text: 'pong' }] })
      )
      server.registerResource(
        'fixture-info',
        'agentgo://fixture/info',
        { mimeType: 'text/plain' },
        async () => ({
          contents: [{ uri: 'agentgo://fixture/info', text: 'fixture' }]
        })
      )
      server.registerPrompt(
        'review',
        { description: 'Review fixture', argsSchema: {} },
        async () => ({
          messages: [
            { role: 'user', content: { type: 'text', text: 'Review the fixture.' } }
          ]
        })
      )
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined
      })
      await server.connect(transport)
      await transport.handleRequest(request, response)
      response.on('close', () => {
        void transport.close()
        void server.close()
      })
    })
    activeServers.push(httpServer)
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve))
    const address = httpServer.address() as AddressInfo
    const hub = new DefaultMcpHub()

    const result = await hub.testConnection(
      remoteRecord(`http://127.0.0.1:${address.port}/mcp`),
      { token: 'fixture-token' }
    )

    expect(result.ok).toBe(true)
    expect(result.serverName).toBe('agentgo-test-mcp')
    expect(result.serverVersion).toBe('1.2.3')
    expect(result.tools).toEqual([{ name: 'ping', description: 'Safe fixture tool' }])
    expect(result.resources).toEqual([
      { uri: 'agentgo://fixture/info', name: 'fixture-info' }
    ])
    expect(result.prompts).toEqual([{ name: 'review', description: 'Review fixture' }])
  })

  it('blocks cloud metadata endpoints before opening a connection', async () => {
    const result = await new DefaultMcpHub().testConnection(
      remoteRecord('http://169.254.169.254/latest/mcp'),
      { token: 'fixture-token' }
    )

    expect(result.ok).toBe(false)
    expect(result.message).toContain('云元数据')
  })
})
