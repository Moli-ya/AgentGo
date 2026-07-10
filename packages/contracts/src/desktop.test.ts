import { describe, expect, it } from 'vitest'
import {
  KnowledgeIntelligenceCandidateSchema,
  SaveMcpServerInputSchema
} from './application'
import { DesktopOutputSchemas, PolicySelfCheckResultSchema } from './desktop'

describe('desktop IPC output contracts', () => {
  it('validates and strips fields outside the renderer contract', () => {
    const parsed = DesktopOutputSchemas.workspace.parse({
      id: 'workspace-1',
      name: 'Authorized lab',
      description: '',
      createdAt: '2026-07-10T00:00:00.000Z',
      updatedAt: '2026-07-10T00:00:00.000Z',
      internalSecret: 'must-not-cross-ipc'
    })

    expect(parsed).not.toHaveProperty('internalSecret')
  })

  it('rejects an unknown policy decision code before it reaches the renderer', () => {
    const result = PolicySelfCheckResultSchema.safeParse({
      safeProbe: {
        allowed: true,
        requiresApproval: false,
        code: 'invented-code',
        reasons: []
      },
      destructiveProbe: {
        allowed: false,
        requiresApproval: false,
        code: 'destructive-action',
        reasons: ['blocked']
      },
      note: 'local check'
    })

    expect(result.success).toBe(false)
  })

  it('validates MCP transport requirements and strips secret fields from output', () => {
    expect(
      SaveMcpServerInputSchema.safeParse({
        name: 'Missing command',
        transport: 'stdio',
        enabled: false,
        args: [],
        authType: 'none',
        timeoutMs: 5_000,
        roots: [],
        allowedAgentRoles: [],
        riskLabels: []
      }).success
    ).toBe(false)

    const now = '2026-07-10T00:00:00.000Z'
    const parsed = DesktopOutputSchemas.mcpServer.parse({
      id: 'mcp-1',
      name: 'Remote MCP',
      transport: 'streamable-http',
      enabled: false,
      args: [],
      url: 'https://mcp.example.test/mcp',
      authType: 'bearer',
      credentialId: 'credential-1',
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
      updatedAt: now,
      token: 'must-not-cross-ipc'
    })

    expect(parsed).not.toHaveProperty('token')
  })

  it('keeps imported PoC request templates inert at the IPC boundary', () => {
    const candidate = {
      schemaVersion: 'vulnerability-intel.v1',
      title: 'Imported advisory',
      vendor: 'Vendor',
      product: 'Product',
      vulnerabilityType: 'Command Injection',
      identifiers: { cve: [], cwe: [], other: [] },
      affectedVersions: [],
      preconditions: [],
      affectedEndpoints: [
        {
          method: 'POST',
          pathTemplate: '/api/test',
          queryParameters: [],
          headersTemplate: {},
          controllableFields: [],
          riskFlags: ['imported-poc'],
          unsafeToExecute: false
        }
      ],
      signals: [],
      confirmationRules: [],
      remediation: [],
      forbiddenActions: [],
      fieldEvidence: [],
      extractionConfidence: 0.5
    }

    expect(KnowledgeIntelligenceCandidateSchema.safeParse(candidate).success).toBe(false)
    expect(
      KnowledgeIntelligenceCandidateSchema.safeParse({
        ...candidate,
        affectedEndpoints: [
          { ...candidate.affectedEndpoints[0], unsafeToExecute: true }
        ]
      }).success
    ).toBe(true)
  })
})
