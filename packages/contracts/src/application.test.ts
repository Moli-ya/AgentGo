import { describe, expect, it } from 'vitest'
import {
  CreateTargetInputSchema,
  TargetBaseUrlSchema,
  UpdateTargetInputSchema
} from './application'

const baseTarget = {
  workspaceId: 'workspace-1',
  name: 'Authorized target',
  baseUrl: 'https://example.test/app/',
  description: '',
  authorizationReference: 'approval-ticket-1',
  scope: {
    allowedOrigins: ['https://example.test'],
    allowedPathPrefixes: ['/app'],
    deniedPathPrefixes: [],
    allowedPorts: [443],
    allowedIdentityIds: [],
    allowActiveProbing: true,
    allowSensitiveProbing: false,
    allowPrivateNetworkTargets: false,
    allowLoopbackTargets: false,
    maxRequestsPerMinute: 10,
    maxConcurrency: 1
  }
}

describe('target Base URL contract', () => {
  it('accepts a credential-free HTTP(S) seed for create and update', () => {
    expect(CreateTargetInputSchema.safeParse(baseTarget).success).toBe(true)
    expect(
      TargetBaseUrlSchema.safeParse(
        'https://example.test/search?id=1&q=hello&url=agentgo-invalid-url'
      ).success
    ).toBe(true)
    expect(
      UpdateTargetInputSchema.safeParse({
        id: 'target-1',
        baseUrl: 'http://127.0.0.1:3000/base'
      }).success
    ).toBe(true)
  })

  it.each([
    'ftp://example.test/',
    'https://alice:password@example.test/',
    'https://example.test/?token=secret',
    'https://example.test/#private',
    'https://example.test/reset/N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa',
    'https://eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature88.example.test/'
  ])('rejects credential-bearing or non-structural target URL %s', (value) => {
    expect(TargetBaseUrlSchema.safeParse(value).success).toBe(false)
    expect(
      CreateTargetInputSchema.safeParse({ ...baseTarget, baseUrl: value }).success
    ).toBe(false)
  })
})
