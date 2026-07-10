import { describe, expect, it } from 'vitest'
import type { ProbeAction, TargetScope } from '@agentgo/contracts'
import {
  classifyNetworkAddress,
  evaluateProbe,
  evaluateResolvedAddresses
} from './index'

const scope: TargetScope = {
  id: 'scope-demo',
  allowedOrigins: ['https://lab.example.test'],
  allowedPathPrefixes: ['/'],
  deniedPathPrefixes: [],
  allowedPorts: [443],
  allowedIdentityIds: [],
  allowActiveProbing: true,
  allowSensitiveProbing: true,
  allowPrivateNetworkTargets: false,
  allowLoopbackTargets: false,
  maxRequestsPerMinute: 30,
  maxConcurrency: 2
}

function action(overrides: Partial<ProbeAction> = {}): ProbeAction {
  return {
    id: 'probe-1',
    kind: 'http-request',
    targetUrl: 'https://lab.example.test/search?q=marker',
    method: 'GET',
    probeLevel: 'active-safe',
    sideEffect: 'none',
    summary: '发送惰性标记并比较响应差异',
    expectedEvidence: '基线与测试响应差异',
    maxRequests: 1,
    timeoutMs: 10_000,
    userApproved: false,
    ...overrides
  }
}

describe('evaluateProbe', () => {
  it('allows an in-scope low-impact active probe', () => {
    expect(evaluateProbe(action(), scope)).toMatchObject({
      allowed: true,
      code: 'allowed'
    })
  })

  it('blocks out-of-scope targets', () => {
    expect(
      evaluateProbe(action({ targetUrl: 'https://outside.example.test/' }), scope)
    ).toMatchObject({
      allowed: false,
      code: 'out-of-scope'
    })
  })

  it('fails closed when untrusted action data is malformed', () => {
    expect(
      evaluateProbe({ targetUrl: 'not-a-url' }, scope)
    ).toMatchObject({
      allowed: false,
      code: 'invalid-target'
    })
  })

  it('blocks destructive database statements even when disguised as a probe', () => {
    expect(
      evaluateProbe(
        action({
          method: 'POST',
          probeLevel: 'active-sensitive',
          sideEffect: 'destructive',
          payloadSummary: 'DROP TABLE users',
          cleanupPlan: 'not possible',
          userApproved: true
        }),
        scope
      )
    ).toMatchObject({
      allowed: false,
      code: 'destructive-action'
    })
  })

  it('requires per-action approval for reversible L2 probes', () => {
    expect(
      evaluateProbe(
        action({
          method: 'POST',
          probeLevel: 'active-sensitive',
          sideEffect: 'reversible',
          cleanupPlan: '删除临时测试对象'
        }),
        scope
      )
    ).toMatchObject({
      allowed: false,
      requiresApproval: true,
      code: 'approval-required'
    })
  })

  it('does not allow POST to masquerade as an L1 read-only probe', () => {
    expect(
      evaluateProbe(
        action({
          method: 'POST',
          probeLevel: 'active-safe',
          sideEffect: 'none'
        }),
        scope
      )
    ).toMatchObject({
      allowed: false,
      requiresApproval: true,
      code: 'mutating-method-requires-l2'
    })
  })

  it('allows an explicitly approved reversible L2 probe with cleanup', () => {
    expect(
      evaluateProbe(
        action({
          method: 'POST',
          probeLevel: 'active-sensitive',
          sideEffect: 'reversible',
          cleanupPlan: '删除专用测试账号创建的临时对象',
          userApproved: true
        }),
        scope
      )
    ).toMatchObject({
      allowed: true,
      code: 'allowed'
    })
  })

  it('does not allow path-prefix confusion', () => {
    const apiScope: TargetScope = {
      ...scope,
      allowedPathPrefixes: ['/api']
    }

    expect(
      evaluateProbe(
        action({ targetUrl: 'https://lab.example.test/api-private' }),
        apiScope
      )
    ).toMatchObject({
      allowed: false,
      code: 'out-of-scope'
    })
  })

  it('blocks unknown side effects and unsafe HTTP methods', () => {
    expect(
      evaluateProbe(action({ sideEffect: 'unknown' }), scope)
    ).toMatchObject({
      allowed: false,
      code: 'unknown-side-effect'
    })

    expect(
      evaluateProbe(action({ method: 'TRACE' }), scope)
    ).toMatchObject({
      allowed: false,
      code: 'http-method-blocked'
    })
  })

  it('blocks requests above the configured rate budget', () => {
    expect(
      evaluateProbe(action({ requestedRequestsPerMinute: 31 }), scope)
    ).toMatchObject({
      allowed: false,
      code: 'rate-limit-exceeded'
    })
  })

  it('enforces denied paths, ports and identity scope', () => {
    const restricted: TargetScope = {
      ...scope,
      deniedPathPrefixes: ['/admin'],
      allowedIdentityIds: ['identity-a']
    }

    expect(
      evaluateProbe(
        action({ targetUrl: 'https://lab.example.test/admin/users' }),
        restricted
      )
    ).toMatchObject({ allowed: false, code: 'out-of-scope' })
    expect(
      evaluateProbe(
        action({ targetUrl: 'https://lab.example.test:8443/search' }),
        restricted
      )
    ).toMatchObject({ allowed: false, code: 'out-of-scope' })
    expect(
      evaluateProbe(action({ identityId: 'identity-b' }), restricted)
    ).toMatchObject({ allowed: false, code: 'identity-out-of-scope' })
  })
})

describe('resolved network boundary', () => {
  it('classifies loopback, private, metadata and public addresses', () => {
    expect(classifyNetworkAddress('127.0.0.1')).toBe('loopback')
    expect(classifyNetworkAddress('10.1.2.3')).toBe('private')
    expect(classifyNetworkAddress('169.254.169.254')).toBe('metadata')
    expect(classifyNetworkAddress('8.8.8.8')).toBe('public')
    expect(classifyNetworkAddress('::1')).toBe('loopback')
  })

  it('blocks local addresses unless explicitly authorized and never allows metadata', () => {
    expect(evaluateResolvedAddresses(['127.0.0.1'], scope)).toMatchObject({
      allowed: false,
      code: 'network-address-blocked'
    })
    expect(
      evaluateResolvedAddresses(['127.0.0.1'], {
        ...scope,
        allowLoopbackTargets: true,
        allowPrivateNetworkTargets: true
      })
    ).toMatchObject({ allowed: true, code: 'allowed' })
    expect(
      evaluateResolvedAddresses(['169.254.169.254'], {
        ...scope,
        allowLoopbackTargets: true,
        allowPrivateNetworkTargets: true
      })
    ).toMatchObject({ allowed: false, code: 'network-address-blocked' })
  })
})
