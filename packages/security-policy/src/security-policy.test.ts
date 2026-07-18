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
  it.each(['GET', 'HEAD', 'OPTIONS'])(
    'allows the reviewed active-safe method %s',
    (method) => {
      expect(evaluateProbe(action({ method }), scope)).toMatchObject({
        allowed: true,
        code: 'allowed'
      })
    }
  )

  it('rejects URL userinfo without echoing credentials into the decision', () => {
    const decision = evaluateProbe(
      action({ targetUrl: 'https://operator:secret@lab.example.test/search' }),
      scope
    )

    expect(decision).toMatchObject({
      allowed: false,
      code: 'invalid-target'
    })
    expect(decision.normalizedTarget).toBeUndefined()
    expect(JSON.stringify(decision)).not.toContain('operator:secret')
  })

  it('allows an in-scope low-impact active probe without an identity', () => {
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

  it.each(['POST', 'PUT', 'PATCH'])(
    'does not allow %s to masquerade as an L1 read-only probe',
    (method) => {
      expect(
        evaluateProbe(
          action({
            method,
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
    }
  )

  it.each(['MKCOL', 'PROPFIND', 'MOVE', 'LOCK', 'PURGE', 'CUSTOM'])(
    'fails closed for the unreviewed HTTP method %s',
    (method) => {
      expect(evaluateProbe(action({ method }), scope)).toMatchObject({
        allowed: false,
        requiresApproval: false,
        code: 'http-method-blocked'
      })
    }
  )

  it('does not let an L2 claim grant unknown HTTP method semantics', () => {
    expect(
      evaluateProbe(
        action({
          method: 'MKCOL',
          probeLevel: 'active-sensitive',
          sideEffect: 'reversible',
          cleanupPlan: 'Remove the dedicated test collection.',
          userApproved: true
        }),
        scope
      )
    ).toMatchObject({
      allowed: false,
      code: 'http-method-blocked'
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

  it('treats an empty identity allowlist as allowing no supplied identity', () => {
    expect(
      evaluateProbe(action({ identityId: 'identity-a' }), scope)
    ).toMatchObject({ allowed: false, code: 'identity-out-of-scope' })

    expect(
      evaluateProbe(action({ identityId: 'identity-a' }), {
        ...scope,
        allowedIdentityIds: ['identity-a']
      })
    ).toMatchObject({ allowed: true, code: 'allowed' })
  })
})

describe('resolved network boundary', () => {
  it('classifies loopback, private, metadata and public addresses', () => {
    expect(classifyNetworkAddress('127.0.0.1')).toBe('loopback')
    expect(classifyNetworkAddress('10.1.2.3')).toBe('private')
    expect(classifyNetworkAddress('169.254.169.254')).toBe('metadata')
    expect(classifyNetworkAddress('8.8.8.8')).toBe('public')
    expect(classifyNetworkAddress('::1')).toBe('loopback')
    expect(classifyNetworkAddress('::ffff:127.0.0.1')).toBe('loopback')
    expect(classifyNetworkAddress('::ffff:7f00:1')).toBe('loopback')
    expect(classifyNetworkAddress('0:0:0:0:0:ffff:7f00:1')).toBe('loopback')
    expect(classifyNetworkAddress('::ffff:a9fe:a9fe')).toBe('metadata')
  })

  it('gates loopback independently from private and link-local addresses', () => {
    expect(evaluateResolvedAddresses(['127.0.0.1'], scope)).toMatchObject({
      allowed: false,
      code: 'network-address-blocked'
    })
    expect(
      evaluateResolvedAddresses(['127.0.0.1'], {
        ...scope,
        allowLoopbackTargets: true,
        allowPrivateNetworkTargets: false
      })
    ).toMatchObject({ allowed: true, code: 'allowed' })
    expect(
      evaluateResolvedAddresses(['::ffff:7f00:1'], {
        ...scope,
        allowLoopbackTargets: true,
        allowPrivateNetworkTargets: false
      })
    ).toMatchObject({ allowed: true, code: 'allowed' })

    const privateOnlyScope: TargetScope = {
      ...scope,
      allowPrivateNetworkTargets: true,
      allowLoopbackTargets: false
    }
    expect(evaluateResolvedAddresses(['10.1.2.3'], privateOnlyScope)).toMatchObject({
      allowed: true,
      code: 'allowed'
    })
    expect(evaluateResolvedAddresses(['169.254.1.1'], privateOnlyScope)).toMatchObject({
      allowed: true,
      code: 'allowed'
    })
    expect(evaluateResolvedAddresses(['127.0.0.1'], privateOnlyScope)).toMatchObject({
      allowed: false,
      code: 'network-address-blocked'
    })
    expect(evaluateResolvedAddresses(['::ffff:7f00:1'], privateOnlyScope)).toMatchObject({
      allowed: false,
      code: 'network-address-blocked'
    })
  })

  it.each([
    'not-an-ip',
    '0.0.0.0',
    '::',
    '224.0.0.1',
    'ff02::1',
    '169.254.169.254',
    '::ffff:a9fe:a9fe'
  ])('never allows the blocked network address %s', (address) => {
    expect(
      evaluateResolvedAddresses([address], {
        ...scope,
        allowLoopbackTargets: true,
        allowPrivateNetworkTargets: true
      })
    ).toMatchObject({ allowed: false, code: 'network-address-blocked' })
  })
})
