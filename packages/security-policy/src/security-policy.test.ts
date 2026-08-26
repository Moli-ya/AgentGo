import { describe, expect, it } from 'vitest'
import type { ProbeAction, TargetScope } from '@agentgo/contracts'
import {
  canonicalizeTargetUrl,
  classifyNetworkAddress,
  deriveScopeNetworkEntriesFromOrigins,
  evaluateExecutionAddresses,
  evaluateProbe,
  evaluateResolvedAddresses,
  evaluateSsrfTargetAddresses
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
  networkEntries: [],
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
      code: 'url-canonicalization-failed'
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
    expect(classifyNetworkAddress('0:0:0:0:0:0:0:1')).toBe('loopback')
    expect(classifyNetworkAddress('::ffff:127.0.0.1')).toBe('loopback')
    expect(classifyNetworkAddress('::ffff:7f00:1')).toBe('loopback')
    expect(classifyNetworkAddress('0:0:0:0:0:ffff:7f00:1')).toBe('loopback')
    expect(classifyNetworkAddress('::ffff:a9fe:a9fe')).toBe('metadata')
  })

  it('does not let allowLoopbackTargets open every loopback address', () => {
    expect(
      evaluateResolvedAddresses(['127.0.0.1'], {
        ...scope,
        allowLoopbackTargets: true,
        allowPrivateNetworkTargets: false
      })
    ).toMatchObject({
      allowed: false,
      code: 'network-target-not-authorized'
    })
  })

  it('allows loopback only when a precise execution network entry matches host, ip and port', () => {
    const loopbackScope: TargetScope = {
      ...scope,
      allowedOrigins: ['http://127.0.0.1:8080'],
      allowedPorts: [8080],
      networkEntries: [
        {
          id: 'loopback-entry',
          addressClass: 'loopback',
          ip: '127.0.0.1',
          ports: [8080],
          purpose: 'execution'
        }
      ]
    }
    expect(
      evaluateExecutionAddresses(
        { hostname: '127.0.0.1', port: 8080, addresses: ['127.0.0.1'] },
        loopbackScope
      )
    ).toMatchObject({ allowed: true, code: 'allowed' })
    expect(
      evaluateExecutionAddresses(
        { hostname: '127.0.0.1', port: 80, addresses: ['127.0.0.1'] },
        loopbackScope
      )
    ).toMatchObject({
      allowed: false,
      code: 'network-target-not-authorized'
    })
    expect(
      evaluateSsrfTargetAddresses(
        { hostname: '127.0.0.1', port: 8080, addresses: ['127.0.0.1'] },
        loopbackScope
      )
    ).toMatchObject({
      allowed: false,
      code: 'network-target-not-authorized'
    })
  })

  it('requires every specified host and IP locator on a network entry to match', () => {
    const dualPinScope: TargetScope = {
      ...scope,
      networkEntries: [
        {
          id: 'dual-pin',
          addressClass: 'private',
          host: 'lab.internal',
          ip: '10.0.0.1',
          ports: [443],
          purpose: 'execution'
        }
      ]
    }
    expect(
      evaluateExecutionAddresses(
        { hostname: 'lab.internal', port: 443, addresses: ['10.0.0.1'] },
        dualPinScope
      )
    ).toMatchObject({ allowed: true, code: 'allowed' })
    expect(
      evaluateExecutionAddresses(
        { hostname: 'lab.internal', port: 443, addresses: ['10.0.0.99'] },
        dualPinScope
      )
    ).toMatchObject({
      allowed: false,
      code: 'network-target-not-authorized'
    })
  })

  it('authorizes IPv6 unique-local CIDR entries and rejects adjacent prefixes', () => {
    const ipv6Scope: TargetScope = {
      ...scope,
      networkEntries: [
        {
          id: 'ula-cidr',
          addressClass: 'private',
          cidr: 'fd12:3456:789a:1::/64',
          ports: [443],
          purpose: 'execution'
        }
      ]
    }
    expect(
      evaluateExecutionAddresses(
        {
          hostname: 'fd12:3456:789a:1::10',
          port: 443,
          addresses: ['fd12:3456:789a:1::10']
        },
        ipv6Scope
      )
    ).toMatchObject({ allowed: true, code: 'allowed' })
    expect(
      evaluateExecutionAddresses(
        {
          hostname: 'fd12:3456:789a:2::10',
          port: 443,
          addresses: ['fd12:3456:789a:2::10']
        },
        ipv6Scope
      )
    ).toMatchObject({
      allowed: false,
      code: 'network-target-not-authorized'
    })
  })

  it('does not let allowPrivateNetworkTargets open reserved, link-local or loopback classes', () => {
    const privateOnlyScope: TargetScope = {
      ...scope,
      allowPrivateNetworkTargets: true,
      allowLoopbackTargets: false,
      networkEntries: [
        {
          id: 'private-entry',
          addressClass: 'private',
          ip: '10.1.2.3',
          ports: [443],
          purpose: 'execution'
        }
      ]
    }
    expect(
      evaluateExecutionAddresses(
        { hostname: '10.1.2.3', port: 443, addresses: ['10.1.2.3'] },
        privateOnlyScope
      )
    ).toMatchObject({ allowed: true, code: 'allowed' })
    expect(
      evaluateExecutionAddresses(
        { hostname: '169.254.1.1', port: 443, addresses: ['169.254.1.1'] },
        privateOnlyScope
      )
    ).toMatchObject({
      allowed: false,
      code: 'network-target-not-authorized'
    })
    expect(
      evaluateExecutionAddresses(
        { hostname: '127.0.0.1', port: 443, addresses: ['127.0.0.1'] },
        privateOnlyScope
      )
    ).toMatchObject({
      allowed: false,
      code: 'network-target-not-authorized'
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
      evaluateExecutionAddresses(
        {
          hostname: 'lab.example.test',
          port: 443,
          addresses: [address]
        },
        {
          ...scope,
          allowLoopbackTargets: true,
          allowPrivateNetworkTargets: true,
          networkEntries: [
            {
              id: 'loopback-entry',
              addressClass: 'loopback',
              host: 'lab.example.test',
              ports: [443],
              purpose: 'execution'
            },
            {
              id: 'private-entry',
              addressClass: 'private',
              host: 'lab.example.test',
              ports: [443],
              purpose: 'execution'
            }
          ]
        }
      )
    ).toMatchObject({ allowed: false, code: 'network-address-blocked' })
  })
})

describe('URL canonicalization', () => {
  it.each([
    ['https://user:pass@lab.example.test/search', 'userinfo'],
    ['https://lab.example.test\\search', 'backslash'],
    ['http://127.1/search', 'short IPv4'],
    ['http://0x7f000001/search', 'hex IPv4'],
    ['http://2130706433/search', 'integer IPv4'],
    ['http://[::1%eth0]/search', 'IPv6 zone'],
    ['https://lab.example.test/%252e%252e/secret', 'double-encoded path'],
    ['javascript:alert(1)', 'scheme confusion']
  ])('fails closed for %s', (url) => {
    expect(canonicalizeTargetUrl(url).ok).toBe(false)
  })

  it('rejects a schema-valid userinfo URL with the canonicalization code', () => {
    expect(
      evaluateProbe(
        action({ targetUrl: 'https://user:pass@lab.example.test/search' }),
        scope
      )
    ).toMatchObject({
      allowed: false,
      code: 'url-canonicalization-failed'
    })
  })

  it('normalizes default HTTPS ports and accepts the in-scope form', () => {
    const canonical = canonicalizeTargetUrl(
      'https://lab.example.test:443/search?q=marker'
    )
    expect(canonical.ok).toBe(true)
    if (canonical.ok) {
      expect(canonical.value.href).toBe(
        'https://lab.example.test/search?q=marker'
      )
    }
    expect(
      evaluateProbe(
        action({ targetUrl: 'https://lab.example.test:443/search?q=marker' }),
        scope
      )
    ).toMatchObject({ allowed: true, code: 'allowed' })
  })

  it('allows @ in path and query while still rejecting userinfo', () => {
    expect(
      canonicalizeTargetUrl('https://lab.example.test/user@home?q=a@b').ok
    ).toBe(true)
    expect(canonicalizeTargetUrl('https://user@lab.example.test/').ok).toBe(false)
    expect(
      canonicalizeTargetUrl('https://user:pass@lab.example.test/').ok
    ).toBe(false)
  })

  it('keeps leading-zero DNS names while rejecting non-standard IPv4', () => {
    expect(canonicalizeTargetUrl('http://07.example.test/').ok).toBe(true)
    expect(canonicalizeTargetUrl('http://0177.0.0.1/').ok).toBe(false)
    expect(canonicalizeTargetUrl('http://0x7f.0.0.1/').ok).toBe(false)
    expect(canonicalizeTargetUrl('http://1.2.3.010/').ok).toBe(false)
    expect(canonicalizeTargetUrl('http://2130706433:8080/').ok).toBe(false)
  })

  it('accepts unicode IDN and pure punycode but rejects mixed input', () => {
    expect(canonicalizeTargetUrl('https://münchen.de/').ok).toBe(true)
    expect(canonicalizeTargetUrl('https://xn--mnchen-3ya.de/').ok).toBe(true)
    expect(canonicalizeTargetUrl('https://xn--mnchen-3ya.münchen/').ok).toBe(false)
  })
})

describe('derived network entries', () => {
  it('derives loopback execution entries from literal origins and not from public hosts', () => {
    const entries = deriveScopeNetworkEntriesFromOrigins([
      'http://127.0.0.1:4173',
      'https://lab.example.test'
    ])
    expect(entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          addressClass: 'loopback',
          ip: '127.0.0.1',
          ports: [4173],
          purpose: 'execution'
        }),
        expect.objectContaining({
          addressClass: 'loopback',
          ip: '127.0.0.1',
          ports: [4173],
          purpose: 'ssrf-target'
        })
      ])
    )
    expect(entries).toHaveLength(2)
  })
})
