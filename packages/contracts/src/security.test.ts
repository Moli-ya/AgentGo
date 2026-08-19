import { describe, expect, it } from 'vitest'
import {
  DynamicValueResolverRefSchema,
  FormRequestBodyTemplateSchema,
  JsonRequestBodyTemplateSchema,
  RequestBodyTemplateSchema,
  RequestMutationTargetSchema,
  ResolvedIntentHashSchema,
  SecretRefResolverRefSchema,
  TemplateIntentHashSchema,
  WireRequestHmacSchema
} from './security'
import { MutationGeneratorMetadataSchema } from './vulnerability'

const digest = 'a'.repeat(64)
const keyRef = '7f3b82e1-bc3d-45a8-9a71-c4aa47c12f80'
const secretRef = 'b7b76e72-16dc-499a-b16a-4a43e14a0d36'

describe('Day 4 phased request proof contracts', () => {
  it('domain-separates strict immutable template, resolved, and wire proofs', () => {
    const template = TemplateIntentHashSchema.parse({
      domain: 'agentgo.template-intent.v1',
      algorithm: 'sha256',
      digest
    })
    const resolved = ResolvedIntentHashSchema.parse({
      domain: 'agentgo.resolved-intent.v1',
      algorithm: 'sha256',
      commitmentKeyRef: keyRef,
      commitmentKeyVersion: 3,
      digest
    })
    const wire = WireRequestHmacSchema.parse({
      domain: 'agentgo.wire-request.v2',
      algorithm: 'hmac-sha256',
      keyRef,
      keyVersion: 3,
      digest
    })

    expect(Object.isFrozen(template)).toBe(true)
    expect(Object.isFrozen(resolved)).toBe(true)
    expect(Object.isFrozen(wire)).toBe(true)
    expect(ResolvedIntentHashSchema.safeParse(template).success).toBe(false)
    expect(TemplateIntentHashSchema.safeParse(resolved).success).toBe(false)
    expect(WireRequestHmacSchema.safeParse(template).success).toBe(false)
  })

  it('rejects malformed digests, key references, algorithms, and unknown fields', () => {
    expect(
      TemplateIntentHashSchema.safeParse({
        domain: 'agentgo.template-intent.v1',
        algorithm: 'sha256',
        digest: digest.toUpperCase()
      }).success
    ).toBe(false)
    expect(
      ResolvedIntentHashSchema.safeParse({
        domain: 'agentgo.resolved-intent.v1',
        algorithm: 'sha256',
        digest
      }).success
    ).toBe(false)
    expect(
      WireRequestHmacSchema.safeParse({
        domain: 'agentgo.wire-request.v2',
        algorithm: 'sha256',
        keyRef,
        keyVersion: 1,
        digest
      }).success
    ).toBe(false)
    expect(
      WireRequestHmacSchema.safeParse({
        domain: 'agentgo.wire-request.v2',
        algorithm: 'hmac-sha256',
        keyRef: 'vault-key-name',
        keyVersion: 1,
        digest
      }).success
    ).toBe(false)
    expect(
      TemplateIntentHashSchema.safeParse({
        domain: 'agentgo.template-intent.v1',
        algorithm: 'sha256',
        digest,
        rawIntent: 'must-not-cross-contract-boundary'
      }).success
    ).toBe(false)
  })
})

describe('Day 4 executable mutation targets', () => {
  it('requires an exact repeated occurrence or all plus missing behavior', () => {
    for (const kind of ['query', 'form', 'cookie'] as const) {
      expect(
        RequestMutationTargetSchema.parse({
          kind,
          name: 'item',
          occurrence: 0,
          onMissing: 'reject'
        })
      ).toMatchObject({ occurrence: 0 })
      expect(
        RequestMutationTargetSchema.safeParse({
          kind,
          name: 'item',
          occurrence: 'all',
          onMissing: 'append'
        }).success
      ).toBe(true)
      expect(
        RequestMutationTargetSchema.safeParse({
          kind,
          name: 'item',
          onMissing: 'reject'
        }).success
      ).toBe(false)
      expect(
        RequestMutationTargetSchema.safeParse({
          kind,
          name: 'item',
          occurrence: -1,
          onMissing: 'reject'
        }).success
      ).toBe(false)
    }
  })

  it('uses an exact zero-based path segment, canonical header, or RFC 6901 pointer', () => {
    expect(
      RequestMutationTargetSchema.safeParse({
        kind: 'path',
        selectorName: 'resourceId',
        segmentIndex: 0
      }).success
    ).toBe(true)
    expect(
      RequestMutationTargetSchema.safeParse({ kind: 'path', segmentIndex: 0 })
        .success
    ).toBe(false)
    expect(
      RequestMutationTargetSchema.safeParse({ kind: 'header', name: 'x-test-id' })
        .success
    ).toBe(true)
    expect(
      RequestMutationTargetSchema.safeParse({ kind: 'header', name: 'X-Test-Id' })
        .success
    ).toBe(false)
    expect(
      RequestMutationTargetSchema.safeParse({
        kind: 'json-pointer',
        pointer: '/items/0/a~1b/~0marker'
      }).success
    ).toBe(true)
    expect(
      RequestMutationTargetSchema.safeParse({
        kind: 'json-pointer',
        pointer: '/invalid~2escape'
      }).success
    ).toBe(false)
    expect(
      RequestMutationTargetSchema.safeParse({
        kind: 'cookie',
        name: 'sid; admin',
        occurrence: 0,
        onMissing: 'reject'
      }).success
    ).toBe(false)
    expect(
      RequestMutationTargetSchema.safeParse({
        kind: 'query',
        name: `item\ud800`,
        occurrence: 0,
        onMissing: 'reject'
      }).success
    ).toBe(false)
    expect(
      RequestMutationTargetSchema.safeParse({
        kind: 'json-pointer',
        pointer: `/item\udc00`
      }).success
    ).toBe(false)
    expect(
      RequestMutationTargetSchema.safeParse({
        kind: 'json-pointer',
        pointer: '/id',
        occurrence: 0
      }).success
    ).toBe(false)
  })
})

describe('Day 4 resolver and body-template contracts', () => {
  const dynamicResolver = {
    kind: 'dynamic-value-resolver' as const,
    resolverId: 'request.csrf-resolver',
    version: '1.0.0'
  }
  const secretResolver = {
    kind: 'secret-ref-resolver' as const,
    resolverId: 'session.secret-resolver',
    version: '2.1.0'
  }

  it('uses strict versioned resolver references', () => {
    expect(DynamicValueResolverRefSchema.parse(dynamicResolver)).toEqual(
      dynamicResolver
    )
    expect(SecretRefResolverRefSchema.parse(secretResolver)).toEqual(
      secretResolver
    )
    expect(DynamicValueResolverRefSchema.safeParse(secretResolver).success).toBe(
      false
    )
    expect(
      DynamicValueResolverRefSchema.safeParse({
        ...dynamicResolver,
        resolve: 'untrusted callback'
      }).success
    ).toBe(false)
  })

  it('preserves repeated ordered form entries with explicit value sources', () => {
    const parsed = FormRequestBodyTemplateSchema.parse({
      encoding: 'form',
      entries: [
        {
          name: 'role',
          value: { kind: 'literal', sensitivity: 'public', value: 'reader' }
        },
        {
          name: 'role',
          value: {
            kind: 'dynamic',
            slotId: 'alternate-role',
            resolver: dynamicResolver
          }
        },
        {
          name: 'csrf',
          value: {
            kind: 'secret-ref',
            secretRef,
            generation: 4,
            resolver: secretResolver
          }
        }
      ]
    })

    expect(parsed.entries.map((entry) => entry.name)).toEqual([
      'role',
      'role',
      'csrf'
    ])
    expect(Object.isFrozen(parsed)).toBe(true)
    expect(Object.isFrozen(parsed.entries)).toBe(true)
    expect(Object.isFrozen(parsed.entries[0]?.value)).toBe(true)
    expect(
      FormRequestBodyTemplateSchema.safeParse({
        ...parsed,
        entries: [
          {
            name: 'csrf',
            value: {
              kind: 'secret-ref',
              secretRef,
              generation: 4,
              resolver: secretResolver,
              rawSecret: 'DAY4_SENTINEL_SECRET'
            }
          }
        ]
      }).success
    ).toBe(false)
  })

  it('represents JSON as a strict recursive value tree with leaf slots', () => {
    const parsed = JsonRequestBodyTemplateSchema.parse({
      encoding: 'json',
      value: {
        kind: 'object',
        entries: [
          {
            key: 'displayName',
            value: {
              kind: 'literal',
              sensitivity: 'public',
              value: '测试用户'
            }
          },
          {
            key: 'items',
            value: {
              kind: 'array',
              items: [
                {
                  kind: 'dynamic',
                  slotId: 'test-object-id',
                  resolver: dynamicResolver
                }
              ]
            }
          }
        ]
      }
    })

    expect(Object.isFrozen(parsed.value)).toBe(true)
    expect(
      JsonRequestBodyTemplateSchema.safeParse({
        encoding: 'json',
        value: {
          kind: 'object',
          entries: [
            {
              key: 'duplicate',
              value: { kind: 'literal', sensitivity: 'public', value: 1 }
            },
            {
              key: 'duplicate',
              value: { kind: 'literal', sensitivity: 'public', value: 2 }
            }
          ]
        }
      }).success
    ).toBe(false)
    expect(
      RequestBodyTemplateSchema.safeParse({
        encoding: 'none',
        body: 'unknown field'
      }).success
    ).toBe(false)
  })

  it('fails closed on raw sensitive literals and hostile JSON depth without leaking keys', () => {
    expect(
      JsonRequestBodyTemplateSchema.safeParse({
        encoding: 'json',
        value: {
          kind: 'literal',
          sensitivity: 'sensitive',
          value: 'DAY4_SENTINEL_SECRET'
        }
      }).success
    ).toBe(false)

    let value: unknown = {
      kind: 'literal',
      sensitivity: 'public',
      value: 'leaf'
    }
    for (let index = 0; index < 65; index += 1) {
      value = { kind: 'array', items: [value] }
    }
    const depthResult = JsonRequestBodyTemplateSchema.safeParse({
      encoding: 'json',
      value
    })
    expect(depthResult.success).toBe(false)

    const duplicateResult = JsonRequestBodyTemplateSchema.safeParse({
      encoding: 'json',
      value: {
        kind: 'object',
        entries: [
          {
            key: 'DAY4_SENTINEL_SECRET',
            value: { kind: 'literal', sensitivity: 'public', value: 1 }
          },
          {
            key: 'DAY4_SENTINEL_SECRET',
            value: { kind: 'literal', sensitivity: 'public', value: 2 }
          }
        ]
      }
    })
    expect(duplicateResult.success).toBe(false)
    expect(JSON.stringify(duplicateResult)).not.toContain('DAY4_SENTINEL_SECRET')

    expect(
      FormRequestBodyTemplateSchema.safeParse({
        encoding: 'form',
        entries: [
          {
            name: 'value',
            value: { kind: 'literal', sensitivity: 'public', value: `x\ud800` }
          }
        ]
      }).success
    ).toBe(false)

    const canonicalObject = JsonRequestBodyTemplateSchema.parse({
      encoding: 'json',
      value: {
        kind: 'object',
        entries: [
          {
            key: 'z',
            value: { kind: 'literal', sensitivity: 'public', value: 1 }
          },
          {
            key: 'a',
            value: { kind: 'literal', sensitivity: 'public', value: 2 }
          }
        ]
      }
    })
    expect(
      canonicalObject.value.kind === 'object'
        ? canonicalObject.value.entries.map((entry) => entry.key)
        : []
    ).toEqual(['a', 'z'])
  })
})

describe('Day 4 mutation generator metadata', () => {
  const metadata = {
    generatorId: 'sqli.boolean-marker',
    version: '1.0.0',
    deterministic: true as const,
    unicodeNormalization: 'NFC' as const,
    safety: {
      sideEffect: 'none' as const,
      dataAccess: 'input-only' as const,
      networkTarget: 'request-target' as const,
      mayExecuteInTargetContext: false
    },
    requiredCapabilityIds: ['http.reviewed-read'],
    forbiddenCapabilityIds: ['process.execute', 'filesystem.write'],
    maxOutputBytes: 4_096,
    supportedSelectorKinds: ['query', 'form', 'json-pointer'] as const,
    supportedBodyEncodings: ['none', 'form', 'json'] as const
  }

  it('freezes registry metadata and every structured collection', () => {
    const parsed = MutationGeneratorMetadataSchema.parse(metadata)
    const reordered = MutationGeneratorMetadataSchema.parse({
      ...metadata,
      forbiddenCapabilityIds: [...metadata.forbiddenCapabilityIds].reverse(),
      supportedSelectorKinds: [...metadata.supportedSelectorKinds].reverse(),
      supportedBodyEncodings: [...metadata.supportedBodyEncodings].reverse()
    })

    expect(Object.isFrozen(parsed)).toBe(true)
    expect(Object.isFrozen(parsed.safety)).toBe(true)
    expect(Object.isFrozen(parsed.requiredCapabilityIds)).toBe(true)
    expect(Object.isFrozen(parsed.forbiddenCapabilityIds)).toBe(true)
    expect(Object.isFrozen(parsed.supportedSelectorKinds)).toBe(true)
    expect(Object.isFrozen(parsed.supportedBodyEncodings)).toBe(true)
    expect(reordered).toEqual(parsed)
  })

  it('rejects nondeterminism, unbounded/duplicate semantics, overlap, and unknown fields', () => {
    expect(
      MutationGeneratorMetadataSchema.safeParse({
        ...metadata,
        deterministic: false
      }).success
    ).toBe(false)
    expect(
      MutationGeneratorMetadataSchema.safeParse({
        ...metadata,
        maxOutputBytes: 1_048_577
      }).success
    ).toBe(false)
    expect(
      MutationGeneratorMetadataSchema.safeParse({
        ...metadata,
        supportedSelectorKinds: ['query', 'query']
      }).success
    ).toBe(false)
    expect(
      MutationGeneratorMetadataSchema.safeParse({
        ...metadata,
        forbiddenCapabilityIds: ['http.reviewed-read']
      }).success
    ).toBe(false)
    expect(
      MutationGeneratorMetadataSchema.safeParse({
        ...metadata,
        payloadSummary: 'free text cannot establish safety'
      }).success
    ).toBe(false)
    const overlapResult = MutationGeneratorMetadataSchema.safeParse({
      ...metadata,
      requiredCapabilityIds: ['day4-sentinel-secret'],
      forbiddenCapabilityIds: ['day4-sentinel-secret']
    })
    expect(overlapResult.success).toBe(false)
    expect(JSON.stringify(overlapResult)).not.toContain('day4-sentinel-secret')
  })
})
