import { describe, expect, it, vi } from 'vitest'
import {
  InventoryEndpointRecordSchema,
  MutationGeneratorMetadataSchema,
  RequestVariantRecordSchema,
  type BodyEncoding,
  type InventoryEndpointRecord,
  type RequestVariantRecord,
  type SelectorRef
} from '@agentgo/contracts'
import {
  canonicalizeAllowedHeaderDescriptors,
  canonicalizeInventoryBodyShape,
  canonicalizeInventoryUrl,
  canonicalizeSelectorRefs,
  compareText,
  stableInventoryHash
} from '@agentgo/domain'
import {
  ProbeRequestCompileError,
  ProbeRequestCompiler,
  computeWireRequestHmac,
  verifyWireRequestHmac,
  type MutationGenerator,
  type ProbeRequestCompilerDependencies,
  type ProbeRequestCompilerInput,
  type ProbeRequestTemplate
} from './request-compiler'

const NOW = '2026-07-19T00:00:00.000Z'
const KEY_REF = '7f3b82e1-bc3d-45a8-9a71-c4aa47c12f80'
const SECOND_KEY_REF = '8e3b82e1-bc3d-45a8-9a71-c4aa47c12f81'
const SECRET_REF = 'b7b76e72-16dc-499a-b16a-4a43e14a0d36'
const OWNER_REF = '1f3b82e1-bc3d-45a8-9a71-c4aa47c12f82'
const SCOPE_REF = '2f3b82e1-bc3d-45a8-9a71-c4aa47c12f83'
const SESSION_REF = '3f3b82e1-bc3d-45a8-9a71-c4aa47c12f84'
const IDENTITY_REF = '4f3b82e1-bc3d-45a8-9a71-c4aa47c12f85'
const TEST_OBJECT_REF = '5f3b82e1-bc3d-45a8-9a71-c4aa47c12f86'
const SECRET_SENTINEL = 'DAY4_SENTINEL_SECRET_must-not-leak'
const READ_CAPABILITY = 'http.reviewed-read'
const EXTRA_CAPABILITY = 'http.extra-safe'
const FORBIDDEN_CAPABILITY = 'process.execute'

function urlTemplate(endpoint: InventoryEndpointRecord): ProbeRequestTemplate['url'] {
  const match = /^(https?:\/\/[^/?#]+)(\/[^?#]*)$/u.exec(
    endpoint.canonicalRoute
  )
  if (!match?.[1] || match[2] === undefined) {
    throw new Error('Test endpoint must contain an origin and path.')
  }
  return {
    origin: {
      kind: 'literal',
      sensitivity: 'public',
      value: match[1]
    },
    pathSegments: match[2]
      .slice(1)
      .split('/')
      .map((segment) => ({
        value: {
          kind: 'literal' as const,
          sensitivity: 'public' as const,
          value: decodeURIComponent(segment)
        }
      }))
  }
}

function secretValueSource(
  generation = 1
): ProbeRequestTemplate['query'][number]['value'] {
  return {
    kind: 'secret-ref',
    secretRef: SECRET_REF,
    generation,
    resolver: {
      kind: 'secret-ref-resolver',
      resolverId: 'test.secret-resolver',
      version: '1.0.0'
    }
  }
}

function createEndpoint(
  overrides: Partial<InventoryEndpointRecord> = {}
): InventoryEndpointRecord {
  return InventoryEndpointRecordSchema.parse({
    id: 'endpoint-1',
    scanId: 'scan-1',
    method: 'GET',
    canonicalRoute: 'https://inventory.example.test/items',
    lifecycleStatus: 'active',
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides
  })
}

function createVariant(input: {
  selectors: readonly SelectorRef[]
  codec?: BodyEncoding
  endpoint?: InventoryEndpointRecord
  contentType?: string
  allowedHeaders?: RequestVariantRecord['allowedHeaders']
  bodyShape?: RequestVariantRecord['bodyShape']
  requiredCapabilityIds?: readonly string[]
}): RequestVariantRecord {
  const endpoint = input.endpoint ?? createEndpoint()
  const codec = input.codec ?? 'none'
  const bodyShape = canonicalizeInventoryBodyShape(
    input.bodyShape ??
      (codec === 'none'
        ? { rootType: 'none', fields: [] }
        : { rootType: 'object', fields: [] })
  )
  const allowedHeaders = canonicalizeAllowedHeaderDescriptors(
    input.allowedHeaders ?? []
  )
  const selectors = canonicalizeSelectorRefs(input.selectors)
  const requiredCapabilityIds = [
    ...(input.requiredCapabilityIds ?? [READ_CAPABILITY])
  ].sort(compareText)
  const structuralValue = {
    contentType: input.contentType ?? null,
    bodyShape,
    codec,
    transport: 'standard-http' as const,
    allowedHeaders,
    templateVersion: '1.0.0',
    requiredCapabilityIds,
    selectors
  }
  return RequestVariantRecordSchema.parse({
    id: 'variant-1',
    scanId: endpoint.scanId,
    endpointId: endpoint.id,
    ...(input.contentType ? { contentType: input.contentType } : {}),
    bodyShape,
    codec,
    transport: 'standard-http',
    allowedHeaders,
    templateVersion: '1.0.0',
    requiredCapabilityIds,
    selectors,
    redactedPreview: { url: endpoint.canonicalRoute },
    reviewStatus: 'reviewed',
    reviewedBy: 'reviewer-1',
    reviewedAt: NOW,
    executionClass: ['POST', 'PUT', 'PATCH'].includes(endpoint.method)
      ? 'active-l2'
      : 'active-l1',
    lifecycleStatus: 'active',
    structureHash: stableInventoryHash(structuralValue),
    createdAt: NOW,
    updatedAt: NOW
  })
}

function generator(
  supportedSelectorKinds: MutationGenerator['metadata']['supportedSelectorKinds'],
  supportedBodyEncodings: MutationGenerator['metadata']['supportedBodyEncodings'],
  generate: MutationGenerator['generate']
): MutationGenerator {
  return {
    metadata: MutationGeneratorMetadataSchema.parse({
      generatorId: 'test.fixed-mutation',
      version: '1.0.0',
      deterministic: true,
      unicodeNormalization: 'NFC',
      safety: {
        sideEffect: 'none',
        dataAccess: 'input-only',
        networkTarget: 'request-target',
        mayExecuteInTargetContext: false
      },
      requiredCapabilityIds: [READ_CAPABILITY],
      forbiddenCapabilityIds: [FORBIDDEN_CAPABILITY],
      maxOutputBytes: 4_096,
      supportedSelectorKinds,
      supportedBodyEncodings
    }),
    generate
  }
}

function createCompiler(
  mutationGenerator: MutationGenerator,
  options: {
    secret?: string
    dynamic?: unknown
    key?: Uint8Array
    dependencyOverrides?: Partial<ProbeRequestCompilerDependencies>
  } = {}
): ProbeRequestCompiler {
  const defaults: ProbeRequestCompilerDependencies = {
    mutationGenerators: [mutationGenerator],
    dynamicValueResolvers: [
      {
        resolverId: 'test.dynamic-resolver',
        version: '1.0.0',
        resolve: () => options.dynamic ?? 'dynamic-value'
      }
    ],
    secretRefResolvers: [
      {
        resolverId: 'test.secret-resolver',
        version: '1.0.0',
        resolve: () => options.secret ?? SECRET_SENTINEL
      }
    ],
    knownCapabilityIds: [READ_CAPABILITY, EXTRA_CAPABILITY, FORBIDDEN_CAPABILITY],
    hashKeyProvider: {
      resolveKey: () => options.key ?? new Uint8Array(32).fill(0x5a)
    }
  }
  return new ProbeRequestCompiler({
    ...defaults,
    ...options.dependencyOverrides
  })
}

function createInput(
  endpoint: InventoryEndpointRecord,
  requestVariant: RequestVariantRecord,
  requestTemplate: ProbeRequestTemplate,
  mutationTarget: ProbeRequestCompilerInput['mutationTarget'],
  overrides: Partial<ProbeRequestCompilerInput> = {}
): ProbeRequestCompilerInput {
  return {
    scanId: endpoint.scanId,
    endpoint,
    requestVariant,
    requestTemplate,
    mutationTarget,
    mutationGenerator: {
      generatorId: 'test.fixed-mutation',
      version: '1.0.0'
    },
    enabledCapabilityIds: [READ_CAPABILITY],
    hashKey: { keyRef: KEY_REF, keyVersion: 1 },
    ...(requestVariant.executionClass === 'active-l2'
      ? {
          ownerRef: OWNER_REF,
          scopeSnapshotId: SCOPE_REF,
          testObjectRef: {
            id: TEST_OBJECT_REF,
            version: 1,
            ownerRef: OWNER_REF,
            scopeSnapshotId: SCOPE_REF,
            statusSummary: 'ready' as const
          }
        }
      : {}),
    ...overrides
  }
}

function createBaselineInput(
  endpoint: InventoryEndpointRecord,
  requestVariant: RequestVariantRecord,
  requestTemplate: ProbeRequestTemplate,
  overrides: Partial<ProbeRequestCompilerInput> = {}
): ProbeRequestCompilerInput {
  return {
    scanId: endpoint.scanId,
    endpoint,
    requestVariant,
    requestTemplate,
    enabledCapabilityIds: [READ_CAPABILITY],
    hashKey: { keyRef: KEY_REF, keyVersion: 1 },
    ...(requestVariant.executionClass === 'active-l2'
      ? {
          ownerRef: OWNER_REF,
          scopeSnapshotId: SCOPE_REF,
          testObjectRef: {
            id: TEST_OBJECT_REF,
            version: 1,
            ownerRef: OWNER_REF,
            scopeSnapshotId: SCOPE_REF,
            statusSummary: 'ready' as const
          }
        }
      : {}),
    ...overrides
  }
}

function expectCompileCode(
  operation: () => unknown,
  code: ProbeRequestCompileError['code']
): ProbeRequestCompileError {
  try {
    operation()
  } catch (error) {
    expect(error).toBeInstanceOf(ProbeRequestCompileError)
    expect(error).toMatchObject({ code })
    return error as ProbeRequestCompileError
  }
  throw new Error('Expected ProbeRequestCompiler to reject the input.')
}

describe('ProbeRequestCompiler phased binding', () => {
  it('preserves duplicate query order, commits secret resolution, and performs zero network I/O', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const endpoint = createEndpoint()
    const variant = createVariant({
      endpoint,
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [
        {
          name: 'id',
          value: { kind: 'literal', sensitivity: 'public', value: 'baseline' }
        },
        {
          name: 'id',
          value: {
            kind: 'secret-ref',
            secretRef: SECRET_REF,
            generation: 7,
            resolver: {
              kind: 'secret-ref-resolver',
              resolverId: 'test.secret-resolver',
              version: '1.0.0'
            }
          }
        }
      ],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const mutationGenerator = generator(['query'], ['none'], () => 'mutated')
    const input = createInput(endpoint, variant, template, {
      kind: 'query',
      name: 'id',
      occurrence: 0,
      onMissing: 'reject'
    })
    const first = createCompiler(mutationGenerator).compile(input)
    const repeat = createCompiler(mutationGenerator).compile(input)
    const changedSecret = createCompiler(mutationGenerator, {
      secret: 'different-secret-value'
    }).compile(input)
    const changedKey = createCompiler(mutationGenerator).compile({
      ...input,
      hashKey: { keyRef: SECOND_KEY_REF, keyVersion: 2 }
    })
    const changedGeneration = createCompiler(mutationGenerator).compile({
      ...input,
      requestTemplate: {
        ...template,
        query: [
          template.query[0]!,
          {
            ...template.query[1]!,
            value: {
              ...template.query[1]!.value,
              generation: 8
            } as never
          }
        ]
      }
    })
    const sessionGenerationOne = createCompiler(mutationGenerator).compile({
      ...input,
      ownerRef: OWNER_REF,
      scopeSnapshotId: SCOPE_REF,
      sessionRef: {
        id: SESSION_REF,
        generation: 1,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF,
        statusSummary: 'active'
      }
    })
    const sessionGenerationTwo = createCompiler(mutationGenerator).compile({
      ...input,
      ownerRef: OWNER_REF,
      scopeSnapshotId: SCOPE_REF,
      sessionRef: {
        id: SESSION_REF,
        generation: 2,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF,
        statusSummary: 'active'
      }
    })
    const activeL2 = createCompiler(mutationGenerator).compile({
      ...input,
      requestVariant: { ...variant, executionClass: 'active-l2' },
      ownerRef: OWNER_REF,
      scopeSnapshotId: SCOPE_REF,
      testObjectRef: {
        id: TEST_OBJECT_REF,
        version: 1,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF,
        statusSummary: 'ready'
      }
    })
    const capabilityOrderOne = createCompiler(mutationGenerator).compile({
      ...input,
      enabledCapabilityIds: [READ_CAPABILITY, EXTRA_CAPABILITY]
    })
    const capabilityOrderTwo = createCompiler(mutationGenerator).compile({
      ...input,
      enabledCapabilityIds: [EXTRA_CAPABILITY, READ_CAPABILITY]
    })
    const unboundExecutionContext = createCompiler(
      mutationGenerator
    ).compile({
      ...input,
      ownerRef: OWNER_REF,
      scopeSnapshotId: SCOPE_REF
    })
    const executionBound = createCompiler(mutationGenerator).compile({
      ...input,
      ownerRef: OWNER_REF,
      scopeSnapshotId: SCOPE_REF,
      executionBinding: {
        stepId: 'step.read',
        purpose: 'read',
        adapterKind: 'http'
      }
    })

    expect(first.request.url).toBe(
      `https://inventory.example.test/items?id=mutated&id=${SECRET_SENTINEL}`
    )
    expect(first.templateIntentHash).toEqual(repeat.templateIntentHash)
    expect(first.resolvedIntentHash).toEqual(repeat.resolvedIntentHash)
    expect(first.wireRequestHmac).toEqual(repeat.wireRequestHmac)
    expect(changedSecret.templateIntentHash).toEqual(first.templateIntentHash)
    expect(changedSecret.resolvedIntentHash.digest).not.toBe(
      first.resolvedIntentHash.digest
    )
    expect(changedSecret.wireRequestHmac.digest).not.toBe(
      first.wireRequestHmac.digest
    )
    expect(changedKey.templateIntentHash).toEqual(first.templateIntentHash)
    expect(changedKey.resolvedIntentHash.digest).not.toBe(
      first.resolvedIntentHash.digest
    )
    expect(changedKey.wireRequestHmac.digest).not.toBe(
      first.wireRequestHmac.digest
    )
    expect(changedGeneration.templateIntentHash.digest).not.toBe(
      first.templateIntentHash.digest
    )
    expect(sessionGenerationOne.templateIntentHash).toEqual(
      sessionGenerationTwo.templateIntentHash
    )
    expect(sessionGenerationOne.resolvedIntentHash.digest).not.toBe(
      sessionGenerationTwo.resolvedIntentHash.digest
    )
    expect(sessionGenerationOne.wireRequestHmac.digest).not.toBe(
      sessionGenerationTwo.wireRequestHmac.digest
    )
    expect(activeL2.request.materialize()).toEqual(first.request.materialize())
    expect(activeL2.templateIntentHash.digest).not.toBe(
      first.templateIntentHash.digest
    )
    expect(activeL2.resolvedIntentHash.digest).not.toBe(
      first.resolvedIntentHash.digest
    )
    expect(activeL2.wireRequestHmac.digest).not.toBe(
      first.wireRequestHmac.digest
    )
    expect(capabilityOrderOne.templateIntentHash).toEqual(
      capabilityOrderTwo.templateIntentHash
    )
    expect(capabilityOrderOne.resolvedIntentHash).toEqual(
      capabilityOrderTwo.resolvedIntentHash
    )
    expect(capabilityOrderOne.wireRequestHmac).toEqual(
      capabilityOrderTwo.wireRequestHmac
    )
    expect(executionBound.templateIntentHash).toEqual(
      unboundExecutionContext.templateIntentHash
    )
    expect(executionBound.resolvedIntentHash).toEqual(
      unboundExecutionContext.resolvedIntentHash
    )
    expect(executionBound.wireRequestHmac.digest).not.toBe(
      unboundExecutionContext.wireRequestHmac.digest
    )
    expect(executionBound.authorizationContext.executionBinding).toEqual({
      stepId: 'step.read',
      purpose: 'read',
      adapterKind: 'http'
    })
    expect(first.authorizationContext).toMatchObject({
      templateIntentHash: first.templateIntentHash,
      enabledCapabilityIds: [READ_CAPABILITY],
      ownerRef: null,
      scopeSnapshotId: null,
      identityRef: null,
      sessionRef: null,
      testObjectRef: null,
      executionBinding: null
    })
    expect(first.resolvedIntentHash).toMatchObject({
      domain: 'agentgo.resolved-intent.v1',
      commitmentKeyRef: KEY_REF,
      commitmentKeyVersion: 1
    })
    expect(first.wireRequestHmac).toMatchObject({
      domain: 'agentgo.wire-request.v2',
      keyRef: KEY_REF,
      keyVersion: 1
    })
    expect(JSON.stringify(first)).not.toContain(SECRET_SENTINEL)
    expect(JSON.stringify(first.request)).toBe(
      '{"redacted":true,"kind":"ephemeral-wire-request"}'
    )
    const encoded = createCompiler(
      generator(['query'], ['none'], () => '!*~ +%/中文')
    ).compile(input)
    expect(encoded.request.url).toBe(
      `https://inventory.example.test/items?id=%21*%7E+%2B%25%2F%E4%B8%AD%E6%96%87&id=${SECRET_SENTINEL}`
    )
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  it('canonicalizes repeated form fields and distinguishes an empty body from no body', () => {
    const endpoint = createEndpoint({ method: 'POST' })
    const variant = createVariant({
      endpoint,
      codec: 'form',
      contentType: 'application/x-www-form-urlencoded',
      bodyShape: {
        rootType: 'object',
        fields: [{ path: '/role', valueType: 'string', required: true }]
      },
      allowedHeaders: [
        { name: 'content-type', valueType: 'string', required: true }
      ],
      selectors: [
        { kind: 'form', name: 'role', valueType: 'string', required: true }
      ]
    })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: {
        encoding: 'form',
        entries: [
          {
            name: 'role',
            value: { kind: 'literal', sensitivity: 'public', value: 'one' }
          },
          {
            name: 'role',
            value: { kind: 'literal', sensitivity: 'public', value: 'two' }
          }
        ]
      }
    }
    const compiler = createCompiler(
      generator(['form'], ['form'], () => 'x y')
    )
    const compiled = compiler.compile(
      createInput(endpoint, variant, template, {
        kind: 'form',
        name: 'role',
        occurrence: 'all',
        onMissing: 'reject'
      })
    )
    const bodyText = Buffer.from(compiled.request.bodyBytes ?? []).toString('utf8')

    expect(bodyText).toBe('role=x+y&role=x+y')
    expect(compiled.request.headers).toEqual([
      { name: 'content-length', value: String(Buffer.byteLength(bodyText)) },
      {
        name: 'content-type',
        value: 'application/x-www-form-urlencoded; charset=utf-8'
      }
    ])
    const encodedForm = createCompiler(
      generator(['form'], ['form'], () => '!*~ +%/中文')
    ).compile(
      createInput(endpoint, variant, template, {
        kind: 'form',
        name: 'role',
        occurrence: 0,
        onMissing: 'reject'
      })
    )
    expect(Buffer.from(encodedForm.request.bodyBytes ?? []).toString('utf8')).toBe(
      'role=%21*%7E+%2B%25%2F%E4%B8%AD%E6%96%87&role=two'
    )

    expectCompileCode(
      () =>
        compiler.compile(
          createInput(endpoint, variant, template, {
            kind: 'form',
            name: 'role',
            occurrence: 3,
            onMissing: 'append'
          })
        ),
      'template-mismatch'
    )

    const queryEndpoint = createEndpoint({ id: 'endpoint-empty-body', method: 'POST' })
    const emptyBodyVariant = createVariant({
      endpoint: queryEndpoint,
      codec: 'form',
      contentType: 'application/x-www-form-urlencoded',
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    const emptyBody = createCompiler(
      generator(['query'], ['form'], () => 'changed')
    ).compile(
      createInput(
        queryEndpoint,
        emptyBodyVariant,
        {
          url: urlTemplate(queryEndpoint),
          query: [
            {
              name: 'id',
              value: { kind: 'literal', sensitivity: 'public', value: 'base' }
            }
          ],
          headers: [],
          cookies: [],
          body: { encoding: 'form', entries: [] }
        },
        { kind: 'query', name: 'id', occurrence: 0, onMissing: 'reject' }
      )
    )
    expect(emptyBody.request.bodyBytes).toEqual([])
    expect(emptyBody.request.headers).toContainEqual({
      name: 'content-length',
      value: '0'
    })
  })

  it('mutates RFC 6901 pointers without prototype pollution and emits canonical JSON', () => {
    const endpoint = createEndpoint({ method: 'POST' })
    const variant = createVariant({
      endpoint,
      codec: 'json',
      contentType: 'application/json',
      bodyShape: {
        rootType: 'object',
        fields: [
          { path: '/__proto__/value', valueType: 'string', required: true },
          { path: '/z', valueType: 'integer', required: true }
        ]
      },
      allowedHeaders: [
        { name: 'content-type', valueType: 'string', required: true }
      ],
      selectors: [
        {
          kind: 'json-pointer',
          pointer: '/__proto__/value',
          valueType: 'string',
          required: true
        }
      ]
    })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: {
        encoding: 'json',
        value: {
          kind: 'object',
          entries: [
            {
              key: 'z',
              value: { kind: 'literal', sensitivity: 'public', value: 1 }
            },
            {
              key: '__proto__',
              value: {
                kind: 'object',
                entries: [
                  {
                    key: 'value',
                    value: {
                      kind: 'literal',
                      sensitivity: 'public',
                      value: 'base'
                    }
                  }
                ]
              }
            }
          ]
        }
      }
    }
    const compiled = createCompiler(
      generator(['json-pointer'], ['json'], () => 'changed')
    ).compile(
      createInput(endpoint, variant, template, {
        kind: 'json-pointer',
        pointer: '/__proto__/value'
      })
    )

    expect(Buffer.from(compiled.request.bodyBytes ?? []).toString('utf8')).toBe(
      '{"__proto__":{"value":"changed"},"z":1}'
    )
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined()
  })

  it('handles escaped/root JSON pointers and rejects ambiguous array or missing addresses', () => {
    const endpoint = createEndpoint({ method: 'POST' })
    const pointers = ['/a~1b/~0key', '/items/01', '/items/-', '/missing', '']
    const variant = createVariant({
      endpoint,
      codec: 'json',
      contentType: 'application/json',
      bodyShape: {
        rootType: 'object',
        fields: [
          { path: '/a~1b/~0key', valueType: 'string', required: true },
          { path: '/items/0', valueType: 'string', required: true }
        ]
      },
      selectors: pointers.map((pointer) => ({
        kind: 'json-pointer' as const,
        pointer,
        valueType: pointer === '' ? 'object' as const : 'string' as const,
        required: false
      }))
    })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: {
        encoding: 'json',
        value: {
          kind: 'object',
          entries: [
            {
              key: 'items',
              value: {
                kind: 'array',
                items: [
                  { kind: 'literal', sensitivity: 'public', value: 'zero' }
                ]
              }
            },
            {
              key: 'a/b',
              value: {
                kind: 'object',
                entries: [
                  {
                    key: '~key',
                    value: {
                      kind: 'literal',
                      sensitivity: 'public',
                      value: 'base'
                    }
                  }
                ]
              }
            }
          ]
        }
      }
    }
    const escaped = createCompiler(
      generator(['json-pointer'], ['json'], () => 'changed')
    ).compile(
      createInput(endpoint, variant, template, {
        kind: 'json-pointer',
        pointer: '/a~1b/~0key'
      })
    )
    expect(Buffer.from(escaped.request.bodyBytes ?? []).toString('utf8')).toBe(
      '{"a/b":{"~key":"changed"},"items":["zero"]}'
    )
    for (const pointer of ['/items/01', '/items/-', '/missing']) {
      expectCompileCode(
        () =>
          createCompiler(
            generator(['json-pointer'], ['json'], () => 'changed')
          ).compile(
            createInput(endpoint, variant, template, {
              kind: 'json-pointer',
              pointer
            })
          ),
        'template-mismatch'
      )
    }
    const root = createCompiler(
      generator(['json-pointer'], ['json'], () => ({
        items: ['root'],
        'a/b': { '~key': 'replacement' }
      }))
    ).compile(
      createInput(endpoint, variant, template, {
        kind: 'json-pointer',
        pointer: ''
      })
    )
    expect(Buffer.from(root.request.bodyBytes ?? []).toString('utf8')).toBe(
      '{"a/b":{"~key":"replacement"},"items":["root"]}'
    )
  })

  it('accepts only canonical reviewed JSON media types and validates synthesized headers', () => {
    const endpoint = createEndpoint({ method: 'POST' })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: {
        encoding: 'json',
        value: {
          kind: 'object',
          entries: [
            {
              key: 'id',
              value: { kind: 'literal', sensitivity: 'public', value: 'base' }
            }
          ]
        }
      }
    }
    const variantFor = (contentType: string) =>
      createVariant({
        endpoint,
        codec: 'json',
        contentType,
        bodyShape: {
          rootType: 'object',
          fields: [{ path: '/id', valueType: 'string', required: true }]
        },
        allowedHeaders: [
          { name: 'content-type', valueType: 'string', required: true }
        ],
        selectors: [
          {
            kind: 'json-pointer',
            pointer: '/id',
            valueType: 'string',
            required: true
          }
        ]
      })
    const target = { kind: 'json-pointer' as const, pointer: '/id' }
    const mutationGenerator = generator(
      ['json-pointer'],
      ['json'],
      () => 'changed'
    )
    for (const contentType of [
      'application/\r\nx-injected: yes+json',
      'application/json; charset=utf-8',
      'Application/JSON'
    ]) {
      expectCompileCode(
        () =>
          createCompiler(mutationGenerator).compile(
            createInput(
              endpoint,
              variantFor(contentType),
              template,
              target
            )
          ),
        'template-mismatch'
      )
    }
    const vendor = createCompiler(mutationGenerator).compile(
      createInput(
        endpoint,
        variantFor('application/vnd.agentgo+json'),
        template,
        target
      )
    )
    expect(vendor.request.headers).toContainEqual({
      name: 'content-type',
      value: 'application/vnd.agentgo+json; charset=utf-8'
    })
  })

  it('canonicalizes header order and preserves explicit duplicate cookie occurrences', () => {
    const endpoint = createEndpoint()
    const headerVariant = createVariant({
      endpoint,
      allowedHeaders: [
        { name: 'x-a', valueType: 'string', required: true },
        { name: 'x-b', valueType: 'string', required: true }
      ],
      selectors: [
        { kind: 'header', name: 'x-a', valueType: 'string', required: true }
      ]
    })
    const header = (name: string, value: string) => ({
      name,
      value: { kind: 'literal' as const, sensitivity: 'public' as const, value }
    })
    const headerTarget = { kind: 'header' as const, name: 'x-a' }
    const headerGenerator = generator(['header'], ['none'], () => 'changed')
    const first = createCompiler(headerGenerator).compile(
      createInput(
        endpoint,
        headerVariant,
        {
          url: urlTemplate(endpoint),
          query: [],
          headers: [header('x-b', 'two'), header('x-a', 'one')],
          cookies: [],
          body: { encoding: 'none' }
        },
        headerTarget
      )
    )
    const reordered = createCompiler(headerGenerator).compile(
      createInput(
        endpoint,
        headerVariant,
        {
          url: urlTemplate(endpoint),
          query: [],
          headers: [header('x-a', 'one'), header('x-b', 'two')],
          cookies: [],
          body: { encoding: 'none' }
        },
        headerTarget
      )
    )
    expect(first.request.headers).toEqual([
      { name: 'x-a', value: 'changed' },
      { name: 'x-b', value: 'two' }
    ])
    expect(first.templateIntentHash).toEqual(reordered.templateIntentHash)
    expect(first.resolvedIntentHash).toEqual(reordered.resolvedIntentHash)
    expect(first.wireRequestHmac).toEqual(reordered.wireRequestHmac)

    const mismatchedHeaderVariant = createVariant({
      endpoint,
      allowedHeaders: [
        { name: 'x-a', valueType: 'string', required: false }
      ],
      selectors: [
        { kind: 'header', name: 'x-a', valueType: 'string', required: true }
      ]
    })
    expectCompileCode(
      () =>
        createCompiler(headerGenerator).compile(
          createInput(
            endpoint,
            mismatchedHeaderVariant,
            {
              url: urlTemplate(endpoint),
              query: [],
              headers: [header('x-a', 'one')],
              cookies: [],
              body: { encoding: 'none' }
            },
            headerTarget
          )
        ),
      'template-mismatch'
    )

    const cookieVariant = createVariant({
      endpoint,
      selectors: [
        { kind: 'cookie', name: 'sid', valueType: 'string', required: true }
      ]
    })
    const cookieInput = createInput(
      endpoint,
      cookieVariant,
      {
        url: urlTemplate(endpoint),
        query: [],
        headers: [],
        cookies: [
          { name: 'sid', value: secretValueSource(1) },
          { name: 'sid', value: secretValueSource(2) }
        ],
        body: { encoding: 'none' }
      },
      { kind: 'cookie', name: 'sid', occurrence: 1, onMissing: 'reject' }
    )
    const cookieCompiled = createCompiler(
      generator(['cookie'], ['none'], () => 'next'),
      { secret: 'one' }
    ).compile(cookieInput)
    expect(cookieCompiled.request.headers).toEqual([
      { name: 'cookie', value: 'sid=one; sid=next' }
    ])
    expectCompileCode(
      () =>
        createCompiler(
          generator(['cookie'], ['none'], () => 'bad;value'),
          { secret: 'one' }
        ).compile(cookieInput),
      'generator-rejected'
    )

    const exactSecretPath = 'N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa'
    const redactedEndpoint = createEndpoint({
      id: 'endpoint-redacted-path',
      canonicalRoute: canonicalizeInventoryUrl(
        `https://inventory.example.test/a/${exactSecretPath}`
      )
    })
    const redactedVariant = createVariant({
      endpoint: redactedEndpoint,
      selectors: [
        { kind: 'path', name: 'resource-id', valueType: 'string', required: true }
      ]
    })
    const secretPathCompiled = createCompiler(
      generator(['path'], ['none'], () => 'replacement'),
      { secret: exactSecretPath }
    ).compile(
      createInput(
        redactedEndpoint,
        redactedVariant,
        {
          url: {
            origin: {
              kind: 'literal',
              sensitivity: 'public',
              value: 'https://inventory.example.test'
            },
            pathSegments: [
              {
                value: { kind: 'literal', sensitivity: 'public', value: 'a' }
              },
              {
                selectorName: 'resource-id',
                value: {
                  kind: 'secret-ref',
                  secretRef: SECRET_REF,
                  generation: 7,
                  resolver: {
                    kind: 'secret-ref-resolver',
                    resolverId: 'test.secret-resolver',
                    version: '1.0.0'
                  }
                }
              }
            ]
          },
          query: [],
          headers: [],
          cookies: [],
          body: { encoding: 'none' }
        },
        {
          kind: 'path',
          selectorName: 'resource-id',
          segmentIndex: 1
        }
      )
    )
    expect(secretPathCompiled.request.url).toBe(
      'https://inventory.example.test/a/replacement'
    )
    expect(JSON.stringify(secretPathCompiled)).not.toContain(exactSecretPath)
  })

  it('binds a path selector name to an exact segment while preserving empty segments', () => {
    const endpoint = createEndpoint({
      canonicalRoute: 'https://inventory.example.test/a//tail/'
    })
    const variant = createVariant({
      endpoint,
      selectors: [
        { kind: 'path', name: 'resource-id', valueType: 'string', required: true }
      ]
    })
    const template: ProbeRequestTemplate = {
      url: {
        ...urlTemplate(endpoint),
        pathSegments: urlTemplate(endpoint).pathSegments.map((segment, index) =>
          index === 1
            ? { ...segment, selectorName: 'resource-id' }
            : segment
        )
      },
      query: [],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const input = createInput(endpoint, variant, template, {
      kind: 'path',
      selectorName: 'resource-id',
      segmentIndex: 1
    })
    const compiled = createCompiler(
      generator(['path'], ['none'], () => 'new id')
    ).compile(input)

    expect(compiled.request.url).toBe(
      'https://inventory.example.test/a/new%20id/tail/'
    )
    expectCompileCode(
      () =>
        createCompiler(generator(['path'], ['none'], () => '../escape')).compile(
          input
        ),
      'generator-rejected'
    )
    for (const invalidSegment of ['.', '..', '/', '\\']) {
      expectCompileCode(
        () =>
          createCompiler(generator(['path'], ['none'], () => 'safe')).compile({
            ...input,
            requestTemplate: {
              ...template,
              url: {
                ...template.url,
                pathSegments: template.url.pathSegments.map((segment, index) =>
                  index === 1
                    ? {
                        ...segment,
                        value: {
                          kind: 'literal',
                          sensitivity: 'public',
                          value: invalidSegment
                        }
                      }
                    : segment
                )
              }
            }
          }),
        'invalid-canonical-input'
      )
    }
    const twoSelectorVariant = createVariant({
      endpoint,
      selectors: [
        { kind: 'path', name: 'resource-id', valueType: 'string', required: true },
        { kind: 'path', name: 'other-id', valueType: 'string', required: false }
      ]
    })
    expectCompileCode(
      () =>
        createCompiler(generator(['path'], ['none'], () => 'safe')).compile(
          createInput(endpoint, twoSelectorVariant, template, {
            kind: 'path',
            selectorName: 'other-id',
            segmentIndex: 1
          })
        ),
      'template-mismatch'
    )
  })
})

describe('ProbeRequestCompiler fail-closed boundaries', () => {
  it('rejects unreviewed/tampered inventory, unknown capabilities, and unknown selectors', () => {
    const endpoint = createEndpoint()
    const variant = createVariant({
      endpoint,
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [
        {
          name: 'id',
          value: { kind: 'literal', sensitivity: 'public', value: 'base' }
        }
      ],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const compiler = createCompiler(generator(['query'], ['none'], () => 'x'))
    const input = createInput(endpoint, variant, template, {
      kind: 'query',
      name: 'id',
      occurrence: 0,
      onMissing: 'reject'
    })

    expectCompileCode(
      () => compiler.compile({ ...input, requestVariant: { ...variant, reviewStatus: 'rejected' } }),
      'variant-not-executable'
    )
    expectCompileCode(
      () =>
        compiler.compile({
          ...input,
          requestVariant: { ...variant, structureHash: 'f'.repeat(64) }
        }),
      'inventory-binding-rejected'
    )
    expectCompileCode(
      () =>
        compiler.compile({
          ...input,
          enabledCapabilityIds: [READ_CAPABILITY, 'unknown.capability']
        }),
      'unknown-capability'
    )
    expectCompileCode(
      () =>
        compiler.compile({
          ...input,
          mutationTarget: { kind: 'xml-path', path: '/id' } as never
        }),
      'unsupported-selector'
    )
  })

  it('rejects parser normalization, malformed names, reserved headers, and oversized templates', () => {
    const endpoint = createEndpoint({
      canonicalRoute: 'https://inventory.example.test/a/%2e%2e/secret'
    })
    const variant = createVariant({
      endpoint,
      selectors: [
        { kind: 'path', name: 'id', valueType: 'string', required: true }
      ]
    })
    const compiler = createCompiler(generator(['path'], ['none'], () => 'x'))
    const input = createInput(
      endpoint,
      variant,
      {
        url: {
          ...urlTemplate(endpoint),
          pathSegments: urlTemplate(endpoint).pathSegments.map((segment, index) =>
            index === 0 ? { ...segment, selectorName: 'id' } : segment
          )
        },
        query: [],
        headers: [],
        cookies: [],
        body: { encoding: 'none' }
      },
      { kind: 'path', selectorName: 'id', segmentIndex: 0 }
    )
    expectCompileCode(() => compiler.compile(input), 'invalid-canonical-input')

    const validEndpoint = createEndpoint()
    const headerVariant = createVariant({
      endpoint: validEndpoint,
      allowedHeaders: [
        { name: 'x-test', valueType: 'string', required: true }
      ],
      selectors: [
        { kind: 'header', name: 'x-test', valueType: 'string', required: true }
      ]
    })
    const headerCompiler = createCompiler(
      generator(['header'], ['none'], () => 'changed')
    )
    const headerInput = createInput(
      validEndpoint,
      headerVariant,
      {
        url: urlTemplate(validEndpoint),
        query: [],
        headers: [
          {
            name: 'x-test',
            value: { kind: 'literal', sensitivity: 'public', value: 'base' }
          }
        ],
        cookies: [],
        body: { encoding: 'none' }
      },
      { kind: 'header', name: 'x-test' }
    )
    expectCompileCode(
      () =>
        headerCompiler.compile({
          ...headerInput,
          requestTemplate: {
            ...headerInput.requestTemplate,
            headers: [
              ...headerInput.requestTemplate.headers,
              {
                name: 'x-test',
                value: { kind: 'literal', sensitivity: 'public', value: 'other' }
              }
            ]
          }
        }),
      'template-mismatch'
    )
    expectCompileCode(
      () =>
        headerCompiler.compile({
          ...headerInput,
          requestTemplate: {
            ...headerInput.requestTemplate,
            headers: [
              {
                name: 'X-Test',
                value: { kind: 'literal', sensitivity: 'public', value: 'one' }
              }
            ]
          }
        }),
      'invalid-canonical-input'
    )
    expectCompileCode(
      () =>
        headerCompiler.compile({
          ...headerInput,
          requestTemplate: {
            ...headerInput.requestTemplate,
            headers: [
              {
                name: 'content-length',
                value: { kind: 'literal', sensitivity: 'public', value: '1' }
              }
            ]
          }
        }),
      'template-mismatch'
    )
    expectCompileCode(
      () =>
        headerCompiler.compile({
          ...headerInput,
          requestTemplate: {
            ...headerInput.requestTemplate,
            query: [
              {
                name: 7 as never,
                value: { kind: 'literal', sensitivity: 'public', value: 'x' }
              }
            ]
          }
        }),
      'invalid-input'
    )
    expectCompileCode(
      () =>
        headerCompiler.compile({
          ...headerInput,
          requestTemplate: {
            ...headerInput.requestTemplate,
            extra: true,
            query: Array.from({ length: 4_097 }, () => ({
              name: 'id',
              value: { kind: 'literal' as const, sensitivity: 'public' as const, value: 'x' }
            }))
          } as never
        }),
      'invalid-input'
    )
  })

  it('redacts resolver and generator failures and rejects unknown resolver registries', () => {
    const endpoint = createEndpoint()
    const variant = createVariant({
      endpoint,
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    const dynamicTemplate: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [
        {
          name: 'id',
          value: {
            kind: 'dynamic',
            slotId: 'request-id',
            resolver: {
              kind: 'dynamic-value-resolver',
              resolverId: 'test.dynamic-resolver',
              version: '1.0.0'
            }
          }
        }
      ],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const target = {
      kind: 'query' as const,
      name: 'id',
      occurrence: 0 as const,
      onMissing: 'reject' as const
    }
    const resolverFailure = createCompiler(
      generator(['query'], ['none'], () => 'x'),
      {
        dependencyOverrides: {
          dynamicValueResolvers: [
            {
              resolverId: 'test.dynamic-resolver',
              version: '1.0.0',
              resolve: () => {
                throw new Error(SECRET_SENTINEL)
              }
            }
          ]
        }
      }
    )
    const resolverError = expectCompileCode(
      () =>
        resolverFailure.compile(
          createInput(endpoint, variant, dynamicTemplate, target)
        ),
      'resolver-rejected'
    )
    expect(resolverError.message).not.toContain(SECRET_SENTINEL)

    const generatorFailure = createCompiler(
      generator(['query'], ['none'], () => {
        throw new Error(SECRET_SENTINEL)
      })
    )
    const generatorError = expectCompileCode(
      () =>
        generatorFailure.compile(
          createInput(endpoint, variant, dynamicTemplate, target)
        ),
      'generator-rejected'
    )
    expect(generatorError.message).not.toContain(SECRET_SENTINEL)

    const unknownResolver = createCompiler(
      generator(['query'], ['none'], () => 'x'),
      { dependencyOverrides: { dynamicValueResolvers: [] } }
    )
    expectCompileCode(
      () =>
        unknownResolver.compile(
          createInput(endpoint, variant, dynamicTemplate, target)
        ),
      'unknown-resolver'
    )
    const crossRegistryTemplate: ProbeRequestTemplate = {
      ...dynamicTemplate,
      query: [
        {
          name: 'id',
          value: {
            ...dynamicTemplate.query[0]!.value,
            resolver: {
              kind: 'dynamic-value-resolver',
              resolverId: 'test.secret-resolver',
              version: '1.0.0'
            }
          } as never
        }
      ]
    }
    expectCompileCode(
      () =>
        createCompiler(
          generator(['query'], ['none'], () => 'x')
        ).compile(createInput(endpoint, variant, crossRegistryTemplate, target)),
      'unknown-resolver'
    )
  })

  it('binds JSON body shape before and after mutation and rejects hostile resolver values', () => {
    const endpoint = createEndpoint({ method: 'POST' })
    const variant = createVariant({
      endpoint,
      codec: 'json',
      contentType: 'application/json',
      bodyShape: {
        rootType: 'object',
        fields: [
          { path: '/id', valueType: 'string', required: true },
          { path: '/optional', valueType: 'string', required: false }
        ]
      },
      selectors: [
        {
          kind: 'json-pointer',
          pointer: '/id',
          valueType: 'string',
          required: true
        }
      ]
    })
    const dynamicId = {
      kind: 'dynamic' as const,
      slotId: 'request-id',
      resolver: {
        kind: 'dynamic-value-resolver' as const,
        resolverId: 'test.dynamic-resolver',
        version: '1.0.0'
      }
    }
    const validTemplate: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: {
        encoding: 'json',
        value: {
          kind: 'object',
          entries: [{ key: 'id', value: dynamicId }]
        }
      }
    }
    const target = { kind: 'json-pointer' as const, pointer: '/id' }

    const valid = createCompiler(
      generator(['json-pointer'], ['json'], () => 'changed'),
      { dynamic: 'base' }
    ).compile(createInput(endpoint, variant, validTemplate, target))
    expect(Buffer.from(valid.request.bodyBytes ?? []).toString('utf8')).toBe(
      '{"id":"changed"}'
    )

    const extraTemplate: ProbeRequestTemplate = {
      ...validTemplate,
      body: {
        encoding: 'json',
        value: {
          kind: 'object',
          entries: [
            { key: 'id', value: dynamicId },
            {
              key: 'extra',
              value: { kind: 'literal', sensitivity: 'public', value: true }
            }
          ]
        }
      }
    }
    expectCompileCode(
      () =>
        createCompiler(
          generator(['json-pointer'], ['json'], () => 'changed')
        ).compile(createInput(endpoint, variant, extraTemplate, target)),
      'template-mismatch'
    )

    expectCompileCode(
      () =>
        createCompiler(
          generator(['json-pointer'], ['json'], () => ({ extra: 'value' })),
          { dynamic: 'base' }
        ).compile(createInput(endpoint, variant, validTemplate, target)),
      'generator-rejected'
    )
    expectCompileCode(
      () =>
        createCompiler(
          generator(['json-pointer'], ['json'], () => 'changed'),
          { dynamic: { extra: 'value' } }
        ).compile(createInput(endpoint, variant, validTemplate, target)),
      'resolver-rejected'
    )

    const cyclic: { self?: unknown } = {}
    cyclic.self = cyclic
    expectCompileCode(
      () =>
        createCompiler(
          generator(['json-pointer'], ['json'], () => 'changed'),
          { dynamic: cyclic }
        ).compile(createInput(endpoint, variant, validTemplate, target)),
      'resolver-rejected'
    )
    const accessor = Object.create(null) as Record<string, unknown>
    Object.defineProperty(accessor, 'secret', {
      enumerable: true,
      get: () => {
        throw new Error(SECRET_SENTINEL)
      }
    })
    const accessorError = expectCompileCode(
      () =>
        createCompiler(
          generator(['json-pointer'], ['json'], () => 'changed'),
          { dynamic: accessor }
        ).compile(createInput(endpoint, variant, validTemplate, target)),
      'resolver-rejected'
    )
    expect(accessorError.message).not.toContain(SECRET_SENTINEL)
  })

  it('freezes a normalized snapshot before callbacks and fails closed on unsafe semantics', () => {
    const mutableEndpoint = { ...createEndpoint() }
    const mutableVariant = {
      ...createVariant({
        endpoint: mutableEndpoint,
        selectors: [
          { kind: 'query', name: 'id', valueType: 'string', required: true }
        ]
      })
    }
    const template: ProbeRequestTemplate = {
      url: urlTemplate(mutableEndpoint),
      query: [
        {
          name: 'id',
          value: { kind: 'literal', sensitivity: 'public', value: 'base' }
        }
      ],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const target = {
      kind: 'query' as const,
      name: 'id',
      occurrence: 0 as const,
      onMissing: 'reject' as const
    }
    const compiled = createCompiler(
      generator(['query'], ['none'], () => {
        mutableVariant.contentType = 'application/changed'
        return 'changed'
      }),
      {
        dependencyOverrides: {
          hashKeyProvider: {
            resolveKey: () => {
              mutableEndpoint.method = 'DELETE'
              return new Uint8Array(32).fill(0x5a)
            }
          }
        }
      }
    ).compile(
      createInput(
        mutableEndpoint,
        mutableVariant,
        template,
        target
      )
    )
    expect(compiled.request.method).toBe('GET')
    expect(() =>
      Object.defineProperty(compiled.request, 'url', {
        value: 'https://attacker.invalid/'
      })
    ).toThrow(TypeError)

    let methodReads = 0
    const switchingEndpoint = new Proxy(createEndpoint(), {
      get: (targetObject, property, receiver) => {
        if (property === 'method') {
          methodReads += 1
          return methodReads < 4 ? 'GET' : 'DELETE'
        }
        return Reflect.get(targetObject, property, receiver)
      }
    })
    const switchingVariant = createVariant({
      endpoint: switchingEndpoint,
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    methodReads = 0
    const switchingCompiled = createCompiler(
      generator(['query'], ['none'], () => 'changed')
    ).compile(
      createInput(
        switchingEndpoint,
        switchingVariant,
        { ...template, url: urlTemplate(createEndpoint()) },
        target
      )
    )
    expect(switchingCompiled.request.method).toBe('GET')
    expect(methodReads).toBe(0)

    const accessorEndpoint = { ...createEndpoint() }
    Object.defineProperty(accessorEndpoint, 'method', {
      enumerable: true,
      get: () => {
        throw new Error(SECRET_SENTINEL)
      }
    })
    const accessorInputError = expectCompileCode(
      () =>
        createCompiler(generator(['query'], ['none'], () => 'x')).compile({
          ...createInput(createEndpoint(), createVariant({
            selectors: [
              { kind: 'query', name: 'id', valueType: 'string', required: true }
            ]
          }), template, target),
          endpoint: accessorEndpoint
        }),
      'invalid-input'
    )
    expect(accessorInputError.message).not.toContain(SECRET_SENTINEL)

    const deleteEndpoint = createEndpoint({ method: 'DELETE' })
    const deleteVariant = createVariant({
      endpoint: deleteEndpoint,
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    expectCompileCode(
      () =>
        createCompiler(generator(['query'], ['none'], () => 'x')).compile(
          createInput(deleteEndpoint, deleteVariant, {
            ...template,
            url: urlTemplate(deleteEndpoint)
          }, target)
        ),
      'variant-not-executable'
    )

    const safeGenerator = generator(['query'], ['none'], () => 'x')
    const unsafeGenerator: MutationGenerator = {
      ...safeGenerator,
      metadata: MutationGeneratorMetadataSchema.parse({
        ...safeGenerator.metadata,
        safety: { ...safeGenerator.metadata.safety, sideEffect: 'unknown' }
      })
    }
    expectCompileCode(
      () =>
        createCompiler(unsafeGenerator).compile(
          createInput(createEndpoint(), createVariant({
            selectors: [
              { kind: 'query', name: 'id', valueType: 'string', required: true }
            ]
          }), template, target)
        ),
      'generator-rejected'
    )
  })

  it('requires explicit controlled-OOB metadata and capability at active L1', () => {
    const oobCapability = 'oob.controlled-observe'
    const endpoint = createEndpoint()
    const variant = createVariant({
      endpoint,
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [
        {
          name: 'id',
          value: {
            kind: 'literal',
            sensitivity: 'public',
            value: 'baseline'
          }
        }
      ],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const target = {
      kind: 'query' as const,
      name: 'id',
      occurrence: 0,
      onMissing: 'reject' as const
    }
    const base = generator(['query'], ['none'], () => 'controlled-callback')
    const controlled: MutationGenerator = {
      ...base,
      metadata: MutationGeneratorMetadataSchema.parse({
        ...base.metadata,
        safety: {
          ...base.metadata.safety,
          networkTarget: 'controlled-oob'
        },
        requiredCapabilityIds: [oobCapability]
      })
    }
    const compilerOptions = {
      dependencyOverrides: {
        knownCapabilityIds: [
          READ_CAPABILITY,
          EXTRA_CAPABILITY,
          FORBIDDEN_CAPABILITY,
          oobCapability
        ]
      }
    }
    expect(
      createCompiler(controlled, compilerOptions).compile(
        createInput(endpoint, variant, template, target, {
          enabledCapabilityIds: [READ_CAPABILITY, oobCapability]
        })
      ).request.url
    ).toContain('controlled-callback')

    expectCompileCode(
      () =>
        createCompiler(controlled, compilerOptions).compile(
          createInput(endpoint, variant, template, target)
        ),
      'generator-rejected'
    )

    const undeclared: MutationGenerator = {
      ...controlled,
      metadata: MutationGeneratorMetadataSchema.parse({
        ...controlled.metadata,
        requiredCapabilityIds: []
      })
    }
    expectCompileCode(
      () =>
        createCompiler(undeclared, compilerOptions).compile(
          createInput(endpoint, variant, template, target, {
            enabledCapabilityIds: [READ_CAPABILITY, oobCapability]
          })
        ),
      'generator-rejected'
    )

    const arbitrary: MutationGenerator = {
      ...controlled,
      metadata: MutationGeneratorMetadataSchema.parse({
        ...controlled.metadata,
        safety: {
          ...controlled.metadata.safety,
          networkTarget: 'arbitrary'
        }
      })
    }
    expectCompileCode(
      () =>
        createCompiler(arbitrary, compilerOptions).compile(
          createInput(endpoint, variant, template, target, {
            enabledCapabilityIds: [READ_CAPABILITY, oobCapability]
          })
        ),
      'generator-rejected'
    )
  })

  it('rejects oversized resolver values in every supported location and oversized generator output', () => {
    const oversized = 'x'.repeat(262_145)
    const dynamicValue = {
      kind: 'dynamic' as const,
      slotId: 'oversized-value',
      resolver: {
        kind: 'dynamic-value-resolver' as const,
        resolverId: 'test.dynamic-resolver',
        version: '1.0.0'
      }
    }
    const queryEndpoint = createEndpoint()
    const queryVariant = createVariant({
      endpoint: queryEndpoint,
      selectors: [
        { kind: 'query', name: 'id', valueType: 'string', required: true }
      ]
    })
    const cases: Array<{
      endpoint: InventoryEndpointRecord
      variant: RequestVariantRecord
      template: ProbeRequestTemplate
      target: ProbeRequestCompilerInput['mutationTarget']
      selectorKind: MutationGenerator['metadata']['supportedSelectorKinds'][number]
      codec: MutationGenerator['metadata']['supportedBodyEncodings'][number]
    }> = [
      {
        endpoint: queryEndpoint,
        variant: queryVariant,
        template: {
          url: urlTemplate(queryEndpoint),
          query: [{ name: 'id', value: dynamicValue }],
          headers: [],
          cookies: [],
          body: { encoding: 'none' }
        },
        target: { kind: 'query', name: 'id', occurrence: 0, onMissing: 'reject' },
        selectorKind: 'query',
        codec: 'none'
      }
    ]

    const pathEndpoint = createEndpoint()
    cases.push({
      endpoint: pathEndpoint,
      variant: createVariant({
        endpoint: pathEndpoint,
        selectors: [
          { kind: 'path', name: 'id', valueType: 'string', required: true }
        ]
      }),
      template: {
        url: {
          ...urlTemplate(pathEndpoint),
          pathSegments: [
            { selectorName: 'id', value: dynamicValue }
          ]
        },
        query: [],
        headers: [],
        cookies: [],
        body: { encoding: 'none' }
      },
      target: { kind: 'path', selectorName: 'id', segmentIndex: 0 },
      selectorKind: 'path',
      codec: 'none'
    })

    const headerEndpoint = createEndpoint()
    cases.push({
      endpoint: headerEndpoint,
      variant: createVariant({
        endpoint: headerEndpoint,
        allowedHeaders: [
          { name: 'x-id', valueType: 'string', required: true }
        ],
        selectors: [
          { kind: 'header', name: 'x-id', valueType: 'string', required: true }
        ]
      }),
      template: {
        url: urlTemplate(headerEndpoint),
        query: [],
        headers: [{ name: 'x-id', value: dynamicValue }],
        cookies: [],
        body: { encoding: 'none' }
      },
      target: { kind: 'header', name: 'x-id' },
      selectorKind: 'header',
      codec: 'none'
    })

    const cookieEndpoint = createEndpoint()
    cases.push({
      endpoint: cookieEndpoint,
      variant: createVariant({
        endpoint: cookieEndpoint,
        selectors: [
          { kind: 'cookie', name: 'sid', valueType: 'string', required: true }
        ]
      }),
      template: {
        url: urlTemplate(cookieEndpoint),
        query: [],
        headers: [],
        cookies: [{ name: 'sid', value: dynamicValue }],
        body: { encoding: 'none' }
      },
      target: { kind: 'cookie', name: 'sid', occurrence: 0, onMissing: 'reject' },
      selectorKind: 'cookie',
      codec: 'none'
    })

    const formEndpoint = createEndpoint({ method: 'POST' })
    cases.push({
      endpoint: formEndpoint,
      variant: createVariant({
        endpoint: formEndpoint,
        codec: 'form',
        contentType: 'application/x-www-form-urlencoded',
        bodyShape: {
          rootType: 'object',
          fields: [{ path: '/id', valueType: 'string', required: true }]
        },
        selectors: [
          { kind: 'form', name: 'id', valueType: 'string', required: true }
        ]
      }),
      template: {
        url: urlTemplate(formEndpoint),
        query: [],
        headers: [],
        cookies: [],
        body: { encoding: 'form', entries: [{ name: 'id', value: dynamicValue }] }
      },
      target: { kind: 'form', name: 'id', occurrence: 0, onMissing: 'reject' },
      selectorKind: 'form',
      codec: 'form'
    })

    const jsonEndpoint = createEndpoint({ method: 'POST' })
    cases.push({
      endpoint: jsonEndpoint,
      variant: createVariant({
        endpoint: jsonEndpoint,
        codec: 'json',
        contentType: 'application/json',
        bodyShape: {
          rootType: 'object',
          fields: [{ path: '/id', valueType: 'string', required: true }]
        },
        selectors: [
          { kind: 'json-pointer', pointer: '/id', valueType: 'string', required: true }
        ]
      }),
      template: {
        url: urlTemplate(jsonEndpoint),
        query: [],
        headers: [],
        cookies: [],
        body: {
          encoding: 'json',
          value: {
            kind: 'object',
            entries: [{ key: 'id', value: dynamicValue }]
          }
        }
      },
      target: { kind: 'json-pointer', pointer: '/id' },
      selectorKind: 'json-pointer',
      codec: 'json'
    })

    for (const testCase of cases) {
      expectCompileCode(
        () =>
          createCompiler(
            generator([testCase.selectorKind], [testCase.codec], () => 'changed'),
            { dynamic: oversized }
          ).compile(
            createInput(
              testCase.endpoint,
              testCase.variant,
              testCase.template,
              testCase.target
            )
          ),
        'resolver-rejected'
      )
    }
    expectCompileCode(
      () =>
        createCompiler(
          generator(['query'], ['none'], () => oversized)
        ).compile(
          createInput(
            queryEndpoint,
            queryVariant,
            {
              url: urlTemplate(queryEndpoint),
              query: [
                {
                  name: 'id',
                  value: { kind: 'literal', sensitivity: 'public', value: 'base' }
                }
              ],
              headers: [],
              cookies: [],
              body: { encoding: 'none' }
            },
            { kind: 'query', name: 'id', occurrence: 0, onMissing: 'reject' }
          )
        ),
      'generator-rejected'
    )
  })

  it('compiles a deterministic baseline without invoking a mutation generator', () => {
    const endpoint = createEndpoint()
    const variant = createVariant({ endpoint, selectors: [] })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const generate = vi.fn(() => 'must-not-run')
    const mutationGenerator = generator(['query'], ['none'], generate)
    const compiler = createCompiler(mutationGenerator)
    const baseline = createBaselineInput(endpoint, variant, template)
    const first = compiler.compile(baseline)
    const repeat = compiler.compile(baseline)

    expect(generate).not.toHaveBeenCalled()
    expect(first.request.materialize()).toEqual({
      method: 'GET',
      url: endpoint.canonicalRoute,
      headers: []
    })
    expect(first.templateIntentHash).toEqual(repeat.templateIntentHash)
    expect(first.resolvedIntentHash).toEqual(repeat.resolvedIntentHash)
    expect(first.wireRequestHmac).toEqual(repeat.wireRequestHmac)

    expectCompileCode(
      () =>
        compiler.compile(
          createBaselineInput(endpoint, variant, template, {
            mutationTarget: {
              kind: 'query',
              name: 'id',
              occurrence: 0,
              onMissing: 'reject'
            }
          })
        ),
      'invalid-input'
    )
    expectCompileCode(
      () =>
        compiler.compile(
          createBaselineInput(endpoint, variant, template, {
            mutationGenerator: {
              generatorId: 'test.fixed-mutation',
              version: '1.0.0'
            }
          })
        ),
      'invalid-input'
    )
  })

  it('computes and verifies the exact ordered wire HMAC with provider-owned keys intact', () => {
    const endpoint = createEndpoint()
    const variant = createVariant({
      endpoint,
      selectors: [],
      allowedHeaders: [
        { name: 'x-a', valueType: 'string', required: true },
        { name: 'x-b', valueType: 'string', required: true }
      ]
    })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [
        {
          name: 'x-b',
          value: { kind: 'literal', sensitivity: 'public', value: 'two' }
        },
        {
          name: 'x-a',
          value: { kind: 'literal', sensitivity: 'public', value: 'one' }
        }
      ],
      cookies: [],
      body: { encoding: 'none' }
    }
    const providerOwnedKey = new Uint8Array(32).fill(0x6d)
    const compiler = createCompiler(
      generator(['query'], ['none'], () => 'unused'),
      { key: providerOwnedKey }
    )
    const baseline = createBaselineInput(endpoint, variant, template)
    const compiled = compiler.compile(baseline)
    const provider = { resolveKey: () => providerOwnedKey }
    const proofInput = {
      hashKey: baseline.hashKey,
      resolvedIntentHash: compiled.resolvedIntentHash,
      authorizationContext: compiled.authorizationContext,
      request: compiled.request.materialize()
    }

    expect(computeWireRequestHmac(proofInput, provider)).toEqual(
      compiled.wireRequestHmac
    )
    expect(
      verifyWireRequestHmac(proofInput, compiled.wireRequestHmac, provider)
    ).toBe(true)
    const authorizationContextTampering = [
      {
        ...compiled.authorizationContext,
        templateIntentHash: {
          ...compiled.templateIntentHash,
          digest: '0'.repeat(64)
        }
      },
      {
        ...compiled.authorizationContext,
        enabledCapabilityIds: [EXTRA_CAPABILITY, READ_CAPABILITY].sort()
      },
      {
        ...compiled.authorizationContext,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF
      },
      {
        ...compiled.authorizationContext,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF,
        identityRef: {
          id: IDENTITY_REF,
          version: 1,
          ownerRef: OWNER_REF,
          scopeSnapshotId: SCOPE_REF,
          statusSummary: 'active' as const
        }
      },
      {
        ...compiled.authorizationContext,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF,
        sessionRef: {
          id: SESSION_REF,
          generation: 1,
          ownerRef: OWNER_REF,
          scopeSnapshotId: SCOPE_REF,
          statusSummary: 'active' as const
        }
      },
      {
        ...compiled.authorizationContext,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF,
        testObjectRef: {
          id: TEST_OBJECT_REF,
          version: 1,
          ownerRef: OWNER_REF,
          scopeSnapshotId: SCOPE_REF,
          statusSummary: 'ready' as const
        }
      },
      {
        ...compiled.authorizationContext,
        executionBinding: {
          stepId: 'step.tampered',
          purpose: 'read' as const,
          adapterKind: 'http' as const
        }
      }
    ]
    for (const authorizationContext of authorizationContextTampering) {
      expect(
        verifyWireRequestHmac(
          {
            ...proofInput,
            authorizationContext
          },
          compiled.wireRequestHmac,
          provider
        )
      ).toBe(false)
    }
    expect(
      verifyWireRequestHmac(
        {
          ...proofInput,
          authorizationContext: {
            ...compiled.authorizationContext,
            unexpected: true
          } as never
        },
        compiled.wireRequestHmac,
        provider
      )
    ).toBe(false)
    expect(
      verifyWireRequestHmac(
        {
          ...proofInput,
          request: { ...proofInput.request, method: 'POST' }
        },
        compiled.wireRequestHmac,
        provider
      )
    ).toBe(false)
    expect(
      verifyWireRequestHmac(
        {
          ...proofInput,
          request: { ...proofInput.request, url: `${proofInput.request.url}?x=1` }
        },
        compiled.wireRequestHmac,
        provider
      )
    ).toBe(false)
    expect(
      verifyWireRequestHmac(
        {
          ...proofInput,
          request: {
            ...proofInput.request,
            headers: proofInput.request.headers.map((header, index) =>
              index === 0 ? { ...header, value: 'tampered' } : header
            )
          }
        },
        compiled.wireRequestHmac,
        provider
      )
    ).toBe(false)
    expect(
      verifyWireRequestHmac(
        {
          ...proofInput,
          request: {
            ...proofInput.request,
            headers: [...proofInput.request.headers].reverse()
          }
        },
        compiled.wireRequestHmac,
        provider
      )
    ).toBe(false)
    expect(
      verifyWireRequestHmac(
        {
          ...proofInput,
          request: { ...proofInput.request, bodyBytes: [] }
        },
        compiled.wireRequestHmac,
        provider
      )
    ).toBe(false)

    const bodyInput = {
      ...proofInput,
      request: { ...proofInput.request, bodyBytes: [0x61] }
    }
    const bodyProof = computeWireRequestHmac(bodyInput, provider)
    expect(
      verifyWireRequestHmac(
        {
          ...bodyInput,
          request: { ...bodyInput.request, bodyBytes: [0x62] }
        },
        bodyProof,
        provider
      )
    ).toBe(false)
    expect(
      verifyWireRequestHmac(
        proofInput,
        { ...compiled.wireRequestHmac, digest: 'malformed' } as never,
        provider
      )
    ).toBe(false)
    expect([...providerOwnedKey].every((value) => value === 0x6d)).toBe(true)
  })

  it('requires a ready or in-use TestObjectRef for every active-l2 compilation', () => {
    const endpoint = createEndpoint()
    const reviewed = createVariant({ endpoint, selectors: [] })
    const l2Variant: RequestVariantRecord = {
      ...reviewed,
      executionClass: 'active-l2'
    }
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const compiler = createCompiler(
      generator(['query'], ['none'], () => 'unused')
    )
    const valid = createBaselineInput(endpoint, l2Variant, template)
    const { testObjectRef: _testObjectRef, ...withoutTestObject } = valid

    expectCompileCode(
      () => compiler.compile(withoutTestObject),
      'opaque-ref-rejected'
    )
    for (const statusSummary of ['cleanup-required', 'retired'] as const) {
      expectCompileCode(
        () =>
          compiler.compile({
            ...valid,
            testObjectRef: {
              ...valid.testObjectRef!,
              statusSummary
            }
          }),
        'opaque-ref-rejected'
      )
    }
    for (const statusSummary of ['ready', 'in-use'] as const) {
      expect(() =>
        compiler.compile({
          ...valid,
          testObjectRef: {
            ...valid.testObjectRef!,
            statusSummary
          }
        })
      ).not.toThrow()
    }
  })

  it('rejects public literals in credential-shaped channels and accepts resolver-backed values', () => {
    const endpoint = createEndpoint()
    const compiler = createCompiler(
      generator(['query'], ['none'], () => 'unused'),
      { secret: 'Bearer resolver-owned' }
    )
    for (const name of [
      'authorization',
      'proxy-authorization',
      'x-api-key',
      'x-auth-token',
      'x-session-token'
    ]) {
      const variant = createVariant({
        endpoint,
        selectors: [],
        allowedHeaders: [
          { name, valueType: 'string', required: true }
        ]
      })
      const template: ProbeRequestTemplate = {
        url: urlTemplate(endpoint),
        query: [],
        headers: [
          {
            name,
            value: {
              kind: 'literal',
              sensitivity: 'public',
              value: 'caller-labelled-public'
            }
          }
        ],
        cookies: [],
        body: { encoding: 'none' }
      }
      expectCompileCode(
        () =>
          compiler.compile(
            createBaselineInput(endpoint, variant, template)
          ),
        'template-mismatch'
      )
    }

    const cookieVariant = createVariant({
      endpoint,
      selectors: [
        { kind: 'cookie', name: 'sid', valueType: 'string', required: true }
      ]
    })
    expectCompileCode(
      () =>
        compiler.compile(
          createBaselineInput(endpoint, cookieVariant, {
            url: urlTemplate(endpoint),
            query: [],
            headers: [],
            cookies: [
              {
                name: 'sid',
                value: {
                  kind: 'literal',
                  sensitivity: 'public',
                  value: 'caller-labelled-public'
                }
              }
            ],
            body: { encoding: 'none' }
          })
        ),
      'template-mismatch'
    )

    const authorizationVariant = createVariant({
      endpoint,
      selectors: [],
      allowedHeaders: [
        { name: 'authorization', valueType: 'string', required: true }
      ]
    })
    const resolved = compiler.compile(
      createBaselineInput(endpoint, authorizationVariant, {
        url: urlTemplate(endpoint),
        query: [],
        headers: [
          { name: 'authorization', value: secretValueSource() }
        ],
        cookies: [],
        body: { encoding: 'none' }
      })
    )
    expect(resolved.request.headers).toEqual([
      { name: 'authorization', value: 'Bearer resolver-owned' }
    ])
  })

  it('keeps authorized identity headers secret-ref-only, normalized, disjoint, and hash-bound', () => {
    const endpoint = createEndpoint()
    const variant = createVariant({ endpoint, selectors: [] })
    const template: ProbeRequestTemplate = {
      url: urlTemplate(endpoint),
      query: [],
      headers: [],
      cookies: [],
      body: { encoding: 'none' }
    }
    const compiler = createCompiler(
      generator(['query'], ['none'], () => 'unused')
    )
    const identityBinding = {
      ownerRef: OWNER_REF,
      scopeSnapshotId: SCOPE_REF,
      identityRef: {
        id: IDENTITY_REF,
        version: 1,
        ownerRef: OWNER_REF,
        scopeSnapshotId: SCOPE_REF,
        statusSummary: 'active' as const
      }
    }
    const identityInput = (
      authorizedIdentityHeaders: NonNullable<
        ProbeRequestCompilerInput['authorizedIdentityHeaders']
      >,
      requestVariant = variant,
      requestTemplate = template,
      credentialGeneration = 1
    ) =>
      createBaselineInput(endpoint, requestVariant, requestTemplate, {
        ...identityBinding,
        credentialRef: {
          id: SECRET_REF,
          kind: 'identity',
          generation: credentialGeneration
        },
        authorizedIdentityHeaders
      })

    const successful = compiler.compile(
      identityInput([
        { name: 'Authorization', value: secretValueSource(1) }
      ])
    )
    const changedGeneration = compiler.compile(
      identityInput([
        { name: 'authorization', value: secretValueSource(2) }
      ], variant, template, 2)
    )
    expect(successful.request.headers).toEqual([
      { name: 'authorization', value: SECRET_SENTINEL }
    ])
    expect(successful.templateIntentHash.digest).not.toBe(
      changedGeneration.templateIntentHash.digest
    )
    expect(JSON.stringify(successful)).not.toContain(SECRET_SENTINEL)
    expect(JSON.stringify(successful.templateIntentHash)).not.toContain(
      SECRET_SENTINEL
    )
    expect(JSON.stringify(successful.resolvedIntentHash)).not.toContain(
      SECRET_SENTINEL
    )

    expectCompileCode(
      () =>
        compiler.compile(
          createBaselineInput(endpoint, variant, template, {
            authorizedIdentityHeaders: [
              { name: 'authorization', value: secretValueSource() }
            ]
          })
        ),
      'opaque-ref-rejected'
    )

    const invalidIdentityValues: Array<
      NonNullable<
        ProbeRequestCompilerInput['authorizedIdentityHeaders']
      >[number]['value']
    > = [
      {
        kind: 'literal',
        sensitivity: 'public',
        value: 'caller-labelled-public'
      },
      {
        kind: 'dynamic',
        slotId: 'identity-header',
        resolver: {
          kind: 'dynamic-value-resolver',
          resolverId: 'test.dynamic-resolver',
          version: '1.0.0'
        }
      }
    ]
    for (const value of invalidIdentityValues) {
      expectCompileCode(
        () =>
          compiler.compile(
            identityInput([{ name: 'authorization', value }])
          ),
        'opaque-ref-rejected'
      )
    }

    expectCompileCode(
      () =>
        compiler.compile(
          identityInput([
            { name: 'Authorization', value: secretValueSource(1) },
            { name: 'authorization', value: secretValueSource(1) }
          ])
        ),
      'template-mismatch'
    )
    expectCompileCode(
      () =>
        compiler.compile(
          identityInput([
            { name: 'content-type', value: secretValueSource() }
          ])
        ),
      'template-mismatch'
    )

    const businessVariant = createVariant({
      endpoint,
      selectors: [],
      allowedHeaders: [
        { name: 'accept', valueType: 'string', required: true }
      ]
    })
    const businessTemplate: ProbeRequestTemplate = {
      ...template,
      headers: [
        {
          name: 'accept',
          value: { kind: 'literal', sensitivity: 'public', value: 'text/plain' }
        }
      ]
    }
    expectCompileCode(
      () =>
        compiler.compile(
          identityInput(
            [{ name: 'accept', value: secretValueSource() }],
            businessVariant,
            businessTemplate
          )
        ),
      'template-mismatch'
    )

    const cookieVariant = createVariant({
      endpoint,
      selectors: [
        { kind: 'cookie', name: 'sid', valueType: 'string', required: true }
      ]
    })
    const cookieTemplate: ProbeRequestTemplate = {
      ...template,
      cookies: [
        { name: 'sid', value: secretValueSource() }
      ]
    }
    expectCompileCode(
      () =>
        compiler.compile(
          identityInput(
            [{ name: 'cookie', value: secretValueSource(2) }],
            cookieVariant,
            cookieTemplate,
            2
          )
        ),
      'template-mismatch'
    )
  })
})
