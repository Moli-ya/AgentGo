import { describe, expect, it, vi } from 'vitest'
import {
  IdentitySchema,
  InventoryEndpointRecordSchema,
  RequestVariantRecordSchema,
  TargetScopeRecordSchema,
  type IdentityRecord,
  type InventoryEndpoint,
  type RequestVariantRecord
} from '@agentgo/contracts'
import {
  canonicalizeAllowedHeaderDescriptors,
  canonicalizeInventoryBodyShape,
  canonicalizeInventoryUrl,
  canonicalizeSelectorRefs,
  stableInventoryHash
} from '@agentgo/domain'
import type {
  CredentialMetadata,
  LegacyV1ExecutionBinding
} from '@agentgo/db'
import {
  LegacyV1RequestCompilerAdapter,
  type LegacyV1RequestCompilerAdapterDependencies,
  type LegacyV1RequestCompilerAdapterErrorCode
} from './legacy-v1-request-compiler-adapter'

const NOW = '2026-07-24T00:00:00.000Z'
const SCAN_ID = '10000000-0000-4000-8000-000000000001'
const TARGET_ID = '10000000-0000-4000-8000-000000000002'
const SCOPE_ID = '10000000-0000-4000-8000-000000000003'
const ENDPOINT_ID = '10000000-0000-4000-8000-000000000004'
const VARIANT_ID = '10000000-0000-4000-8000-000000000005'
const IDENTITY_ID = '10000000-0000-4000-8000-000000000006'
const CREDENTIAL_ID = '10000000-0000-4000-8000-000000000007'
const KEY_REF = '10000000-0000-4000-8000-000000000008'
const CAPABILITY_ID = 'http.reviewed-read'
const ROUTE = 'https://legacy.example.test/items'
const QUERY_SENTINEL = 'QUERY_VALUE_SENTINEL_4w9p'
const CREDENTIAL_SENTINEL = 'CREDENTIAL_SENTINEL_7k2m'

function createBinding(
  overrides: Partial<LegacyV1ExecutionBinding> = {}
): LegacyV1ExecutionBinding {
  const endpointRecord = InventoryEndpointRecordSchema.parse({
    id: ENDPOINT_ID,
    scanId: SCAN_ID,
    method: 'GET',
    canonicalRoute: ROUTE,
    lifecycleStatus: 'active',
    createdAt: NOW,
    updatedAt: NOW
  })
  const selectors = canonicalizeSelectorRefs([
    { kind: 'query', name: 'id', valueType: 'string', required: true }
  ])
  const allowedHeaders = canonicalizeAllowedHeaderDescriptors([
    { name: 'accept', valueType: 'string', required: true },
    { name: 'user-agent', valueType: 'string', required: true }
  ])
  const bodyShape = canonicalizeInventoryBodyShape({
    rootType: 'none',
    fields: []
  })
  const structuralValue = {
    contentType: null,
    bodyShape,
    codec: 'none' as const,
    transport: 'standard-http' as const,
    allowedHeaders,
    templateVersion: '1.0.0',
    requiredCapabilityIds: [CAPABILITY_ID],
    selectors
  }
  const requestVariant = RequestVariantRecordSchema.parse({
    id: VARIANT_ID,
    scanId: SCAN_ID,
    endpointId: ENDPOINT_ID,
    bodyShape,
    codec: 'none',
    transport: 'standard-http',
    allowedHeaders,
    templateVersion: '1.0.0',
    requiredCapabilityIds: [CAPABILITY_ID],
    selectors,
    redactedPreview: { url: `${ROUTE}?id=%5BREDACTED%5D` },
    reviewStatus: 'reviewed',
    reviewedBy: 'reviewer',
    reviewedAt: NOW,
    executionClass: 'active-l1',
    lifecycleStatus: 'active',
    structureHash: stableInventoryHash(structuralValue),
    createdAt: NOW,
    updatedAt: NOW
  })
  const endpoint: InventoryEndpoint = {
    id: ENDPOINT_ID,
    method: 'GET',
    url: `${ROUTE}?id=%5BREDACTED%5D`,
    source: 'target-base',
    parameters: [
      {
        id: 'parameter-id',
        name: 'id',
        location: 'query',
        dataType: 'string',
        required: true
      }
    ]
  }
  return {
    endpoint,
    endpointRecord,
    requestVariant,
    ...overrides
  }
}

function createPathBinding(): LegacyV1ExecutionBinding {
  const pathUrl = `${ROUTE}/1`
  const endpointRecord = InventoryEndpointRecordSchema.parse({
    id: ENDPOINT_ID,
    scanId: SCAN_ID,
    method: 'GET',
    canonicalRoute: canonicalizeInventoryUrl(pathUrl),
    lifecycleStatus: 'active',
    createdAt: NOW,
    updatedAt: NOW
  })
  const selectors = canonicalizeSelectorRefs([
    { kind: 'path', name: 'id', valueType: 'string', required: true }
  ])
  const allowedHeaders = canonicalizeAllowedHeaderDescriptors([
    { name: 'accept', valueType: 'string', required: true },
    { name: 'user-agent', valueType: 'string', required: true }
  ])
  const bodyShape = canonicalizeInventoryBodyShape({
    rootType: 'none',
    fields: []
  })
  const structuralValue = {
    contentType: null,
    bodyShape,
    codec: 'none' as const,
    transport: 'standard-http' as const,
    allowedHeaders,
    templateVersion: '1.0.0',
    requiredCapabilityIds: [CAPABILITY_ID],
    selectors
  }
  const requestVariant = RequestVariantRecordSchema.parse({
    id: VARIANT_ID,
    scanId: SCAN_ID,
    endpointId: ENDPOINT_ID,
    bodyShape,
    codec: 'none',
    transport: 'standard-http',
    allowedHeaders,
    templateVersion: '1.0.0',
    requiredCapabilityIds: [CAPABILITY_ID],
    selectors,
    redactedPreview: { url: pathUrl },
    reviewStatus: 'reviewed',
    reviewedBy: 'reviewer',
    reviewedAt: NOW,
    executionClass: 'active-l1',
    lifecycleStatus: 'active',
    structureHash: stableInventoryHash(structuralValue),
    createdAt: NOW,
    updatedAt: NOW
  })
  const endpoint: InventoryEndpoint = {
    id: ENDPOINT_ID,
    method: 'GET',
    url: pathUrl,
    source: 'target-base',
    parameters: [
      {
        id: '10000000-0000-4000-8000-000000000009',
        name: 'id',
        location: 'path',
        dataType: 'string',
        required: true
      }
    ]
  }
  return { endpoint, endpointRecord, requestVariant }
}

function createNoQueryBinding(): LegacyV1ExecutionBinding {
  const base = createBinding()
  const selectors = canonicalizeSelectorRefs([])
  const requestVariant = RequestVariantRecordSchema.parse({
    ...base.requestVariant,
    selectors,
    redactedPreview: { url: ROUTE },
    structureHash: stableInventoryHash({
      contentType: null,
      bodyShape: base.requestVariant.bodyShape,
      codec: base.requestVariant.codec,
      transport: base.requestVariant.transport,
      allowedHeaders: base.requestVariant.allowedHeaders,
      templateVersion: base.requestVariant.templateVersion,
      requiredCapabilityIds: base.requestVariant.requiredCapabilityIds,
      selectors
    })
  })
  return {
    endpoint: {
      ...base.endpoint,
      url: ROUTE,
      parameters: []
    },
    endpointRecord: base.endpointRecord,
    requestVariant
  }
}

function createScope(allowedIdentityIds: readonly string[] = [IDENTITY_ID]) {
  return TargetScopeRecordSchema.parse({
    id: SCOPE_ID,
    targetId: TARGET_ID,
    allowedOrigins: ['https://legacy.example.test'],
    allowedPathPrefixes: ['/'],
    deniedPathPrefixes: [],
    allowedPorts: [],
    allowedIdentityIds: [...allowedIdentityIds],
    allowActiveProbing: true,
    allowSensitiveProbing: false,
    allowPrivateNetworkTargets: false,
    allowLoopbackTargets: false,
    maxRequestsPerMinute: 30,
    maxConcurrency: 1,
    authorizationReference: 'test',
    revision: 1,
    snapshotHash: 'a'.repeat(64),
    createdAt: NOW
  })
}

function createIdentity(
  overrides: Partial<IdentityRecord> = {}
): IdentityRecord {
  return IdentitySchema.parse({
    id: IDENTITY_ID,
    targetId: TARGET_ID,
    label: 'test identity',
    role: 'owner',
    authType: 'bearer',
    credentialId: CREDENTIAL_ID,
    isTestIdentity: true,
    ownedResourceIds: [],
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides
  })
}

function createCredentialMetadata(
  overrides: Partial<CredentialMetadata> = {}
): CredentialMetadata {
  return {
    id: CREDENTIAL_ID,
    kind: 'identity',
    label: 'test identity credential',
    generation: 7,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides
  }
}

function createHarness(options: {
  binding?: LegacyV1ExecutionBinding | null
  credential?: string
  credentialAvailable?: boolean
  credentialMetadata?: CredentialMetadata | null
  credentialMetadataAfterGet?: CredentialMetadata | null
  identity?: IdentityRecord | null
  scanTargetId?: string
  scanIdentityIds?: readonly string[]
  scopeAllowedIdentityIds?: readonly string[]
  scopeTargetId?: string
} = {}) {
  const binding = options.binding === null
    ? undefined
    : options.binding ?? createBinding()
  const scanTargetId = options.scanTargetId ?? TARGET_ID
  const scope = {
    ...createScope(options.scopeAllowedIdentityIds),
    targetId: options.scopeTargetId ?? TARGET_ID
  }
  const identity = options.identity === null
    ? undefined
    : options.identity ?? createIdentity()
  const repository = {
    getIdentity: vi.fn(async () => identity),
    getLegacyV1ExecutionBinding: vi.fn(async () => binding),
    getScanRow: vi.fn(async () => ({
      id: SCAN_ID,
      targetId: scanTargetId,
      scopeSnapshotId: SCOPE_ID,
      configJson: {
        identityIds: [...(options.scanIdentityIds ?? [IDENTITY_ID])]
      }
    })),
    getScope: vi.fn(async () => scope)
  } as unknown as LegacyV1RequestCompilerAdapterDependencies['repository']
  const firstMetadata = options.credentialMetadata === null
    ? []
    : [options.credentialMetadata ?? createCredentialMetadata()]
  const laterMetadata = options.credentialMetadataAfterGet === null
    ? []
    : [options.credentialMetadataAfterGet ?? firstMetadata[0]!]
  const credentialStore = {
    isAvailable: vi.fn(() => options.credentialAvailable ?? true),
    list: vi.fn()
      .mockReturnValueOnce(firstMetadata)
      .mockReturnValue(laterMetadata),
    get: vi.fn(() => options.credential)
  } as unknown as LegacyV1RequestCompilerAdapterDependencies['credentialStore']
  const adapter = new LegacyV1RequestCompilerAdapter({
    repository,
    credentialStore,
    hashKey: { keyRef: KEY_REF, keyVersion: 1 },
    hashKeyProvider: {
      resolveKey: () => new Uint8Array(32).fill(0x52)
    }
  })
  return { adapter, repository, credentialStore }
}

async function expectAdapterCode(
  operation: Promise<unknown>,
  code: LegacyV1RequestCompilerAdapterErrorCode
): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code })
}

describe('LegacyV1RequestCompilerAdapter', () => {
  it('compiles exact baselines with reviewed headers and dynamic query commitments', async () => {
    const { adapter } = createHarness()
    const first = await adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=${QUERY_SENTINEL}`
    })
    const changed = await adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=changed-dynamic-value`
    })
    const executionBound = await adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=${QUERY_SENTINEL}`,
      executionBinding: {
        stepId: 'inventory.target-base.read',
        purpose: 'read',
        adapterKind: 'http'
      }
    })

    expect(first.endpoint.id).toBe(ENDPOINT_ID)
    expect(first.requestVariant.id).toBe(VARIANT_ID)
    expect(first.capabilityIds).toEqual([CAPABILITY_ID])
    expect(first.ownerRef).toBe(TARGET_ID)
    expect(first.identityRef).toBeUndefined()
    expect(first.credentialRef).toBeNull()
    expect(first.compiledRequest.authorizationContext).toMatchObject({
      ownerRef: TARGET_ID,
      scopeSnapshotId: SCOPE_ID,
      identityRef: null,
      credentialRef: null,
      executionBinding: null
    })
    expect(executionBound.compiledRequest.authorizationContext.executionBinding)
      .toEqual({
        stepId: 'inventory.target-base.read',
        purpose: 'read',
        adapterKind: 'http'
      })
    expect(executionBound.compiledRequest.wireRequestHmac.digest).not.toBe(
      first.compiledRequest.wireRequestHmac.digest
    )
    expect(first.requestBytes).toBeGreaterThan(0)
    expect(first.compiledRequest.request.materialize()).toEqual({
      method: 'GET',
      url: `${ROUTE}?id=${QUERY_SENTINEL}`,
      headers: [
        {
          name: 'accept',
          value: 'text/html,application/json;q=0.9,*/*;q=0.8'
        },
        {
          name: 'user-agent',
          value: 'AgentGo/0.1 Authorized Security Validation'
        }
      ]
    })
    expect(first.compiledRequest.templateIntentHash).toEqual(
      changed.compiledRequest.templateIntentHash
    )
    expect(first.compiledRequest.resolvedIntentHash.digest).not.toBe(
      changed.compiledRequest.resolvedIntentHash.digest
    )
    expect(JSON.stringify(first)).not.toContain(QUERY_SENTINEL)
  })

  it('supports zero-selector baselines and enforces the exact reviewed query-name multiset', async () => {
    const noQueryHarness = createHarness({ binding: createNoQueryBinding() })
    const noQuery = await noQueryHarness.adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: ROUTE
    })
    expect(noQuery.compiledRequest.request.materialize()).toEqual({
      method: 'GET',
      url: ROUTE,
      headers: [
        {
          name: 'accept',
          value: 'text/html,application/json;q=0.9,*/*;q=0.8'
        },
        {
          name: 'user-agent',
          value: 'AgentGo/0.1 Authorized Security Validation'
        }
      ]
    })

    const { adapter } = createHarness()
    for (const desiredTargetUrl of [
      ROUTE,
      `${ROUTE}?id=one&id=two`,
      `${ROUTE}?other=value`
    ]) {
      await expectAdapterCode(
        adapter.compile({
          scanId: SCAN_ID,
          endpointId: ENDPOINT_ID,
          desiredTargetUrl
        }),
        'raw-target-mismatch'
      )
    }
    for (const desiredTargetUrl of [
      `https://other.example.test/items?id=value`,
      `https://legacy.example.test/other?id=value`
    ]) {
      await expectAdapterCode(
        adapter.compile({
          scanId: SCAN_ID,
          endpointId: ENDPOINT_ID,
          desiredTargetUrl
        }),
        'compile-rejected'
      )
    }
  })

  it('derives SSRF generator safety and IDOR capability proof from familyId', async () => {
    const genericMutation = await createHarness().adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=controlled-oob-value`,
      familyId: 'sqli',
      queryMutation: {
        name: 'id',
        occurrence: 0,
        value: 'controlled-oob-value'
      }
    })
    const ssrfMutation = await createHarness().adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=controlled-oob-value`,
      familyId: 'ssrf',
      queryMutation: {
        name: 'id',
        occurrence: 0,
        value: 'controlled-oob-value'
      }
    })
    expect(ssrfMutation.capabilityIds).toEqual([
      CAPABILITY_ID,
      'oob.controlled-observe'
    ])
    expect(ssrfMutation.compiledRequest.templateIntentHash.digest).not.toBe(
      genericMutation.compiledRequest.templateIntentHash.digest
    )

    const genericBaseline = await createHarness().adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=value`
    })
    const idorBaseline = await createHarness().adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=value`,
      familyId: 'idor'
    })
    expect(idorBaseline.capabilityIds).toEqual([
      'http.identity-read-compare',
      CAPABILITY_ID
    ])
    expect(idorBaseline.compiledRequest.templateIntentHash.digest).not.toBe(
      genericBaseline.compiledRequest.templateIntentHash.digest
    )
    await expectAdapterCode(
      createHarness().adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=controlled-oob-value`,
        payloadSummary: 'ssrf',
        queryMutation: {
          name: 'id',
          occurrence: 0,
          value: 'controlled-oob-value'
        }
      } as never),
      'invalid-input'
    )
  })

  it('uses the fixed query generator and rejects non-query, fragment, or non-exact targets', async () => {
    const { adapter } = createHarness()
    const desiredTargetUrl = `${ROUTE}?id=QUERY_MUTATION_SENTINEL`
    const compiled = await adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl,
      queryMutation: {
        name: 'id',
        occurrence: 0,
        value: 'QUERY_MUTATION_SENTINEL'
      }
    })
    expect(compiled.compiledRequest.request.url).toBe(desiredTargetUrl)

    await expectAdapterCode(
      adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl,
        queryMutation: {
          kind: 'header',
          name: 'id',
          occurrence: 0,
          value: 'QUERY_MUTATION_SENTINEL'
        } as never
      }),
      'invalid-input'
    )
    await expectAdapterCode(
      adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${desiredTargetUrl}#fragment`
      }),
      'invalid-input'
    )
    await expectAdapterCode(
      adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=%51UERY_MUTATION_SENTINEL`
      }),
      'raw-target-mismatch'
    )
    await expectAdapterCode(
      adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=other-value`,
        queryMutation: {
          name: 'id',
          occurrence: 0,
          value: 'different-value'
        }
      }),
      'raw-target-mismatch'
    )
  })

  it('prefetches typed, stable credentials without serializing secrets', async () => {
    const cases: Array<{
      identity: IdentityRecord
      headerName: string
      headerValue: string
    }> = [
      {
        identity: createIdentity({ authType: 'bearer' }),
        headerName: 'authorization',
        headerValue: `Bearer ${CREDENTIAL_SENTINEL}`
      },
      {
        identity: createIdentity({ authType: 'cookie' }),
        headerName: 'cookie',
        headerValue: CREDENTIAL_SENTINEL
      },
      {
        identity: createIdentity({ authType: 'basic' }),
        headerName: 'authorization',
        headerValue: `Basic ${Buffer.from(CREDENTIAL_SENTINEL).toString('base64')}`
      },
      {
        identity: createIdentity({
          authType: 'header',
          headerName: 'x-legacy-token'
        }),
        headerName: 'x-legacy-token',
        headerValue: CREDENTIAL_SENTINEL
      }
    ]

    for (const testCase of cases) {
      const { adapter, repository, credentialStore } = createHarness({
        credential: CREDENTIAL_SENTINEL,
        identity: testCase.identity
      })
      const output = await adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      })
      expect(repository.getIdentity).toHaveBeenCalledWith(IDENTITY_ID)
      expect(credentialStore.isAvailable).toHaveBeenCalledTimes(2)
      expect(credentialStore.list).toHaveBeenCalledTimes(2)
      expect(credentialStore.get).toHaveBeenCalledWith(CREDENTIAL_ID)
      expect(output.ownerRef).toBe(TARGET_ID)
      expect(output.identityRef).toMatchObject({
        id: IDENTITY_ID,
        version: Date.parse(NOW),
        ownerRef: TARGET_ID,
        scopeSnapshotId: SCOPE_ID,
        statusSummary: 'active'
      })
      expect(output.credentialRef).toEqual({
        id: CREDENTIAL_ID,
        kind: 'identity',
        generation: 7
      })
      expect(output.compiledRequest.authorizationContext.credentialRef).toEqual({
        id: CREDENTIAL_ID,
        kind: 'identity',
        generation: 7
      })
      expect(output.compiledRequest.request.headers).toContainEqual({
        name: testCase.headerName,
        value: testCase.headerValue
      })
      expect(JSON.stringify(output)).not.toContain(CREDENTIAL_SENTINEL)
      expect(JSON.stringify(output.compiledRequest.templateIntentHash)).not.toContain(
        CREDENTIAL_SENTINEL
      )
      expect(JSON.stringify(output.compiledRequest.resolvedIntentHash)).not.toContain(
        CREDENTIAL_SENTINEL
      )
    }
  })

  it('binds credential-free and omit-mode identities without reading secrets', async () => {
    const noCredentialIdentity = createIdentity({
      authType: 'none',
      credentialId: undefined
    })
    const noCredentialHarness = createHarness({ identity: noCredentialIdentity })
    const withoutCredential = await noCredentialHarness.adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=value`,
      identityId: IDENTITY_ID
    })
    expect(withoutCredential.identityRef?.id).toBe(IDENTITY_ID)
    expect(withoutCredential.credentialRef).toBeNull()
    expect(withoutCredential.ownerRef).toBe(TARGET_ID)
    expect(noCredentialHarness.credentialStore.list).not.toHaveBeenCalled()
    expect(noCredentialHarness.credentialStore.get).not.toHaveBeenCalled()

    const omitHarness = createHarness({ identity: createIdentity() })
    const omitted = await omitHarness.adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}?id=value`,
      identityId: IDENTITY_ID,
      credentialMode: 'omit'
    })
    expect(omitted.ownerRef).toBe(TARGET_ID)
    expect(omitted.credentialRef).toBeNull()
    expect(omitted.identityRef).toEqual(withoutCredential.identityRef)
    expect(omitted.compiledRequest.request.headers).toHaveLength(2)
    expect(omitHarness.repository.getIdentity).toHaveBeenCalledWith(IDENTITY_ID)
    expect(omitHarness.credentialStore.isAvailable).not.toHaveBeenCalled()
    expect(omitHarness.credentialStore.list).not.toHaveBeenCalled()
    expect(omitHarness.credentialStore.get).not.toHaveBeenCalled()
  })

  it('rejects unavailable, mistyped, missing, or rotated identity credentials', async () => {
    const compileIdentity = (options: Parameters<typeof createHarness>[0]) =>
      createHarness(options).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      })

    await expectAdapterCode(
      compileIdentity({ credentialAvailable: false }),
      'credential-unavailable'
    )
    await expectAdapterCode(
      compileIdentity({
        credential: CREDENTIAL_SENTINEL,
        credentialMetadata: null
      }),
      'credential-unavailable'
    )
    await expectAdapterCode(
      compileIdentity({
        credential: CREDENTIAL_SENTINEL,
        credentialMetadata: createCredentialMetadata({
          kind: 'model-api-key'
        })
      }),
      'credential-unavailable'
    )
    await expectAdapterCode(
      compileIdentity({
        credential: CREDENTIAL_SENTINEL,
        credentialMetadataAfterGet: createCredentialMetadata({
          generation: 8
        })
      }),
      'credential-unavailable'
    )
  })

  it('fails closed for missing bindings, scope, DB identities, and stale inputs', async () => {
    await expectAdapterCode(
      createHarness({ binding: null }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`
      }),
      'binding-not-found'
    )
    await expectAdapterCode(
      createHarness().adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      }),
      'credential-unavailable'
    )
    await expectAdapterCode(
      createHarness({ identity: null }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      }),
      'identity-rejected'
    )
    await expectAdapterCode(
      createHarness({ scanTargetId: 'different-target' }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`
      }),
      'binding-rejected'
    )
    await expectAdapterCode(
      createHarness({ scanIdentityIds: [] }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      }),
      'identity-rejected'
    )
    await expectAdapterCode(
      createHarness({ scopeAllowedIdentityIds: [] }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      }),
      'identity-rejected'
    )
    await expectAdapterCode(
      createHarness({ scopeTargetId: 'different-target' }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`
      }),
      'binding-rejected'
    )
    await expectAdapterCode(
      createHarness({
        identity: createIdentity({ isTestIdentity: false })
      }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      }),
      'identity-rejected'
    )
    await expectAdapterCode(
      createHarness({
        identity: createIdentity({ targetId: SCAN_ID })
      }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identityId: IDENTITY_ID
      }),
      'identity-rejected'
    )
    await expectAdapterCode(
      createHarness().adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        identity: createIdentity()
      } as never),
      'invalid-input'
    )
    await expectAdapterCode(
      createHarness().adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`,
        credentialMode: 'forward'
      } as never),
      'invalid-input'
    )

    const mismatchedBinding = createBinding({
      requestVariant: {
        ...createBinding().requestVariant,
        scanId: 'different-scan'
      } as RequestVariantRecord
    })
    await expectAdapterCode(
      createHarness({ binding: mismatchedBinding }).adapter.compile({
        scanId: SCAN_ID,
        endpointId: ENDPOINT_ID,
        desiredTargetUrl: `${ROUTE}?id=value`
      }),
      'binding-rejected'
    )
  })

  it('compiles a reviewed path selector through the same RequestCompiler', async () => {
    const { adapter } = createHarness({ binding: createPathBinding() })
    const compiled = await adapter.compile({
      scanId: SCAN_ID,
      endpointId: ENDPOINT_ID,
      desiredTargetUrl: `${ROUTE}/1%20AND%201%3D1`,
      pathMutation: {
        selectorName: 'id',
        segmentIndex: 1,
        value: '1 AND 1=1'
      }
    })
    expect(compiled.compiledRequest.request.materialize().url).toBe(
      `${ROUTE}/1%20AND%201%3D1`
    )
  })
})
