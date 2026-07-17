import { describe, expect, it } from 'vitest'
import {
  BodyEncodingSchema,
  UpsertInventoryInputSchema as RootUpsertInventoryInputSchema
} from './index'
import {
  IdentityRefSchema,
  InventoryEndpointRecordSchema,
  InventorySourceRecordSchema,
  RequestVariantRecordSchema,
  RetireVariantInputSchema,
  ReviewVariantInputSchema,
  ScanModuleSnapshotDraftSchema,
  ScanModuleSnapshotRecordSchema,
  SelectorRefSchema,
  SessionGenerationRefSchema,
  SubjectRefSchema,
  TestObjectRefSchema,
  UpsertInventoryInputSchema
} from './inventory'

const hash = 'a'.repeat(64)
const now = '2026-07-17T08:00:00.000Z'
const evidenceId = '10000000-0000-4000-8000-000000000001'
const identityRefId = '10000000-0000-4000-8000-000000000002'
const sessionRefId = '10000000-0000-4000-8000-000000000003'
const testObjectRefId = '10000000-0000-4000-8000-000000000004'
const ownerRefId = '10000000-0000-4000-8000-000000000005'
const scopeSnapshotId = '10000000-0000-4000-8000-000000000006'

const bodyShape = {
  rootType: 'object' as const,
  fields: [
    { path: '/profile/name', valueType: 'string' as const, required: true }
  ]
}

const upsertInput = {
  scanId: 'scan-1',
  pageId: 'page-1',
  method: 'POST',
  url: 'https://example.test/api/profile?token=sentinel-secret',
  contentType: 'application/json',
  bodyShape,
  codec: 'json' as const,
  transport: 'standard-http' as const,
  allowedHeaders: [
    { name: 'content-type', valueType: 'string' as const, required: true }
  ],
  templateVersion: '1.0.0',
  requiredCapabilityIds: ['http.reviewed-read'],
  selectors: [
    { kind: 'json-pointer' as const, pointer: '/profile/name', valueType: 'string' as const, required: true }
  ],
  preview: {
    url: 'https://example.test/api/profile?token=sentinel-secret',
    headers: { authorization: 'Bearer sentinel-secret' },
    body: '{"profile":{"name":"example"}}'
  },
  source: {
    type: 'openapi.import',
    sourceHash: hash,
    pageId: 'page-1',
    evidenceRef: evidenceId,
    initiator: 'offline-import',
    confidence: 0.9
  }
}

describe('Day 3 inventory write contracts', () => {
  it('exports and parses a strict producer-owned upsert shape', () => {
    expect(RootUpsertInventoryInputSchema).toBe(UpsertInventoryInputSchema)
    expect(UpsertInventoryInputSchema.parse(upsertInput)).toEqual(upsertInput)
    expect(BodyEncodingSchema.parse('raw')).toBe('raw')
  })

  it('does not let a producer author review, execution, lifecycle, or secret fields', () => {
    for (const injected of [
      { reviewStatus: 'reviewed' },
      { executionClass: 'active-l1' },
      { lifecycleStatus: 'active' },
      { reviewedAt: now }
    ]) {
      expect(
        UpsertInventoryInputSchema.safeParse({ ...upsertInput, ...injected }).success
      ).toBe(false)
    }

    expect(
      UpsertInventoryInputSchema.safeParse({
        ...upsertInput,
        bodyShape: {
          ...bodyShape,
          fields: [{ ...bodyShape.fields[0], value: 'raw-secret' }]
        }
      }).success
    ).toBe(false)
    expect(
      UpsertInventoryInputSchema.safeParse({
        ...upsertInput,
        allowedHeaders: [
          { name: 'authorization', valueType: 'string', required: false, value: 'Bearer raw-secret' }
        ]
      }).success
    ).toBe(false)
    expect(
      UpsertInventoryInputSchema.safeParse({
        ...upsertInput,
        source: { ...upsertInput.source, reviewStatus: 'reviewed' }
      }).success
    ).toBe(false)
    expect(
      UpsertInventoryInputSchema.safeParse({
        ...upsertInput,
        source: {
          ...upsertInput.source,
          evidenceRef: 'DAY3_SENTINEL_SECRET_must-not-leak'
        }
      }).success
    ).toBe(false)
    expect(
      UpsertInventoryInputSchema.safeParse({
        ...upsertInput,
        codec: 'none',
        bodyShape
      }).success
    ).toBe(false)
  })

  it('keeps review and retirement commands minimal and strict', () => {
    expect(
      ReviewVariantInputSchema.parse({
        scanId: 'scan-1',
        requestVariantId: 'variant-1',
        reviewStatus: 'reviewed',
        reviewedBy: 'review-audit-1'
      })
    ).toMatchObject({ reviewStatus: 'reviewed' })
    expect(
      ReviewVariantInputSchema.safeParse({
        scanId: 'scan-1',
        requestVariantId: 'variant-1',
        reviewStatus: 'unreviewed',
        reviewedBy: 'review-audit-1'
      }).success
    ).toBe(false)
    expect(
      ReviewVariantInputSchema.safeParse({
        scanId: 'scan-1',
        requestVariantId: 'variant-1',
        reviewStatus: 'reviewed',
        reviewedBy: 'review-audit-1',
        executionClass: 'active-l1'
      }).success
    ).toBe(false)

    expect(
      RetireVariantInputSchema.parse({ scanId: 'scan-1', requestVariantId: 'variant-1' })
    ).toEqual({ scanId: 'scan-1', requestVariantId: 'variant-1' })
    expect(
      RetireVariantInputSchema.safeParse({
        scanId: 'scan-1',
        requestVariantId: 'variant-1',
        retiredAt: now
      }).success
    ).toBe(false)
  })
})

describe('structured selector and subject references', () => {
  it.each([
    { kind: 'query', name: 'q', valueType: 'string', required: false },
    { kind: 'path', name: 'id', valueType: 'integer', required: true },
    { kind: 'header', name: 'x-tenant', valueType: 'string', required: true },
    { kind: 'cookie', name: 'locale', valueType: 'string', required: false },
    { kind: 'form', name: 'title', valueType: 'string', required: true },
    { kind: 'json-pointer', pointer: '/user/id', valueType: 'string', required: true },
    { kind: 'multipart-part', partName: 'avatar', valueType: 'binary', required: false },
    { kind: 'xml-path', path: '/Envelope/Body/id', valueType: 'string', required: true },
    { kind: 'graphql-variable', variableName: 'userId', valueType: 'string', required: true },
    {
      kind: 'graphql-argument',
      fieldPath: ['query', 'user'],
      argumentName: 'id',
      valueType: 'string',
      required: true
    },
    { kind: 'websocket-field', messagePath: '/payload/id', valueType: 'string', required: true }
  ])('accepts selector kind $kind without a sample value', (selector) => {
    expect(SelectorRefSchema.safeParse(selector).success).toBe(true)
  })

  it('rejects selector addresses that do not match their discriminator', () => {
    expect(
      SelectorRefSchema.safeParse({
        kind: 'json-pointer',
        name: 'id',
        valueType: 'string',
        required: true
      }).success
    ).toBe(false)
    expect(
      SelectorRefSchema.parse({
        kind: 'header',
        name: 'X-Tenant',
        valueType: 'string',
        required: true
      })
    ).toMatchObject({ name: 'x-tenant' })
  })

  it.each([
    { kind: 'endpoint', endpointId: 'endpoint-1' },
    {
      kind: 'selector',
      requestVariantId: 'variant-1',
      selector: { kind: 'query', name: 'id', valueType: 'string', required: true }
    },
    { kind: 'page-dom', pageId: 'page-1', sinkRef: 'sink-1' },
    { kind: 'identity-pair', firstIdentityId: 'identity-1', secondIdentityId: 'identity-2' },
    { kind: 'authorization-matrix', matrixId: 'matrix-1', version: '1.0.0' },
    { kind: 'workflow-transition', workflowId: 'workflow-1', transitionId: 'approve' },
    { kind: 'protocol-channel', channelId: 'channel-1', protocol: 'websocket' },
    { kind: 'component', componentId: 'component-1', version: '1.2.3' }
  ])('accepts subject kind $kind', (subject) => {
    expect(SubjectRefSchema.safeParse(subject).success).toBe(true)
  })
})

describe('inventory records and independent state dimensions', () => {
  const variant = {
    id: 'variant-1',
    scanId: 'scan-1',
    endpointId: 'endpoint-1',
    contentType: 'application/json',
    bodyShape,
    codec: 'json' as const,
    transport: 'standard-http' as const,
    allowedHeaders: [
      { name: 'content-type', valueType: 'string' as const, required: true }
    ],
    templateVersion: '1.0.0',
    requiredCapabilityIds: ['http.reviewed-read'],
    selectors: upsertInput.selectors,
    redactedPreview: {
      url: 'https://example.test/api/profile?token=%5BREDACTED%5D',
      headers: { authorization: '[REDACTED]' },
      body: '{"profile":{"name":"example"}}'
    },
    reviewStatus: 'unreviewed' as const,
    executionClass: 'active-l2' as const,
    lifecycleStatus: 'active' as const,
    structureHash: hash,
    createdAt: now,
    updatedAt: now
  }

  it('does not infer deterministic execution class from human review status', () => {
    expect(RequestVariantRecordSchema.parse(variant)).toMatchObject({
      reviewStatus: 'unreviewed',
      executionClass: 'active-l2'
    })
  })

  it('enforces review and retirement audit invariants', () => {
    expect(
      RequestVariantRecordSchema.safeParse({ ...variant, reviewStatus: 'reviewed' }).success
    ).toBe(false)
    expect(
      RequestVariantRecordSchema.safeParse({ ...variant, lifecycleStatus: 'retired' }).success
    ).toBe(false)
    expect(
      RequestVariantRecordSchema.safeParse({ ...variant, retiredAt: now }).success
    ).toBe(false)
    expect(
      RequestVariantRecordSchema.safeParse({
        ...variant,
        redactedPreview: {
          ...variant.redactedPreview,
          url: 'https://example.test/api/profile?token=raw-secret'
        }
      }).success
    ).toBe(false)
  })

  it('parses scan-scoped endpoint and provenance records', () => {
    expect(
      InventoryEndpointRecordSchema.parse({
        id: 'endpoint-1',
        scanId: 'scan-1',
        pageId: 'page-1',
        method: 'POST',
        canonicalRoute: 'https://example.test/api/profile',
        lifecycleStatus: 'active',
        createdAt: now,
        updatedAt: now
      }).canonicalRoute
    ).toBe('https://example.test/api/profile')
    expect(
      InventoryEndpointRecordSchema.safeParse({
        id: 'endpoint-1',
        scanId: 'scan-1',
        method: 'POST',
        canonicalRoute: 'https://example.test/api/profile?token=secret',
        lifecycleStatus: 'active',
        createdAt: now,
        updatedAt: now
      }).success
    ).toBe(false)

    expect(
      InventorySourceRecordSchema.parse({
        id: 'source-1',
        scanId: 'scan-1',
        endpointId: 'endpoint-1',
        requestVariantId: 'variant-1',
        type: 'openapi.import',
        sourceHash: hash,
        provenanceHash: 'b'.repeat(64),
        pageId: 'page-1',
        confidencePpm: 900_000,
        discoveredAt: now,
        reviewStatus: 'unreviewed',
        createdAt: now
      }).confidencePpm
    ).toBe(900_000)
  })
})

describe('opaque references and immutable scan module snapshots', () => {
  const opaqueBase = {
    id: identityRefId,
    ownerRef: ownerRefId,
    scopeSnapshotId,
    statusSummary: 'active'
  }

  it('accepts only system-issued metadata and rejects credential-shaped values', () => {
    const identity = IdentityRefSchema.parse({ ...opaqueBase, version: 1 })
    const session = SessionGenerationRefSchema.parse({
      ...opaqueBase,
      id: sessionRefId,
      generation: 2
    })
    const testObject = TestObjectRefSchema.parse({
      ...opaqueBase,
      id: testObjectRefId,
      statusSummary: 'ready',
      version: 3
    })
    expect(Object.isFrozen(identity)).toBe(true)
    expect(Object.isFrozen(session)).toBe(true)
    expect(Object.isFrozen(testObject)).toBe(true)

    expect(
      IdentityRefSchema.safeParse({ ...opaqueBase, version: 1, token: 'sentinel-secret' })
        .success
    ).toBe(false)
    expect(
      SessionGenerationRefSchema.safeParse({
        ...opaqueBase,
        generation: 1,
        cookie: 'sentinel-secret'
      }).success
    ).toBe(false)
    expect(
      TestObjectRefSchema.safeParse({
        ...opaqueBase,
        id: testObjectRefId,
        statusSummary: 'ready',
        version: 1,
        rawObject: { id: 'real-object' }
      }).success
    ).toBe(false)

    for (const secret of [
      'DAY3_SENTINEL_SECRET_must-not-leak',
      'Bearer N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa',
      'N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa'
    ]) {
      expect(
        IdentityRefSchema.safeParse({ ...opaqueBase, id: secret, version: 1 }).success
      ).toBe(false)
      expect(
        IdentityRefSchema.safeParse({ ...opaqueBase, ownerRef: secret, version: 1 })
          .success
      ).toBe(false)
      expect(
        IdentityRefSchema.safeParse({
          ...opaqueBase,
          scopeSnapshotId: secret,
          version: 1
        }).success
      ).toBe(false)
    }

    expect(
      IdentityRefSchema.safeParse({
        ...opaqueBase,
        version: 1,
        statusSummary: 'ready'
      }).success
    ).toBe(false)
    expect(
      SessionGenerationRefSchema.safeParse({
        ...opaqueBase,
        id: sessionRefId,
        generation: 1,
        statusSummary: 'ready'
      }).success
    ).toBe(false)
    expect(
      TestObjectRefSchema.safeParse({
        ...opaqueBase,
        id: testObjectRefId,
        version: 1,
        statusSummary: 'active'
      }).success
    ).toBe(false)
  })

  const snapshotDraft = {
    familyId: 'sqli',
    moduleId: 'legacy.sqli.module',
    moduleVersion: '1.0.0',
    definitionHash: hash,
    techniqueId: 'legacy.sqli.query',
    techniqueVersion: '1.0.0',
    strategyRefs: [{ id: 'legacy.sqli.strategy', version: '1.0.0' }],
    confirmationRuleRefs: [{ id: 'legacy.sqli.rule', version: '1.0.0' }],
    evidenceProfileRefs: [{ id: 'legacy.sqli.evidence', version: '1.0.0' }],
    remediationRefs: [{ id: 'legacy.sqli.remediation', version: '1.0.0' }],
    requiredCapabilityIds: ['http.reviewed-read'],
    capabilityDescriptors: [
      {
        id: 'http.reviewed-read',
        riskFloor: 'l1' as const,
        descriptorHash: 'a'.repeat(64)
      }
    ],
    capabilitySnapshotHash: 'b'.repeat(64),
    selectedCapabilitiesHash: 'c'.repeat(64),
    selectedDefinitionsHash: 'd'.repeat(64),
    registrySnapshotHash: 'e'.repeat(64),
    environment: 'legacy-unknown' as const,
    authorization: 'legacy-v1-compatibility' as const
  }

  it('separates draft selection facts from persisted record identity', () => {
    const draft = ScanModuleSnapshotDraftSchema.parse(snapshotDraft)
    expect(draft.environment).toBe('legacy-unknown')
    expect(Object.isFrozen(draft)).toBe(true)

    const record = ScanModuleSnapshotRecordSchema.parse({
      id: 'snapshot-1',
      scanId: 'scan-1',
      ...snapshotDraft,
      snapshotHash: 'f'.repeat(64),
      createdAt: now
    })
    expect(record.selectedCapabilitiesHash).toBe('c'.repeat(64))
    expect(record.capabilitySnapshotHash).toBe('b'.repeat(64))
    expect(Object.isFrozen(record)).toBe(true)
  })

  it('does not accept authored snapshot IDs or missing selected-content hashes in a draft', () => {
    const { selectedDefinitionsHash: _omitted, ...missingHash } = snapshotDraft
    expect(ScanModuleSnapshotDraftSchema.safeParse(missingHash).success).toBe(false)
    expect(
      ScanModuleSnapshotDraftSchema.safeParse({ ...snapshotDraft, scanId: 'scan-1' }).success
    ).toBe(false)
  })
})
