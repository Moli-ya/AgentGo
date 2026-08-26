import { describe, expect, it } from 'vitest'
import {
  IdentityRefSchema,
  SessionGenerationRefSchema,
  TestObjectRefSchema
} from '@agentgo/contracts'
import {
  INVENTORY_REDACTION_MARKER,
  MAX_REDACTED_INVENTORY_URL_LENGTH,
  canonicalizeAllowedHeaderDescriptors,
  canonicalizeInventoryBodyShape,
  canonicalizeInventoryUrl,
  canonicalizeSelectorRef,
  canonicalizeSelectorRefs,
  isHighEntropySecret,
  redactInventoryPreview,
  redactInventoryText,
  redactInventoryUrlPreview,
  stableInventoryHash
} from './inventory'

const sentinel = 'INVENTORY_SENTINEL_SECRET_must-not-leak'
const jwt =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYXkzLXVzZXIifQ.QWx3YXlzUmVkYWN0VGhpc1NpZ25hdHVyZQ'
const highEntropy = 'N7vQ2mL9xR4pT8kW3sF6cH1jB5zD0yUa'

describe('inventory URL canonicalization', () => {
  it('uses only normalized origin and path for endpoint identity', () => {
    expect(
      canonicalizeInventoryUrl(
        `HTTPS://user:${sentinel}@Example.COM:443/a/../api/items?token=${sentinel}&q=visible#section`
      )
    ).toBe('https://example.com/api/items')
  })

  it('does not let query names or values change the canonical route', () => {
    const first = canonicalizeInventoryUrl('https://example.test/search?a=one')
    const second = canonicalizeInventoryUrl('https://example.test/search?b=two&a=three')
    expect(first).toBe(second)
    expect(first).toBe('https://example.test/search')
  })

  it('redacts plain and percent-encoded secret-shaped path segments', () => {
    const plain = canonicalizeInventoryUrl(
      `https://example.test/download/${highEntropy}/receipt`
    )
    const encoded = canonicalizeInventoryUrl(
      `https://example.test/callback/${encodeURIComponent(jwt)}`
    )
    expect(plain).toBe('https://example.test/download/:redacted/receipt')
    expect(encoded).toBe('https://example.test/callback/:redacted')
    expect(plain).not.toContain(highEntropy)
    expect(encoded).not.toContain(jwt)
  })

  it('replaces secret-shaped hostname labels with stable non-secret hashes', () => {
    const normalizedToken = highEntropy.toLowerCase()
    const expectedLabel = 'redacted-54b6f7862c7c18c9'
    const route = canonicalizeInventoryUrl(
      `https://${highEntropy}.callbacks.example.test/result?token=hidden`
    )
    const preview = redactInventoryUrlPreview(
      `https://${highEntropy}.callbacks.example.test/result?token=hidden`
    )

    expect(route).toBe(`https://${expectedLabel}.callbacks.example.test/result`)
    expect(preview).toBe(
      `https://${expectedLabel}.callbacks.example.test/result?token=%5BREDACTED%5D`
    )
    expect(route).not.toContain(normalizedToken)
    expect(preview).not.toContain(normalizedToken)
    expect(
      canonicalizeInventoryUrl(
        'https://m8k3p9v2q7x4r6t1n5c0b2d8f7h9j3l6.callbacks.example.test/result'
      )
    ).not.toBe(route)
  })

  it('keeps query structure only in a deterministically redacted preview', () => {
    const preview = redactInventoryUrlPreview(
      `https://user:${sentinel}@EXAMPLE.test:443/search?token=${sentinel}&q=${highEntropy}#fragment`
    )
    expect(preview).toBe(
      'https://example.test/search?q=%5BREDACTED%5D&token=%5BREDACTED%5D'
    )
    expect(preview).not.toContain(sentinel)
    expect(preview).not.toContain(highEntropy)
    expect(preview).not.toContain('user')
    expect(preview).not.toContain('fragment')
  })

  it('truncates query entries structurally when redaction expands the URL budget', () => {
    const input = `https://example.test/search?${Array.from(
      { length: 1_000 },
      () => 'a='
    ).join('&')}`
    const preview = redactInventoryUrlPreview(input)
    const redactedEntryCount = preview.split('%5BREDACTED%5D').length - 1

    expect(preview.length).toBeLessThanOrEqual(MAX_REDACTED_INVENTORY_URL_LENGTH)
    expect(redactedEntryCount).toBeGreaterThan(0)
    expect(redactedEntryCount).toBeLessThan(1_000)
    expect(preview).not.toMatch(/(?:^|[?&])a=(?!%5BREDACTED%5D)/u)
    expect(redactInventoryUrlPreview(input)).toBe(preview)
  })

  it('bounds canonical routes after Unicode percent-encoding expansion', () => {
    const input = `https://example.test/${String.fromCodePoint(0x1f600).repeat(4_000)}`
    const route = canonicalizeInventoryUrl(input)

    expect(route.length).toBeLessThanOrEqual(MAX_REDACTED_INVENTORY_URL_LENGTH)
    expect(route).toMatch(
      /^https:\/\/example\.test\/_redacted-path-[a-f0-9]{16}$/u
    )
    expect(canonicalizeInventoryUrl(input)).toBe(route)
  })

  it('also redacts secret-shaped path segments in URL previews', () => {
    const preview = redactInventoryUrlPreview(
      `https://user:${sentinel}@example.test/reset/${highEntropy}?token=${sentinel}`
    )
    expect(preview).toBe(
      'https://example.test/reset/:redacted?token=%5BREDACTED%5D'
    )
    expect(preview).not.toContain(sentinel)
    expect(preview).not.toContain(highEntropy)
  })

  it('fails closed on relative and non-Web URLs', () => {
    expect(() => canonicalizeInventoryUrl('/relative')).toThrow(/absolute URL/)
    expect(() => canonicalizeInventoryUrl('file:///tmp/capture.har')).toThrow(
      /Unsupported inventory URL protocol/
    )
  })
})

describe('inventory secret detection and preview redaction', () => {
  it('detects sentinel, Bearer, JWT, prefixed, and random high-entropy values', () => {
    expect(isHighEntropySecret(sentinel)).toBe(true)
    expect(isHighEntropySecret(`Bearer ${highEntropy}`)).toBe(true)
    expect(isHighEntropySecret(jwt)).toBe(true)
    expect(isHighEntropySecret('sk-live_51N7vQ2mL9xR4pT')).toBe(true)
    expect(isHighEntropySecret(highEntropy)).toBe(true)
    expect(isHighEntropySecret('ordinary readable preview text')).toBe(false)
    expect(isHighEntropySecret('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(false)
  })

  it('redacts credentials and token-shaped fragments in plain text', () => {
    const value = redactInventoryText(
      `authorization=Bearer ${highEntropy}&password=${sentinel}&jwt=${jwt}`
    )
    expect(value).toContain(INVENTORY_REDACTION_MARKER)
    expect(value).not.toContain(highEntropy)
    expect(value).not.toContain(sentinel)
    expect(value).not.toContain(jwt)
  })

  it('redacts URL, sensitive headers, cookies, body fields, JWTs, and high-entropy values', () => {
    const input = {
      url: `https://alice:${sentinel}@example.test/items?query=${sentinel}&next=${highEntropy}#private`,
      headers: {
        Authorization: `Bearer ${highEntropy}`,
        Cookie: `sid=${sentinel}`,
        'X-Trace': highEntropy,
        Accept: 'application/json'
      },
      body: JSON.stringify({
        visible: 'kept',
        password: sentinel,
        nested: { csrfToken: highEntropy, jwt },
        values: [highEntropy, 'safe']
      })
    }
    const untouched = JSON.parse(JSON.stringify(input)) as typeof input
    const redacted = redactInventoryPreview(input)

    expect(input).toEqual(untouched)
    expect(redacted.url).not.toContain(sentinel)
    expect(redacted.url).not.toContain(highEntropy)
    expect(redacted.url).not.toContain('alice')
    expect(redacted.headers).toEqual({
      accept: 'application/json',
      authorization: INVENTORY_REDACTION_MARKER,
      cookie: INVENTORY_REDACTION_MARKER,
      'x-trace': INVENTORY_REDACTION_MARKER
    })
    expect(redacted.body).toContain('"visible":"kept"')
    expect(redacted.body).not.toContain(sentinel)
    expect(redacted.body).not.toContain(highEntropy)
    expect(redacted.body).not.toContain(jwt)
  })

  it('redacts sentinel and credential assignments in non-JSON bodies', () => {
    const redacted = redactInventoryPreview({
      url: `https://example.test/form?csrf=${sentinel}`,
      body: `name=safe&csrf=${sentinel}&password=${highEntropy}`
    })
    expect(redacted.body).toContain('name=safe')
    expect(redacted.body).not.toContain(sentinel)
    expect(redacted.body).not.toContain(highEntropy)
  })
})

describe('stable inventory hashes', () => {
  it('is stable across object insertion order and sensitive to structure', () => {
    const first = stableInventoryHash({
      transport: 'standard-http',
      selector: { kind: 'query', name: 'id' }
    })
    const second = stableInventoryHash({
      selector: { name: 'id', kind: 'query' },
      transport: 'standard-http'
    })
    const changed = stableInventoryHash({
      selector: { name: 'other', kind: 'query' },
      transport: 'standard-http'
    })
    expect(first).toMatch(/^[a-f0-9]{64}$/)
    expect(first).toBe(second)
    expect(changed).not.toBe(first)
  })

  it('lets opaque identity/session/test-object metadata participate without secret material', () => {
    const refs = {
      identity: IdentityRefSchema.parse({
        id: '10000000-0000-4000-8000-000000000001',
        version: 1,
        ownerRef: '10000000-0000-4000-8000-000000000004',
        scopeSnapshotId: '10000000-0000-4000-8000-000000000005',
        statusSummary: 'active'
      }),
      session: SessionGenerationRefSchema.parse({
        id: '10000000-0000-4000-8000-000000000002',
        generation: 2,
        ownerRef: '10000000-0000-4000-8000-000000000004',
        scopeSnapshotId: '10000000-0000-4000-8000-000000000005',
        statusSummary: 'active'
      }),
      testObject: TestObjectRefSchema.parse({
        id: '10000000-0000-4000-8000-000000000003',
        version: 3,
        ownerRef: '10000000-0000-4000-8000-000000000004',
        scopeSnapshotId: '10000000-0000-4000-8000-000000000005',
        statusSummary: 'ready'
      })
    }
    expect(stableInventoryHash(refs)).toBe(
      stableInventoryHash({
        testObject: refs.testObject,
        identity: refs.identity,
        session: refs.session
      })
    )
    expect(JSON.stringify(refs)).not.toMatch(/cookie|token|csrf|password/iu)
    expect(
      stableInventoryHash({
        ...refs,
        session: { ...refs.session, generation: refs.session.generation + 1 }
      })
    ).not.toBe(stableInventoryHash(refs))
  })
})

describe('value-free structure canonicalization', () => {
  it('normalizes header names, order, and secret-shaped structural names', () => {
    expect(
      canonicalizeAllowedHeaderDescriptors([
        { name: ' X-Tenant ', valueType: 'string', required: true },
        { name: highEntropy, valueType: 'unknown', required: false }
      ])
    ).toEqual([
      { name: 'x-redacted', valueType: 'unknown', required: false },
      { name: 'x-tenant', valueType: 'string', required: true }
    ])
  })

  it('canonicalizes selector header casing and redacts secret-shaped addresses', () => {
    expect(
      canonicalizeSelectorRef({
        kind: 'header',
        name: ' X-Tenant ',
        valueType: 'string',
        required: true
      })
    ).toMatchObject({ name: 'x-tenant' })
    expect(
      canonicalizeSelectorRef({
        kind: 'query',
        name: highEntropy,
        valueType: 'string',
        required: false
      })
    ).toMatchObject({ name: ':redacted' })
  })

  it('orders selectors/body fields and rejects conflicts introduced by redaction', () => {
    expect(
      canonicalizeSelectorRefs([
        { kind: 'query', name: 'z', valueType: 'string', required: false },
        { kind: 'header', name: 'X-A', valueType: 'string', required: true }
      ]).map((selector) => selector.kind)
    ).toEqual(['header', 'query'])
    expect(
      canonicalizeInventoryBodyShape({
        rootType: 'object',
        fields: [
          { path: '/z', valueType: 'string', required: false },
          { path: `/users/${highEntropy}`, valueType: 'object', required: true }
        ]
      }).fields.map((field) => field.path)
    ).toEqual(['/users/:redacted', '/z'])
    expect(() =>
      canonicalizeAllowedHeaderDescriptors([
        { name: 'X-Tenant', valueType: 'string', required: true },
        { name: 'x-tenant', valueType: 'integer', required: true }
      ])
    ).toThrow(/Conflicting allowed-header descriptors/)
  })
})
