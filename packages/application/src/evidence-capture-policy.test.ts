import { describe, expect, it, vi } from 'vitest'
import {
  EVIDENCE_SOURCE_HASH_DOMAIN,
  EvidenceArtifactDraftSchema,
  EvidenceCaptureDecisionSchema,
  EvidenceCaptureResultSchema,
  EvidenceSourceHashSchema,
  OOB_TOKEN_COMMITMENT_DOMAIN,
  PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
  PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
  PROTECTED_EVIDENCE_PROTECTION_SCHEME,
  PROTECTED_EVIDENCE_POLICY_VERSION,
  type EvidenceCaptureContext,
  type EvidenceCaptureDecision
} from '@agentgo/contracts'
import {
  EvidenceCapturePolicy,
  EvidenceCapturePolicyError,
  type OobCommitmentKeyProvider
} from './evidence-capture-policy'

const IDS = Object.freeze({
  scan: '10000000-0000-4000-8000-000000000001',
  policy: '10000000-0000-4000-8000-000000000002',
  capture: '10000000-0000-4000-8000-000000000003',
  key: '10000000-0000-4000-8000-000000000004'
})
const SENTINEL = 'DAY4-SENTINEL-SECRET-MUST-NOT-LEAK'
const FIXTURE_OOB_KEY = Buffer.alloc(32, 0x42)
const PROTECTED_PLAN = Object.freeze({
  protectionScheme: PROTECTED_EVIDENCE_PROTECTION_SCHEME,
  accessPolicyId: PROTECTED_EVIDENCE_ACCESS_POLICY_ID,
  accessPolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
  derivativePolicyId: PROTECTED_EVIDENCE_DERIVATIVE_POLICY_ID,
  derivativePolicyVersion: PROTECTED_EVIDENCE_POLICY_VERSION,
  retentionSeconds: 3_600,
  maxScanPlaintextBytes: 8_192,
  maxWorkspacePlaintextBytes: 16_384
})

function byteContext(
  overrides: Partial<EvidenceCaptureContext> = {}
): EvidenceCaptureContext {
  return {
    scanId: IDS.scan,
    policyDecisionId: IDS.policy,
    techniqueId: 'sqli.boolean',
    techniqueVersion: '1.0.0',
    stepId: 'baseline',
    executionState: 'succeeded',
    source: 'http-response-body',
    role: 'response-body',
    occurredAt: '2026-07-19T01:00:00.000Z',
    response: {
      mediaType: 'text/plain',
      charset: 'utf-8',
      contentEncoding: 'identity'
    },
    ...overrides
  } as EvidenceCaptureContext
}

function decision(
  context: EvidenceCaptureContext,
  overrides: Partial<EvidenceCaptureDecision> = {}
): EvidenceCaptureDecision {
  const action = overrides.action ?? 'persist-minimized'
  return {
    id: IDS.capture,
    scanId: context.scanId,
    policyDecisionId: context.policyDecisionId,
    capturePolicyId: 'default-minimized-evidence',
    capturePolicyVersion: '1.0.0',
    techniqueId: context.techniqueId,
    techniqueVersion: context.techniqueVersion,
    stepId: context.stepId,
    executionState: context.executionState,
    source: context.source,
    role: context.role,
    action,
    validFrom: '2026-07-19T00:59:00.000Z',
    validUntil: '2026-07-19T01:01:00.000Z',
    maxSourceBytes: 4_096,
    maxExcerptBytes: 128,
    jsonPointers: [],
    oobMetadataFields: [],
    ...(action === 'protected-original'
      ? { protectedOriginalPlan: PROTECTED_PLAN }
      : {}),
    ...(context.source === 'oob-event' &&
    (action === 'persist-minimized' || action === 'hash-only')
      ? {
          oobCommitmentKeyRef: IDS.key,
          oobCommitmentKeyVersion: 7
        }
      : {}),
    ...overrides
  }
}

function bytes(value: string): Uint8Array {
  return Buffer.from(value, 'utf8')
}

describe('EvidenceCapturePolicy', () => {
  it('hashes unstructured text without persisting heuristic excerpts or doing network I/O', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const context = byteContext()
    const captureDecision = decision(context, { maxExcerptBytes: 64 })
    const input = {
      kind: 'bytes' as const,
      context,
      decision: captureDecision,
      content: bytes(
        `password is hunter2; prefix token=${SENTINEL} 中文内容 `.repeat(12)
      ),
      completeness: 'complete' as const
    }
    const policy = new EvidenceCapturePolicy()

    const first = policy.capture(input)
    const second = policy.capture(input)

    expect(second).toEqual(first)
    expect(first.state).toBe('hash-only')
    expect(first.reason).toBe('unstructured-text-source')
    expect(first.sourceHash).toMatchObject({
      domain: EVIDENCE_SOURCE_HASH_DOMAIN,
      basis: 'source-bytes',
      coverage: 'complete',
      hashedBytes: input.content.byteLength
    })
    expect(first.artifacts).toHaveLength(1)
    expect(first).toMatchObject({
      capturePolicyId: 'default-minimized-evidence',
      capturePolicyVersion: '1.0.0'
    })
    expect(first.artifacts[0]).toMatchObject({
      capturePolicyId: 'default-minimized-evidence',
      capturePolicyVersion: '1.0.0'
    })
    expect(first.artifacts[0]?.payload).toMatchObject({
      kind: 'hash-only',
      reason: 'unstructured-text-source'
    })
    expect(JSON.stringify(first)).not.toContain(SENTINEL)
    expect(JSON.stringify(first)).not.toContain('hunter2')
    expect(Object.isFrozen(first)).toBe(true)
    expect(Object.isFrozen(first.artifacts)).toBe(true)
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  it('persists only explicit JSON pointers and redacts sensitive or structured selections', () => {
    const context = byteContext({
      response: {
        mediaType: 'application/json',
        charset: 'utf-8',
        contentEncoding: 'identity'
      }
    })
    const captureDecision = decision(context, {
      maxExcerptBytes: 512,
      jsonPointers: ['/profile', '/public', '/safe', '/password']
    })
    const raw = JSON.stringify({
      safe: 'visible',
      public: SENTINEL,
      password: SENTINEL,
      ignored: SENTINEL,
      profile: { email: 'person@example.test', token: SENTINEL }
    })

    const captured = new EvidenceCapturePolicy().capture({
      kind: 'bytes',
      context,
      decision: captureDecision,
      content: bytes(raw),
      completeness: 'complete'
    })

    expect(captured.state).toBe('captured')
    expect(captured.reason).toBe('allowlisted-json-selection')
    const artifact = captured.artifacts[0]
    if (artifact?.type !== 'evidence-capture-json-selection') {
      throw new Error('Expected a structured JSON-selection artifact.')
    }
    expect(JSON.stringify(artifact.payload)).not.toContain(SENTINEL)
    expect(JSON.stringify(artifact.payload)).not.toContain('ignored')
    const payload = artifact.payload
    expect(payload.selections.map(({ pointer }) => pointer)).toEqual([
      '/password',
      '/profile',
      '/public',
      '/safe'
    ])
    expect(payload.selections[0]?.value).toBe('[REDACTED]')
    expect(payload.selections[1]?.value).toBe('[REDACTED]')
    expect(String(payload.selections[2]?.value)).toContain('[REDACTED]')
    expect(payload.selections[3]?.value).toBe('[REDACTED]')
  })

  it('redacts a deeply nested selected JSON value without recursive hashing', () => {
    const context = byteContext({
      response: {
        mediaType: 'application/json',
        charset: 'utf-8',
        contentEncoding: 'identity'
      }
    })
    const raw = `{"deep":${'['.repeat(1_000)}"${SENTINEL}"${']'.repeat(1_000)}}`
    const captured = new EvidenceCapturePolicy().capture({
      kind: 'bytes',
      context,
      decision: decision(context, { jsonPointers: ['/deep'] }),
      content: bytes(raw),
      completeness: 'complete'
    })

    expect(captured.state).toBe('captured')
    const artifact = captured.artifacts[0]
    if (artifact?.type !== 'evidence-capture-json-selection') {
      throw new Error('Expected a structured JSON-selection artifact.')
    }
    expect(JSON.stringify(artifact.payload)).toContain('[REDACTED]')
    expect(JSON.stringify(artifact.payload)).not.toContain(SENTINEL)
  })

  it.each([
    {
      label: 'partial content',
      context: byteContext(),
      content: bytes('partial'),
      completeness: 'prefix' as const,
      knownTotalBytes: 100,
      decision: {},
      reason: 'partial-source'
    },
    {
      label: 'oversize content',
      context: byteContext(),
      content: bytes('x'.repeat(65)),
      completeness: 'complete' as const,
      decision: { maxSourceBytes: 64, maxExcerptBytes: 32 },
      reason: 'oversize-source'
    },
    {
      label: 'compressed content',
      context: byteContext({
        response: {
          mediaType: 'text/plain',
          charset: 'utf-8',
          contentEncoding: 'compressed'
        }
      }),
      content: bytes(SENTINEL),
      completeness: 'complete' as const,
      decision: {},
      reason: 'compressed-source'
    },
    {
      label: 'XML content',
      context: byteContext({
        response: {
          mediaType: 'application/xml',
          charset: 'utf-8',
          contentEncoding: 'identity'
        }
      }),
      content: bytes(`<secret>${SENTINEL}</secret>`),
      completeness: 'complete' as const,
      decision: {},
      reason: 'xml-source'
    },
    {
      label: 'binary screenshot',
      context: byteContext({
        source: 'browser-screenshot',
        role: 'screenshot',
        response: {
          mediaType: 'image/png',
          charset: 'not-applicable',
          contentEncoding: 'identity'
        }
      }),
      content: Uint8Array.from([0x89, 0x50, 0x4e, 0x47]),
      completeness: 'complete' as const,
      decision: {},
      reason: 'binary-source'
    },
    {
      label: 'non UTF-8 content',
      context: byteContext(),
      content: Uint8Array.from([0xc3, 0x28]),
      completeness: 'complete' as const,
      decision: {},
      reason: 'non-utf8-source'
    },
    {
      label: 'invalid JSON',
      context: byteContext({
        response: {
          mediaType: 'application/json',
          charset: 'utf-8',
          contentEncoding: 'identity'
        }
      }),
      content: bytes(`{"secret":"${SENTINEL}"`),
      completeness: 'complete' as const,
      decision: { jsonPointers: ['/secret'] },
      reason: 'json-parse-failed'
    }
  ])('falls back to an explicit hash-only artifact for $label', (fixture) => {
    const captureDecision = decision(fixture.context, fixture.decision)
    const captured = new EvidenceCapturePolicy().capture({
      kind: 'bytes',
      context: fixture.context,
      decision: captureDecision,
      content: fixture.content,
      completeness: fixture.completeness,
      ...(fixture.knownTotalBytes !== undefined
        ? { knownTotalBytes: fixture.knownTotalBytes }
        : {})
    })

    expect(captured.state).toBe('hash-only')
    expect(captured.reason).toBe(fixture.reason)
    expect(captured.artifacts).toHaveLength(1)
    expect(captured.artifacts[0]?.type).toBe('evidence-capture-hash-only')
    expect(JSON.stringify(captured)).not.toContain(SENTINEL)
    if (fixture.completeness === 'prefix') {
      expect(captured.sourceHash).toMatchObject({
        coverage: 'partial',
        hashedBytes: fixture.content.byteLength,
        knownTotalBytes: fixture.knownTotalBytes
      })
    }
  })

  it('does not label a known full byte count as partial coverage', () => {
    const context = byteContext()
    const sourceHash = {
      domain: EVIDENCE_SOURCE_HASH_DOMAIN,
      algorithm: 'sha256',
      digest: '0'.repeat(64),
      basis: 'source-bytes',
      coverage: 'partial',
      hashedBytes: 7,
      knownTotalBytes: 7
    }
    expect(EvidenceSourceHashSchema.safeParse(sourceHash).success).toBe(false)
    expect(() =>
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: decision(context),
        content: bytes('partial'),
        completeness: 'prefix',
        knownTotalBytes: 7
      })
    ).toThrow('Evidence capture source input is invalid.')
  })

  it('uses intrinsic byte length and rejects an oversized Uint8Array subclass', () => {
    class UnderstatedBytes extends Uint8Array {
      override get byteLength(): number {
        return 1
      }
    }
    const context = byteContext()
    const content = new UnderstatedBytes(16_777_217)

    expect(() =>
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: decision(context),
        content,
        completeness: 'complete'
      })
    ).toThrow('Evidence capture source input is invalid.')
  })

  it.each(['http-response-body', 'dom-snapshot', 'browser-screenshot'] as const)(
    'authorizes a metadata-only protected-original persistence plan for %s',
    (source) => {
      const context = byteContext({
        source,
        role: source === 'browser-screenshot' ? 'screenshot' : 'response-body',
        response:
          source === 'browser-screenshot'
            ? {
                mediaType: 'image/png',
                charset: 'not-applicable',
                contentEncoding: 'identity'
              }
            : {
                mediaType: 'text/html',
                charset: 'utf-8',
                contentEncoding: 'identity'
              }
      })
      const content =
        source === 'browser-screenshot'
          ? Uint8Array.from([
              0x89,
              0x50,
              0x4e,
              0x47,
              ...bytes(SENTINEL)
            ])
          : bytes(SENTINEL)
      const captured = new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: decision(context, { action: 'protected-original' }),
        content,
        completeness: 'complete'
      })

      expect(captured).toMatchObject({
        state: 'captured',
        reason: 'protected-original-authorized'
      })
      const artifact = captured.artifacts[0]
      expect(artifact).toMatchObject({
        type: 'evidence-capture-protected-original',
        source,
        redactionState: 'original',
        scanId: IDS.scan,
        policyDecisionId: IDS.policy,
        payload: {
          kind: 'protected-original-persistence-plan',
          plaintextSize: content.byteLength,
          protectionPlan: PROTECTED_PLAN
        }
      })
      expect(artifact?.sourceHash.digest).toBe(captured.sourceHash.digest)
      expect(JSON.stringify(captured)).not.toContain(SENTINEL)
      expect(Buffer.from(content).includes(Buffer.from(SENTINEL))).toBe(true)
    }
  )

  it.each([
    {
      completeness: 'prefix' as const,
      content: bytes('partial'),
      knownTotalBytes: 100,
      overrides: {},
      reason: 'partial-source'
    },
    {
      completeness: 'complete' as const,
      content: bytes('x'.repeat(65)),
      overrides: {
        maxSourceBytes: 64,
        maxExcerptBytes: 32,
        protectedOriginalPlan: {
          ...PROTECTED_PLAN,
          maxScanPlaintextBytes: 64,
          maxWorkspacePlaintextBytes: 64
        }
      },
      reason: 'oversize-source'
    },
    {
      completeness: 'complete' as const,
      content: new Uint8Array(),
      overrides: {},
      reason: 'empty-source'
    }
  ])(
    'downgrades an incomplete or oversized protected original to $reason',
    (fixture) => {
      const context = byteContext()
      const captured = new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: decision(context, {
          action: 'protected-original',
          ...fixture.overrides
        }),
        content: fixture.content,
        completeness: fixture.completeness,
        ...(fixture.knownTotalBytes === undefined
          ? {}
          : { knownTotalBytes: fixture.knownTotalBytes })
      })

      expect(captured).toMatchObject({
        state: 'hash-only',
        reason: fixture.reason
      })
      expect(captured.artifacts[0]?.type).toBe(
        'evidence-capture-hash-only'
      )
    }
  )

  it('rejects protected-original decisions for OOB tokens', () => {
    const context: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'ssrf.oob',
      techniqueVersion: '1.0.0',
      stepId: 'callback',
      executionState: 'succeeded',
      source: 'oob-event',
      role: 'oob-callback',
      occurredAt: '2026-07-19T01:00:00.000Z'
    }

    expect(
      EvidenceCaptureDecisionSchema.safeParse(
        decision(context, { action: 'protected-original' })
      ).success
    ).toBe(false)
  })

  it('keeps OOB tokens out of artifacts and computes a decision-bound HMAC itself', () => {
    const resolveKey = vi.fn(() => FIXTURE_OOB_KEY)
    const keyProvider: OobCommitmentKeyProvider = { resolveKey }
    const context: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'ssrf.oob',
      techniqueVersion: '1.0.0',
      stepId: 'callback',
      executionState: 'succeeded',
      source: 'oob-event',
      role: 'oob-callback',
      occurredAt: '2026-07-19T01:00:00.000Z'
    }
    const captureDecision = decision(context, {
      oobMetadataFields: ['channel', 'eventType', 'statusCode']
    })

    const policy = new EvidenceCapturePolicy(keyProvider)
    const captureInput = {
      kind: 'oob',
      context,
      decision: captureDecision,
      token: SENTINEL,
      metadata: {
        channel: 'http',
        eventType: 'http-request',
        receivedAt: '2026-07-19T01:00:00.000Z',
        statusCode: 204
      }
    } as const
    const captured = policy.capture(captureInput)
    const repeated = policy.capture(captureInput)
    const differentToken = policy.capture({
      ...captureInput,
      token: `${SENTINEL}-different`
    })

    expect(captured.state).toBe('captured')
    expect(captured.sourceHash).toMatchObject({
      basis: 'selected-oob-metadata',
      coverage: 'partial'
    })
    expect(captured.tokenCommitment).toMatchObject({
      domain: OOB_TOKEN_COMMITMENT_DOMAIN,
      algorithm: 'hmac-sha256',
      keyRef: IDS.key,
      keyVersion: 7,
      captureDecisionId: IDS.capture,
      capturePolicyId: 'default-minimized-evidence',
      capturePolicyVersion: '1.0.0',
      selectedMetadata: {
        channel: 'http',
        eventType: 'http-request',
        statusCode: 204
      },
      sourceHash: captured.sourceHash
    })
    expect(repeated.tokenCommitment?.digest).toBe(
      captured.tokenCommitment?.digest
    )
    expect(differentToken.tokenCommitment?.digest).not.toBe(
      captured.tokenCommitment?.digest
    )
    expect(resolveKey).toHaveBeenCalledTimes(3)
    expect(resolveKey).toHaveBeenLastCalledWith({
      keyRef: IDS.key,
      keyVersion: 7
    })
    expect([...FIXTURE_OOB_KEY]).toEqual([...Buffer.alloc(32, 0x42)])
    expect(JSON.stringify(captured)).not.toContain(SENTINEL)
    const artifact = captured.artifacts[0]
    if (artifact?.type !== 'evidence-capture-oob-metadata') {
      throw new Error('Expected a structured OOB metadata artifact.')
    }
    expect(artifact.payload.metadata).not.toHaveProperty('receivedAt')
    expect(artifact.payload.metadata.eventType).toBe('http-request')

    const splicedArtifact = {
      ...artifact,
      payload: {
        ...artifact.payload,
        metadata: { ...artifact.payload.metadata, channel: 'dns' }
      }
    }
    expect(EvidenceArtifactDraftSchema.safeParse(splicedArtifact).success).toBe(
      false
    )
    expect(
      EvidenceCaptureResultSchema.safeParse({
        ...captured,
        artifacts: [splicedArtifact]
      }).success
    ).toBe(false)
  })

  it('returns unsupported when OOB commitment capability is absent', () => {
    const context: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'ssrf.oob',
      techniqueVersion: '1.0.0',
      stepId: 'callback',
      executionState: 'succeeded',
      source: 'oob-event',
      role: 'oob-callback',
      occurredAt: '2026-07-19T01:00:00.000Z'
    }
    const captured = new EvidenceCapturePolicy().capture({
      kind: 'oob',
      context,
      decision: decision(context),
      token: SENTINEL,
      metadata: { channel: 'dns' }
    })

    expect(captured).toMatchObject({
      state: 'unsupported',
      reason: 'oob-commitment-unavailable',
      artifacts: []
    })
    expect(JSON.stringify(captured)).not.toContain(SENTINEL)
  })

  it('does not require or invoke an OOB commitment key for discard', () => {
      const context: EvidenceCaptureContext = {
        scanId: IDS.scan,
        policyDecisionId: IDS.policy,
        techniqueId: 'ssrf.oob',
        techniqueVersion: '1.0.0',
        stepId: 'callback',
        executionState: 'succeeded',
        source: 'oob-event',
        role: 'oob-callback',
        occurredAt: '2026-07-19T01:00:00.000Z'
      }
      const resolveKey = vi.fn(() => FIXTURE_OOB_KEY)
      const captured = new EvidenceCapturePolicy({ resolveKey }).capture({
        kind: 'oob',
        context,
        decision: decision(context, { action: 'discard' }),
        token: SENTINEL,
        metadata: { channel: 'http' }
      })

      expect(captured).toMatchObject({
        state: 'discarded',
        reason: 'decision-discard',
        artifacts: []
      })
      expect(resolveKey).not.toHaveBeenCalled()
      expect(JSON.stringify(captured)).not.toContain(SENTINEL)
    })

  it('rejects strict contract or binding errors without reflecting untrusted values', () => {
    const context = byteContext()
    const validDecision = decision(context)
    expect(
      EvidenceCaptureDecisionSchema.safeParse({
        ...validDecision,
        unexpected: SENTINEL
      }).success
    ).toBe(false)

    let error: unknown
    try {
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: { ...validDecision, role: 'different-role' },
        content: bytes(SENTINEL),
        completeness: 'complete'
      })
    } catch (caught) {
      error = caught
    }
    expect(error).toBeInstanceOf(EvidenceCapturePolicyError)
    expect(String(error)).not.toContain(SENTINEL)
    expect(error).toMatchObject({ code: 'decision-context-mismatch' })
  })

  it('accepts schema-valid sealed definition IDs without treating them as secrets', () => {
    const context: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'sqli.boolean-differential',
      techniqueVersion: '1.0.0',
      stepId: 'inventory.target-base.read',
      executionState: 'succeeded',
      source: 'http-request-summary',
      role: 'request-summary',
      occurredAt: '2026-07-19T01:00:00.000Z',
      content: {
        mediaType: 'application/json',
        charset: 'utf-8',
        contentEncoding: 'identity',
        declaredSizeBytes: 2
      }
    }

    const captured = new EvidenceCapturePolicy().capture({
      kind: 'bytes',
      context,
      decision: decision(context, {
        capturePolicyId: 'evidence-summary-v1',
        action: 'hash-only'
      }),
      content: bytes('{}'),
      completeness: 'complete',
      knownTotalBytes: 2
    })

    expect(captured).toMatchObject({
      state: 'hash-only',
      reason: 'decision-hash-only',
      source: 'http-request-summary',
      role: 'request-summary'
    })
  })

  it('rejects complete protected capture when declared source size exceeds supplied bytes', () => {
    const content = bytes('truncated')
    const context = byteContext({
      response: {
        mediaType: 'application/octet-stream',
        charset: 'not-applicable',
        contentEncoding: 'compressed',
        declaredSizeBytes: content.byteLength + 10
      }
    })

    expect(() =>
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: decision(context, {
          action: 'protected-original',
          maxSourceBytes: 32,
          maxExcerptBytes: 32
        }),
        content,
        completeness: 'complete'
      })
    ).toThrowError(
      expect.objectContaining({ code: 'invalid-source-input' })
    )
  })

  it('still rejects secret-bearing JSON pointer selections', () => {
    const context = byteContext()
    let error: unknown
    try {
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: decision(context, {
          jsonPointers: ['/token=abcdefghijklmnopqrstuvwx']
        }),
        content: bytes('{}'),
        completeness: 'complete'
      })
    } catch (caught) {
      error = caught
    }

    expect(error).toMatchObject({ code: 'invalid-decision' })
  })

  it('rejects unknown discriminants, extra fields, and accessors at the capture boundary', () => {
    const context = byteContext()
    const captureDecision = decision(context)
    const base = {
      context,
      decision: captureDecision,
      content: bytes('safe'),
      completeness: 'complete'
    } as const

    for (const input of [
      { ...base, kind: 'bogus' },
      { ...base, kind: 'bytes', unexpected: SENTINEL }
    ]) {
      let error: unknown
      try {
        new EvidenceCapturePolicy().capture(input as never)
      } catch (caught) {
        error = caught
      }
      expect(error).toMatchObject({ code: 'invalid-source-input' })
      expect(String(error)).not.toContain(SENTINEL)
    }

    const accessorInput = { ...base } as Record<string, unknown>
    Object.defineProperty(accessorInput, 'kind', {
      enumerable: true,
      get: () => {
        throw new Error(SENTINEL)
      }
    })
    let accessorError: unknown
    try {
      new EvidenceCapturePolicy().capture(accessorInput as never)
    } catch (caught) {
      accessorError = caught
    }
    expect(accessorError).toMatchObject({ code: 'invalid-source-input' })
    expect(String(accessorError)).not.toContain(SENTINEL)

    const proxyTarget = {
      ...base,
      kind: 'bytes' as const
    }
    const descriptorReads = new Map<PropertyKey, number>()
    const switchingProxy = new Proxy(proxyTarget, {
      getOwnPropertyDescriptor: (target, key) => {
        const count = (descriptorReads.get(key) ?? 0) + 1
        descriptorReads.set(key, count)
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key)
        if (!descriptor || count === 1) return descriptor
        if (key === 'kind') return { ...descriptor, value: 'bogus' }
        if (key === 'content') return { ...descriptor, value: SENTINEL }
        if (key === 'context') return { ...descriptor, value: null }
        return descriptor
      }
    })
    const proxyResult = new EvidenceCapturePolicy().capture(
      switchingProxy as never
    )
    expect(proxyResult.state).toBe('hash-only')
    expect(descriptorReads.get('kind')).toBe(1)
    expect(descriptorReads.get('content')).toBe(1)
    expect(descriptorReads.get('context')).toBe(1)
  })

  it('bounds nested decisions and metadata before reading sparse or accessor values', () => {
    const context = byteContext()
    const hugePointers: unknown[] = []
    let pointerGetterReads = 0
    Object.defineProperty(hugePointers, '0', {
      enumerable: true,
      configurable: true,
      get: () => {
        pointerGetterReads += 1
        return `/${SENTINEL}`
      }
    })
    hugePointers.length = 200_000

    let decisionError: unknown
    try {
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: {
          ...decision(context),
          jsonPointers: hugePointers
        } as never,
        content: bytes('safe'),
        completeness: 'complete'
      })
    } catch (caught) {
      decisionError = caught
    }
    expect(decisionError).toMatchObject({ code: 'invalid-decision' })
    expect(pointerGetterReads).toBe(0)

    const sparsePointers: unknown[] = []
    let sparseGetterReads = 0
    Object.defineProperty(sparsePointers, '0', {
      enumerable: true,
      configurable: true,
      get: () => {
        sparseGetterReads += 1
        return '/safe'
      }
    })
    sparsePointers.length = 8
    expect(() =>
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: {
          ...decision(context),
          jsonPointers: sparsePointers
        } as never,
        content: bytes('safe'),
        completeness: 'complete'
      })
    ).toThrow('Evidence capture decision is invalid.')
    expect(sparseGetterReads).toBe(0)

    const accessorResponse: Record<string, unknown> = {
      charset: 'utf-8',
      contentEncoding: 'identity'
    }
    let responseGetterReads = 0
    Object.defineProperty(accessorResponse, 'mediaType', {
      enumerable: true,
      get: () => {
        responseGetterReads += 1
        throw new Error(SENTINEL)
      }
    })
    expect(() =>
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context: { ...context, response: accessorResponse } as never,
        decision: decision(context),
        content: bytes('safe'),
        completeness: 'complete'
      })
    ).toThrow('Evidence capture context is invalid.')
    expect(responseGetterReads).toBe(0)

    const oobContext: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'ssrf.oob',
      techniqueVersion: '1.0.0',
      stepId: 'callback',
      executionState: 'succeeded',
      source: 'oob-event',
      role: 'oob-callback',
      occurredAt: '2026-07-19T01:00:00.000Z'
    }
    const accessorMetadata: Record<string, unknown> = {}
    let metadataGetterReads = 0
    Object.defineProperty(accessorMetadata, 'channel', {
      enumerable: true,
      get: () => {
        metadataGetterReads += 1
        throw new Error(SENTINEL)
      }
    })
    expect(() =>
      new EvidenceCapturePolicy().capture({
        kind: 'oob',
        context: oobContext,
        decision: decision(oobContext, { action: 'discard' }),
        token: SENTINEL,
        metadata: accessorMetadata as never
      })
    ).toThrow('Evidence capture source input is invalid.')
    expect(metadataGetterReads).toBe(0)

    expect(() =>
      new EvidenceCapturePolicy().capture({
        kind: 'bytes',
        context,
        decision: {
          ...decision(context),
          jsonPointers: [`/${'x'.repeat(2_000_000)}`]
        },
        content: bytes('safe'),
        completeness: 'complete'
      })
    ).toThrow('Evidence capture decision is invalid.')
  })

  it('rejects artifact drafts spliced from a different capture binding', () => {
    const context = byteContext()
    const captured = new EvidenceCapturePolicy().capture({
      kind: 'bytes',
      context,
      decision: decision(context),
      content: bytes('safe response'),
      completeness: 'complete'
    })
    const artifact = captured.artifacts[0]
    if (!artifact) throw new Error('Expected an evidence artifact.')

    expect(
      EvidenceCaptureResultSchema.safeParse({
        ...captured,
        artifacts: [
          {
            ...artifact,
            capturePolicyVersion: '2.0.0'
          }
        ]
      }).success
    ).toBe(false)
    expect(
      EvidenceArtifactDraftSchema.safeParse({
        ...artifact,
        payload: {
          ...artifact.payload,
          sourceHash: {
            ...captured.sourceHash,
            digest: 'e'.repeat(64)
          }
        }
      }).success
    ).toBe(false)
    expect(
      EvidenceCaptureResultSchema.safeParse({
        ...captured,
        artifacts: []
      }).success
    ).toBe(false)
    expect(
      EvidenceCaptureResultSchema.safeParse({
        ...captured,
        artifacts: [{ ...artifact, content: `not-json ${SENTINEL}` }]
      }).success
    ).toBe(false)
    expect(
      EvidenceCaptureResultSchema.safeParse({
        ...captured,
        artifacts: [
          {
            ...artifact,
            payload: {
              ...artifact.payload,
              sourceHash: {
                ...captured.sourceHash,
                digest: 'f'.repeat(64)
              }
            }
          }
        ]
      }).success
    ).toBe(false)
    expect(
      EvidenceCaptureResultSchema.safeParse({
        ...captured,
        state: 'captured',
        reason: 'decision-discard'
      }).success
    ).toBe(false)

    const wrongBasisHash = {
      domain: EVIDENCE_SOURCE_HASH_DOMAIN,
      algorithm: 'sha256' as const,
      digest: captured.sourceHash.digest,
      basis: 'selected-oob-metadata' as const,
      coverage: 'partial' as const,
      hashedBytes: captured.sourceHash.hashedBytes
    }
    expect(
      EvidenceCaptureResultSchema.safeParse({
        ...captured,
        sourceHash: wrongBasisHash,
        artifacts: [
          {
            ...artifact,
            sourceHash: wrongBasisHash,
            payload: { ...artifact.payload, sourceHash: wrongBasisHash }
          }
        ]
      }).success
    ).toBe(false)
  })

  it('rejects a failing key provider with a static error', () => {
    const context: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'ssrf.oob',
      techniqueVersion: '1.0.0',
      stepId: 'callback',
      executionState: 'succeeded',
      source: 'oob-event',
      role: 'oob-callback',
      occurredAt: '2026-07-19T01:00:00.000Z'
    }
    const keyProvider: OobCommitmentKeyProvider = {
      resolveKey: () => {
        throw new Error(SENTINEL)
      }
    }

    expect(() =>
      new EvidenceCapturePolicy(keyProvider).capture({
        kind: 'oob',
        context,
        decision: decision(context),
        token: SENTINEL,
        metadata: { channel: 'http' }
      })
    ).toThrow('OOB token commitment failed validation.')
    try {
      new EvidenceCapturePolicy(keyProvider).capture({
        kind: 'oob',
        context,
        decision: decision(context),
        token: SENTINEL,
        metadata: { channel: 'http' }
      })
    } catch (error) {
      expect(String(error)).not.toContain(SENTINEL)
    }
  })

  it('rejects key material that cannot provide a secure HMAC', () => {
    const context: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'ssrf.oob',
      techniqueVersion: '1.0.0',
      stepId: 'callback',
      executionState: 'succeeded',
      source: 'oob-event',
      role: 'oob-callback',
      occurredAt: '2026-07-19T01:00:00.000Z'
    }
    const weakKeyProvider: OobCommitmentKeyProvider = {
      resolveKey: () => Uint8Array.from([1, 2, 3])
    }

    expect(() =>
      new EvidenceCapturePolicy(weakKeyProvider).capture({
        kind: 'oob',
        context,
        decision: decision(context),
        token: SENTINEL,
        metadata: { channel: 'http', eventType: 'http-request' }
      })
    ).toThrow('OOB token commitment failed validation.')
  })

  it('rejects non-categorical OOB metadata without leaking it', () => {
    const context: EvidenceCaptureContext = {
      scanId: IDS.scan,
      policyDecisionId: IDS.policy,
      techniqueId: 'ssrf.oob',
      techniqueVersion: '1.0.0',
      stepId: 'callback',
      executionState: 'succeeded',
      source: 'oob-event',
      role: 'oob-callback',
      occurredAt: '2026-07-19T01:00:00.000Z'
    }

    let error: unknown
    try {
      new EvidenceCapturePolicy().capture({
        kind: 'oob',
        context,
        decision: decision(context),
        token: SENTINEL,
        metadata: {
          channel: 'http',
          eventType: SENTINEL
        } as never
      })
    } catch (caught) {
      error = caught
    }
    expect(error).toMatchObject({ code: 'invalid-source-input' })
    expect(String(error)).not.toContain(SENTINEL)
  })
})
