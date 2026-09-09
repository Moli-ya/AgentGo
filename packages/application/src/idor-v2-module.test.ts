import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type {
  AuthorizationMatrix,
  Candidate,
  IdentityRecord,
  InventoryEndpoint
} from '@agentgo/contracts'
import { sealAuthorizationMatrix } from '@agentgo/domain'
import {
  compileLegacyParityPlan,
  type LegacyParityCompileInput
} from './legacy-parity-adapters'
import {
  assessBola,
  type HttpObservation
} from './validation-engine'
import { IDOR_NORMALIZER_VERSION } from './idor-response-normalizer'
import { IDOR_V2_TECHNIQUE_IDS } from './vulnerability-bundles'
import { createVulnerabilityPlatform } from './vulnerability-platform'

const endpointId = randomUUID()
const parameterId = randomUUID()
const ownerId = randomUUID()
const secondId = randomUUID()
const publicId = randomUUID()

function candidate(techniqueId: string): Candidate {
  return {
    candidateId: randomUUID(),
    familyId: 'idor',
    techniqueId,
    moduleVersion: '1.1.0',
    subjectRefs: [{ kind: 'endpoint', id: endpointId }],
    variantRefs: [],
    dependencyRefs: [],
    identityRefs: [ownerId, secondId],
    testObjectRefs: [],
    matrixRefs: [],
    parameterId,
    reason: 'IDOR V2 module candidate.',
    expectedSignal: techniqueId,
    suggestedStrategy: 'idor.legacy.strategy'
  }
}

function identity(
  id: string,
  ownedResourceIds: string[],
  role = 'member'
): IdentityRecord {
  return {
    id,
    targetId: randomUUID(),
    label: role,
    role,
    authType: 'bearer',
    isTestIdentity: true,
    ownedResourceIds,
    createdAt: '2026-09-02T00:00:00.000Z',
    updatedAt: '2026-09-02T00:00:00.000Z'
  }
}

function endpoint(
  url: string,
  name: string,
  location: InventoryEndpoint['parameters'][number]['location'] = 'query'
): InventoryEndpoint {
  return {
    id: endpointId,
    method: location === 'form' || location === 'json' ? 'POST' : 'GET',
    url,
    source: 'link',
    parameters: [
      {
        id: parameterId,
        name,
        location,
        required: true
      }
    ]
  }
}

function matrix(expected: 'not-visible' | 'visible' = 'not-visible'): AuthorizationMatrix {
  return sealAuthorizationMatrix({
    schemaVersion: 'agentgo-identity-session/1.0',
    matrixId: randomUUID(),
    matrixVersion: 1,
    targetId: randomUUID(),
    scopeSnapshotId: randomUUID(),
    entries: [
      {
        subjectIdentityId: secondId,
        resourceOwnerIdentityId: ownerId,
        role: 'member',
        operation: 'read',
        resourceRef: 'owner-resource-1',
        expected,
        humanSource: 'IDOR V2 fixture matrix'
      }
    ],
    humanAttestationRef: randomUUID(),
    issuedAt: '2026-09-02T00:00:00.000Z',
    expiresAt: '2026-09-03T00:00:00.000Z'
  })
}

function input(
  techniqueId: string,
  url: string,
  name: string,
  location: InventoryEndpoint['parameters'][number]['location'] = 'query',
  extras: Partial<LegacyParityCompileInput> = {}
): LegacyParityCompileInput {
  return {
    scanId: randomUUID(),
    candidate: candidate(techniqueId),
    endpoint: endpoint(url, name, location),
    identities: [
      identity(ownerId, ['owner-resource-1'], 'owner'),
      identity(secondId, ['member-resource-1'], 'member')
    ],
    allowedIdentityIds: [ownerId, secondId],
    environment: 'attested-fixture',
    upsertReadInventory: async () => {
      throw new Error('IDOR V2 tests must not perform a second I/O path.')
    },
    ...extras
  }
}

function http(
  body: string,
  extras: { statusCode?: number; cacheControl?: string } = {}
): HttpObservation {
  return {
    result: {
      status: 'succeeded',
      statusCode: extras.statusCode ?? 200,
      responseBody: Buffer.from(body),
      responseBodySha256: 'ab'.repeat(32),
      responseBytes: Buffer.byteLength(body),
      durationMs: 10,
      responseHeaders: {
        'content-type': 'application/json',
        'cache-control': extras.cacheControl ?? 'no-store'
      }
    },
    evidenceRefs: [],
    toolCallId: randomUUID(),
    proposalId: randomUUID(),
    policyDecisionId: randomUUID()
  }
}

describe('IDOR/BOLA V2 reference module', () => {
  it('keeps the qualified two-identity technique first and reserves write/BFLA as signal-only', () => {
    const platform = createVulnerabilityPlatform()
    const bundle = platform.definitionRegistry.getBundle('idor.legacy-v1', '1.2.0')
    const techniques = bundle?.bundle.manifest.techniques ?? []
    expect(techniques.map((item) => item.techniqueId)).toEqual([
      IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly,
      IDOR_V2_TECHNIQUE_IDS.bflaFunctionLevel,
      IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
      IDOR_V2_TECHNIQUE_IDS.boplaMassAssignment,
      IDOR_V2_TECHNIQUE_IDS.crossTenantRead,
      IDOR_V2_TECHNIQUE_IDS.parentChildHierarchy
    ])
    expect(techniques[0]?.declaredMode).toBe('active-l1')
    expect(
      techniques.find((item) => item.techniqueId === IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential)
        ?.declaredMode
    ).toBe('active-l1')
    expect(
      techniques.find((item) => item.techniqueId === IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential)
        ?.supportedSubjectKinds
    ).toContain('authorization-matrix')
    expect(
      techniques
        .filter((item) => item.techniqueId !== IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly)
        .filter((item) => item.techniqueId !== IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential)
        .every((item) => item.declaredMode === 'signal-only')
    ).toBe(true)
    expect(bundle?.bundle.remediations[0]?.remediation).toContain(
      '不以不可猜 ID 作为根本修复'
    )
    expect(IDOR_NORMALIZER_VERSION).toBe('idor.normalize@1.1.0')
  })

  it('compiles identity-switch plus path BOLA only when the matrix denies the cross-read', async () => {
    const missing = await compileLegacyParityPlan(
      input(
        IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
        'https://fixture.agentgo.test/research/idor/bola/path/positive/owner-resource-1',
        'id',
        'path'
      )
    )
    expect(missing).toMatchObject({ kind: 'awaiting-user' })

    const compiled = await compileLegacyParityPlan(
      input(
        IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
        'https://fixture.agentgo.test/research/idor/bola/path/positive/owner-resource-1',
        'id',
        'path',
        { authorizationMatrix: matrix() }
      )
    )
    expect(compiled.kind).toBe('plan')
    if (compiled.kind !== 'plan') return
    expect(compiled.draft.steps.map((step) => step.stepId)).toEqual([
      'bola.switch-owner',
      'bola.owner',
      'bola.switch-second',
      'bola.second-own',
      'bola.cross-read'
    ])
    expect(compiled.draft.steps.filter((step) => step.kind === 'identity-switch')).toHaveLength(2)
    const cross = compiled.draft.steps.find((step) => step.stepId === 'bola.cross-read')
    expect(cross).toMatchObject({
      mutationKind: 'path',
      mutationValue: 'owner-resource-1',
      payloadSummary: expect.stringMatching(/identityLabel=member; identityHash=[a-f0-9]{64}/)
    })
    expect(JSON.stringify(compiled.draft.steps)).not.toMatch(/Cookie|Bearer |Authorization/i)
  })

  it('emits public control when a public identity is present and rejects writes', async () => {
    const compiled = await compileLegacyParityPlan(
      input(
        IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
        'https://fixture.agentgo.test/research/idor/bola/query/positive?item_id=owner-resource-1',
        'item_id',
        'query',
        {
          authorizationMatrix: matrix(),
          identities: [
            identity(ownerId, ['owner-resource-1'], 'owner'),
            identity(secondId, ['member-resource-1'], 'member'),
            identity(publicId, ['public-resource-1'], 'public')
          ],
          allowedIdentityIds: [ownerId, secondId, publicId]
        }
      )
    )
    expect(compiled.kind).toBe('plan')
    if (compiled.kind === 'plan') {
      expect(compiled.draft.steps.some((step) => step.stepId === 'bola.public')).toBe(true)
    }

    const form = await compileLegacyParityPlan(
      input(
        IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential,
        'https://fixture.agentgo.test/research/idor/bola/form',
        'document',
        'form',
        { authorizationMatrix: matrix() }
      )
    )
    expect(form).toMatchObject({ kind: 'awaiting-user', waitFor: 'approval' })
  })

  it('confirms BOLA only with parsed resource identity and matrix deny', () => {
    const ownerRead = http(
      JSON.stringify({ id: 'owner-resource-1', ownerId: 'owner', value: 'test-only' })
    )
    const secondOwn = http(
      JSON.stringify({ id: 'member-resource-1', ownerId: 'member', value: 'own' })
    )
    const cross = http(
      JSON.stringify({ id: 'owner-resource-1', ownerId: 'owner', value: 'test-only' })
    )
    const confirmed = assessBola({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead,
      secondIdentityOwnRead: secondOwn,
      secondIdentityOwnerRead: cross,
      identitiesAuthorized: true,
      matrixCrossExpected: 'not-visible'
    })
    expect(confirmed.verdict).toBe('confirmed')
    expect(confirmed.confirmationRuleId).toBe('idor-v2-bola-read-differential')
    expect(confirmed.signalSummary).toContain(IDOR_NORMALIZER_VERSION)

    const lengthOnly = assessBola({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead,
      secondIdentityOwnRead: secondOwn,
      secondIdentityOwnerRead: http('{"value":"xxxxxxxxxxxxxxxxxxxxxxxx"}'),
      identitiesAuthorized: true,
      matrixCrossExpected: 'not-visible'
    })
    expect(lengthOnly.verdict).toBe('not-confirmed')
    expect(lengthOnly.failedChecks).toContain(
      'cross-response-contains-target-resource-identity'
    )

    const publicVisible = assessBola({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead,
      secondIdentityOwnRead: secondOwn,
      secondIdentityOwnerRead: cross,
      identitiesAuthorized: true,
      matrixCrossExpected: 'not-visible',
      publicControl: http(
        JSON.stringify({ id: 'owner-resource-1', ownerId: 'owner', visibility: 'public' })
      )
    })
    expect(publicVisible.verdict).toBe('not-confirmed')

    const session = assessBola({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead: http('{"error":"unauthorized"}', { statusCode: 401 }),
      secondIdentityOwnRead: secondOwn,
      secondIdentityOwnerRead: cross,
      identitiesAuthorized: true,
      matrixCrossExpected: 'not-visible'
    })
    expect(session.verdict).toBe('inconclusive')

    const cached = assessBola({
      ownerResourceId: 'owner-resource-1',
      secondIdentityResourceId: 'member-resource-1',
      ownerRead,
      secondIdentityOwnRead: secondOwn,
      secondIdentityOwnerRead: http(
        JSON.stringify({ id: 'owner-resource-1', ownerId: 'owner', value: 'cached' }),
        { cacheControl: 'public, max-age=60' }
      ),
      identitiesAuthorized: true,
      matrixCrossExpected: 'not-visible'
    })
    expect(cached.verdict).toBe('inconclusive')
  })
})
