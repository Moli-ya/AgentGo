import { randomUUID } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  DetectorService,
  schemaHintsFromImportOperations,
  selectIdorTechnique,
  selectSqliTechnique,
  selectSsrfTechnique,
  selectXssTechnique
} from './detector-service'
import { createVulnerabilityPlatform } from './vulnerability-platform'
import {
  IDOR_V2_TECHNIQUE_IDS,
  SQLI_V2_TECHNIQUE_IDS,
  SSRF_V2_TECHNIQUE_IDS,
  XSS_V2_TECHNIQUE_IDS
} from './vulnerability-bundles'

const endpointId = randomUUID()

describe('DetectorService', () => {
  const platform = createVulnerabilityPlatform()
  const detector = new DetectorService()

  it('emits parameter seeds from frozen inventory without I/O', () => {
    const parameterId = randomUUID()
    const seeds = detector.detect({
      families: ['sqli', 'security.headers'],
      registry: platform.definitionRegistry,
      surfaces: [
        {
          endpoint: {
            id: endpointId,
            method: 'GET',
            url: 'https://fixture.agentgo.test/items?id=1',
            source: 'link',
            parameters: [
              {
                id: parameterId,
                name: 'id',
                location: 'query',
                dataType: 'number',
                required: true
              }
            ]
          },
          variantIds: [randomUUID()],
          method: 'GET',
          reviewStatus: 'reviewed',
          codec: 'none'
        }
      ]
    })
    const sqli = seeds.filter((seed) => seed.familyId === 'sqli')
    expect(sqli).toHaveLength(1)
    expect(sqli[0]?.techniqueId).toBe(SQLI_V2_TECHNIQUE_IDS.booleanDifferential)
    expect(sqli[0]?.parameterId).toBe(parameterId)
    expect(seeds.some((seed) => seed.familyId === 'security.headers' && !seed.parameterId)).toBe(
      true
    )
    expect(seeds.every((seed) => seed.detectorId.length > 0)).toBe(true)
  })

  it('selects techniques from type, location and codec rather than name regex alone', () => {
    expect(
      selectSqliTechnique({
        parameter: { id: randomUUID(), name: 'row', location: 'query', dataType: 'integer', required: true },
        method: 'GET',
        codec: 'none'
      })
    ).toBe(SQLI_V2_TECHNIQUE_IDS.booleanDifferential)
    expect(
      selectSqliTechnique({
        parameter: { id: randomUUID(), name: 'msg', location: 'query', dataType: 'string', required: true },
        method: 'GET'
      })
    ).toBe(SQLI_V2_TECHNIQUE_IDS.errorSignal)
    expect(
      selectSqliTechnique({
        parameter: { id: randomUUID(), name: 'wait', location: 'query', dataType: 'string', required: true },
        method: 'GET'
      })
    ).toBe(SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential)
    expect(
      selectSqliTechnique({
        parameter: { id: randomUUID(), name: 'id', location: 'path', required: true },
        method: 'GET'
      })
    ).toBe(SQLI_V2_TECHNIQUE_IDS.booleanDifferential)
    expect(
      selectSqliTechnique({
        parameter: { id: randomUUID(), name: 'utm_source', location: 'query', dataType: 'string', required: false },
        method: 'GET'
      })
    ).toBeUndefined()
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'id', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly)
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'resource_id', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly)
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'id', location: 'path', required: true },
        method: 'GET'
      })
    ).toBe(IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential)
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'item_id', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential)
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'uuid', location: 'query', required: true },
        method: 'GET'
      })
    ).toBeUndefined()
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'tenant', location: 'query', required: true },
        method: 'GET'
      })
    ).toBeUndefined()
    expect(
      selectXssTechnique({
        parameter: { id: randomUUID(), name: 'q', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(XSS_V2_TECHNIQUE_IDS.reflectedInertMarker)
    expect(
      selectXssTechnique({
        parameter: { id: randomUUID(), name: 'hash', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(XSS_V2_TECHNIQUE_IDS.domOfflineReplay)
    expect(
      selectXssTechnique({
        parameter: { id: randomUUID(), name: 'comment', location: 'form', required: true },
        method: 'POST'
      })
    ).toBe(XSS_V2_TECHNIQUE_IDS.storedTestObject)
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'uuid', location: 'query', required: true },
        method: 'GET',
        schemaHint: { format: 'uuid', resourceKind: 'resource-id', operation: 'read' }
      })
    ).toBe(IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential)
    expect(
      selectIdorTechnique({
        parameter: {
          id: randomUUID(),
          name: 'resource_id',
          location: 'query',
          required: true
        },
        method: 'GET',
        schemaHint: { format: 'string', resourceKind: 'resource-id', operation: 'read' }
      })
    ).toBe(IDOR_V2_TECHNIQUE_IDS.twoTestIdentitiesReadonly)
    expect(
      selectIdorTechnique({
        parameter: { id: randomUUID(), name: 'trace', location: 'query', required: true },
        method: 'GET',
        schemaHint: { format: 'uuid', resourceKind: 'opaque' }
      })
    ).toBeUndefined()
    expect(
      selectXssTechnique({
        parameter: { id: randomUUID(), name: 'q', location: 'query', required: true },
        method: 'GET',
        sinkHint: { context: 'dom', encoding: 'none', source: 'asset-manifest' }
      })
    ).toBe(XSS_V2_TECHNIQUE_IDS.domOfflineReplay)
    expect(
      selectSsrfTechnique({
        parameter: { id: randomUUID(), name: 'url', location: 'query', required: true },
        method: 'GET'
      })
    ).toBe(SSRF_V2_TECHNIQUE_IDS.controlledProofResponse)
    expect(
      selectSsrfTechnique({
        parameter: { id: randomUUID(), name: 'homepage', location: 'query', required: true },
        method: 'GET'
      })
    ).toBeUndefined()
  })

  it('emits a single technique seed per parameter including header inventory candidates', () => {
    const headerId = randomUUID()
    const waitId = randomUUID()
    const seeds = detector.detect({
      families: ['sqli'],
      registry: platform.definitionRegistry,
      surfaces: [
        {
          endpoint: {
            id: endpointId,
            method: 'GET',
            url: 'https://fixture.agentgo.test/items',
            source: 'link',
            parameters: [
              { id: headerId, name: 'x-trace', location: 'header', required: false },
              { id: waitId, name: 'wait', location: 'query', required: true }
            ]
          },
          variantIds: [randomUUID()],
          method: 'GET',
          codec: 'none',
          reviewStatus: 'reviewed'
        }
      ]
    })
    expect(seeds.filter((seed) => seed.parameterId === headerId)).toHaveLength(1)
    expect(seeds.find((seed) => seed.parameterId === headerId)?.techniqueId).toBe(
      SQLI_V2_TECHNIQUE_IDS.booleanDifferential
    )
    expect(seeds.find((seed) => seed.parameterId === waitId)?.techniqueId).toBe(
      SQLI_V2_TECHNIQUE_IDS.boundedTimeDifferential
    )
  })

  it('attaches identity subjects and matrix refs for BOLA seeds', () => {
    const parameterId = randomUUID()
    const ownerId = randomUUID()
    const matrixId = randomUUID()
    const seeds = detector.detect({
      families: ['idor'],
      registry: platform.definitionRegistry,
      matrixId,
      identities: [
        {
          id: ownerId,
          role: 'owner',
          isTestIdentity: true,
          ownedResourceIds: ['res-1']
        }
      ],
      surfaces: [
        {
          endpoint: {
            id: endpointId,
            method: 'GET',
            url: 'https://fixture.agentgo.test/items?item_id=1',
            source: 'link',
            parameters: [
              {
                id: parameterId,
                name: 'item_id',
                location: 'query',
                required: true
              }
            ]
          },
          variantIds: [randomUUID()],
          method: 'GET',
          reviewStatus: 'reviewed',
          codec: 'none',
          schemaHints: {
            [parameterId]: {
              format: 'integer',
              resourceKind: 'resource-id',
              operation: 'read',
              ownerField: 'owner_id'
            }
          }
        }
      ]
    })
    const bola = seeds.find(
      (seed) => seed.techniqueId === IDOR_V2_TECHNIQUE_IDS.bolaReadDifferential
    )
    expect(bola?.matrixRefs).toEqual([matrixId])
    expect(bola?.identityRefs).toEqual([ownerId])
    expect(bola?.subjectRefs.some((ref) => ref.kind === 'identity' && ref.id === ownerId)).toBe(
      true
    )
    expect(bola?.reason).toContain('operation=read')
    expect(bola?.reason).toContain('ownerField=owner_id')
  })

  it('maps committed OpenAPI operations onto inventory parameter schema hints', () => {
    const parameterId = randomUUID()
    const hints = schemaHintsFromImportOperations(
      {
        id: endpointId,
        method: 'GET',
        url: 'https://inventory.example.test/orders/:orderId',
        source: 'openapi.import',
        parameters: [
          {
            id: parameterId,
            name: 'orderId',
            location: 'path',
            required: true
          }
        ]
      },
      [
        {
          operationRef: 'GET /orders/{orderId}',
          method: 'GET',
          url: 'https://inventory.example.test/orders/:orderId',
          scopeVerdict: 'in-scope',
          codec: 'none',
          transport: 'standard-http',
          parameterLocations: ['path'],
          parameters: [
            {
              name: 'orderId',
              location: 'path',
              valueType: 'integer',
              required: true,
              resourceKind: 'resource-id',
              ownerField: 'owner_id',
              responseIdentityField: 'id'
            }
          ],
          securitySchemes: [],
          warnings: []
        }
      ]
    )
    expect(hints[parameterId]).toMatchObject({
      resourceKind: 'resource-id',
      ownerField: 'owner_id',
      responseIdentityField: 'id',
      operation: 'read'
    })
  })
})
