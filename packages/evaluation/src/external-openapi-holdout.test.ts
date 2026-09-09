import { describe, expect, it } from 'vitest'
import {
  EXTERNAL_OPENAPI_HOLDOUT,
  normalizeExternalHoldoutBaseUrl,
  preflightExternalOpenApiHoldout
} from './external-openapi-holdout'

function responseFor(document: unknown): Response {
  return new Response(JSON.stringify(document), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  })
}

const document = {
  openapi: '3.0.3',
  info: { title: 'Swagger Petstore - OpenAPI 3.0', version: '1.0.16' },
  paths: {
    '/pet/findByStatus': { get: {} },
    '/pet/{petId}': { get: {} },
    '/store/inventory': { get: {} }
  }
}

describe('external OpenAPI holdout preflight', () => {
  it('accepts only an explicit loopback origin', () => {
    expect(normalizeExternalHoldoutBaseUrl('http://127.0.0.1:18080')).toBe(
      'http://127.0.0.1:18080'
    )
    expect(() => normalizeExternalHoldoutBaseUrl('https://petstore3.swagger.io')).toThrow(
      '127.0.0.1'
    )
    expect(() => normalizeExternalHoldoutBaseUrl('http://localhost:18080')).toThrow(
      '127.0.0.1'
    )
  })

  it('pins product identity without claiming an AgentGo benchmark result', async () => {
    const result = await preflightExternalOpenApiHoldout({
      baseUrl: 'http://127.0.0.1:18080',
      fetchImpl: async () => responseFor(document)
    })
    expect(result).toMatchObject({
      status: 'target-ready',
      resultClass: 'external-local-holdout',
      packVersion: 'swagger-petstore-v3/1.0.16',
      qualificationScope: 'target-preflight-only',
      pathCount: 3
    })
    expect(result.image).toBe(EXTERNAL_OPENAPI_HOLDOUT.image)
    expect(result.specificationSha256).toMatch(/^[a-f0-9]{64}$/u)
  })

  it('rejects version drift and missing compatibility routes', async () => {
    await expect(
      preflightExternalOpenApiHoldout({
        baseUrl: 'http://127.0.0.1:18080',
        fetchImpl: async () =>
          responseFor({ ...document, info: { ...document.info, version: '1.0.27' } })
      })
    ).rejects.toThrow('Unexpected Petstore version')
    await expect(
      preflightExternalOpenApiHoldout({
        baseUrl: 'http://127.0.0.1:18080',
        fetchImpl: async () => responseFor({ ...document, paths: {} })
      })
    ).rejects.toThrow('missing required paths')
  })
})
