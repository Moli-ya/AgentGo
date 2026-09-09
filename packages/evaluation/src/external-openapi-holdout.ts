import { createHash } from 'node:crypto'

export const EXTERNAL_OPENAPI_HOLDOUT = Object.freeze({
  packId: 'swagger-petstore-v3-rest-openapi',
  packVersion: 'swagger-petstore-v3/1.0.16',
  resultClass: 'external-local-holdout' as const,
  image:
    'swaggerapi/petstore3@sha256:221da3038bf91fad98e249d5f123cbca21d5bfc8e10a786c8c060ec8058cc522',
  openApiPath: '/api/v3/openapi.json',
  expectedInfoVersion: '1.0.16',
  expectedOpenApiPrefix: '3.',
  requiredPaths: ['/pet/findByStatus', '/pet/{petId}', '/store/inventory'] as const
})

const MAX_OPENAPI_BYTES = 2 * 1024 * 1024

export interface ExternalOpenApiPreflightResult {
  readonly schemaVersion: 'agentgo-external-openapi-preflight/1.0'
  readonly status: 'target-ready'
  readonly resultClass: 'external-local-holdout'
  readonly packId: string
  readonly packVersion: string
  readonly image: string
  readonly baseUrl: string
  readonly openApiUrl: string
  readonly openApiVersion: string
  readonly infoVersion: string
  readonly specificationSha256: string
  readonly pathCount: number
  readonly qualificationScope: 'target-preflight-only'
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`)
  }
  return value as Record<string, unknown>
}

export function normalizeExternalHoldoutBaseUrl(value: string): string {
  const url = new URL(value)
  if (
    url.protocol !== 'http:' ||
    url.hostname !== '127.0.0.1' ||
    !url.port ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== '/' && url.pathname !== '')
  ) {
    throw new Error(
      'External holdout base URL must be an explicit http://127.0.0.1:<port> origin.'
    )
  }
  return url.origin
}

export async function preflightExternalOpenApiHoldout(input: {
  readonly baseUrl: string
  readonly fetchImpl?: typeof fetch
}): Promise<ExternalOpenApiPreflightResult> {
  const baseUrl = normalizeExternalHoldoutBaseUrl(input.baseUrl)
  const openApiUrl = new URL(EXTERNAL_OPENAPI_HOLDOUT.openApiPath, `${baseUrl}/`).href
  const response = await (input.fetchImpl ?? fetch)(openApiUrl, {
    method: 'GET',
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
    headers: { accept: 'application/json' }
  })
  if (!response.ok) {
    throw new Error(`External OpenAPI target returned HTTP ${response.status}.`)
  }
  if (response.url && response.url !== openApiUrl) {
    throw new Error('External OpenAPI target changed origin or path.')
  }
  const declaredLength = Number(response.headers.get('content-length') ?? '0')
  if (Number.isFinite(declaredLength) && declaredLength > MAX_OPENAPI_BYTES) {
    throw new Error('External OpenAPI document exceeds the preflight size limit.')
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength > MAX_OPENAPI_BYTES) {
    throw new Error('External OpenAPI document exceeds the preflight size limit.')
  }
  let document: unknown
  try {
    document = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new Error('External OpenAPI target did not return valid JSON.')
  }
  const root = requireRecord(document, 'OpenAPI document')
  const info = requireRecord(root.info, 'OpenAPI info')
  const paths = requireRecord(root.paths, 'OpenAPI paths')
  const openApiVersion = typeof root.openapi === 'string' ? root.openapi : ''
  const infoVersion = typeof info.version === 'string' ? info.version : ''
  if (!openApiVersion.startsWith(EXTERNAL_OPENAPI_HOLDOUT.expectedOpenApiPrefix)) {
    throw new Error(`Unexpected OpenAPI version: ${openApiVersion || 'missing'}.`)
  }
  if (infoVersion !== EXTERNAL_OPENAPI_HOLDOUT.expectedInfoVersion) {
    throw new Error(`Unexpected Petstore version: ${infoVersion || 'missing'}.`)
  }
  const missingPaths = EXTERNAL_OPENAPI_HOLDOUT.requiredPaths.filter(
    (path) => !(path in paths)
  )
  if (missingPaths.length > 0) {
    throw new Error(`External OpenAPI document is missing required paths: ${missingPaths.join(', ')}.`)
  }
  return Object.freeze({
    schemaVersion: 'agentgo-external-openapi-preflight/1.0',
    status: 'target-ready',
    resultClass: EXTERNAL_OPENAPI_HOLDOUT.resultClass,
    packId: EXTERNAL_OPENAPI_HOLDOUT.packId,
    packVersion: EXTERNAL_OPENAPI_HOLDOUT.packVersion,
    image: EXTERNAL_OPENAPI_HOLDOUT.image,
    baseUrl,
    openApiUrl,
    openApiVersion,
    infoVersion,
    specificationSha256: createHash('sha256').update(bytes).digest('hex'),
    pathCount: Object.keys(paths).length,
    qualificationScope: 'target-preflight-only'
  })
}
