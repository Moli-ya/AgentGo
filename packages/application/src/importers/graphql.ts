import type { ImportPreviewOperation, ImportWarning, TargetScope } from '@agentgo/contracts'
import { asRecord, scopeVerdict, type AdapterResult } from './openapi'

export function extractGraphqlSdl(
  text: string,
  scope: TargetScope,
  maxOperations: number
): AdapterResult {
  const warnings: ImportWarning[] = []
  const operations: ImportPreviewOperation[] = []
  const endpoint = /#\s*endpoint:\s*(\S+)/iu.exec(text)?.[1]
  const types = [
    ...text.matchAll(/\b(?:type|interface|input|enum)\s+([A-Za-z_][\w]*)/gu)
  ].map((match) => match[1] ?? 'Unknown')
  const fields = [...text.matchAll(/^\s{2}([A-Za-z_][\w]*)\s*(?:\(([^)]*)\))?\s*:/gmu)]
  if (!endpoint) {
    warnings.push({
      code: 'unresolved-base',
      location: 'sdl',
      message: 'GraphQL SDL has no trusted endpoint hint; operations stay unresolved.'
    })
  }
  for (const [index, field] of fields.entries()) {
    if (operations.length >= maxOperations) break
    const name = field[1] ?? `field${index}`
    const args = field[2]
    operations.push({
      operationRef: name,
      method: 'POST',
      url: endpoint ?? name,
      scopeVerdict: endpoint ? scopeVerdict(endpoint, scope) : 'unresolved',
      contentType: 'application/json',
      codec: 'graphql',
      transport: 'standard-http',
      parameterLocations: args ? ['body'] : [],
      securitySchemes: [],
      warnings: []
    })
  }
  warnings.push({
    code: 'unsupported-protocol',
    location: 'sdl',
    message: `GraphQL types inventoried: ${types.slice(0, 16).join(', ') || 'none'}. No introspection query is sent.`
  })
  return { format: 'graphql-sdl', operations, warnings }
}

export function extractGraphqlIntrospection(
  document: unknown,
  scope: TargetScope,
  maxOperations: number
): AdapterResult {
  const schema = asRecord(asRecord(asRecord(document).data).__schema)
  const types = Array.isArray(schema.types) ? schema.types : []
  const warnings: ImportWarning[] = [
    {
      code: 'unsupported-protocol',
      location: '__schema',
      message: 'User-supplied introspection is inventoried. Live GraphQL execution is unsupported.'
    }
  ]
  const operations: ImportPreviewOperation[] = []
  const queryType = asRecord(schema.queryType).name
  for (const type of types) {
    const record = asRecord(type)
    if (record.name !== queryType) continue
    const fields = Array.isArray(record.fields) ? record.fields : []
    for (const field of fields) {
      if (operations.length >= maxOperations) break
      const name = String(asRecord(field).name ?? 'field')
      operations.push({
        operationRef: name,
        method: 'POST',
        url: name,
        scopeVerdict: 'unresolved',
        codec: 'graphql',
        transport: 'standard-http',
        parameterLocations: ['body'],
        securitySchemes: [],
        warnings: []
      })
    }
  }
  void scope
  return { format: 'graphql-introspection', operations, warnings }
}

export function extractUnsupported(
  format: AdapterResult['format'],
  hintUrl: string | undefined,
  scope: TargetScope
): AdapterResult {
  return {
    format,
    operations: hintUrl
      ? [
          {
            operationRef: format,
            method: 'POST',
            url: hintUrl,
            scopeVerdict: scopeVerdict(hintUrl, scope),
            codec: 'raw',
            transport:
              format === 'websocket'
                ? 'websocket'
                : format === 'sse'
                  ? 'sse'
                  : 'standard-http',
            parameterLocations: [],
            securitySchemes: [],
            warnings: [
              {
                code: 'unsupported-protocol',
                location: format,
                message: `${format} can only produce inventory-only hints.`
              }
            ]
          }
        ]
      : [],
    warnings: [
      {
        code: 'unsupported-format',
        location: format,
        message: `${format} is not replayable or executable.`
      }
    ]
  }
}
