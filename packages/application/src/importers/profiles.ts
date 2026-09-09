import type { ImportAdapterProfile } from '@agentgo/contracts'

const PARSER_VERSION = '1.0.0'

export const IMPORT_PARSER_VERSION = PARSER_VERSION

export const OPENAPI_31_UNSUPPORTED_KEYWORDS = [
  'dynamic-ref',
  'dynamic-anchor',
  'unevaluated-properties',
  'unevaluated-items',
  'dependent-schemas',
  'prefix-items',
  'if-then-else'
] as const

export const IMPORT_ADAPTER_PROFILES: readonly ImportAdapterProfile[] = [
  {
    format: 'openapi-3.0',
    parserName: 'import.openapi',
    parserVersion: PARSER_VERSION,
    status: 'fully-parsed',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json', 'application/yaml', 'text/yaml'],
    supportedKeywords: ['openapi', 'info', 'servers', 'paths', 'components', 'security'],
    unsupportedKeywords: ['callbacks', 'webhooks', 'links'],
    notes: [
      'OpenAPI 3.0 is inventoried offline. Remote $ref, callbacks, and vendor execution hints are never replayable.'
    ]
  },
  {
    format: 'openapi-3.1',
    parserName: 'import.openapi',
    parserVersion: PARSER_VERSION,
    status: 'fully-parsed',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json', 'application/yaml', 'text/yaml'],
    supportedKeywords: ['openapi', 'json-schema-2020-12-subset', 'paths', 'webhooks-inventory-only'],
    unsupportedKeywords: [...OPENAPI_31_UNSUPPORTED_KEYWORDS],
    notes: [
      'JSON Schema 2020-12 is limited to type/properties/required/items/enum/format. Unevaluated and dynamic refs are warnings, not silent drops.'
    ]
  },
  {
    format: 'swagger-2.0',
    parserName: 'import.swagger',
    parserVersion: PARSER_VERSION,
    status: 'fully-parsed',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json', 'application/yaml', 'text/yaml'],
    supportedKeywords: ['swagger', 'host', 'base-path', 'schemes', 'paths', 'security-definitions'],
    unsupportedKeywords: ['external-docs-fetch'],
    notes: [
      'host/basePath/schemes are composed into an absolute URL. body parameters become json/form codec hints only.'
    ]
  },
  {
    format: 'har-1.2',
    parserName: 'import.har',
    parserVersion: PARSER_VERSION,
    status: 'fully-parsed',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json', 'application/har+json'],
    supportedKeywords: ['log', 'entries', 'request', 'initiator'],
    unsupportedKeywords: ['response-body-replay'],
    notes: ['HAR request URLs are inventoried. Cookies, Authorization, and bodies are redacted.']
  },
  {
    format: 'postman-2.1',
    parserName: 'import.postman',
    parserVersion: PARSER_VERSION,
    status: 'fully-parsed',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json'],
    supportedKeywords: ['info', 'item', 'variable', 'request'],
    unsupportedKeywords: ['event-script-exec'],
    notes: ['Collection variables substitute only in-document values. Scripts are never executed.']
  },
  {
    format: 'graphql-sdl',
    parserName: 'import.graphql',
    parserVersion: PARSER_VERSION,
    status: 'partial-inventory',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/graphql', 'text/plain'],
    supportedKeywords: ['type', 'field', 'argument', 'operation'],
    unsupportedKeywords: ['introspection-query'],
    notes: ['SDL is inventoried. No introspection query is sent.']
  },
  {
    format: 'graphql-introspection',
    parserName: 'import.graphql',
    parserVersion: PARSER_VERSION,
    status: 'partial-inventory',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json'],
    supportedKeywords: ['__schema', 'types', 'fields'],
    unsupportedKeywords: ['live-introspection'],
    notes: ['User-supplied introspection JSON is inventoried. AgentGo never fetches schema.']
  },
  {
    format: 'asyncapi',
    parserName: 'import.unsupported',
    parserVersion: PARSER_VERSION,
    status: 'unsupported',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json', 'application/yaml'],
    supportedKeywords: [],
    unsupportedKeywords: ['asyncapi'],
    notes: ['AsyncAPI is inventory-only with unsupported warnings until a dedicated runner exists.']
  },
  {
    format: 'wsdl',
    parserName: 'import.unsupported',
    parserVersion: PARSER_VERSION,
    status: 'unsupported',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/xml', 'text/xml'],
    supportedKeywords: [],
    unsupportedKeywords: ['wsdl', 'soap'],
    notes: ['SOAP/WSDL is not executable.']
  },
  {
    format: 'protobuf',
    parserName: 'import.unsupported',
    parserVersion: PARSER_VERSION,
    status: 'unsupported',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/x-protobuf', 'text/plain'],
    supportedKeywords: [],
    unsupportedKeywords: ['protobuf', 'grpc'],
    notes: ['protobuf/gRPC descriptors stay unsupported.']
  },
  {
    format: 'grpc-reflection',
    parserName: 'import.unsupported',
    parserVersion: PARSER_VERSION,
    status: 'unsupported',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json'],
    supportedKeywords: [],
    unsupportedKeywords: ['grpc-reflection'],
    notes: ['gRPC reflection exports stay unsupported.']
  },
  {
    format: 'websocket',
    parserName: 'import.unsupported',
    parserVersion: PARSER_VERSION,
    status: 'unsupported',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json'],
    supportedKeywords: [],
    unsupportedKeywords: ['websocket'],
    notes: ['WebSocket descriptions are inventory-only hints.']
  },
  {
    format: 'sse',
    parserName: 'import.unsupported',
    parserVersion: PARSER_VERSION,
    status: 'unsupported',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json'],
    supportedKeywords: [],
    unsupportedKeywords: ['sse'],
    notes: ['SSE descriptions are inventory-only hints.']
  },
  {
    format: 'callback-webhook',
    parserName: 'import.unsupported',
    parserVersion: PARSER_VERSION,
    status: 'unsupported',
    replayable: false,
    executable: false,
    supportedMediaTypes: ['application/json'],
    supportedKeywords: [],
    unsupportedKeywords: ['callback-webhook'],
    notes: ['Callbacks and webhooks are inventory-only until a dedicated adapter exists.']
  }
]

export function profileFor(format: ImportAdapterProfile['format']): ImportAdapterProfile {
  const profile = IMPORT_ADAPTER_PROFILES.find((item) => item.format === format)
  if (!profile) {
    return {
      format: 'unknown',
      parserName: 'import.unknown',
      parserVersion: PARSER_VERSION,
      status: 'unsupported',
      replayable: false,
      executable: false,
      supportedMediaTypes: ['application/octet-stream'],
      supportedKeywords: [],
      unsupportedKeywords: ['unknown'],
      notes: ['Format is not in the import whitelist.']
    }
  }
  return profile
}
