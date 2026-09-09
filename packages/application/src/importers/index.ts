import {
  DEFAULT_IMPORT_PARSER_LIMITS,
  type ImportFormat,
  type ImportParserLimits,
  type TargetScope
} from '@agentgo/contracts'
import {
  OfflineParseError,
  decodeUtf8,
  parseOfflineDocument,
  type ParsedOfflineDocument
} from './bounded-document'
import { detectImportFormat } from './detect'
import { extractGraphqlIntrospection, extractGraphqlSdl, extractUnsupported } from './graphql'
import { extractOpenApi, extractSwagger, type AdapterResult } from './openapi'
import { extractHar, extractPostman } from './traffic'

export { detectImportFormat } from './detect'
export { OfflineParseError, decodeUtf8, parseOfflineDocument, sha256Bytes } from './bounded-document'
export { IMPORT_ADAPTER_PROFILES, IMPORT_PARSER_VERSION, profileFor } from './profiles'

const UNSUPPORTED_FORMATS = new Set<ImportFormat>([
  'asyncapi',
  'wsdl',
  'protobuf',
  'grpc-reflection',
  'websocket',
  'sse',
  'callback-webhook',
  'unknown'
])

export interface ExtractedImportDocument extends AdapterResult {
  readonly parserWarnings: ParsedOfflineDocument['warnings']
}

export function extractImportedDocument(
  bytes: Uint8Array,
  mediaType: string | undefined,
  scope: TargetScope,
  limits: ImportParserLimits = DEFAULT_IMPORT_PARSER_LIMITS
): ExtractedImportDocument {
  const startedAt = Date.now()
  if (bytes.byteLength > limits.maxFileBytes) {
    throw new OfflineParseError('document-too-large', 'Document exceeds the size budget.')
  }
  const text = decodeUtf8(bytes, limits.maxStringLength)
  const trimmed = text.trimStart()
  const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[')
  const xmlOrProto =
    /<(?:definitions|wsdl:definitions)[\s>]/u.test(text) || /syntax\s*=\s*"proto3"/u.test(text)
  const graphqlSdl =
    !looksJson &&
    /^\s*(?:type|interface|enum|input|schema|#\s*endpoint)\s/mu.test(text) &&
    !/^\s*(?:openapi|swagger)\s*:/mu.test(text)

  let document: unknown
  let parserWarnings: ParsedOfflineDocument['warnings'] = []
  if (looksJson) {
    const parsed = parseOfflineDocument(bytes, limits, startedAt)
    document = parsed.value
    parserWarnings = parsed.warnings
  } else if (graphqlSdl || xmlOrProto) {
    document = {}
  } else {
    const parsed = parseOfflineDocument(bytes, limits, startedAt)
    document = parsed.value
    parserWarnings = parsed.warnings
  }

  const format = detectImportFormat(mediaType, document, text)
  const extracted = dispatchExtractor(format, document, text, scope, limits)
  return {
    ...extracted,
    parserWarnings
  }
}

function dispatchExtractor(
  format: ImportFormat,
  document: unknown,
  text: string,
  scope: TargetScope,
  limits: ImportParserLimits
): AdapterResult {
  switch (format) {
    case 'openapi-3.0':
    case 'openapi-3.1':
      return extractOpenApi(document, scope, limits)
    case 'swagger-2.0':
      return extractSwagger(document, scope, limits)
    case 'har-1.2':
      return extractHar(document, scope, limits.maxOperations)
    case 'postman-2.1':
      return extractPostman(document, scope, limits.maxOperations)
    case 'graphql-sdl':
      return extractGraphqlSdl(text, scope, limits.maxOperations)
    case 'graphql-introspection':
      return extractGraphqlIntrospection(document, scope, limits.maxOperations)
    default:
      if (UNSUPPORTED_FORMATS.has(format)) {
        return extractUnsupported(format, undefined, scope)
      }
      return {
        format,
        operations: [],
        warnings: [
          {
            code: 'unsupported-format',
            location: 'document',
            message: 'Format is not in the import whitelist.'
          }
        ]
      }
  }
}
