import type { ImportFormat } from '@agentgo/contracts'
import { asRecord } from './openapi'

export function detectImportFormat(
  mediaType: string | undefined,
  document: unknown,
  text: string
): ImportFormat {
  const mime = (mediaType ?? '').toLowerCase()
  if (mime.includes('har')) return 'har-1.2'
  const root = asRecord(document)
  if (typeof root.openapi === 'string') {
    return root.openapi.startsWith('3.1') ? 'openapi-3.1' : 'openapi-3.0'
  }
  if (root.swagger === '2.0') return 'swagger-2.0'
  if (Array.isArray(asRecord(root.log).entries)) return 'har-1.2'
  const info = asRecord(root.info)
  if (String(info.schema ?? '').includes('postman') || (Array.isArray(root.item) && info.name)) {
    return 'postman-2.1'
  }
  if (Array.isArray(asRecord(asRecord(root.data).__schema).types)) {
    return 'graphql-introspection'
  }
  if (typeof root.asyncapi === 'string') return 'asyncapi'
  if (mime.includes('xml') || /<(?:definitions|wsdl:definitions)[\s>]/u.test(text)) {
    return 'wsdl'
  }
  if (mime.includes('graphql') || /^\s*(?:type|interface|enum|input|schema)\s/mu.test(text)) {
    return 'graphql-sdl'
  }
  if (/syntax\s*=\s*"proto3"/u.test(text)) return 'protobuf'
  return 'unknown'
}
