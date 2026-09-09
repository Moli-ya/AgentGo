import { createHash } from 'node:crypto'
import {
  DEFAULT_IMPORT_PARSER_LIMITS,
  type ImportParserLimits,
  type ImportWarning
} from '@agentgo/contracts'

export class OfflineParseError extends Error {
  readonly code: ImportWarning['code']

  constructor(code: ImportWarning['code'], message: string) {
    super(message)
    this.name = 'OfflineParseError'
    this.code = code
  }
}

export interface ParsedOfflineDocument {
  readonly value: unknown
  readonly warnings: ImportWarning[]
}

export function sha256Bytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex')
}

export function decodeUtf8(bytes: Uint8Array, maxStringLength: number): string {
  if (bytes.byteLength === 0) {
    throw new OfflineParseError('malformed-document', 'Document is empty.')
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  if (text.includes('\u0000')) {
    throw new OfflineParseError('malformed-document', 'Document contains NUL.')
  }
  if ([...text].some((character) => character.length > maxStringLength)) {
    throw new OfflineParseError('string-too-long', 'A scalar exceeds the string budget.')
  }
  return text
}

export function parseOfflineDocument(
  bytes: Uint8Array,
  limits: ImportParserLimits = DEFAULT_IMPORT_PARSER_LIMITS,
  startedAt = Date.now()
): ParsedOfflineDocument {
  if (bytes.byteLength > limits.maxFileBytes) {
    throw new OfflineParseError('document-too-large', 'Document exceeds the size budget.')
  }
  const text = decodeUtf8(bytes, limits.maxStringLength)
  assertParseBudget(startedAt, limits)
  const trimmed = text.trimStart()
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return {
      value: parseJsonDocument(trimmed, limits, startedAt),
      warnings: []
    }
  }
  return parseYamlDocument(text, limits, startedAt)
}

function assertParseBudget(startedAt: number, limits: ImportParserLimits): void {
  if (Date.now() - startedAt > limits.maxParseTimeMs) {
    throw new OfflineParseError('parse-timeout', 'Parser time budget exhausted.')
  }
}

function parseJsonDocument(
  text: string,
  limits: ImportParserLimits,
  startedAt: number
): unknown {
  const parsed: unknown = JSON.parse(text, (key, value) => {
    assertParseBudget(startedAt, limits)
    if (key.length > limits.maxStringLength) {
      throw new OfflineParseError('string-too-long', 'JSON key exceeds the string budget.')
    }
    if (typeof value === 'string' && value.length > limits.maxStringLength) {
      throw new OfflineParseError('string-too-long', 'JSON string exceeds the string budget.')
    }
    return value
  })
  countNodes(parsed, limits, 0)
  return parsed
}

function countNodes(value: unknown, limits: ImportParserLimits, depth: number): number {
  if (depth > limits.maxDocumentDepth) {
    throw new OfflineParseError('document-too-deep', 'Document exceeds the depth budget.')
  }
  if (value === null || typeof value !== 'object') return 1
  let count = 1
  const entries = Array.isArray(value) ? value : Object.values(value)
  for (const entry of entries) {
    count += countNodes(entry, limits, depth + 1)
    if (count > limits.maxObjectCount) {
      throw new OfflineParseError('too-many-objects', 'Document exceeds the object budget.')
    }
  }
  return count
}

export function parseYamlDocument(
  text: string,
  limits: ImportParserLimits,
  startedAt: number
): ParsedOfflineDocument {
  const warnings: ImportWarning[] = []
  if (/^\s*%YAML/mu.test(text) && (text.match(/%YAML/gu) ?? []).length > 1) {
    throw new OfflineParseError('malformed-document', 'Multiple YAML documents are forbidden.')
  }
  if (/(?:^|\s)!!\w/u.test(text)) {
    throw new OfflineParseError('yaml-tag-forbidden', 'YAML tags are forbidden.')
  }
  if (/(?:^|\n)\s*<<\s*:/u.test(text)) {
    throw new OfflineParseError('yaml-merge-forbidden', 'YAML merge keys are forbidden.')
  }
  const aliasCount = (text.match(/&[A-Za-z0-9_-]+/gu) ?? []).length
  if (aliasCount > limits.maxYamlAliases) {
    throw new OfflineParseError('yaml-alias-limit', 'YAML alias budget exceeded.')
  }
  const parser = new YamlParser(text, limits, startedAt, warnings)
  const value = parser.parse()
  countNodes(value, limits, 0)
  return { value, warnings }
}

class YamlParser {
  readonly #lines: string[]
  readonly #limits: ImportParserLimits
  readonly #startedAt: number
  readonly #warnings: ImportWarning[]
  readonly #anchors = new Map<string, unknown>()
  #index = 0

  constructor(
    text: string,
    limits: ImportParserLimits,
    startedAt: number,
    warnings: ImportWarning[]
  ) {
    this.#lines = text.replace(/\r\n/gu, '\n').split('\n')
    this.#limits = limits
    this.#startedAt = startedAt
    this.#warnings = warnings
  }

  parse(): unknown {
    this.#skipEmpty()
    if (this.#index >= this.#lines.length) {
      throw new OfflineParseError('malformed-document', 'YAML document is empty.')
    }
    return this.#readBlock(indentOf(this.#lines[this.#index] ?? ''))
  }

  #readBlock(indent: number): unknown {
    this.#assertBudget()
    const line = this.#peek()
    if (line === undefined) return null
    const trimmed = line.trim()
    if (trimmed.startsWith('- ')) return this.#readSequence(indent)
    if (trimmed.includes(':')) return this.#readMapping(indent)
    this.#index += 1
    return this.#parseScalar(trimmed)
  }

  #readMapping(indent: number): Record<string, unknown> {
    const output: Record<string, unknown> = {}
    let nodes = 0
    while (this.#index < this.#lines.length) {
      this.#assertBudget()
      const raw = this.#peek()
      if (raw === undefined) break
      if (raw.trim() === '' || raw.trim().startsWith('#')) {
        this.#index += 1
        continue
      }
      const currentIndent = indentOf(raw)
      if (currentIndent < indent) break
      if (currentIndent > indent) {
        throw new OfflineParseError('malformed-document', 'Unexpected YAML indent.')
      }
      const trimmed = raw.trim()
      if (trimmed.startsWith('- ')) break
      const match = /^((?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^:#]+?)):\s*(.*)$/u.exec(
        trimmed
      )
      if (!match) {
        throw new OfflineParseError('malformed-document', `Invalid YAML mapping at ${this.#index + 1}.`)
      }
      const key = String(this.#parseScalar(match[1] ?? ''))
      if (key.startsWith('$ref') && /https?:\/\//iu.test(match[2] ?? '')) {
        throw new OfflineParseError('remote-ref-forbidden', 'Remote $ref is forbidden.')
      }
      this.#index += 1
      let value: unknown
      const rest = (match[2] ?? '').trim()
      if (rest.length === 0 || rest.startsWith('#')) {
        const next = this.#peek()
        if (next !== undefined && indentOf(next) > indent) {
          value = this.#readBlock(indentOf(next))
        } else {
          value = null
        }
      } else if (rest.startsWith('&')) {
        const anchored = /^&([A-Za-z0-9_-]+)\s*(.*)$/u.exec(rest)
        if (!anchored) throw new OfflineParseError('malformed-document', 'Invalid YAML anchor.')
        if (anchored[2]) {
          value = this.#parseScalar(anchored[2])
        } else {
          const next = this.#peek()
          value = next !== undefined && indentOf(next) > indent ? this.#readBlock(indentOf(next)) : null
        }
        this.#anchors.set(anchored[1] ?? '', value)
      } else {
        value = this.#parseScalar(rest)
      }
      output[key] = value
      nodes += 1
      if (nodes > this.#limits.maxObjectCount) {
        throw new OfflineParseError('too-many-objects', 'YAML mapping exceeds the object budget.')
      }
    }
    return output
  }

  #readSequence(indent: number): unknown[] {
    const output: unknown[] = []
    while (this.#index < this.#lines.length) {
      this.#assertBudget()
      const raw = this.#peek()
      if (raw === undefined) break
      if (raw.trim() === '' || raw.trim().startsWith('#')) {
        this.#index += 1
        continue
      }
      const currentIndent = indentOf(raw)
      if (currentIndent < indent) break
      const trimmed = raw.trim()
      if (!trimmed.startsWith('- ')) break
      this.#index += 1
      const rest = trimmed.slice(2).trim()
      if (rest.length === 0) {
        const next = this.#peek()
        output.push(
          next !== undefined && indentOf(next) > currentIndent
            ? this.#readBlock(indentOf(next))
            : null
        )
      } else if (rest.includes(':') && !rest.startsWith('"') && !rest.startsWith("'")) {
        const inline = this.#readMappingFromInlineItem(rest, currentIndent + 2)
        output.push(inline)
      } else {
        output.push(this.#parseScalar(rest))
      }
      if (output.length > this.#limits.maxObjectCount) {
        throw new OfflineParseError('too-many-objects', 'YAML sequence exceeds the object budget.')
      }
    }
    return output
  }

  #readMappingFromInlineItem(first: string, childIndent: number): Record<string, unknown> {
    const match = /^((?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^:#]+?)):\s*(.*)$/u.exec(first)
    if (!match) {
      return { value: this.#parseScalar(first) }
    }
    const mapping: Record<string, unknown> = {
      [String(this.#parseScalar(match[1] ?? ''))]: (match[2] ?? '').trim()
        ? this.#parseScalar(match[2] ?? '')
        : null
    }
    while (this.#index < this.#lines.length) {
      const raw = this.#peek()
      if (raw === undefined) break
      if (indentOf(raw) < childIndent) break
      if (raw.trim().startsWith('- ')) break
      const nested = this.#readMapping(childIndent)
      Object.assign(mapping, nested)
      break
    }
    return mapping
  }

  #parseScalar(raw: string): unknown {
    const value = raw.replace(/\s+#.*$/u, '').trim()
    if (value.startsWith('*')) {
      const name = value.slice(1)
      if (!this.#anchors.has(name)) {
        throw new OfflineParseError('malformed-document', `Unknown YAML alias ${name}.`)
      }
      return this.#anchors.get(name)
    }
    if (/^https?:\/\//iu.test(value) && this.#looksLikeRefContext()) {
      this.#warnings.push({
        code: 'remote-ref-forbidden',
        location: `line:${this.#index}`,
        message: 'Remote URL scalars are recorded; network resolution is forbidden.'
      })
    }
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      return unescapeQuoted(value.slice(1, -1), value.startsWith('"'))
    }
    if (value === '~' || value === 'null' || value === 'Null') return null
    if (value === 'true' || value === 'True') return true
    if (value === 'false' || value === 'False') return false
    if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/u.test(value)) return Number(value)
    if (value.length > this.#limits.maxStringLength) {
      throw new OfflineParseError('string-too-long', 'YAML scalar exceeds the string budget.')
    }
    return value
  }

  #looksLikeRefContext(): boolean {
    return true
  }

  #peek(): string | undefined {
    return this.#lines[this.#index]
  }

  #skipEmpty(): void {
    while (this.#index < this.#lines.length) {
      const line = this.#lines[this.#index]
      if (line !== undefined && line.trim() !== '' && !line.trim().startsWith('#')) return
      this.#index += 1
    }
  }

  #assertBudget(): void {
    if (Date.now() - this.#startedAt > this.#limits.maxParseTimeMs) {
      throw new OfflineParseError('parse-timeout', 'Parser time budget exhausted.')
    }
  }
}

function indentOf(line: string): number {
  const match = /^( *)/u.exec(line.replace(/\t/gu, '  '))
  return match?.[1]?.length ?? 0
}

function unescapeQuoted(value: string, doubleQuoted: boolean): string {
  if (!doubleQuoted) return value.replace(/''/gu, "'")
  return value.replace(/\\([\\nrt"])/gu, (_, escaped: string) => {
    if (escaped === 'n') return '\n'
    if (escaped === 't') return '\t'
    if (escaped === 'r') return '\r'
    return escaped
  })
}
