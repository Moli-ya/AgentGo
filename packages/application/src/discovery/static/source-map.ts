import {
  DEFAULT_STATIC_DISCOVERY_BUDGET,
  type StaticDiscoveryCandidate,
  type StaticDiscoveryResourceBudget,
  type StaticDiscoverySourceProvenance,
  type TargetScope
} from '@agentgo/contracts'
import { redactInventoryText } from '@agentgo/domain'
import { evaluateUrlScope } from '@agentgo/security-policy'
import { OfflineParseError, parseOfflineDocument } from '../../importers/bounded-document'
import { sanitizeDiscoveredUrl } from './html'

interface DecodedMapping {
  readonly generatedLine: number
  readonly generatedColumn: number
  readonly sourceIndex: number
  readonly originalLine: number
  readonly originalColumn: number
  readonly nameIndex?: number
}

const BASE64_VALUES = new Map(
  [...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'].map((value, index) => [
    value,
    index
  ])
)

export function extractSourceMapCandidates(
  bytes: Uint8Array,
  scope: TargetScope,
  generatedFileHint: string | undefined,
  budget: StaticDiscoveryResourceBudget = DEFAULT_STATIC_DISCOVERY_BUDGET
): { readonly candidates: StaticDiscoveryCandidate[]; readonly warnings: string[] } {
  const warnings: string[] = []
  const candidates: StaticDiscoveryCandidate[] = []
  const startedAt = Date.now()
  let document: unknown
  try {
    document = parseOfflineDocument(bytes, {
      maxFileBytes: budget.maxFileBytes,
      maxDocumentDepth: budget.maxRecursionDepth,
      maxObjectCount: budget.maxAstNodes,
      maxOperations: 1,
      maxStringLength: Math.min(budget.maxRegexSteps, 100_000),
      maxYamlAliases: 0,
      maxParseTimeMs: budget.maxParseTimeMs
    }).value
  } catch (error) {
    const message =
      error instanceof OfflineParseError ? error.message : 'Source map parse failed closed.'
    return { candidates: [], warnings: [redactInventoryText(message, 2_048)] }
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    return { candidates: [], warnings: ['Source map root must be a JSON object.'] }
  }

  const root = document as Record<string, unknown>
  if (root.version !== 3) {
    return { candidates: [], warnings: ['Only Source Map version 3 is supported.'] }
  }
  const generatedFile = safeFile(
    typeof root.file === 'string' ? root.file : generatedFileHint ?? 'generated.js'
  )
  const rawSources = Array.isArray(root.sources) ? root.sources : []
  const sources = rawSources.map((item) => (typeof item === 'string' ? item : undefined))
  const sourceRoot = typeof root.sourceRoot === 'string' ? root.sourceRoot : undefined
  const names = Array.isArray(root.names)
    ? root.names.map((item) => (typeof item === 'string' ? item : undefined))
    : []
  if (sources.length > budget.maxSources) {
    warnings.push('Source map source budget reached; extra sources omitted.')
  }

  const sourceLimit = Math.min(sources.length, budget.maxSources)
  for (let index = 0; index < sourceLimit; index += 1) {
    const source = sources[index]
    if (!source) {
      warnings.push(`Source map source ${index} is not a string and cannot be referenced.`)
      continue
    }
    const resolved = resolveSource(source, sourceRoot, generatedFileHint)
    if (/^https?:\/\//iu.test(resolved)) {
      warnings.push(`Remote source map origin ${index} is never fetched.`)
    }
    if (resolved.startsWith('data:')) {
      warnings.push(`Inline data source ${index} is size-limited and not executed.`)
    }
    const verdict = evaluateUrlScope(resolved, scope, generatedFileHint)
    const url = sanitizeDiscoveredUrl(resolved, generatedFileHint)
    candidates.push({
      key: `source-map:${generatedFile}:source:${index}:${url}`,
      kind: 'source-map',
      url,
      location: `${generatedFile}:sources[${index}]`,
      confidence: verdict.ok ? 0.55 : 0.3,
      capabilityStatus: 'unsupported',
      secretClassification: /(?:token|secret|password)/iu.test(url) ? 'likely-secret' : 'none',
      warnings: [
        'Source map content is untrusted and not an Agent instruction.',
        ...(verdict.ok ? [] : [`scope:${verdict.reason}`])
      ]
    })
  }

  if (typeof root.mappings !== 'string' || root.mappings.length === 0) {
    warnings.push('Source map has no mappings to decode.')
    return sanitizeResult(candidates, warnings)
  }

  let mappings: readonly DecodedMapping[]
  try {
    mappings = decodeMappings(root.mappings, budget, startedAt)
  } catch (error) {
    warnings.push(error instanceof Error ? error.message : 'Source map mappings failed closed.')
    return sanitizeResult(candidates, warnings)
  }

  let omitted = 0
  for (const mapping of mappings) {
    if (candidates.length >= budget.maxStringCandidates) {
      omitted += 1
      continue
    }
    if (mapping.sourceIndex >= sourceLimit) {
      warnings.push(
        `Source map mapping at ${mapping.generatedLine}:${mapping.generatedColumn} references an unavailable source index.`
      )
      continue
    }
    const source = sources[mapping.sourceIndex]
    if (!source) continue
    const resolved = resolveSource(source, sourceRoot, generatedFileHint)
    const sourceFile = safeFile(sanitizeDiscoveredUrl(resolved, generatedFileHint))
    const provenance: StaticDiscoverySourceProvenance = {
      generated: {
        file: generatedFile,
        line: mapping.generatedLine,
        column: mapping.generatedColumn
      },
      original: {
        file: sourceFile,
        line: mapping.originalLine,
        column: mapping.originalColumn
      },
      ...(mapping.nameIndex !== undefined && names[mapping.nameIndex]
        ? { name: safeFile(names[mapping.nameIndex] as string) }
        : {})
    }
    candidates.push({
      key: `source-map:${generatedFile}:${mapping.generatedLine}:${mapping.generatedColumn}:${mapping.sourceIndex}:${mapping.originalLine}:${mapping.originalColumn}`,
      kind: 'source-map',
      url: sourceFile,
      location: `${generatedFile}:${mapping.generatedLine}:${mapping.generatedColumn} -> source[${mapping.sourceIndex}]:${mapping.originalLine}:${mapping.originalColumn}`,
      sourceProvenance: provenance,
      confidence: 0.8,
      capabilityStatus: 'unsupported',
      secretClassification: /(?:token|secret|password)/iu.test(sourceFile)
        ? 'likely-secret'
        : 'none',
      warnings: ['Decoded Source Map provenance only; source code is not fetched or executed.']
    })
  }
  if (omitted > 0) {
    warnings.push(`Source map candidate budget reached; ${omitted} decoded mapping(s) omitted.`)
  }
  return sanitizeResult(candidates, warnings)
}

function decodeMappings(
  encoded: string,
  budget: StaticDiscoveryResourceBudget,
  startedAt: number
): readonly DecodedMapping[] {
  if (encoded.length > budget.maxRegexSteps) {
    throw new Error('Source map mapping step budget exhausted.')
  }
  const output: DecodedMapping[] = []
  let sourceIndex = 0
  let originalLine = 0
  let originalColumn = 0
  let nameIndex = 0
  let generatedLine = 1
  let segment = ''
  let steps = 0

  const consume = (): void => {
    if (!segment) return
    steps += segment.length + 1
    if (steps > budget.maxRegexSteps) {
      throw new Error('Source map mapping step budget exhausted.')
    }
    if (Date.now() - startedAt > budget.maxParseTimeMs) {
      throw new Error('Source map parse time budget exhausted.')
    }
    const values = decodeVlqSegment(segment)
    segment = ''
    generatedColumn += values[0] ?? 0
    if (generatedColumn < 0) throw new Error('Source map generated column became negative.')
    if (values.length === 1) return
    if (values.length !== 4 && values.length !== 5) {
      throw new Error('Source map segment must contain 1, 4, or 5 VLQ fields.')
    }
    sourceIndex += values[1] ?? 0
    originalLine += values[2] ?? 0
    originalColumn += values[3] ?? 0
    if (values.length === 5) nameIndex += values[4] ?? 0
    if (sourceIndex < 0 || originalLine < 0 || originalColumn < 0 || nameIndex < 0) {
      throw new Error('Source map mapping resolved to a negative index or position.')
    }
    output.push({
      generatedLine,
      generatedColumn,
      sourceIndex,
      originalLine: originalLine + 1,
      originalColumn,
      ...(values.length === 5 ? { nameIndex } : {})
    })
    if (output.length > budget.maxStringCandidates) {
      throw new Error('Source map decoded mapping budget exhausted.')
    }
  }

  let generatedColumn = 0
  for (const character of encoded) {
    if (character === ',') {
      consume()
      continue
    }
    if (character === ';') {
      consume()
      generatedLine += 1
      generatedColumn = 0
      continue
    }
    if (!BASE64_VALUES.has(character)) {
      throw new Error('Source map mappings contain an invalid Base64 VLQ character.')
    }
    segment += character
  }
  consume()
  return output
}

function decodeVlqSegment(segment: string): number[] {
  const values: number[] = []
  let value = 0
  let shift = 0
  for (const character of segment) {
    const digit = BASE64_VALUES.get(character)
    if (digit === undefined) throw new Error('Invalid Source Map Base64 VLQ digit.')
    const continuation = (digit & 32) !== 0
    value += (digit & 31) * 2 ** shift
    if (!Number.isSafeInteger(value) || shift > 48) {
      throw new Error('Source map VLQ value exceeds the safe integer budget.')
    }
    if (continuation) {
      shift += 5
      continue
    }
    const negative = (value & 1) === 1
    values.push((negative ? -1 : 1) * Math.floor(value / 2))
    value = 0
    shift = 0
  }
  if (shift !== 0) throw new Error('Source map VLQ segment ended mid-value.')
  return values
}

function resolveSource(
  source: string,
  sourceRoot: string | undefined,
  generatedFileHint: string | undefined
): string {
  const rooted = sourceRoot ? joinReference(sourceRoot, source) : source
  return joinReference(generatedFileHint, rooted)
}

function joinReference(base: string | undefined, value: string): string {
  if (!base || /^[a-z][a-z0-9+.-]*:/iu.test(value)) return value
  try {
    return new URL(value, base).href
  } catch {
    const separator = base.endsWith('/') || value.startsWith('/') ? '' : '/'
    return `${base}${separator}${value}`
  }
}

function safeFile(value: string): string {
  return redactInventoryText(value, 2_048)
}

function sanitizeResult(
  candidates: readonly StaticDiscoveryCandidate[],
  warnings: readonly string[]
): { readonly candidates: StaticDiscoveryCandidate[]; readonly warnings: string[] } {
  return {
    candidates: [...candidates],
    warnings: warnings.map((warning) => redactInventoryText(warning, 2_048))
  }
}
