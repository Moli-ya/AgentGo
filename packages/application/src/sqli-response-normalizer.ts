import { createHash } from 'node:crypto'
import type { HttpObservation } from './validation-engine'

export const SQLI_NORMALIZER_VERSION = 'sqli.normalize@1.1.0' as const

export const SQLI_NORMALIZER_THRESHOLDS = Object.freeze({
  trueRepeatSimilarity: 0.98,
  baselineTrueSimilarity: 0.9,
  maximumFalseSimilarity: 0.75,
  boundedTimeMinDeltaMs: 1_500,
  boundedTimeFalseMaxDeltaMs: 500,
  boundedTimeRepeatDeltaToleranceMs: 400
})

const UUID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi
const TIME_PATTERN = /\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+\b/g
const LONG_NUMBER_PATTERN = /\b\d{7,}\b/g

export interface NormalizedHttpView {
  readonly normalizerVersion: typeof SQLI_NORMALIZER_VERSION
  readonly statusCode: number | undefined
  readonly bodyText: string
  readonly bodyHash: string
  readonly jsonShapeHash?: string
  readonly cacheControl: string
  readonly etag: string
}

export function observationBodyText(observation: HttpObservation): string {
  return observation.result.responseBody
    ? Buffer.from(observation.result.responseBody).toString('utf8')
    : ''
}

export function stripVolatileText(value: string): string {
  return value
    .slice(0, 1_000_000)
    .replace(UUID_PATTERN, '<uuid>')
    .replace(TIME_PATTERN, '<time>')
    .replace(LONG_NUMBER_PATTERN, '<number>')
    .replace(/\s+/g, ' ')
    .trim()
}

function jsonShapeHash(value: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(value)
    return createHash('sha256')
      .update(stableShape(parsed), 'utf8')
      .digest('hex')
  } catch {
    return undefined
  }
}

function stableShape(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return typeof value
  }
  if (Array.isArray(value)) {
    return `[${value.slice(0, 8).map((item) => stableShape(item)).join(',')}]`
  }
  const keys = Object.keys(value as Record<string, unknown>).sort()
  return `{${keys
    .slice(0, 32)
    .map(
      (key) =>
        `${key}:${stableShape((value as Record<string, unknown>)[key])}`
    )
    .join(',')}}`
}

function headerValue(
  headers: Readonly<Record<string, string>> | undefined,
  name: string
): string {
  if (!headers) return ''
  const exact = headers[name]
  if (typeof exact === 'string') return exact
  const lower = name.toLowerCase()
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value
  }
  return ''
}

export function normalizeHttpObservation(
  observation: HttpObservation
): NormalizedHttpView {
  const bodyText = stripVolatileText(observationBodyText(observation))
  const headers = observation.result.responseHeaders
  return {
    normalizerVersion: SQLI_NORMALIZER_VERSION,
    statusCode: observation.result.statusCode,
    bodyText,
    bodyHash: createHash('sha256').update(bodyText, 'utf8').digest('hex'),
    ...(jsonShapeHash(observationBodyText(observation))
      ? { jsonShapeHash: jsonShapeHash(observationBodyText(observation)) }
      : {}),
    cacheControl: headerValue(headers, 'cache-control'),
    etag: headerValue(headers, 'etag')
  }
}
