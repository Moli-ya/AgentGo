import type {
  CsrfBindingFailureReason,
  CsrfBindingRule
} from '@agentgo/contracts'
import {
  createRuntimeSearchParams,
  parseRuntimeUrl,
  type RuntimeUrl
} from './runtime-url'

/**
 * Deterministic CSRF token extraction and injection. Model output is never
 * involved: tokens come only from exact rules over observed responses, and a
 * binding is usable only for the identity/session/origin/method/path it was
 * sealed against.
 */

export const CSRF_TOKEN_MAX_LENGTH = 512

const TOKEN_CONTROL_PATTERN = /[\x00-\x1f\x7f]/u

export type CsrfExtractionOutcome =
  | { readonly ok: true; readonly token: string }
  | { readonly ok: false; readonly reason: CsrfBindingFailureReason }

export interface CsrfExtractionResponse {
  readonly url: string
  readonly headers?: Readonly<Record<string, string>>
  readonly bodyText?: string
}

function isUsableToken(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= CSRF_TOKEN_MAX_LENGTH &&
    !TOKEN_CONTROL_PATTERN.test(value)
  )
}

function htmlAttribute(tag: string, name: string): string | undefined {
  const pattern = new RegExp(
    `${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`,
    'iu'
  )
  const match = pattern.exec(tag)
  if (!match) return undefined
  return match[1] ?? match[2] ?? match[3]
}

function extractFromHtmlInput(
  body: string,
  selector: string
): readonly string[] {
  const tokens: string[] = []
  const inputPattern = /<input\b[^>]*>/giu
  for (const match of body.matchAll(inputPattern)) {
    const tag = match[0]
    const name = htmlAttribute(tag, 'name')
    if (name !== selector) continue
    const value = htmlAttribute(tag, 'value')
    if (value !== undefined) tokens.push(value)
  }
  return tokens
}

function extractFromHtmlMeta(body: string, selector: string): readonly string[] {
  const tokens: string[] = []
  const metaPattern = /<meta\b[^>]*>/giu
  for (const match of body.matchAll(metaPattern)) {
    const tag = match[0]
    const name = htmlAttribute(tag, 'name')
    if (name !== selector) continue
    const content = htmlAttribute(tag, 'content')
    if (content !== undefined) tokens.push(content)
  }
  return tokens
}

function extractFromFormField(body: string, selector: string): readonly string[] {
  const params = createRuntimeSearchParams(body)
  return params.getAll(selector)
}

function resolveJsonPointer(document: unknown, pointer: string): readonly unknown[] {
  if (!pointer.startsWith('/')) return []
  const segments = pointer
    .split('/')
    .slice(1)
    .map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'))
  let current: unknown = document
  for (const segment of segments) {
    if (Array.isArray(current)) {
      if (!/^(0|[1-9]\d*)$/u.test(segment)) return []
      const index = Number(segment)
      if (index >= current.length) return []
      current = current[index]
    } else if (current !== null && typeof current === 'object') {
      if (!Object.prototype.hasOwnProperty.call(current, segment)) return []
      current = (current as Record<string, unknown>)[segment]
    } else {
      return []
    }
  }
  return [current]
}

function extractFromJsonPointer(body: string, pointer: string): readonly unknown[] {
  let document: unknown
  try {
    document = JSON.parse(body)
  } catch {
    return []
  }
  return resolveJsonPointer(document, pointer)
}

function extractFromHeader(
  headers: Readonly<Record<string, string>>,
  selector: string
): readonly string[] {
  const wanted = selector.toLowerCase()
  const matches: string[] = []
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === wanted) matches.push(value)
  }
  return matches
}

/**
 * Extracts exactly one token. Multiple candidates are ambiguous and fail
 * closed; an untrusted source URL (wrong origin or outside the declared path
 * prefix) is rejected before parsing.
 */
export function extractCsrfToken(
  rule: CsrfBindingRule,
  response: CsrfExtractionResponse
): CsrfExtractionOutcome {
  const url: RuntimeUrl | undefined = parseRuntimeUrl(response.url)
  if (!url) return { ok: false, reason: 'untrusted-source' }
  if (url.origin !== rule.sourceOrigin) {
    return { ok: false, reason: 'untrusted-source' }
  }
  if (!url.pathname.startsWith(rule.sourcePathPrefix)) {
    return { ok: false, reason: 'untrusted-source' }
  }

  let candidates: readonly unknown[]
  switch (rule.sourceKind) {
    case 'response-header':
      if (!response.headers) return { ok: false, reason: 'token-missing' }
      candidates = extractFromHeader(response.headers, rule.sourceSelector)
      break
    case 'html-input':
      if (response.bodyText === undefined) return { ok: false, reason: 'token-missing' }
      candidates = extractFromHtmlInput(response.bodyText, rule.sourceSelector)
      break
    case 'html-meta':
      if (response.bodyText === undefined) return { ok: false, reason: 'token-missing' }
      candidates = extractFromHtmlMeta(response.bodyText, rule.sourceSelector)
      break
    case 'form-field':
      if (response.bodyText === undefined) return { ok: false, reason: 'token-missing' }
      candidates = extractFromFormField(response.bodyText, rule.sourceSelector)
      break
    case 'json-pointer':
      if (response.bodyText === undefined) return { ok: false, reason: 'token-missing' }
      candidates = extractFromJsonPointer(response.bodyText, rule.sourceSelector)
      break
  }

  if (candidates.length === 0) return { ok: false, reason: 'token-missing' }
  if (candidates.length > 1) return { ok: false, reason: 'token-ambiguous' }
  const token = candidates[0]
  if (!isUsableToken(token)) return { ok: false, reason: 'token-missing' }
  return { ok: true, token }
}

export type CsrfInjectionTarget =
  | {
      readonly location: 'header'
      readonly headers: Readonly<Record<string, string>>
    }
  | {
      readonly location: 'form-field'
      readonly bodyText: string
    }
  | {
      readonly location: 'json-pointer'
      readonly bodyText: string
    }

export type CsrfInjectionOutcome =
  | {
      readonly ok: true
      readonly headers?: Record<string, string>
      readonly bodyText?: string
    }
  | { readonly ok: false; readonly reason: CsrfBindingFailureReason }

export function injectCsrfToken(
  rule: CsrfBindingRule,
  token: string,
  target: CsrfInjectionTarget
): CsrfInjectionOutcome {
  if (!isUsableToken(token)) return { ok: false, reason: 'token-missing' }
  if (target.location !== rule.injectionLocation) {
    return { ok: false, reason: 'method-path-mismatch' }
  }
  const wireToken = rule.encoding === 'url-form' ? encodeURIComponent(token) : token

  switch (target.location) {
    case 'header': {
      const headers: Record<string, string> = { ...target.headers }
      const wanted = rule.injectionName.toLowerCase()
      for (const existing of Object.keys(headers)) {
        if (existing.toLowerCase() === wanted) {
          return { ok: false, reason: 'token-ambiguous' }
        }
      }
      headers[rule.injectionName] = wireToken
      return { ok: true, headers }
    }
    case 'form-field': {
      const params = createRuntimeSearchParams(target.bodyText)
      if (params.has(rule.injectionName)) {
        return { ok: false, reason: 'token-ambiguous' }
      }
      params.append(rule.injectionName, token)
      return { ok: true, bodyText: params.toString() }
    }
    case 'json-pointer': {
      let document: unknown
      try {
        document = JSON.parse(target.bodyText)
      } catch {
        return { ok: false, reason: 'token-missing' }
      }
      const pointer = rule.injectionName
      if (!pointer.startsWith('/')) return { ok: false, reason: 'method-path-mismatch' }
      const segments = pointer
        .split('/')
        .slice(1)
        .map((segment) => segment.replaceAll('~1', '/').replaceAll('~0', '~'))
      if (segments.length === 0) return { ok: false, reason: 'method-path-mismatch' }
      let current: unknown = document
      for (const segment of segments.slice(0, -1)) {
        if (current === null || typeof current !== 'object' || Array.isArray(current)) {
          return { ok: false, reason: 'method-path-mismatch' }
        }
        current = (current as Record<string, unknown>)[segment]
      }
      if (current === null || typeof current !== 'object' || Array.isArray(current)) {
        return { ok: false, reason: 'method-path-mismatch' }
      }
      const leaf = segments[segments.length - 1]
      if (leaf === undefined) return { ok: false, reason: 'method-path-mismatch' }
      const record = current as Record<string, unknown>
      if (Object.prototype.hasOwnProperty.call(record, leaf)) {
        return { ok: false, reason: 'token-ambiguous' }
      }
      record[leaf] = token
      return { ok: true, bodyText: JSON.stringify(document) }
    }
  }
}

/**
 * Deterministic binding check before a token may be injected into a wire
 * request. Any drift fails closed with a stable reason code for the
 * awaiting-user surface.
 */
export function assertCsrfBindingUsable(input: {
  readonly rule: CsrfBindingRule
  readonly binding: {
    readonly identityId: string
    readonly sessionId: string
    readonly sessionGeneration: number
    readonly origin: string
    readonly boundMethod: string
    readonly boundPath: string
    readonly expiresAt: string
  }
  readonly request: {
    readonly identityId: string
    readonly sessionId: string
    readonly sessionGeneration: number
    readonly url: string
    readonly method: string
  }
  readonly now: number
}):
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: CsrfBindingFailureReason } {
  const { binding, request } = input
  if (binding.identityId !== request.identityId) {
    return { ok: false, reason: 'identity-mismatch' }
  }
  if (
    binding.sessionId !== request.sessionId ||
    binding.sessionGeneration !== request.sessionGeneration
  ) {
    return { ok: false, reason: 'session-generation-mismatch' }
  }
  if (Date.parse(binding.expiresAt) <= input.now) {
    return { ok: false, reason: 'token-expired' }
  }
  const url: RuntimeUrl | undefined = parseRuntimeUrl(request.url)
  if (!url) return { ok: false, reason: 'origin-mismatch' }
  if (url.origin !== binding.origin) return { ok: false, reason: 'origin-mismatch' }
  if (
    binding.boundMethod !== request.method.toUpperCase() ||
    url.pathname !== binding.boundPath
  ) {
    return { ok: false, reason: 'method-path-mismatch' }
  }
  return { ok: true }
}
