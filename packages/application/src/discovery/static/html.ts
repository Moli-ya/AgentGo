import {
  DEFAULT_STATIC_DISCOVERY_BUDGET,
  type StaticDiscoveryCandidate,
  type StaticDiscoveryResourceBudget,
  type TargetScope
} from '@agentgo/contracts'
import { evaluateUrlScope } from '@agentgo/security-policy'
import { redactInventoryText, redactInventoryUrlPreview } from '@agentgo/domain'

const FORM_PATTERN = /<form\b([^>]*)>([\s\S]*?)<\/form>/giu
const SOURCEMAP_HINT = /[#@]\s*sourceMappingURL\s*=\s*(\S+)/gu
const INLINE_HANDLER_PATTERN = /\bon[a-z]+\s*=\s*(?:"[^"]*"|'[^']*')/giu

export function extractHtmlCandidates(
  html: string,
  scope: TargetScope,
  baseUrlHint: string | undefined,
  budget: StaticDiscoveryResourceBudget = DEFAULT_STATIC_DISCOVERY_BUDGET
): { readonly candidates: StaticDiscoveryCandidate[]; readonly warnings: string[] } {
  const startedAt = Date.now()
  const warnings: string[] = []
  const candidates: StaticDiscoveryCandidate[] = []
  const seen = new Set<string>()
  const baseHref = firstAttribute(html, 'base', 'href') ?? baseUrlHint

  const push = (candidate: StaticDiscoveryCandidate): void => {
    if (Date.now() - startedAt > budget.maxParseTimeMs) {
      warnings.push('HTML parse time budget exhausted.')
      return
    }
    if (candidates.length >= budget.maxStringCandidates) {
      warnings.push('HTML candidate budget reached.')
      return
    }
    if (seen.has(candidate.key)) return
    seen.add(candidate.key)
    candidates.push(candidate)
  }

  collectTagUrls(html, 'a', ['href'], 'http-endpoint', scope, baseHref, push, warnings)
  collectTagUrls(html, 'link', ['href'], 'http-endpoint', scope, baseHref, push, warnings)
  collectTagUrls(html, 'script', ['src'], 'script', scope, baseHref, push, warnings)
  collectTagUrls(html, 'iframe', ['src'], 'iframe', scope, baseHref, push, warnings)
  collectTagUrls(html, 'img', ['src'], 'http-endpoint', scope, baseHref, push, warnings)

  for (const match of html.matchAll(
    /<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\d+\s*;\s*url=([^"'>\s]+)/giu
  )) {
    addUrlCandidate(
      match[1] ?? '',
      'http-endpoint',
      'meta[refresh]',
      scope,
      baseHref,
      push,
      warnings
    )
  }

  for (const match of html.matchAll(FORM_PATTERN)) {
    if (candidates.length >= budget.maxStringCandidates) break
    const attrs = match[1] ?? ''
    const action = attributeValue(attrs, 'action') ?? baseHref ?? ''
    const method = (attributeValue(attrs, 'method') ?? 'GET').toUpperCase()
    addUrlCandidate(action, 'form', 'form[action]', scope, baseHref, push, warnings, method)
  }

  for (const match of html.matchAll(SOURCEMAP_HINT)) {
    addUrlCandidate(
      match[1] ?? '',
      'source-map',
      'html-sourceMappingURL',
      scope,
      baseHref,
      push,
      warnings
    )
  }

  const handlers = html.match(INLINE_HANDLER_PATTERN) ?? []
  if (handlers.length > 0) {
    warnings.push(
      `${Math.min(handlers.length, 32)} inline event handler(s) recorded as untrusted; they are not executed.`
    )
  }

  if (/<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy/iu.test(html)) {
    warnings.push('CSP meta is inventoried as untrusted page policy, not an execution grant.')
  }

  return {
    candidates: candidates.map(sanitizeCandidate),
    warnings: warnings.map((warning) => redactInventoryText(warning, 2_048))
  }
}

function collectTagUrls(
  html: string,
  tag: string,
  names: readonly string[],
  kind: StaticDiscoveryCandidate['kind'],
  scope: TargetScope,
  base: string | undefined,
  push: (candidate: StaticDiscoveryCandidate) => void,
  warnings: string[]
): void {
  const re = new RegExp(`<${tag}\\b([^>]*)>`, 'giu')
  for (const match of html.matchAll(re)) {
    const attrs = match[1] ?? ''
    const rel = attributeValue(attrs, 'rel')
    const resolvedKind =
      tag === 'link' && rel && /manifest|preload|modulepreload/iu.test(rel) ? 'manifest' : kind
    for (const name of names) {
      const url = attributeValue(attrs, name)
      if (url) addUrlCandidate(url, resolvedKind, `${tag}[${name}]`, scope, base, push, warnings)
    }
  }
}

function addUrlCandidate(
  raw: string,
  kind: StaticDiscoveryCandidate['kind'],
  location: string,
  scope: TargetScope,
  base: string | undefined,
  push: (candidate: StaticDiscoveryCandidate) => void,
  warnings: string[],
  method?: string
): void {
  const trimmed = raw.trim()
  if (!trimmed || trimmed.startsWith('javascript:') || trimmed.startsWith('vbscript:')) {
    if (trimmed.startsWith('javascript:') || trimmed.startsWith('vbscript:')) {
      warnings.push(`Rejected active URL scheme at ${location}.`)
    }
    return
  }
  if (trimmed.startsWith('data:')) {
    warnings.push(`Inline data URL at ${location} is not downloaded; recorded as inventory-only.`)
  }
  const verdict = evaluateUrlScope(trimmed, scope, base)
  const url = sanitizeDiscoveredUrl(trimmed, base)
  const capabilityStatus =
    kind === 'websocket' || kind === 'sse' || kind === 'graphql' || kind === 'source-map'
      ? 'unsupported'
      : 'inventory-only'
  const secretClassification = /(?:token|secret|password|authorization|api[-_]?key)/iu.test(url)
    ? 'likely-secret'
    : 'none'
  if (!verdict.ok) {
    warnings.push(`URL at ${location} is ${verdict.reason}.`)
  }
  push({
    key: `${kind}:${method ?? 'GET'}:${url}`,
    kind,
    ...(method ? { method } : {}),
    url,
    location: redactInventoryText(location, 256),
    confidence: verdict.ok ? 0.7 : 0.3,
    capabilityStatus,
    secretClassification,
    warnings: verdict.ok ? [] : [`scope:${verdict.reason}`]
  })
}

function firstAttribute(html: string, tag: string, name: string): string | undefined {
  const match = new RegExp(
    `<${tag}\\b[^>]*\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`,
    'iu'
  ).exec(html)
  return match?.[1] ?? match?.[2] ?? match?.[3]
}

function attributeValue(attrs: string, name: string): string | undefined {
  const match = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'iu').exec(
    attrs
  )
  return match?.[1] ?? match?.[2] ?? match?.[3]
}

export function sanitizeDiscoveredUrl(url: string, base?: string): string {
  try {
    const absolute = /^[a-z][a-z0-9+.-]*:/iu.test(url)
      ? url
      : base
        ? new URL(url, base).href
        : url
    return redactInventoryUrlPreview(absolute)
  } catch {
    return redactInventoryText(url, 2_048)
  }
}

function sanitizeCandidate(candidate: StaticDiscoveryCandidate): StaticDiscoveryCandidate {
  return {
    ...candidate,
    url: redactInventoryText(candidate.url, 16_384),
    warnings: candidate.warnings.map((warning) => redactInventoryText(warning, 2_048))
  }
}
