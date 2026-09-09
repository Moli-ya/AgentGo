import { Buffer } from 'node:buffer'
import { parse } from '@babel/parser'
import {
  DEFAULT_STATIC_DISCOVERY_BUDGET,
  type StaticDiscoveryCandidate,
  type StaticDiscoveryResourceBudget,
  type StaticDiscoverySourceProvenance,
  type TargetScope
} from '@agentgo/contracts'
import { evaluateUrlScope } from '@agentgo/security-policy'
import { redactInventoryText } from '@agentgo/domain'
import { sanitizeDiscoveredUrl } from './html'
import { extractSourceMapCandidates } from './source-map'

interface BabelNode {
  readonly type: string
  readonly loc?: {
    readonly start: { readonly line: number; readonly column: number }
  } | null
  readonly [key: string]: unknown
}

interface WalkBudget {
  nodes: number
  readonly maxNodes: number
  readonly deadline: number
}

const HTTP_METHOD_PATTERN = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u

export function extractJavaScriptCandidates(
  source: string,
  scope: TargetScope,
  baseUrlHint: string | undefined,
  budget: StaticDiscoveryResourceBudget = DEFAULT_STATIC_DISCOVERY_BUDGET
): { readonly candidates: StaticDiscoveryCandidate[]; readonly warnings: string[] } {
  const warnings: string[] = []
  const candidates: StaticDiscoveryCandidate[] = []
  const seen = new Set<string>()
  const xhrBindings = new Set<string>()
  const nodes: BabelNode[] = []
  const startedAt = Date.now()
  let ast: { readonly comments?: ReadonlyArray<{ readonly value: string }> } & BabelNode
  try {
    ast = parse(source, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx'],
      errorRecovery: false,
      attachComment: true,
      strictMode: false
    }) as unknown as typeof ast
  } catch {
    warnings.push('JavaScript parse failed closed; no unbounded regex fallback is used.')
    return { candidates: [], warnings }
  }

  const walkBudget: WalkBudget = {
    nodes: 0,
    maxNodes: budget.maxAstNodes,
    deadline: startedAt + budget.maxParseTimeMs
  }

  const push = (candidate: StaticDiscoveryCandidate): void => {
    if (seen.has(candidate.key) || candidates.length >= budget.maxStringCandidates) return
    seen.add(candidate.key)
    candidates.push(candidate)
  }

  try {
    walk(ast, walkBudget, (node) => {
      recordXmlHttpRequestBinding(node, xhrBindings)
      nodes.push(node)
    })
    for (const node of nodes) {
      if (Date.now() > walkBudget.deadline) {
        throw new Error('JavaScript parse time budget exhausted.')
      }
      visitJsNode(node, scope, baseUrlHint, xhrBindings, push, warnings)
    }
  } catch (error) {
    warnings.push(error instanceof Error ? error.message : 'JavaScript walk aborted.')
  }

  for (const comment of ast.comments ?? []) {
    const mapping = /[#@]\s*sourceMappingURL\s*=\s*(\S+)/u.exec(comment.value)
    if (!mapping) continue
    const url = mapping[1] ?? ''
    if (url.startsWith('data:')) {
      const decoded = decodeInlineSourceMap(url, budget)
      if (!decoded.ok) {
        warnings.push(decoded.warning)
        continue
      }
      push(
        candidateFor(
          'source-map',
          'inline:application/json',
          'sourceMappingURL:inline',
          scope,
          undefined,
          'unsupported'
        )
      )
      const mapped = extractSourceMapCandidates(
        decoded.bytes,
        scope,
        baseUrlHint ?? 'generated.js',
        budget
      )
      for (const candidate of mapped.candidates) push(candidate)
      warnings.push(...mapped.warnings)
      continue
    }
    if (/^https?:\/\//iu.test(url)) {
      warnings.push('Remote sourceMappingURL is recorded and never downloaded.')
    }
    push(candidateFor('source-map', url, 'sourceMappingURL', scope, baseUrlHint, 'unsupported'))
  }

  return {
    candidates,
    warnings: warnings.map((warning) => redactInventoryText(warning, 2_048))
  }
}

function visitJsNode(
  node: BabelNode,
  scope: TargetScope,
  base: string | undefined,
  xhrBindings: ReadonlySet<string>,
  push: (candidate: StaticDiscoveryCandidate) => void,
  warnings: string[]
): void {
  const provenance = generatedProvenance(node, base)
  if (node.type === 'CallExpression') {
    const callee = calleeName(node.callee)
    const args = Array.isArray(node.arguments) ? node.arguments : []
    if (isFetchCallee(callee)) {
      const request = staticFetchRequest(args)
      if (request?.url) {
        if (request.method === undefined) {
          warnings.push('fetch() method is dynamic; endpoint inventoried without a claimed method.')
        }
        push(
          candidateFor(
            'http-endpoint',
            request.url,
            'fetch()',
            scope,
            base,
            'inventory-only',
            request.method,
            provenance
          )
        )
      }
    }
    if (isXmlHttpRequestOpen(node.callee, xhrBindings) && args.length >= 2) {
      const method = staticHttpMethod(args[0])
      const xhrUrl = staticString(args[1])
      if (xhrUrl) {
        if (method === undefined) {
          warnings.push(
            'XMLHttpRequest.open() method is dynamic; endpoint inventoried without a claimed method.'
          )
        }
        push(
          candidateFor(
            'http-endpoint',
            xhrUrl,
            'xhr.open()',
            scope,
            base,
            'inventory-only',
            method,
            provenance
          )
        )
      }
    }
    if (callee === 'navigator.serviceWorker.register' || callee === 'serviceWorker.register') {
      const url = staticString(args[0])
      if (url) {
        push(
          candidateFor(
            'worker',
            url,
            'serviceWorker.register()',
            scope,
            base,
            'unsupported',
            undefined,
            provenance
          )
        )
        warnings.push('Service Worker script is inventoried and never registered or executed.')
      }
    }
    if (callee === 'importScripts') {
      let found = false
      for (const argument of args) {
        const url = staticString(argument)
        if (!url) continue
        found = true
        push(
          candidateFor(
            'worker',
            url,
            'importScripts()',
            scope,
            base,
            'unsupported',
            undefined,
            provenance
          )
        )
      }
      if (found) {
        warnings.push('Worker importScripts() resource is inventoried and never loaded or executed.')
      }
    }
  }
  if (node.type === 'NewExpression') {
    const callee = calleeName(node.callee)
    const args = Array.isArray(node.arguments) ? node.arguments : []
    const url = staticString(args[0])
    if (callee === 'WebSocket' && url) {
      push(
        candidateFor(
          'websocket',
          url,
          'new WebSocket()',
          scope,
          base,
          'unsupported',
          undefined,
          provenance
        )
      )
    }
    if (callee === 'EventSource' && url) {
      push(
        candidateFor(
          'sse',
          url,
          'new EventSource()',
          scope,
          base,
          'unsupported',
          undefined,
          provenance
        )
      )
    }
    if ((callee === 'Worker' || callee === 'SharedWorker') && url) {
      push(
        candidateFor(
          'worker',
          url,
          `new ${callee}()`,
          scope,
          base,
          'unsupported',
          undefined,
          provenance
        )
      )
      warnings.push(`${callee} script is inventoried and never loaded or executed.`)
    }
  }
  if (node.type === 'StringLiteral' && typeof node.value === 'string' && looksLikeGraphql(node.value)) {
    push(
      candidateFor(
        'graphql',
        node.value.slice(0, 200),
        'graphql-string',
        scope,
        base,
        'unsupported',
        undefined,
        provenance
      )
    )
    warnings.push('GraphQL operation string inventoried as unsupported protocol hint.')
  }
}

function candidateFor(
  kind: StaticDiscoveryCandidate['kind'],
  rawUrl: string,
  location: string,
  scope: TargetScope,
  base: string | undefined,
  capabilityStatus: StaticDiscoveryCandidate['capabilityStatus'],
  method?: string,
  sourceProvenance?: StaticDiscoverySourceProvenance
): StaticDiscoveryCandidate {
  const url = sanitizeDiscoveredUrl(rawUrl, base)
  const verdict = evaluateUrlScope(rawUrl, scope, base)
  return {
    key: `${kind}:${method ?? '-'}:${url}`,
    kind,
    ...(method ? { method } : {}),
    url,
    location,
    ...(sourceProvenance ? { sourceProvenance } : {}),
    confidence: verdict.ok ? 0.6 : 0.25,
    capabilityStatus,
    secretClassification: /(?:token|secret|password|authorization)/iu.test(url)
      ? 'likely-secret'
      : 'none',
    warnings: verdict.ok ? [] : [`scope:${verdict.reason}`]
  }
}

function walk(node: BabelNode, budget: WalkBudget, visit: (node: BabelNode) => void): void {
  if (Date.now() > budget.deadline) {
    throw new Error('JavaScript parse time budget exhausted.')
  }
  budget.nodes += 1
  if (budget.nodes > budget.maxNodes) {
    throw new Error('JavaScript AST node budget exhausted.')
  }
  visit(node)
  for (const value of Object.values(node)) {
    if (!value || typeof value !== 'object') continue
    if (Array.isArray(value)) {
      for (const entry of value) {
        if (entry && typeof entry === 'object' && 'type' in entry) {
          walk(entry as BabelNode, budget, visit)
        }
      }
    } else if ('type' in value) {
      walk(value as BabelNode, budget, visit)
    }
  }
}

function recordXmlHttpRequestBinding(node: BabelNode, bindings: Set<string>): void {
  if (node.type === 'VariableDeclarator' && isXmlHttpRequestConstruction(node.init)) {
    const name = identifierName(node.id)
    if (name) bindings.add(name)
  }
  if (node.type === 'AssignmentExpression' && isXmlHttpRequestConstruction(node.right)) {
    const name = identifierName(node.left)
    if (name) bindings.add(name)
  }
}

function isXmlHttpRequestConstruction(node: unknown): boolean {
  return isNode(node, 'NewExpression') && calleeName(node.callee) === 'XMLHttpRequest'
}

function isXmlHttpRequestOpen(callee: unknown, bindings: ReadonlySet<string>): boolean {
  if (!isNode(callee, 'MemberExpression') || calleeName(callee.property) !== 'open') return false
  if (isXmlHttpRequestConstruction(callee.object)) return true
  const receiver = identifierName(callee.object)
  return receiver !== undefined && bindings.has(receiver)
}

function staticFetchRequest(args: readonly unknown[]): { url?: string; method?: string } | undefined {
  const first = args[0]
  if (isNode(first, 'NewExpression') && calleeName(first.callee) === 'Request') {
    const requestArgs = Array.isArray(first.arguments) ? first.arguments : []
    const url = staticString(requestArgs[0])
    if (!url) return undefined
    if (requestArgs.length < 2) return { url, method: 'GET' }
    return { url, method: methodFromFetchOptions(requestArgs[1]) }
  }
  const url = staticString(first)
  if (!url) return undefined
  if (args.length < 2) return { url, method: 'GET' }
  return { url, method: methodFromFetchOptions(args[1]) }
}

function methodFromFetchOptions(node: unknown): string | undefined {
  if (!isNode(node, 'ObjectExpression') || !Array.isArray(node.properties)) return undefined
  const methodProperty = node.properties.find((property) => {
    if (!isNode(property, 'ObjectProperty')) return false
    return staticPropertyName(property.key) === 'method'
  })
  if (!methodProperty || !isNode(methodProperty, 'ObjectProperty')) return 'GET'
  return staticHttpMethod(methodProperty.value)
}

function staticHttpMethod(node: unknown): string | undefined {
  const value = staticString(node)?.toUpperCase()
  return value && HTTP_METHOD_PATTERN.test(value) ? value : undefined
}

function staticString(node: unknown): string | undefined {
  if (!node || typeof node !== 'object' || !('type' in node)) return undefined
  const value = node as {
    type: string
    value?: unknown
    quasis?: unknown
    expressions?: unknown
  }
  if (value.type === 'StringLiteral' && typeof value.value === 'string') return value.value
  if (
    value.type === 'TemplateLiteral' &&
    Array.isArray(value.expressions) &&
    value.expressions.length === 0
  ) {
    const quasis = Array.isArray(value.quasis) ? value.quasis : []
    const first = quasis[0]
    if (first && typeof first === 'object' && 'value' in first) {
      const quasiValue = (first as { value?: { cooked?: unknown } }).value
      if (quasiValue && typeof quasiValue.cooked === 'string') return quasiValue.cooked
    }
  }
  return undefined
}

function staticPropertyName(node: unknown): string | undefined {
  return identifierName(node) ?? staticString(node)
}

function isFetchCallee(name: string): boolean {
  return (
    name === 'fetch' ||
    name === 'globalThis.fetch' ||
    name === 'window.fetch' ||
    name === 'self.fetch'
  )
}

function identifierName(node: unknown): string | undefined {
  if (!isNode(node, 'Identifier')) return undefined
  return typeof node.name === 'string' ? node.name : undefined
}

function isNode(node: unknown, type: string): node is BabelNode {
  return Boolean(node && typeof node === 'object' && 'type' in node && node.type === type)
}

function calleeName(node: unknown): string {
  if (!node || typeof node !== 'object' || !('type' in node)) return ''
  const value = node as { type: string; name?: string; property?: unknown; object?: unknown }
  if (value.type === 'Identifier') return value.name ?? ''
  if (value.type === 'MemberExpression' || value.type === 'OptionalMemberExpression') {
    const object = calleeName(value.object)
    const property = calleeName(value.property) || staticString(value.property) || ''
    return property ? `${object}.${property}` : object
  }
  return ''
}

function generatedProvenance(
  node: BabelNode,
  generatedFile: string | undefined
): StaticDiscoverySourceProvenance | undefined {
  const start = node.loc?.start
  if (!start) return undefined
  return {
    generated: {
      file: redactInventoryText(generatedFile ?? 'generated.js', 2_048),
      line: start.line,
      column: start.column
    }
  }
}

function decodeInlineSourceMap(
  url: string,
  budget: StaticDiscoveryResourceBudget
):
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly warning: string } {
  const match = /^data:([^,]*),(.*)$/su.exec(url)
  if (!match) return { ok: false, warning: 'Inline source map data URL is malformed.' }
  const metadata = (match[1] ?? '').toLowerCase()
  const payload = match[2] ?? ''
  const mediaType = metadata.split(';')[0] || 'text/plain'
  if (mediaType !== 'application/json' && mediaType !== 'application/source-map+json') {
    return { ok: false, warning: `Inline source map media type ${mediaType} is unsupported.` }
  }
  try {
    const bytes = metadata.split(';').includes('base64')
      ? new Uint8Array(Buffer.from(payload, 'base64'))
      : new TextEncoder().encode(decodeURIComponent(payload))
    const maxBytes = Math.min(budget.maxFileBytes, budget.maxTotalBytes)
    if (bytes.byteLength > maxBytes) {
      return { ok: false, warning: 'Inline source map exceeds the static discovery byte budget.' }
    }
    return { ok: true, bytes }
  } catch {
    return { ok: false, warning: 'Inline source map decoding failed closed.' }
  }
}

function looksLikeGraphql(value: string): boolean {
  return /^\s*(?:query|mutation|subscription)\s/u.test(value)
}
