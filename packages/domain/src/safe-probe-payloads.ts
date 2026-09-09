/**
 * Builds inert XSS markers. Payloads only write a random marker onto the current
 * offline DOM and contain no outbound, storage, cookie, persistence, or
 * harassment capability.
 */

export const XSS_INERT_MARKER_PATTERN = /^agx_[a-f0-9]{16,64}$/u

export type InertXssMarkerContext =
  | 'html'
  | 'attribute'
  | 'url'
  | 'script'
  | 'json'
  | 'dom'

const FORBIDDEN_XSS_CAPABILITY =
  /(?:\bfetch\b|xmlhttprequest|websocket|sendbeacon|navigator\.sendbeacon|document\.cookie|localstorage|sessionstorage|indexeddb|document\.write|innerhtml|\beval\s*\(|new\s+function\b|\bimport\s*\(|javascript:|data:text\/html|alert\s*\(|prompt\s*\(|confirm\s*\(|window\.open|location\s*=|opener|parent\.location|childnodes|src\s*=\s*['"]https?:)/i

export class InertXssPayloadError extends Error {
  readonly code = 'inert-xss-payload-rejected'

  constructor(message: string) {
    super(message)
    this.name = 'InertXssPayloadError'
  }
}

export function assertXssMarker(marker: string): void {
  if (!XSS_INERT_MARKER_PATTERN.test(marker)) {
    throw new InertXssPayloadError(
      'XSS marker must be an AgentGo random hexadecimal marker.'
    )
  }
}

export function assertInertXssPayload(payload: string): void {
  if (payload.length === 0 || payload.length > 512) {
    throw new InertXssPayloadError('XSS marker payload length is outside the allowed set.')
  }
  if (FORBIDDEN_XSS_CAPABILITY.test(payload)) {
    throw new InertXssPayloadError(
      'XSS marker payload contains network, storage, cookie, persistence, or harassment capability.'
    )
  }
  if (!payload.includes('data-agentgo-marker') && !payload.startsWith('#agx_')) {
    throw new InertXssPayloadError('XSS marker payload is missing the inert local proof.')
  }
}

function htmlMarker(marker: string): string {
  return `"><svg data-agentgo-marker="${marker}" onload="document.documentElement.setAttribute('data-agentgo-xss','${marker}')"></svg>`
}

/**
 * Builds the V1 inert XSS marker. The default HTML context payload is the
 * Day15/Day18 40-case proof string and must not change.
 */
export function buildInertXssMarkerPayload(
  marker: string,
  context: InertXssMarkerContext = 'html'
): string {
  assertXssMarker(marker)
  const payload =
    context === 'dom' || context === 'url'
      ? `#${marker}`
      : context === 'json'
        ? htmlMarker(marker).replaceAll('"', '\\"')
        : htmlMarker(marker)
  assertInertXssPayload(payload)
  return payload
}

export function xssMarkerContextFromParameter(name: string): InertXssMarkerContext {
  if (/(?:hash|fragment|sink|dom)/i.test(name)) return 'dom'
  if (/(?:callback|return|redirect|url|href|src)/i.test(name)) return 'url'
  if (/(?:onclick|onerror|attr|attribute)/i.test(name)) return 'attribute'
  if (/(?:script|js|callback)/i.test(name)) return 'script'
  if (/(?:json|payload|body)/i.test(name)) return 'json'
  return 'html'
}
