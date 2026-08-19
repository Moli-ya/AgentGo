/**
 * Builds the V1 inert XSS marker. The payload only writes the random marker to
 * the current offline DOM and contains no outbound or persistence capability.
 */
export function buildInertXssMarkerPayload(marker: string): string {
  if (!/^agx_[a-f0-9]{16,64}$/u.test(marker)) {
    throw new Error('XSS marker must be an AgentGo random hexadecimal marker.')
  }
  return `"><svg data-agentgo-marker="${marker}" onload="document.documentElement.setAttribute('data-agentgo-xss','${marker}')"></svg>`
}
