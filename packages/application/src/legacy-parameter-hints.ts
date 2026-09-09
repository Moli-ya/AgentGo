import type { LegacyV1VulnerabilityFamily } from '@agentgo/contracts'

export const LEGACY_PARAMETER_HINTS: Record<LegacyV1VulnerabilityFamily, RegExp> = {
  sqli: /(?:^|_)(?:id|uid|user|item|product|order|page|sort|filter|query|search|q)(?:$|_)/i,
  xss: /(?:^|_)(?:q|query|search|keyword|name|message|comment|title|return|redirect)(?:$|_)/i,
  ssrf: /(?:^|_)(?:url|uri|target|endpoint|callback|webhook|fetch|image|avatar|src)(?:$|_)/i,
  idor: /(?:^|_)(?:id|uid|user_id|account_id|resource_id|order_id|document_id|file_id)(?:$|_)/i
}
