export interface CanonicalTargetUrl {
  readonly href: string
  readonly url: URL
  readonly hostname: string
  readonly port: number
}

export type CanonicalTargetUrlResult =
  | { readonly ok: true; readonly value: CanonicalTargetUrl }
  | { readonly ok: false; readonly reason: string }

const DEFAULT_HTTP_PORT = 80
const DEFAULT_HTTPS_PORT = 443
const IPV4_DECIMAL_OCTET = /^(?:0|[1-9]\d{0,2})$/
const DNS_LABEL = /^(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i

function fail(reason: string): CanonicalTargetUrlResult {
  return { ok: false, reason }
}

function hasDisallowedControlOrWhitespace(value: string): boolean {
  return /[\u0000-\u001f\u007f\u00a0\u1680\u2000-\u200b\u2028\u2029\u202f\u205f\u3000\ufeff]/.test(
    value
  )
}

function extractHostLiteral(input: string): string | undefined {
  const match = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(input)
  return match?.[1]
}

function isStandardIpv4Literal(hostname: string): boolean {
  const parts = hostname.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    if (!IPV4_DECIMAL_OCTET.test(part)) return false
    const value = Number(part)
    return value >= 0 && value <= 255 && String(value) === part
  })
}

function isDnsHostname(hostname: string): boolean {
  if (hostname.length === 0 || hostname.length > 253 || hostname.startsWith('.') || hostname.endsWith('.')) {
    return false
  }
  return hostname.split('.').every((label) => DNS_LABEL.test(label) && label.length > 0)
}

function isDoubleEncoded(value: string): boolean {
  let once: string
  try {
    once = decodeURIComponent(value)
  } catch {
    return true
  }
  if (once === value) return false
  let twice: string
  try {
    twice = decodeURIComponent(once)
  } catch {
    return true
  }
  return twice !== once
}

function reconstructCanonicalHref(url: URL): string | undefined {
  if (url.username !== '' || url.password !== '' || url.hash !== '') {
    return undefined
  }
  const protocol = url.protocol.toLowerCase()
  if (protocol !== 'http:' && protocol !== 'https:') return undefined
  const defaultPort = protocol === 'https:' ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT
  const port = url.port === '' ? defaultPort : Number(url.port)
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return undefined
  const hostname = url.hostname
  const host =
    hostname.includes(':') && !hostname.startsWith('[') ? `[${hostname}]` : hostname
  const portSuffix = port === defaultPort ? '' : `:${port}`
  return `${protocol}//${host}${portSuffix}${url.pathname}${url.search}`
}

export function canonicalizeTargetUrl(input: unknown): CanonicalTargetUrlResult {
  if (typeof input !== 'string' || input.length === 0 || input.length > 16_384) {
    return fail('目标 URL 无法解析。')
  }
  if (input.trim() !== input || input.includes('\\') || hasDisallowedControlOrWhitespace(input)) {
    return fail('目标 URL 含有反斜杠、空白或控制字符，已失败关闭。')
  }

  let parsed: URL
  try {
    parsed = new URL(input)
  } catch {
    return fail('目标 URL 无法解析。')
  }

  if (parsed.username || parsed.password) {
    return fail('目标 URL 不得包含 userinfo 或凭据。')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return fail('只允许 HTTP 或 HTTPS Web 目标。')
  }
  if (parsed.hash !== '') {
    return fail('目标 URL 不得包含 fragment。')
  }
  if (parsed.hostname.includes('%') || /%[0-9a-z]+\]/i.test(input)) {
    return fail('IPv6 zone identifier 不被允许。')
  }

  const hostLiteral = extractHostLiteral(input)
  if (hostLiteral === undefined || hostLiteral.includes('\\') || hostLiteral.includes('@')) {
    return fail('目标主机无法安全解析。')
  }
  const rawHost = hostLiteral.startsWith('[')
    ? undefined
    : hostLiteral.replace(/:\d+$/, '')
  if (rawHost !== undefined && /[^\x00-\x7f]/.test(rawHost) && /xn--/i.test(rawHost)) {
    return fail('IDN 与 punycode 混用，已失败关闭。')
  }
  // Non-standard IPv4 rejection applies only to numeric-looking hosts; DNS
  // names such as 07.example.com stay governed by the DNS label rule below.
  if (rawHost !== undefined && /^[\da-fx.]+$/i.test(rawHost)) {
    if (/^(?:0x|0[0-7])/i.test(rawHost)) {
      return fail('IPv4 非标准表示不被允许。')
    }
    if (/^\d+$/.test(rawHost) || rawHost.includes('0x') || /(?:^|\.)0\d/.test(rawHost)) {
      return fail('IPv4 非标准表示不被允许。')
    }
  }

  const hostname = parsed.hostname.toLowerCase()
  if (hostname.includes(':')) {
    if (!hostname.startsWith('[') && input.includes('%')) {
      return fail('IPv6 zone identifier 不被允许。')
    }
  } else if (hostname.split('.').every((part) => /^\d+$/.test(part))) {
    if (!isStandardIpv4Literal(hostname)) {
      return fail('IPv4 非标准表示不被允许。')
    }
    const originalHost = hostLiteral.replace(/:\d+$/, '')
    if (originalHost !== hostname && originalHost !== `[${hostname}]`) {
      return fail('IPv4 非标准表示不被允许。')
    }
  } else if (!isDnsHostname(hostname)) {
    const originalHost = hostLiteral.replace(/^\[|\]$/g, '').split(':')[0] ?? ''
    const hasUnicode = /[^\x00-\x7f]/.test(originalHost)
    const hasPunycode = /(?:^|\.)xn--/i.test(hostname)
    if (!(hasUnicode && hasPunycode && hostname.includes('xn--'))) {
      return fail('主机名无法安全归一化。')
    }
  }

  if (isDoubleEncoded(parsed.pathname) || isDoubleEncoded(parsed.search)) {
    return fail('双编码路径或查询不被允许。')
  }

  parsed.hash = ''
  const canonicalHref = reconstructCanonicalHref(parsed)
  if (!canonicalHref) {
    return fail('目标 URL 无法归一化为规范形式。')
  }

  let roundTrip: URL
  try {
    roundTrip = new URL(canonicalHref)
  } catch {
    return fail('目标 URL 重解析失败。')
  }
  roundTrip.hash = ''
  const roundTripHref = reconstructCanonicalHref(roundTrip)
  if (roundTripHref !== canonicalHref || roundTrip.href !== canonicalHref) {
    return fail('目标 URL 重解析后发生变化，已失败关闭。')
  }

  const port =
    roundTrip.port === ''
      ? roundTrip.protocol === 'https:'
        ? DEFAULT_HTTPS_PORT
        : DEFAULT_HTTP_PORT
      : Number(roundTrip.port)

  return {
    ok: true,
    value: {
      href: canonicalHref,
      url: roundTrip,
      hostname: roundTrip.hostname,
      port
    }
  }
}
