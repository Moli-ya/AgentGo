/**
 * The domain package stays environment-agnostic: URL primitives are taken
 * from globalThis with a minimal structural interface instead of DOM or
 * Node type dependencies (same convention as inventory.ts).
 */

export interface RuntimeUrl {
  readonly protocol: string
  readonly hostname: string
  readonly pathname: string
  readonly origin: string
}

export interface RuntimeUrlSearchParams {
  getAll(name: string): string[]
  has(name: string): boolean
  append(name: string, value: string): void
  toString(): string
}

interface RuntimeUrlConstructor {
  new (value: string): RuntimeUrl
}

interface RuntimeUrlSearchParamsConstructor {
  new (value: string): RuntimeUrlSearchParams
}

const globals = globalThis as unknown as {
  URL: RuntimeUrlConstructor
  URLSearchParams: RuntimeUrlSearchParamsConstructor
}

export function parseRuntimeUrl(value: string): RuntimeUrl | undefined {
  try {
    return new globals.URL(value)
  } catch {
    return undefined
  }
}

export function createRuntimeSearchParams(value: string): RuntimeUrlSearchParams {
  return new globals.URLSearchParams(value)
}
