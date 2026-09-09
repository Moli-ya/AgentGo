export interface PathValueMutationView {
  readonly kind: 'path'
  readonly name: string
  readonly segmentIndex: number
  readonly value: string
}

function encodeRfc3986Component(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  )
}

function pathSegments(url: URL): string[] {
  if (url.pathname === '/' || url.pathname === '') return []
  return url.pathname
    .slice(1)
    .split('/')
    .map((segment) => decodeURIComponent(segment))
}

export function pathValueMutation(
  urlValue: string,
  name: string,
  value: string
): { desiredUrl: string; mutation: PathValueMutationView } {
  const url = new URL(urlValue)
  const segments = pathSegments(url)
  if (segments.length === 0) {
    throw new Error(`Reviewed path selector ${name} is absent from the endpoint URL.`)
  }
  const segmentIndex = segments.length - 1
  segments[segmentIndex] = value
  url.pathname = `/${segments.map(encodeRfc3986Component).join('/')}`
  return {
    desiredUrl: url.toString(),
    mutation: {
      kind: 'path',
      name,
      segmentIndex,
      value
    }
  }
}
