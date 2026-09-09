export interface QueryValueMutationView {
  readonly kind: 'query'
  readonly name: string
  readonly occurrence: 0
  readonly value: string
}

export function queryValueMutation(
  urlValue: string,
  name: string,
  value: string
): { desiredUrl: string; mutation: QueryValueMutationView } {
  const url = new URL(urlValue)
  const entries = [...url.searchParams.entries()]
  let mutated = false
  url.search = ''
  for (const [entryName, entryValue] of entries) {
    if (!mutated && entryName === name) {
      url.searchParams.append(entryName, value)
      mutated = true
      continue
    }
    url.searchParams.append(entryName, entryValue)
  }
  if (!mutated) {
    throw new Error(`Reviewed query selector ${name} is absent from the endpoint URL.`)
  }
  return {
    desiredUrl: url.toString(),
    mutation: {
      kind: 'query',
      name,
      occurrence: 0,
      value
    }
  }
}
