const CALLBACK_TOKEN_PARAMETER = 'agentgo_token'
const CALLBACK_REVIEW_PLACEHOLDER = 'agentgo-callback-review-placeholder'

export function controlledCallbackInventoryUrl(urlValue: string): string {
  const url = new URL(urlValue)
  url.searchParams.set(CALLBACK_TOKEN_PARAMETER, CALLBACK_REVIEW_PLACEHOLDER)
  return url.toString()
}

export function controlledCallbackTokenParameter(): string {
  return CALLBACK_TOKEN_PARAMETER
}
