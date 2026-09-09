import { preflightExternalOpenApiHoldout } from './external-openapi-holdout'

function parseBaseUrl(argv: readonly string[]): string {
  const index = argv.indexOf('--base-url')
  const value = index >= 0 ? argv[index + 1] : undefined
  if (!value || value.startsWith('--')) {
    throw new Error('Usage: --base-url http://127.0.0.1:<port>')
  }
  if (argv.length !== index + 2) {
    throw new Error('Unknown or incomplete external holdout preflight argument.')
  }
  return value
}

const result = await preflightExternalOpenApiHoldout({
  baseUrl: parseBaseUrl(process.argv.slice(2))
})
console.log(JSON.stringify(result, null, 2))
