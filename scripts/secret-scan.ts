import { readdir, readFile } from 'node:fs/promises'
import { basename, join, relative, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const ROOT = resolve(import.meta.dirname, '..')
const SKIP_DIR_NAMES = new Set([
  '.git', 'node_modules', 'dist', 'out', 'release', 'benchmark-results',
  '.turbo', 'coverage'
])
const ROOT_CONFIG_FILE_NAMES = new Set([
  '.editorconfig',
  '.gitattributes',
  '.gitignore',
  '.npmrc',
  '.yarnrc',
  'Dockerfile',
  'package.json',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml'
])

const PATTERNS: ReadonlyArray<{ name: string; regex: RegExp }> = [
  { name: 'pem-private-key', regex: /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
  { name: 'aws-access-key', regex: /(?:AKIA|ASIA)[0-9A-Z]{16}/g },
  { name: 'github-token', regex: /(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{40,})/g },
  { name: 'slack-token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'provider-api-key', regex: /\bsk-(?:(?:proj|svcacct|ant-api\d+)-)?[A-Za-z0-9_-]{32,}/g }
]

export interface SecretScanFinding {
  readonly file: string
  readonly name: string
  readonly line: number
}

/** Findings contain locations only: scanning a secret must never print any part of it. */
export function scanSecretText(file: string, text: string): SecretScanFinding[] {
  const findings: SecretScanFinding[] = []
  for (const pattern of PATTERNS) {
    for (const match of text.matchAll(pattern.regex)) {
      findings.push({ file, name: pattern.name, line: text.slice(0, match.index).split('\n').length })
    }
  }
  if (basename(file).startsWith('.env')) {
    for (const [index, line] of text.split(/\r?\n/u).entries()) {
      const assignment = /^\s*(?:export\s+)?[A-Z0-9_]*(?:API_KEY|TOKEN|PASSWORD|SECRET)[A-Z0-9_]*\s*=\s*["']?([^"'\s#]+)/iu.exec(line)
      const value = assignment?.[1]
      if (value && value.length >= 8 && !/^(?:\$\{|<|REDACTED|replace[-_ ]|your[-_ ]|example|placeholder)/iu.test(value)) {
        findings.push({ file, name: 'environment-credential', line: index + 1 })
      }
    }
  }
  return findings
}

export async function scanSecretFiles(root: string): Promise<{ scannedFiles: number; findings: SecretScanFinding[] }> {
  const files: string[] = []
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory() && !SKIP_DIR_NAMES.has(entry.name)) await walk(path)
      else if (entry.isFile() && (
        /\.(?:[cm]?[jt]sx?|json|md|ps1|ya?ml|toml|ini|conf|config|pem|key)$/iu.test(entry.name) ||
        entry.name.startsWith('.env') ||
        (directory === root && ROOT_CONFIG_FILE_NAMES.has(entry.name))
      )) files.push(path)
    }
  }
  await walk(root)
  const findings: SecretScanFinding[] = []
  for (const file of files) {
    findings.push(...scanSecretText(relative(root, file).replaceAll('\\', '/'), await readFile(file, 'utf8')))
  }
  return { scannedFiles: files.length, findings }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await scanSecretFiles(ROOT)
  console.log(JSON.stringify({ status: result.findings.length ? 'failed' : 'passed', ...result }))
  if (result.findings.length) process.exitCode = 1
}
