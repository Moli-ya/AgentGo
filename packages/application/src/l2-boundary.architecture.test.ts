import { readdir, readFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from '@babel/parser'
import { describe, expect, it } from 'vitest'

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const l2Roots = [
  join(workspaceRoot, 'packages/application/src'),
  join(workspaceRoot, 'packages/domain/src/l2'),
  join(workspaceRoot, 'packages/db/src')
]
const forbidden = ['@agentgo/http-runner', '@agentgo/browser-runner']

function toRepoRelativePath(absolutePath: string): string {
  return relative(workspaceRoot, absolutePath).split(sep).join('/')
}

function isL2Source(fileName: string, relativePath: string): boolean {
  if (!/\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName)) return false
  if (/\.(?:test|spec)\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName)) return false
  return (
    relativePath.includes('/l2/') ||
    /l2-protocol-service\.ts$/u.test(relativePath) ||
    /l2-repository\.ts$/u.test(relativePath) ||
    /l2-migration\.ts$/u.test(relativePath) ||
    /l2\.ts$/u.test(relativePath)
  )
}

async function collectL2Files(): Promise<string[]> {
  const files: string[] = []
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true })
    for (const entry of entries) {
      const absolutePath = join(directory, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules') continue
        await visit(absolutePath)
        continue
      }
      const relativePath = toRepoRelativePath(absolutePath)
      if (entry.isFile() && isL2Source(entry.name, relativePath)) {
        files.push(absolutePath)
      }
    }
  }
  for (const root of l2Roots) await visit(root)
  return files
}

function importSpecifiers(source: string): string[] {
  const syntaxTree = parse(source, {
    sourceType: 'unambiguous',
    plugins: ['typescript', 'importAttributes']
  })
  const specifiers: string[] = []
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item)
      return
    }
    if (value === null || typeof value !== 'object') return
    const node = value as { type?: string; source?: { value?: string }; argument?: unknown }
    if (
      node.type &&
      ['ImportDeclaration', 'ExportAllDeclaration', 'ExportNamedDeclaration'].includes(
        node.type
      ) &&
      typeof node.source?.value === 'string'
    ) {
      specifiers.push(node.source.value)
    }
    if (node.type === 'TSImportType') visit(node.argument)
    for (const [key, child] of Object.entries(value)) {
      if (key !== 'loc' && key !== 'extra') visit(child)
    }
  }
  visit(syntaxTree)
  return specifiers
}

describe('L2 network and runner boundary', () => {
  it('does not import HTTP or browser runners from L2 protocol modules', async () => {
    const files = await collectL2Files()
    expect(files.length).toBeGreaterThan(0)
    const violations: string[] = []
    for (const file of files) {
      const source = await readFile(file, 'utf8')
      for (const specifier of importSpecifiers(source)) {
        if (forbidden.includes(specifier)) {
          violations.push(`${toRepoRelativePath(file)} -> ${specifier}`)
        }
      }
    }
    expect(violations).toEqual([])
  })
})
