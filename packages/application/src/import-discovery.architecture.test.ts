import { readdir, readFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from '@babel/parser'
import { describe, expect, it } from 'vitest'

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const roots = [
  join(workspaceRoot, 'packages/application/src/importers'),
  join(workspaceRoot, 'packages/application/src/discovery'),
  join(workspaceRoot, 'packages/application/src')
]
const forbidden = [
  '@agentgo/http-runner',
  '@agentgo/browser-runner',
  '@agentgo/model-gateway',
  'node:http',
  'node:https',
  'node:dns',
  'node:net',
  'node:dgram',
  'undici',
  'node:child_process'
]
const files = new Set([
  'import-service.ts',
  'asset-manifest-service.ts',
  'extraction-rule-service.ts',
  'static-discovery-service.ts',
  'inventory-merge-service.ts',
  'dependency-graph-service.ts'
])

function toRepoRelativePath(absolutePath: string): string {
  return relative(workspaceRoot, absolutePath).split(sep).join('/')
}

function isImportDiscoverySource(fileName: string, relativePath: string): boolean {
  if (!/\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName)) return false
  if (/\.(?:test|spec)\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName)) return false
  return (
    relativePath.includes('/importers/') ||
    relativePath.includes('/discovery/') ||
    files.has(fileName)
  )
}

async function collectFiles(): Promise<string[]> {
  const collected: string[] = []
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
      if (entry.isFile() && isImportDiscoverySource(entry.name, relativePath)) {
        collected.push(absolutePath)
      }
    }
  }
  for (const root of roots) await visit(root)
  return [...new Set(collected)]
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

describe('Import and static discovery network boundary', () => {
  it('does not import runners or the model gateway', async () => {
    const collected = await collectFiles()
    expect(collected.length).toBeGreaterThan(5)
    const violations: string[] = []
    for (const file of collected) {
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
