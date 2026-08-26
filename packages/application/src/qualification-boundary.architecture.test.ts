import { readFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from '@babel/parser'
import { describe, expect, it } from 'vitest'

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const applicationRoot = join(workspaceRoot, 'packages/application/src')
const evaluationPackage = '@agentgo/evaluation'

function toRepoRelativePath(absolutePath: string): string {
  return relative(workspaceRoot, absolutePath).split(sep).join('/')
}

function isProductionSourceFile(fileName: string): boolean {
  return (
    /\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName) &&
    !/\.(?:test|spec)\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName)
  )
}

async function collectApplicationProductionFiles(): Promise<string[]> {
  const { readdir } = await import('node:fs/promises')
  const files: string[] = []
  const visit = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true })
    for (const entry of entries) {
      const absolutePath = join(directory, entry.name)
      if (entry.isDirectory()) {
        await visit(absolutePath)
        continue
      }
      if (entry.isFile() && isProductionSourceFile(entry.name)) {
        files.push(absolutePath)
      }
    }
  }
  await visit(applicationRoot)
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

describe('qualification production boundary', () => {
  it('does not let the application composition import fixture or evaluation packages', async () => {
    const files = await collectApplicationProductionFiles()
    expect(files.length).toBeGreaterThan(0)

    const violations: string[] = []
    for (const file of files) {
      const source = await readFile(file, 'utf8')
      for (const specifier of importSpecifiers(source)) {
        if (
          specifier === evaluationPackage ||
          specifier.startsWith(`${evaluationPackage}/`)
        ) {
          violations.push(`${toRepoRelativePath(file)} -> ${specifier}`)
        }
      }
    }

    expect(violations).toEqual([])
  })
})
