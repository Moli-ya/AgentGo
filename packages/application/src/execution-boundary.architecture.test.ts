import { readdir, readFile } from 'node:fs/promises'
import { dirname, extname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from '@babel/parser'
import { describe, expect, it } from 'vitest'

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const runnerBoundaries = [
  {
    packageName: '@agentgo/browser-runner',
    relativeRoot: 'packages/browser-runner'
  },
  {
    packageName: '@agentgo/http-runner',
    relativeRoot: 'packages/http-runner'
  }
] as const
const runnerPackages = runnerBoundaries.map(
  (boundary) => boundary.packageName
)
const sourceContainers = [
  join(workspaceRoot, 'apps'),
  join(workspaceRoot, 'packages')
]
const excludedRunnerRoots = runnerBoundaries.map(
  (boundary) => boundary.relativeRoot
)
const allowedRunnerImporters = new Set([
  'apps/desktop/src/main/index.ts',
  'packages/application/src/execution-policy.ts',
  'packages/application/src/execution-service.ts',
  'packages/evaluation/src/run-local-benchmark.ts'
])
const allowedRunnerDependencyManifests = new Set([
  'apps/desktop/package.json',
  'packages/application/package.json',
  'packages/evaluation/package.json'
])
const dependencySections = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies'
] as const
const nonLiteralDynamicImport = '<non-literal import()>'
const nonLiteralRequire = '<non-literal require()>'

type RunnerPackage = (typeof runnerPackages)[number]
type ForbiddenRunnerReference =
  | RunnerPackage
  | typeof nonLiteralDynamicImport
  | typeof nonLiteralRequire

interface RunnerImportViolation {
  readonly reference: ForbiddenRunnerReference
  readonly relativePath: string
}

interface RunnerDependencyViolation {
  readonly packageName: RunnerPackage
  readonly relativePath: string
}

interface AstNode {
  readonly type: string
  readonly [key: string]: unknown
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function toRepoRelativePath(absolutePath: string): string {
  return relative(workspaceRoot, absolutePath).split(sep).join('/')
}

function isInsideExcludedRunner(relativePath: string): boolean {
  return excludedRunnerRoots.some(
    (root) => relativePath === root || relativePath.startsWith(`${root}/`)
  )
}

function isProductionSourceFile(fileName: string): boolean {
  return (
    /\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName) &&
    !/\.(?:test|spec)\.(?:[cm]?[jt]s|[jt]sx)$/u.test(fileName)
  )
}

async function collectProductionSourceFiles(): Promise<string[]> {
  const files: string[] = []

  const visit = async (
    directory: string,
    insideSourceRoot: boolean
  ): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true })
    entries.sort((left, right) => compareText(left.name, right.name))
    for (const entry of entries) {
      const absolutePath = join(directory, entry.name)
      const relativePath = toRepoRelativePath(absolutePath)
      if (entry.isDirectory()) {
        if (
          entry.name === 'node_modules' ||
          isInsideExcludedRunner(relativePath)
        ) {
          continue
        }
        await visit(absolutePath, insideSourceRoot || entry.name === 'src')
        continue
      }
      if (
        insideSourceRoot &&
        entry.isFile() &&
        isProductionSourceFile(entry.name)
      ) {
        files.push(absolutePath)
      }
    }
  }

  for (const container of sourceContainers) {
    await visit(container, false)
  }
  return files.sort((left, right) =>
    compareText(toRepoRelativePath(left), toRepoRelativePath(right))
  )
}

async function collectWorkspacePackageManifests(): Promise<string[]> {
  const manifests = [join(workspaceRoot, 'package.json')]

  for (const container of sourceContainers) {
    const entries = await readdir(container, { withFileTypes: true })
    entries.sort((left, right) => compareText(left.name, right.name))
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const packageDirectory = join(container, entry.name)
      const packageEntries = await readdir(packageDirectory, {
        withFileTypes: true
      })
      if (
        packageEntries.some(
          (packageEntry) =>
            packageEntry.isFile() && packageEntry.name === 'package.json'
        )
      ) {
        manifests.push(join(packageDirectory, 'package.json'))
      }
    }
  }

  return manifests.sort((left, right) =>
    compareText(toRepoRelativePath(left), toRepoRelativePath(right))
  )
}

function packageFromSpecifier(specifier: string): RunnerPackage | undefined {
  return runnerPackages.find(
    (packageName) =>
      specifier === packageName || specifier.startsWith(`${packageName}/`)
  )
}

function packageFromRelativeSpecifier(
  specifier: string,
  importingFile: string | undefined
): RunnerPackage | undefined {
  if (!importingFile || !specifier.startsWith('.')) return undefined
  const resolvedRelativePath = toRepoRelativePath(
    resolve(dirname(importingFile), specifier)
  )
  return runnerBoundaries.find(
    (boundary) =>
      resolvedRelativePath === boundary.relativeRoot ||
      resolvedRelativePath.startsWith(`${boundary.relativeRoot}/`)
  )?.packageName
}

function runnerDependenciesFromManifest(source: string): RunnerPackage[] {
  const manifest: unknown = JSON.parse(source)
  if (manifest === null || typeof manifest !== 'object') return []

  const dependencies = new Set<RunnerPackage>()
  for (const section of dependencySections) {
    const entries = Reflect.get(manifest, section)
    if (entries === null || typeof entries !== 'object') continue
    for (const packageName of runnerPackages) {
      if (Object.prototype.hasOwnProperty.call(entries, packageName)) {
        dependencies.add(packageName)
      }
    }
  }
  return [...dependencies].sort(compareText)
}

function isAstNode(value: unknown): value is AstNode {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    typeof Reflect.get(value, 'type') === 'string'
  )
}

function stringLiteralValue(value: unknown): string | undefined {
  if (
    !isAstNode(value) ||
    !['StringLiteral', 'Literal'].includes(value.type)
  ) {
    return undefined
  }
  const literal = Reflect.get(value, 'value')
  return typeof literal === 'string' ? literal : undefined
}

function findForbiddenRunnerImports(
  source: string,
  importingFile?: string
): ForbiddenRunnerReference[] {
  const extension = extname(importingFile ?? 'source.ts').toLowerCase()
  const isTypeScript = ['.ts', '.tsx', '.mts', '.cts'].includes(extension)
  const isJsx = ['.tsx', '.jsx'].includes(extension)
  const syntaxTree = parse(source, {
    sourceType: 'unambiguous',
    plugins: [
      ...(isTypeScript ? (['typescript'] as const) : []),
      ...(isJsx ? (['jsx'] as const) : []),
      'decorators-legacy',
      'importAttributes'
    ]
  })
  const matches = new Set<ForbiddenRunnerReference>()

  const recordSpecifier = (value: unknown): void => {
    const specifier = stringLiteralValue(value)
    if (!specifier) return
    const packageName =
      packageFromSpecifier(specifier) ??
      packageFromRelativeSpecifier(specifier, importingFile)
    if (packageName) matches.add(packageName)
  }

  const recordLoaderArgument = (
    value: unknown,
    nonLiteralReference: typeof nonLiteralDynamicImport | typeof nonLiteralRequire
  ): void => {
    const specifier = stringLiteralValue(value)
    if (specifier === undefined) {
      matches.add(nonLiteralReference)
      return
    }
    recordSpecifier(value)
  }

  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item)
      return
    }
    if (!isAstNode(value)) return

    switch (value.type) {
      case 'ImportDeclaration':
      case 'ExportAllDeclaration':
      case 'ExportNamedDeclaration':
        recordSpecifier(value.source)
        break
      case 'ImportExpression':
        recordLoaderArgument(value.source, nonLiteralDynamicImport)
        break
      case 'TSImportType':
        recordSpecifier(value.argument)
        break
      case 'TSImportEqualsDeclaration': {
        const moduleReference = value.moduleReference
        if (
          isAstNode(moduleReference) &&
          moduleReference.type === 'TSExternalModuleReference'
        ) {
          recordSpecifier(moduleReference.expression)
        }
        break
      }
      case 'CallExpression': {
        const callee = value.callee
        const isDynamicImport = isAstNode(callee) && callee.type === 'Import'
        const isRequire =
          isAstNode(callee) &&
          callee.type === 'Identifier' &&
          callee.name === 'require'
        if (isDynamicImport || isRequire) {
          const argumentsValue = value.arguments
          if (Array.isArray(argumentsValue)) {
            recordLoaderArgument(
              argumentsValue[0],
              isDynamicImport ? nonLiteralDynamicImport : nonLiteralRequire
            )
          } else {
            matches.add(
              isDynamicImport ? nonLiteralDynamicImport : nonLiteralRequire
            )
          }
        }
        break
      }
    }

    for (const [key, child] of Object.entries(value)) {
      if (key !== 'loc' && key !== 'extra') visit(child)
    }
  }

  visit(syntaxTree)
  return [...matches].sort(compareText)
}

describe('execution boundary architecture', () => {
  it('recognizes type re-exports, import types, and dynamic imports', () => {
    const matches = findForbiddenRunnerImports(`
      import type { HttpRunner } from '@agentgo/http-runner'
      export type { BrowserRunner } from '@agentgo/browser-runner'
      type Result = import('@agentgo/http-runner').HttpExecutionResult
      const lazy = import('@agentgo/browser-runner/runtime')
      const legacy = require('@agentgo/http-runner')
    `)

    expect(matches).toEqual([
      '@agentgo/browser-runner',
      '@agentgo/http-runner'
    ])
    expect(
      findForbiddenRunnerImports(`
        // import '@agentgo/http-runner'
        const packageLabel = '@agentgo/browser-runner'
      `)
    ).toEqual([])
  })

  it('rejects import-equals, relative Runner paths, and non-literal loaders', () => {
    const importingFile = join(
      workspaceRoot,
      'packages/application/src/boundary-bypass.cts'
    )
    const matches = findForbiddenRunnerImports(
      `
        import HttpRunner = require('@agentgo/http-runner')
        export { BrowserRunner } from '../../browser-runner/src/index.js'
        const packageName = '@agentgo/http-runner'
        const lazy = import(packageName)
        const legacy = require(packageName)
      `,
      importingFile
    )

    expect(matches).toEqual([
      nonLiteralDynamicImport,
      nonLiteralRequire,
      '@agentgo/browser-runner',
      '@agentgo/http-runner'
    ])
  })

  it('scans all supported production extensions without scanning tests', () => {
    const productionFiles = [
      'index.ts',
      'index.tsx',
      'index.mts',
      'index.cts',
      'index.js',
      'index.jsx',
      'index.mjs',
      'index.cjs'
    ]
    for (const fileName of productionFiles) {
      expect(isProductionSourceFile(fileName)).toBe(true)
      expect(findForbiddenRunnerImports(
        `import '@agentgo/http-runner'`,
        join(workspaceRoot, 'packages/application/src', fileName)
      )).toEqual(['@agentgo/http-runner'])
    }

    for (const fileName of ['index.test.ts', 'index.spec.mts', 'index.test.cjs']) {
      expect(isProductionSourceFile(fileName)).toBe(false)
    }
  })

  it('recognizes Runner dependencies in every dependency section', () => {
    for (const section of dependencySections) {
      expect(
        runnerDependenciesFromManifest(
          JSON.stringify({
            [section]: {
              '@agentgo/http-runner': 'workspace:*'
            }
          })
        )
      ).toEqual(['@agentgo/http-runner'])
    }

    expect(
      runnerDependenciesFromManifest(
        JSON.stringify({
          dependencies: {
            '@agentgo/http-runner': 'workspace:*'
          },
          optionalDependencies: {
            '@agentgo/browser-runner': 'workspace:*'
          },
          peerDependencies: {
            unrelated: '1.0.0'
          }
        })
      )
    ).toEqual([
      '@agentgo/browser-runner',
      '@agentgo/http-runner'
    ])
  })

  it('keeps direct Runner imports behind the unified execution boundary', async () => {
    const files = await collectProductionSourceFiles()
    expect(files.length).toBeGreaterThan(0)

    const violations: RunnerImportViolation[] = []
    for (const file of files) {
      const relativePath = toRepoRelativePath(file)
      if (allowedRunnerImporters.has(relativePath)) continue
      const source = await readFile(file, 'utf8')
      for (const reference of findForbiddenRunnerImports(source, file)) {
        violations.push({ reference, relativePath })
      }
    }
    violations.sort((left, right) =>
      compareText(
        `${left.relativePath}\u0000${left.reference}`,
        `${right.relativePath}\u0000${right.reference}`
      )
    )

    if (violations.length > 0) {
      throw new Error(
        [
          'Direct Runner imports are restricted to the unified execution boundary and composition roots:',
          ...violations.map(
            (violation) =>
              `- ${violation.relativePath} -> ${violation.reference}`
          )
        ].join('\n')
      )
    }
  })

  it('keeps Runner package dependencies on an explicit manifest allowlist', async () => {
    const manifests = await collectWorkspacePackageManifests()
    expect(manifests.length).toBeGreaterThan(0)

    const violations: RunnerDependencyViolation[] = []
    for (const manifest of manifests) {
      const relativePath = toRepoRelativePath(manifest)
      if (allowedRunnerDependencyManifests.has(relativePath)) continue
      const source = await readFile(manifest, 'utf8')
      for (const packageName of runnerDependenciesFromManifest(source)) {
        violations.push({ packageName, relativePath })
      }
    }
    violations.sort((left, right) =>
      compareText(
        `${left.relativePath}\u0000${left.packageName}`,
        `${right.relativePath}\u0000${right.packageName}`
      )
    )

    if (violations.length > 0) {
      throw new Error(
        [
          'Runner dependencies are restricted to approved execution-boundary and composition packages:',
          ...violations.map(
            (violation) =>
              `- ${violation.relativePath} -> ${violation.packageName}`
          )
        ].join('\n')
      )
    }
  })
})
