import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

type ImplementationState =
  | 'implemented-v1'
  | 'partial-v1'
  | 'inventory-partial'
  | 'not-started'
  | 'policy-forbidden'

type SafetyMode =
  | 'inventory-only'
  | 'signal-only'
  | 'active-l1'
  | 'active-l2'
  | 'fixture-only'
  | 'forbidden'

type QualificationState =
  | 'legacy-v1-unqualified'
  | 'not-qualified'
  | 'policy-constrained-unqualified'
  | 'policy-ineligible'

interface CoverageEntry {
  id: string
  title: string
  standardMapping: string
  implementationState: ImplementationState
  declaredModes: SafetyMode[]
  safetyCeilingByEnvironment: Record<string, SafetyMode>
  allowedEnvironments: string[]
  requiredCapabilityIds: string[]
  stopConditionRefs: string[]
  qualificationState: QualificationState
  ownerWorkPackage: string
  enhancementWaves: string[]
  constraints: string[]
}

interface CoverageCatalog {
  catalogSchemaVersion: string
  catalogRole: string
  sources: Record<string, string>
  lifecycleBoundary: {
    definitionRegistryCreated: boolean
    executionActivationCatalogCreated: boolean
    emittedSupportClaims: boolean
  }
  entrySchema: {
    required: string[]
    implementationStates: string[]
    safetyModes: string[]
    qualificationStates: string[]
    enhancementWaves: string[]
  }
  environmentDefinitions: Record<string, string>
  capabilityDefinitions: Record<string, string>
  stopConditionDefinitions: Record<string, { source: string; meaning: string }>
  ownerWorkPackageDefinitions: Record<string, string>
  sourceAudit: {
    wstgV42: {
      version: string
      status: string
      categoryIndex: Record<string, string[]>
      pendingVerificationEntryIds: string[]
      noIndependentStableEntryIds: string[]
      limitationOwnerWorkPackage: string
    }
    asvsV500: {
      version: string
      status: string
      verifiedRequirementIndex: Record<string, string[]>
      pendingVerificationEntryIds: string[]
      limitation: string
      limitationOwnerWorkPackage: string
    }
    srcHunter: {
      status: string
      categoryIndex: Record<string, string[]>
      limitation: string
    }
    owaspTop10_2025: {
      version: string
      status: string
      categoryIndex: Record<string, string[]>
      limitation: string
      limitationOwnerWorkPackage: string
    }
  }
  apiTop10Coverage: Record<string, string[]>
  entries: CoverageEntry[]
}

interface MatrixRow {
  id: string
  title: string
  standardMapping: string
  implementationState: string
  modeText: string
  gap: string
  waveText: string
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const matrixPath = resolve(
  repositoryRoot,
  'docs/planning/web-vulnerability-coverage-matrix.md'
)
const catalogPath = resolve(
  repositoryRoot,
  'docs/planning/web-vulnerability-coverage-catalog.json'
)
const matrixText = readFileSync(matrixPath, 'utf8')
const catalogText = readFileSync(catalogPath, 'utf8')
const catalog = JSON.parse(catalogText) as CoverageCatalog

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function sorted(values: string[]): string[] {
  return [...values].sort((left, right) => left.localeCompare(right))
}

function parseMatrixRows(markdown: string): MatrixRow[] {
  return markdown
    .split(/\r?\n/u)
    .filter((line) => /^\|\s*WEB-[A-Z0-9-]+\s*\|/u.test(line))
    .map((line) => {
      const cells = line
        .split('|')
        .slice(1, -1)
        .map((cell) => cell.trim())
      if (cells.length !== 7) {
        throw new Error(`Expected seven matrix cells: ${line}`)
      }
      return {
        id: cells[0]!,
        title: cells[1]!,
        standardMapping: cells[2]!,
        implementationState: cells[3]!.replaceAll('`', ''),
        modeText: cells[4]!,
        gap: cells[5]!,
        waveText: cells[6]!
      }
    })
}

function modesFrom(text: string): string[] {
  return unique(
    [...text.matchAll(/`(active-l1|active-l2|signal-only|fixture-only|inventory-only|forbidden)`/gu)]
      .map((match) => match[1]!)
  )
}

function wavesFrom(text: string): string[] {
  return unique([...text.matchAll(/\bW[1-7]\b/gu)].map((match) => match[0]))
}

function apiRefsFrom(text: string): string[] {
  return unique(
    (text.match(/API\d+(?:\/API\d+)*:2023/gu) ?? []).flatMap((segment) =>
      [...segment.matchAll(/API(\d+)/gu)].map((match) => `API${match[1]!}:2023`)
    )
  )
}

const matrixRows = parseMatrixRows(matrixText)
const matrixById = new Map(matrixRows.map((row) => [row.id, row]))
const catalogById = new Map(catalog.entries.map((entry) => [entry.id, entry]))

describe('Day 1 web vulnerability coverage catalog', () => {
  it('preserves the exact 98-row Markdown identity set without duplicates', () => {
    const matrixIds = matrixRows.map((row) => row.id)
    const catalogIds = catalog.entries.map((entry) => entry.id)

    expect(matrixIds).toHaveLength(98)
    expect(catalogIds).toHaveLength(98)
    expect(new Set(matrixIds).size).toBe(98)
    expect(new Set(catalogIds).size).toBe(98)
    expect(catalogIds.every((id) => /^WEB-[A-Z0-9]+(?:-[A-Z0-9]+)+$/u.test(id))).toBe(true)
    expect(sorted(catalogIds)).toEqual(sorted(matrixIds))
  })

  it('validates required fields, enums, current-state facts, and planning-only lifecycle', () => {
    expect(catalog.catalogSchemaVersion).toBe('1.0.0')
    expect(catalog.catalogRole).toBe('day1-planning-metadata-only')
    expect(catalog.lifecycleBoundary).toEqual({
      definitionRegistryCreated: false,
      executionActivationCatalogCreated: false,
      emittedSupportClaims: false
    })
    expect(catalog.entrySchema.required).toEqual([
      'id',
      'title',
      'standardMapping',
      'implementationState',
      'declaredModes',
      'safetyCeilingByEnvironment',
      'allowedEnvironments',
      'requiredCapabilityIds',
      'stopConditionRefs',
      'qualificationState',
      'ownerWorkPackage',
      'enhancementWaves',
      'constraints'
    ])

    const stateCounts: Record<string, number> = {}
    for (const entry of catalog.entries) {
      const matrixRow = matrixById.get(entry.id)
      expect(matrixRow, entry.id).toBeDefined()
      for (const field of catalog.entrySchema.required) {
        expect(Object.hasOwn(entry, field), `${entry.id}.${field}`).toBe(true)
      }

      expect(entry.title).toBe(matrixRow?.title)
      expect(entry.standardMapping).toBe(matrixRow?.standardMapping)
      expect(entry.implementationState).toBe(matrixRow?.implementationState)
      expect(catalog.entrySchema.implementationStates).toContain(entry.implementationState)
      expect(entry.declaredModes).toEqual(modesFrom(matrixRow?.modeText ?? ''))
      expect(entry.declaredModes).toHaveLength(new Set(entry.declaredModes).size)
      expect(entry.declaredModes.every((mode) => catalog.entrySchema.safetyModes.includes(mode))).toBe(true)
      expect(entry.enhancementWaves).toEqual(wavesFrom(matrixRow?.waveText ?? ''))
      expect(entry.enhancementWaves).toHaveLength(new Set(entry.enhancementWaves).size)
      expect(entry.enhancementWaves.every((wave) => catalog.entrySchema.enhancementWaves.includes(wave))).toBe(true)
      expect(catalog.entrySchema.qualificationStates).toContain(entry.qualificationState)
      expect(entry.qualificationState).not.toBe('qualified')

      if (['implemented-v1', 'partial-v1', 'inventory-partial'].includes(entry.implementationState)) {
        expect(entry.qualificationState).toBe('legacy-v1-unqualified')
      } else if (entry.implementationState === 'not-started') {
        expect(entry.qualificationState).toBe('not-qualified')
      } else if (entry.declaredModes.includes('forbidden')) {
        expect(entry.qualificationState).toBe('policy-ineligible')
      } else {
        expect(entry.qualificationState).toBe('policy-constrained-unqualified')
      }

      stateCounts[entry.implementationState] = (stateCounts[entry.implementationState] ?? 0) + 1
    }

    expect(stateCounts).toEqual({
      'partial-v1': 5,
      'not-started': 87,
      'inventory-partial': 1,
      'policy-forbidden': 5
    })
  })

  it('resolves every environment, capability, stop condition, and singular owner reference', () => {
    for (const source of Object.values(catalog.sources)) {
      expect(existsSync(resolve(repositoryRoot, source)), source).toBe(true)
    }
    for (const definition of Object.values(catalog.stopConditionDefinitions)) {
      expect(existsSync(resolve(repositoryRoot, definition.source.split('#')[0]!)), definition.source).toBe(true)
      expect(definition.meaning.length).toBeGreaterThan(0)
    }

    for (const entry of catalog.entries) {
      expect(entry.allowedEnvironments).toEqual(Object.keys(entry.safetyCeilingByEnvironment))
      expect(entry.allowedEnvironments).toHaveLength(new Set(entry.allowedEnvironments).size)
      expect(entry.requiredCapabilityIds.length).toBeGreaterThan(0)
      expect(entry.requiredCapabilityIds).toHaveLength(new Set(entry.requiredCapabilityIds).size)
      expect(entry.stopConditionRefs.length).toBeGreaterThan(0)
      expect(entry.stopConditionRefs).toHaveLength(new Set(entry.stopConditionRefs).size)
      expect(typeof entry.ownerWorkPackage).toBe('string')
      expect(entry.ownerWorkPackage.length).toBeGreaterThan(0)
      expect(catalog.ownerWorkPackageDefinitions[entry.ownerWorkPackage], entry.id).toBeDefined()

      for (const environment of entry.allowedEnvironments) {
        expect(catalog.environmentDefinitions[environment], `${entry.id}:${environment}`).toBeDefined()
        const ceiling = entry.safetyCeilingByEnvironment[environment]
        expect(entry.declaredModes, `${entry.id}:${environment}:${ceiling}`).toContain(ceiling)
      }
      for (const capabilityId of entry.requiredCapabilityIds) {
        expect(catalog.capabilityDefinitions[capabilityId], `${entry.id}:${capabilityId}`).toBeDefined()
      }
      for (const stopRef of entry.stopConditionRefs) {
        expect(catalog.stopConditionDefinitions[stopRef], `${entry.id}:${stopRef}`).toBeDefined()
      }

      const realCeiling = entry.safetyCeilingByEnvironment['authorized-real']
      expect(realCeiling).not.toBe('active-l2')
      expect(realCeiling).not.toBe('fixture-only')
      expect(realCeiling).not.toBe('forbidden')
      if (entry.declaredModes.includes('forbidden')) {
        expect(entry.allowedEnvironments).toEqual([])
        expect(entry.safetyCeilingByEnvironment).toEqual({})
      }
    }
  })

  it('covers API Security Top 10 2023 exactly through concrete catalog IDs', () => {
    const expectedApiIds = Array.from({ length: 10 }, (_, index) => `API${index + 1}:2023`)
    expect(sorted(Object.keys(catalog.apiTop10Coverage))).toEqual(sorted(expectedApiIds))

    for (const apiId of expectedApiIds) {
      const expectedIds = matrixRows
        .filter((row) => apiRefsFrom(row.standardMapping).includes(apiId))
        .map((row) => row.id)
      const catalogIds = catalog.apiTop10Coverage[apiId] ?? []
      expect(catalogIds.length, apiId).toBeGreaterThan(0)
      expect(catalogIds).toHaveLength(new Set(catalogIds).size)
      expect(sorted(catalogIds)).toEqual(sorted(expectedIds))
      expect(catalogIds.every((id) => catalogById.has(id))).toBe(true)
    }

    expect(matrixRows.some((row) => /^其他(?:漏洞|风险)?$/u.test(row.title))).toBe(false)
    expect(catalog.entries.some((entry) => /^其他(?:漏洞|风险)?$/u.test(entry.title))).toBe(false)
  })

  it('indexes WSTG and SRC categories while leaving unverified ASVS and Top 10 mappings pending', () => {
    const expectedWstgIndex: Record<string, string[]> = {}
    for (const row of matrixRows) {
      for (const match of row.standardMapping.matchAll(/\b([A-Z]{4})-\d/gu)) {
        const category = match[1]!
        expectedWstgIndex[category] ??= []
        if (!expectedWstgIndex[category].includes(row.id)) {
          expectedWstgIndex[category].push(row.id)
        }
      }
    }

    expect(catalog.sourceAudit.wstgV42.version).toBe('4.2')
    expect(catalog.sourceAudit.wstgV42.status).toBe('category-indexed-with-explicit-limitations')
    expect(catalog.sourceAudit.wstgV42.categoryIndex).toEqual(expectedWstgIndex)
    expect(sorted(catalog.sourceAudit.wstgV42.pendingVerificationEntryIds)).toEqual(
      sorted(
        matrixRows
          .filter((row) => /WSTG v4\.2 对应映射待核对|其他精确 ID 待核对/u.test(row.standardMapping))
          .map((row) => row.id)
      )
    )
    expect(sorted(catalog.sourceAudit.wstgV42.noIndependentStableEntryIds)).toEqual(
      sorted(
        matrixRows
          .filter((row) => row.standardMapping.includes('WSTG v4.2 无独立'))
          .map((row) => row.id)
      )
    )

    const pendingAsvsIds = matrixRows
      .filter((row) => row.standardMapping.includes('ASVS v5.0.0 条目待核对'))
      .map((row) => row.id)
    expect(catalog.sourceAudit.asvsV500).toMatchObject({
      version: '5.0.0',
      status: 'pending-verification',
      verifiedRequirementIndex: {},
      limitationOwnerWorkPackage: 'SOURCE-CROSSWALK'
    })
    expect(sorted(catalog.sourceAudit.asvsV500.pendingVerificationEntryIds)).toEqual(sorted(pendingAsvsIds))
    expect(
      matrixRows
        .filter((row) => row.standardMapping.includes('ASVS v5.0.0'))
        .every((row) => row.standardMapping.includes('ASVS v5.0.0 条目待核对'))
    ).toBe(true)

    expect(Object.keys(catalog.sourceAudit.srcHunter.categoryIndex)).toEqual([
      'authorized-src',
      'api',
      'authentication',
      'protocol',
      'business-logic',
      'llm-web'
    ])
    for (const [category, ids] of Object.entries(catalog.sourceAudit.srcHunter.categoryIndex)) {
      expect(ids.length, category).toBeGreaterThan(0)
      expect(ids).toHaveLength(new Set(ids).size)
      expect(ids.every((id) => catalogById.has(id))).toBe(true)
    }
    for (const [category, ids] of Object.entries(catalog.sourceAudit.wstgV42.categoryIndex)) {
      expect(ids.length, category).toBeGreaterThan(0)
      expect(ids).toHaveLength(new Set(ids).size)
      expect(ids.every((id) => catalogById.has(id))).toBe(true)
    }

    expect(catalog.sourceAudit.owaspTop10_2025).toMatchObject({
      version: '2025',
      status: 'pending-verification',
      categoryIndex: {},
      limitationOwnerWorkPackage: 'SOURCE-CROSSWALK'
    })
    expect(catalog.sourceAudit.owaspTop10_2025.limitation.length).toBeGreaterThan(0)
    expect(matrixText).toContain('OWASP Top 10 2025')
    expect(matrixText).toContain('`pending-verification`')

    for (const owner of [
      catalog.sourceAudit.wstgV42.limitationOwnerWorkPackage,
      catalog.sourceAudit.asvsV500.limitationOwnerWorkPackage,
      catalog.sourceAudit.owaspTop10_2025.limitationOwnerWorkPackage
    ]) {
      expect(catalog.ownerWorkPackageDefinitions[owner], owner).toBeDefined()
    }
  })

  it('locks the TRACE and SSRF safety-boundary corrections', () => {
    const methods = catalogById.get('WEB-CONF-09')
    const methodsRow = matrixById.get('WEB-CONF-09')
    expect(methods?.safetyCeilingByEnvironment).toEqual({
      'authorized-real': 'active-l1',
      'isolated-fixture': 'fixture-only'
    })
    expect(methods?.constraints).toContain('authorized-real:no-trace')
    expect(methods?.constraints).toContain('trace:isolated-fixture-only')
    expect(methods?.requiredCapabilityIds).toContain('request.options')
    expect(methods?.requiredCapabilityIds).not.toContain('request.trace')
    expect(methodsRow?.gap).toContain('真实目标不发送 TRACE')

    const ssrf = catalogById.get('WEB-SRV-01')
    const ssrfRow = matrixById.get('WEB-SRV-01')
    expect(ssrf?.safetyCeilingByEnvironment).toEqual({
      'authorized-real': 'active-l1',
      'scoped-internal-test-service': 'active-l2'
    })
    expect(ssrf?.constraints).toContain('controlled-oob:active-l1')
    expect(ssrf?.constraints).toContain('scoped-internal-test-service:active-l2')
    expect(ssrf?.stopConditionRefs).toContain('POLICY-SSRF-BOUNDARY')
    expect(ssrfRow?.modeText).toContain('项目控制 OOB `active-l1`')
    expect(ssrfRow?.gap).toContain('私网/metadata 地址拒绝')
  })
})
