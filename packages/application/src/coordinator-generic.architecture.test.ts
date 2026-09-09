import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const coordinatorPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  'scan-coordinator.ts'
)

const forbiddenQuotedFamilies = /['"](?:sqli|xss|ssrf|idor|security\.headers)['"]/u
const forbiddenSymbols = [
  'assessSqli',
  'assessXss',
  'assessSsrf',
  'assessIdor',
  'buildInertXssMarkerPayload',
  'AND 1=1',
  'agentgo_token',
  '@agentgo/http-runner',
  '@agentgo/browser-runner'
]

describe('generic Coordinator architecture', () => {
  it('keeps validation I/O out of family switches, payloads, and runners', async () => {
    const source = await readFile(coordinatorPath, 'utf8')
    expect(forbiddenQuotedFamilies.test(source)).toBe(false)
    for (const symbol of forbiddenSymbols) {
      expect(source.includes(symbol), symbol).toBe(false)
    }
    expect(source).toContain('compileLegacyParityPlan')
    expect(source).toContain('ValidationPlanExecutor')
    expect(source).toContain('DetectorService')
    expect(source).toContain('CandidateCompiler')
    expect(source).toContain('FindingAssembler')
  })
})
