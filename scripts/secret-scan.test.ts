import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { scanSecretFiles, scanSecretText } from './secret-scan'

describe('secret scan', () => {
  it('identifies credentials without exposing the match or a prefix', () => {
    const secret = 'gh' + 'p_' + 'Abcd1234'.repeat(5)
    const findings = scanSecretText('root.ts', `line one\nconst token = '${secret}'`)
    expect(findings).toEqual([{ file: 'root.ts', name: 'github-token', line: 2 }])
    expect(JSON.stringify(findings)).not.toContain(secret.slice(0, 8))
    expect(scanSecretText('root.ts', 'sk-' + 'proj-' + 'Abcd1234'.repeat(5))).toHaveLength(1)
  })

  it('includes root configuration and hidden environment files while excluding generated dependencies', async () => {
    const root = await mkdtemp(join(tmpdir(), 'agentgo-secret-scan-'))
    try {
      await mkdir(join(root, 'node_modules'))
      await writeFile(join(root, '.env.local'), 'API_KEY=fixture_private_value_123\nPASSWORD=${PASSWORD}\n')
      await writeFile(join(root, '.gitignore'), 'token=' + 'gh' + 'p_' + 'Abcd1234'.repeat(5))
      await writeFile(join(root, 'settings.toml'), 'token="' + 'gh' + 'p_' + 'Abcd1234'.repeat(5) + '"')
      await writeFile(join(root, 'node_modules', '.env'), 'PASSWORD=fixture_private_value_123')
      const result = await scanSecretFiles(root)
      expect(result.scannedFiles).toBe(3)
      expect(result.findings.map((item) => item.file).sort()).toEqual([
        '.env.local',
        '.gitignore',
        'settings.toml'
      ])
      expect(JSON.stringify(result)).not.toContain('ghp_')
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })
})
