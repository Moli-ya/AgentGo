import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { FileCredentialStore, type SecretProtector } from './credential-store'

const directories: string[] = []
const xorProtector: SecretProtector = {
  isAvailable: () => true,
  protect: (value) =>
    Buffer.from(Buffer.from(value, 'utf8').map((byte) => byte ^ 0x5a)),
  unprotect: (value) => Buffer.from(value.map((byte) => byte ^ 0x5a)).toString('utf8')
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('FileCredentialStore', () => {
  it('stores only protected bytes and can rotate a credential', () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-credentials-'))
    directories.push(directory)
    const filePath = join(directory, 'credentials.json')
    const store = new FileCredentialStore(filePath, xorProtector)

    const created = store.save({
      kind: 'model-api-key',
      label: 'OpenAI-compatible',
      secret: 'sk-super-secret'
    })
    expect(store.get(created.id)).toBe('sk-super-secret')
    expect(readFileSync(filePath, 'utf8')).not.toContain('sk-super-secret')

    store.save({
      id: created.id,
      kind: 'model-api-key',
      label: 'OpenAI-compatible',
      secret: 'sk-rotated'
    })
    expect(store.get(created.id)).toBe('sk-rotated')
    expect(store.list()).toHaveLength(1)
  })
})
