import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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
    expect(created.generation).toBe(0)
    expect(readFileSync(filePath, 'utf8')).not.toContain('sk-super-secret')

    const rotated = store.save({
      id: created.id,
      kind: 'model-api-key',
      label: 'OpenAI-compatible',
      secret: 'sk-rotated'
    })
    expect(store.get(created.id)).toBe('sk-rotated')
    expect(rotated.generation).toBe(1)
    expect(store.list()[0]?.generation).toBe(1)
    expect(store.list()).toHaveLength(1)
    expect(() =>
      store.save({
        id: 'missing-old-id',
        kind: 'model-api-key',
        label: 'must-not-recreate',
        secret: 'secret'
      })
    ).toThrow(/missing credential/i)
  })

  it('reads version 1 stores as generation zero and writes version 2 on rotation', () => {
    const directory = mkdtempSync(join(tmpdir(), 'agentgo-credentials-v1-'))
    directories.push(directory)
    const filePath = join(directory, 'credentials.json')
    const timestamp = '2026-01-01T00:00:00.000Z'
    writeFileSync(
      filePath,
      JSON.stringify({
        version: 1,
        entries: {
          'legacy-credential': {
            id: 'legacy-credential',
            kind: 'identity',
            label: 'Legacy identity',
            ciphertext: xorProtector.protect('legacy-secret').toString('base64'),
            createdAt: timestamp,
            updatedAt: timestamp
          }
        }
      }),
      'utf8'
    )
    const store = new FileCredentialStore(filePath, xorProtector)
    expect(store.list()[0]?.generation).toBe(0)
    const rotated = store.save({
      id: 'legacy-credential',
      kind: 'identity',
      label: 'Legacy identity',
      secret: 'rotated-secret'
    })
    expect(rotated.generation).toBe(1)
    expect(
      (JSON.parse(readFileSync(filePath, 'utf8')) as { version: number })
        .version
    ).toBe(2)
  })
})
