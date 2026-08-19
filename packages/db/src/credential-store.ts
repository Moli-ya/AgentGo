import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

export interface SecretProtector {
  isAvailable(): boolean
  protect(value: string): Buffer
  unprotect(value: Buffer): string
}

export interface CredentialMetadata {
  id: string
  kind: 'identity' | 'model-api-key' | 'mcp-server-secret'
  label: string
  generation: number
  createdAt: string
  updatedAt: string
}

interface StoredCredential extends CredentialMetadata {
  ciphertext: string
}

interface CredentialFile {
  version: 2
  entries: Record<string, StoredCredential>
}

function emptyCredentialFile(): CredentialFile {
  return { version: 2, entries: {} }
}

const credentialKinds = new Set<CredentialMetadata['kind']>([
  'identity',
  'model-api-key',
  'mcp-server-secret'
])

export class FileCredentialStore {
  constructor(
    private readonly filePath: string,
    private readonly protector: SecretProtector
  ) {}

  isAvailable(): boolean {
    return this.protector.isAvailable()
  }

  save(input: {
    id?: string
    kind: CredentialMetadata['kind']
    label: string
    secret: string
  }): CredentialMetadata {
    if (!this.protector.isAvailable()) {
      throw new Error('操作系统安全凭据存储当前不可用。')
    }
    if (!input.secret) {
      throw new Error('凭据不能为空。')
    }

    const store = this.readStore()
    const id = input.id ?? randomUUID()
    const now = new Date().toISOString()
    const existing = store.entries[id]
    if (input.id !== undefined && !existing) {
      throw new Error('A missing credential cannot be recreated with an old identifier.')
    }
    if (existing && existing.kind !== input.kind) {
      throw new Error('A credential kind cannot change during rotation.')
    }
    if (existing?.generation === Number.MAX_SAFE_INTEGER) {
      throw new Error('The credential generation is exhausted.')
    }
    const entry: StoredCredential = {
      id,
      kind: input.kind,
      label: input.label,
      ciphertext: this.protector.protect(input.secret).toString('base64'),
      createdAt: existing?.createdAt ?? now,
      generation: existing ? existing.generation + 1 : 0,
      updatedAt: now
    }
    store.entries[id] = entry
    this.writeStore(store)
    return this.toMetadata(entry)
  }

  get(id: string): string | undefined {
    const entry = this.readStore().entries[id]
    if (!entry) return undefined
    if (!this.protector.isAvailable()) {
      throw new Error('操作系统安全凭据存储当前不可用。')
    }
    return this.protector.unprotect(Buffer.from(entry.ciphertext, 'base64'))
  }

  delete(id: string): boolean {
    const store = this.readStore()
    if (!store.entries[id]) return false
    delete store.entries[id]
    this.writeStore(store)
    return true
  }

  list(): CredentialMetadata[] {
    return Object.values(this.readStore().entries)
      .map((entry) => this.toMetadata(entry))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
  }

  private toMetadata(entry: StoredCredential): CredentialMetadata {
    return {
      id: entry.id,
      kind: entry.kind,
      label: entry.label,
      generation: entry.generation,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt
    }
  }

  private readStore(): CredentialFile {
    if (!existsSync(this.filePath)) return emptyCredentialFile()
    const parsed: unknown = JSON.parse(readFileSync(this.filePath, 'utf8'))
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('凭据存储文件格式无效。')
    }
    const root = parsed as Record<string, unknown>
    if (
      JSON.stringify(Object.keys(root).sort()) !==
        JSON.stringify(['entries', 'version']) ||
      (root.version !== 1 && root.version !== 2) ||
      !root.entries ||
      typeof root.entries !== 'object' ||
      Array.isArray(root.entries)
    ) {
      throw new Error('凭据存储文件格式无效。')
    }
    const entries: Record<string, StoredCredential> = {}
    for (const [id, rawEntry] of Object.entries(
      root.entries as Record<string, unknown>
    )) {
      entries[id] = this.parseStoredCredential(id, rawEntry, root.version)
    }
    return { version: 2, entries }
  }

  private parseStoredCredential(
    id: string,
    rawEntry: unknown,
    version: 1 | 2
  ): StoredCredential {
    if (!rawEntry || typeof rawEntry !== 'object' || Array.isArray(rawEntry)) {
      throw new Error('凭据存储文件格式无效。')
    }
    const entry = rawEntry as Record<string, unknown>
    const expectedKeys = version === 1
      ? ['ciphertext', 'createdAt', 'id', 'kind', 'label', 'updatedAt']
      : [
          'ciphertext',
          'createdAt',
          'generation',
          'id',
          'kind',
          'label',
          'updatedAt'
        ]
    const kind = entry.kind
    const generation = version === 1 ? 0 : entry.generation
    if (
      JSON.stringify(Object.keys(entry).sort()) !==
        JSON.stringify(expectedKeys) ||
      entry.id !== id ||
      id.length === 0 ||
      typeof kind !== 'string' ||
      !credentialKinds.has(kind as CredentialMetadata['kind']) ||
      typeof entry.label !== 'string' ||
      typeof entry.ciphertext !== 'string' ||
      typeof entry.createdAt !== 'string' ||
      typeof entry.updatedAt !== 'string' ||
      !Number.isSafeInteger(generation) ||
      (generation as number) < 0 ||
      !this.isCanonicalIsoDate(entry.createdAt) ||
      !this.isCanonicalIsoDate(entry.updatedAt)
    ) {
      throw new Error('凭据存储文件格式无效。')
    }
    return {
      id,
      kind: kind as CredentialMetadata['kind'],
      label: entry.label,
      ciphertext: entry.ciphertext,
      generation: generation as number,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt
    }
  }

  private isCanonicalIsoDate(value: string): boolean {
    const timestamp = Date.parse(value)
    return (
      Number.isFinite(timestamp) &&
      new Date(timestamp).toISOString() === value
    )
  }

  private writeStore(store: CredentialFile): void {
    mkdirSync(dirname(this.filePath), { recursive: true })
    const temporaryPath = `${this.filePath}.${process.pid}.${randomUUID()}.tmp`
    writeFileSync(temporaryPath, JSON.stringify(store), {
      encoding: 'utf8',
      mode: 0o600
    })
    renameSync(temporaryPath, this.filePath)
  }
}
