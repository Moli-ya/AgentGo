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
  createdAt: string
  updatedAt: string
}

interface StoredCredential extends CredentialMetadata {
  ciphertext: string
}

interface CredentialFile {
  version: 1
  entries: Record<string, StoredCredential>
}

function emptyCredentialFile(): CredentialFile {
  return { version: 1, entries: {} }
}

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
    const entry: StoredCredential = {
      id,
      kind: input.kind,
      label: input.label,
      ciphertext: this.protector.protect(input.secret).toString('base64'),
      createdAt: existing?.createdAt ?? now,
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
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt
    }
  }

  private readStore(): CredentialFile {
    if (!existsSync(this.filePath)) return emptyCredentialFile()
    const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as Partial<CredentialFile>
    if (parsed.version !== 1 || !parsed.entries || typeof parsed.entries !== 'object') {
      throw new Error('凭据存储文件格式无效。')
    }
    return parsed as CredentialFile
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
