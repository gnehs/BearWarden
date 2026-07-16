import { describe, expect, it } from 'vitest'
import type { SshKeyMaterial } from '../shared/vault-contract'
import {
  SshKeyImportSessionStore,
  type SshKeyImportParser,
  type SshKeyImportTimer
} from './ssh-key-import-session'

const material: SshKeyMaterial = {
  privateKey: 'private material that stays in the main process',
  publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPublicKey',
  fingerprint: 'SHA256:test-fingerprint'
}

const context = { senderId: 1, vaultGeneration: 9 }

class ImportError extends Error {
  constructor(
    readonly code: 'ParsingError' | 'UnsupportedKeyType' | 'PasswordRequired' | 'WrongPassword'
  ) {
    super(code)
  }
}

class ManualTimer implements SshKeyImportTimer {
  readonly callbacks = new Map<number, () => void>()
  private nextHandle = 1

  setTimeout(callback: () => void): number {
    const handle = this.nextHandle++
    this.callbacks.set(handle, callback)
    return handle
  }

  clearTimeout(handle: unknown): void {
    this.callbacks.delete(handle as number)
  }

  runAll(): void {
    for (const callback of [...this.callbacks.values()]) callback()
  }
}

function makeStore(options?: {
  clipboard?: string
  parser?: SshKeyImportParser
  now?: () => number
  timer?: SshKeyImportTimer
  ttlMs?: number
}): { store: SshKeyImportSessionStore; reads: () => number } {
  let clipboardReads = 0
  let randomFill = 0
  return {
    store: new SshKeyImportSessionStore({
      readClipboard: () => {
        clipboardReads += 1
        return options?.clipboard ?? 'ssh-key-from-clipboard'
      },
      parser: options?.parser ?? { importSshKey: () => material },
      now: options?.now,
      timer: options?.timer,
      ttlMs: options?.ttlMs,
      randomBytes: (size) => Buffer.alloc(size, randomFill++)
    }),
    reads: () => clipboardReads
  }
}

describe('SshKeyImportSessionStore', () => {
  it('stages generated private material without exposing it and consumes it once', () => {
    const { store, reads } = makeStore()

    const ready = store.stageGenerated(context, material)

    expect(reads()).toBe(0)
    expect(ready).toEqual({
      status: 'ready',
      token: expect.any(String),
      expiresAt: expect.any(Number),
      publicKey: material.publicKey,
      fingerprint: material.fingerprint
    })
    expect(JSON.stringify(ready)).not.toContain(material.privateKey)
    if (ready.status !== 'ready') return
    expect(
      store.consumeReady(ready.token, {
        senderId: context.senderId,
        vaultGeneration: context.vaultGeneration + 1
      })
    ).toEqual({ status: 'error', code: 'SessionUnavailable' })
    expect(store.consumeReady(ready.token, context)).toEqual({ status: 'ready', material })
    expect(store.consumeReady(ready.token, context)).toEqual({
      status: 'error',
      code: 'SessionUnavailable'
    })
  })

  it('reads the clipboard once and never exposes private material in ready metadata', () => {
    const { store, reads } = makeStore()

    const result = store.begin(context)

    expect(reads()).toBe(1)
    expect(result).toEqual({
      status: 'ready',
      token: expect.any(String),
      expiresAt: expect.any(Number),
      publicKey: material.publicKey,
      fingerprint: material.fingerprint
    })
    expect(result).not.toHaveProperty('privateKey')
    expect(JSON.stringify(result)).not.toContain(material.privateKey)
  })

  it('keeps the same encrypted session across a wrong passphrase without rereading clipboard', () => {
    const rawSeen: Buffer[] = []
    const parser: SshKeyImportParser = {
      importSshKey(key, password) {
        if (!password) {
          rawSeen.push(key as Buffer)
          throw new ImportError('PasswordRequired')
        }
        if ((password as Buffer).toString('utf8') !== 'correct')
          throw new ImportError('WrongPassword')
        return material
      }
    }
    const { store, reads } = makeStore({ parser })
    const awaiting = store.begin(context)
    expect(awaiting.status).toBe('awaitingPassphrase')
    if (awaiting.status !== 'awaitingPassphrase') return

    const wrong = Buffer.from('incorrect', 'utf8')
    const failed = store.submitPassphrase(awaiting.token, context, wrong)

    expect(failed).toEqual({ status: 'error', code: 'WrongPassword' })
    expect(reads()).toBe(1)
    expect(rawSeen).toHaveLength(1)
    expect(rawSeen[0]!.every((byte) => byte !== 0)).toBe(true)
    expect(wrong.every((byte) => byte === 0)).toBe(true)
    expect(store.submitPassphrase(awaiting.token, context, 'correct').status).toBe('ready')
    expect(rawSeen[0]!.every((byte) => byte === 0)).toBe(true)
  })

  it('returns the material exactly once and removes its session', () => {
    const { store } = makeStore()
    const ready = store.begin(context)
    expect(ready.status).toBe('ready')
    if (ready.status !== 'ready') return

    expect(store.consumeReady(ready.token, context)).toEqual({ status: 'ready', material })
    expect(store.consumeReady(ready.token, context)).toEqual({
      status: 'error',
      code: 'SessionUnavailable'
    })
  })

  it('does not let a different sender or generation inspect or cancel the session', () => {
    const rawSeen: Buffer[] = []
    const { store } = makeStore({
      parser: {
        importSshKey(key, password) {
          if (!password) {
            rawSeen.push(key as Buffer)
            throw new ImportError('PasswordRequired')
          }
          if ((password as Buffer).toString('utf8') !== 'correct') {
            throw new ImportError('WrongPassword')
          }
          return material
        }
      }
    })
    const awaiting = store.begin(context)
    expect(awaiting.status).toBe('awaitingPassphrase')
    if (awaiting.status !== 'awaitingPassphrase') return

    store.cancel(awaiting.token, { senderId: 2, vaultGeneration: context.vaultGeneration })
    expect(
      store.submitPassphrase(
        awaiting.token,
        { senderId: 2, vaultGeneration: context.vaultGeneration },
        'x'
      )
    ).toEqual({
      status: 'error',
      code: 'SessionUnavailable'
    })
    expect(
      store.submitPassphrase(
        awaiting.token,
        { senderId: context.senderId, vaultGeneration: context.vaultGeneration + 1 },
        'x'
      )
    ).toEqual({
      status: 'error',
      code: 'SessionUnavailable'
    })
    expect(rawSeen[0]!.every((byte) => byte !== 0)).toBe(true)
    expect(store.submitPassphrase(awaiting.token, context, 'x')).toEqual({
      status: 'error',
      code: 'WrongPassword'
    })
    expect(store.submitPassphrase(awaiting.token, context, 'correct').status).toBe('ready')
    expect(rawSeen[0]!.every((byte) => byte === 0)).toBe(true)
  })

  it('expires sessions by clock and by their scheduled timer, wiping encrypted clipboard bytes', () => {
    let now = 10
    const timer = new ManualTimer()
    let raw: Buffer | undefined
    const { store } = makeStore({
      now: () => now,
      timer,
      ttlMs: 20,
      parser: {
        importSshKey(key) {
          raw = key as Buffer
          throw new ImportError('PasswordRequired')
        }
      }
    })
    const awaiting = store.begin(context)
    expect(awaiting.status).toBe('awaitingPassphrase')
    if (awaiting.status !== 'awaitingPassphrase') return

    now = 30
    timer.runAll()
    expect(raw?.every((byte) => byte === 0)).toBe(true)
    expect(store.submitPassphrase(awaiting.token, context, 'x')).toEqual({
      status: 'error',
      code: 'SessionUnavailable'
    })
  })

  it('clears sessions on a new begin from the same sender and on clearAll', () => {
    const raws: Buffer[] = []
    const { store } = makeStore({
      parser: {
        importSshKey(key) {
          raws.push(key as Buffer)
          throw new ImportError('PasswordRequired')
        }
      }
    })
    const first = store.begin(context)
    const second = store.begin({ ...context, vaultGeneration: context.vaultGeneration + 1 })
    expect(first.status).toBe('awaitingPassphrase')
    expect(second.status).toBe('awaitingPassphrase')
    expect(raws[0]!.every((byte) => byte === 0)).toBe(true)
    store.clearAll()
    expect(raws[1]!.every((byte) => byte === 0)).toBe(true)
  })

  it('enforces input bounds and maps parser errors without retaining raw clipboard data', () => {
    const empty = makeStore({ clipboard: '  \n\t ' }).store
    expect(empty.begin(context)).toEqual({ status: 'error', code: 'EmptyClipboard' })

    const tooLarge = makeStore({ clipboard: 'x'.repeat(256 * 1024 + 1) }).store
    expect(tooLarge.begin(context)).toEqual({ status: 'error', code: 'ClipboardTooLarge' })

    const unsupported = makeStore({
      parser: {
        importSshKey: () => {
          throw new ImportError('UnsupportedKeyType')
        }
      }
    }).store
    expect(unsupported.begin(context)).toEqual({ status: 'error', code: 'UnsupportedKeyType' })

    const malformed = makeStore({
      parser: {
        importSshKey: () => {
          throw new ImportError('ParsingError')
        }
      }
    }).store
    expect(malformed.begin(context)).toEqual({ status: 'error', code: 'ParsingError' })

    const encrypted = makeStore({
      parser: {
        importSshKey(_key, password) {
          if (!password) throw new ImportError('PasswordRequired')
          if ((password as Buffer).toString('utf8') !== 'correct')
            throw new ImportError('WrongPassword')
          return material
        }
      }
    }).store
    const awaiting = encrypted.begin(context)
    expect(awaiting.status).toBe('awaitingPassphrase')
    if (awaiting.status !== 'awaitingPassphrase') return
    expect(encrypted.submitPassphrase(awaiting.token, context, '')).toEqual({
      status: 'error',
      code: 'InvalidPassphrase'
    })
    expect(encrypted.submitPassphrase(awaiting.token, context, 'x'.repeat(1025))).toEqual({
      status: 'error',
      code: 'InvalidPassphrase'
    })
    expect(encrypted.submitPassphrase(awaiting.token, context, 'correct').status).toBe('ready')
  })

  it('caps concurrent sessions to prevent global memory exhaustion', () => {
    let senderId = 0
    const { store } = makeStore({
      parser: {
        importSshKey: () => {
          throw new ImportError('PasswordRequired')
        }
      }
    })
    for (senderId = 0; senderId < 32; senderId += 1) {
      expect(store.begin({ senderId, vaultGeneration: 1 }).status).toBe('awaitingPassphrase')
    }
    expect(store.begin({ senderId: 32, vaultGeneration: 1 })).toEqual({
      status: 'error',
      code: 'SessionLimitReached'
    })
    expect(store.stageGenerated({ senderId: 32, vaultGeneration: 1 }, material)).toEqual({
      status: 'error',
      code: 'SessionLimitReached'
    })
  })
})
