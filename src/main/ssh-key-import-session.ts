import { randomBytes as systemRandomBytes } from 'node:crypto'
import type { SshKeyMaterial } from '../shared/vault-contract'
import { importSshKey } from './ssh-key-import'

const MAX_CLIPBOARD_BYTES = 256 * 1024
const MAX_PASSPHRASE_BYTES = 1024
const MAX_SESSIONS = 32
const DEFAULT_TTL_MS = 5 * 60 * 1000
const TOKEN_BYTES = 32

export interface SshKeyImportContext {
  senderId: number
  vaultGeneration: number
}

export interface SshKeyImportParser {
  importSshKey(key: string | Buffer, password?: string | Buffer): SshKeyMaterial
}

export interface SshKeyImportTimer {
  setTimeout(callback: () => void, delayMs: number): unknown
  clearTimeout(handle: unknown): void
}

export interface SshKeyImportSessionStoreOptions {
  readClipboard: () => string
  parser?: SshKeyImportParser
  now?: () => number
  randomBytes?: (size: number) => Buffer
  timer?: SshKeyImportTimer
  ttlMs?: number
}

export type SshKeyImportSessionErrorCode =
  | 'EmptyClipboard'
  | 'ClipboardTooLarge'
  | 'ParsingError'
  | 'UnsupportedKeyType'
  | 'WrongPassword'
  | 'InvalidPassphrase'
  | 'SessionUnavailable'
  | 'SessionLimitReached'

export interface SshKeyImportSessionError {
  status: 'error'
  code: SshKeyImportSessionErrorCode
}

export interface SshKeyImportAwaitingPassphrase {
  status: 'awaitingPassphrase'
  token: string
  expiresAt: number
}

/** This contains no private key material and is safe to return over IPC. */
export interface SshKeyImportReady {
  status: 'ready'
  token: string
  expiresAt: number
  publicKey: string
  fingerprint: string
}

export type SshKeyImportBeginResult =
  SshKeyImportSessionError | SshKeyImportAwaitingPassphrase | SshKeyImportReady

/** Only main-process callers may receive `material`; it must never cross IPC. */
export type SshKeyImportConsumeResult =
  { status: 'ready'; material: SshKeyMaterial } | SshKeyImportSessionError

interface AwaitingSession {
  state: 'awaitingPassphrase'
  token: string
  context: SshKeyImportContext
  expiresAt: number
  timer: unknown
  raw: Buffer
}

interface ReadySession {
  state: 'ready'
  token: string
  context: SshKeyImportContext
  expiresAt: number
  timer: unknown
  material: SshKeyMaterial
}

type Session = AwaitingSession | ReadySession

type ParserErrorCode = 'ParsingError' | 'UnsupportedKeyType' | 'PasswordRequired' | 'WrongPassword'

function defaultTimer(): SshKeyImportTimer {
  return {
    setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
    clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>)
  }
}

function isParserErrorCode(value: unknown): value is ParserErrorCode {
  return (
    value === 'ParsingError' ||
    value === 'UnsupportedKeyType' ||
    value === 'PasswordRequired' ||
    value === 'WrongPassword'
  )
}

function parserErrorCode(error: unknown): ParserErrorCode | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const code = Reflect.get(error, 'code')
  return isParserErrorCode(code) ? code : undefined
}

function error(code: SshKeyImportSessionErrorCode): SshKeyImportSessionError {
  return { status: 'error', code }
}

function sameContext(left: SshKeyImportContext, right: SshKeyImportContext): boolean {
  return left.senderId === right.senderId && left.vaultGeneration === right.vaultGeneration
}

function isWhitespaceOnly(bytes: Buffer): boolean {
  for (const byte of bytes) {
    if (byte !== 0x09 && byte !== 0x0a && byte !== 0x0d && byte !== 0x20) return false
  }
  return true
}

/**
 * Ephemeral, main-process-only holder for an SSH key imported from the clipboard.
 * JavaScript strings are immutable and cannot be overwritten; all controllable binary
 * clipboard/passphrase buffers are explicitly wiped when this store no longer needs them.
 */
export class SshKeyImportSessionStore {
  private readonly sessions = new Map<string, Session>()
  private readonly senderSessions = new Map<number, string>()
  private readonly parser: SshKeyImportParser
  private readonly now: () => number
  private readonly randomBytes: (size: number) => Buffer
  private readonly timer: SshKeyImportTimer
  private readonly ttlMs: number

  constructor(private readonly options: SshKeyImportSessionStoreOptions) {
    this.parser = options.parser ?? { importSshKey }
    this.now = options.now ?? Date.now
    this.randomBytes = options.randomBytes ?? systemRandomBytes
    this.timer = options.timer ?? defaultTimer()
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS

    if (!Number.isSafeInteger(this.ttlMs) || this.ttlMs <= 0) {
      throw new Error('INVALID_SSH_KEY_IMPORT_SESSION_TTL')
    }
  }

  /**
   * Stages freshly generated material behind the same one-time capability used by imports.
   * Callers must first bind `context` to an unlocked vault generation and trusted IPC sender.
   */
  stageGenerated(
    context: SshKeyImportContext,
    material: SshKeyMaterial
  ): SshKeyImportReady | SshKeyImportSessionError {
    this.cancelExistingForSender(context.senderId)
    if (this.sessions.size >= MAX_SESSIONS) return error('SessionLimitReached')

    try {
      return this.createReady(context, material)
    } catch {
      return error('SessionUnavailable')
    }
  }

  begin(context: SshKeyImportContext): SshKeyImportBeginResult {
    this.cancelExistingForSender(context.senderId)

    // The clipboard is intentionally read exactly once per begin attempt.
    const clipboard = this.options.readClipboard()
    const raw = Buffer.from(clipboard, 'utf8')
    if (raw.length > MAX_CLIPBOARD_BYTES) {
      raw.fill(0)
      return error('ClipboardTooLarge')
    }
    if (raw.length === 0 || isWhitespaceOnly(raw)) {
      raw.fill(0)
      return error('EmptyClipboard')
    }
    if (this.sessions.size >= MAX_SESSIONS) {
      raw.fill(0)
      return error('SessionLimitReached')
    }

    try {
      const material = this.parser.importSshKey(raw)
      raw.fill(0)
      return this.createReady(context, material)
    } catch (caught) {
      const code = parserErrorCode(caught)
      if (code === 'PasswordRequired') {
        try {
          return this.createAwaiting(context, raw)
        } catch {
          raw.fill(0)
          return error('SessionUnavailable')
        }
      }
      raw.fill(0)
      return error(
        code === 'UnsupportedKeyType' ? code : code === 'WrongPassword' ? code : 'ParsingError'
      )
    }
  }

  submitPassphrase(
    token: string,
    context: SshKeyImportContext,
    passphrase: string | Buffer
  ): SshKeyImportBeginResult {
    // A caller-provided Buffer is intentionally consumed and wiped rather than retained.
    const password = Buffer.isBuffer(passphrase) ? passphrase : Buffer.from(passphrase, 'utf8')
    try {
      const session = this.claimForContext(token, context)
      if (!session) return error('SessionUnavailable')
      if (session.state !== 'awaitingPassphrase') {
        this.destroy(session)
        return error('SessionUnavailable')
      }
      if (password.length === 0 || password.length > MAX_PASSPHRASE_BYTES) {
        return error('InvalidPassphrase')
      }

      try {
        const material = this.parser.importSshKey(session.raw, password)
        this.destroy(session)
        return this.createReady(context, material)
      } catch (caught) {
        const code = parserErrorCode(caught)
        if (code === 'WrongPassword') return error('WrongPassword')
        this.destroy(session)
        return error(code === 'UnsupportedKeyType' ? code : 'ParsingError')
      }
    } finally {
      password.fill(0)
    }
  }

  consumeReady(token: string, context: SshKeyImportContext): SshKeyImportConsumeResult {
    const session = this.claimForContext(token, context)
    if (!session || session.state !== 'ready') {
      if (session) this.destroy(session)
      return error('SessionUnavailable')
    }

    const material = session.material
    this.destroy(session)
    return { status: 'ready', material }
  }

  /** Safe to call repeatedly. A mismatched caller may not cancel another sender's session. */
  cancel(token: string, context: SshKeyImportContext): void {
    const session = this.sessions.get(token)
    if (!session || !sameContext(session.context, context)) return
    this.destroy(session)
  }

  /** Invoke on vault lock and application shutdown. */
  clearAll(): void {
    for (const session of [...this.sessions.values()]) this.destroy(session)
  }

  private createAwaiting(
    context: SshKeyImportContext,
    raw: Buffer
  ): SshKeyImportAwaitingPassphrase {
    const session = this.createSession({ state: 'awaitingPassphrase', context, raw })
    return { status: 'awaitingPassphrase', token: session.token, expiresAt: session.expiresAt }
  }

  private createReady(context: SshKeyImportContext, material: SshKeyMaterial): SshKeyImportReady {
    const session = this.createSession({ state: 'ready', context, material })
    return {
      status: 'ready',
      token: session.token,
      expiresAt: session.expiresAt,
      publicKey: material.publicKey,
      fingerprint: material.fingerprint
    }
  }

  private createSession(
    input:
      | Pick<AwaitingSession, 'state' | 'context' | 'raw'>
      | Pick<ReadySession, 'state' | 'context' | 'material'>
  ): Session {
    const token = this.createToken()
    const expiresAt = this.now() + this.ttlMs
    const session = { ...input, token, expiresAt, timer: undefined } as Session
    session.timer = this.timer.setTimeout(() => this.expire(token), this.ttlMs)
    this.sessions.set(token, session)
    this.senderSessions.set(input.context.senderId, token)
    return session
  }

  private createToken(): string {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const bytes = this.randomBytes(TOKEN_BYTES)
      try {
        if (bytes.length !== TOKEN_BYTES) throw new Error('SSH_KEY_IMPORT_TOKEN_GENERATION_FAILED')
        const token = bytes.toString('base64url')
        if (!this.sessions.has(token)) return token
      } finally {
        bytes.fill(0)
      }
    }
    throw new Error('SSH_KEY_IMPORT_TOKEN_GENERATION_FAILED')
  }

  private claimForContext(token: string, context: SshKeyImportContext): Session | undefined {
    const session = this.sessions.get(token)
    if (!session) return undefined
    if (!sameContext(session.context, context)) return undefined
    if (session.expiresAt <= this.now()) {
      this.destroy(session)
      return undefined
    }
    return session
  }

  private expire(token: string): void {
    const session = this.sessions.get(token)
    if (!session) return
    const remaining = session.expiresAt - this.now()
    if (remaining <= 0) {
      this.destroy(session)
      return
    }
    session.timer = this.timer.setTimeout(() => this.expire(token), remaining)
  }

  private cancelExistingForSender(senderId: number): void {
    const token = this.senderSessions.get(senderId)
    if (!token) return
    const session = this.sessions.get(token)
    if (session) this.destroy(session)
    else this.senderSessions.delete(senderId)
  }

  private destroy(session: Session): void {
    if (this.sessions.get(session.token) !== session) return
    this.timer.clearTimeout(session.timer)
    this.sessions.delete(session.token)
    if (this.senderSessions.get(session.context.senderId) === session.token) {
      this.senderSessions.delete(session.context.senderId)
    }
    if (session.state === 'awaitingPassphrase') session.raw.fill(0)
  }
}
