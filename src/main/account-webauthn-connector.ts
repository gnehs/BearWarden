import {
  parseAccountWebAuthnChallenge,
  serializeAccountWebAuthnAssertion,
  type AccountWebAuthnAssertion,
  type AccountWebAuthnChallenge
} from './account-webauthn-codec'

const CONNECTOR_PATH = '/webauthn-connector.html'
const MAX_WEB_VAULT_URL_LENGTH = 4_096
const MAX_PARENT_URL_LENGTH = 2_048
const MAX_CONNECTOR_URL_LENGTH = 128 * 1_024
const MAX_MESSAGE_LENGTH = 128 * 1_024
const MAX_REMOTE_ERROR_LENGTH = 512
const MAX_SESSION_TIMEOUT_MS = 10 * 60 * 1_000

type SourceIdentity = object | symbol

export type AccountWebAuthnConnectorErrorCode =
  | 'INVALID_CONFIGURATION'
  | 'INVALID_MESSAGE'
  | 'REMOTE_ERROR'
  | 'TIMEOUT'
  | 'ABORTED'
  | 'CANCELLED'
  | 'DISPOSED'

/** Stable errors deliberately do not echo connector, parent, or challenge data. */
export class AccountWebAuthnConnectorError extends Error {
  constructor(readonly code: AccountWebAuthnConnectorErrorCode) {
    super(`ACCOUNT_WEBAUTHN_CONNECTOR_${code}`)
    this.name = 'AccountWebAuthnConnectorError'
  }
}

/** Authenticated event metadata supplied by the native adapter, never by connector data. */
export interface AccountWebAuthnConnectorMessageContext {
  readonly origin: string
  readonly source: SourceIdentity
  readonly epoch: number
  readonly capability: SourceIdentity
}

export interface AccountWebAuthnConnectorSessionOptions {
  readonly webVaultUrl: string
  /** URL of the local wrapper which opened the connector. */
  readonly parentUrl: string
  readonly challenge: unknown
  /** Exact WindowProxy/webContents identity expected from the adapter. */
  readonly expectedSource: SourceIdentity
  /** Active adapter epoch captured out-of-band when the one-shot session is created. */
  readonly epoch: number
  /** Opaque process-memory capability captured out-of-band at session creation. */
  readonly capability: SourceIdentity
  readonly timeoutMs?: number
  readonly signal?: AbortSignal
}

export type AccountWebAuthnConnectorMessageResult = 'ignored' | 'ready' | 'settled'

export interface AccountWebAuthnConnectorSession {
  readonly origin: string
  /** Cleared as soon as the one-shot session reaches a terminal state. */
  readonly connectorUrl: string | null
  readonly result: Promise<AccountWebAuthnAssertion>
  readonly active: boolean
  readonly ready: boolean
  /** Handle the native `MessageEvent.data` and separately authenticated metadata. */
  handleMessage(value: unknown, context: unknown): AccountWebAuthnConnectorMessageResult
  cancel(): void
  dispose(): void
}

function failConfiguration(): never {
  throw new AccountWebAuthnConnectorError('INVALID_CONFIGURATION')
}

function isSourceIdentity(value: unknown): value is SourceIdentity {
  return (typeof value === 'object' && value !== null) || typeof value === 'symbol'
}

function strictRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) failConfiguration()
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) failConfiguration()
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const ownKeys = Reflect.ownKeys(descriptors)
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some((key) => {
        const descriptor = descriptors[key]
        return !descriptor || !('value' in descriptor)
      })
    ) {
      failConfiguration()
    }
    const snapshot = Object.create(null) as Record<string, unknown>
    for (const key of keys) snapshot[key] = descriptors[key]!.value
    return snapshot
  } catch (error) {
    if (error instanceof AccountWebAuthnConnectorError) throw error
    failConfiguration()
  }
}

function ownData(record: Record<string, unknown>, key: string): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(record, key)
    if (!descriptor || !('value' in descriptor)) failConfiguration()
    return descriptor.value
  } catch (error) {
    if (error instanceof AccountWebAuthnConnectorError) throw error
    failConfiguration()
  }
}

function parseWebVaultTarget(value: unknown): { origin: string; pageUrl: string } {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_WEB_VAULT_URL_LENGTH ||
    value.trim() !== value ||
    containsUnsafePathSyntax(value)
  ) {
    failConfiguration()
  }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    failConfiguration()
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname !== '/'
  ) {
    failConfiguration()
  }
  return { origin: url.origin, pageUrl: `${url.origin}${CONNECTOR_PATH}` }
}

function containsUnsafePathSyntax(raw: string): boolean {
  return /(?:^|\/)(?:\.{1,2})(?:\/|$)|%2e|%2f|%5c|\\/iu.test(raw)
}

function parseParentUrl(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_PARENT_URL_LENGTH ||
    value.trim() !== value
  ) {
    failConfiguration()
  }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    failConfiguration()
  }
  if (
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname.length === 0 ||
    containsUnsafePathSyntax(value)
  ) {
    failConfiguration()
  }
  if (url.protocol === 'file:') {
    if (url.hostname !== '') failConfiguration()
  } else if (url.protocol !== 'app:' || url.hostname !== 'bearwarden' || url.port !== '') {
    failConfiguration()
  }
  return url.toString()
}

function buildConnectorUrl(
  pageUrl: string,
  parentUrl: string,
  challenge: AccountWebAuthnChallenge
): string {
  const data = Buffer.from(JSON.stringify(challenge), 'utf8').toString('base64')
  if (data.length === 0 || data.length > MAX_CONNECTOR_URL_LENGTH) failConfiguration()
  const connectorUrl = `${pageUrl}?${new URLSearchParams({
    v: '1',
    data,
    parent: parentUrl
  }).toString()}`
  if (connectorUrl.length > MAX_CONNECTOR_URL_LENGTH) failConfiguration()
  return connectorUrl
}

function normalizeOfficialAssertion(value: unknown): AccountWebAuthnAssertion {
  const assertion = strictRecord(value, ['id', 'rawId', 'type', 'extensions', 'response'])
  const response = strictRecord(ownData(assertion, 'response'), [
    'authenticatorData',
    'clientDataJson',
    'signature'
  ])
  const candidate: AccountWebAuthnAssertion = {
    id: ownData(assertion, 'id') as string,
    rawId: ownData(assertion, 'rawId') as string,
    type: ownData(assertion, 'type') as 'public-key',
    response: {
      clientDataJSON: ownData(response, 'clientDataJson') as string,
      authenticatorData: ownData(response, 'authenticatorData') as string,
      signature: ownData(response, 'signature') as string,
      userHandle: null
    },
    clientExtensionResults: ownData(
      assertion,
      'extensions'
    ) as AccountWebAuthnAssertion['clientExtensionResults']
  }
  // The Stage 2A codec is the canonical assertion validator and serializer.
  const wire = JSON.parse(serializeAccountWebAuthnAssertion(candidate)) as {
    id: string
    rawId: string
    type: 'public-key'
    response: {
      clientDataJson: string
      authenticatorData: string
      signature: string
      userHandle?: string
    }
    extensions: { appid?: boolean; uvm?: number[][] }
  }
  const normalizedExtensions = Object.freeze({
    ...(wire.extensions.appid === undefined ? {} : { appid: wire.extensions.appid }),
    ...(wire.extensions.uvm === undefined
      ? {}
      : { uvm: Object.freeze(wire.extensions.uvm.map((row) => Object.freeze([...row]))) })
  })
  return Object.freeze({
    id: wire.id,
    rawId: wire.rawId,
    type: wire.type,
    response: Object.freeze({
      clientDataJSON: wire.response.clientDataJson,
      authenticatorData: wire.response.authenticatorData,
      signature: wire.response.signature,
      userHandle: wire.response.userHandle ?? null
    }),
    clientExtensionResults: normalizedExtensions
  })
}

function parseSuccess(data: string): AccountWebAuthnAssertion {
  const payload = data.slice('success|'.length)
  if (payload.length === 0 || payload.length > MAX_MESSAGE_LENGTH) {
    throw new AccountWebAuthnConnectorError('INVALID_MESSAGE')
  }
  try {
    return normalizeOfficialAssertion(JSON.parse(payload) as unknown)
  } catch (error) {
    if (error instanceof AccountWebAuthnConnectorError) throw error
    throw new AccountWebAuthnConnectorError('INVALID_MESSAGE')
  }
}

function validRemoteError(data: string): boolean {
  if (!data.startsWith('error|')) return false
  const reason = data.slice('error|'.length)
  return (
    reason.length > 0 &&
    reason.length <= MAX_REMOTE_ERROR_LENGTH &&
    /^[\x20-\x7e]+$/u.test(reason) &&
    !reason.includes('|')
  )
}

interface PreparedSession {
  readonly origin: string
  connectorUrl: string | null
  expectedSource: SourceIdentity | null
  readonly epoch: number
  capability: SourceIdentity | null
  readonly timeoutMs: number
  readonly signal: AbortSignal | undefined
}

function prepareSession(options: AccountWebAuthnConnectorSessionOptions): PreparedSession {
  const target = parseWebVaultTarget(options.webVaultUrl)
  const parentUrl = parseParentUrl(options.parentUrl)
  let challenge: AccountWebAuthnChallenge
  try {
    challenge = parseAccountWebAuthnChallenge(options.challenge)
  } catch {
    failConfiguration()
  }
  if (!isSourceIdentity(options.expectedSource) || !isSourceIdentity(options.capability)) {
    failConfiguration()
  }
  if (!Number.isSafeInteger(options.epoch) || options.epoch < 0) failConfiguration()
  const timeoutMs = options.timeoutMs ?? Math.min(challenge.timeout + 5_000, MAX_SESSION_TIMEOUT_MS)
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_SESSION_TIMEOUT_MS) {
    failConfiguration()
  }
  return {
    origin: target.origin,
    connectorUrl: buildConnectorUrl(target.pageUrl, parentUrl, challenge),
    expectedSource: options.expectedSource,
    epoch: options.epoch,
    capability: options.capability,
    timeoutMs,
    signal: options.signal
  }
}

export function createAccountWebAuthnConnectorSession(
  options: AccountWebAuthnConnectorSessionOptions
): AccountWebAuthnConnectorSession {
  return createPreparedSession(prepareSession(options))
}

function createPreparedSession(prepared: PreparedSession): AccountWebAuthnConnectorSession {
  let connectorUrlValue: string | null = prepared.connectorUrl
  let expectedSourceValue: SourceIdentity | null = prepared.expectedSource
  let capabilityValue: SourceIdentity | null = prepared.capability
  let active = true
  let ready = false
  let resolveResult!: (assertion: AccountWebAuthnAssertion) => void
  let rejectResult!: (error: AccountWebAuthnConnectorError) => void
  const result = new Promise<AccountWebAuthnAssertion>((resolve, reject) => {
    resolveResult = resolve
    rejectResult = reject
  })

  const onAbort = (): void => settleError('ABORTED')
  const timer = setTimeout(() => settleError('TIMEOUT'), prepared.timeoutMs)

  function cleanup(): void {
    clearTimeout(timer)
    prepared.signal?.removeEventListener('abort', onAbort)
    connectorUrlValue = null
    expectedSourceValue = null
    capabilityValue = null
    prepared.connectorUrl = null
    prepared.expectedSource = null
    prepared.capability = null
  }

  function settleError(code: AccountWebAuthnConnectorErrorCode): void {
    if (!active) return
    active = false
    cleanup()
    rejectResult(new AccountWebAuthnConnectorError(code))
  }

  function settleSuccess(assertion: AccountWebAuthnAssertion): void {
    if (!active) return
    active = false
    cleanup()
    resolveResult(assertion)
  }

  function readContext(value: unknown): AccountWebAuthnConnectorMessageContext | undefined {
    try {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
      const descriptors = Object.getOwnPropertyDescriptors(value)
      const keys = Reflect.ownKeys(descriptors)
      if (
        keys.length !== 4 ||
        keys.some(
          (key) =>
            typeof key !== 'string' ||
            !['origin', 'source', 'epoch', 'capability'].includes(key) ||
            !('value' in descriptors[key]!)
        )
      ) {
        return undefined
      }
      const context = Object.create(null) as Record<string, unknown>
      for (const key of ['origin', 'source', 'epoch', 'capability']) {
        context[key] = descriptors[key]!.value
      }
      const epoch = context.epoch
      if (
        typeof context.origin !== 'string' ||
        !isSourceIdentity(context.source) ||
        !isSourceIdentity(context.capability) ||
        typeof epoch !== 'number' ||
        !Number.isSafeInteger(epoch) ||
        epoch < 0
      ) {
        return undefined
      }
      return context as unknown as AccountWebAuthnConnectorMessageContext
    } catch {
      return undefined
    }
  }

  prepared.signal?.addEventListener('abort', onAbort, { once: true })
  if (prepared.signal?.aborted) onAbort()

  return {
    get connectorUrl() {
      return connectorUrlValue
    },
    origin: prepared.origin,
    result,
    get active() {
      return active
    },
    get ready() {
      return ready
    },
    handleMessage(value: unknown, contextValue: unknown): AccountWebAuthnConnectorMessageResult {
      if (!active) return 'ignored'
      const context = readContext(contextValue)
      if (
        context === undefined ||
        context.origin !== prepared.origin ||
        context.source !== expectedSourceValue ||
        context.epoch !== prepared.epoch ||
        context.capability !== capabilityValue
      ) {
        return 'ignored'
      }
      if (typeof value !== 'string' || value.length === 0 || value.length > MAX_MESSAGE_LENGTH) {
        settleError('INVALID_MESSAGE')
        return 'settled'
      }
      if (value === 'info|ready') {
        if (ready) return 'ignored'
        ready = true
        return 'ready'
      }
      if (value.startsWith('success|')) {
        try {
          settleSuccess(parseSuccess(value))
        } catch {
          settleError('INVALID_MESSAGE')
        }
        return 'settled'
      }
      if (validRemoteError(value)) {
        settleError('REMOTE_ERROR')
        return 'settled'
      }
      settleError('INVALID_MESSAGE')
      return 'settled'
    },
    cancel(): void {
      settleError('CANCELLED')
    },
    dispose(): void {
      settleError('DISPOSED')
    }
  }
}
