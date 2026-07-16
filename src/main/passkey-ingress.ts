import { createHash, timingSafeEqual } from 'node:crypto'
import { validatePasskeyOrigin } from './passkey-origin-validation'

const MAX_PROVIDER_LENGTH = 128
const MAX_PEER_BINDING_LENGTH = 256
const MAX_CLIENT_DATA_JSON_BYTES = 8_192
const MIN_CHALLENGE_BYTES = 16
const MAX_CHALLENGE_BYTES = 1_024
const MAX_TEXT_LENGTH = 1_024
const MAX_TIMEOUT_MS = 600_000
const MAX_USER_HANDLE_BYTES = 64
const MAX_CREDENTIAL_ID_BYTES = 1_023
const MAX_CREDENTIAL_DESCRIPTORS = 128
const MAX_TRANSPORTS = 32
const MAX_TRANSPORT_LENGTH = 64
const MAX_PUB_KEY_CREDENTIAL_PARAMETERS = 32
const MIN_COSE_ALGORITHM = -0x8000_0000
const MAX_COSE_ALGORITHM = 0x7fff_ffff
const ES256_ALGORITHM = -7 as const
const BASE64URL = /^[A-Za-z0-9_-]+$/u
const TRUSTED_IDENTITY = /^[\x21-\x7e]+$/u

export type PasskeyIngressErrorCode =
  | 'INVALID_TRANSPORT_CONTEXT'
  | 'PEER_DISCONNECTED'
  | 'INVALID_PAYLOAD'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_OPTION'
  | 'INVALID_CLIENT_DATA'
  | 'CEREMONY_MISMATCH'
  | 'ORIGIN_REJECTED'
  | 'CROSS_ORIGIN_UNSUPPORTED'

/** Error messages are deliberately stable codes and never echo provider-controlled data. */
export class PasskeyIngressError extends Error {
  constructor(public readonly code: PasskeyIngressErrorCode) {
    super(code)
    this.name = 'PasskeyIngressError'
  }
}

/**
 * Authenticated connection state supplied out-of-band by a native transport adapter.
 * None of these fields may be read from the ceremony payload.
 */
export interface PasskeyIngressTransportContext {
  readonly provider: string
  readonly binding: string
  readonly epoch: number
  readonly signal: AbortSignal
}

export interface PasskeyIngressPeer {
  readonly provider: string
  readonly binding: string
  readonly epoch: number
}

export type PasskeyIngressUserVerification = 'required' | 'preferred' | 'discouraged'
export type PasskeyIngressAuthenticatorAttachment = 'platform'
export type PasskeyIngressResidentKey = 'required' | 'preferred' | 'discouraged'
export type PasskeyIngressMediation = 'silent' | 'optional' | 'required'
export type PasskeyIngressAuthenticatorTransport =
  'usb' | 'nfc' | 'ble' | 'smart-card' | 'hybrid' | 'internal'

export interface PasskeyIngressCredentialDescriptor {
  readonly type: 'public-key'
  readonly id: readonly number[]
  readonly transports: readonly PasskeyIngressAuthenticatorTransport[]
}

export interface PasskeyIngressAuthenticatorSelection {
  readonly authenticatorAttachment?: PasskeyIngressAuthenticatorAttachment
  readonly residentKey?: PasskeyIngressResidentKey
  readonly requireResidentKey?: boolean
  readonly userVerification: PasskeyIngressUserVerification
}

export interface PasskeyIngressCreateOptions {
  readonly challenge: readonly number[]
  readonly rp: Readonly<{ id: string; name: string }>
  readonly user: Readonly<{
    id: readonly number[]
    name: string
    displayName: string
  }>
  readonly pubKeyCredParams: readonly [
    Readonly<{ type: 'public-key'; alg: typeof ES256_ALGORITHM }>
  ]
  readonly timeout?: number
  readonly excludeCredentials: readonly PasskeyIngressCredentialDescriptor[]
  readonly authenticatorSelection: PasskeyIngressAuthenticatorSelection
  readonly attestation: 'none'
  readonly extensions: Readonly<Record<string, never>>
}

export interface PasskeyIngressGetOptions {
  readonly challenge: readonly number[]
  readonly rpId: string
  readonly timeout?: number
  readonly allowCredentials: readonly PasskeyIngressCredentialDescriptor[]
  readonly userVerification: PasskeyIngressUserVerification
  readonly mediation: PasskeyIngressMediation
  readonly extensions: Readonly<Record<string, never>>
}

type ParsedPasskeyIngressCreateOptions = Omit<PasskeyIngressCreateOptions, 'rp'> & {
  readonly rp: Readonly<{ id?: string; name: string }>
}

type ParsedPasskeyIngressGetOptions = Omit<PasskeyIngressGetOptions, 'rpId'> & {
  readonly rpId?: string
}

interface PasskeyIngressSnapshotBase {
  readonly version: 1
  readonly kind: 'create' | 'get'
  /** Authenticated out-of-band identity, copied before any request is admitted. */
  readonly peer: PasskeyIngressPeer
  /** The adapter-owned lifetime; pass this signal to the request coordinator. */
  readonly signal: AbortSignal
  /** Exact decoded bytes received in the clientDataJSON transport field. */
  readonly clientDataJSON: readonly number[]
  /** SHA-256 over the exact clientDataJSON bytes above. */
  readonly clientDataHash: readonly number[]
  readonly requestDigest: readonly number[]
  readonly challenge: readonly number[]
  readonly origin: string
  readonly rpId: string
}

export interface PasskeyIngressCreateSnapshot extends PasskeyIngressSnapshotBase {
  readonly kind: 'create'
  readonly options: PasskeyIngressCreateOptions
  readonly discoverable: boolean
}

export interface PasskeyIngressGetSnapshot extends PasskeyIngressSnapshotBase {
  readonly kind: 'get'
  readonly options: PasskeyIngressGetOptions
}

/** Main-process-only ceremony input. It is intentionally unsuitable for renderer IPC. */
export type PasskeyIngressSnapshot = PasskeyIngressCreateSnapshot | PasskeyIngressGetSnapshot

type PlainRecord = Record<string, unknown>

function fail(code: PasskeyIngressErrorCode): never {
  throw new PasskeyIngressError(code)
}

function isPlainRecord(value: unknown): value is PlainRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return Reflect.ownKeys(descriptors).every((key) => {
    if (typeof key !== 'string') return false
    const descriptor = descriptors[key]!
    return (
      descriptor.enumerable === true &&
      'value' in descriptor &&
      descriptor.get === undefined &&
      descriptor.set === undefined
    )
  })
}

function record(value: unknown, code: PasskeyIngressErrorCode = 'INVALID_PAYLOAD'): PlainRecord {
  if (!isPlainRecord(value)) fail(code)
  return value
}

function exactKeys(
  value: PlainRecord,
  required: readonly string[],
  optional: readonly string[] = [],
  code: PasskeyIngressErrorCode = 'INVALID_PAYLOAD'
): void {
  const keys = Object.keys(value)
  const allowed = new Set([...required, ...optional])
  if (
    required.some((key) => !Object.prototype.hasOwnProperty.call(value, key)) ||
    keys.some((key) => !allowed.has(key))
  ) {
    fail(code)
  }
}

function rawArray(
  value: unknown,
  maximum: number,
  code: PasskeyIngressErrorCode = 'INVALID_PAYLOAD'
): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail(code)
  if (value.length > maximum) fail(code)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.some((key) => typeof key !== 'string')) fail(code)
  const elementKeys = keys.filter((key) => key !== 'length') as string[]
  if (elementKeys.length !== value.length) fail(code)
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)]
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !('value' in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      fail(code)
    }
  }
  return value
}

function boundedString(
  value: unknown,
  maximum: number,
  code: PasskeyIngressErrorCode = 'INVALID_PAYLOAD'
): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) fail(code)
  return value
}

function boundedText(value: unknown): string {
  const text = boundedString(value, MAX_TEXT_LENGTH)
  if (/\p{Cc}/u.test(text)) fail('INVALID_PAYLOAD')
  return text
}

function frozenBytes(value: Uint8Array): readonly number[] {
  return Object.freeze(Array.from(value))
}

function decodeBase64Url(
  value: unknown,
  minimumBytes: number,
  maximumBytes: number,
  code: PasskeyIngressErrorCode
): Uint8Array {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > Math.ceil((maximumBytes * 4) / 3) ||
    !BASE64URL.test(value)
  ) {
    fail(code)
  }
  const bytes = Buffer.from(value, 'base64url')
  if (
    bytes.byteLength < minimumBytes ||
    bytes.byteLength > maximumBytes ||
    bytes.toString('base64url') !== value
  ) {
    fail(code)
  }
  return bytes
}

function validateTransportContext(context: PasskeyIngressTransportContext): PasskeyIngressPeer {
  const candidate = record(context, 'INVALID_TRANSPORT_CONTEXT')
  exactKeys(candidate, ['provider', 'binding', 'epoch', 'signal'], [], 'INVALID_TRANSPORT_CONTEXT')
  const provider = boundedString(
    candidate.provider,
    MAX_PROVIDER_LENGTH,
    'INVALID_TRANSPORT_CONTEXT'
  )
  const binding = boundedString(
    candidate.binding,
    MAX_PEER_BINDING_LENGTH,
    'INVALID_TRANSPORT_CONTEXT'
  )
  if (!TRUSTED_IDENTITY.test(provider) || !TRUSTED_IDENTITY.test(binding)) {
    fail('INVALID_TRANSPORT_CONTEXT')
  }
  if (
    typeof candidate.epoch !== 'number' ||
    !Number.isSafeInteger(candidate.epoch) ||
    candidate.epoch < 0 ||
    !(candidate.signal instanceof AbortSignal)
  ) {
    fail('INVALID_TRANSPORT_CONTEXT')
  }
  if (candidate.signal.aborted) fail('PEER_DISCONNECTED')
  return Object.freeze({ provider, binding, epoch: candidate.epoch })
}

function parseTimeout(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_TIMEOUT_MS
  ) {
    fail('INVALID_PAYLOAD')
  }
  return value
}

function parseUserVerification(value: unknown): PasskeyIngressUserVerification {
  if (value === undefined) return 'preferred'
  if (value === 'required' || value === 'preferred' || value === 'discouraged') return value
  return fail('INVALID_PAYLOAD')
}

function parseExtensions(value: unknown): Readonly<Record<string, never>> {
  if (value === undefined) return Object.freeze({})
  const extensions = record(value)
  if (Object.keys(extensions).length !== 0) fail('UNSUPPORTED_OPTION')
  return Object.freeze({})
}

function parseTransports(value: unknown): readonly PasskeyIngressAuthenticatorTransport[] {
  if (value === undefined) return Object.freeze([])
  const input = rawArray(value, MAX_TRANSPORTS)
  const seen = new Set<string>()
  const transports: PasskeyIngressAuthenticatorTransport[] = []
  for (const transport of input) {
    if (
      typeof transport !== 'string' ||
      transport.length === 0 ||
      transport.length > MAX_TRANSPORT_LENGTH ||
      /\p{Cc}/u.test(transport)
    ) {
      fail('INVALID_PAYLOAD')
    }
    if (
      transport !== 'usb' &&
      transport !== 'nfc' &&
      transport !== 'ble' &&
      transport !== 'smart-card' &&
      transport !== 'internal' &&
      transport !== 'hybrid'
    ) {
      continue
    }
    if (seen.has(transport)) continue
    seen.add(transport)
    transports.push(transport)
  }
  return Object.freeze(transports)
}

function parseCredentialDescriptors(value: unknown): readonly PasskeyIngressCredentialDescriptor[] {
  if (value === undefined) return Object.freeze([])
  const input = rawArray(value, MAX_CREDENTIAL_DESCRIPTORS)
  const seen = new Set<string>()
  return Object.freeze(
    input.map((candidate): PasskeyIngressCredentialDescriptor => {
      const descriptor = record(candidate)
      exactKeys(descriptor, ['type', 'id'], ['transports'])
      if (descriptor.type !== 'public-key') fail('INVALID_PAYLOAD')
      const idBytes = decodeBase64Url(descriptor.id, 1, MAX_CREDENTIAL_ID_BYTES, 'INVALID_PAYLOAD')
      const idKey = Buffer.from(idBytes).toString('base64url')
      if (seen.has(idKey)) fail('INVALID_PAYLOAD')
      seen.add(idKey)
      return Object.freeze({
        type: 'public-key' as const,
        id: frozenBytes(idBytes),
        transports: parseTransports(descriptor.transports)
      })
    })
  )
}

function parseAuthenticatorSelection(value: unknown): PasskeyIngressAuthenticatorSelection {
  if (value === undefined) {
    return Object.freeze({ userVerification: 'preferred' })
  }
  const selection = record(value)
  exactKeys(
    selection,
    [],
    ['authenticatorAttachment', 'residentKey', 'requireResidentKey', 'userVerification']
  )
  if (
    selection.authenticatorAttachment !== undefined &&
    selection.authenticatorAttachment !== 'platform' &&
    selection.authenticatorAttachment !== 'cross-platform'
  ) {
    fail('INVALID_PAYLOAD')
  }
  if (selection.authenticatorAttachment === 'cross-platform') fail('UNSUPPORTED_OPTION')
  if (
    selection.residentKey !== undefined &&
    selection.residentKey !== 'required' &&
    selection.residentKey !== 'preferred' &&
    selection.residentKey !== 'discouraged'
  ) {
    fail('INVALID_PAYLOAD')
  }
  if (
    selection.requireResidentKey !== undefined &&
    typeof selection.requireResidentKey !== 'boolean'
  ) {
    fail('INVALID_PAYLOAD')
  }
  if (
    (selection.residentKey === 'required' && selection.requireResidentKey === false) ||
    (selection.residentKey === 'discouraged' && selection.requireResidentKey === true)
  ) {
    fail('INVALID_PAYLOAD')
  }
  return Object.freeze({
    ...(selection.authenticatorAttachment === undefined
      ? {}
      : { authenticatorAttachment: selection.authenticatorAttachment }),
    ...(selection.residentKey === undefined ? {} : { residentKey: selection.residentKey }),
    ...(selection.requireResidentKey === undefined
      ? {}
      : { requireResidentKey: selection.requireResidentKey }),
    userVerification: parseUserVerification(selection.userVerification)
  })
}

function parsePubKeyCredParams(value: unknown): PasskeyIngressCreateOptions['pubKeyCredParams'] {
  const parameters = rawArray(value, MAX_PUB_KEY_CREDENTIAL_PARAMETERS)
  let supportsEs256 = false
  for (const candidate of parameters) {
    const parameter = record(candidate)
    exactKeys(parameter, ['type', 'alg'])
    if (
      typeof parameter.type !== 'string' ||
      parameter.type.length === 0 ||
      parameter.type.length > MAX_TEXT_LENGTH ||
      /\p{Cc}/u.test(parameter.type) ||
      typeof parameter.alg !== 'number' ||
      !Number.isInteger(parameter.alg) ||
      parameter.alg < MIN_COSE_ALGORITHM ||
      parameter.alg > MAX_COSE_ALGORITHM
    ) {
      fail('INVALID_PAYLOAD')
    }
    if (parameter.type === 'public-key' && parameter.alg === ES256_ALGORITHM) {
      supportsEs256 = true
    }
  }
  if (!supportsEs256) fail('UNSUPPORTED_OPTION')
  return Object.freeze([Object.freeze({ type: 'public-key' as const, alg: ES256_ALGORITHM })])
}

function parseCreateOptions(value: unknown): ParsedPasskeyIngressCreateOptions {
  const options = record(value)
  exactKeys(
    options,
    ['challenge', 'rp', 'user', 'pubKeyCredParams'],
    ['timeout', 'excludeCredentials', 'authenticatorSelection', 'attestation', 'extensions']
  )
  const challenge = decodeBase64Url(
    options.challenge,
    MIN_CHALLENGE_BYTES,
    MAX_CHALLENGE_BYTES,
    'INVALID_PAYLOAD'
  )
  const rp = record(options.rp)
  exactKeys(rp, ['name'], ['id'])
  const user = record(options.user)
  exactKeys(user, ['id', 'name', 'displayName'])
  const userId = decodeBase64Url(user.id, 1, MAX_USER_HANDLE_BYTES, 'INVALID_PAYLOAD')
  if (options.attestation !== undefined && options.attestation !== 'none') {
    fail('UNSUPPORTED_OPTION')
  }
  return Object.freeze({
    challenge: frozenBytes(challenge),
    rp: Object.freeze({
      ...(rp.id === undefined ? {} : { id: boundedString(rp.id, 253) }),
      name: boundedText(rp.name)
    }),
    user: Object.freeze({
      id: frozenBytes(userId),
      name: boundedText(user.name),
      displayName: boundedText(user.displayName)
    }),
    pubKeyCredParams: parsePubKeyCredParams(options.pubKeyCredParams),
    ...(options.timeout === undefined ? {} : { timeout: parseTimeout(options.timeout) }),
    excludeCredentials: parseCredentialDescriptors(options.excludeCredentials),
    authenticatorSelection: parseAuthenticatorSelection(options.authenticatorSelection),
    attestation: 'none' as const,
    extensions: parseExtensions(options.extensions)
  })
}

function parseMediation(value: unknown): PasskeyIngressMediation {
  if (value === undefined) return 'optional'
  if (value === 'conditional') fail('UNSUPPORTED_OPTION')
  if (value === 'silent' || value === 'optional' || value === 'required') return value
  return fail('INVALID_PAYLOAD')
}

function parseGetOptions(value: unknown): ParsedPasskeyIngressGetOptions {
  const options = record(value)
  exactKeys(
    options,
    ['challenge'],
    ['rpId', 'timeout', 'allowCredentials', 'userVerification', 'mediation', 'extensions']
  )
  const challenge = decodeBase64Url(
    options.challenge,
    MIN_CHALLENGE_BYTES,
    MAX_CHALLENGE_BYTES,
    'INVALID_PAYLOAD'
  )
  return Object.freeze({
    challenge: frozenBytes(challenge),
    ...(options.rpId === undefined ? {} : { rpId: boundedString(options.rpId, 253) }),
    ...(options.timeout === undefined ? {} : { timeout: parseTimeout(options.timeout) }),
    allowCredentials: parseCredentialDescriptors(options.allowCredentials),
    userVerification: parseUserVerification(options.userVerification),
    mediation: parseMediation(options.mediation),
    extensions: parseExtensions(options.extensions)
  })
}

function collectTopLevelJsonKeys(json: string): readonly string[] {
  const keys: string[] = []
  let depth = 0
  let index = 0
  let inString = false
  while (index < json.length) {
    const character = json[index]!
    if (character === '"') {
      const start = index
      inString = true
      index += 1
      while (index < json.length && inString) {
        if (json[index] === '\\') {
          index += 2
        } else if (json[index] === '"') {
          inString = false
          index += 1
        } else {
          index += 1
        }
      }
      if (depth === 1) {
        let cursor = index
        while (cursor < json.length && /\s/u.test(json[cursor]!)) cursor += 1
        if (json[cursor] === ':') {
          try {
            keys.push(JSON.parse(json.slice(start, index)) as string)
          } catch {
            fail('INVALID_CLIENT_DATA')
          }
        }
      }
      continue
    }
    if (character === '{' || character === '[') depth += 1
    if (character === '}' || character === ']') depth -= 1
    index += 1
  }
  return keys
}

interface ParsedClientData {
  readonly bytes: Uint8Array
  readonly hash: Uint8Array
  readonly type: string
  readonly challenge: Uint8Array
  readonly origin: string
  readonly crossOrigin: boolean
}

function parseClientData(value: unknown): ParsedClientData {
  const bytes = decodeBase64Url(value, 2, MAX_CLIENT_DATA_JSON_BYTES, 'INVALID_CLIENT_DATA')
  let json: string
  let parsed: PlainRecord
  try {
    json = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    parsed = record(JSON.parse(json), 'INVALID_CLIENT_DATA')
  } catch (error) {
    if (error instanceof PasskeyIngressError) throw error
    return fail('INVALID_CLIENT_DATA')
  }
  const keys = collectTopLevelJsonKeys(json)
  if (new Set(keys).size !== keys.length) fail('INVALID_CLIENT_DATA')
  if (Object.prototype.hasOwnProperty.call(parsed, 'topOrigin')) {
    fail('CROSS_ORIGIN_UNSUPPORTED')
  }
  exactKeys(parsed, ['type', 'challenge', 'origin'], ['crossOrigin'], 'INVALID_CLIENT_DATA')
  if (
    typeof parsed.type !== 'string' ||
    typeof parsed.origin !== 'string' ||
    (parsed.crossOrigin !== undefined && typeof parsed.crossOrigin !== 'boolean')
  ) {
    fail('INVALID_CLIENT_DATA')
  }
  if (parsed.crossOrigin === true) fail('CROSS_ORIGIN_UNSUPPORTED')
  return Object.freeze({
    bytes,
    hash: createHash('sha256').update(bytes).digest(),
    type: parsed.type,
    challenge: decodeBase64Url(
      parsed.challenge,
      MIN_CHALLENGE_BYTES,
      MAX_CHALLENGE_BYTES,
      'INVALID_CLIENT_DATA'
    ),
    origin: parsed.origin,
    crossOrigin: parsed.crossOrigin ?? false
  })
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('INVALID_PAYLOAD')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const object = record(value)
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(',')}}`
}

function requestDigest(
  peer: PasskeyIngressPeer,
  kind: 'create' | 'get',
  origin: string,
  rpId: string,
  clientDataHash: Uint8Array,
  challenge: Uint8Array,
  options: PasskeyIngressCreateOptions | PasskeyIngressGetOptions
): readonly number[] {
  const input = {
    version: 1,
    peer,
    kind,
    origin,
    rpId,
    clientDataHash: Buffer.from(clientDataHash).toString('base64url'),
    challenge: Buffer.from(challenge).toString('base64url'),
    options
  }
  return frozenBytes(createHash('sha256').update(canonicalJson(input), 'utf8').digest())
}

function matchesChallenge(left: Uint8Array, right: readonly number[]): boolean {
  return left.byteLength === right.length && timingSafeEqual(left, Uint8Array.from(right))
}

function createDiscoverable(selection: PasskeyIngressAuthenticatorSelection): boolean {
  if (selection.residentKey === 'required' || selection.residentKey === 'preferred') return true
  if (selection.residentKey === 'discouraged') return false
  return selection.requireResidentKey === true
}

function defaultRpIdFromOrigin(origin: string): string {
  try {
    return new URL(origin).hostname
  } catch {
    return fail('ORIGIN_REJECTED')
  }
}

/**
 * Parses and binds one provider-neutral v1 ceremony. The returned snapshot stays in main; only a
 * separately derived approval prompt may cross into a renderer.
 *
 * @see https://www.w3.org/TR/webauthn-3/#client-data
 * @see https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
 */
export function bindPasskeyIngressRequest(
  rawPayload: unknown,
  transport: PasskeyIngressTransportContext
): PasskeyIngressSnapshot {
  try {
    return bindPasskeyIngressRequestInternal(rawPayload, transport)
  } catch (error) {
    if (error instanceof PasskeyIngressError) throw error
    return fail('INVALID_PAYLOAD')
  }
}

function bindPasskeyIngressRequestInternal(
  rawPayload: unknown,
  transport: PasskeyIngressTransportContext
): PasskeyIngressSnapshot {
  const peer = validateTransportContext(transport)
  const signal = transport.signal
  const payload = record(rawPayload)
  exactKeys(payload, ['version', 'kind', 'clientDataJSON', 'options'])
  if (payload.version !== 1) fail('UNSUPPORTED_VERSION')
  if (payload.kind !== 'create' && payload.kind !== 'get') fail('INVALID_PAYLOAD')

  const clientData = parseClientData(payload.clientDataJSON)
  const expectedType = payload.kind === 'create' ? 'webauthn.create' : 'webauthn.get'
  if (clientData.type !== expectedType) fail('CEREMONY_MISMATCH')
  const options =
    payload.kind === 'create'
      ? parseCreateOptions(payload.options)
      : parseGetOptions(payload.options)
  if (!matchesChallenge(clientData.challenge, options.challenge)) fail('CEREMONY_MISMATCH')
  const requestedRpId =
    payload.kind === 'create'
      ? ((options as ParsedPasskeyIngressCreateOptions).rp.id ??
        defaultRpIdFromOrigin(clientData.origin))
      : ((options as ParsedPasskeyIngressGetOptions).rpId ??
        defaultRpIdFromOrigin(clientData.origin))
  let validatedOrigin: ReturnType<typeof validatePasskeyOrigin>
  try {
    validatedOrigin = validatePasskeyOrigin({
      origin: clientData.origin,
      rpId: requestedRpId,
      crossOrigin: clientData.crossOrigin
    })
  } catch {
    fail('ORIGIN_REJECTED')
  }
  // clientDataJSON contains an RFC 6454 serialized origin. Do not accept a spelling that only
  // becomes valid after URL normalization; the exact claimed origin is part of the ceremony.
  if (clientData.origin !== validatedOrigin.origin) fail('ORIGIN_REJECTED')
  if (signal.aborted) fail('PEER_DISCONNECTED')

  // Keep one canonical RP ID throughout the trusted snapshot. Raw options are never spread over
  // this value, so downstream code cannot accidentally choose an unnormalized spelling.
  const canonicalOptions: PasskeyIngressCreateOptions | PasskeyIngressGetOptions =
    payload.kind === 'create'
      ? Object.freeze({
          ...(options as ParsedPasskeyIngressCreateOptions),
          rp: Object.freeze({
            ...(options as ParsedPasskeyIngressCreateOptions).rp,
            id: validatedOrigin.rpId
          })
        })
      : Object.freeze({
          ...(options as ParsedPasskeyIngressGetOptions),
          rpId: validatedOrigin.rpId
        })

  const base = {
    version: 1 as const,
    peer,
    signal,
    clientDataJSON: frozenBytes(clientData.bytes),
    clientDataHash: frozenBytes(clientData.hash),
    challenge: canonicalOptions.challenge,
    origin: validatedOrigin.origin,
    rpId: validatedOrigin.rpId
  }
  const digest = requestDigest(
    peer,
    payload.kind,
    base.origin,
    base.rpId,
    clientData.hash,
    clientData.challenge,
    canonicalOptions
  )

  if (payload.kind === 'create') {
    const createOptions = canonicalOptions as PasskeyIngressCreateOptions
    return Object.freeze({
      ...base,
      kind: 'create' as const,
      requestDigest: digest,
      options: createOptions,
      discoverable: createDiscoverable(createOptions.authenticatorSelection)
    })
  }
  const getOptions = canonicalOptions as PasskeyIngressGetOptions
  return Object.freeze({
    ...base,
    kind: 'get' as const,
    requestDigest: digest,
    options: getOptions
  })
}
