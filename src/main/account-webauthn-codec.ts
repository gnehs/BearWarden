import { domainToASCII } from 'node:url'
import { parse as parseDomain } from 'tldts'

const MAX_CHALLENGE_BYTES = 1_024
const MAX_CREDENTIAL_ID_BYTES = 1_023
const MAX_ALLOW_CREDENTIALS = 64
const MAX_TIMEOUT_MS = 10 * 60 * 1_000
const MAX_RP_ID_LENGTH = 253
const MAX_UVM_ENTRIES = 16
const MAX_UVM_VALUES = 3

type PlainRecord = Record<string, unknown>

export class AccountWebAuthnCodecError extends Error {
  constructor() {
    super('INVALID_ACCOUNT_WEBAUTHN_PAYLOAD')
    this.name = 'AccountWebAuthnCodecError'
  }
}

export interface AccountWebAuthnCredentialDescriptor {
  readonly type: 'public-key'
  readonly id: string
  readonly transports?: readonly ('usb' | 'nfc' | 'ble' | 'internal' | 'hybrid')[]
}

export interface AccountWebAuthnChallenge {
  readonly challenge: string
  readonly rpId: string
  readonly allowCredentials: readonly AccountWebAuthnCredentialDescriptor[]
  readonly timeout: number
  readonly userVerification: 'required' | 'preferred' | 'discouraged'
  readonly extensions: Readonly<{ appid?: string; uvm?: true }>
}

export interface AccountWebAuthnAssertion {
  id: string
  rawId: string
  type: 'public-key'
  response: {
    clientDataJSON: string
    authenticatorData: string
    signature: string
    userHandle: string | null
  }
  clientExtensionResults: {
    appid?: boolean
    uvm?: readonly (readonly number[])[]
  }
  authenticatorAttachment?: 'platform' | 'cross-platform' | null
}

function invalid(): never {
  throw new AccountWebAuthnCodecError()
}

function record(value: unknown): PlainRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid()
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) invalid()
    return value as PlainRecord
  } catch (error) {
    if (error instanceof AccountWebAuthnCodecError) throw error
    invalid()
  }
}

function data(recordValue: PlainRecord, key: PropertyKey): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(recordValue, key)
    if (!descriptor || !('value' in descriptor)) invalid()
    return descriptor.value
  } catch (error) {
    if (error instanceof AccountWebAuthnCodecError) throw error
    invalid()
  }
}

function optionalData(recordValue: PlainRecord, key: PropertyKey): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(recordValue, key)
    if (!descriptor) return undefined
    if (!('value' in descriptor)) invalid()
    return descriptor.value
  } catch (error) {
    if (error instanceof AccountWebAuthnCodecError) throw error
    invalid()
  }
}

function keys(recordValue: PlainRecord): string[] {
  try {
    const ownKeys = Reflect.ownKeys(recordValue)
    if (ownKeys.some((key) => typeof key !== 'string')) invalid()
    return ownKeys as string[]
  } catch (error) {
    if (error instanceof AccountWebAuthnCodecError) throw error
    invalid()
  }
}

function exact(
  recordValue: PlainRecord,
  required: readonly string[],
  optional: readonly string[]
): void {
  const ownKeys = keys(recordValue)
  if (
    required.some((key) => !ownKeys.includes(key)) ||
    ownKeys.some((key) => !required.includes(key) && !optional.includes(key))
  ) {
    invalid()
  }
  for (const key of ownKeys) data(recordValue, key)
}

function alias(recordValue: PlainRecord, names: readonly string[], required = true): unknown {
  let present: string[]
  try {
    present = names.filter((name) => Object.hasOwn(recordValue, name))
  } catch {
    invalid()
  }
  if (present.length > 1 || (required && present.length !== 1)) invalid()
  return present.length === 0 ? undefined : data(recordValue, present[0]!)
}

function strictArray(value: unknown, maximum: number): unknown[] {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid()
    if (value.length > maximum) invalid()
    const descriptors = Object.getOwnPropertyDescriptors(value)
    if (Reflect.ownKeys(descriptors).filter((key) => key !== 'length').length !== value.length)
      invalid()
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)]
      if (!descriptor || !('value' in descriptor)) invalid()
    }
    return value
  } catch (error) {
    if (error instanceof AccountWebAuthnCodecError) throw error
    invalid()
  }
}

function canonicalBase64Url(value: unknown, minimum: number, maximum: number): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) invalid()
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64url') !== value) {
    invalid()
  }
  return value
}

function canonicalRpId(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_RP_ID_LENGTH) invalid()
  const ascii = domainToASCII(value).toLowerCase()
  if (ascii !== value || ascii.includes('..')) invalid()
  const labels = ascii.split('.')
  if (
    labels.length < 2 ||
    labels.some(
      (label) =>
        label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    )
  ) {
    invalid()
  }
  const parsed = parseDomain(ascii, { allowPrivateDomains: true })
  if (parsed.isIp || parsed.domain === null) invalid()
  return ascii
}

function credentialDescriptor(value: unknown): AccountWebAuthnCredentialDescriptor {
  const candidate = record(value)
  const normalizedKeys = keys(candidate).map((key) => key.toLowerCase())
  if (
    normalizedKeys.length !== new Set(normalizedKeys).size ||
    normalizedKeys.some((key) => !['id', 'type', 'transports'].includes(key)) ||
    !normalizedKeys.includes('id') ||
    !normalizedKeys.includes('type')
  ) {
    invalid()
  }
  const id = canonicalBase64Url(alias(candidate, ['id', 'Id']), 1, MAX_CREDENTIAL_ID_BYTES)
  if (alias(candidate, ['type', 'Type']) !== 'public-key') invalid()
  const rawTransports = alias(candidate, ['transports', 'Transports'], false)
  if (rawTransports === undefined) return Object.freeze({ type: 'public-key', id })
  const transports = strictArray(rawTransports, 5)
  const allowed = new Set(['usb', 'nfc', 'ble', 'internal', 'hybrid'])
  if (
    transports.some((transport) => typeof transport !== 'string' || !allowed.has(transport)) ||
    new Set(transports).size !== transports.length
  ) {
    invalid()
  }
  return Object.freeze({
    type: 'public-key',
    id,
    transports: Object.freeze(transports as AccountWebAuthnCredentialDescriptor['transports'])
  })
}

function extensions(value: unknown, rpId: string): AccountWebAuthnChallenge['extensions'] {
  if (value === undefined) return Object.freeze({})
  const candidate = record(value)
  const normalizedKeys = keys(candidate).map((key) => key.toLowerCase())
  if (
    normalizedKeys.length !== new Set(normalizedKeys).size ||
    normalizedKeys.some((key) => !['appid', 'uvm', 'getcredblob'].includes(key))
  ) {
    invalid()
  }
  const result: { appid?: string; uvm?: true } = {}
  const appid = alias(candidate, ['appid', 'Appid', 'AppId'], false)
  if (appid !== undefined) {
    if (typeof appid !== 'string' || appid.length > 4_096) invalid()
    let url: URL
    try {
      url = new URL(appid)
    } catch {
      invalid()
    }
    if (
      url.protocol !== 'https:' ||
      url.hostname !== rpId ||
      (url.port !== '' && url.port !== '443') ||
      url.username !== '' ||
      url.password !== ''
    ) {
      invalid()
    }
    result.appid = url.toString()
  }
  const uvm = alias(candidate, ['uvm', 'Uvm'], false)
  if (uvm !== undefined) {
    if (uvm !== true) invalid()
    result.uvm = true
  }
  const getCredBlob = alias(candidate, ['getCredBlob', 'GetCredBlob'], false)
  if (getCredBlob !== undefined && typeof getCredBlob !== 'boolean') invalid()
  return Object.freeze(result)
}

export function parseAccountWebAuthnChallenge(value: unknown): AccountWebAuthnChallenge {
  const candidate = record(value)
  const normalizedKeys = keys(candidate).map((key) => key.toLowerCase())
  const allowed = [
    'challenge',
    'rpid',
    'allowcredentials',
    'timeout',
    'userverification',
    'extensions'
  ]
  if (
    normalizedKeys.length !== new Set(normalizedKeys).size ||
    normalizedKeys.some((key) => !allowed.includes(key)) ||
    allowed.slice(0, 5).some((key) => !normalizedKeys.includes(key))
  ) {
    invalid()
  }
  const challenge = canonicalBase64Url(
    alias(candidate, ['challenge', 'Challenge']),
    16,
    MAX_CHALLENGE_BYTES
  )
  const rpId = canonicalRpId(alias(candidate, ['rpId', 'RpId', 'RelyingPartyId']))
  const rawCredentials = alias(candidate, ['allowCredentials', 'AllowCredentials'])
  const allowCredentials = strictArray(rawCredentials, MAX_ALLOW_CREDENTIALS).map(
    credentialDescriptor
  )
  if (allowCredentials.length === 0) invalid()
  const credentialIds = allowCredentials.map(({ id }) => id)
  if (new Set(credentialIds).size !== credentialIds.length) invalid()
  const timeout = alias(candidate, ['timeout', 'Timeout'])
  const userVerification = alias(candidate, ['userVerification', 'UserVerification'])
  if (
    typeof timeout !== 'number' ||
    !Number.isSafeInteger(timeout) ||
    timeout < 1 ||
    timeout > MAX_TIMEOUT_MS ||
    (userVerification !== 'required' &&
      userVerification !== 'preferred' &&
      userVerification !== 'discouraged')
  ) {
    invalid()
  }
  return Object.freeze({
    challenge,
    rpId,
    allowCredentials: Object.freeze(allowCredentials),
    timeout,
    userVerification,
    extensions: extensions(alias(candidate, ['extensions', 'Extensions'], false), rpId)
  })
}

export function parseAccountWebAuthnChallengeFromTokenError(
  value: unknown
): AccountWebAuthnChallenge | undefined {
  const payload = record(value)
  const providers = alias(payload, ['TwoFactorProviders2', 'twoFactorProviders2'], false)
  if (providers === undefined) return undefined
  const providerMap = record(providers)
  const provider = optionalData(providerMap, '7')
  if (provider === undefined || provider === null) return undefined
  return parseAccountWebAuthnChallenge(provider)
}

function assertionUvm(value: unknown): readonly (readonly number[])[] {
  const rows = strictArray(value, MAX_UVM_ENTRIES)
  return Object.freeze(
    rows.map((row) => {
      const values = strictArray(row, MAX_UVM_VALUES)
      if (
        values.length !== MAX_UVM_VALUES ||
        values.some(
          (entry) =>
            typeof entry !== 'number' ||
            !Number.isSafeInteger(entry) ||
            entry < 0 ||
            entry > 0xffff_ffff
        )
      ) {
        invalid()
      }
      return Object.freeze(values as number[])
    })
  )
}

export function serializeAccountWebAuthnAssertion(value: unknown): string {
  const assertion = record(value)
  exact(
    assertion,
    ['id', 'rawId', 'type', 'response', 'clientExtensionResults'],
    ['authenticatorAttachment']
  )
  const id = canonicalBase64Url(data(assertion, 'id'), 1, MAX_CREDENTIAL_ID_BYTES)
  const rawId = canonicalBase64Url(data(assertion, 'rawId'), 1, MAX_CREDENTIAL_ID_BYTES)
  if (id !== rawId || data(assertion, 'type') !== 'public-key') invalid()
  const response = record(data(assertion, 'response'))
  exact(response, ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle'], [])
  const normalizedResponse = {
    clientDataJSON: canonicalBase64Url(data(response, 'clientDataJSON'), 1, 64 * 1024),
    authenticatorData: canonicalBase64Url(data(response, 'authenticatorData'), 1, 4 * 1024),
    signature: canonicalBase64Url(data(response, 'signature'), 1, 4 * 1024),
    userHandle:
      data(response, 'userHandle') === null
        ? null
        : canonicalBase64Url(data(response, 'userHandle'), 1, 64)
  }
  const clientExtensions = record(data(assertion, 'clientExtensionResults'))
  exact(clientExtensions, [], ['appid', 'uvm'])
  const appid = optionalData(clientExtensions, 'appid')
  const uvm = optionalData(clientExtensions, 'uvm')
  if (appid !== undefined && typeof appid !== 'boolean') invalid()
  const normalizedExtensions = {
    ...(appid === undefined ? {} : { appid }),
    ...(uvm === undefined ? {} : { uvm: assertionUvm(uvm) })
  }
  const attachment = optionalData(assertion, 'authenticatorAttachment')
  if (
    attachment !== undefined &&
    attachment !== null &&
    attachment !== 'platform' &&
    attachment !== 'cross-platform'
  )
    invalid()
  return JSON.stringify({
    id,
    rawId,
    type: 'public-key',
    response: {
      clientDataJson: normalizedResponse.clientDataJSON,
      authenticatorData: normalizedResponse.authenticatorData,
      signature: normalizedResponse.signature,
      ...(normalizedResponse.userHandle === null
        ? {}
        : { userHandle: normalizedResponse.userHandle })
    },
    extensions: normalizedExtensions
  })
}
