import { domainToASCII } from 'node:url'
import { parse as parseDomain } from 'tldts'
import { AccountWebAuthnCodecError } from './account-webauthn-codec'

const MAX_CHALLENGE_BYTES = 1_024
const MAX_CREDENTIAL_ID_BYTES = 1_023
const MAX_USER_ID_BYTES = 64
const MAX_CREDENTIALS = 64
const MAX_PARAMETERS = 32
const MAX_TIMEOUT_MS = 10 * 60 * 1_000
const MAX_RP_ID_LENGTH = 253
const MAX_ENTITY_NAME_LENGTH = 256
const MAX_CLIENT_DATA_BYTES = 64 * 1_024
const MAX_ATTESTATION_OBJECT_BYTES = 1024 * 1_024
const MAX_EXTENSION_BYTES = 4 * 1_024
const MAX_UVM_ENTRIES = 16
const MAX_UVM_VALUES = 3

type PlainRecord = Record<string, unknown>

type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'smart-card' | 'hybrid' | 'internal'

export interface AccountWebAuthnRegistrationCredentialDescriptor {
  readonly type: 'public-key'
  readonly id: string
  readonly transports?: readonly AuthenticatorTransport[]
}

export interface AccountWebAuthnRegistrationChallenge {
  readonly rp: Readonly<{ id: string; name: string }>
  readonly user: Readonly<{ id: string; name: string; displayName: string }>
  readonly challenge: string
  readonly pubKeyCredParams: readonly Readonly<{ type: 'public-key'; alg: number }>[]
  readonly timeout?: number
  readonly excludeCredentials: readonly AccountWebAuthnRegistrationCredentialDescriptor[]
  readonly authenticatorSelection: Readonly<{
    authenticatorAttachment?: 'platform' | 'cross-platform'
    residentKey?: 'discouraged' | 'preferred' | 'required'
    requireResidentKey?: boolean
    userVerification?: 'required' | 'preferred' | 'discouraged'
  }>
  readonly attestation: 'none' | 'indirect' | 'direct' | 'enterprise'
  readonly extensions: Readonly<{
    appidExclude?: string
    credProps?: boolean
    uvm?: boolean
    hmacCreateSecret?: boolean
    minPinLength?: boolean
    credBlob?: string
    largeBlob?: Readonly<{ support: 'required' | 'preferred' }>
    prf?: Readonly<{
      eval?: Readonly<{ first: string; second?: string }>
    }>
  }>
}

export interface AccountWebAuthnAttestation {
  id: string
  rawId: string
  type: 'public-key'
  response: {
    clientDataJSON: string
    attestationObject: string
  }
  clientExtensionResults: {
    appidExclude?: boolean
    credProps?: { rk?: boolean }
    largeBlob?: { supported?: boolean }
    prf?: { enabled?: boolean }
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

function aliasedShape(
  recordValue: PlainRecord,
  allowed: readonly string[],
  required: readonly string[]
): void {
  const normalizedKeys = keys(recordValue).map((key) => key.toLowerCase())
  if (
    normalizedKeys.length !== new Set(normalizedKeys).size ||
    normalizedKeys.some((key) => !allowed.includes(key)) ||
    required.some((key) => !normalizedKeys.includes(key))
  ) {
    invalid()
  }
  for (const key of keys(recordValue)) data(recordValue, key)
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

function boundedString(value: unknown, minimum: number, maximum: number): string {
  if (
    typeof value !== 'string' ||
    value.length < minimum ||
    value.length > maximum ||
    value.includes('\0') ||
    Buffer.from(value, 'utf8').toString('utf8') !== value
  ) {
    invalid()
  }
  return value
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

function rpEntity(value: unknown): AccountWebAuthnRegistrationChallenge['rp'] {
  const candidate = record(value)
  aliasedShape(candidate, ['id', 'name'], ['id', 'name'])
  return Object.freeze({
    id: canonicalRpId(alias(candidate, ['id', 'Id'])),
    name: boundedString(alias(candidate, ['name', 'Name']), 1, MAX_ENTITY_NAME_LENGTH)
  })
}

function userEntity(value: unknown): AccountWebAuthnRegistrationChallenge['user'] {
  const candidate = record(value)
  aliasedShape(candidate, ['id', 'name', 'displayname'], ['id', 'name', 'displayname'])
  return Object.freeze({
    id: canonicalBase64Url(alias(candidate, ['id', 'Id']), 1, MAX_USER_ID_BYTES),
    name: boundedString(alias(candidate, ['name', 'Name']), 1, MAX_ENTITY_NAME_LENGTH),
    displayName: boundedString(
      alias(candidate, ['displayName', 'DisplayName']),
      1,
      MAX_ENTITY_NAME_LENGTH
    )
  })
}

function credentialDescriptor(value: unknown): AccountWebAuthnRegistrationCredentialDescriptor {
  const candidate = record(value)
  aliasedShape(candidate, ['id', 'type', 'transports'], ['id', 'type'])
  const id = canonicalBase64Url(alias(candidate, ['id', 'Id']), 1, MAX_CREDENTIAL_ID_BYTES)
  if (alias(candidate, ['type', 'Type']) !== 'public-key') invalid()
  const rawTransports = alias(candidate, ['transports', 'Transports'], false)
  if (rawTransports === undefined) return Object.freeze({ type: 'public-key', id })
  const transports = strictArray(rawTransports, 6)
  const allowed = new Set<unknown>(['usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal'])
  if (
    transports.some((transport) => !allowed.has(transport)) ||
    new Set(transports).size !== transports.length
  ) {
    invalid()
  }
  return Object.freeze({
    type: 'public-key',
    id,
    transports: Object.freeze(transports as AuthenticatorTransport[])
  })
}

function publicKeyCredentialParameter(
  value: unknown
): AccountWebAuthnRegistrationChallenge['pubKeyCredParams'][number] {
  const candidate = record(value)
  aliasedShape(candidate, ['type', 'alg'], ['type', 'alg'])
  if (alias(candidate, ['type', 'Type']) !== 'public-key') invalid()
  const alg = alias(candidate, ['alg', 'Alg'])
  if (
    typeof alg !== 'number' ||
    !Number.isSafeInteger(alg) ||
    alg < -0x8000_0000 ||
    alg > 0x7fff_ffff
  )
    invalid()
  return Object.freeze({ type: 'public-key', alg })
}

function authenticatorSelection(
  value: unknown
): AccountWebAuthnRegistrationChallenge['authenticatorSelection'] {
  if (value === undefined) return Object.freeze({})
  const candidate = record(value)
  aliasedShape(
    candidate,
    ['authenticatorattachment', 'residentkey', 'requireresidentkey', 'userverification'],
    []
  )
  const authenticatorAttachment = alias(
    candidate,
    ['authenticatorAttachment', 'AuthenticatorAttachment'],
    false
  )
  const residentKey = alias(candidate, ['residentKey', 'ResidentKey'], false)
  const requireResidentKey = alias(candidate, ['requireResidentKey', 'RequireResidentKey'], false)
  const userVerification = alias(candidate, ['userVerification', 'UserVerification'], false)
  if (
    authenticatorAttachment !== undefined &&
    authenticatorAttachment !== 'platform' &&
    authenticatorAttachment !== 'cross-platform'
  )
    invalid()
  if (
    residentKey !== undefined &&
    residentKey !== 'discouraged' &&
    residentKey !== 'preferred' &&
    residentKey !== 'required'
  )
    invalid()
  if (requireResidentKey !== undefined && typeof requireResidentKey !== 'boolean') invalid()
  if (requireResidentKey === true && residentKey !== undefined && residentKey !== 'required')
    invalid()
  if (
    userVerification !== undefined &&
    userVerification !== 'required' &&
    userVerification !== 'preferred' &&
    userVerification !== 'discouraged'
  )
    invalid()
  return Object.freeze({
    ...(authenticatorAttachment === undefined ? {} : { authenticatorAttachment }),
    ...(residentKey === undefined ? {} : { residentKey }),
    ...(requireResidentKey === undefined ? {} : { requireResidentKey }),
    ...(userVerification === undefined ? {} : { userVerification })
  }) as AccountWebAuthnRegistrationChallenge['authenticatorSelection']
}

function extensionPrfEval(value: unknown): Readonly<{ first: string; second?: string }> {
  const candidate = record(value)
  exact(candidate, ['first'], ['second'])
  const first = canonicalBase64Url(data(candidate, 'first'), 1, MAX_EXTENSION_BYTES)
  const second = optionalData(candidate, 'second')
  return Object.freeze({
    first,
    ...(second === undefined ? {} : { second: canonicalBase64Url(second, 1, MAX_EXTENSION_BYTES) })
  })
}

function appId(value: unknown, rpId: string): string {
  if (typeof value !== 'string' || value.length > MAX_EXTENSION_BYTES) invalid()
  let url: URL
  try {
    url = new URL(value)
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
  return url.toString()
}

function creationExtensions(
  value: unknown,
  rpId: string
): AccountWebAuthnRegistrationChallenge['extensions'] {
  if (value === undefined) return Object.freeze({})
  const candidate = record(value)
  aliasedShape(
    candidate,
    [
      'appidexclude',
      'credprops',
      'uvm',
      'hmaccreatesecret',
      'minpinlength',
      'credblob',
      'largeblob',
      'prf'
    ],
    []
  )
  const result: {
    appidExclude?: string
    credProps?: boolean
    uvm?: boolean
    hmacCreateSecret?: boolean
    minPinLength?: boolean
    credBlob?: string
    largeBlob?: Readonly<{ support: 'required' | 'preferred' }>
    prf?: Readonly<{ eval?: Readonly<{ first: string; second?: string }> }>
  } = {}
  const appidExclude = alias(candidate, ['appidExclude', 'AppidExclude', 'AppIdExclude'], false)
  if (appidExclude !== undefined) result.appidExclude = appId(appidExclude, rpId)
  for (const [names, target] of [
    [['credProps', 'CredProps'], 'credProps'],
    [['uvm', 'Uvm'], 'uvm'],
    [['hmacCreateSecret', 'HmacCreateSecret'], 'hmacCreateSecret'],
    [['minPinLength', 'MinPinLength'], 'minPinLength']
  ] as const) {
    const extension = alias(candidate, names, false)
    if (extension !== undefined) {
      if (typeof extension !== 'boolean') invalid()
      result[target] = extension
    }
  }
  const credBlob = alias(candidate, ['credBlob', 'CredBlob'], false)
  if (credBlob !== undefined) {
    result.credBlob = canonicalBase64Url(credBlob, 1, MAX_EXTENSION_BYTES)
  }
  const largeBlob = alias(candidate, ['largeBlob', 'LargeBlob'], false)
  if (largeBlob !== undefined) {
    const largeBlobRecord = record(largeBlob)
    aliasedShape(largeBlobRecord, ['support'], ['support'])
    const support = alias(largeBlobRecord, ['support', 'Support'])
    if (support !== 'required' && support !== 'preferred') invalid()
    result.largeBlob = Object.freeze({ support })
  }
  const prf = alias(candidate, ['prf', 'Prf'], false)
  if (prf !== undefined) {
    const prfRecord = record(prf)
    aliasedShape(prfRecord, ['eval'], [])
    const evaluation = alias(prfRecord, ['eval', 'Eval'], false)
    result.prf = Object.freeze({
      ...(evaluation === undefined ? {} : { eval: extensionPrfEval(evaluation) })
    })
  }
  return Object.freeze(result)
}

/** Parses server-minted JSON options for `navigator.credentials.create()`. */
export function parseAccountWebAuthnRegistrationChallenge(
  value: unknown
): AccountWebAuthnRegistrationChallenge {
  const candidate = record(value)
  const allowed = [
    'rp',
    'user',
    'challenge',
    'pubkeycredparams',
    'timeout',
    'excludecredentials',
    'authenticatorselection',
    'attestation',
    'extensions',
    'status',
    'errormessage'
  ]
  aliasedShape(candidate, allowed, ['rp', 'user', 'challenge', 'pubkeycredparams'])

  const status = alias(candidate, ['status', 'Status'], false)
  const errorMessage = alias(candidate, ['errorMessage', 'ErrorMessage'], false)
  if (status !== undefined && status !== 'ok') invalid()
  if (errorMessage !== undefined && errorMessage !== '') invalid()

  const rawParameters = strictArray(
    alias(candidate, ['pubKeyCredParams', 'PubKeyCredParams']),
    MAX_PARAMETERS
  )
  if (rawParameters.length === 0) invalid()
  const pubKeyCredParams = rawParameters.map(publicKeyCredentialParameter)

  const rawExcluded = alias(candidate, ['excludeCredentials', 'ExcludeCredentials'], false)
  const excludeCredentials = (
    rawExcluded === undefined ? [] : strictArray(rawExcluded, MAX_CREDENTIALS)
  ).map(credentialDescriptor)
  const excludedIds = excludeCredentials.map(({ id }) => id)
  if (new Set(excludedIds).size !== excludedIds.length) invalid()

  const rawTimeout = alias(candidate, ['timeout', 'Timeout'], false)
  if (
    rawTimeout !== undefined &&
    (typeof rawTimeout !== 'number' ||
      !Number.isSafeInteger(rawTimeout) ||
      rawTimeout < 1 ||
      rawTimeout > MAX_TIMEOUT_MS)
  ) {
    invalid()
  }
  const rawAttestation = alias(candidate, ['attestation', 'Attestation'], false)
  const attestation = rawAttestation === undefined ? 'none' : rawAttestation
  if (
    attestation !== 'none' &&
    attestation !== 'indirect' &&
    attestation !== 'direct' &&
    attestation !== 'enterprise'
  )
    invalid()

  const rp = rpEntity(alias(candidate, ['rp', 'Rp']))
  return Object.freeze({
    rp,
    user: userEntity(alias(candidate, ['user', 'User'])),
    challenge: canonicalBase64Url(
      alias(candidate, ['challenge', 'Challenge']),
      16,
      MAX_CHALLENGE_BYTES
    ),
    pubKeyCredParams: Object.freeze(pubKeyCredParams),
    ...(rawTimeout === undefined ? {} : { timeout: rawTimeout }),
    excludeCredentials: Object.freeze(excludeCredentials),
    authenticatorSelection: authenticatorSelection(
      alias(candidate, ['authenticatorSelection', 'AuthenticatorSelection'], false)
    ),
    attestation,
    extensions: creationExtensions(alias(candidate, ['extensions', 'Extensions'], false), rp.id)
  }) as AccountWebAuthnRegistrationChallenge
}

/** Supports the official Bitwarden `{ options }` envelope and Vaultwarden's direct options. */
export function parseAccountWebAuthnRegistrationChallengeFromResponse(
  value: unknown
): AccountWebAuthnRegistrationChallenge {
  const payload = record(value)
  const options = alias(payload, ['options', 'Options'], false)
  if (options === undefined) return parseAccountWebAuthnRegistrationChallenge(payload)
  aliasedShape(payload, ['options', 'object'], ['options'])
  const object = alias(payload, ['object', 'Object'], false)
  if (object !== undefined && typeof object !== 'string') invalid()
  return parseAccountWebAuthnRegistrationChallenge(options)
}

function uvmResult(value: unknown): readonly (readonly number[])[] {
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

function booleanResultObject(value: unknown, key: string): Readonly<Record<string, boolean>> {
  const candidate = record(value)
  exact(candidate, [], [key])
  const result = optionalData(candidate, key)
  if (result !== undefined && typeof result !== 'boolean') invalid()
  return Object.freeze(result === undefined ? {} : { [key]: result })
}

function registrationExtensionResults(value: unknown): Readonly<Record<string, unknown>> {
  const candidate = record(value)
  exact(candidate, [], ['appidExclude', 'credProps', 'largeBlob', 'prf', 'uvm'])
  const appidExclude = optionalData(candidate, 'appidExclude')
  const credProps = optionalData(candidate, 'credProps')
  const largeBlob = optionalData(candidate, 'largeBlob')
  const prf = optionalData(candidate, 'prf')
  const uvm = optionalData(candidate, 'uvm')
  if (appidExclude !== undefined && typeof appidExclude !== 'boolean') invalid()
  return Object.freeze({
    ...(appidExclude === undefined ? {} : { appidExclude }),
    ...(credProps === undefined ? {} : { credProps: booleanResultObject(credProps, 'rk') }),
    ...(largeBlob === undefined ? {} : { largeBlob: booleanResultObject(largeBlob, 'supported') }),
    ...(prf === undefined ? {} : { prf: booleanResultObject(prf, 'enabled') }),
    ...(uvm === undefined ? {} : { uvm: uvmResult(uvm) })
  })
}

/** Serializes the native creation result to Bitwarden/Vaultwarden's exact wire casing. */
export function serializeAccountWebAuthnAttestation(value: unknown): string {
  const attestation = record(value)
  exact(
    attestation,
    ['id', 'rawId', 'type', 'response', 'clientExtensionResults'],
    ['authenticatorAttachment']
  )
  const id = canonicalBase64Url(data(attestation, 'id'), 1, MAX_CREDENTIAL_ID_BYTES)
  const rawId = canonicalBase64Url(data(attestation, 'rawId'), 1, MAX_CREDENTIAL_ID_BYTES)
  if (id !== rawId || data(attestation, 'type') !== 'public-key') invalid()

  const response = record(data(attestation, 'response'))
  exact(response, ['clientDataJSON', 'attestationObject'], [])
  const clientDataJson = canonicalBase64Url(
    data(response, 'clientDataJSON'),
    1,
    MAX_CLIENT_DATA_BYTES
  )
  const attestationObject = canonicalBase64Url(
    data(response, 'attestationObject'),
    1,
    MAX_ATTESTATION_OBJECT_BYTES
  )
  const extensions = registrationExtensionResults(data(attestation, 'clientExtensionResults'))
  const attachment = optionalData(attestation, 'authenticatorAttachment')
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
    extensions,
    response: {
      AttestationObject: attestationObject,
      clientDataJson
    }
  })
}
