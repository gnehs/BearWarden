import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomUUID,
  sign as signData,
  type KeyObject
} from 'node:crypto'
import { isIP } from 'node:net'
import { Encoder } from 'cbor-x'
import type { StoredPasskeyCredential } from './passkey'

const ES256_ALGORITHM = -7 as const
const MAX_RP_ID_LENGTH = 253
const MAX_TEXT_LENGTH = 1024
const MAX_USER_HANDLE_BYTES = 64
const MAX_CREDENTIAL_ID_BYTES = 1023
const MAX_PKCS8_BYTES = 1024
const MAX_UINT32 = 0xffff_ffff
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u
const AAGUID_BYTES = Buffer.from('d548826e79b4db40a3d811116f7e8349', 'hex')

/** The AAGUID used by Bitwarden's software authenticator. */
export const BITWARDEN_AAGUID = 'd548826e-79b4-db40-a3d8-11116f7e8349'

export type PasskeyAuthenticatorErrorCode =
  'INVALID_INPUT' | 'INVALID_CREDENTIAL' | 'RP_ID_MISMATCH' | 'COUNTER_OVERFLOW'

export class PasskeyAuthenticatorError extends Error {
  constructor(public readonly code: PasskeyAuthenticatorErrorCode) {
    super(code)
    this.name = 'PasskeyAuthenticatorError'
  }
}

export interface CreatePasskeyCredentialParams {
  rpId: string
  rpName: string
  userHandle: Uint8Array
  userName: string
  userDisplayName: string
  discoverable: boolean
  userVerified: boolean
  userPresent?: boolean
}

export interface PasskeyAuthenticatorDependencies {
  uuid?: () => string
  now?: () => Date
}

export interface CreatePasskeyCredentialResult {
  credential: StoredPasskeyCredential
  credentialId: Uint8Array
  attestationObject: Uint8Array
  authenticatorData: Uint8Array
  publicKey: Uint8Array
  publicKeyAlgorithm: typeof ES256_ALGORITHM
}

export interface GetPasskeyAssertionParams {
  credential: StoredPasskeyCredential
  rpId: string
  clientDataHash: Uint8Array
  userVerified: boolean
  userPresent?: boolean
}

export interface GetPasskeyAssertionResult {
  credentialId: Uint8Array
  userHandle: Uint8Array | null
  authenticatorData: Uint8Array
  signature: Uint8Array
  /** The validated next value that the vault must persist atomically. */
  counter: string
}

const attestationEncoder = new Encoder({
  useRecords: false,
  tagUint8Array: false,
  variableMapSize: true
})

function fail(code: PasskeyAuthenticatorErrorCode): never {
  throw new PasskeyAuthenticatorError(code)
}

function validateBoundedString(
  value: unknown,
  maximumLength: number,
  allowEmpty: boolean,
  code: PasskeyAuthenticatorErrorCode
): string {
  if (typeof value !== 'string' || value.length > maximumLength) fail(code)
  if (!allowEmpty && value.length === 0) fail(code)
  return value
}

function validateNullableText(value: unknown): void {
  if (value === null) return
  validateBoundedString(value, MAX_TEXT_LENGTH, true, 'INVALID_CREDENTIAL')
}

function validateRpId(value: unknown, code: PasskeyAuthenticatorErrorCode): string {
  const rpId = validateBoundedString(value, MAX_RP_ID_LENGTH, false, code)
  if (rpId !== rpId.toLowerCase() || !/^[\x21-\x7e]+$/u.test(rpId) || isIP(rpId) !== 0) {
    fail(code)
  }
  if (rpId === 'localhost') return rpId
  if (rpId.endsWith('.') || !rpId.includes('.')) fail(code)

  const labels = rpId.split('.')
  for (const label of labels) {
    if (
      label.length === 0 ||
      label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    ) {
      fail(code)
    }
  }
  return rpId
}

function copyBoundedBytes(
  value: unknown,
  minimum: number,
  maximum: number,
  code: PasskeyAuthenticatorErrorCode
): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength < minimum || value.byteLength > maximum) {
    fail(code)
  }
  return Buffer.from(value)
}

function decodeBase64Url(
  value: unknown,
  minimumBytes: number,
  maximumBytes: number,
  code: PasskeyAuthenticatorErrorCode
): Buffer {
  const encoded = validateBoundedString(value, Math.ceil((maximumBytes * 4) / 3), false, code)
  if (!BASE64URL_PATTERN.test(encoded)) fail(code)

  const decoded = Buffer.from(encoded, 'base64url')
  if (
    decoded.byteLength < minimumBytes ||
    decoded.byteLength > maximumBytes ||
    decoded.toString('base64url') !== encoded
  ) {
    fail(code)
  }
  return decoded
}

function uuidToBytes(value: unknown, code: PasskeyAuthenticatorErrorCode): Buffer {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) fail(code)
  return Buffer.from(value.replaceAll('-', ''), 'hex')
}

function credentialIdToBytes(value: unknown): Buffer {
  if (typeof value !== 'string') fail('INVALID_CREDENTIAL')
  if (value.startsWith('b64.')) {
    return decodeBase64Url(value.slice(4), 1, MAX_CREDENTIAL_ID_BYTES, 'INVALID_CREDENTIAL')
  }
  return uuidToBytes(value, 'INVALID_CREDENTIAL')
}

function parseCounter(value: unknown): number {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    fail('INVALID_CREDENTIAL')
  }
  const counter = Number(value)
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > MAX_UINT32) {
    fail('INVALID_CREDENTIAL')
  }
  return counter
}

function nextCounter(counter: number): number {
  if (counter === 0) return 0
  if (counter === MAX_UINT32) fail('COUNTER_OVERFLOW')
  return counter + 1
}

function flags(attested: boolean, userPresent: boolean, userVerified: boolean): number {
  return (
    (userPresent ? 0x01 : 0) |
    (userVerified ? 0x04 : 0) |
    0x08 | // BE: vault credentials are backup eligible.
    0x10 | // BS: vault credentials are synchronized/backed up.
    (attested ? 0x40 : 0)
  )
}

function canonicalCoseEc2PublicKey(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: 'jwk' })
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.x === undefined || jwk.y === undefined) {
    fail('INVALID_CREDENTIAL')
  }
  const x = decodeBase64Url(jwk.x, 32, 32, 'INVALID_CREDENTIAL')
  const y = decodeBase64Url(jwk.y, 32, 32, 'INVALID_CREDENTIAL')

  // CTAP2 canonical CBOR: { 1: 2, 3: -7, -1: 1, -2: x, -3: y }.
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y
  ])
}

function authenticatorData(
  rpId: string,
  counter: number,
  userPresent: boolean,
  userVerified: boolean,
  attestedCredentialData?: Buffer
): Buffer {
  const rpIdHash = createPublicKeyHash(rpId)
  const header = Buffer.alloc(37)
  rpIdHash.copy(header, 0)
  header[32] = flags(attestedCredentialData !== undefined, userPresent, userVerified)
  header.writeUInt32BE(counter, 33)
  return attestedCredentialData === undefined
    ? header
    : Buffer.concat([header, attestedCredentialData])
}

function createPublicKeyHash(rpId: string): Buffer {
  // Kept separate to make it impossible to hash a URL or display name accidentally.
  return createHash('sha256').update(Buffer.from(rpId, 'ascii')).digest()
}

function validateBoolean(value: unknown, code: PasskeyAuthenticatorErrorCode): boolean {
  if (typeof value !== 'boolean') fail(code)
  return value
}

function validateCreationDate(value: unknown): void {
  if (typeof value !== 'string' || value.length > 64) fail('INVALID_CREDENTIAL')
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    fail('INVALID_CREDENTIAL')
  }
}

function validateStoredCredential(credential: StoredPasskeyCredential): {
  credentialId: Buffer
  userHandle: Buffer | null
  counter: number
  rpId: string
} {
  if (credential === null || typeof credential !== 'object') fail('INVALID_CREDENTIAL')
  if (
    credential.keyType !== 'public-key' ||
    credential.keyAlgorithm !== 'ECDSA' ||
    credential.keyCurve !== 'P-256'
  ) {
    fail('INVALID_CREDENTIAL')
  }
  if (typeof credential.discoverable !== 'boolean') fail('INVALID_CREDENTIAL')
  validateNullableText(credential.rpName)
  validateNullableText(credential.userName)
  validateNullableText(credential.userDisplayName)
  validateCreationDate(credential.creationDate)

  const credentialId = credentialIdToBytes(credential.credentialId)
  const userHandle =
    credential.userHandle === null
      ? null
      : decodeBase64Url(credential.userHandle, 1, MAX_USER_HANDLE_BYTES, 'INVALID_CREDENTIAL')
  return {
    credentialId,
    userHandle,
    counter: parseCounter(credential.counter),
    rpId: validateRpId(credential.rpId, 'INVALID_CREDENTIAL')
  }
}

function importP256PrivateKey(keyValue: unknown): ReturnType<typeof createPrivateKey> {
  const keyBytes = decodeBase64Url(keyValue, 1, MAX_PKCS8_BYTES, 'INVALID_CREDENTIAL')
  try {
    const privateKey = createPrivateKey({ key: keyBytes, format: 'der', type: 'pkcs8' })
    if (
      privateKey.asymmetricKeyType !== 'ec' ||
      privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
    ) {
      fail('INVALID_CREDENTIAL')
    }
    const jwk = privateKey.export({ format: 'jwk' })
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.d !== 'string') {
      fail('INVALID_CREDENTIAL')
    }
    return privateKey
  } catch (error) {
    if (error instanceof PasskeyAuthenticatorError) throw error
    fail('INVALID_CREDENTIAL')
  } finally {
    keyBytes.fill(0)
  }
}

export async function createPasskeyCredential(
  params: CreatePasskeyCredentialParams,
  dependencies: PasskeyAuthenticatorDependencies = {}
): Promise<CreatePasskeyCredentialResult> {
  if (params === null || typeof params !== 'object') fail('INVALID_INPUT')
  const rpId = validateRpId(params.rpId, 'INVALID_INPUT')
  const rpName = validateBoundedString(params.rpName, MAX_TEXT_LENGTH, false, 'INVALID_INPUT')
  const userName = validateBoundedString(params.userName, MAX_TEXT_LENGTH, false, 'INVALID_INPUT')
  const userDisplayName = validateBoundedString(
    params.userDisplayName,
    MAX_TEXT_LENGTH,
    false,
    'INVALID_INPUT'
  )
  const discoverable = validateBoolean(params.discoverable, 'INVALID_INPUT')
  const userVerified = validateBoolean(params.userVerified, 'INVALID_INPUT')
  const userPresent =
    params.userPresent === undefined ? true : validateBoolean(params.userPresent, 'INVALID_INPUT')

  const uuid = (dependencies.uuid ?? randomUUID)()
  const credentialId = uuidToBytes(uuid, 'INVALID_INPUT')
  const now = (dependencies.now ?? (() => new Date()))()
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail('INVALID_INPUT')

  const userHandle = copyBoundedBytes(params.userHandle, 1, MAX_USER_HANDLE_BYTES, 'INVALID_INPUT')
  try {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' })
    try {
      const coseKey = canonicalCoseEc2PublicKey(publicKey)
      const credentialIdLength = Buffer.alloc(2)
      credentialIdLength.writeUInt16BE(credentialId.byteLength)
      const attestedData = Buffer.concat([AAGUID_BYTES, credentialIdLength, credentialId, coseKey])
      const authData = authenticatorData(rpId, 0, userPresent, userVerified, attestedData)
      const attestationObject = attestationEncoder.encode({
        fmt: 'none',
        attStmt: {},
        authData: Uint8Array.from(authData)
      })
      const credential: StoredPasskeyCredential = {
        credentialId: uuid,
        keyType: 'public-key',
        keyAlgorithm: 'ECDSA',
        keyCurve: 'P-256',
        keyValue: pkcs8.toString('base64url'),
        rpId,
        userHandle: userHandle.toString('base64url'),
        userName,
        counter: '0',
        rpName,
        userDisplayName,
        discoverable,
        creationDate: now.toISOString()
      }

      return {
        credential,
        credentialId: Uint8Array.from(credentialId),
        attestationObject: Uint8Array.from(attestationObject),
        authenticatorData: Uint8Array.from(authData),
        publicKey: Uint8Array.from(publicKey.export({ format: 'der', type: 'spki' })),
        publicKeyAlgorithm: ES256_ALGORITHM
      }
    } finally {
      pkcs8.fill(0)
    }
  } finally {
    userHandle.fill(0)
  }
}

export async function getPasskeyAssertion(
  params: GetPasskeyAssertionParams
): Promise<GetPasskeyAssertionResult> {
  if (params === null || typeof params !== 'object') fail('INVALID_INPUT')
  const requestedRpId = validateRpId(params.rpId, 'INVALID_INPUT')
  const userVerified = validateBoolean(params.userVerified, 'INVALID_INPUT')
  const userPresent =
    params.userPresent === undefined ? true : validateBoolean(params.userPresent, 'INVALID_INPUT')
  const clientDataHash = copyBoundedBytes(params.clientDataHash, 32, 32, 'INVALID_INPUT')
  let userHandle: Buffer | null | undefined
  let signatureBase: Buffer | undefined
  try {
    const stored = validateStoredCredential(params.credential)
    userHandle = stored.userHandle
    if (stored.rpId !== requestedRpId) fail('RP_ID_MISMATCH')

    const counter = nextCounter(stored.counter)
    const authData = authenticatorData(requestedRpId, counter, userPresent, userVerified)
    const privateKey = importP256PrivateKey(params.credential.keyValue)
    signatureBase = Buffer.concat([authData, clientDataHash])
    const signature = signData('sha256', signatureBase, {
      key: privateKey,
      dsaEncoding: 'der'
    })
    return {
      credentialId: Uint8Array.from(stored.credentialId),
      userHandle: stored.userHandle === null ? null : Uint8Array.from(stored.userHandle),
      authenticatorData: Uint8Array.from(authData),
      signature: Uint8Array.from(signature),
      counter: String(counter)
    }
  } finally {
    clientDataHash.fill(0)
    signatureBase?.fill(0)
    userHandle?.fill(0)
  }
}
