import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  verify
} from 'node:crypto'
import { decode } from 'cbor-x'
import { describe, expect, it } from 'vitest'
import type { StoredPasskeyCredential } from './passkey'
import {
  BITWARDEN_AAGUID,
  createPasskeyCredential,
  getPasskeyAssertion,
  PasskeyAuthenticatorError,
  type CreatePasskeyCredentialParams,
  type PasskeyAuthenticatorErrorCode
} from './passkey-authenticator'

const UUID = '52217b91-73f1-4fea-b3f2-54a7959fd5aa'
const UUID_BYTES = Buffer.from('52217b9173f14feab3f254a7959fd5aa', 'hex')
const NOW = new Date('2026-01-02T03:04:05.000Z')

function createParams(
  overrides: Partial<CreatePasskeyCredentialParams> = {}
): CreatePasskeyCredentialParams {
  return {
    rpId: 'login.example.com',
    rpName: 'Example',
    userHandle: Uint8Array.from({ length: 32 }, (_, index) => index),
    userName: 'example-user',
    userDisplayName: 'Example User',
    discoverable: true,
    userVerified: true,
    ...overrides
  }
}

async function createCredential(
  overrides: Partial<CreatePasskeyCredentialParams> = {}
): ReturnType<typeof createPasskeyCredential> {
  return createPasskeyCredential(createParams(overrides), {
    uuid: () => UUID,
    now: () => NOW
  })
}

async function expectPasskeyError(
  action: () => Promise<unknown>,
  code: PasskeyAuthenticatorErrorCode
): Promise<void> {
  try {
    await action()
    throw new Error(`Expected ${code}`)
  } catch (error) {
    expect(error).toBeInstanceOf(PasskeyAuthenticatorError)
    expect((error as PasskeyAuthenticatorError).code).toBe(code)
    expect((error as Error).message).toBe(code)
  }
}

describe('passkey software authenticator', () => {
  it('creates a Bitwarden-compatible ES256 credential and none attestation', async () => {
    const userHandle = Uint8Array.from({ length: 32 }, (_, index) => index)
    const originalUserHandle = userHandle.slice()
    const result = await createCredential({ userHandle })

    expect(userHandle).toEqual(originalUserHandle)
    expect(result.credential).toMatchObject({
      credentialId: UUID,
      keyType: 'public-key',
      keyAlgorithm: 'ECDSA',
      keyCurve: 'P-256',
      rpId: 'login.example.com',
      userHandle: Buffer.from(userHandle).toString('base64url'),
      counter: '0',
      discoverable: true,
      creationDate: NOW.toISOString()
    })
    expect(result.credentialId).toEqual(Uint8Array.from(UUID_BYTES))
    expect(result.publicKeyAlgorithm).toBe(-7)

    const privateKey = createPrivateKey({
      key: Buffer.from(result.credential.keyValue, 'base64url'),
      format: 'der',
      type: 'pkcs8'
    })
    expect(privateKey.asymmetricKeyType).toBe('ec')
    expect(privateKey.asymmetricKeyDetails?.namedCurve).toBe('prime256v1')

    // A direct CBOR map (0xa3), not a cbor-x record extension.
    expect(result.attestationObject[0]).toBe(0xa3)
    const attestation = decode(Buffer.from(result.attestationObject)) as {
      fmt: string
      attStmt: Record<string, never>
      authData: Uint8Array
    }
    expect(Object.getPrototypeOf(attestation)).toBe(Object.prototype)
    expect(attestation.fmt).toBe('none')
    expect(attestation.attStmt).toEqual({})
    expect(Buffer.from(attestation.authData)).toEqual(Buffer.from(result.authenticatorData))
    // authData is encoded as a plain CBOR byte string (0x58 0x94), without tag 64.
    expect(
      Buffer.from(result.attestationObject).includes(
        Buffer.concat([Buffer.from([0x58, 0x94]), Buffer.from(result.authenticatorData)])
      )
    ).toBe(true)

    const authData = Buffer.from(result.authenticatorData)
    expect(authData).toHaveLength(148)
    expect(authData.subarray(0, 32)).toEqual(
      createHash('sha256').update('login.example.com', 'ascii').digest()
    )
    expect(authData[32]).toBe(0x5d) // UP | UV | BE | BS | AT
    expect(authData.readUInt32BE(33)).toBe(0)
    expect(authData.subarray(37, 53).toString('hex')).toBe(BITWARDEN_AAGUID.replaceAll('-', ''))
    expect(authData.readUInt16BE(53)).toBe(16)
    expect(authData.subarray(55, 71)).toEqual(UUID_BYTES)

    const coseKey = authData.subarray(71)
    expect(coseKey).toHaveLength(77)
    expect(coseKey.subarray(0, 10)).toEqual(
      Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
    )
    expect(coseKey.subarray(42, 45)).toEqual(Buffer.from([0x22, 0x58, 0x20]))
    const publicKey = createPublicKey({
      key: Buffer.from(result.publicKey),
      format: 'der',
      type: 'spki'
    })
    const publicJwk = publicKey.export({ format: 'jwk' })
    expect(coseKey.subarray(10, 42)).toEqual(Buffer.from(publicJwk.x!, 'base64url'))
    expect(coseKey.subarray(45)).toEqual(Buffer.from(publicJwk.y!, 'base64url'))
  })

  it('round-trips the official stored format and returns a verifiable DER assertion', async () => {
    const created = await createCredential()
    const credential = JSON.parse(JSON.stringify(created.credential)) as StoredPasskeyCredential
    credential.counter = '7'
    const clientDataHash = Uint8Array.from({ length: 32 }, (_, index) => 255 - index)
    const originalHash = clientDataHash.slice()

    const assertion = await getPasskeyAssertion({
      credential,
      rpId: credential.rpId,
      clientDataHash,
      userVerified: true
    })

    expect(clientDataHash).toEqual(originalHash)
    expect(credential.counter).toBe('7')
    expect(assertion.counter).toBe('8')
    expect(assertion.credentialId).toEqual(created.credentialId)
    expect(assertion.userHandle).toEqual(
      Uint8Array.from(Buffer.from(credential.userHandle!, 'base64url'))
    )
    expect(assertion.authenticatorData).toHaveLength(37)
    expect(assertion.authenticatorData[32]).toBe(0x1d) // UP | UV | BE | BS
    expect(Buffer.from(assertion.authenticatorData).readUInt32BE(33)).toBe(8)
    expect(assertion.signature[0]).toBe(0x30)

    const signatureBase = Buffer.concat([
      Buffer.from(assertion.authenticatorData),
      Buffer.from(clientDataHash)
    ])
    expect(
      verify(
        'sha256',
        signatureBase,
        createPublicKey({ key: Buffer.from(created.publicKey), format: 'der', type: 'spki' }),
        Buffer.from(assertion.signature)
      )
    ).toBe(true)
  })

  it('keeps a disabled counter at zero and supports official b64 credential IDs', async () => {
    const created = await createCredential()
    const rawCredentialId = Buffer.alloc(32, 0xa5)
    const credential: StoredPasskeyCredential = {
      ...created.credential,
      credentialId: `b64.${rawCredentialId.toString('base64url')}`,
      userHandle: null,
      counter: '0'
    }
    const assertion = await getPasskeyAssertion({
      credential,
      rpId: credential.rpId,
      clientDataHash: Buffer.alloc(32, 0x11),
      userVerified: false
    })

    expect(assertion.counter).toBe('0')
    expect(Buffer.from(assertion.authenticatorData).readUInt32BE(33)).toBe(0)
    expect(assertion.authenticatorData[32]).toBe(0x19) // UP | BE | BS
    expect(assertion.credentialId).toEqual(Uint8Array.from(rawCredentialId))
    expect(assertion.userHandle).toBeNull()
  })

  it('requires an exact canonical RP ID and rejects URL, port, IP, and single-label forms', async () => {
    const created = await createCredential()
    await expectPasskeyError(
      () =>
        getPasskeyAssertion({
          credential: created.credential,
          rpId: 'other.example.com',
          clientDataHash: Buffer.alloc(32),
          userVerified: false
        }),
      'RP_ID_MISMATCH'
    )

    for (const rpId of [
      'https://login.example.com',
      'Login.example.com',
      'login.example.com:443',
      '127.0.0.1',
      'intranet',
      '-bad.example'
    ]) {
      await expectPasskeyError(() => createCredential({ rpId }), 'INVALID_INPUT')
    }

    const localhost = await createCredential({ rpId: 'localhost' })
    expect(localhost.credential.rpId).toBe('localhost')
  })

  it('fails closed on wrong key metadata and malformed or non-P-256 PKCS8', async () => {
    const created = await createCredential()
    const clientDataHash = Buffer.alloc(32)
    for (const credential of [
      { ...created.credential, keyType: 'private-key' },
      { ...created.credential, keyAlgorithm: 'RSA' },
      { ...created.credential, keyCurve: 'P-384' },
      { ...created.credential, keyValue: 'not_a_pkcs8_key' }
    ]) {
      await expectPasskeyError(
        () =>
          getPasskeyAssertion({
            credential,
            rpId: created.credential.rpId,
            clientDataHash,
            userVerified: false
          }),
        'INVALID_CREDENTIAL'
      )
    }

    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey.export({
      format: 'der',
      type: 'pkcs8'
    })
    await expectPasskeyError(
      () =>
        getPasskeyAssertion({
          credential: { ...created.credential, keyValue: p384.toString('base64url') },
          rpId: created.credential.rpId,
          clientDataHash,
          userVerified: false
        }),
      'INVALID_CREDENTIAL'
    )
  })

  it('strictly validates credential IDs and user handles within WebAuthn bounds', async () => {
    const created = await createCredential()
    const invalidCredentials: StoredPasskeyCredential[] = [
      { ...created.credential, credentialId: UUID.toUpperCase() },
      { ...created.credential, credentialId: 'b64.AA==' },
      {
        ...created.credential,
        credentialId: `b64.${Buffer.alloc(1024).toString('base64url')}`
      },
      { ...created.credential, userHandle: '' },
      { ...created.credential, userHandle: 'AA==' },
      { ...created.credential, userHandle: Buffer.alloc(65).toString('base64url') }
    ]

    for (const credential of invalidCredentials) {
      await expectPasskeyError(
        () =>
          getPasskeyAssertion({
            credential,
            rpId: created.credential.rpId,
            clientDataHash: Buffer.alloc(32),
            userVerified: false
          }),
        'INVALID_CREDENTIAL'
      )
    }
    await expectPasskeyError(
      () => createCredential({ userHandle: Buffer.alloc(65) }),
      'INVALID_INPUT'
    )
  })

  it('rejects malformed counters and prevents uint32 overflow', async () => {
    const created = await createCredential()
    for (const counter of ['-1', '01', '1.5', '4294967296', 'not-a-counter']) {
      await expectPasskeyError(
        () =>
          getPasskeyAssertion({
            credential: { ...created.credential, counter },
            rpId: created.credential.rpId,
            clientDataHash: Buffer.alloc(32),
            userVerified: false
          }),
        'INVALID_CREDENTIAL'
      )
    }
    await expectPasskeyError(
      () =>
        getPasskeyAssertion({
          credential: { ...created.credential, counter: '4294967295' },
          rpId: created.credential.rpId,
          clientDataHash: Buffer.alloc(32),
          userVerified: false
        }),
      'COUNTER_OVERFLOW'
    )
  })

  it('rejects wrong client hash lengths without mutating caller buffers', async () => {
    const created = await createCredential()
    const shortHash = Buffer.alloc(31, 0xcc)
    const original = Buffer.from(shortHash)
    await expectPasskeyError(
      () =>
        getPasskeyAssertion({
          credential: created.credential,
          rpId: created.credential.rpId,
          clientDataHash: shortHash,
          userVerified: false
        }),
      'INVALID_INPUT'
    )
    expect(shortHash).toEqual(original)
  })
})
