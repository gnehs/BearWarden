import {
  constants,
  createCipheriv,
  createHmac,
  createPrivateKey,
  generateKeyPairSync,
  publicEncrypt,
  webcrypto,
  type KeyObject
} from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { Encoder } from 'cbor-x'
import {
  BitwardenCryptoError,
  decodeBitwardenUserKey,
  decryptBitwardenAttachmentBuffer,
  decryptBitwardenBytes,
  decryptBitwardenCipherBlob,
  decryptBitwardenString,
  decryptBitwardenWrappedKey,
  decryptRsaPrivateKey,
  deriveMasterKey,
  derivePasswordKey,
  encryptBitwardenBytes,
  encryptBitwardenCipherBlob,
  encryptBitwardenString,
  stretchMasterKey,
  verifyBitwardenV2AccountState
} from './bitwarden-crypto'

const COMBINED_KEY = Buffer.from([...Array(64).keys()])
const TYPE_2_VECTOR =
  '2.ABEiM0RVZneImaq7zN3u/w==|a2Qcb3JZP7GMstiHZNPrFfRO+hzkpgdwm51iJZcuUy0=|/RO+Ei7G48C38o5fWq6Lzwfa0bjUxXifjQaVSiy9u/0='
const TYPE_1_VECTOR =
  '1.ABEiM0RVZneImaq7zN3u/w==|SlyzY8ruQp1TEkLizfIzli8PM+0v7xKMbdwfl57UfUE=|XRD3eKrm9IDGMjIxN0db6mI4vqM6FZfQbViEkYP/cIE='
const VECTOR_PLAINTEXT = 'Bitwarden fixed AES vector'

function attachmentEnvelope(type: 0 | 2, plaintext: Buffer, key: Buffer): Buffer {
  const iv = Buffer.from([...Array(16).keys()])
  const cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  if (type === 0) return Buffer.concat([Buffer.from([type]), iv, ciphertext])
  const mac = createHmac('sha256', key.subarray(32)).update(iv).update(ciphertext).digest()
  return Buffer.concat([Buffer.from([type]), iv, mac, ciphertext])
}
const V2_USER_KEY_B64 =
  'pQEEAlACHUUoybNAuJoZzqNMxz2bAzoAARFvBIQDBAUGIFggAvGl4ifaUAomQdCdUPpXLHtypiQxHjZwRHeI83caZM4B'
const TYPE_7_VECTOR =
  '7.g1gcowE6AAERbwMYKgRQAAECAwQFBgcICQoLDA0OD6EFWBhOFBydtPaD3FJoSElLK0WL2KeR3EOokK1YI3/qwlO9rEEdnEliV+dXgQ/rf31h0zPU0wINJHs1DB+/KA2v'
const V2_WRAPPED_SIGNING_KEY =
  '7.g1gcowE6AAERbwMYZQRQAh1FKMmzQLiaGc6jTMc9m6EFWBhYePc2qkCruHAPXgbzXsIP1WVk11ArbLNYUBpifToURlwHKs1je2BwZ1C/5thz4nyNbL0wDaYkRWI9ex1wvB7KhdzC7ltStEd5QttboTSCaXQROSZaGBPNO5+Bu3sTY8F5qK1pBUo6AHNN'
const V2_SECURITY_STATE =
  'hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8CoFgkomhlbnRpdHlJZFBHOOw2BI9OQoNq+Vl1xZZKZ3ZlcnNpb24CWEAlchbJR0vmRfShG8On7Q2gknjkw4Dd6MYBLiH4u+/CmfQdmjNZdf6kozgW/6NXyKVNu8dAsKsin+xxXkDyVZoG'
const V2_SIGNED_PUBLIC_KEY =
  'hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8BoFkBTqNpYWxnb3JpdGhtAG1jb250ZW50Rm9ybWF0AGlwdWJsaWNLZXlZASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP/7WM8nUepxoJ0qtM+azxcly+eZ31qUjjZTZcX/gYw1MzkoXWAjqyeFH/bdktq1lEUwegrxkIxKkY2SMtp0CvPnaV1x5O8E6FBSJbKWRlDg181rfEhgm5tc6aR4PJ827IvFVm9xk6Sj091P5DHZDEOsWLZc2jYjtpUV3X38I4gSR7HiYnR4DcwcWkoJ3FhtxMCwYgPz6RVH0vzhLUmm1mgbzH6IH8Pf9DjLTZSxBikVO7S9s9jzhiZbTeeAl3FbNLxfj9Qkj+NoSfms7jGVTlBwvSXgjJs/ktGkT1cR5QcBMpU4bt41+l73MN8pXapCih9Awf1W+RY7imxpYOMFJ3AgMBAAFYQMq/hT4wod2w8xyoM7D86ctuLNX4ZRo+jRHf2sZfaO7QsvonG/ZYuNKF5fq8wpxMRjfoMvnY2TTShbgzLrW8BA4='
const V2_PUBLIC_KEY =
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz/+1jPJ1HqcaCdKrTPms8XJcvnmd9alI42U2XF/4GMNTM5KF1gI6snhR/23ZLatZRFMHoK8ZCMSpGNkjLadArz52ldceTvBOhQUiWylkZQ4NfNa3xIYJubXOmkeDyfNuyLxVZvcZOko9PdT+Qx2QxDrFi2XNo2I7aVFd19/COIEkex4mJ0eA3MHFpKCdxYbcTAsGID8+kVR9L84S1JptZoG8x+iB/D3/Q4y02UsQYpFTu0vbPY84YmW03ngJdxWzS8X4/UJI/jaEn5rO4xlU5QcL0l4IybP5LRpE9XEeUHATKVOG7eNfpe9zDfKV2qQoofQMH9VvkWO4psaWDjBSdwIDAQAB'
const LEGACY_BLOB_ITEM_KEY =
  'e0MSZ4/Z4AS7fzjxMos7MXibNALU4mDJQwmge+uVwahg9P25cuaNiSpLvYMk2BgJfntbQs4FszcnY5nPe2FpVA=='
const LEGACY_CBOR_SEALED_CIPHER_BLOB =
  'o25mb3JtYXRfdmVyc2lvbgFrd3JhcHBlZF9jZWt4tDIub1dJMUloMDVleWxpeGxCQUM4V253QT09fDdOTVFiU3JXS3ZOWFNoTkNHdmZZWld0T2doMEcvZ294YXdod01UWm5PR1hLeVZ6RXA1WWRXRUhoRnQ0UFVrbVVOT204Z2JMRlhyTFN4MW5CU25PdjlEeEJLNFp6ejNJVFp3dm92Z3NBTFQwPXxBMzhlZkFhSlhmMnk2aFdxTHBUanJ6NlF5OS9FRERMWnpJOWZFSGhtVExJPWhlbnZlbG9wZXkBKGcxaExwUUU2QUFFUmJ3TjRJMkZ3Y0d4cFkyRjBhVzl1TDNndVltbDBkMkZ5WkdWdUxtTmliM0l0Y0dGa1pHVmtCRkFQV0dnR1lPblBYVGlNY2NUOVVrVUFPZ0FCT0lFQ09nQUJPSUFCb1FWWUdDeWk1cEtQSHQ2NXAwU0MxR1FGMTZ1TE85SEtUODFmZWxoeFF2UDBrTlYyQXpibks5RXlSUjlSRUUvUURYK0JVcE53bkxjUTZKZldJb2cycHp4TjBBNUlKTmhmZ1Uzd0NMSS9WOVZHcThkM1RZanBLSm9MNitKSVhVQnI0UWtHeGgzekZmci8rQThGN3RwR2dSK0tnLzVQRGJLMk9ENjdkM0ZnOW12b2t2UVBzQ0F5MnlIaVJ6aHdONUU9'
const OFFICIAL_BLOB_WRAPPING_KEY =
  'z27dMz/RK4wboY/Ako0YVFr9jaiSjgQQyGkTZ4LIuNrOXyeDAjeD41qbhVKl0OSjP3QuN9xmAJQE8+V5/Tl7ig=='
const OFFICIAL_SEALED_CIPHER_BLOB =
  '{"format_version":1,"wrapped_cek":"2.LQJf2BbznXX+NelBY4pSJg==|txMmjZEOhSMA7Jrm+rZt1LDfA6s3G2QU5Z8MqO4nG9s2ZXuzSLU/iYOUXD8xw+eHVSu7IUHu1LsCm4SLf+ZhkX5QIo4hJT3DHSbgu6VPUC0=|yuU/EWQWyihf2Yh9lQ1NP+zTROEpnXoRS//GfxDgC4k=","envelope":"g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFBoHnjLne8MPV72YPXuskd6OgABOIECOgABOIABoQVYGA00vxb7gF7Y3SUyoCMy34C1HrB3fSY3jVhxZXQmmotGEIwwRlG+SpTcyTl5m4lUnozWrjAYfWitl1+cz457Wq3iDW/MvrHE7c1g38QJxY6t1yhQL0dQy9DyDXQDiWGPtYzic2Ay+GtrlIERN37wOdhQ1HZDeoobHL+aKomvPTems/Ta2SqWC9HfE38="}'

describe('Bitwarden KDF compatibility', () => {
  it('matches Bitwarden SDK PBKDF2 and Argon2id published test vectors', async () => {
    // https://sdk-api-docs.bitwarden.com/src/bitwarden_crypto/keys/kdf.rs.html#218-264
    await expect(
      deriveMasterKey('67t9b5g67$%Dh89n', 'test_key', { type: 'pbkdf2', iterations: 10_000 })
    ).resolves.toEqual(
      Buffer.from('1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b', 'hex')
    )
    await expect(
      deriveMasterKey('67t9b5g67$%Dh89n', 'test_key', {
        type: 'argon2id',
        iterations: 4,
        memoryMiB: 32,
        parallelism: 2
      })
    ).resolves.toEqual(
      Buffer.from('cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2', 'hex')
    )
  })

  it('uses the caller-provided salt bytes and the Bitwarden password-key ordering', async () => {
    const masterKey = Buffer.from([...Array(32).keys()])
    const explicitSaltKey = await deriveMasterKey('password', '  Exact-Salt  ', {
      type: 'pbkdf2',
      iterations: 5_000
    })
    const normalizedSaltKey = await deriveMasterKey('password', 'exact-salt', {
      type: 'pbkdf2',
      iterations: 5_000
    })
    expect(explicitSaltKey).not.toEqual(normalizedSaltKey)
    explicitSaltKey.fill(0)
    normalizedSaltKey.fill(0)
    await expect(derivePasswordKey(masterKey, 'password')).resolves.toEqual(
      Buffer.from('0cde72cf5075b941510cf98c16c151b84f2a9c595cfa946af7098ee85cc1630f', 'hex')
    )
  })

  it('uses HKDF expand-only to stretch a master key', () => {
    const stretched = stretchMasterKey(Buffer.from([...Array(32).keys()]))
    expect(stretched.encKey.toString('hex')).toBe(
      '9c5639fac602366b486253191cb7900d7d8e3a1514676b118d5803a11dd97213'
    )
    expect(stretched.macKey.toString('hex')).toBe(
      'cce388b4ac0f05edee78d40dcbe78a7715640de75ed9ba06942fb42398d6b1f1'
    )
    expect(stretched.combinedKey).toEqual(Buffer.concat([stretched.encKey, stretched.macKey]))
  })

  it('rejects weak or malformed KDF parameters before performing expensive work', async () => {
    await expect(
      deriveMasterKey('password', 'salt', { type: 'pbkdf2', iterations: 4_999 })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' satisfies BitwardenCryptoError['code'] })
    await expect(
      deriveMasterKey('password', 'salt', {
        type: 'argon2id',
        iterations: 1,
        memoryMiB: 16,
        parallelism: 1
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' satisfies BitwardenCryptoError['code'] })
  })
})

describe('Bitwarden EncString compatibility', () => {
  it('decrypts independent fixed AES type 2 and legacy type 1 vectors', () => {
    expect(decryptBitwardenString(TYPE_2_VECTOR, COMBINED_KEY)).toBe(VECTOR_PLAINTEXT)
    expect(decryptBitwardenString(TYPE_1_VECTOR, COMBINED_KEY.subarray(0, 32))).toBe(
      VECTOR_PLAINTEXT
    )
  })

  it('authenticates type 2 before decrypting and rejects malformed fields', () => {
    const tamperedMac = TYPE_2_VECTOR.replace('/RO+', 'ARO+')
    const macError = (() => {
      try {
        decryptBitwardenBytes(tamperedMac, COMBINED_KEY)
      } catch (error) {
        return error
      }
      throw new Error('expected MAC validation to fail')
    })()
    expect(macError).toMatchObject({
      code: 'AUTHENTICATION_FAILED' satisfies BitwardenCryptoError['code']
    })
    const parsingError = (() => {
      try {
        decryptBitwardenBytes('2.bad|base64|fields', COMBINED_KEY)
      } catch (error) {
        return error
      }
      throw new Error('expected malformed cipher string to fail')
    })()
    expect(parsingError).toMatchObject({
      code: 'INVALID_CIPHERSTRING' satisfies BitwardenCryptoError['code']
    })
  })

  it('round-trips UTF-8 and raw binary plaintext as authenticated type 2 data', () => {
    const binary = Buffer.from([0, 255, 16, 127])
    const encryptedBinary = encryptBitwardenBytes(binary, COMBINED_KEY)
    expect(encryptedBinary).toMatch(/^2\./)
    expect(decryptBitwardenBytes(encryptedBinary, COMBINED_KEY)).toEqual(binary)

    const encryptedString = encryptBitwardenString('臺灣 UTF-8', COMBINED_KEY)
    expect(decryptBitwardenString(encryptedString, COMBINED_KEY)).toBe('臺灣 UTF-8')
  })

  it('parses an official V2 COSE user key and decrypts the official type 7 vector', () => {
    const encodedUserKey = Buffer.from(V2_USER_KEY_B64, 'base64')
    const userKey = decodeBitwardenUserKey(encodedUserKey)
    expect(Buffer.isBuffer(userKey)).toBe(false)

    const vectorKey = {
      algorithm: 'xchacha20-poly1305' as const,
      keyId: Buffer.from([...Array(16).keys()]),
      encryptionKey: Buffer.from([...Array(32).keys()])
    }
    expect(decryptBitwardenBytes(TYPE_7_VECTOR, vectorKey).toString()).toBe('Message test vector')
  })

  it('round-trips V2 UTF-8 and wrapped AES keys with strict content types', () => {
    const key = {
      algorithm: 'xchacha20-poly1305' as const,
      keyId: Buffer.from([...Array(16).keys()]),
      encryptionKey: Buffer.from([...Array(32).keys()].map((value) => value + 1))
    }
    const encryptedString = encryptBitwardenString('臺灣 V2 UTF-8', key)
    expect(encryptedString).toMatch(/^7\./)
    expect(decryptBitwardenString(encryptedString, key)).toBe('臺灣 V2 UTF-8')

    const itemKey = Buffer.from([...Array(64).keys()])
    const wrappedKey = encryptBitwardenBytes(itemKey, key, 'legacy-key')
    expect(decryptBitwardenWrappedKey(wrappedKey, key)).toEqual(itemKey)
    expect(() => decryptBitwardenWrappedKey(encryptedString, key)).toThrowError(
      BitwardenCryptoError
    )
  })

  it('rejects type 7 tampering and key-id mismatches before returning plaintext', () => {
    const key = {
      algorithm: 'xchacha20-poly1305' as const,
      keyId: Buffer.from([...Array(16).keys()]),
      encryptionKey: Buffer.from([...Array(32).keys()])
    }
    const wrongKeyId = { ...key, keyId: Buffer.alloc(16, 9) }
    expect(() => decryptBitwardenBytes(TYPE_7_VECTOR, wrongKeyId)).toThrowError(
      BitwardenCryptoError
    )
    const serialized = Buffer.from(TYPE_7_VECTOR.slice(2), 'base64')
    serialized[serialized.length - 1] ^= 1
    expect(() => decryptBitwardenBytes(`7.${serialized.toString('base64')}`, key)).toThrowError(
      BitwardenCryptoError
    )
  })

  it('rejects duplicate CBOR labels and trailing data in V2 keys', () => {
    const padded = Buffer.from(V2_USER_KEY_B64, 'base64')
    const raw = Buffer.from(padded.subarray(0, -1))
    raw[0] = 0xa6
    const duplicate = Buffer.concat([raw, Buffer.of(1, 4, 1)])
    expect(() => decodeBitwardenUserKey(duplicate)).toThrowError(BitwardenCryptoError)

    const trailing = Buffer.concat([padded.subarray(0, -1), Buffer.of(0, 1)])
    expect(() => decodeBitwardenUserKey(trailing)).toThrowError(BitwardenCryptoError)
  })
})

describe('Bitwarden attachment EncArrayBuffer compatibility', () => {
  it('decrypts authenticated type 2 and historical type 0 attachment envelopes', () => {
    const plaintext = Buffer.from([0, 1, 2, 127, 128, 255])
    const type2 = attachmentEnvelope(2, plaintext, COMBINED_KEY)
    const legacyKey = Buffer.from(COMBINED_KEY.subarray(0, 32))
    const type0 = attachmentEnvelope(0, plaintext, legacyKey)

    expect(decryptBitwardenAttachmentBuffer(type2, COMBINED_KEY)).toEqual(plaintext)
    expect(decryptBitwardenAttachmentBuffer(type0, legacyKey)).toEqual(plaintext)
    expect(decryptBitwardenAttachmentBuffer(type0, COMBINED_KEY)).toEqual(plaintext)
  })

  it('authenticates type 2 before decryption and rejects malformed envelopes', () => {
    const envelope = attachmentEnvelope(2, Buffer.from('authenticated attachment'), COMBINED_KEY)
    const tampered = Buffer.from(envelope)
    tampered[17] ^= 1

    expect(() => decryptBitwardenAttachmentBuffer(tampered, COMBINED_KEY)).toThrowError(
      BitwardenCryptoError
    )
    try {
      decryptBitwardenAttachmentBuffer(tampered, COMBINED_KEY)
    } catch (error) {
      expect(error).toMatchObject({ code: 'AUTHENTICATION_FAILED' })
    }

    expect(() =>
      decryptBitwardenAttachmentBuffer(Buffer.from([1, ...Buffer.alloc(64)]), COMBINED_KEY)
    ).toThrowError(BitwardenCryptoError)
    expect(() => decryptBitwardenAttachmentBuffer(Buffer.alloc(32), COMBINED_KEY)).toThrowError(
      BitwardenCryptoError
    )
    expect(() =>
      decryptBitwardenAttachmentBuffer(Buffer.concat([envelope, Buffer.from([0])]), COMBINED_KEY)
    ).toThrowError(BitwardenCryptoError)
    expect(() => decryptBitwardenAttachmentBuffer(envelope, Buffer.alloc(32))).toThrowError(
      BitwardenCryptoError
    )
  })
})

describe('Bitwarden Cipher.data blob compatibility', () => {
  it('opens the official SDK sealed-blob vector including its legacy XChaCha envelope', () => {
    const itemKey = Buffer.from(OFFICIAL_BLOB_WRAPPING_KEY, 'base64')
    expect(decryptBitwardenCipherBlob(OFFICIAL_SEALED_CIPHER_BLOB, itemKey)).toEqual({
      name: 'Test Cipher',
      notes: 'Some notes',
      typeData: { type: 'secureNote', secureNoteType: 0 }
    })
    itemKey.fill(0)
  })

  it("retains read compatibility with BearWarden's former base64-CBOR outer container", () => {
    const itemKey = Buffer.from(LEGACY_BLOB_ITEM_KEY, 'base64')
    expect(decryptBitwardenCipherBlob(LEGACY_CBOR_SEALED_CIPHER_BLOB, itemKey)).toEqual({
      name: 'Test Cipher',
      notes: 'Some notes',
      typeData: { type: 'secureNote', secureNoteType: 0 }
    })
    itemKey.fill(0)
  })

  it('round-trips a login using the current AES-256-GCM data envelope and rejects tampering', () => {
    const itemKey = Buffer.from([...Array(64).keys()])
    const content = {
      name: 'Blob login',
      notes: null,
      typeData: {
        type: 'login',
        username: 'blob-user@example.invalid',
        password: 'fake-secret',
        passwordRevisionDate: null,
        uris: [{ uri: 'https://blob.example.invalid', match: null }],
        totp: null,
        autofillOnPageLoad: null,
        fido2Credentials: []
      },
      fields: [],
      passwordHistory: []
    }
    const sealed = encryptBitwardenCipherBlob(content, itemKey)
    expect(JSON.parse(sealed)).toEqual({
      format_version: 1,
      wrapped_cek: expect.stringMatching(/^2\./),
      envelope: expect.any(String)
    })
    expect(decryptBitwardenCipherBlob(sealed, itemKey)).toEqual(content)

    const tamperedContainer = JSON.parse(sealed) as {
      format_version: number
      wrapped_cek: string
      envelope: string
    }
    const tampered = Buffer.from(tamperedContainer.envelope, 'base64')
    tampered[tampered.length - 1] ^= 1
    tamperedContainer.envelope = tampered.toString('base64')
    expect(() =>
      decryptBitwardenCipherBlob(JSON.stringify(tamperedContainer), itemKey)
    ).toThrowError(BitwardenCryptoError)
    itemKey.fill(0)
    tampered.fill(0)
  })
})

describe('Bitwarden Account Encryption V2 state', () => {
  it('verifies the official Ed25519 signed public key and legacy security-state vector', async () => {
    const userKey = decodeBitwardenUserKey(Buffer.from(V2_USER_KEY_B64, 'base64'))
    await expect(
      verifyBitwardenV2AccountState(
        {
          wrappedSigningKey: V2_WRAPPED_SIGNING_KEY,
          securityState: V2_SECURITY_STATE,
          signedPublicKey: V2_SIGNED_PUBLIC_KEY,
          publicKey: V2_PUBLIC_KEY
        },
        userKey
      )
    ).resolves.toBe(2)

    const tampered = Buffer.from(V2_SECURITY_STATE, 'base64')
    tampered[tampered.length - 1] ^= 1
    await expect(
      verifyBitwardenV2AccountState(
        {
          wrappedSigningKey: V2_WRAPPED_SIGNING_KEY,
          securityState: tampered.toString('base64')
        },
        userKey
      )
    ).rejects.toMatchObject({
      code: 'AUTHENTICATION_FAILED' satisfies BitwardenCryptoError['code']
    })
  })

  it('verifies an ML-DSA-44 COSE account state through Node WebCrypto', async () => {
    const encoder = new Encoder({ mapsAsObjects: false, tagUint8Array: false, useRecords: false })
    const userKey = {
      algorithm: 'xchacha20-poly1305' as const,
      keyId: Buffer.from([...Array(16).keys()]),
      encryptionKey: Buffer.from([...Array(32).keys()].map((value) => value + 1))
    }
    const signingKeys = (await webcrypto.subtle.generateKey('ML-DSA-44', true, [
      'sign',
      'verify'
    ])) as CryptoKeyPair
    const publicKey = Buffer.from(
      await webcrypto.subtle.exportKey('raw-public', signingKeys.publicKey)
    )
    const seed = Buffer.from(await webcrypto.subtle.exportKey('raw-seed', signingKeys.privateKey))
    const signingKeyId = Buffer.alloc(16, 7)
    const signingCoseKey = encoder.encode(
      new Map<unknown, unknown>([
        [1, 7],
        [2, signingKeyId],
        [3, -48],
        [4, [1]],
        [-1, publicKey],
        [-2, seed]
      ])
    )
    const wrappedSigningKey = encryptBitwardenBytes(
      Buffer.from(signingCoseKey),
      userKey,
      'cose-key'
    )
    const protectedHeader = encoder.encode(
      new Map<unknown, unknown>([
        [1, -48],
        [3, 60],
        [4, signingKeyId],
        [-80_000, 2]
      ])
    )
    const payload = encoder.encode(new Map([['version', 2]]))
    const signatureStructure = encoder.encode([
      'Signature1',
      protectedHeader,
      Buffer.alloc(0),
      payload
    ])
    const signature = Buffer.from(
      await webcrypto.subtle.sign('ML-DSA-44', signingKeys.privateKey, signatureStructure)
    )
    const securityState = encoder
      .encode([protectedHeader, new Map(), payload, signature])
      .toString('base64')

    await expect(
      verifyBitwardenV2AccountState({ wrappedSigningKey, securityState }, userKey)
    ).resolves.toBe(2)
  })
})

describe('Bitwarden RSA EncString compatibility', () => {
  function makeRsaKeys(): { privateKey: KeyObject; publicKey: KeyObject } {
    return generateKeyPairSync('rsa', { modulusLength: 2048 })
  }

  it('decrypts type 3 SHA-256 and type 4 SHA-1 OAEP payloads', () => {
    const { privateKey, publicKey } = makeRsaKeys()
    for (const [type, oaepHash] of [
      [3, 'sha256'],
      [4, 'sha1']
    ] as const) {
      const ciphertext = publicEncrypt(
        { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
        Buffer.from('RSA fixed behavior')
      )
      expect(
        decryptBitwardenString(`${type}.${ciphertext.toString('base64')}`, COMBINED_KEY, privateKey)
      ).toBe('RSA fixed behavior')
    }
  })

  it('accepts PEM, DER, and base64 DER PKCS#8 private-key payloads', () => {
    const { privateKey, publicKey } = makeRsaKeys()
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    const der = privateKey.export({ format: 'der', type: 'pkcs8' })
    const variants = [
      encryptBitwardenString(pem, COMBINED_KEY),
      encryptBitwardenBytes(der, COMBINED_KEY),
      encryptBitwardenString(der.toString('base64'), COMBINED_KEY)
    ]
    const ciphertext = publicEncrypt(
      { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from('private key format')
    )
    for (const encryptedPrivateKey of variants) {
      const decryptedPrivateKey = decryptRsaPrivateKey(encryptedPrivateKey, COMBINED_KEY)
      expect(
        decryptBitwardenString(
          `3.${ciphertext.toString('base64')}`,
          COMBINED_KEY,
          decryptedPrivateKey
        )
      ).toBe('private key format')
    }
    expect(createPrivateKey(pem).type).toBe('private')
  })
})
