import { constants, createPublicKey, publicEncrypt } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { DeviceLoginRequest, authRequestFingerprint } from './bitwarden-device-login'

const EMAIL = 'Bear@Example.invalid'

function approverEnvelope(publicKey: string, userKey: Buffer): string {
  const encrypted = publicEncrypt(
    {
      key: createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' }),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha1'
    },
    userKey
  )
  return `4.${encrypted.toString('base64')}`
}

describe('DeviceLoginRequest', () => {
  it('publishes an RSA-2048 SPKI key, a 25-character access code and the shared phrase', () => {
    const request = DeviceLoginRequest.create(EMAIL, 1_000)
    const key = createPublicKey({
      key: Buffer.from(request.publicKey, 'base64'),
      format: 'der',
      type: 'spki'
    })
    expect(key.asymmetricKeyDetails?.modulusLength).toBe(2_048)
    expect(request.accessCode).toMatch(/^[A-Za-z0-9]{25}$/u)
    expect(request.fingerprint).toBe(
      authRequestFingerprint(EMAIL.toLowerCase(), Buffer.from(request.publicKey, 'base64'))
    )
    expect(request.fingerprint.split('-')).toHaveLength(6)
    expect(request.createdAt).toBe(1_000)
  })

  it('never reuses a key pair or access code between requests', () => {
    const first = DeviceLoginRequest.create(EMAIL, 0)
    const second = DeviceLoginRequest.create(EMAIL, 0)
    expect(second.publicKey).not.toBe(first.publicKey)
    expect(second.accessCode).not.toBe(first.accessCode)
  })

  it('decrypts the approving device RSA-OAEP-SHA1 envelope into the user key', () => {
    const request = DeviceLoginRequest.create(EMAIL, 0)
    request.accept('50000000-0000-4000-8000-000000000001')
    request.approve(approverEnvelope(request.publicKey, Buffer.alloc(64, 7)))
    expect(request.approved).toBe(true)
    expect(request.userKey()).toEqual(Buffer.alloc(64, 7))
    expect(() =>
      request.approve(approverEnvelope(request.publicKey, Buffer.alloc(64, 8)))
    ).toThrow()
  })

  it('rejects an envelope sealed to another key', () => {
    const request = DeviceLoginRequest.create(EMAIL, 0)
    const other = DeviceLoginRequest.create(EMAIL, 0)
    expect(() => request.approve(approverEnvelope(other.publicKey, Buffer.alloc(64, 7)))).toThrow(
      expect.objectContaining({ code: 'INVALID_RESPONSE' })
    )
    expect(request.approved).toBe(false)
  })

  it('drops every secret on dispose', () => {
    const request = DeviceLoginRequest.create(EMAIL, 0)
    request.accept('50000000-0000-4000-8000-000000000001')
    request.approve(approverEnvelope(request.publicKey, Buffer.alloc(64, 7)))
    const copy = request.userKey()
    request.dispose()
    expect(copy).toEqual(Buffer.alloc(64, 7))
    expect(() => request.accessCode).toThrow(expect.objectContaining({ code: 'ABORTED' }))
    expect(() => request.id).toThrow(expect.objectContaining({ code: 'ABORTED' }))
    expect(() => request.userKey()).toThrow(expect.objectContaining({ code: 'ABORTED' }))
    expect(request.approved).toBe(false)
  })
})
