import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { PinUnlockCapability } from './pin-unlock'

interface CapsuleInternals {
  kdfSalt: Buffer
  iv: Buffer
  authTag: Buffer
  ciphertext: Buffer
}

function material(): { key: Buffer; salt: Buffer } {
  return { key: randomBytes(32), salt: randomBytes(16) }
}

function clearMaterial(value: { key: Buffer; salt: Buffer }): void {
  value.key.fill(0)
  value.salt.fill(0)
}

describe('PinUnlockCapability', () => {
  it('returns copied vault key material and retains no plaintext PIN or key API', async () => {
    const source = material()
    const keyBefore = Buffer.from(source.key)
    const saltBefore = Buffer.from(source.salt)
    const capability = await PinUnlockCapability.create('bear-2026', source.key, source.salt)

    const unlocked = await capability.unlock('bear-2026')

    expect(unlocked.key).toEqual(keyBefore)
    expect(unlocked.salt).toEqual(saltBefore)
    expect(unlocked.key).not.toBe(source.key)
    expect(unlocked.salt).not.toBe(source.salt)
    expect(source.key).toEqual(keyBefore)
    expect(source.salt).toEqual(saltBefore)
    expect(capability.status()).toEqual({ available: true, remainingAttempts: 5 })

    clearMaterial(unlocked)
    clearMaterial(source)
    keyBefore.fill(0)
    saltBefore.fill(0)
    capability.dispose()
  })

  it('disposes the capability on the fifth serialized failed attempt', async () => {
    const source = material()
    const capability = await PinUnlockCapability.create('correct-pin', source.key, source.salt)

    for (let attempt = 1; attempt <= 4; attempt += 1) {
      await expect(capability.unlock(`wrong-${attempt}`)).rejects.toMatchObject({
        code: 'INVALID_PIN'
      })
      expect(capability.status()).toEqual({
        available: true,
        remainingAttempts: 5 - attempt
      })
    }
    await expect(capability.unlock('wrong-5')).rejects.toMatchObject({ code: 'PIN_DISABLED' })
    expect(capability.status()).toEqual({ available: false, remainingAttempts: 0 })
    await expect(capability.unlock('correct-pin')).rejects.toMatchObject({ code: 'PIN_DISABLED' })

    clearMaterial(source)
  })

  it('serializes concurrent attempts so they cannot bypass the five-attempt policy', async () => {
    const source = material()
    const capability = await PinUnlockCapability.create('correct-pin', source.key, source.salt)

    const attempts = await Promise.allSettled(
      Array.from({ length: 5 }, (_, index) => capability.unlock(`wrong-${index}`))
    )

    expect(attempts).toHaveLength(5)
    expect(attempts.every(({ status }) => status === 'rejected')).toBe(true)
    expect(capability.status()).toEqual({ available: false, remainingAttempts: 0 })
    clearMaterial(source)
  })

  it('authenticates capsule metadata and ciphertext before returning key material', async () => {
    const source = material()
    const capability = await PinUnlockCapability.create('correct-pin', source.key, source.salt)
    const internals = capability as unknown as CapsuleInternals
    internals.iv[0] = internals.iv[0]! ^ 0x80

    await expect(capability.unlock('correct-pin')).rejects.toMatchObject({ code: 'INVALID_PIN' })
    expect(capability.status()).toEqual({ available: true, remainingAttempts: 4 })

    capability.dispose()
    clearMaterial(source)
  })

  it('zeroes retained capsule buffers when explicitly disposed', async () => {
    const source = material()
    const capability = await PinUnlockCapability.create('correct-pin', source.key, source.salt)
    const internals = capability as unknown as CapsuleInternals

    capability.dispose()

    for (const buffer of [
      internals.kdfSalt,
      internals.iv,
      internals.authTag,
      internals.ciphertext
    ]) {
      expect(buffer.every((value) => value === 0)).toBe(true)
    }
    expect(capability.status()).toEqual({ available: false, remainingAttempts: 0 })
    clearMaterial(source)
  })

  it('cannot complete an unlock queued before synchronous disposal', async () => {
    const source = material()
    const capability = await PinUnlockCapability.create('correct-pin', source.key, source.salt)

    const pending = capability.unlock('correct-pin')
    capability.dispose()

    await expect(pending).rejects.toMatchObject({ code: 'PIN_DISABLED' })
    clearMaterial(source)
  })

  it('enforces PIN and vault material bounds before allocating KDF work', async () => {
    const source = material()

    await expect(PinUnlockCapability.create('123', source.key, source.salt)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(
      PinUnlockCapability.create('x'.repeat(1_025), source.key, source.salt)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      PinUnlockCapability.create('valid-pin', Buffer.alloc(31), source.salt)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      PinUnlockCapability.create('valid-pin', source.key, Buffer.alloc(15))
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    clearMaterial(source)
  })
})
