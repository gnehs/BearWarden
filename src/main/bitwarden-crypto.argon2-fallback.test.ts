import { vi } from 'vitest'

vi.mock('node:crypto', async (importOriginal) => {
  const original = await importOriginal<typeof import('node:crypto')>()
  return {
    ...original,
    argon2: vi.fn(
      (
        _algorithm: string,
        _parameters: unknown,
        callback: (error: Error & { code?: string }) => void
      ) => {
        callback(
          Object.assign(new Error('native Argon2 is unavailable'), {
            code: 'ERR_CRYPTO_ARGON2_NOT_SUPPORTED'
          })
        )
      }
    )
  }
})

import { describe, expect, it } from 'vitest'
import { deriveMasterKey } from './bitwarden-crypto'

describe('Bitwarden portable Argon2id fallback', () => {
  it('matches the published Bitwarden vector when Electron lacks native Argon2', async () => {
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

  it('serializes concurrent portable derivations without corrupting either result', async () => {
    const [first, second] = await Promise.all([
      deriveMasterKey('67t9b5g67$%Dh89n', 'test_key', {
        type: 'argon2id',
        iterations: 4,
        memoryMiB: 32,
        parallelism: 2
      }),
      deriveMasterKey('password', 'second_test_salt', {
        type: 'argon2id',
        iterations: 2,
        memoryMiB: 32,
        parallelism: 4
      })
    ])

    expect(first.toString('hex')).toBe(
      'cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2'
    )
    expect(second.toString('hex')).toBe(
      '1d60dd9829ede942cc88309096504190a32a029f7fa6e158dc180cb03601c1fd'
    )
    first.fill(0)
    second.fill(0)
  })
})
