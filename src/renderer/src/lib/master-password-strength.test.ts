import { describe, expect, it } from 'vitest'
import {
  MASTER_PASSWORD_STRENGTH_LEVELS,
  scoreMasterPassword,
  type MasterPasswordStrengthScore
} from './master-password-strength'

describe('master password strength levels', () => {
  it('maps zxcvbn scores to segments and tones', () => {
    const summary = Object.fromEntries(
      Object.entries(MASTER_PASSWORD_STRENGTH_LEVELS).map(([score, level]) => [
        score,
        [level.segments, level.tone]
      ])
    )
    expect(summary).toEqual({
      0: [1, 'destructive'],
      1: [1, 'destructive'],
      2: [2, 'warning'],
      3: [3, 'success'],
      4: [4, 'success']
    })
  })

  it('keys every level by its own score', () => {
    for (const [score, level] of Object.entries(MASTER_PASSWORD_STRENGTH_LEVELS)) {
      expect(level.score).toBe(Number(score) as MasterPasswordStrengthScore)
    }
  })
})

describe('scoreMasterPassword', () => {
  it('returns null for an empty password', async () => {
    await expect(scoreMasterPassword('')).resolves.toBeNull()
  })

  it('rates a common password as weak', async () => {
    const level = await scoreMasterPassword('password1234')
    expect(level).toMatchObject({ segments: 1, tone: 'destructive' })
  })

  it('rates a long random passphrase as the strongest level', async () => {
    await expect(scoreMasterPassword('vq7-lantern-OXIDE-puzzle-mango-42')).resolves.toBe(
      MASTER_PASSWORD_STRENGTH_LEVELS[4]
    )
  })

  it('treats the product name as guessable', async () => {
    const level = await scoreMasterPassword('bearwarden2026')
    expect(level?.segments).toBeLessThanOrEqual(2)
  })

  it('scores only the first 100 characters', async () => {
    const head = 'vq7-lantern-OXIDE-puzzle-mango-42'.repeat(4)
    expect(head.length).toBeGreaterThan(100)
    await expect(scoreMasterPassword(`${head}${'a'.repeat(50)}`)).resolves.toBe(
      await scoreMasterPassword(head.slice(0, 100))
    )
  })
})
