import { describe, expect, it } from 'vitest'
import type { SendView } from '../../../shared/vault-contract'
import {
  dateTimeLocalToIso,
  dateTimeLocalValue,
  formatSendDate,
  maxAccessCountValidationMessage,
  sendStatuses,
  usesEmailVerification
} from './send-ui'

const baseSend: SendView = {
  id: 'send-1',
  accessId: 'access-1',
  type: 'text',
  name: '秘密',
  notes: null,
  text: '內容',
  hidden: false,
  maxAccessCount: null,
  accessCount: 0,
  revisionDate: '2026-07-19T08:00:00.000Z',
  expirationDate: null,
  deletionDate: '2026-07-30T08:00:00.000Z',
  disabled: false,
  hideEmail: false,
  authType: 'none',
  passwordProtected: false
}

describe('sendStatuses', () => {
  it('reports every active access, lifespan, and privacy condition', () => {
    expect(
      sendStatuses(
        {
          ...baseSend,
          hidden: true,
          maxAccessCount: 2,
          accessCount: 2,
          expirationDate: '2026-07-19T09:00:00.000Z',
          deletionDate: '2026-07-19T10:00:00.000Z',
          disabled: true,
          hideEmail: true,
          authType: 'password',
          passwordProtected: true
        },
        new Date('2026-07-20T00:00:00.000Z')
      ).map(({ key }) => key)
    ).toEqual([
      'password',
      'disabled',
      'expired',
      'max-access-reached',
      'pending-deletion',
      'hidden-text',
      'hidden-email'
    ])
  })

  it('does not mark future dates or an unreached view limit as inactive', () => {
    expect(
      sendStatuses(
        { ...baseSend, maxAccessCount: 2, accessCount: 1 },
        new Date('2026-07-20T00:00:00.000Z')
      )
    ).toEqual([])
  })
})

describe('email-verified Send safety', () => {
  it('recognizes a forward-compatible email auth type without weakening it', () => {
    const emailSend = { ...baseSend, authType: 'email' }
    expect(usesEmailVerification(emailSend)).toBe(true)
    expect(sendStatuses(emailSend).map(({ key }) => key)).toContain('email-verification')
  })
})

describe('Send dates', () => {
  it('round-trips datetime-local values through ISO timestamps', () => {
    const iso = '2026-07-20T08:30:00.000Z'
    expect(dateTimeLocalToIso(dateTimeLocalValue(iso))).toBe(iso)
  })

  it('handles missing and malformed dates without throwing', () => {
    expect(formatSendDate(null)).toBe('未設定')
    expect(formatSendDate('not-a-date')).toBe('日期格式無效')
    expect(dateTimeLocalValue('not-a-date')).toBe('')
    expect(dateTimeLocalToIso('')).toBeNull()
  })
})

describe('maximum access count', () => {
  it.each([null, undefined, 1, 42])('accepts an unset or positive integer value (%s)', (value) => {
    expect(maxAccessCountValidationMessage(value)).toBeNull()
  })

  it.each([0, -1, 1.5, 2_147_483_648, Number.NaN])('rejects an unsafe limit (%s)', (value) => {
    expect(maxAccessCountValidationMessage(value)).toContain('1 到 2,147,483,647')
  })
})
