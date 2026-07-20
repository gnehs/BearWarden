import { describe, expect, it } from 'vitest'
import { parseStoredSend, sendViewFromRemote } from './send-parsing'

const emailAuthenticatedSend = {
  id: '10000000-0000-4000-8000-000000000001',
  accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
  type: 'text' as const,
  name: 'Verified Send',
  notes: null,
  text: 'secret',
  hidden: true,
  maxAccessCount: 2,
  accessCount: 1,
  revisionDate: '2026-07-19T00:00:00.000Z',
  expirationDate: '2026-07-21T00:00:00.000Z',
  deletionDate: '2026-07-22T00:00:00.000Z',
  disabled: false,
  hideEmail: true,
  authType: 'email' as const,
  passwordProtected: false
}

describe('Send parsing', () => {
  it('accepts the renderer-safe Email OTP authentication marker', () => {
    expect(parseStoredSend(emailAuthenticatedSend)).toEqual(emailAuthenticatedSend)
  })

  it('maps the wire Email auth type without exposing recipient addresses', () => {
    expect(
      sendViewFromRemote({
        ...emailAuthenticatedSend,
        authType: 0
      })
    ).toEqual(emailAuthenticatedSend)
  })
})
