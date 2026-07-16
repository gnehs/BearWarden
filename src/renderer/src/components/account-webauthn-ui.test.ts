import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import {
  canEnrollWebAuthnKey,
  canRemoveWebAuthnKey,
  isWebAuthnMutationOutcomeUnknown,
  webAuthnActionError,
  webAuthnKeyPresentation
} from './account-webauthn-ui'

function renderKeyMarkup(keys: Parameters<typeof webAuthnKeyPresentation>[0]): string {
  return renderToStaticMarkup(
    createElement(
      'ul',
      null,
      webAuthnKeyPresentation(keys).map((key) =>
        createElement(
          'li',
          { key: key.id },
          key.name,
          key.migrated ? createElement('span', null, '已移轉') : null
        )
      )
    )
  )
}

describe('account WebAuthn key renderer policy', () => {
  it('allows adding a key after an empty, disabled provider list is verified', () => {
    const keys = webAuthnKeyPresentation([])

    expect(keys).toEqual([])
    expect(canEnrollWebAuthnKey(false, '桌面安全金鑰', 'correct horse')).toBe(true)
    expect(canEnrollWebAuthnKey(true, '桌面安全金鑰', 'correct horse')).toBe(false)
  })

  it('renders only safe names and migration status, never the server slot', () => {
    const keys = [
      { id: 42, name: '  辦公室安全金鑰\n', migrated: true },
      { id: 43, name: '', migrated: false }
    ]
    const rendered = webAuthnKeyPresentation(keys)
    const markup = renderKeyMarkup(keys)

    expect(rendered).toEqual([
      { id: 42, name: '辦公室安全金鑰', migrated: true },
      { id: 43, name: '未命名的安全金鑰', migrated: false }
    ])
    expect(rendered.map(({ name, migrated }) => ({ name, migrated }))).toEqual([
      { name: '辦公室安全金鑰', migrated: true },
      { name: '未命名的安全金鑰', migrated: false }
    ])
    expect(markup).toContain('辦公室安全金鑰')
    expect(markup).toContain('已移轉')
    expect(markup).not.toContain('42')
    expect(markup).not.toContain('43')
  })

  it('keeps busy and final-key removal controls fail-closed', () => {
    expect(canRemoveWebAuthnKey(false, 1)).toBe(false)
    expect(canRemoveWebAuthnKey(true, 2)).toBe(false)
    expect(canRemoveWebAuthnKey(false, 2)).toBe(true)
  })

  it('maps failures to safe messages and refreshes unknown outcomes', () => {
    const internalDetail = new Error('TWO_FACTOR_MUTATION_UNKNOWN: server response body')

    expect(isWebAuthnMutationOutcomeUnknown(internalDetail)).toBe(true)
    expect(webAuthnActionError(internalDetail, 'remove')).toContain('結果不明')
    expect(webAuthnActionError(internalDetail, 'remove')).not.toContain('server response body')
    expect(webAuthnActionError(new Error('INVALID_MASTER_PASSWORD: internal'), 'enroll')).toBe(
      '主密碼驗證失敗；若要再試，請重新輸入主密碼。'
    )
  })

  it('does not render browser ceremony payload fields', () => {
    const markup = renderKeyMarkup([{ id: 7, name: '旅行安全金鑰', migrated: false }])
    const forbidden = ['chal' + 'lenge', 'attest' + 'ation', 'to' + 'ken']

    expect(forbidden.every((field) => !markup.includes(field))).toBe(true)
  })
})
