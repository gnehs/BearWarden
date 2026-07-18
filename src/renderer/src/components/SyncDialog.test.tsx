import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PendingImportWarning } from './PendingImportWarning'
import { buildSyncTwoFactorRequest, WEB_AUTHN_TWO_FACTOR_METHOD } from './sync-two-factor-request'
import {
  accountProfileStateForStatus,
  accountProfileIdentity,
  applyAccountProfileIfCurrent,
  SyncFailureAlert,
  syncErrorPresentation,
  syncInvalidResponseStageLabel,
  shouldAcceptAccountProfile
} from './SyncDialog'

describe('SyncDialog error diagnostics', () => {
  it('renders a safe reason and stable error code for automatic sync failures', () => {
    const markup = renderToStaticMarkup(<SyncFailureAlert code="SYNC_NETWORK" />)

    expect(markup).toContain('無法連線到同步伺服器')
    expect(markup).toContain('錯誤代碼：SYNC_NETWORK')
  })

  it('shows only a coarse incompatible snapshot section', () => {
    const markup = renderToStaticMarkup(
      <SyncFailureAlert code="SYNC_INVALID_RESPONSE" detail="cipher" />
    )

    expect(markup).toContain('問題區段：密碼庫項目資料')
    expect(markup).not.toMatch(/uuid|credential|ciphertext/i)
    expect(syncInvalidResponseStageLabel('organization')).toBe('組織金鑰與成員資料')
  })

  it('maps every public error category without accepting raw connector details', () => {
    expect(syncErrorPresentation('SYNC_INVALID_RESPONSE')).toEqual({
      title: '伺服器回應不相容',
      description: '伺服器回傳的資料無法安全處理。請確認 Bitwarden 或 Vaultwarden 版本與相容性。'
    })
    expect(syncErrorPresentation('SYNC_INVALID_SSH_KEY')).toEqual({
      title: '伺服器包含不完整的 SSH Key',
      description:
        'Vaultwarden 回傳了一筆缺少必要金鑰欄位的 SSH Key。請先使用官方 Web Vault 修復或刪除該項目，再重新同步。'
    })
  })
})

describe('SyncDialog account profile identity gate', () => {
  it('keeps the loaded profile mounted while the same account is syncing', () => {
    const identity = accountProfileIdentity(
      'https://vault.example.invalid',
      'profile@example.invalid'
    )
    const profile = {
      name: 'Profile',
      email: 'profile@example.invalid',
      avatarColor: null,
      emailVerified: true,
      twoFactorEnabled: false
    }
    const loadedState = { owner: identity, profile }

    expect(accountProfileStateForStatus(loadedState, identity, 'syncing')).toBe(loadedState)
    expect(accountProfileStateForStatus(loadedState, identity, 'ready')).toBe(loadedState)
    expect(accountProfileStateForStatus(loadedState, identity, 'locked')).toEqual({
      owner: identity,
      profile: null
    })
  })

  it('clears a stale profile when the account identity changes during sync', () => {
    const oldIdentity = accountProfileIdentity(
      'https://vault.example.invalid',
      'old@example.invalid'
    )
    const newIdentity = accountProfileIdentity(
      'https://vault.example.invalid',
      'new@example.invalid'
    )

    expect(
      accountProfileStateForStatus(
        {
          owner: oldIdentity,
          profile: {
            name: 'Old account',
            email: 'old@example.invalid',
            avatarColor: null,
            emailVerified: true,
            twoFactorEnabled: false
          }
        },
        newIdentity,
        'syncing'
      )
    ).toEqual({ owner: newIdentity, profile: null })
  })

  it('rejects an old mutation completion after the new account profile has loaded', () => {
    const oldIdentity = accountProfileIdentity(
      'https://vault.example.invalid',
      'OLD@EXAMPLE.INVALID'
    )
    const newIdentity = accountProfileIdentity(
      'https://vault.example.invalid',
      'new@example.invalid'
    )

    expect(oldIdentity).toContain('old@example.invalid')
    expect(shouldAcceptAccountProfile(newIdentity, newIdentity)).toBe(true)
    expect(shouldAcceptAccountProfile(oldIdentity, newIdentity)).toBe(false)

    const newProfile = {
      name: 'New account',
      email: 'new@example.invalid',
      avatarColor: null,
      emailVerified: true,
      twoFactorEnabled: false
    }
    const oldCompletion = {
      ...newProfile,
      name: 'Old account',
      email: 'old@example.invalid'
    }
    const loadedNewState = { owner: newIdentity, profile: newProfile }
    expect(applyAccountProfileIfCurrent(loadedNewState, oldIdentity, oldCompletion)).toBe(
      loadedNewState
    )
  })
})

describe('SyncDialog WebAuthn request boundary', () => {
  it('keeps legacy two-factor requests free of the WebAuthn remember flag', () => {
    const request = buildSyncTwoFactorRequest({
      twoFactorMethod: '0',
      twoFactorCode: '  123456  ',
      webAuthnRemember: false
    })

    expect(request).toEqual({ twoFactorMethod: '0', twoFactorCode: '123456' })
    expect(request).not.toHaveProperty('webAuthnRemember')
  })

  it.each([false, true])(
    'sends an explicit remember value for the local security-key choice (%s)',
    (webAuthnRemember) => {
      const request = buildSyncTwoFactorRequest({
        twoFactorMethod: WEB_AUTHN_TWO_FACTOR_METHOD,
        twoFactorCode: 'legacy-code-must-not-leave-the-renderer',
        webAuthnRemember
      })

      expect(request).toEqual({ webAuthnRemember })
      expect(request).not.toHaveProperty('twoFactorMethod')
      expect(request).not.toHaveProperty('twoFactorCode')
    }
  )

  it('does not model WebAuthn ceremony data in the main application request', () => {
    expect(
      JSON.stringify(
        buildSyncTwoFactorRequest({
          twoFactorMethod: WEB_AUTHN_TWO_FACTOR_METHOD,
          twoFactorCode: '',
          webAuthnRemember: false
        })
      )
    ).not.toMatch(/challenge|assertion/i)
  })
})

describe('SyncDialog pending import resolution', () => {
  it('shows aggregate uncertainty, duplicate risk, password proof, and the safe disconnect exit', () => {
    const markup = renderToStaticMarkup(
      <PendingImportWarning
        count={3}
        startedAt="2026-07-17T00:00:00.000Z"
        masterPassword=""
        showPassword={false}
        busy={false}
        onMasterPasswordChange={() => undefined}
        onTogglePassword={() => undefined}
        onConfirm={() => undefined}
      />
    )

    expect(markup).toContain('批次匯入的伺服器結果未知')
    expect(markup).toContain('這 3 筆項目')
    expect(markup).toContain('不會自動重送')
    expect(markup).toContain('可能出現重複項目')
    expect(markup).toContain('本機密碼庫資料會保留')
    expect(markup).toContain('我了解風險，允許重新傳送')
    expect(markup).toContain('type="password"')
    expect(markup).toContain('maxLength="1024"')
    expect(markup).not.toMatch(/marker|localId/i)
  })
})
