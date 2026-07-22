import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PendingImportWarning } from './PendingImportWarning'
import {
  buildSyncTwoFactorRequest,
  resolveSyncTwoFactorMethod,
  syncTwoFactorProviderForMethod,
  WEB_AUTHN_TWO_FACTOR_METHOD
} from './sync-two-factor-request'
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

    expect(markup).toContain('無法連線至同步伺服器')
    expect(markup).toContain('錯誤代碼：SYNC_NETWORK')
  })

  it('shows only a coarse incompatible snapshot section', () => {
    const markup = renderToStaticMarkup(
      <SyncFailureAlert code="SYNC_INVALID_RESPONSE" detail="cipher" />
    )

    expect(markup).toContain('問題區段：保管庫項目資料')
    expect(markup).not.toMatch(/uuid|credential|ciphertext/i)
    expect(syncInvalidResponseStageLabel('organization')).toBe('組織金鑰與成員資料')
  })

  it('maps every public error category without accepting raw connector details', () => {
    expect(syncErrorPresentation('SYNC_INVALID_RESPONSE')).toEqual({
      title: '伺服器回應不相容',
      description: '無法安全處理伺服器傳回的資料。請檢查 Bitwarden 或 Vaultwarden 的版本與相容性。'
    })
    expect(syncErrorPresentation('SYNC_INVALID_SSH_KEY')).toEqual({
      title: '伺服器包含不完整的 SSH 金鑰',
      description:
        'Vaultwarden 回傳的 SSH 金鑰缺少必要的金鑰欄位。請在官方網頁保管庫中修復或刪除該金鑰，然後再次同步。'
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
  it('keeps the current advertised provider and otherwise chooses a supported fallback', () => {
    expect(resolveSyncTwoFactorMethod('1', ['0', '1'])).toBe('1')
    expect(resolveSyncTwoFactorMethod('3', ['7', '1'])).toBe('1')
    expect(resolveSyncTwoFactorMethod('0', ['7'])).toBe(WEB_AUTHN_TWO_FACTOR_METHOD)
  })

  it('does not offer unsupported server providers as a usable form method', () => {
    expect(resolveSyncTwoFactorMethod('0', ['2', '5', '6', '8'])).toBeNull()
    expect(syncTwoFactorProviderForMethod(WEB_AUTHN_TWO_FACTOR_METHOD)).toBe('7')
  })

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

    expect(markup).toContain('此批次匯入的伺服器結果不明')
    expect(markup).toContain('這 3 個項目')
    expect(markup).toContain('不會自動重新傳送')
    expect(markup).toContain('可能會在伺服器上建立重複項目')
    expect(markup).toContain('本機保管庫資料將會保留')
    expect(markup).toContain('我了解風險。允許重新傳送')
    expect(markup).toContain('type="password"')
    expect(markup).toContain('maxLength="1024"')
    expect(markup).not.toMatch(/marker|localId/i)
  })
})
