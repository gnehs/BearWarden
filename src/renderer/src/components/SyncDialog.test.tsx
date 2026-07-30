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
  shouldAutoOpenSyncErrorDetails,
  SyncFailureAlert,
  SyncOperationFailureAlert,
  syncErrorPresentation,
  syncErrorCodeFromThrown,
  syncInvalidResponseReasonLabel,
  syncInvalidResponseStageLabel,
  shouldOfferNewDeviceOtpResend,
  shouldAcceptAccountProfile
} from './SyncDialog'
import { buildSyncDiagnosticReport } from './sync-error-diagnostics'

describe('SyncDialog error diagnostics', () => {
  it('renders a safe reason and stable error code for automatic sync failures', () => {
    const markup = renderToStaticMarkup(<SyncFailureAlert code="SYNC_NETWORK" />)

    expect(markup).toContain('無法連線至同步伺服器')
    expect(markup).toContain('錯誤代碼：SYNC_NETWORK')
  })

  it('shows only a coarse incompatible snapshot section', () => {
    const markup = renderToStaticMarkup(
      <SyncFailureAlert
        code="SYNC_INVALID_RESPONSE"
        detail="cipher"
        onShowDetails={() => undefined}
      />
    )

    expect(markup).toContain('問題區段：保管庫項目資料')
    expect(markup).toContain('檢視詳細資訊')
    expect(markup).not.toMatch(/uuid|credential|ciphertext/i)
    expect(syncInvalidResponseStageLabel('prelogin')).toBe('帳戶金鑰衍生設定')
    expect(syncInvalidResponseStageLabel('authentication')).toBe('登入權杖回應')
    expect(syncInvalidResponseStageLabel('access-token')).toBe('存取權杖更新')
    expect(syncInvalidResponseStageLabel('organization')).toBe('組織金鑰與成員資料')
    expect(syncInvalidResponseReasonLabel('provider-organization-key')).toBe(
      '服務提供者管理的組織金鑰'
    )
  })

  it('maps every invalid-response reason to a fixed non-sensitive label', () => {
    const reasons = [
      'response-shape',
      'empty-response',
      'invalid-json',
      'non-object-response',
      'session-response',
      'prelogin-route-response',
      'kdf-settings',
      'kdf-parameters',
      'account-profile',
      'user-decryption-data',
      'organization-profile',
      'organization-key',
      'provider-organization-key',
      'folder-data',
      'unsupported-cipher-type',
      'cipher-data',
      'collection-data',
      'send-data',
      'snapshot-limit'
    ] as const

    for (const reason of reasons) {
      expect(syncInvalidResponseReasonLabel(reason)).toBeTruthy()
    }
    expect(JSON.stringify(reasons.map(syncInvalidResponseReasonLabel))).not.toMatch(
      /uuid|ciphertext|https?:\/\/|@/i
    )
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

  it('presents unsupported sign-in capabilities as stable safe categories', () => {
    expect(syncErrorPresentation('SYNC_SSO_REQUIRED').title).toBe('Single sign-on is required')
    expect(syncErrorPresentation('SYNC_DUO_UNSUPPORTED').title).toBe(
      'Duo verification is not supported'
    )
    expect(syncErrorPresentation('SYNC_KEY_CONNECTOR_UNSUPPORTED').title).toBe(
      'Key Connector accounts are not supported'
    )
    expect(syncErrorPresentation('SYNC_TRUSTED_DEVICE_UNSUPPORTED').title).toBe(
      'Trusted-device encryption is not supported'
    )
    expect(
      JSON.stringify([
        syncErrorPresentation('SYNC_SSO_REQUIRED'),
        syncErrorPresentation('SYNC_DUO_UNSUPPORTED'),
        syncErrorPresentation('SYNC_KEY_CONNECTOR_UNSUPPORTED'),
        syncErrorPresentation('SYNC_TRUSTED_DEVICE_UNSUPPORTED')
      ])
    ).not.toMatch(/error_description|server message|stack|https?:\/\//i)
  })

  it('offers OTP resend only for the explicit new-device challenge', () => {
    expect(shouldOfferNewDeviceOtpResend('SYNC_NEW_DEVICE_REQUIRED')).toBe(true)
    for (const code of [
      undefined,
      'SYNC_AUTH_REQUIRED',
      'SYNC_SSO_REQUIRED',
      'SYNC_DUO_UNSUPPORTED',
      'SYNC_FAILED'
    ] as const) {
      expect(shouldOfferNewDeviceOtpResend(code)).toBe(false)
    }
  })

  it('opens diagnostics for an incompatible response already present when the dialog mounts', () => {
    expect(
      shouldAutoOpenSyncErrorDetails(
        'SYNC_INVALID_RESPONSE',
        '2026-07-23T01:02:03.000Z',
        '2026-07-23T01:02:03.000Z',
        true
      )
    ).toBe(true)
    expect(
      shouldAutoOpenSyncErrorDetails('SYNC_INVALID_RESPONSE', undefined, undefined, true)
    ).toBe(true)
  })

  it('reopens diagnostics only for a newly recorded incompatible response', () => {
    const previous = '2026-07-23T01:02:03.000Z'
    expect(shouldAutoOpenSyncErrorDetails('SYNC_INVALID_RESPONSE', previous, previous)).toBe(false)
    expect(
      shouldAutoOpenSyncErrorDetails('SYNC_INVALID_RESPONSE', '2026-07-23T01:03:04.000Z', previous)
    ).toBe(true)
    expect(
      shouldAutoOpenSyncErrorDetails('SYNC_NETWORK', '2026-07-23T01:03:04.000Z', previous, true)
    ).toBe(false)
  })

  it('keeps a manual details action when an operation error has no status snapshot', () => {
    const markup = renderToStaticMarkup(
      <SyncOperationFailureAlert
        message="The server returned an incompatible response."
        onShowDetails={() => undefined}
      />
    )

    expect(markup).toContain('The server returned an incompatible response.')
    expect(markup).toContain('檢視詳細資訊')
  })

  it('accepts only fixed renderer-safe sync error codes from rejected operations', () => {
    expect(
      syncErrorCodeFromThrown(
        new Error('Error invoking remote method: BEARWARDEN:SYNC_INVALID_RESPONSE')
      )
    ).toBe('SYNC_INVALID_RESPONSE')
    expect(
      syncErrorCodeFromThrown(new Error('server said SYNC_NOT_A_REAL_CODE for account@example.com'))
    ).toBeUndefined()
    expect(
      syncErrorCodeFromThrown(new Error('BEARWARDEN:SYNC_INVALID_RESPONSE_WITH_RAW_SUFFIX'))
    ).toBeUndefined()
    expect(syncErrorCodeFromThrown('SYNC_INVALID_RESPONSE')).toBeUndefined()
  })

  it('builds a copyable allowlisted report without account or server identifiers', () => {
    const report = buildSyncDiagnosticReport({
      appVersion: '0.1.10',
      code: 'SYNC_INVALID_RESPONSE',
      detail: 'organization',
      reason: 'provider-organization-key',
      occurredAt: '2026-07-23T01:02:03.000Z',
      serverUrl:
        'https://person%40example.invalid:secret@private-vault.example.invalid/vault/item-id?access_token=token-secret#ciphertext-secret'
    })

    expect(report).toContain('App version: 0.1.10')
    expect(report).toContain('Error code: SYNC_INVALID_RESPONSE')
    expect(report).toContain('Problem section: organization')
    expect(report).toContain('Safe reason: provider-organization-key')
    expect(report).toContain('Server kind: self-hosted')
    expect(report).not.toContain('private-vault.example.invalid')
    expect(report).not.toMatch(/person%40|secret|item-id|access_token|token-secret/i)
    expect(report).not.toMatch(/email|password|credential|ciphertext|uuid/i)
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
