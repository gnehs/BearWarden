import { describe, expect, expectTypeOf, it } from 'vitest'
import {
  IPC_CHANNELS,
  type AccountRemoveRequest,
  type AccountReorderRequest,
  type AccountSessionDeauthorizationRequest,
  type AccountWebAuthnKeyEnrollmentRequest,
  type AccountWebAuthnKeyRemovalRequest,
  type AccountWebAuthnKeyView,
  type AccountWebAuthnKeysRequest,
  type BearWardenAPI,
  type LoginView,
  type SyncPurgePersonalVaultRequest,
  type SyncPurgePersonalVaultResult,
  type SyncResolvePendingImportRequest,
  type SyncStatus,
  type VaultExportRequest,
  type VaultExportResult,
  type VaultImportRequest,
  type VaultImportResult
} from './vault-contract'

describe('item history renderer contract', () => {
  it('exposes only nullable password revision metadata on an authorized item view', () => {
    expectTypeOf<LoginView['passwordUpdatedAt']>().toEqualTypeOf<string | null>()
  })
})

describe('vault export renderer contract', () => {
  it('makes plaintext CSV and ZIP passwordless while encrypted formats require a password', () => {
    expectTypeOf<VaultExportRequest>().toMatchTypeOf<
      | {
          masterPassword: string
          password: string
          format?: 'bitwarden-json' | 'bearwarden-native'
        }
      | {
          masterPassword: string
          password?: never
          format: 'bitwarden-csv' | 'bitwarden-zip'
        }
    >()
    expectTypeOf<VaultExportResult['skippedAttachments']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultExportResult['skippedPasswordHistoryEntries']>().toEqualTypeOf<
      number | undefined
    >()
    expectTypeOf<VaultExportResult['simplifiedUriMatches']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultExportResult['skippedPasswordRevisionDates']>().toEqualTypeOf<
      number | undefined
    >()
    expectTypeOf<VaultExportResult['skippedAutofillSettings']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultExportResult['simplifiedCustomFieldTypes']>().toEqualTypeOf<
      number | undefined
    >()
    expectTypeOf<VaultExportResult['riskyCustomFields']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultExportResult['emptyCustomFieldNames']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultExportResult['multilineCustomFields']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultExportResult['colonValueCustomFields']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultExportResult['durabilityWarning']>().toEqualTypeOf<true | undefined>()
  })
})

describe('vault import renderer contract', () => {
  it('makes the selected import disclosure an explicit format contract', () => {
    expectTypeOf<VaultImportRequest>().toMatchTypeOf<
      | { masterPassword: string; password?: string; format?: 'portable' }
      | { masterPassword: string; password?: never; format: 'keepass-xml' }
    >()
  })

  it('exposes only aggregate KeePass loss counts', () => {
    expectTypeOf<VaultImportResult['skippedAttachments']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultImportResult['skippedHistoryEntries']>().toEqualTypeOf<number | undefined>()
    expectTypeOf<VaultImportResult['skippedTemplateEntries']>().toEqualTypeOf<number | undefined>()
  })
})

describe('personal vault purge renderer contract', () => {
  it('requires two explicit confirmations and exposes only aggregate results', () => {
    expectTypeOf<SyncPurgePersonalVaultRequest>().toEqualTypeOf<{
      masterPassword: string
      confirmation: 'PURGE'
      confirmPurge: true
    }>()
    expectTypeOf<SyncPurgePersonalVaultResult>().toEqualTypeOf<
      | { status: 'complete'; removedItems: number; removedFolders: number }
      | {
          status: 'pending'
          remainingItems: number
          remainingFolders: number
          startedAt: string
        }
    >()
    expectTypeOf<SyncStatus['pendingPurge']>().toEqualTypeOf<
      { startedAt: string; remainingItems: number; remainingFolders: number } | undefined
    >()
    expectTypeOf<BearWardenAPI['sync']['purgePersonalVault']>().parameters.toEqualTypeOf<
      [SyncPurgePersonalVaultRequest]
    >()
    expect(IPC_CHANNELS.syncPurgePersonalVault).toBe('sync:purge-personal-vault')
  })
})

describe('pending sync import renderer contract', () => {
  it('exposes only aggregate status and a master-password resolution request', () => {
    expectTypeOf<SyncStatus['pendingImport']>().toEqualTypeOf<
      { count: number; startedAt: string } | undefined
    >()
    expectTypeOf<SyncResolvePendingImportRequest>().toEqualTypeOf<{
      masterPassword: string
      confirmRetry: true
    }>()
    expectTypeOf<BearWardenAPI['sync']['resolvePendingImport']>().parameters.toEqualTypeOf<
      [SyncResolvePendingImportRequest]
    >()
    expect(IPC_CHANNELS.syncResolvePendingImport).toBe('sync:resolve-pending-import')
  })
})

describe('local account management renderer contract', () => {
  it('keeps reorder and destructive removal requests narrow and explicit', () => {
    expectTypeOf<AccountReorderRequest>().toEqualTypeOf<{
      readonly accountIds: readonly string[]
      readonly expectedRevision: number
    }>()
    expectTypeOf<AccountRemoveRequest>().toEqualTypeOf<{
      readonly accountId: string
      readonly confirm: true
    }>()
    expect(IPC_CHANNELS.accountReorder).toBe('account:reorder')
    expect(IPC_CHANNELS.accountRemove).toBe('account:remove')
  })
})

describe('account WebAuthn renderer contract', () => {
  it('limits the public view to server key metadata', () => {
    const key: AccountWebAuthnKeyView = { id: 1, name: 'USB key', migrated: false }

    expect(key).toEqual({ id: 1, name: 'USB key', migrated: false })
    expect(Object.keys(key)).toEqual(['id', 'name', 'migrated'])
  })

  it('types only the narrow list, enrollment, and removal requests', () => {
    expectTypeOf<AccountWebAuthnKeysRequest>().toEqualTypeOf<{ masterPassword: string }>()
    expectTypeOf<AccountWebAuthnKeyEnrollmentRequest>().toEqualTypeOf<{
      masterPassword: string
      name: string
    }>()
    expectTypeOf<AccountWebAuthnKeyRemovalRequest>().toEqualTypeOf<{
      id: number
      masterPassword: string
      confirm: true
    }>()
    expectTypeOf<BearWardenAPI['accountSecurity']['listWebAuthnKeys']>().parameters.toEqualTypeOf<
      [AccountWebAuthnKeysRequest]
    >()
    expectTypeOf<BearWardenAPI['accountSecurity']['listWebAuthnKeys']>().returns.toEqualTypeOf<
      Promise<AccountWebAuthnKeyView[]>
    >()
    expectTypeOf<BearWardenAPI['accountSecurity']['enrollWebAuthnKey']>().returns.toEqualTypeOf<
      Promise<void>
    >()
    expectTypeOf<BearWardenAPI['accountSecurity']['removeWebAuthnKey']>().returns.toEqualTypeOf<
      Promise<void>
    >()
    expect(IPC_CHANNELS.accountSecurityWebAuthnKeys).toBe('account-security:webauthn-keys')
    expect(IPC_CHANNELS.accountSecurityEnrollWebAuthnKey).toBe(
      'account-security:enroll-webauthn-key'
    )
    expect(IPC_CHANNELS.accountSecurityRemoveWebAuthnKey).toBe(
      'account-security:remove-webauthn-key'
    )
  })
})

describe('account session deauthorization renderer contract', () => {
  it('requires a fresh password and two exact destructive confirmations', () => {
    expectTypeOf<AccountSessionDeauthorizationRequest>().toEqualTypeOf<{
      masterPassword: string
      confirmation: '取消所有工作階段'
      confirm: true
    }>()
    expectTypeOf<
      BearWardenAPI['accountSecurity']['deauthorizeSessions']
    >().parameters.toEqualTypeOf<[AccountSessionDeauthorizationRequest]>()
    expectTypeOf<BearWardenAPI['accountSecurity']['deauthorizeSessions']>().returns.toEqualTypeOf<
      Promise<void>
    >()
    expect(IPC_CHANNELS.accountDeauthorizeSessions).toBe('account-security:deauthorize-sessions')
  })
})
