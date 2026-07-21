import { useLingui } from '@lingui/react/macro'
import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  AccountMutationResult,
  AccountSecurityProfile,
  AccountStatus,
  SyncStatus
} from '../../../shared/vault-contract'
import {
  accountMutationError,
  accountMutationKeepsBusy,
  AccountMutationGate,
  isCurrentAccountRefresh
} from '../components/account-switcher-ui'

type AccountOperation = 'add' | 'switch' | 'reorder' | 'remove'

interface UseVaultAccountsOptions {
  settingsOpen: boolean
  syncStatus: SyncStatus
  announce: (message: string) => void
}

interface UseVaultAccountsResult {
  accountStatus: AccountStatus | null
  accountBusy: boolean
  accountBusyLabel: string
  accountError: string
  sidebarAccountProfileName: string | null
  refreshAccountProfile: () => void
  addLocalAccount: () => Promise<void>
  switchLocalAccount: (accountId: string) => Promise<void>
  reorderLocalAccounts: (accountIds: readonly string[], expectedRevision: number) => Promise<void>
  removeLocalAccount: (accountId: string) => Promise<void>
}

export function useVaultAccounts({
  settingsOpen,
  syncStatus,
  announce
}: UseVaultAccountsOptions): UseVaultAccountsResult {
  const { t } = useLingui()
  const [accountProfileRefreshRevision, setAccountProfileRefreshRevision] = useState(0)
  const [sidebarAccountProfile, setSidebarAccountProfile] = useState<{
    owner: string
    profile: AccountSecurityProfile | null
  }>({ owner: '', profile: null })
  const [accountStatus, setAccountStatus] = useState<AccountStatus | null>(null)
  const [accountBusy, setAccountBusy] = useState(false)
  const [accountBusyLabel, setAccountBusyLabel] = useState('')
  const [accountError, setAccountError] = useState('')
  const accountStatusRequestRef = useRef(0)
  const accountMutationRequestRef = useRef(0)
  const accountMutationGateRef = useRef(new AccountMutationGate())
  const accountStaleRefreshPendingRef = useRef(false)

  const syncAccountIdentity = `${syncStatus.serverUrl ?? ''}\0${syncStatus.email?.toLowerCase() ?? ''}`
  const sidebarAccountProfileName =
    sidebarAccountProfile.owner === syncAccountIdentity
      ? sidebarAccountProfile.profile?.name.trim() || null
      : null

  useEffect(() => {
    let active = true
    if (syncStatus.state === 'ready') {
      void window.bearwarden.accountSecurity.profile().then(
        (profile) => {
          if (active) setSidebarAccountProfile({ owner: syncAccountIdentity, profile })
        },
        () => {
          // The footer stays usable when the remote profile is temporarily unavailable.
        }
      )
    }
    return () => {
      active = false
    }
  }, [accountProfileRefreshRevision, syncAccountIdentity, syncStatus.state])

  useEffect(() => {
    if (!settingsOpen) return
    if (accountStaleRefreshPendingRef.current) {
      accountStaleRefreshPendingRef.current = false
      accountMutationGateRef.current.leave()
      setAccountBusy(false)
      setAccountBusyLabel('')
    }
    let active = true
    const requestId = ++accountStatusRequestRef.current
    queueMicrotask(() => {
      if (!active) return
      setAccountStatus(null)
      setAccountError('')
      void window.bearwarden.accounts.status().then(
        (status) => {
          if (active && requestId === accountStatusRequestRef.current) setAccountStatus(status)
        },
        () => {
          if (active && requestId === accountStatusRequestRef.current) {
            setAccountError(t`The local account list could not be loaded. Try again later.`)
          }
        }
      )
    })
    return () => {
      active = false
    }
  }, [settingsOpen, t])

  const refreshAccountProfile = useCallback((): void => {
    setAccountProfileRefreshRevision((revision) => revision + 1)
  }, [])

  const runAccountMutation = useCallback(
    async (
      operation: AccountOperation,
      mutation: () => Promise<AccountMutationResult>
    ): Promise<void> => {
      if (!accountMutationGateRef.current.tryEnter()) return
      accountStatusRequestRef.current += 1
      const mutationRequestId = ++accountMutationRequestRef.current
      setAccountBusy(true)
      setAccountBusyLabel(
        operation === 'add' || operation === 'switch'
          ? t`Securely switching accounts and restarting`
          : operation === 'remove'
            ? t`Securely removing local account`
            : t`Updating local account order`
      )
      setAccountError('')
      try {
        const result = await mutation()
        if (mutationRequestId !== accountMutationRequestRef.current) return
        accountStatusRequestRef.current += 1
        setAccountStatus(result.status)
        if (!accountMutationKeepsBusy(result)) {
          accountMutationGateRef.current.leave()
          setAccountBusy(false)
          setAccountBusyLabel('')
          if (operation === 'remove') {
            announce(
              result.kind === 'updated' && result.cleanupPending
                ? t`The local account was removed. Remaining encrypted local data will be securely cleaned up on the next launch.`
                : t`The local account and its data on this device were removed.`
            )
          } else if (operation === 'reorder' && result.kind === 'updated') {
            announce(t`Local account order updated.`)
          }
        }
      } catch (accountMutationFailure) {
        if (mutationRequestId !== accountMutationRequestRef.current) return
        const message = accountMutationError(accountMutationFailure)
        setAccountError(message)
        if (
          accountMutationFailure instanceof Error &&
          accountMutationFailure.message.includes('ACCOUNT_STALE_STATE')
        ) {
          const statusRequestId = ++accountStatusRequestRef.current
          accountStaleRefreshPendingRef.current = true
          setAccountBusy(true)
          setAccountBusyLabel(t`Reloading local accounts`)
          void window.bearwarden.accounts.status().then(
            (status) => {
              if (
                !isCurrentAccountRefresh(
                  mutationRequestId,
                  accountMutationRequestRef.current,
                  statusRequestId,
                  accountStatusRequestRef.current
                )
              )
                return
              accountStaleRefreshPendingRef.current = false
              setAccountStatus(status)
              accountMutationGateRef.current.leave()
              setAccountBusy(false)
              setAccountBusyLabel('')
            },
            () => {
              if (
                !isCurrentAccountRefresh(
                  mutationRequestId,
                  accountMutationRequestRef.current,
                  statusRequestId,
                  accountStatusRequestRef.current
                )
              )
                return
              accountStaleRefreshPendingRef.current = false
              setAccountError(
                t`${message} The list could not be reloaded. Close Settings and try again.`
              )
              accountMutationGateRef.current.leave()
              setAccountBusy(false)
              setAccountBusyLabel('')
            }
          )
          return
        }
        accountMutationGateRef.current.leave()
        setAccountBusy(false)
        setAccountBusyLabel('')
      }
    },
    [announce, t]
  )

  const addLocalAccount = useCallback(async (): Promise<void> => {
    await runAccountMutation('add', () => window.bearwarden.accounts.add())
  }, [runAccountMutation])

  const switchLocalAccount = useCallback(
    async (accountId: string): Promise<void> => {
      await runAccountMutation('switch', () => window.bearwarden.accounts.switch(accountId))
    },
    [runAccountMutation]
  )

  const reorderLocalAccounts = useCallback(
    async (accountIds: readonly string[], expectedRevision: number): Promise<void> => {
      await runAccountMutation('reorder', () =>
        window.bearwarden.accounts.reorder(accountIds, expectedRevision)
      )
    },
    [runAccountMutation]
  )

  const removeLocalAccount = useCallback(
    async (accountId: string): Promise<void> => {
      await runAccountMutation('remove', () => window.bearwarden.accounts.remove(accountId, true))
    },
    [runAccountMutation]
  )

  return {
    accountStatus,
    accountBusy,
    accountBusyLabel,
    accountError,
    sidebarAccountProfileName,
    refreshAccountProfile,
    addLocalAccount,
    switchLocalAccount,
    reorderLocalAccounts,
    removeLocalAccount
  }
}
