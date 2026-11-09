import { useLingui } from '@lingui/react/macro'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useShallow } from 'zustand/react/shallow'
import type { LoginAuthorization, LoginSummary, TotpCodeView } from '../../../shared/vault-contract'
import { isSharedLoginSummary } from '../components/organizations-ui'
import { resolveTotpRefreshTarget } from '../components/totp-refresh-target'
import { authorizationTokenField } from '../components/vault-detail-cache'
import { isRepromptRequired } from '../components/vault-error-ui'
import type { VaultItemAccess } from '../components/vault-item-access'
import type { TotpGenerationErrorState, TotpListEntry } from '../components/VaultShell-model'
import { useDescribeVaultError } from './use-describe-vault-error'
import { announceError } from '@renderer/lib/vault-notices'
import type { VaultAuthorization } from '@renderer/stores/vault-authorization-store'
import {
  findVaultItem,
  useVaultSessionStore,
  useVaultSessionStoreApi
} from '@renderer/stores/vault-session-store'

export interface SelectedItemTotp {
  code: TotpCodeView | null
  /** Code period index of the last fetched code, so the countdown restarts per code. */
  cycle: number | null
  generationError: TotpGenerationErrorState['kind'] | null
  revealReady: boolean
  showSkeleton: boolean
}

/**
 * The selected item's current TOTP code, refreshed every second while its detail is open.
 * A rejected authorization closes the selection instead of prompting again.
 */
export function useSelectedItemTotp(
  authorization: VaultAuthorization,
  itemAccess: VaultItemAccess,
  clearItemSelection: () => void
): SelectedItemTotp {
  const { t } = useLingui()
  const session = useVaultSessionStoreApi()
  const { selectedId, selectedLogin, editorMode, sharedItems } = useVaultSessionStore(
    useShallow((state) => ({
      selectedId: state.selectedId,
      selectedLogin: state.selectedLogin,
      editorMode: state.editorMode,
      sharedItems: state.sharedItems
    }))
  )
  const selectedSharedSummary = sharedItems.find((item) => item.id === selectedId) ?? null
  const [totpCodeState, setTotpCodeState] = useState<{
    itemId: string
    code: TotpCodeView
    cycle: number
  } | null>(null)
  const [totpGenerationErrorState, setTotpGenerationErrorState] =
    useState<TotpGenerationErrorState | null>(null)
  const totpCode =
    selectedLogin && totpCodeState?.itemId === selectedLogin.id ? totpCodeState.code : null
  const totpGenerationError =
    selectedLogin && totpGenerationErrorState?.itemId === selectedLogin.id
      ? totpGenerationErrorState.kind
      : null
  const totpRevealReady = totpCode !== null || totpGenerationError !== null
  const [showTotpSkeleton, setShowTotpSkeleton] = useState(false)
  const totpRefreshTarget =
    selectedSharedSummary && !selectedSharedSummary.viewPassword
      ? null
      : resolveTotpRefreshTarget(selectedLogin, selectedId, editorMode !== null)

  useEffect(() => {
    let active = true
    const itemId = totpRefreshTarget?.itemId
    const sourceRevision = totpRefreshTarget?.sourceRevision
    queueMicrotask(() => {
      if (!active) return
      setTotpCodeState(null)
      setTotpGenerationErrorState(null)
    })
    if (!itemId || !sourceRevision) {
      return () => {
        active = false
      }
    }

    let stopped = false
    let refreshing = false
    const refresh = (): void => {
      if (stopped || refreshing) return
      refreshing = true
      const item = findVaultItem(session.getState(), itemId)
      if (!item) {
        refreshing = false
        return
      }
      itemAccess
        .getTotp(item)
        .then(
          (nextCode) => {
            if (!active) return
            setTotpCodeState({
              itemId,
              code: nextCode,
              cycle: Math.floor(Date.now() / (nextCode.period * 1_000))
            })
            setTotpGenerationErrorState(null)
          },
          (totpError) => {
            if (!active) return
            if (isRepromptRequired(totpError)) {
              stopped = true
              window.clearInterval(timer)
              setTotpCodeState(null)
              authorization.revoke(itemId)
              clearItemSelection()
              announceError(
                t`Authorization expired. Select the item again and verify your master password.`
              )
              return
            }
            stopped = true
            window.clearInterval(timer)
            setTotpCodeState(null)
            setTotpGenerationErrorState({ itemId, kind: 'unsupported' })
          }
        )
        .finally(() => {
          refreshing = false
        })
    }
    const timer = window.setInterval(refresh, 1_000)
    refresh()
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [
    clearItemSelection,
    t,
    totpRefreshTarget?.itemId,
    totpRefreshTarget?.sourceRevision,
    itemAccess,
    session,
    authorization
  ])

  useEffect(() => {
    if (totpRevealReady || !totpRefreshTarget?.itemId) {
      queueMicrotask(() => setShowTotpSkeleton(false))
      return
    }
    const timer = window.setTimeout(() => setShowTotpSkeleton(true), 100)
    return () => window.clearTimeout(timer)
  }, [totpRefreshTarget?.itemId, totpRefreshTarget?.sourceRevision, totpRevealReady])

  return {
    code: totpCode,
    cycle: totpCodeState?.cycle ?? null,
    generationError: totpGenerationError,
    revealReady: totpRevealReady,
    showSkeleton: showTotpSkeleton
  }
}

function isTotpListItem(item: LoginSummary): boolean {
  return !isSharedLoginSummary(item) && item.type === 'login' && Boolean(item.hasTotp)
}

export interface TotpListCodes {
  codes: ReadonlyMap<string, TotpCodeView | null>
  /** The first available code, which drives the shared countdown in the list header. */
  countdown: TotpCodeView | null
}

/**
 * Codes for every personal TOTP item in the Codes list. Protected items are authorized
 * together with one reprompt, and each code refreshes when its period ends.
 */
export function useTotpListCodes(
  authorization: VaultAuthorization,
  scopedItems: readonly LoginSummary[],
  enabled: boolean
): TotpListCodes {
  const describeVaultError = useDescribeVaultError()
  const session = useVaultSessionStoreApi()
  const logins = window.bearwarden.logins
  const [totpListState, setTotpListState] = useState<Map<string, TotpListEntry>>(() => new Map())
  const totpListStateRef = useRef(new Map<string, TotpListEntry>())
  const totpListItemIds = useMemo(
    () => scopedItems.filter(isTotpListItem).map((item) => item.id),
    [scopedItems]
  )
  const totpListRevision = useMemo(
    () =>
      scopedItems
        .filter(isTotpListItem)
        .map((item) => `${item.id}:${item.updatedAt}`)
        .join('\0'),
    [scopedItems]
  )
  const totpListCodes = useMemo(() => {
    const codes = new Map<string, TotpCodeView | null>()
    for (const [id, entry] of totpListState) codes.set(id, entry?.code ?? null)
    return codes
  }, [totpListState])
  const totpListCountdown = useMemo(() => {
    for (const code of totpListCodes.values()) {
      if (code) return code
    }
    return null
  }, [totpListCodes])

  useEffect(() => {
    if (!enabled || totpListItemIds.length === 0) {
      totpListStateRef.current = new Map()
      queueMicrotask(() => setTotpListState(new Map()))
      return
    }

    let active = true
    let refreshing = false
    let listAuthorization: LoginAuthorization | undefined
    totpListStateRef.current = new Map()
    queueMicrotask(() => {
      if (active) setTotpListState(new Map())
    })

    const readCodes = async (
      tokenFor: (id: string) => string | undefined
    ): Promise<Array<{ id: string; code: TotpCodeView | null; fetchedAt: number }>> =>
      Promise.all(
        totpListItemIds.map(async (id) => {
          try {
            const code = await logins.getTotp({ id, ...authorizationTokenField(tokenFor(id)) })
            return { id, code, fetchedAt: Date.now() }
          } catch (error) {
            if (isRepromptRequired(error)) throw error
            return { id, code: null, fetchedAt: Date.now() }
          }
        })
      )

    const refresh = async (): Promise<void> => {
      if (!active || refreshing) return
      refreshing = true
      try {
        const now = Date.now()
        if (listAuthorization && listAuthorization.expiresAt <= now) listAuthorization = undefined
        const requiresListAuthorization = totpListItemIds.some(
          (id) => findVaultItem(session.getState(), id)?.reprompt === 1 && !authorization.token(id)
        )
        if (!listAuthorization && requiresListAuthorization) {
          listAuthorization = await authorization.request(totpListItemIds)
        }

        const tokenFor = (id: string): string | undefined =>
          listAuthorization?.token ?? authorization.token(id)
        let results: Array<{ id: string; code: TotpCodeView | null; fetchedAt: number }>
        try {
          results = await readCodes(tokenFor)
        } catch (error) {
          if (!isRepromptRequired(error)) throw error
          listAuthorization = await authorization.request(totpListItemIds)
          results = await readCodes(() => listAuthorization?.token)
        }
        if (!active) return

        const next = new Map<string, TotpListEntry>()
        for (const entry of results) {
          next.set(
            entry.id,
            entry.code
              ? {
                  code: entry.code,
                  expiresAt: entry.fetchedAt + entry.code.remainingSeconds * 1_000
                }
              : null
          )
        }
        totpListStateRef.current = next
        setTotpListState(next)
      } catch (error) {
        if (active) announceError(describeVaultError(error))
      } finally {
        refreshing = false
      }
    }

    const tick = (): void => {
      const now = Date.now()
      const current = totpListStateRef.current
      if (current.size === 0) return
      let shouldRefresh = false
      let changed = false
      const next = new Map<string, TotpListEntry>()
      for (const [id, entry] of current) {
        if (!entry) {
          next.set(id, null)
          continue
        }
        const remainingSeconds = Math.max(0, Math.ceil((entry.expiresAt - now) / 1_000))
        if (remainingSeconds === 0) shouldRefresh = true
        if (remainingSeconds !== entry.code.remainingSeconds) changed = true
        next.set(id, {
          ...entry,
          code: { ...entry.code, remainingSeconds }
        })
      }
      if (changed || shouldRefresh) {
        totpListStateRef.current = next
        setTotpListState(next)
      }
      if (shouldRefresh) void refresh()
    }

    void refresh()
    const timer = window.setInterval(tick, 1_000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [
    authorization,
    describeVaultError,
    session,
    totpListItemIds,
    totpListRevision,
    enabled,
    logins
  ])

  return { codes: totpListCodes, countdown: totpListCountdown }
}
