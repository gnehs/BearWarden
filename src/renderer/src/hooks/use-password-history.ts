import { useLingui } from '@lingui/react/macro'
import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  PasswordHistoryEntryRequest,
  VaultPasswordHistoryView
} from '../../../shared/vault-contract'
import { useCopyFeedback } from '@renderer/hooks/use-copy-feedback'

export type PasswordHistoryEntryLocator = Omit<
  PasswordHistoryEntryRequest,
  'id' | 'authorizationToken'
>

export interface UsePasswordHistoryOptions {
  onLoad: () => Promise<VaultPasswordHistoryView>
  onReveal: (locator: PasswordHistoryEntryLocator) => Promise<string>
  onCopy: (locator: PasswordHistoryEntryLocator) => Promise<void>
}

interface UsePasswordHistoryResult {
  history: VaultPasswordHistoryView | null
  loading: boolean
  revealedValues: Record<string, string>
  revealing: Record<string, boolean>
  copying: Record<string, boolean>
  copiedKey: string | null
  error: string
  clearSecrets: () => void
  loadHistory: (retry?: boolean) => void
  toggleReveal: (index: number, lastUsedDate: string) => Promise<void>
  copyEntry: (index: number, lastUsedDate: string) => Promise<void>
}

export function usePasswordHistory({
  onLoad,
  onReveal,
  onCopy
}: UsePasswordHistoryOptions): UsePasswordHistoryResult {
  const { t } = useLingui()
  const [history, setHistory] = useState<VaultPasswordHistoryView | null>(null)
  const [loading, setLoading] = useState(true)
  const [revealedValues, setRevealedValues] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState<Record<string, boolean>>({})
  const [copying, setCopying] = useState<Record<string, boolean>>({})
  const [error, setError] = useState('')
  const { copiedKey, showCopied } = useCopyFeedback()
  const mountedRef = useRef(true)
  const loadRequestRef = useRef<Promise<VaultPasswordHistoryView> | null>(null)
  const revealTimersRef = useRef(new Map<string, number>())

  const clearRevealTimer = useCallback((key: string): void => {
    const timer = revealTimersRef.current.get(key)
    if (timer !== undefined) window.clearTimeout(timer)
    revealTimersRef.current.delete(key)
  }, [])

  const clearSecrets = useCallback((): void => {
    for (const timer of revealTimersRef.current.values()) window.clearTimeout(timer)
    revealTimersRef.current.clear()
    setRevealedValues({})
  }, [])

  const loadHistory = useCallback(
    (retry = false): void => {
      if (retry) loadRequestRef.current = null
      setLoading(true)
      setError('')
      const request = loadRequestRef.current ?? onLoad()
      loadRequestRef.current = request
      void request
        .then((loaded) => {
          if (mountedRef.current) setHistory(loaded)
        })
        .catch(() => {
          if (mountedRef.current) setError(t`Unable to read password history. Try again.`)
        })
        .finally(() => {
          if (mountedRef.current) setLoading(false)
        })
    },
    [onLoad, t]
  )

  useEffect(() => {
    mountedRef.current = true
    const revealTimers = revealTimersRef.current
    queueMicrotask(() => {
      if (mountedRef.current) loadHistory()
    })
    return () => {
      mountedRef.current = false
      for (const timer of revealTimers.values()) window.clearTimeout(timer)
      revealTimers.clear()
    }
  }, [loadHistory])

  const locatorFor = useCallback(
    (index: number, lastUsedDate: string): PasswordHistoryEntryLocator => ({
      index,
      lastUsedDate,
      expectedUpdatedAt: history!.expectedUpdatedAt
    }),
    [history]
  )

  const toggleReveal = useCallback(
    async (index: number, lastUsedDate: string): Promise<void> => {
      const key = `${index}:${lastUsedDate}`
      if (revealedValues[key] !== undefined) {
        clearRevealTimer(key)
        setRevealedValues((current) => {
          const next = { ...current }
          delete next[key]
          return next
        })
        return
      }
      setRevealing((current) => ({ ...current, [key]: true }))
      setError('')
      try {
        const value = await onReveal(locatorFor(index, lastUsedDate))
        if (!mountedRef.current) return
        setRevealedValues((current) => ({ ...current, [key]: value }))
        clearRevealTimer(key)
        revealTimersRef.current.set(
          key,
          window.setTimeout(() => {
            revealTimersRef.current.delete(key)
            setRevealedValues((current) => {
              const next = { ...current }
              delete next[key]
              return next
            })
          }, 30_000)
        )
      } catch {
        if (mountedRef.current) {
          setError(t`Unable to display this history entry. The item may have changed elsewhere.`)
        }
      } finally {
        if (mountedRef.current) {
          setRevealing((current) => {
            const next = { ...current }
            delete next[key]
            return next
          })
        }
      }
    },
    [clearRevealTimer, locatorFor, onReveal, revealedValues, t]
  )

  const copyEntry = useCallback(
    async (index: number, lastUsedDate: string): Promise<void> => {
      const key = `${index}:${lastUsedDate}`
      setCopying((current) => ({ ...current, [key]: true }))
      setError('')
      try {
        await onCopy(locatorFor(index, lastUsedDate))
        if (mountedRef.current) showCopied(key)
      } catch {
        if (mountedRef.current) {
          setError(t`Unable to copy this history entry. The item may have changed elsewhere.`)
        }
      } finally {
        if (mountedRef.current) {
          setCopying((current) => {
            const next = { ...current }
            delete next[key]
            return next
          })
        }
      }
    },
    [locatorFor, onCopy, showCopied, t]
  )

  return {
    history,
    loading,
    revealedValues,
    revealing,
    copying,
    copiedKey,
    error,
    clearSecrets,
    loadHistory,
    toggleReveal,
    copyEntry
  }
}
