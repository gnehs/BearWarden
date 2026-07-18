import { useCallback, useEffect, useRef, useState } from 'react'

const DEFAULT_COPY_FEEDBACK_DURATION_MS = 2_000

export function useCopyFeedback(durationMs = DEFAULT_COPY_FEEDBACK_DURATION_MS): {
  copiedKey: string | null
  clearCopied: () => void
  showCopied: (key: string) => void
} {
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const timerRef = useRef<number | null>(null)
  const mountedRef = useRef(true)

  const clearCopied = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
    if (mountedRef.current) setCopiedKey(null)
  }, [])

  const showCopied = useCallback(
    (key: string) => {
      if (!mountedRef.current) return
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
      setCopiedKey(key)
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null
        setCopiedKey(null)
      }, durationMs)
    },
    [durationMs]
  )

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current)
        timerRef.current = null
      }
    }
  }, [])

  return { copiedKey, clearCopied, showCopied }
}
