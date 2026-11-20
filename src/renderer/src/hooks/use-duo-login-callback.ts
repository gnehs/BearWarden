import { useCallback, useEffect, useRef, useState } from 'react'

export type DuoCallbackSubmitResult = 'accepted' | 'rejected'

/**
 * Tracks the window in which a Duo login is in flight in main and relays the pasted result to it.
 * Leaving the dialog while waiting cancels the login so main does not hold the vault for Duo.
 */
export function useDuoLoginCallback(): {
  awaiting: boolean
  callback: string
  setCallback: (value: string) => void
  submitting: boolean
  begin: () => void
  finish: () => void
  submit: () => Promise<DuoCallbackSubmitResult>
  cancel: () => void
} {
  const [awaiting, setAwaiting] = useState(false)
  const [callback, setCallback] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const awaitingRef = useRef(false)

  const begin = useCallback(() => {
    awaitingRef.current = true
    setAwaiting(true)
    setCallback('')
  }, [])

  const finish = useCallback(() => {
    awaitingRef.current = false
    setAwaiting(false)
    setCallback('')
    setSubmitting(false)
  }, [])

  const submit = useCallback(async (): Promise<DuoCallbackSubmitResult> => {
    const value = callback.trim()
    if (!awaitingRef.current || !value) return 'rejected'
    setSubmitting(true)
    try {
      await window.bearwarden.sync.submitDuoCallback(value)
      return 'accepted'
    } catch {
      return 'rejected'
    } finally {
      setSubmitting(false)
    }
  }, [callback])

  const cancel = useCallback(() => {
    if (!awaitingRef.current) return
    void window.bearwarden.sync.cancelDuo().catch(() => undefined)
  }, [])

  useEffect(
    () => () => {
      if (awaitingRef.current) void window.bearwarden.sync.cancelDuo().catch(() => undefined)
    },
    []
  )

  return { awaiting, callback, setCallback, submitting, begin, finish, submit, cancel }
}
