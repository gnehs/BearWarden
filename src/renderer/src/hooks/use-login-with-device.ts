import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  SyncLoginWithDeviceCompleteRequest,
  SyncResult,
  SyncTwoFactorProvider
} from '../../../shared/vault-contract'

/**
 * `awaiting-approval` covers the first completion call, which main holds until another device
 * answers; `completing` is a sign-in after a two-step answer. Done and failed return to `idle`
 * after the matching handler runs.
 */
export type LoginWithDeviceState =
  | { readonly phase: 'idle' }
  | { readonly phase: 'requesting' }
  | { readonly phase: 'awaiting-approval'; readonly fingerprint: string }
  | { readonly phase: 'two-factor'; readonly fingerprint: string }
  | { readonly phase: 'completing'; readonly fingerprint: string }

export interface LoginWithDeviceHandlers {
  onSynced: (result: SyncResult) => Promise<void>
  onTwoFactor: (providers: readonly SyncTwoFactorProvider[]) => void
  onFailure: (error: unknown) => Promise<void>
}

function isCanceled(error: unknown): boolean {
  return error instanceof Error && error.message.includes('SYNC_LOGIN_WITH_DEVICE_CANCELED')
}

/**
 * Drives one Login with device attempt held in main. Results that arrive after a cancel, a newer
 * attempt, or unmount are ignored, and leaving the dialog cancels the attempt in main.
 */
export function useLoginWithDevice(handlers: LoginWithDeviceHandlers): {
  state: LoginWithDeviceState
  begin: () => Promise<void>
  submitTwoFactor: (request: SyncLoginWithDeviceCompleteRequest) => Promise<void>
  sendEmailCode: () => Promise<void>
  cancel: () => void
} {
  const [state, setState] = useState<LoginWithDeviceState>({ phase: 'idle' })
  const attempt = useRef(0)
  const active = useRef(false)
  const handlersRef = useRef(handlers)
  useEffect(() => {
    handlersRef.current = handlers
  })

  const run = useCallback(
    async (
      id: number,
      fingerprint: string,
      request: SyncLoginWithDeviceCompleteRequest
    ): Promise<void> => {
      try {
        const response = await window.bearwarden.sync.completeLoginWithDevice(request)
        if (attempt.current !== id) return
        if (response.kind === 'two-factor-required') {
          setState({ phase: 'two-factor', fingerprint })
          handlersRef.current.onTwoFactor(response.providers)
          return
        }
        active.current = false
        setState({ phase: 'idle' })
        await handlersRef.current.onSynced(response.result)
      } catch (error) {
        if (attempt.current !== id || isCanceled(error)) return
        active.current = false
        setState({ phase: 'idle' })
        await handlersRef.current.onFailure(error)
      }
    },
    []
  )

  const begin = useCallback(async (): Promise<void> => {
    const id = ++attempt.current
    active.current = true
    setState({ phase: 'requesting' })
    let fingerprint: string
    try {
      ;({ fingerprint } = await window.bearwarden.sync.beginLoginWithDevice())
    } catch (error) {
      if (attempt.current !== id) return
      active.current = false
      setState({ phase: 'idle' })
      await handlersRef.current.onFailure(error)
      return
    }
    if (attempt.current !== id) return
    setState({ phase: 'awaiting-approval', fingerprint })
    await run(id, fingerprint, {})
  }, [run])

  const submitTwoFactor = useCallback(
    async (request: SyncLoginWithDeviceCompleteRequest): Promise<void> => {
      if (state.phase !== 'two-factor') return
      setState({ phase: 'completing', fingerprint: state.fingerprint })
      await run(attempt.current, state.fingerprint, request)
    },
    [run, state]
  )

  const sendEmailCode = useCallback(async (): Promise<void> => {
    await window.bearwarden.sync.sendLoginWithDeviceEmailCode()
  }, [])

  const cancel = useCallback((): void => {
    attempt.current += 1
    if (active.current) void window.bearwarden.sync.cancelLoginWithDevice().catch(() => undefined)
    active.current = false
    setState({ phase: 'idle' })
  }, [])

  useEffect(
    () => () => {
      attempt.current += 1
      if (active.current) void window.bearwarden.sync.cancelLoginWithDevice().catch(() => undefined)
    },
    []
  )

  return { state, begin, submitTwoFactor, sendEmailCode, cancel }
}
