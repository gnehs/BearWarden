import { useCallback, useEffect, useState } from 'react'
import type { LoginApprovalPrompt } from '../../../shared/vault-contract'

export interface LoginApprovalQueue {
  current: LoginApprovalPrompt | undefined
  dismissCurrent: () => void
}

/** Device login approval requests, shown one at a time in arrival order without duplicates. */
export function useLoginApprovalQueue(): LoginApprovalQueue {
  const [prompts, setPrompts] = useState<LoginApprovalPrompt[]>([])
  useEffect(
    () =>
      window.bearwarden.accountSecurity.onLoginApprovalRequested((prompt) => {
        setPrompts((current) =>
          current.some((entry) => entry.token === prompt.token) ? current : [...current, prompt]
        )
      }),
    []
  )
  const dismissCurrent = useCallback(() => setPrompts((current) => current.slice(1)), [])
  return { current: prompts[0], dismissCurrent }
}
