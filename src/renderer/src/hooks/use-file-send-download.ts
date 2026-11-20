import { useLingui } from '@lingui/react/macro'
import { useState } from 'react'
import { toast } from 'sonner'
import type { SendView } from '../../../shared/vault-contract'
import { classifySendDownloadFailure } from '../components/send-ui'
import type { SendPasswordPrompt } from '../components/SendPasswordDialog'

interface PasswordPrompt {
  send: SendView
  reason: SendPasswordPrompt
}

/**
 * Drives the file Send download flow, including the password prompt. A Send that is not marked
 * protected locally is tried without a password first, and a server `password required` answer
 * opens the prompt; a wrong password keeps it open with an error. Passwords never leave the
 * submit call.
 */
export function useFileSendDownload(setBusy: (busy: boolean) => void): {
  prompt: PasswordPrompt | null
  start: (send: SendView) => void
  submitPassword: (password: string) => void
  cancel: () => void
} {
  const { t } = useLingui()
  const [prompt, setPrompt] = useState<PasswordPrompt | null>(null)

  async function run(send: SendView, password: string | null): Promise<void> {
    setBusy(true)
    try {
      const result = await window.bearwarden.sends.downloadFile({ id: send.id, password })
      setPrompt(null)
      if (!result.canceled) toast.success(t`Saved ${result.fileName}`)
    } catch (error) {
      const failure = classifySendDownloadFailure(error)
      if (failure === 'failed') {
        setPrompt(null)
        toast.error(
          t({
            message: `Could not download the file Send. Check the sync connection.`,
            comment:
              'Error toast when downloading a file Send fails for a reason other than its password.'
          })
        )
      } else {
        setPrompt({ send, reason: failure })
      }
    } finally {
      setBusy(false)
    }
  }

  return {
    prompt,
    start: (send) => {
      if (send.passwordProtected) setPrompt({ send, reason: 'password-required' })
      else void run(send, null)
    },
    submitPassword: (password) => {
      if (prompt) void run(prompt.send, password)
    },
    cancel: () => setPrompt(null)
  }
}
