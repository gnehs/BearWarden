import { useEffect, useState } from 'react'
import { useLingui } from '@lingui/react/macro'
import type { AutofillPrompt, AutofillPromptErrorCode } from '../../../shared/vault-contract'
import AutofillPicker from './AutofillPicker'

export default function AutofillPickerHost(): React.JSX.Element {
  const { t } = useLingui()
  const [prompt, setPrompt] = useState<AutofillPrompt | null>(null)

  useEffect(() => {
    let active = true
    const unsubscribe = window.bearwarden.autofill.onPromptChanged((next) => {
      if (active) setPrompt(next)
    })
    void window.bearwarden.autofill.current().then(
      (current) => {
        if (active) setPrompt(current)
      },
      () => undefined
    )
    return () => {
      active = false
      unsubscribe()
    }
  }, [])

  const requestId = prompt?.requestId ?? 'loading'
  const errorCode = prompt?.error
  const errorMessages: Record<AutofillPromptErrorCode, string> = {
    NO_MATCHES: t`There are no matching logins for this website.`,
    LOCKED: t`The vault is locked. Unlock it in BearWarden first.`,
    REPROMPT_REQUIRED: t`This item requires reauthentication in BearWarden.`,
    ACCESSIBILITY_PERMISSION_DENIED: t`Accessibility permission is required to identify the current browser and website.`,
    UNSUPPORTED_APPLICATION: t`The active application is not a supported browser.`,
    URL_UNAVAILABLE: t`Unable to read the URL from the current browser tab.`,
    FOCUSED_WINDOW_UNAVAILABLE: t`Arc did not provide the currently active browser window.`,
    FOCUSED_ELEMENT_UNAVAILABLE: t`Place the cursor in a username or password field in the login form first.`,
    FOCUSED_FIELD_NOT_EDITABLE: t`Arc reported that the focused field is not editable text.`,
    FOCUSED_FIELD_OUTSIDE_WEB_CONTENT: t`Arc did not mark the focused field as web content.`,
    ADDRESS_FIELD_FOCUSED: t`The browser address bar is focused. Select a login field instead.`,
    TARGET_NOT_FOUND: t`The original browser tab has closed or could not be focused again.`,
    CONTEXT_CHANGED: t`The browser tab or URL has changed. Return to the login field and try again.`,
    FILL_FAILED: t`The browser did not provide a login field that can be filled safely.`,
    UNAVAILABLE: t`The autofill service is currently unavailable.`
  }
  const specializedError = errorCode === 'LOCKED' || errorCode === 'ACCESSIBILITY_PERMISSION_DENIED'
  return (
    <main className="bg-transparent p-2">
      <AutofillPicker
        requestId={requestId}
        choices={(prompt?.choices ?? []).map((choice) => ({
          id: choice.id,
          name: choice.name,
          username: choice.username,
          hostname: choice.hostname,
          reprompt: choice.reprompt
        }))}
        loading={!prompt || prompt.status === 'filling'}
        error={errorCode && !specializedError ? errorMessages[errorCode] : null}
        locked={errorCode === 'LOCKED'}
        permission={errorCode === 'ACCESSIBILITY_PERMISSION_DENIED' ? 'denied' : 'granted'}
        onSelect={(itemId) => {
          if (!prompt || prompt.status !== 'ready') return
          void window.bearwarden.autofill.select({ requestId: prompt.requestId, itemId })
        }}
        onCancel={() => {
          if (!prompt) return
          void window.bearwarden.autofill.cancel({ requestId: prompt.requestId })
        }}
        onOpenMain={() => {
          if (!prompt) return
          void window.bearwarden.autofill.openMain({ requestId: prompt.requestId })
        }}
      />
    </main>
  )
}
