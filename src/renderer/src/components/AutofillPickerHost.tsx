import { useEffect, useState } from 'react'
import type { AutofillPrompt, AutofillPromptErrorCode } from '../../../shared/vault-contract'
import AutofillPicker from './AutofillPicker'

const errorMessages: Record<AutofillPromptErrorCode, string> = {
  NO_MATCHES: '目前網站沒有相符的登入項目。',
  LOCKED: '密碼庫已鎖定，請先在 BearWarden 解鎖。',
  REPROMPT_REQUIRED: '此項目需要在 BearWarden 中重新驗證。',
  ACCESSIBILITY_PERMISSION_DENIED: '需要輔助使用權限才能辨識目前瀏覽器與網站。',
  UNSUPPORTED_APPLICATION: '目前前景應用程式不是支援的瀏覽器。',
  URL_UNAVAILABLE: '無法從目前瀏覽器分頁讀取網址。',
  FOCUSED_WINDOW_UNAVAILABLE: 'Arc 沒有提供目前作用中的瀏覽器視窗。',
  FOCUSED_ELEMENT_UNAVAILABLE: '請先將游標放在登入表單的帳號或密碼欄位。',
  FOCUSED_FIELD_NOT_EDITABLE: 'Arc 回報的焦點不是可編輯的文字欄位。',
  FOCUSED_FIELD_OUTSIDE_WEB_CONTENT: 'Arc 沒有將目前欄位標示為網頁內容。',
  ADDRESS_FIELD_FOCUSED: '目前焦點位於瀏覽器網址列，請改點登入欄位。',
  TARGET_NOT_FOUND: '原本的瀏覽器分頁已關閉或無法重新取得焦點。',
  CONTEXT_CHANGED: '瀏覽器分頁或網址已變更，請回到登入欄位後重新操作。',
  FILL_FAILED: '瀏覽器沒有提供可安全寫入的登入欄位。',
  UNAVAILABLE: '自動填入服務目前無法使用。'
}

export default function AutofillPickerHost(): React.JSX.Element {
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
