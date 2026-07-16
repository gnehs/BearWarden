import { renderToStaticMarkup } from 'react-dom/server'
import { toast } from 'sonner'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { InactiveTwoFactorReport } from '../../../shared/vault-contract'
import {
  InactiveTwoFactorPanel,
  failInactiveTwoFactorCheck,
  openInactiveTwoFactorDocumentation,
  resolveInactiveTwoFactorCheck,
  type InactiveTwoFactorCheckState
} from './VaultHealthPage'

vi.mock('@renderer/lib/utils', () => ({
  cn: (...inputs: unknown[]) => inputs.filter(Boolean).join(' ')
}))

vi.mock('./ui/field', () => ({
  Field: () => null,
  FieldDescription: () => null,
  FieldError: () => null,
  FieldGroup: () => null,
  FieldLabel: () => null
}))

vi.mock('sonner', () => ({ toast: { error: vi.fn() } }))

const report: InactiveTwoFactorReport = {
  analyzedCount: 5,
  excludedTotpCount: 2,
  excludedDeletedCount: 1,
  excludedArchivedCount: 3,
  findings: [
    {
      id: 'main-generated-item-id',
      name: 'Example account',
      matchedDomain: 'example.com',
      documentationUrl: 'https://canary.invalid/private-path'
    },
    {
      id: 'no-documentation-item-id',
      name: 'Service without guide',
      matchedDomain: 'service.example',
      documentationUrl: null
    }
  ]
}

function renderPanel(state: InactiveTwoFactorCheckState): string {
  return renderToStaticMarkup(
    <InactiveTwoFactorPanel state={state} onStart={() => undefined} onOpenItem={() => undefined} />
  )
}

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

describe('InactiveTwoFactorPanel', () => {
  it('starts idle without invoking the on-demand request', () => {
    const onStart = vi.fn()
    const markup = renderToStaticMarkup(
      <InactiveTwoFactorPanel
        state={{ status: 'idle', revision: 'revision-1' }}
        onStart={onStart}
        onOpenItem={() => undefined}
      />
    )

    expect(onStart).not.toHaveBeenCalled()
    expect(markup).toContain('只有在你按下按鈕後才會載入服務清單')
    expect(markup).toContain('檢查雙因素驗證')
  })

  it('renders loading, retry, counts, and empty states in Taiwan Traditional Chinese', () => {
    expect(renderPanel({ status: 'loading', revision: 'revision-1', requestId: 1 })).toContain(
      '正在載入 2fa.directory 服務清單'
    )
    expect(renderPanel({ status: 'failed', revision: 'revision-1' })).toContain('重試')

    const successMarkup = renderPanel({ status: 'success', revision: 'revision-1', report })
    expect(successMarkup).toContain('本次已分析')
    expect(successMarkup).toContain('已有 TOTP 2')
    expect(successMarkup).toContain('垃圾桶 1')
    expect(successMarkup).toContain('封存 3')

    const emptyMarkup = renderPanel({
      status: 'success',
      revision: 'revision-1',
      report: { ...report, findings: [] }
    })
    expect(emptyMarkup).toContain('沒有找到尚未設定 TOTP 的支援服務')
  })

  it('uses documentationUrl only as a button gate and never renders it', () => {
    const markup = renderPanel({ status: 'success', revision: 'revision-1', report })

    expect(markup).not.toContain('canary.invalid')
    expect(markup).toContain('2fa.directory 服務：example.com')
    expect(markup.match(/>設定說明</g)).toHaveLength(1)
  })
})

describe('inactive two-factor request safety', () => {
  it('discards stale results and failures', () => {
    const loading: InactiveTwoFactorCheckState = {
      status: 'loading',
      revision: 'revision-2',
      requestId: 8
    }

    expect(resolveInactiveTwoFactorCheck(loading, 'revision-1', 8, report)).toBe(loading)
    expect(resolveInactiveTwoFactorCheck(loading, 'revision-2', 7, report)).toBe(loading)
    expect(failInactiveTwoFactorCheck(loading, 'revision-2', 7)).toBe(loading)
    expect(resolveInactiveTwoFactorCheck(loading, 'revision-2', 8, report)).toEqual({
      status: 'success',
      revision: 'revision-2',
      report
    })
  })

  it('sends only the public matched domain to the main process', async () => {
    const openTwoFactorDocumentation = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('window', {
      bearwarden: { health: { openTwoFactorDocumentation } }
    })

    await openInactiveTwoFactorDocumentation(report.findings[0])
    expect(openTwoFactorDocumentation).toHaveBeenCalledWith({ matchedDomain: 'example.com' })

    await openInactiveTwoFactorDocumentation(report.findings[1])
    expect(openTwoFactorDocumentation).toHaveBeenCalledTimes(1)
  })

  it('shows a visible error when the main process cannot open documentation', async () => {
    const openTwoFactorDocumentation = vi.fn().mockRejectedValue(new Error('open failed'))
    vi.stubGlobal('window', {
      bearwarden: { health: { openTwoFactorDocumentation } }
    })

    await openInactiveTwoFactorDocumentation(report.findings[0])

    expect(toast.error).toHaveBeenCalledWith('無法開啟雙因素驗證設定說明')
  })
})
