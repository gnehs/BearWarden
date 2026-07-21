import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { AutofillAccessibilityGuide } from './AutofillAccessibilityGuide'

describe('AutoFill Accessibility guidance', () => {
  it('explains initial setup and stale permission recovery', () => {
    const markup = renderToStaticMarkup(
      <AutofillAccessibilityGuide shortcut={'Control+\\'} troubleshootingOpen />
    )

    expect(markup).toContain('設定輔助使用權限')
    expect(markup).toContain('隱私權與安全性')
    expect(markup).toContain('開啟 BearWarden')
    expect(markup).toContain('重新檢查')
    expect(markup).toContain('只會在您按下')
    expect(markup).toContain('Ctrl')
    expect(markup).toContain('已開啟但仍無法使用？')
    expect(markup).toContain('移除舊項目')
    expect(markup).toContain('role="note"')
  })
})
