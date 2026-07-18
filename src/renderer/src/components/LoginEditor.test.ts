import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import LoginEditor from './LoginEditor'
import { editorHeaderContent } from './login-editor-ui'

describe('editorHeaderContent', () => {
  it('新增時只顯示一次項目類型', () => {
    expect(editorHeaderContent('安全備註', null)).toEqual({
      eyebrow: '新增項目',
      heading: '安全備註',
      typeBadge: null
    })
  })

  it('編輯時保留項目名稱與類型資訊', () => {
    expect(editorHeaderContent('安全備註', '離線復原程序')).toEqual({
      eyebrow: '編輯安全備註',
      heading: '離線復原程序',
      typeBadge: '安全備註'
    })
  })
})

describe('LoginEditor design language', () => {
  it('新增畫面沿用檢視頁的項目標題與卡片結構', () => {
    const markup = renderToStaticMarkup(
      createElement(LoginEditor, {
        folders: [],
        busy: false,
        onCancel: () => undefined,
        onDirtyChange: () => undefined,
        onDeletePasskey: async () => null,
        onSave: async () => true
      })
    )

    expect(markup).toContain('class="detail-icon login"')
    expect(markup).toContain('class="detail-heading editor-heading"')
    expect(markup).toContain('detail-card form-section gap-0 py-0')
    expect(markup).toContain('data-slot="card-header"')
    expect(markup).toContain('aria-labelledby="item-section-title"')
  })
})
