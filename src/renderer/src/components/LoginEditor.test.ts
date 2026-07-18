import { describe, expect, it } from 'vitest'
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
