import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { LoginView } from '../../../shared/vault-contract'
import LoginEditor from './LoginEditor'
import { editorHeaderContent, uriMatchExample, uriMatchOptions } from './login-editor-ui'

const loginFixture: LoginView = {
  id: 'login-fixture',
  type: 'login',
  name: '範例登入',
  subtitle: '○.example.com',
  username: 'sample-user',
  uri: 'https://○.example.com/△',
  uris: [{ uri: 'https://○.example.com/△', match: 1 }],
  passwordHistoryCount: 0,
  attachmentCount: 0,
  folderId: null,
  favorite: false,
  usageCount: 0,
  lastUsedAt: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
  deletedAt: null,
  archivedAt: null,
  reprompt: 0,
  passwordUpdatedAt: null,
  notes: null,
  hasTotp: false,
  passkeys: [],
  customFields: [],
  attachments: [],
  cardholderName: '',
  brand: '',
  expMonth: '',
  expYear: '',
  title: '',
  firstName: '',
  middleName: '',
  lastName: '',
  address1: '',
  address2: '',
  address3: '',
  city: '',
  state: '',
  postalCode: '',
  country: '',
  company: '',
  email: '',
  phone: '',
  identityUsername: '',
  publicKey: '',
  fingerprint: ''
}

function renderLoginEditor(login?: LoginView): string {
  return renderToStaticMarkup(
    createElement(LoginEditor, {
      login,
      folders: [],
      busy: false,
      onCancel: () => undefined,
      onDirtyChange: () => undefined,
      onDeletePasskey: async () => null,
      onSave: async () => true
    })
  )
}

describe('editorHeaderContent', () => {
  it('新增時只顯示一次項目類型', () => {
    expect(editorHeaderContent('安全備註', null)).toEqual({
      eyebrow: '新項目',
      heading: '安全備註',
      typeBadge: null
    })
  })

  it('編輯時保留項目名稱與類型資訊', () => {
    expect(editorHeaderContent('安全備註', '離線復原程序')).toEqual({
      eyebrow: '編輯 安全備註',
      heading: '離線復原程序',
      typeBadge: '安全備註'
    })
  })
})

describe('LoginEditor design language', () => {
  it('新增畫面沿用檢視頁的項目標題與卡片結構', () => {
    const markup = renderLoginEditor()

    expect(markup).toContain('aria-labelledby="editor-title"')
    expect(markup).toContain('id="editor-title">登入</h2>')
    expect(markup).toContain('data-slot="card"')
    expect(markup).toContain('data-slot="card-header"')
    expect(markup).toContain('aria-labelledby="item-section-title"')
  })

  it('新增模式不使用分頁，並同時呈現所有編輯器區段', () => {
    const markup = renderLoginEditor()

    expect(markup).not.toContain('aria-label="編輯器區段"')
    expect(markup).not.toContain('role="tablist"')
    expect(markup).not.toContain('data-slot="tabs"')
    expect(markup).toContain('data-editor-section="details"')
    expect(markup).toContain('data-editor-section="custom"')
    expect(markup).toContain('data-editor-section="organize"')
  })

  it('編輯既有項目也不使用分頁，並同時呈現所有編輯器區段', () => {
    const markup = renderLoginEditor(loginFixture)

    expect(markup).not.toContain('aria-label="編輯器區段"')
    expect(markup).not.toContain('role="tablist"')
    expect(markup).not.toContain('data-slot="tabs"')
    expect(markup).toContain('data-editor-section="details"')
    expect(markup).toContain('data-editor-section="custom"')
    expect(markup).toContain('data-editor-section="organize"')
  })

  it('所有網站匹配選項都有標籤，並以使用者網址產生符號範例', () => {
    const uri = 'https://vault.example.invalid/account'

    expect(uriMatchOptions).toHaveLength(7)
    for (const option of uriMatchOptions) {
      expect(option.label.trim()).not.toBe('')
      expect(uriMatchExample(option.value, uri)).toContain(uri)
      expect(uriMatchExample(option.value, uri)).toMatch(/[○△]/)
    }
    expect(uriMatchExample('1', '   ')).toBe('輸入 URL 以顯示相符範例')
  })

  it('網站 URI 的匹配範例會以淡色輔助文字出現在 SSR 標記', () => {
    const markup = renderLoginEditor(loginFixture)

    expect(markup).toMatch(/<p class="[^"]*text-muted-foreground[^"]*" data-uri-match-example="1">/)
    expect(markup).toContain(loginFixture.uris[0]!.uri)
  })
})
