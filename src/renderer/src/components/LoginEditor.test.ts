import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { LoginView } from '../../../shared/vault-contract'
import LoginEditor from './LoginEditor'
import {
  editorHeaderContent,
  reorderEditorItemsByClientId,
  reorderEditorUris,
  uriMatchExample,
  uriMatchOptions,
  uriMatchRecognizedParts,
  type EditorLoginUri
} from './login-editor-ui'

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

  it('網站匹配範例會標示實際參與辨識的網址片段', () => {
    const uri = 'https://gist.github.com/make-agent/project'

    expect(uriMatchRecognizedParts('default', uri)).toEqual({
      leading: 'https://gist.',
      recognized: 'github.com',
      trailing: '/make-agent/project'
    })
    expect(uriMatchRecognizedParts('0', uri).recognized).toBe('github.com')
    expect(uriMatchRecognizedParts('1', uri).recognized).toBe('gist.github.com')
    expect(uriMatchRecognizedParts('2', uri).recognized).toBe(uri)
    expect(uriMatchRecognizedParts('2', `  ${uri}  `).recognized).toBe(`  ${uri}  `)
    expect(uriMatchRecognizedParts('3', uri).recognized).toBe(uri)
    expect(uriMatchRecognizedParts('4', '^https://github\\.com/.*$').recognized).toBe(
      '^https://github\\.com/.*$'
    )
    expect(uriMatchRecognizedParts('5', uri)).toEqual({
      leading: uri,
      recognized: null,
      trailing: ''
    })
  })

  it('網站 URI 的匹配範例會以淡色輔助文字出現在 SSR 標記', () => {
    const recognizedUri = 'https://gist.github.com/make-agent/project'
    const markup = renderLoginEditor({
      ...loginFixture,
      uri: recognizedUri,
      uris: [{ uri: recognizedUri, match: 0 }]
    })

    expect(markup).toMatch(/<p class="[^"]*text-muted-foreground[^"]*" data-uri-match-example="0">/)
    expect(markup).toContain('https://gist.')
    expect(markup).toContain('/make-agent/project')
    expect(markup).toContain('<strong class="text-foreground font-semibold">github.com</strong>')
  })

  it('網站 URI 輸入框獨占第一行，匹配方式與操作按鈕排列在第二行', () => {
    const markup = renderLoginEditor(loginFixture)

    expect(markup).toContain('grid-cols-[auto_minmax(0,1fr)_auto]')
    expect(markup).toMatch(
      /<input(?=[^>]*id="editor-uri-0")(?=[^>]*class="[^"]*col-start-2[^"]*col-end-4)[^>]*>/
    )
  })

  it('網站 URI 使用拖曳把手取代上下移按鈕', () => {
    const markup = renderLoginEditor(loginFixture)

    expect(markup).toContain('data-uri-sortable-row=""')
    expect(markup).toContain('lucide-grip-vertical')
    expect(markup).toMatch(/<button[^>]*class="[^"]*row-span-2[^"]*w-5[^"]*cursor-grab/)
    expect(markup).not.toContain('aria-label="將網站上移"')
    expect(markup).not.toContain('aria-label="將網站下移"')
  })

  it('拖曳排序會同步更新網站順序與主要網址', () => {
    const uris: EditorLoginUri[] = [
      { clientId: 'uri-1', uri: 'https://one.example.invalid', match: null },
      { clientId: 'uri-2', uri: 'https://two.example.invalid', match: 1 },
      { clientId: 'uri-3', uri: 'https://three.example.invalid', match: 3 }
    ]

    const reordered = reorderEditorUris(uris, 'uri-3', 'uri-1')

    expect(reordered.uris.map((entry) => entry.clientId)).toEqual(['uri-3', 'uri-1', 'uri-2'])
    expect(reordered.uri).toBe('https://three.example.invalid')
  })

  it('自訂欄位使用左側窄版拖曳把手取代上下移按鈕', () => {
    const markup = renderLoginEditor({
      ...loginFixture,
      uri: null,
      uris: [],
      customFields: [
        { name: '環境', type: 'text', value: '測試', linkedId: null },
        { name: '復原碼', type: 'hidden', value: null, linkedId: null }
      ]
    })

    expect(markup.match(/data-custom-field-sortable-row=""/g)).toHaveLength(2)
    expect(markup.match(/lucide-grip-vertical/g)).toHaveLength(2)
    expect(markup).toMatch(/<button[^>]*type="button"[^>]*class="[^"]*w-5[^"]*cursor-grab/)
    expect(markup).toContain('aria-label="重新排序 環境"')
    expect(markup).not.toContain('aria-label="將「環境」上移"')
    expect(markup).not.toContain('aria-label="將「環境」下移"')
  })

  it('自訂欄位排序保留隱藏值的來源快照', () => {
    const customFields = [
      {
        clientId: 'field-1',
        source: { index: 0, name: '環境', type: 'text' as const, linkedId: null },
        name: '環境',
        type: 'text' as const,
        value: '測試',
        linkedId: null
      },
      {
        clientId: 'field-2',
        source: { index: 1, name: '復原碼', type: 'hidden' as const, linkedId: null },
        name: '復原碼',
        type: 'hidden' as const,
        value: null,
        linkedId: null
      }
    ]

    const reordered = reorderEditorItemsByClientId(customFields, 'field-2', 'field-1')

    expect(reordered.map((field) => field.clientId)).toEqual(['field-2', 'field-1'])
    expect(reordered[0]).toMatchObject({
      clientId: 'field-2',
      source: { index: 1, name: '復原碼', type: 'hidden', linkedId: null },
      value: null
    })
  })
})
