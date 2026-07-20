import {
  Children,
  isValidElement,
  type ElementType,
  type ReactElement,
  type ReactNode
} from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import { CommandItem } from '@renderer/components/ui/command'
import AutofillPicker, { type AutofillPickerProps } from './AutofillPicker'

function props(overrides: Partial<AutofillPickerProps> = {}): AutofillPickerProps {
  return {
    requestId: 'request-1',
    choices: [
      {
        id: 'login-1',
        name: 'Example Admin',
        username: 'admin@example.test',
        uri: 'https://accounts.example.test/login?secret=must-not-leak',
        reprompt: true
      }
    ],
    onSelect: vi.fn(),
    onCancel: vi.fn(),
    onOpenMain: vi.fn(),
    ...overrides
  }
}

function findElement(
  node: ReactNode,
  type: ElementType
): ReactElement<{ onSelect?: () => void }> | null {
  if (!isValidElement(node)) return null
  if (node.type === type) return node as ReactElement<{ onSelect?: () => void }>

  const { children } = node.props as { children?: ReactNode }
  for (const child of Children.toArray(children)) {
    const match = findElement(child, type)
    if (match) return match
  }
  return null
}

describe('AutofillPicker', () => {
  it('renders searchable safe metadata without exposing a URI path or secret', () => {
    const markup = renderToStaticMarkup(<AutofillPicker {...props()} />)

    expect(markup).toContain('Example Admin')
    expect(markup).toContain('admin@example.test')
    expect(markup).toContain('accounts.example.test')
    expect(markup).toContain('需重新驗證')
    expect(markup).toContain('搜尋名稱、帳號或網站')
    expect(markup).not.toContain('/login')
    expect(markup).not.toContain('must-not-leak')
  })

  it('renders locked and permission guidance with a route to the main window', () => {
    const locked = renderToStaticMarkup(<AutofillPicker {...props({ locked: true })} />)
    const denied = renderToStaticMarkup(<AutofillPicker {...props({ permission: 'denied' })} />)

    expect(locked).toContain('密碼庫已鎖定')
    expect(locked).toContain('開啟 BearWarden')
    expect(denied).toContain('需要輔助使用權限')
    expect(denied).not.toContain('Example Admin')
  })

  it('gives errors precedence over loading and does not render choices', () => {
    const markup = renderToStaticMarkup(
      <AutofillPicker {...props({ loading: true, error: '讀取失敗，請稍後再試。' })} />
    )

    expect(markup).toContain('role="alert"')
    expect(markup).toContain('讀取失敗，請稍後再試。')
    expect(markup).not.toContain('Example Admin')
    expect(markup).not.toContain('正在尋找可自動填入')
  })

  it('renders an accessible loading state and keyboard hints', () => {
    const markup = renderToStaticMarkup(<AutofillPicker {...props({ loading: true })} />)

    expect(markup).toContain('正在尋找可自動填入的登入項目')
    expect(markup).toContain('Esc')
    expect(markup).toContain('↵')
    expect(markup).not.toContain('Example Admin')
  })

  it('wires item selection and Escape to the request callbacks', () => {
    const onSelect = vi.fn()
    const onCancel = vi.fn()
    const preventDefault = vi.fn()
    const tree = AutofillPicker(props({ onSelect, onCancel }))
    const section = tree as ReactElement<{
      onKeyDown: (event: { key: string; preventDefault: () => void }) => void
    }>

    findElement(tree, CommandItem)?.props.onSelect?.()
    section.props.onKeyDown({ key: 'Escape', preventDefault })

    expect(onSelect).toHaveBeenCalledWith('login-1')
    expect(onCancel).toHaveBeenCalledOnce()
    expect(preventDefault).toHaveBeenCalledOnce()
  })
})
