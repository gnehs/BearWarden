import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import AutofillPicker, { type AutofillPickerProps } from './AutofillPicker'

const renderedHandlers = vi.hoisted(() => ({
  onSelect: undefined as (() => void) | undefined,
  onKeyDown: undefined as ((event: { key: string; preventDefault: () => void }) => void) | undefined
}))

vi.mock('react/jsx-runtime', async (importOriginal) => {
  const runtime = await importOriginal<typeof import('react/jsx-runtime')>()

  function capture(factory: typeof runtime.jsx): typeof runtime.jsx {
    return ((type, componentProps, key) => {
      const props = componentProps as Record<string, unknown>
      if (type === 'section' && props['data-request-id'] === 'request-1') {
        renderedHandlers.onKeyDown = props.onKeyDown as typeof renderedHandlers.onKeyDown
      }
      if (props.className === 'min-h-12' && typeof props.onSelect === 'function') {
        renderedHandlers.onSelect = props.onSelect as typeof renderedHandlers.onSelect
      }
      return factory(type, componentProps, key)
    }) as typeof runtime.jsx
  }

  return {
    ...runtime,
    jsx: capture(runtime.jsx),
    jsxs: capture(runtime.jsxs)
  }
})

vi.mock('react/jsx-dev-runtime', async (importOriginal) => {
  const runtime = await importOriginal<typeof import('react/jsx-dev-runtime')>()
  const jsxDEV: typeof runtime.jsxDEV = ((type, componentProps, ...rest) => {
    const props = componentProps as Record<string, unknown>
    if (type === 'section' && props['data-request-id'] === 'request-1') {
      renderedHandlers.onKeyDown = props.onKeyDown as typeof renderedHandlers.onKeyDown
    }
    if (props.className === 'min-h-12' && typeof props.onSelect === 'function') {
      renderedHandlers.onSelect = props.onSelect as typeof renderedHandlers.onSelect
    }
    return runtime.jsxDEV(type, componentProps, ...rest)
  }) as typeof runtime.jsxDEV

  return { ...runtime, jsxDEV }
})

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

describe('AutofillPicker', () => {
  it('renders searchable safe metadata without exposing a URI path or secret', () => {
    const markup = renderToStaticMarkup(<AutofillPicker {...props()} />)

    expect(markup).toContain('Example Admin')
    expect(markup).toContain('admin@example.test')
    expect(markup).toContain('accounts.example.test')
    expect(markup).toContain('需要重新驗證身分')
    expect(markup).toContain('依名稱、使用者名稱或網站搜尋…')
    expect(markup).not.toContain('/login')
    expect(markup).not.toContain('must-not-leak')
  })

  it('renders locked and permission guidance with a route to the main window', () => {
    const locked = renderToStaticMarkup(<AutofillPicker {...props({ locked: true })} />)
    const denied = renderToStaticMarkup(<AutofillPicker {...props({ permission: 'denied' })} />)

    expect(locked).toContain('保管庫已鎖定')
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

    expect(markup).toContain('正在尋找可自動填寫的登入資訊')
    expect(markup).toContain('Esc')
    expect(markup).toContain('↵')
    expect(markup).not.toContain('Example Admin')
  })

  it('wires item selection and Escape to the request callbacks', () => {
    const onSelect = vi.fn()
    const onCancel = vi.fn()
    const preventDefault = vi.fn()
    renderedHandlers.onSelect = undefined
    renderedHandlers.onKeyDown = undefined

    renderToStaticMarkup(<AutofillPicker {...props({ onSelect, onCancel })} />)

    const renderedOnSelect = renderedHandlers.onSelect as (() => void) | undefined
    const renderedOnKeyDown = renderedHandlers.onKeyDown as
      ((event: { key: string; preventDefault: () => void }) => void) | undefined
    renderedOnSelect?.()
    renderedOnKeyDown?.({ key: 'Escape', preventDefault })

    expect(onSelect).toHaveBeenCalledWith('login-1')
    expect(onCancel).toHaveBeenCalledOnce()
    expect(preventDefault).toHaveBeenCalledOnce()
  })
})
