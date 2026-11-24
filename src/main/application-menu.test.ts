import { beforeEach, describe, expect, it, vi } from 'vitest'

const { buildFromTemplate, setApplicationMenu } = vi.hoisted(() => ({
  buildFromTemplate: vi.fn(),
  setApplicationMenu: vi.fn()
}))

vi.mock('electron', () => ({
  BrowserWindow: class {
    static getFocusedWindow = vi.fn()
  },
  Menu: {
    buildFromTemplate,
    setApplicationMenu
  }
}))

import { executeApplicationMenuCommand, installApplicationMenu } from './application-menu'
import { initializeMainI18n } from './i18n'

type TemplateEntry = {
  id?: string
  label?: string
  role?: string
  accelerator?: string
  submenu?: TemplateEntry[]
  click?: () => void
}

function menuEntry(template: TemplateEntry[], id: string): TemplateEntry {
  const entry = template.find((candidate) => candidate.id === id)
  if (!entry) throw new Error(`Missing menu entry: ${id}`)
  return entry
}

describe('installApplicationMenu', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('installs a macOS application menu whose lock command uses the shared callback', () => {
    const menu = { id: 'application-menu' }
    const onLockVault = vi.fn()
    buildFromTemplate.mockReturnValue(menu)

    expect(installApplicationMenu({ isMac: true, onLockVault })).toBe(menu)

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    expect(template[0]?.role).toBe('appMenu')
    const viewMenu = template.find((candidate) => candidate.label === 'View')
    expect(viewMenu?.submenu?.map((entry) => entry.role)).toEqual([
      'toggleDevTools',
      'togglefullscreen'
    ])
    const vaultMenu = menuEntry(template, 'vault-menu')
    const lockItem = menuEntry(vaultMenu.submenu ?? [], 'vault-menu-lock')
    expect(lockItem.label).toBe('Lock')
    expect(lockItem.accelerator).toBe('CommandOrControl+L')
    const itemMenu = menuEntry(template, 'item-menu')
    const itemSubmenu = itemMenu.submenu ?? []
    expect(menuEntry(itemSubmenu, 'item-menu-copy-username').accelerator).toBe('CommandOrControl+U')
    expect(menuEntry(itemSubmenu, 'item-menu-copy-password').accelerator).toBe('CommandOrControl+P')
    expect(menuEntry(itemSubmenu, 'item-menu-copy-totp').accelerator).toBe('CommandOrControl+T')
    expect(menuEntry(itemSubmenu, 'item-menu-copy-website').accelerator).toBe(
      'CommandOrControl+Shift+W'
    )

    lockItem.click?.()
    expect(onLockVault).toHaveBeenCalledOnce()
    expect(setApplicationMenu).toHaveBeenCalledWith(menu)
  })

  it('labels the native edit and window roles in the active locale', () => {
    buildFromTemplate.mockReturnValue({})
    initializeMainI18n('zh-TW')

    try {
      installApplicationMenu({ isMac: true, onLockVault: vi.fn() })
    } finally {
      initializeMainI18n('en')
    }

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    const editMenu = template.find((candidate) => candidate.role === 'editMenu')
    expect(editMenu?.label).toBe('編輯')
    expect(editMenu?.submenu?.find((entry) => entry.role === 'copy')?.label).toBe('拷貝')
    const windowMenu = template.find((candidate) => candidate.role === 'window')
    expect(windowMenu?.label).toBe('視窗')
    const roleItems = template
      .flatMap((menu) => menu.submenu ?? [])
      .flatMap((entry) => [entry, ...(entry.submenu ?? [])])
      .filter((entry) => entry.role)
    expect(roleItems.filter((entry) => !entry.label)).toEqual([])
  })

  it('uses the native file menu role outside macOS', () => {
    buildFromTemplate.mockReturnValue({})

    installApplicationMenu({ isMac: false, onLockVault: vi.fn() })

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    expect(template[0]?.role).toBe('fileMenu')
  })
})

describe('executeApplicationMenuCommand', () => {
  it('dispatches only the explicit window and editing commands', () => {
    const webContents = {
      undo: vi.fn(),
      redo: vi.fn(),
      cut: vi.fn(),
      copy: vi.fn(),
      paste: vi.fn(),
      delete: vi.fn(),
      selectAll: vi.fn(),
      toggleDevTools: vi.fn(),
      send: vi.fn()
    }
    const window = {
      webContents,
      close: vi.fn(),
      minimize: vi.fn(),
      maximize: vi.fn(),
      unmaximize: vi.fn(),
      isMaximized: vi.fn(() => false),
      isFullScreen: vi.fn(() => false),
      setFullScreen: vi.fn()
    }
    executeApplicationMenuCommand(window as never, 'close-window')
    executeApplicationMenuCommand(window as never, 'undo')
    executeApplicationMenuCommand(window as never, 'redo')
    executeApplicationMenuCommand(window as never, 'cut')
    executeApplicationMenuCommand(window as never, 'copy')
    executeApplicationMenuCommand(window as never, 'paste')
    executeApplicationMenuCommand(window as never, 'delete')
    executeApplicationMenuCommand(window as never, 'select-all')
    executeApplicationMenuCommand(window as never, 'toggle-developer-tools')
    executeApplicationMenuCommand(window as never, 'toggle-full-screen')
    executeApplicationMenuCommand(window as never, 'minimize-window')
    executeApplicationMenuCommand(window as never, 'toggle-maximize-window')
    executeApplicationMenuCommand(window as never, 'copy-selected-username')

    expect(window.close).toHaveBeenCalledOnce()
    expect(webContents.undo).toHaveBeenCalledOnce()
    expect(webContents.redo).toHaveBeenCalledOnce()
    expect(webContents.cut).toHaveBeenCalledOnce()
    expect(webContents.copy).toHaveBeenCalledOnce()
    expect(webContents.paste).toHaveBeenCalledOnce()
    expect(webContents.delete).toHaveBeenCalledOnce()
    expect(webContents.selectAll).toHaveBeenCalledOnce()
    expect(webContents.toggleDevTools).toHaveBeenCalledOnce()
    expect(window.setFullScreen).toHaveBeenCalledWith(true)
    expect(window.minimize).toHaveBeenCalledOnce()
    expect(window.maximize).toHaveBeenCalledOnce()
    expect(window.unmaximize).not.toHaveBeenCalled()
    expect(webContents.send).toHaveBeenCalledWith('application-menu:copy-selected-item', 'username')
  })

  it('restores an already maximized window', () => {
    const window = {
      webContents: {},
      isMaximized: () => true,
      unmaximize: vi.fn(),
      maximize: vi.fn()
    }

    executeApplicationMenuCommand(window as never, 'toggle-maximize-window')

    expect(window.unmaximize).toHaveBeenCalledOnce()
    expect(window.maximize).not.toHaveBeenCalled()
  })
})
