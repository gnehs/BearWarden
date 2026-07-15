import { beforeEach, describe, expect, it, vi } from 'vitest'

const { buildFromTemplate, setApplicationMenu } = vi.hoisted(() => ({
  buildFromTemplate: vi.fn(),
  setApplicationMenu: vi.fn()
}))

vi.mock('electron', () => ({
  Menu: {
    buildFromTemplate,
    setApplicationMenu
  }
}))

import { installApplicationMenu } from './application-menu'

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
    const vaultMenu = menuEntry(template, 'vault-menu')
    const lockItem = menuEntry(vaultMenu.submenu ?? [], 'vault-menu-lock')
    expect(lockItem.label).toBe('鎖定')
    expect(lockItem.accelerator).toBe('CommandOrControl+L')

    lockItem.click?.()
    expect(onLockVault).toHaveBeenCalledOnce()
    expect(setApplicationMenu).toHaveBeenCalledWith(menu)
  })

  it('uses the native file menu role outside macOS', () => {
    buildFromTemplate.mockReturnValue({})

    installApplicationMenu({ isMac: false, onLockVault: vi.fn() })

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    expect(template[0]?.role).toBe('fileMenu')
  })
})
