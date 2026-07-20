import { beforeEach, describe, expect, it, vi } from 'vitest'

const { buildFromTemplate, popup } = vi.hoisted(() => ({
  buildFromTemplate: vi.fn(),
  popup: vi.fn()
}))

vi.mock('electron', () => ({
  Menu: {
    buildFromTemplate
  }
}))

import { showItemContextMenu, type ItemContextMenuOptions } from './item-context-menu'

type TemplateEntry = {
  id?: string
  label?: string
  enabled?: boolean
  submenu?: TemplateEntry[]
  click?: () => void
  type?: 'separator'
}

function menuEntry(template: TemplateEntry[], id: string): TemplateEntry {
  const entry = template.find((candidate) => candidate.id === id)
  if (!entry) throw new Error(`Missing menu entry: ${id}`)
  return entry
}

function createOptions(): ItemContextMenuOptions {
  return {
    window: {} as ItemContextMenuOptions['window'],
    item: {
      id: 'item-1',
      hasUsername: true,
      hasPassword: true,
      uriLabels: ['https://example.test'],
      folderId: 'folder-1',
      archivedAt: null
    },
    folders: [
      { id: 'folder-1', name: 'Personal' },
      { id: 'folder-2', name: 'Work' }
    ],
    callbacks: {
      openInNewWindow: vi.fn(),
      copyUsername: vi.fn(),
      copyPassword: vi.fn(),
      copyWebsite: vi.fn(),
      moveToFolder: vi.fn(),
      cloneItem: vi.fn(),
      toggleArchive: vi.fn(),
      deleteItem: vi.fn()
    },
    position: { x: 24, y: 48 }
  }
}

describe('showItemContextMenu', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('builds and displays an item menu with the expected callbacks', () => {
    buildFromTemplate.mockReturnValue({ popup })
    const options = createOptions()

    showItemContextMenu(options)

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    expect(menuEntry(template, 'item-context-open-in-new-window').enabled).toBe(true)
    expect(menuEntry(template, 'item-context-copy-username').enabled).toBe(true)
    expect(menuEntry(template, 'item-context-copy-password').enabled).toBe(true)
    expect(menuEntry(template, 'item-context-copy-website').enabled).toBe(true)
    expect(menuEntry(template, 'item-context-clone').enabled).toBe(true)
    expect(menuEntry(template, 'item-context-toggle-archive').label).toBe('Archive Item')
    expect(menuEntry(template, 'item-context-delete').enabled).toBe(true)
    expect(popup).toHaveBeenCalledWith({ window: options.window, x: 24, y: 48 })

    menuEntry(template, 'item-context-open-in-new-window').click?.()
    menuEntry(template, 'item-context-copy-username').click?.()
    menuEntry(template, 'item-context-copy-password').click?.()
    menuEntry(template, 'item-context-copy-website').click?.()
    menuEntry(template, 'item-context-clone').click?.()
    menuEntry(template, 'item-context-toggle-archive').click?.()
    menuEntry(template, 'item-context-delete').click?.()

    const move = menuEntry(template, 'item-context-move')
    expect(move.enabled).toBe(true)
    expect(move.submenu).toBeDefined()
    const submenu = move.submenu!
    expect(menuEntry(submenu, 'item-context-move-unfiled').enabled).toBe(true)
    expect(menuEntry(submenu, 'item-context-move-folder-folder-1').enabled).toBe(false)
    expect(menuEntry(submenu, 'item-context-move-folder-folder-2').enabled).toBe(true)
    menuEntry(submenu, 'item-context-move-unfiled').click?.()
    menuEntry(submenu, 'item-context-move-folder-folder-2').click?.()

    expect(options.callbacks.openInNewWindow).toHaveBeenCalledWith('item-1', 0)
    expect(options.callbacks.copyUsername).toHaveBeenCalledWith('item-1')
    expect(options.callbacks.copyPassword).toHaveBeenCalledWith('item-1')
    expect(options.callbacks.copyWebsite).toHaveBeenCalledWith('item-1', 0)
    expect(options.callbacks.cloneItem).toHaveBeenCalledWith('item-1')
    expect(options.callbacks.toggleArchive).toHaveBeenCalledWith('item-1', false)
    expect(options.callbacks.moveToFolder).toHaveBeenNthCalledWith(1, 'item-1', null)
    expect(options.callbacks.moveToFolder).toHaveBeenNthCalledWith(2, 'item-1', 'folder-2')
    expect(options.callbacks.deleteItem).toHaveBeenCalledWith('item-1')
  })

  it('disables unavailable actions without reading or copying secrets directly', () => {
    buildFromTemplate.mockReturnValue({ popup })
    const options = createOptions()
    options.item = {
      id: '',
      hasUsername: false,
      hasPassword: false,
      uriLabels: [],
      folderId: null,
      archivedAt: null
    }
    options.folders = []
    delete options.position

    showItemContextMenu(options)

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    expect(menuEntry(template, 'item-context-open-in-new-window').enabled).toBe(false)
    expect(menuEntry(template, 'item-context-copy-username').enabled).toBe(false)
    expect(menuEntry(template, 'item-context-copy-password').enabled).toBe(false)
    expect(menuEntry(template, 'item-context-copy-website').enabled).toBe(false)
    expect(menuEntry(template, 'item-context-clone').enabled).toBe(false)
    expect(menuEntry(template, 'item-context-toggle-archive').enabled).toBe(false)
    expect(menuEntry(template, 'item-context-move').enabled).toBe(false)
    expect(menuEntry(template, 'item-context-delete').enabled).toBe(false)
    expect(popup).toHaveBeenLastCalledWith({ window: options.window })
  })

  it('uses indexed submenus for multiple URIs and generic labels for redacted metadata', () => {
    buildFromTemplate.mockReturnValue({ popup })
    const options = createOptions()
    options.item.uriLabels = ['', '']

    showItemContextMenu(options)

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    const open = menuEntry(template, 'item-context-open-in-new-window')
    const copy = menuEntry(template, 'item-context-copy-website')
    expect(open.submenu?.map((entry) => entry.label)).toEqual(['Website 1', 'Website 2'])
    expect(copy.submenu?.map((entry) => entry.label)).toEqual(['Website 1', 'Website 2'])
    menuEntry(open.submenu!, 'item-context-open-uri-1').click?.()
    menuEntry(copy.submenu!, 'item-context-copy-uri-1').click?.()
    expect(options.callbacks.openInNewWindow).toHaveBeenCalledWith('item-1', 1)
    expect(options.callbacks.copyWebsite).toHaveBeenCalledWith('item-1', 1)
  })

  it('disables password copying when the item has no password field', () => {
    buildFromTemplate.mockReturnValue({ popup })
    const options = createOptions()
    options.item.hasPassword = false

    showItemContextMenu(options)

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    expect(menuEntry(template, 'item-context-copy-password').enabled).toBe(false)
  })

  it('reports synchronous and asynchronous action failures', async () => {
    buildFromTemplate.mockReturnValue({ popup })
    const options = createOptions()
    const asyncError = new Error('async failure')
    const syncError = new Error('sync failure')
    options.onError = vi.fn()
    options.callbacks.copyUsername = vi.fn().mockRejectedValue(asyncError)
    options.callbacks.copyWebsite = vi.fn(() => {
      throw syncError
    })

    showItemContextMenu(options)

    const template = buildFromTemplate.mock.calls[0]?.[0] as TemplateEntry[]
    menuEntry(template, 'item-context-copy-username').click?.()
    menuEntry(template, 'item-context-copy-website').click?.()
    await Promise.resolve()

    expect(options.onError).toHaveBeenCalledWith(asyncError)
    expect(options.onError).toHaveBeenCalledWith(syncError)
  })
})
