import { Menu, type BrowserWindow, type MenuItemConstructorOptions } from 'electron'
import { translateMain } from './i18n'

export interface ItemContextMenuItem {
  id: string
  hasUsername: boolean
  hasPassword: boolean
  /** Empty labels intentionally represent protected rows without retaining URI metadata. */
  uriLabels: string[]
  folderId: string | null
  archivedAt: string | null
}

export interface ItemContextMenuFolder {
  id: string
  name: string
}

export interface ItemContextMenuCallbacks {
  openInNewWindow: (itemId: string, uriIndex: number) => void | Promise<void>
  copyUsername: (itemId: string) => void | Promise<void>
  copyPassword: (itemId: string) => void | Promise<void>
  copyWebsite: (itemId: string, uriIndex: number) => void | Promise<void>
  moveToFolder: (itemId: string, folderId: string | null) => void | Promise<void>
  cloneItem: (itemId: string) => void | Promise<void>
  toggleArchive: (itemId: string, archived: boolean) => void | Promise<void>
  deleteItem: (itemId: string) => void | Promise<void>
}

export interface ItemContextMenuOptions {
  window: BrowserWindow
  item: ItemContextMenuItem
  folders: readonly ItemContextMenuFolder[]
  callbacks: ItemContextMenuCallbacks
  onError?: (error: unknown) => void
  position?: { x: number; y: number }
}

type MenuAction = () => void | Promise<void>

function invoke(action: MenuAction, onError?: (error: unknown) => void): void {
  try {
    void Promise.resolve(action()).catch((error: unknown) => onError?.(error))
  } catch (error) {
    onError?.(error)
  }
}

function canUseItem(item: ItemContextMenuItem): boolean {
  return item.id.trim().length > 0
}

function uriMenuLabel(label: string, index: number): string {
  return label.trim() || `${translateMain('itemContext.website')} ${index + 1}`
}

function folderMenu(
  item: ItemContextMenuItem,
  folders: readonly ItemContextMenuFolder[],
  callbacks: ItemContextMenuCallbacks,
  itemEnabled: boolean,
  onError?: (error: unknown) => void
): MenuItemConstructorOptions {
  const unfiledEnabled = itemEnabled && item.folderId !== null
  const submenu: MenuItemConstructorOptions[] = [
    {
      id: 'item-context-move-unfiled',
      label: translateMain('itemContext.unfiled'),
      enabled: unfiledEnabled,
      click: () => invoke(() => callbacks.moveToFolder(item.id, null), onError)
    },
    { type: 'separator' },
    ...folders.map((folder) => ({
      id: `item-context-move-folder-${folder.id}`,
      label: folder.name,
      enabled: itemEnabled && folder.id !== item.folderId,
      click: () => invoke(() => callbacks.moveToFolder(item.id, folder.id), onError)
    }))
  ]
  const enabled = submenu.some((entry) => entry.enabled === true)

  return {
    id: 'item-context-move',
    label: translateMain('itemContext.moveToFolder'),
    enabled,
    submenu
  }
}

export function showItemContextMenu(options: ItemContextMenuOptions): Menu {
  const { callbacks, folders, item, onError, position, window } = options
  const itemEnabled = canUseItem(item)
  const hasUris = item.uriLabels.length > 0
  const openWebsite: MenuItemConstructorOptions =
    item.uriLabels.length <= 1
      ? {
          id: 'item-context-open-in-new-window',
          label: translateMain('itemContext.openInBrowser'),
          enabled: itemEnabled && hasUris,
          click: () => invoke(() => callbacks.openInNewWindow(item.id, 0), onError)
        }
      : {
          id: 'item-context-open-in-new-window',
          label: translateMain('itemContext.openInBrowser'),
          enabled: itemEnabled,
          submenu: item.uriLabels.map((label, index) => ({
            id: `item-context-open-uri-${index}`,
            label: uriMenuLabel(label, index),
            click: () => invoke(() => callbacks.openInNewWindow(item.id, index), onError)
          }))
        }
  const copyWebsite: MenuItemConstructorOptions =
    item.uriLabels.length <= 1
      ? {
          id: 'item-context-copy-website',
          label: translateMain('itemContext.copyWebsite'),
          enabled: itemEnabled && hasUris,
          click: () => invoke(() => callbacks.copyWebsite(item.id, 0), onError)
        }
      : {
          id: 'item-context-copy-website',
          label: translateMain('itemContext.copyWebsite'),
          enabled: itemEnabled,
          submenu: item.uriLabels.map((label, index) => ({
            id: `item-context-copy-uri-${index}`,
            label: uriMenuLabel(label, index),
            click: () => invoke(() => callbacks.copyWebsite(item.id, index), onError)
          }))
        }
  const template: MenuItemConstructorOptions[] = [
    openWebsite,
    { type: 'separator' },
    {
      id: 'item-context-copy-username',
      label: translateMain('itemContext.copyUsername'),
      enabled: itemEnabled && item.hasUsername,
      click: () => invoke(() => callbacks.copyUsername(item.id), onError)
    },
    {
      id: 'item-context-copy-password',
      label: translateMain('itemContext.copyPassword'),
      enabled: itemEnabled && item.hasPassword,
      click: () => invoke(() => callbacks.copyPassword(item.id), onError)
    },
    copyWebsite,
    { type: 'separator' },
    {
      id: 'item-context-clone',
      label: translateMain('itemContext.duplicateItem'),
      enabled: itemEnabled,
      click: () => invoke(() => callbacks.cloneItem(item.id), onError)
    },
    {
      id: 'item-context-toggle-archive',
      label: item.archivedAt
        ? translateMain('itemContext.unarchive')
        : translateMain('itemContext.archiveItem'),
      enabled: itemEnabled,
      click: () => invoke(() => callbacks.toggleArchive(item.id, item.archivedAt !== null), onError)
    },
    { type: 'separator' },
    folderMenu(item, folders, callbacks, itemEnabled, onError),
    { type: 'separator' },
    {
      id: 'item-context-delete',
      label: translateMain('itemContext.deleteItem'),
      enabled: itemEnabled,
      click: () => invoke(() => callbacks.deleteItem(item.id), onError)
    }
  ]
  const menu = Menu.buildFromTemplate(template)
  menu.popup({ window, ...(position ?? {}) })
  return menu
}
