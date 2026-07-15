import { Menu, type BrowserWindow, type MenuItemConstructorOptions } from 'electron'

export interface ItemContextMenuItem {
  id: string
  username: string
  uri: string | null
  folderId: string | null
}

export interface ItemContextMenuFolder {
  id: string
  name: string
}

export interface ItemContextMenuCallbacks {
  openInNewWindow: (itemId: string) => void | Promise<void>
  copyUsername: (itemId: string) => void | Promise<void>
  copyWebsite: (itemId: string) => void | Promise<void>
  moveToFolder: (itemId: string, folderId: string | null) => void | Promise<void>
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

function hasText(value: string | null): boolean {
  return value !== null && value.trim().length > 0
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
      label: '未分類',
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
    label: '移至資料夾',
    enabled,
    submenu
  }
}

export function showItemContextMenu(options: ItemContextMenuOptions): Menu {
  const { callbacks, folders, item, onError, position, window } = options
  const itemEnabled = canUseItem(item)
  const template: MenuItemConstructorOptions[] = [
    {
      id: 'item-context-open-in-new-window',
      label: '在瀏覽器打開',
      enabled: itemEnabled && hasText(item.uri),
      click: () => invoke(() => callbacks.openInNewWindow(item.id), onError)
    },
    { type: 'separator' },
    {
      id: 'item-context-copy-username',
      label: '複製使用者名稱',
      enabled: itemEnabled && hasText(item.username),
      click: () => invoke(() => callbacks.copyUsername(item.id), onError)
    },
    {
      id: 'item-context-copy-website',
      label: '複製網站',
      enabled: itemEnabled && hasText(item.uri),
      click: () => invoke(() => callbacks.copyWebsite(item.id), onError)
    },
    { type: 'separator' },
    folderMenu(item, folders, callbacks, itemEnabled, onError),
    { type: 'separator' },
    {
      id: 'item-context-delete',
      label: '刪除項目',
      enabled: itemEnabled,
      click: () => invoke(() => callbacks.deleteItem(item.id), onError)
    }
  ]
  const menu = Menu.buildFromTemplate(template)
  menu.popup({ window, ...(position ?? {}) })
  return menu
}
