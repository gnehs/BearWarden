import { BrowserWindow, Menu, type MenuItemConstructorOptions } from 'electron'
import { IPC_EVENTS, type ApplicationMenuCommand } from '../shared/vault-contract'
import {
  SELECTED_ITEM_COPY_SHORTCUTS,
  type SelectedItemCopyCommand
} from '../shared/selected-item-shortcuts'
import { translateMain } from './i18n'

export interface ApplicationMenuOptions {
  isMac: boolean
  onLockVault: () => void
}

export function executeApplicationMenuCommand(
  window: BrowserWindow,
  command: ApplicationMenuCommand
): void {
  if (command.startsWith('copy-selected-')) {
    const copyCommand = command.slice('copy-selected-'.length) as SelectedItemCopyCommand
    window.webContents.send(IPC_EVENTS.applicationMenuCopySelectedItem, copyCommand)
    return
  }

  switch (command) {
    case 'close-window':
      window.close()
      return
    case 'undo':
      window.webContents.undo()
      return
    case 'redo':
      window.webContents.redo()
      return
    case 'cut':
      window.webContents.cut()
      return
    case 'copy':
      window.webContents.copy()
      return
    case 'paste':
      window.webContents.paste()
      return
    case 'delete':
      window.webContents.delete()
      return
    case 'select-all':
      window.webContents.selectAll()
      return
    case 'toggle-developer-tools':
      window.webContents.toggleDevTools()
      return
    case 'toggle-full-screen':
      window.setFullScreen(!window.isFullScreen())
      return
    case 'minimize-window':
      window.minimize()
      return
    case 'toggle-maximize-window':
      if (window.isMaximized()) window.unmaximize()
      else window.maximize()
  }
}

export function installApplicationMenu(options: ApplicationMenuOptions): Menu {
  const copySelectedItem = (command: SelectedItemCopyCommand): void => {
    const window = BrowserWindow.getFocusedWindow()
    if (!window || window.isDestroyed()) return
    executeApplicationMenuCommand(window, `copy-selected-${command}`)
  }

  const template: MenuItemConstructorOptions[] = [
    options.isMac ? { role: 'appMenu' } : { role: 'fileMenu' },
    {
      id: 'vault-menu',
      label: translateMain('applicationMenu.vault'),
      submenu: [
        {
          id: 'vault-menu-lock',
          label: translateMain('applicationMenu.lock'),
          accelerator: 'CommandOrControl+L',
          click: options.onLockVault
        }
      ]
    },
    { role: 'editMenu' },
    {
      id: 'item-menu',
      label: translateMain('applicationMenu.item'),
      submenu: [
        {
          id: 'item-menu-copy-username',
          label: translateMain('itemContext.copyUsername'),
          accelerator: SELECTED_ITEM_COPY_SHORTCUTS.username.accelerator,
          click: () => copySelectedItem('username')
        },
        {
          id: 'item-menu-copy-password',
          label: translateMain('itemContext.copyPassword'),
          accelerator: SELECTED_ITEM_COPY_SHORTCUTS.password.accelerator,
          click: () => copySelectedItem('password')
        },
        {
          id: 'item-menu-copy-totp',
          label: translateMain('itemContext.copyTotp'),
          accelerator: SELECTED_ITEM_COPY_SHORTCUTS.totp.accelerator,
          click: () => copySelectedItem('totp')
        },
        {
          id: 'item-menu-copy-website',
          label: translateMain('itemContext.copyWebsite'),
          accelerator: SELECTED_ITEM_COPY_SHORTCUTS.website.accelerator,
          click: () => copySelectedItem('website')
        }
      ]
    },
    {
      label: translateMain('applicationMenu.view'),
      submenu: [{ role: 'toggleDevTools' }, { role: 'togglefullscreen' }]
    },
    { role: 'windowMenu' }
  ]

  const menu = Menu.buildFromTemplate(template)
  Menu.setApplicationMenu(menu)
  return menu
}
