import { BrowserWindow, Menu, type MenuItemConstructorOptions } from 'electron'
import type { ApplicationMenuCommand } from '../shared/vault-contract'
import { translateMain } from './i18n'

export interface ApplicationMenuOptions {
  isMac: boolean
  onLockVault: () => void
}

export function executeApplicationMenuCommand(
  window: BrowserWindow,
  command: ApplicationMenuCommand
): void {
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
      label: translateMain('applicationMenu.view'),
      submenu: [{ role: 'togglefullscreen' }]
    },
    { role: 'windowMenu' }
  ]

  const menu = Menu.buildFromTemplate(template)
  Menu.setApplicationMenu(menu)
  return menu
}
