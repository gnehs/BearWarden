import { Menu, type MenuItemConstructorOptions } from 'electron'

export interface ApplicationMenuOptions {
  isMac: boolean
  onLockVault: () => void
}

export function installApplicationMenu(options: ApplicationMenuOptions): Menu {
  const template: MenuItemConstructorOptions[] = [
    options.isMac ? { role: 'appMenu' } : { role: 'fileMenu' },
    {
      id: 'vault-menu',
      label: '保管庫',
      submenu: [
        {
          id: 'vault-menu-lock',
          label: '鎖定',
          accelerator: 'CommandOrControl+L',
          click: options.onLockVault
        }
      ]
    },
    { role: 'editMenu' },
    {
      label: '顯示方式',
      submenu: [{ role: 'togglefullscreen' }]
    },
    { role: 'windowMenu' }
  ]

  const menu = Menu.buildFromTemplate(template)
  Menu.setApplicationMenu(menu)
  return menu
}
