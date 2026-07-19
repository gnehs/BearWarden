import { ipcMain, type BrowserWindow } from 'electron'
import { IPC_CHANNELS, type ApplicationMenuCommand } from '../shared/vault-contract'
import { executeApplicationMenuCommand } from './application-menu'

const applicationMenuCommands = new Set<ApplicationMenuCommand>([
  'close-window',
  'undo',
  'redo',
  'cut',
  'copy',
  'paste',
  'delete',
  'select-all',
  'toggle-full-screen',
  'minimize-window',
  'toggle-maximize-window'
])

export interface ApplicationMenuIpcOptions {
  getMainWindow: () => BrowserWindow | null
}

export function isApplicationMenuCommand(value: unknown): value is ApplicationMenuCommand {
  return typeof value === 'string' && applicationMenuCommands.has(value as ApplicationMenuCommand)
}

export function registerApplicationMenuIpc(options: ApplicationMenuIpcOptions): void {
  ipcMain.handle(IPC_CHANNELS.applicationMenuExecute, (event, command: unknown) => {
    const window = options.getMainWindow()
    if (
      !window ||
      window.isDestroyed() ||
      event.sender !== window.webContents ||
      !isApplicationMenuCommand(command)
    ) {
      throw new Error('Invalid application menu request')
    }
    executeApplicationMenuCommand(window, command)
  })
}
