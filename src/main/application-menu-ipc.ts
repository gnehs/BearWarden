import type { BrowserWindow } from 'electron'
import type { ApplicationMenuCommand } from '../shared/vault-contract'
import { SELECTED_ITEM_COPY_SHORTCUTS } from '../shared/selected-item-shortcuts'
import { executeApplicationMenuCommand } from './application-menu'
import { createTrustedIpc, type IpcDisposer } from './typed-ipc'
import { VaultError } from './vault-errors'

const applicationMenuCommands = new Set<ApplicationMenuCommand>([
  'close-window',
  'undo',
  'redo',
  'cut',
  'copy',
  'paste',
  'delete',
  'select-all',
  'toggle-developer-tools',
  'toggle-full-screen',
  'minimize-window',
  'toggle-maximize-window',
  ...Object.keys(SELECTED_ITEM_COPY_SHORTCUTS).map(
    (command) => `copy-selected-${command}` as ApplicationMenuCommand
  )
])

export interface ApplicationMenuIpcOptions {
  getMainWindow: () => BrowserWindow | null
}

export function isApplicationMenuCommand(value: unknown): value is ApplicationMenuCommand {
  return typeof value === 'string' && applicationMenuCommands.has(value as ApplicationMenuCommand)
}

function parseApplicationMenuCommand(value: unknown): ApplicationMenuCommand {
  if (!isApplicationMenuCommand(value)) throw new VaultError('INVALID_INPUT')
  return value
}

export function registerApplicationMenuIpc(options: ApplicationMenuIpcOptions): IpcDisposer {
  const ipc = createTrustedIpc({ getMainWindow: options.getMainWindow })
  ipc.handle('application-menu:execute', parseApplicationMenuCommand, (command) => {
    const window = options.getMainWindow()
    if (!window) throw new VaultError('INVALID_INPUT')
    executeApplicationMenuCommand(window, command)
  })
  return () => ipc.dispose()
}
