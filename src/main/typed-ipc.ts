import {
  ipcMain,
  type BrowserWindow,
  type IpcMainEvent,
  type IpcMainInvokeEvent,
  type WebContents
} from 'electron'
import type {
  IpcEventArgs,
  IpcEventChannel,
  IpcInvokeChannel,
  IpcRequest,
  IpcResponse,
  IpcSendChannel
} from '../shared/ipc-api'
import { IPC_ERROR_PREFIX, type VaultErrorCode } from '../shared/vault-contract'
import { isVaultError, VaultError } from './vault-errors'

type MaybePromise<T> = T | Promise<T>

export type IpcDisposer = () => void

/** A raw invoke handler whose result is checked against the channel's contract response. */
export type IpcInvokeHandler<Channel extends IpcInvokeChannel> = (
  event: IpcMainInvokeEvent,
  input: unknown
) => MaybePromise<IpcResponse<Channel>>

/** Registers one invoke handler and returns the disposer that removes it. */
export function handleIpc<Channel extends IpcInvokeChannel>(
  channel: Channel,
  handler: IpcInvokeHandler<Channel>
): IpcDisposer {
  ipcMain.handle(channel, handler)
  return () => ipcMain.removeHandler(channel)
}

/** Registers one `ipcRenderer.send` listener and returns the disposer that removes it. */
export function onIpcSend(
  channel: IpcSendChannel,
  listener: (event: IpcMainEvent, payload: unknown) => void
): IpcDisposer {
  ipcMain.on(channel, listener)
  return () => ipcMain.removeListener(channel, listener)
}

/** Sends one main-to-renderer event with the payload its contract declares. */
export function sendIpcEvent<Channel extends IpcEventChannel>(
  target: Pick<WebContents, 'send'>,
  channel: Channel,
  ...args: IpcEventArgs<Channel>
): void {
  target.send(channel, ...args)
}

export function isTrustedVaultSender(
  event: Pick<IpcMainInvokeEvent, 'sender' | 'senderFrame'>,
  mainWindow: BrowserWindow | null
): boolean {
  if (!mainWindow || mainWindow.isDestroyed()) return false
  const webContents = mainWindow.webContents
  const senderFrame = event.senderFrame
  return (
    event.sender === webContents &&
    senderFrame != null &&
    senderFrame === webContents.mainFrame &&
    senderFrame.url === webContents.getURL()
  )
}

/** No-argument channels carry no payload, so renderer data can never steer an operation that takes none. */
export function parseNoInput(value: unknown): void {
  if (value !== undefined) throw new VaultError('INVALID_INPUT')
}

export function publicIpcError(code: VaultErrorCode): Error {
  return new Error(`${IPC_ERROR_PREFIX}${code}`)
}

export interface IpcErrorLog {
  recordMainError: (
    kind: 'ipc-error',
    error: unknown,
    metadata?: { channel?: string; code?: string }
  ) => void
}

export interface TrustedIpcContext {
  getMainWindow: () => BrowserWindow | null
  errorLog?: IpcErrorLog
}

export interface TrustedIpcHandlerOptions {
  /** Clears secrets from the raw renderer payload after the handler settles, even if parsing failed. */
  scrubInput?: (input: unknown) => void
}

export interface TrustedIpc {
  /**
   * Registers a main-window handler. `parse` validates the raw payload into the contract request,
   * and the handler's result must match the contract response.
   */
  handle<Channel extends IpcInvokeChannel, Request extends IpcRequest<Channel>>(
    channel: Channel,
    parse: (input: unknown) => Request,
    handler: (request: Request, event: IpcMainInvokeEvent) => MaybePromise<IpcResponse<Channel>>,
    options?: TrustedIpcHandlerOptions
  ): void
  /** Removes every handler registered through this registry; repeated calls are no-ops. */
  dispose(): void
}

/**
 * Creates a registry of main-window handlers that reject other senders and expose failures only as
 * `BEARWARDEN:<code>` errors.
 */
export function createTrustedIpc(context: TrustedIpcContext): TrustedIpc {
  const disposers: IpcDisposer[] = []
  return {
    handle(channel, parse, handler, options) {
      const dispose = handleIpc(channel, async (event, input) => {
        if (!isTrustedVaultSender(event, context.getMainWindow())) {
          const error = publicIpcError('INVALID_INPUT')
          context.errorLog?.recordMainError('ipc-error', error, { channel, code: 'INVALID_INPUT' })
          throw error
        }

        try {
          return await handler(parse(input), event)
        } catch (error) {
          if (isVaultError(error)) {
            context.errorLog?.recordMainError('ipc-error', error, { channel, code: error.code })
            // Stage-tagged failures carry a static diagnostic label in their message (never paths,
            // secrets, or vault content). Surface it in the main-process log so intermittent faults
            // like CORRUPT_VAULT can be traced to their exact throw site.
            if (error.message !== error.code)
              console.error(`[vault-ipc] ${channel}: ${error.message}`)
            throw publicIpcError(error.code)
          }
          context.errorLog?.recordMainError('ipc-error', error, {
            channel,
            code: 'INTERNAL_ERROR'
          })
          throw publicIpcError('INTERNAL_ERROR')
        } finally {
          options?.scrubInput?.(input)
        }
      })
      disposers.push(dispose)
    },
    dispose() {
      disposers.splice(0).forEach((dispose) => dispose())
    }
  }
}
