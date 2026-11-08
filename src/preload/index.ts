import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron'
import { IPC_API, PRELOAD_IPC, type BearWardenAPI, type IpcEndpoint } from '../shared/ipc-api'
import type { RendererErrorLogRequest } from '../shared/vault-contract'

const MAX_RENDERER_LOG_FIELD_LENGTH = 12_000

function boundedRendererLogText(value: string): string {
  const normalized = value.replace(/\0/g, '\\0')
  return normalized.length > MAX_RENDERER_LOG_FIELD_LENGTH
    ? `${normalized.slice(0, MAX_RENDERER_LOG_FIELD_LENGTH)}...[truncated]`
    : normalized
}

function errorLikeDetails(value: unknown): { message: string; stack?: string } {
  if (value instanceof Error) {
    return {
      message: boundedRendererLogText(
        value.name && value.name !== 'Error' ? `${value.name}: ${value.message}` : value.message
      ),
      ...(value.stack ? { stack: boundedRendererLogText(value.stack) } : {})
    }
  }
  if (typeof value === 'string') return { message: boundedRendererLogText(value) }
  if (value === null) return { message: 'null' }
  if (value === undefined) return { message: 'undefined' }
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return { message: String(value) }
  }
  return { message: `[${Object.prototype.toString.call(value)}]` }
}

function sendRendererErrorLog(report: RendererErrorLogRequest): void {
  void ipcRenderer.invoke(PRELOAD_IPC.recordRendererError.channel, report).catch(() => undefined)
}

function installRendererErrorReporting(): void {
  if (typeof window === 'undefined') return

  const originalConsoleError = console.error.bind(console)
  console.error = (...args: unknown[]): void => {
    originalConsoleError(...args)
    const details = args.map(errorLikeDetails)
    const stack = details.find((entry) => entry.stack)?.stack
    sendRendererErrorLog({
      kind: 'renderer-console-error',
      message: boundedRendererLogText(details.map((entry) => entry.message).join(' ')),
      ...(stack ? { stack } : {})
    })
  }

  window.addEventListener('error', (event) => {
    const details = errorLikeDetails(event.error ?? event.message)
    sendRendererErrorLog({
      kind: 'renderer-window-error',
      message: details.message || boundedRendererLogText(event.message),
      ...(details.stack ? { stack: details.stack } : {}),
      ...(event.filename ? { filename: boundedRendererLogText(event.filename) } : {}),
      ...(Number.isSafeInteger(event.lineno) ? { lineno: event.lineno } : {}),
      ...(Number.isSafeInteger(event.colno) ? { colno: event.colno } : {})
    })
  })

  window.addEventListener('unhandledrejection', (event) => {
    sendRendererErrorLog({
      kind: 'renderer-unhandled-rejection',
      ...errorLikeDetails(event.reason)
    })
  })
}

function subscribe(
  channel: string,
  wrappedListener: (event: IpcRendererEvent, payload: unknown) => void
): () => void {
  ipcRenderer.on(channel, wrappedListener)
  return () => ipcRenderer.removeListener(channel, wrappedListener)
}

function rendererMethod(endpoint: IpcEndpoint): (...args: never[]) => unknown {
  const { channel } = endpoint
  switch (endpoint.kind) {
    case 'invoke': {
      const { toRequest } = endpoint
      if (!toRequest) return () => ipcRenderer.invoke(channel)
      return (...args) => ipcRenderer.invoke(channel, toRequest(...args))
    }
    case 'send': {
      const { toPayload } = endpoint
      return (...args) => ipcRenderer.send(channel, toPayload(...args))
    }
    case 'event':
      return (listener: (payload: unknown) => void) =>
        subscribe(channel, (_event, payload) => listener(payload))
    case 'signal':
      return (listener: () => void) => subscribe(channel, () => listener())
  }
}

const api = Object.fromEntries(
  Object.entries(IPC_API).map(([namespace, endpoints]) => [
    namespace,
    Object.fromEntries(
      Object.entries(endpoints).map(([method, endpoint]) => [method, rendererMethod(endpoint)])
    )
  ])
) as BearWardenAPI

if (!process.contextIsolated) {
  throw new Error('BearWarden requires Electron context isolation')
}

installRendererErrorReporting()
contextBridge.exposeInMainWorld('bearwarden', api)
