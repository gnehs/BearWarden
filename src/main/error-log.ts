import { mkdirSync, appendFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { RendererErrorLogRequest } from '../shared/vault-contract'

const MAX_FIELD_LENGTH = 12_000

export type ErrorLogKind =
  | 'console-error'
  | 'ipc-error'
  | 'uncaught-exception'
  | 'unhandled-rejection'
  | 'renderer-console-error'
  | 'renderer-window-error'
  | 'renderer-unhandled-rejection'

interface ErrorLogRecord {
  timestamp: string
  process: 'main' | 'renderer'
  kind: ErrorLogKind
  message: string
  stack?: string
  channel?: string
  code?: string
  filename?: string
  lineno?: number
  colno?: number
}

interface ErrorLogOptions {
  now?: () => Date
  showItemInFolder?: (path: string) => void
  openPath?: (path: string) => Promise<string>
}

function boundedText(value: string): string {
  const normalized = value.replace(/\0/g, '\\0')
  return normalized.length > MAX_FIELD_LENGTH
    ? `${normalized.slice(0, MAX_FIELD_LENGTH)}...[truncated]`
    : normalized
}

function errorName(error: Error): string {
  return error.name && error.name !== 'Error' ? `${error.name}: ` : ''
}

function formatUnknownError(value: unknown): { message: string; stack?: string } {
  if (value instanceof Error) {
    return {
      message: boundedText(`${errorName(value)}${value.message}`),
      ...(value.stack ? { stack: boundedText(value.stack) } : {})
    }
  }
  if (typeof value === 'string') return { message: boundedText(value) }
  if (value === null) return { message: 'null' }
  if (value === undefined) return { message: 'undefined' }
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return { message: String(value) }
  }
  return { message: `[${Object.prototype.toString.call(value)}]` }
}

function formatConsoleError(args: readonly unknown[]): { message: string; stack?: string } {
  const formatted = args.map(formatUnknownError)
  const stack = formatted.find((entry) => entry.stack)?.stack
  return {
    message: boundedText(formatted.map((entry) => entry.message).join(' ')),
    ...(stack ? { stack } : {})
  }
}

function sanitizeRendererReport(report: RendererErrorLogRequest): RendererErrorLogRequest {
  return {
    kind: report.kind,
    message: boundedText(report.message),
    ...(report.stack ? { stack: boundedText(report.stack) } : {}),
    ...(report.filename ? { filename: boundedText(report.filename) } : {}),
    ...(Number.isSafeInteger(report.lineno) ? { lineno: report.lineno } : {}),
    ...(Number.isSafeInteger(report.colno) ? { colno: report.colno } : {})
  }
}

export class ErrorLogService {
  private installed = false

  constructor(
    readonly filePath: string,
    private readonly options: ErrorLogOptions = {}
  ) {}

  install(): void {
    if (this.installed) return
    this.installed = true
    this.ensureFile()

    const originalConsoleError = console.error.bind(console)
    console.error = (...args: unknown[]): void => {
      originalConsoleError(...args)
      const formatted = formatConsoleError(args)
      this.record('main', 'console-error', formatted)
    }

    process.on('uncaughtExceptionMonitor', (error, origin) => {
      this.record(
        'main',
        origin === 'unhandledRejection' ? 'unhandled-rejection' : 'uncaught-exception',
        formatUnknownError(error)
      )
    })
  }

  recordRendererError(report: RendererErrorLogRequest): void {
    const sanitized = sanitizeRendererReport(report)
    this.append({
      timestamp: this.timestamp(),
      process: 'renderer',
      ...sanitized
    })
  }

  recordMainError(
    kind: Extract<ErrorLogKind, 'ipc-error'>,
    error: unknown,
    metadata: { channel?: string; code?: string } = {}
  ): void {
    this.append({
      timestamp: this.timestamp(),
      process: 'main',
      kind,
      ...formatUnknownError(error),
      ...(metadata.channel ? { channel: boundedText(metadata.channel) } : {}),
      ...(metadata.code ? { code: boundedText(metadata.code) } : {})
    })
  }

  async showInFileManager(): Promise<void> {
    this.ensureFile()
    if (this.options.showItemInFolder) {
      this.options.showItemInFolder(this.filePath)
      return
    }
    const result = await this.options.openPath?.(dirname(this.filePath))
    if (result) throw new Error(result)
  }

  private record(
    processName: ErrorLogRecord['process'],
    kind: ErrorLogKind,
    details: { message: string; stack?: string }
  ): void {
    this.append({
      timestamp: this.timestamp(),
      process: processName,
      kind,
      ...details
    })
  }

  private ensureFile(): void {
    mkdirSync(dirname(this.filePath), { recursive: true })
    writeFileSync(this.filePath, '', { flag: 'a' })
  }

  private append(record: ErrorLogRecord): void {
    try {
      this.ensureFile()
      appendFileSync(this.filePath, `${JSON.stringify(record)}\n`, { encoding: 'utf8' })
    } catch {
      // Logging must never crash the application or mask the original error.
    }
  }

  private timestamp(): string {
    return (this.options.now?.() ?? new Date()).toISOString()
  }
}
