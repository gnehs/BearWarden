import { execFile, spawn } from 'node:child_process'
import { access } from 'node:fs/promises'
import { join } from 'node:path'
import { app } from 'electron'
import type { AutofillCredentials } from './autofill'

// Chromium may debounce AXEnhancedUserInterface activation for up to three seconds.
const HELPER_TIMEOUT_MS = 15_000
const HELPER_TERMINATION_GRACE_MS = 1_000
const MAX_HELPER_OUTPUT_BYTES = 16 * 1024

export type MacOSAutofillErrorCode =
  | 'UNAVAILABLE'
  | 'ACCESSIBILITY_PERMISSION_DENIED'
  | 'UNSUPPORTED_APPLICATION'
  | 'URL_UNAVAILABLE'
  | 'FOCUSED_WINDOW_UNAVAILABLE'
  | 'FOCUSED_ELEMENT_UNAVAILABLE'
  | 'FOCUSED_FIELD_NOT_EDITABLE'
  | 'FOCUSED_FIELD_OUTSIDE_WEB_CONTENT'
  | 'ADDRESS_FIELD_FOCUSED'
  | 'TARGET_NOT_FOUND'
  | 'TARGET_ACTIVATION_FAILED'
  | 'CONTEXT_CHANGED'
  | 'FILL_FAILED'
  | 'INVALID_HELPER_RESPONSE'

export class MacOSAutofillError extends Error {
  constructor(public readonly code: MacOSAutofillErrorCode) {
    super(code)
    this.name = 'MacOSAutofillError'
  }
}

export interface MacOSBrowserContext {
  readonly pid: number
  readonly bundleIdentifier: string
  readonly browser: string
  readonly url: string
  readonly focus: Readonly<{
    role: string | null
    subrole: string | null
    editable: boolean
    secure: boolean
    x: number | null
    y: number | null
    width: number | null
    height: number | null
  }>
}

interface HelperErrorBody {
  readonly error?: { readonly code?: string }
}

function helperPath(): string {
  return app.isPackaged
    ? join(process.resourcesPath, 'bin', 'bearwarden-macos-autofill')
    : join(app.getAppPath(), 'resources', 'bin', 'bearwarden-macos-autofill')
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function mapHelperError(value: string): MacOSAutofillError {
  let code = ''
  try {
    code = (JSON.parse(value) as HelperErrorBody).error?.code ?? ''
  } catch {
    // Never echo native stderr because it could contain platform details.
  }
  switch (code) {
    case 'ACCESSIBILITY_PERMISSION_DENIED':
    case 'UNSUPPORTED_APPLICATION':
    case 'URL_UNAVAILABLE':
    case 'FOCUSED_WINDOW_UNAVAILABLE':
    case 'FOCUSED_ELEMENT_UNAVAILABLE':
    case 'FOCUSED_FIELD_NOT_EDITABLE':
    case 'FOCUSED_FIELD_OUTSIDE_WEB_CONTENT':
    case 'ADDRESS_FIELD_FOCUSED':
    case 'TARGET_NOT_FOUND':
    case 'TARGET_ACTIVATION_FAILED':
    case 'CONTEXT_CHANGED':
    case 'FILL_FAILED':
      return new MacOSAutofillError(code)
    default:
      return new MacOSAutofillError('UNAVAILABLE')
  }
}

async function runHelper(command: string, args: readonly string[] = []): Promise<string> {
  if (process.platform !== 'darwin') throw new MacOSAutofillError('UNAVAILABLE')
  const executable = helperPath()
  await access(executable).catch(() => {
    throw new MacOSAutofillError('UNAVAILABLE')
  })
  return new Promise((resolve, reject) => {
    execFile(
      executable,
      [command, ...args],
      { timeout: HELPER_TIMEOUT_MS, maxBuffer: MAX_HELPER_OUTPUT_BYTES, encoding: 'utf8' },
      (error, stdout, stderr) => {
        if (error) {
          reject(mapHelperError(stderr))
          return
        }
        resolve(stdout)
      }
    )
  })
}

export function parseMacOSBrowserContext(value: string): MacOSBrowserContext {
  let raw: unknown
  try {
    raw = JSON.parse(value)
  } catch {
    throw new MacOSAutofillError('INVALID_HELPER_RESPONSE')
  }
  const context = record(raw)
  const focus = record(context?.focus)
  if (
    context?.ok !== true ||
    typeof context.pid !== 'number' ||
    !Number.isSafeInteger(context.pid) ||
    context.pid <= 0 ||
    typeof context.bundleIdentifier !== 'string' ||
    typeof context.browser !== 'string' ||
    typeof context.url !== 'string' ||
    !focus ||
    (focus.role !== undefined && focus.role !== null && typeof focus.role !== 'string') ||
    (focus.subrole !== undefined && focus.subrole !== null && typeof focus.subrole !== 'string') ||
    typeof focus.editable !== 'boolean' ||
    typeof focus.secure !== 'boolean' ||
    !['x', 'y', 'width', 'height'].every(
      (key) => focus[key] === undefined || focus[key] === null || typeof focus[key] === 'number'
    )
  ) {
    throw new MacOSAutofillError('INVALID_HELPER_RESPONSE')
  }
  let url: URL
  try {
    url = new URL(context.url)
  } catch {
    throw new MacOSAutofillError('INVALID_HELPER_RESPONSE')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new MacOSAutofillError('INVALID_HELPER_RESPONSE')
  }
  return {
    pid: context.pid,
    bundleIdentifier: context.bundleIdentifier,
    browser: context.browser,
    url: url.toString(),
    focus: {
      role: (focus.role as string | null | undefined) ?? null,
      subrole: (focus.subrole as string | null | undefined) ?? null,
      editable: focus.editable,
      secure: focus.secure,
      x: (focus.x as number | null | undefined) ?? null,
      y: (focus.y as number | null | undefined) ?? null,
      width: (focus.width as number | null | undefined) ?? null,
      height: (focus.height as number | null | undefined) ?? null
    }
  }
}

export class MacOSAutofillAdapter {
  async permission(prompt = false): Promise<boolean> {
    const output = await runHelper('permission', prompt ? ['--prompt'] : [])
    try {
      const parsed = record(JSON.parse(output))
      if (parsed?.ok !== true || typeof parsed.trusted !== 'boolean') {
        throw new Error('invalid')
      }
      return parsed.trusted
    } catch {
      throw new MacOSAutofillError('INVALID_HELPER_RESPONSE')
    }
  }

  async context(): Promise<MacOSBrowserContext> {
    return parseMacOSBrowserContext(await runHelper('context'))
  }

  async fill(
    context: MacOSBrowserContext,
    credentials: AutofillCredentials,
    signal: AbortSignal
  ): Promise<void> {
    if (process.platform !== 'darwin') throw new MacOSAutofillError('UNAVAILABLE')
    if (signal.aborted) throw new MacOSAutofillError('UNAVAILABLE')
    const executable = helperPath()
    await access(executable).catch(() => {
      throw new MacOSAutofillError('UNAVAILABLE')
    })
    await new Promise<void>((resolve, reject) => {
      const child = spawn(executable, ['fill'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true
      })
      let stdout = ''
      let stderr = ''
      let settled = false
      const finish = (operation: () => void): void => {
        if (settled) return
        settled = true
        clearTimeout(timeout)
        signal.removeEventListener('abort', abort)
        operation()
      }
      const abort = (): void => {
        child.kill()
        const forceTermination = setTimeout(
          () => child.kill('SIGKILL'),
          HELPER_TERMINATION_GRACE_MS
        )
        forceTermination.unref()
        finish(() => reject(new MacOSAutofillError('UNAVAILABLE')))
      }
      const timeout = setTimeout(() => {
        child.kill()
        const forceTermination = setTimeout(
          () => child.kill('SIGKILL'),
          HELPER_TERMINATION_GRACE_MS
        )
        forceTermination.unref()
        finish(() => reject(new MacOSAutofillError('UNAVAILABLE')))
      }, HELPER_TIMEOUT_MS)
      signal.addEventListener('abort', abort, { once: true })
      child.stdout.setEncoding('utf8')
      child.stderr.setEncoding('utf8')
      child.stdout.on('data', (chunk: string) => {
        stdout = (stdout + chunk).slice(0, MAX_HELPER_OUTPUT_BYTES)
      })
      child.stderr.on('data', (chunk: string) => {
        stderr = (stderr + chunk).slice(0, MAX_HELPER_OUTPUT_BYTES)
      })
      child.on('error', () => {
        finish(() => reject(new MacOSAutofillError('UNAVAILABLE')))
      })
      child.on('close', (code) => {
        if (code !== 0) {
          finish(() => reject(mapHelperError(stderr)))
          return
        }
        try {
          const parsed = record(JSON.parse(stdout))
          if (parsed?.ok !== true) throw new Error('invalid')
          finish(resolve)
        } catch {
          finish(() => reject(new MacOSAutofillError('INVALID_HELPER_RESPONSE')))
        }
      })
      // Secrets travel only through the child's private stdin, never argv, logs, or clipboard.
      child.stdin.end(
        JSON.stringify({
          pid: context.pid,
          bundleIdentifier: context.bundleIdentifier,
          url: context.url,
          focus: context.focus,
          username: credentials.username,
          password: credentials.password
        })
      )
    })
  }
}
