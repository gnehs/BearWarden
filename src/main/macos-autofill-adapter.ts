import { execFile, spawn } from 'node:child_process'
import { access } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { app } from 'electron'
import { z } from 'zod'
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

const nullableOptionalStringSchema = z
  .string()
  .nullable()
  .optional()
  .transform((value) => value ?? null)
const nullableOptionalNumberSchema = z
  .number()
  .nullable()
  .optional()
  .transform((value) => value ?? null)

const focusContextSchema = z.strictObject({
  role: nullableOptionalStringSchema,
  subrole: nullableOptionalStringSchema,
  editable: z.boolean(),
  secure: z.boolean(),
  x: nullableOptionalNumberSchema,
  y: nullableOptionalNumberSchema,
  width: nullableOptionalNumberSchema,
  height: nullableOptionalNumberSchema
})

const browserContextResponseSchema = z.strictObject({
  ok: z.literal(true),
  pid: z.int().positive(),
  bundleIdentifier: z.string(),
  browser: z.string(),
  url: z.string(),
  focus: focusContextSchema
})

const permissionResponseSchema = z.strictObject({
  ok: z.literal(true),
  trusted: z.boolean()
})

const fillSuccessResponseSchema = z.strictObject({
  ok: z.literal(true),
  filledUsername: z.boolean(),
  filledPassword: z.boolean()
})

const helperErrorResponseSchema = z.strictObject({
  ok: z.literal(false),
  error: z.strictObject({
    code: z.string(),
    message: z.string()
  })
})

export function resolveMacOSAutofillHelperPath(
  packaged: boolean,
  resourcesPath: string,
  appPath: string
): string {
  const bundleRoot = packaged
    ? join(dirname(resourcesPath), 'Helpers', 'BearWarden Autofill Helper.app')
    : join(appPath, 'resources', 'bin', 'BearWarden Autofill Helper.app')
  return join(bundleRoot, 'Contents', 'MacOS', 'bearwarden-macos-autofill')
}

function helperPath(): string {
  return resolveMacOSAutofillHelperPath(app.isPackaged, process.resourcesPath, app.getAppPath())
}

function parseHelperJson<T extends z.ZodType>(value: string, schema: T): z.output<T> | null {
  try {
    const result = schema.safeParse(JSON.parse(value))
    return result.success ? result.data : null
  } catch {
    return null
  }
}

function parseHelperResponse<T extends z.ZodType>(value: string, schema: T): z.output<T> {
  const parsed = parseHelperJson(value, schema)
  if (parsed === null) throw new MacOSAutofillError('INVALID_HELPER_RESPONSE')
  return parsed
}

function mapHelperError(value: string): MacOSAutofillError {
  // Parse only the bounded helper contract and never echo native stderr.
  const code = parseHelperJson(value, helperErrorResponseSchema)?.error.code ?? ''
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
  const context = parseHelperResponse(value, browserContextResponseSchema)
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
    focus: context.focus
  }
}

export class MacOSAutofillAdapter {
  async permission(prompt = false): Promise<boolean> {
    const output = await runHelper('permission', prompt ? ['--prompt'] : [])
    return parseHelperResponse(output, permissionResponseSchema).trusted
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
        const parsed = parseHelperJson(stdout, fillSuccessResponseSchema)
        finish(
          parsed === null
            ? () => reject(new MacOSAutofillError('INVALID_HELPER_RESPONSE'))
            : resolve
        )
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
