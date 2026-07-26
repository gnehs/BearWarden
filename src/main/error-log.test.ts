import { mkdtemp, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, expect, it, vi } from 'vitest'
import { ErrorLogService } from './error-log'

describe('ErrorLogService', () => {
  it('writes renderer error records as append-only JSON lines', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-error-log-'))
    const log = new ErrorLogService(join(directory, 'logs', 'errors.log'), {
      now: () => new Date('2026-07-26T10:11:12.000Z')
    })

    log.recordRendererError({
      kind: 'renderer-window-error',
      message: 'Render failed',
      stack: 'Error: Render failed',
      filename: 'app://bearwarden/index.html',
      lineno: 7,
      colno: 9
    })

    const lines = (await readFile(join(directory, 'logs', 'errors.log'), 'utf8')).trim().split('\n')
    expect(lines).toHaveLength(1)
    expect(JSON.parse(lines[0]!)).toEqual({
      timestamp: '2026-07-26T10:11:12.000Z',
      process: 'renderer',
      kind: 'renderer-window-error',
      message: 'Render failed',
      stack: 'Error: Render failed',
      filename: 'app://bearwarden/index.html',
      lineno: 7,
      colno: 9
    })
  })

  it('writes main IPC errors with safe diagnostic metadata', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-error-log-'))
    const log = new ErrorLogService(join(directory, 'logs', 'errors.log'), {
      now: () => new Date('2026-07-26T10:11:12.000Z')
    })

    log.recordMainError('ipc-error', new Error('BEARWARDEN:SYNC_NETWORK'), {
      channel: 'sync:now',
      code: 'SYNC_NETWORK'
    })

    const lines = (await readFile(join(directory, 'logs', 'errors.log'), 'utf8')).trim().split('\n')
    expect(JSON.parse(lines[0]!)).toEqual({
      timestamp: '2026-07-26T10:11:12.000Z',
      process: 'main',
      kind: 'ipc-error',
      message: 'BEARWARDEN:SYNC_NETWORK',
      stack: expect.stringContaining('BEARWARDEN:SYNC_NETWORK'),
      channel: 'sync:now',
      code: 'SYNC_NETWORK'
    })
  })

  it('creates the log file before showing it in the platform file manager', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-error-log-'))
    const filePath = join(directory, 'logs', 'errors.log')
    const showItemInFolder = vi.fn()
    const log = new ErrorLogService(filePath, { showItemInFolder })

    await log.showInFileManager()

    expect(showItemInFolder).toHaveBeenCalledWith(filePath)
    await expect(readFile(filePath, 'utf8')).resolves.toBe('')
  })
})
