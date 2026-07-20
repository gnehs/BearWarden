import { chmod, lstat, mkdir, mkdtemp, rm, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it } from 'vitest'
import { prepareDevelopmentUserData } from './development-user-data'

describe('prepareDevelopmentUserData', () => {
  const directories: string[] = []

  afterEach(async () => {
    await Promise.all(
      directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))
    )
  })

  it('creates a private directory and repairs an existing permissive mode', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-development-user-data-'))
    directories.push(root)
    const target = join(root, 'data')
    await mkdir(target, { mode: 0o755 })
    if (process.platform !== 'win32') await chmod(target, 0o755)

    prepareDevelopmentUserData(target)

    const metadata = await lstat(target)
    expect(metadata.isDirectory()).toBe(true)
    if (process.platform !== 'win32') expect(metadata.mode & 0o777).toBe(0o700)
  })

  it('rejects a pre-existing symlink', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-development-user-data-'))
    directories.push(root)
    const target = join(root, 'data')
    await symlink(root, target, process.platform === 'win32' ? 'junction' : 'dir')

    expect(() => prepareDevelopmentUserData(target)).toThrow('UNSAFE_DEVELOPMENT_USER_DATA')
  })
})
