import { mkdtemp, mkdir, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  createAccountId,
  createAccountPathLayout,
  ensurePrivateDirectory,
  syncDirectory
} from './account-paths'

const ACCOUNT_ID = '11111111-1111-4111-8111-111111111111'

describe('account paths', () => {
  it('derives every account path internally from a strict v4 UUID', () => {
    const layout = createAccountPathLayout('/tmp/bearwarden-user-data')
    const account = layout.account(ACCOUNT_ID)

    expect(account.accountDirectory).toBe(
      '/tmp/bearwarden-user-data/accounts/11111111-1111-4111-8111-111111111111'
    )
    expect(account.vaultPath).toBe(join(account.accountDirectory, 'vault', 'vault.json'))
    expect(account.settingsPath).toBe(join(account.accountDirectory, 'account-settings.json'))
    expect(account.touchIdPath).toBe(join(account.accountDirectory, 'touch-id.bin'))
    expect(layout.removalJournalPath).toBe(
      '/tmp/bearwarden-user-data/accounts/.account-removal.json'
    )
    expect(layout.accountRemovalTombstone(ACCOUNT_ID, ACCOUNT_ID)).toBe(
      `/tmp/bearwarden-user-data/accounts/.removed-${ACCOUNT_ID}-${ACCOUNT_ID}`
    )
  })

  it.each([
    '../escape',
    '/absolute',
    '11111111-1111-1111-8111-111111111111',
    '11111111-1111-4111-7111-111111111111',
    '11111111-1111-4111-8111-111111111111/../../escape',
    '11111111-1111-4111-8111-111111111111\0suffix'
  ])('rejects unsafe account directory input %j', (value) => {
    const layout = createAccountPathLayout('/tmp/bearwarden-user-data')
    expect(() => layout.account(value)).toThrow('INVALID_ACCOUNT_ID')
  })

  it('validates injected UUID generators before using them in paths', () => {
    expect(() => createAccountId(() => '../escape')).toThrow('INVALID_ACCOUNT_ID')
  })

  it('rejects unsafe removal tombstone identifiers', () => {
    const layout = createAccountPathLayout('/tmp/bearwarden-user-data')
    expect(() => layout.accountRemovalTombstone(ACCOUNT_ID, '../escape')).toThrow(
      'INVALID_ACCOUNT_ID'
    )
  })

  it('fails closed when a private directory path is a symlink', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-account-paths-'))
    const outside = join(root, 'outside')
    const linked = join(root, 'accounts')
    await mkdir(outside)
    await symlink(outside, linked)

    await expect(ensurePrivateDirectory(linked)).rejects.toThrow('UNSAFE_DIRECTORY')
  })

  it('does not swallow a missing-directory durability failure', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-account-sync-directory-'))
    await expect(syncDirectory(join(root, 'missing'))).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('treats an unsupported Windows directory-open failure as a durability limitation', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-account-sync-windows-'))
    const unsupported = Object.assign(new Error('directory handles are unsupported'), {
      code: 'EPERM'
    })

    await expect(
      syncDirectory(root, {
        platform: 'win32',
        openDirectory: async () => Promise.reject(unsupported)
      })
    ).resolves.toBeUndefined()
  })

  it('does not swallow the same directory-open failure on other platforms', async () => {
    const denied = Object.assign(new Error('permission denied'), { code: 'EPERM' })

    await expect(
      syncDirectory('/private/account-data', {
        platform: 'darwin',
        openDirectory: async () => Promise.reject(denied)
      })
    ).rejects.toBe(denied)
  })

  it('does not swallow a Windows open failure when the directory path was replaced', async () => {
    const root = await mkdtemp(join(tmpdir(), 'bearwarden-account-sync-replaced-'))
    const outside = join(root, 'outside')
    const linked = join(root, 'account')
    await mkdir(outside)
    await symlink(outside, linked)
    const denied = Object.assign(new Error('permission denied'), { code: 'EPERM' })

    await expect(
      syncDirectory(linked, {
        platform: 'win32',
        openDirectory: async () => Promise.reject(denied)
      })
    ).rejects.toBe(denied)
  })
})
