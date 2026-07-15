import { beforeEach, describe, expect, it, vi } from 'vitest'

const electronMock = vi.hoisted(() => ({
  handlers: new Map<string, (event: unknown, input: unknown) => Promise<unknown>>()
}))

vi.mock('electron', () => ({
  dialog: {},
  ipcMain: {
    handle: vi.fn(
      (channel: string, handler: (event: unknown, input: unknown) => Promise<unknown>) => {
        electronMock.handlers.set(channel, handler)
      }
    ),
    removeHandler: vi.fn()
  },
  Menu: { buildFromTemplate: vi.fn() }
}))

import { IPC_CHANNELS } from '../shared/vault-contract'
import type { AppSettingsService } from './app-settings'
import { VaultError } from './vault-errors'
import { registerVaultIpc, RepromptAuthorizationStore } from './vault-ipc'
import type { VaultService } from './vault-service'

beforeEach(() => electronMock.handlers.clear())

describe('RepromptAuthorizationStore', () => {
  it('binds an opaque token to sender, item, vault generation, and expiry', () => {
    let now = 1_000
    let byte = 1
    const store = new RepromptAuthorizationStore(
      () => now,
      (size) => Buffer.alloc(size, byte++)
    )
    const authorization = store.issue(7, 'item-a', 3)

    expect(authorization.token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(authorization.expiresAt).toBe(61_000)
    expect(store.validate(authorization.token, 7, 'item-a', 3)).toBe(true)
    expect(store.validate(authorization.token, 8, 'item-a', 3)).toBe(false)
    expect(store.validate(authorization.token, 7, 'item-b', 3)).toBe(false)
    expect(store.validate(authorization.token, 7, 'item-a', 4)).toBe(false)

    now = authorization.expiresAt
    expect(store.validate(authorization.token, 7, 'item-a', 3)).toBe(false)
  })

  it('invalidates every issued token when cleared', () => {
    const store = new RepromptAuthorizationStore(
      () => 0,
      (size) => Buffer.alloc(size, 9)
    )
    const authorization = store.issue(1, 'item-a', 1)
    store.clear()
    expect(store.validate(authorization.token, 1, 'item-a', 1)).toBe(false)
  })

  it.each([129, 1_001])('binds one constant-size capability to an exact %i-item set', (count) => {
    const store = new RepromptAuthorizationStore(
      () => 5_000,
      (size) => Buffer.alloc(size, 3)
    )
    const ids = Array.from(
      { length: count },
      (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`
    )
    const authorization = store.issueMany(9, ids, 4)
    expect(store.validateMany(authorization.token, 9, [...ids].reverse(), 4)).toBe(true)
    expect(store.validateMany(authorization.token, 9, ids.slice(1), 4)).toBe(false)
    expect(store.validateMany(authorization.token, 8, ids, 4)).toBe(false)
    expect(store.validateMany(authorization.token, 9, ids, 5)).toBe(false)
  })
})

describe('registerVaultIpc reprompt gate', () => {
  function harness(): {
    event: unknown
    vault: Record<string, ReturnType<typeof vi.fn>>
    portability: {
      exportVault: ReturnType<typeof vi.fn>
      importVault: ReturnType<typeof vi.fn>
    }
    setAuthorizationState: (state: { reprompt: 0 | 1; generation: number }) => void
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 7,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn()
    }
    const event = { sender: webContents, senderFrame: mainFrame }
    let authorizationState: { reprompt: 0 | 1; generation: number } = {
      reprompt: 1,
      generation: 3
    }
    const vault: Record<string, ReturnType<typeof vi.fn>> = {
      loginAuthorizationState: vi.fn(async () => authorizationState),
      authorizeLogin: vi.fn(async ({ masterPassword }: { masterPassword: string }) => {
        if (masterPassword !== 'correct horse battery staple') {
          throw new VaultError('INVALID_MASTER_PASSWORD')
        }
        return 3
      }),
      authorizeLogins: vi.fn(async () => 3),
      getLogin: vi.fn(async () => ({ id: 'item-a' })),
      getPasswordHistory: vi.fn(async () => [
        { password: 'old-secret', lastUsedDate: '2026-07-14T00:00:00.000Z' }
      ]),
      createLogin: vi.fn(async (request) => ({ id: 'created', ...request })),
      cloneLogin: vi.fn(async () => ({ id: 'clone' })),
      updateLogin: vi.fn(async () => ({ id: 'item-a' })),
      deleteLogin: vi.fn(async () => undefined),
      setLoginFavorite: vi.fn(async () => ({ id: 'item-a' })),
      moveLogin: vi.fn(async () => ({ id: 'item-a' })),
      revealSecret: vi.fn(async () => 'secret'),
      copyField: vi.fn(async () => undefined),
      revealEditorSecrets: vi.fn(async () => ({ fields: {}, customFields: [] })),
      openLoginUri: vi.fn(async () => undefined),
      generateCredential: vi.fn(async (request) => ({
        credential: 'generated-value',
        category: 'password',
        generationDate: 1,
        algorithm: 'password',
        historyLocator: {
          index: 0,
          generationDate: 1,
          category: 'password',
          algorithm: 'password'
        },
        request
      })),
      generatorHistory: vi.fn(async () => []),
      clearGeneratorHistory: vi.fn(async () => undefined),
      copyGeneratorHistory: vi.fn(async () => undefined)
    }
    vault.runAuthorizedOperation = vi.fn(
      async (
        validate: (ids: readonly string[], state: { generation: number }) => boolean,
        operation: (authorize: (ids: readonly string[]) => void) => Promise<unknown>
      ) =>
        operation((ids) => {
          if (authorizationState.reprompt === 1 && !validate(ids, authorizationState)) {
            throw new VaultError('REPROMPT_REQUIRED')
          }
        })
    )
    const portability = {
      exportVault: vi.fn(async () => ({
        canceled: false,
        exportedFolders: 1,
        exportedItems: 2,
        skippedTrashItems: 1
      })),
      importVault: vi.fn(async () => ({
        canceled: false,
        importedFolders: 1,
        importedItems: 2,
        skippedTrashItems: 0
      }))
    }
    registerVaultIpc({
      vault: vault as unknown as VaultService,
      portability: portability as unknown as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      getMainWindow: () =>
        ({ isDestroyed: () => false, webContents }) as unknown as ReturnType<
          Parameters<typeof registerVaultIpc>[0]['getMainWindow']
        >,
      repromptNow: () => 1_000,
      repromptRandomBytes: (size) => Buffer.alloc(size, 5)
    })
    return {
      event,
      vault,
      portability,
      setAuthorizationState: (state) => {
        authorizationState = state
      }
    }
  }

  it('keeps portability IPC path-free, exact, and password-proof scoped', async () => {
    const { event, portability } = harness()
    const exportVault = electronMock.handlers.get(IPC_CHANNELS.vaultExport)!
    const importVault = electronMock.handlers.get(IPC_CHANNELS.vaultImport)!
    await expect(
      exportVault(event, {
        masterPassword: 'correct horse battery staple',
        password: 'portable backup password'
      })
    ).resolves.toMatchObject({ exportedItems: 2 })
    expect(portability.exportVault).toHaveBeenCalledWith({
      masterPassword: 'correct horse battery staple',
      password: 'portable backup password'
    })
    await expect(
      importVault(event, {
        masterPassword: 'correct horse battery staple',
        password: 'portable backup password'
      })
    ).resolves.toMatchObject({ importedItems: 2 })

    for (const invalid of [
      { password: 'portable backup password' },
      { masterPassword: 'correct horse battery staple' },
      {
        masterPassword: 'correct horse battery staple',
        password: 'portable backup password',
        path: '/tmp/renderer-controlled.json'
      }
    ]) {
      await expect(exportVault(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    await expect(
      importVault(event, {
        masterPassword: 'correct horse battery staple',
        password: 123
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
  })

  it.each([
    [IPC_CHANNELS.loginGet, 'getLogin', { id: 'item-a' }],
    [IPC_CHANNELS.loginGetPasswordHistory, 'getPasswordHistory', { id: 'item-a' }],
    [IPC_CHANNELS.loginClone, 'cloneLogin', { id: 'item-a' }],
    [IPC_CHANNELS.loginUpdate, 'updateLogin', { id: 'item-a', name: 'Updated' }],
    [IPC_CHANNELS.loginDelete, 'deleteLogin', { id: 'item-a' }],
    [IPC_CHANNELS.loginSetFavorite, 'setLoginFavorite', { id: 'item-a', favorite: true }],
    [IPC_CHANNELS.loginMove, 'moveLogin', { id: 'item-a', folderId: null }],
    [IPC_CHANNELS.itemRevealSecret, 'revealSecret', { id: 'item-a', field: 'password' }],
    [
      IPC_CHANNELS.itemRevealEditorSecrets,
      'revealEditorSecrets',
      { id: 'item-a', expectedUpdatedAt: '2026-07-16T00:00:00.000Z' }
    ],
    [IPC_CHANNELS.loginOpenUri, 'openLoginUri', { id: 'item-a' }]
  ])('blocks %s before invoking %s without an item token', async (channel, method, input) => {
    const { event, vault } = harness()
    await expect(electronMock.handlers.get(channel)!(event, input)).rejects.toThrow(
      'BEARWARDEN:REPROMPT_REQUIRED'
    )
    expect(vault[method]).not.toHaveBeenCalled()
  })

  it('issues proof only after password verification and rejects wrong item or epoch', async () => {
    const { event, setAuthorizationState } = harness()
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    await expect(
      authorize(event, { id: 'item-a', masterPassword: 'wrong password' })
    ).rejects.toThrow('BEARWARDEN:INVALID_MASTER_PASSWORD')

    const authorization = (await authorize(event, {
      id: 'item-a',
      masterPassword: 'correct horse battery staple'
    })) as { token: string }
    const get = electronMock.handlers.get(IPC_CHANNELS.loginGet)!
    const getHistory = electronMock.handlers.get(IPC_CHANNELS.loginGetPasswordHistory)!
    await expect(
      get(event, { id: 'item-a', authorizationToken: authorization.token })
    ).resolves.toEqual({ id: 'item-a' })

    await expect(
      get(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getHistory(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    setAuthorizationState({ reprompt: 1, generation: 4 })
    await expect(
      get(event, { id: 'item-a', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getHistory(event, { id: 'item-a', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
  })

  it('uses a narrow exact history request and propagates the trash rejection', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const getHistory = electronMock.handlers.get(IPC_CHANNELS.loginGetPasswordHistory)!
    await expect(getHistory(event, { id: 'item-a', future: true })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    vault.getPasswordHistory.mockRejectedValueOnce(new VaultError('INVALID_INPUT'))
    await expect(getHistory(event, { id: 'item-a' })).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
  })

  it.each([
    [
      { algorithm: 'password', options: { length: 20, minNumber: 2 } },
      { algorithm: 'password', options: { length: 20, minNumber: 2 } }
    ],
    [
      { algorithm: 'passphrase', options: { wordCount: 8, separator: ' ', capitalize: true } },
      { algorithm: 'passphrase', options: { wordCount: 8, separator: ' ', capitalize: true } }
    ],
    [
      { algorithm: 'username', options: { includeNumber: true } },
      { algorithm: 'username', options: { includeNumber: true } }
    ],
    [
      { algorithm: 'subaddress', email: 'bear@example.invalid' },
      { algorithm: 'subaddress', email: 'bear@example.invalid' }
    ],
    [
      { algorithm: 'catchall', domain: 'example.invalid' },
      { algorithm: 'catchall', domain: 'example.invalid' }
    ]
  ])('parses an exact generator request %#', async (input, expected) => {
    const { event, vault } = harness()
    const generate = electronMock.handlers.get(IPC_CHANNELS.generatorGenerate)!
    await generate(event, input)
    expect(vault.generateCredential).toHaveBeenLastCalledWith(expected)
  })

  it.each([
    { algorithm: 'password', options: { length: 4 } },
    { algorithm: 'password', options: { minNumber: 10 } },
    { algorithm: 'password', options: { future: true } },
    { algorithm: 'password', options: {}, email: 'bear@example.invalid' },
    { algorithm: 'passphrase', options: { separator: '🙂' } },
    { algorithm: 'username', options: { includeNumber: 'yes' } },
    { algorithm: 'subaddress', email: 'x'.repeat(255) },
    { algorithm: 'catchall', domain: 'x'.repeat(255) },
    { algorithm: 'forwarder', options: {} }
  ])('rejects an oversized or non-exact generator request %#', async (input) => {
    const { event, vault } = harness()
    const generate = electronMock.handlers.get(IPC_CHANNELS.generatorGenerate)!
    await expect(generate(event, input)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(vault.generateCredential).not.toHaveBeenCalled()
  })

  it('keeps generator history IPC narrow and rejects stale-shaped copy locators', async () => {
    const { event, vault } = harness()
    const history = electronMock.handlers.get(IPC_CHANNELS.generatorHistoryList)!
    const clear = electronMock.handlers.get(IPC_CHANNELS.generatorHistoryClear)!
    const copy = electronMock.handlers.get(IPC_CHANNELS.generatorHistoryCopy)!
    await expect(history(event, undefined)).resolves.toEqual([])
    await expect(clear(event, undefined)).resolves.toBeUndefined()
    await copy(event, {
      index: 0,
      generationDate: 1,
      category: 'password',
      algorithm: 'password'
    })
    expect(vault.copyGeneratorHistory).toHaveBeenCalledWith({
      index: 0,
      generationDate: 1,
      category: 'password',
      algorithm: 'password'
    })
    for (const invalid of [
      { index: 200, generationDate: 1, category: 'password', algorithm: 'password' },
      {
        index: 0,
        generationDate: 1,
        category: 'password',
        algorithm: 'password',
        credential: 'renderer-secret'
      },
      { index: 0, generationDate: 1, category: 'password', algorithm: 'future' }
    ]) {
      await expect(copy(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    await expect(history(event, {})).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(clear(event, {})).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
  })

  it('parses ordered URI match rows and indexed copy/open requests', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const create = electronMock.handlers.get(IPC_CHANNELS.loginCreate)!
    await create(event, {
      name: 'Multiple URIs',
      uri: 'https://primary.example.invalid',
      uris: [
        { uri: 'https://primary.example.invalid', match: null },
        { uri: '^https://secondary\\.example\\.invalid/', match: 4 }
      ]
    })
    expect(vault.createLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        uris: [
          { uri: 'https://primary.example.invalid', match: null },
          { uri: '^https://secondary\\.example\\.invalid/', match: 4 }
        ]
      })
    )

    const copy = electronMock.handlers.get(IPC_CHANNELS.itemCopyField)!
    await copy(event, { id: 'item-a', field: 'uri', uriIndex: 1, authorizationToken: 'token' })
    expect(vault.copyField).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'item-a', field: 'uri', uriIndex: 1 })
    )
    const open = electronMock.handlers.get(IPC_CHANNELS.loginOpenUri)!
    await open(event, { id: 'item-a', uriIndex: 1, authorizationToken: 'token' })
    expect(vault.openLoginUri).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'item-a', uriIndex: 1 })
    )
    await expect(
      create(event, { name: 'Invalid match', uris: [{ uri: 'x', match: 6 }] })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
  })

  it('issues one batch capability for 1,001 validated item IDs', async () => {
    const { event, vault } = harness()
    const ids = Array.from(
      { length: 1_001 },
      (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`
    )
    const authorizeMany = electronMock.handlers.get(IPC_CHANNELS.loginAuthorizeMany)!
    await expect(
      authorizeMany(event, { ids, masterPassword: 'correct horse battery staple' })
    ).resolves.toMatchObject({ token: expect.any(String), expiresAt: 61_000 })
    expect(vault.authorizeLogins).toHaveBeenCalledWith({
      ids,
      masterPassword: 'correct horse battery staple'
    })
  })
})
