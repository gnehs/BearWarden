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

import { IPC_CHANNELS, IPC_EVENTS } from '../shared/vault-contract'
import type { AppSettingsService } from './app-settings'
import { VaultError } from './vault-errors'
import { registerVaultIpc, RepromptAuthorizationStore } from './vault-ipc'
import type { VaultService } from './vault-service'
import { SshKeyImportSessionStore } from './ssh-key-import-session'
import { SshKeyImportError } from './ssh-key-import'

beforeEach(() => electronMock.handlers.clear())

describe('registerVaultIpc settings validation', () => {
  function settingsHarness(): {
    event: unknown
    settings: { update: ReturnType<typeof vi.fn> }
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 91,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    const settings = { update: vi.fn(async (update) => update), get: vi.fn() }
    registerVaultIpc({
      vault: {} as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: settings as unknown as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () =>
        ({ isDestroyed: () => false, webContents }) as unknown as ReturnType<
          Parameters<typeof registerVaultIpc>[0]['getMainWindow']
        >
    })
    return { event: { sender: webContents, senderFrame: mainFrame }, settings }
  }

  it('whitelists and validates SSH agent settings before they reach persistence', async () => {
    const { event, settings } = settingsHarness()
    const update = electronMock.handlers.get(IPC_CHANNELS.settingsUpdate)!

    await expect(
      update(event, { sshAgentEnabled: true, sshAgentPromptBehavior: 'rememberUntilLock' })
    ).resolves.toEqual({ sshAgentEnabled: true, sshAgentPromptBehavior: 'rememberUntilLock' })
    expect(settings.update).toHaveBeenCalledWith({
      sshAgentEnabled: true,
      sshAgentPromptBehavior: 'rememberUntilLock'
    })

    for (const invalid of [
      { sshAgentEnabled: 'true' },
      { sshAgentPromptBehavior: 'ask-every-time' },
      { sshAgentPromptBehavior: null },
      { sshAgentEnabled: true, privateKey: 'must-not-be-accepted' }
    ]) {
      await expect(update(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(settings.update).toHaveBeenCalledTimes(1)
  })
})

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

describe('registerVaultIpc shared main-process hooks', () => {
  function registerHarness(options: {
    vault: Partial<VaultService>
    repromptAuthorizations?: RepromptAuthorizationStore
    afterSetup?: () => void | Promise<void>
  }): { event: unknown } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 73,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    registerVaultIpc({
      vault: options.vault as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () => ({ isDestroyed: () => false, webContents }) as never,
      ...(options.repromptAuthorizations === undefined
        ? {}
        : { repromptAuthorizations: options.repromptAuthorizations }),
      ...(options.afterSetup === undefined ? {} : { afterSetup: options.afterSetup })
    })
    return { event: { sender: webContents, senderFrame: mainFrame } }
  }

  it('issues renderer reprompt capabilities from the injected store', async () => {
    const itemId = '00000000-0000-4000-8000-000000000001'
    const store = new RepromptAuthorizationStore(
      () => 2_000,
      (size) => Buffer.alloc(size, 4)
    )
    const { event } = registerHarness({
      vault: { authorizeLogin: vi.fn().mockResolvedValue(9) },
      repromptAuthorizations: store
    })
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    const result = (await authorize(event, { id: itemId, masterPassword: 'test-only' })) as {
      token: string
    }
    expect(store.validate(result.token, 73, itemId, 9)).toBe(true)
  })

  it('runs the successful setup hook without turning auxiliary failures into setup failures', async () => {
    const afterSetup = vi.fn().mockRejectedValue(new Error('agent unavailable'))
    const setup = vi.fn().mockResolvedValue({ state: 'unlocked' })
    const { event } = registerHarness({ vault: { setup }, afterSetup })
    await expect(
      electronMock.handlers.get(IPC_CHANNELS.vaultSetup)!(event, { masterPassword: 'test-only' })
    ).resolves.toEqual({ state: 'unlocked' })
    expect(setup).toHaveBeenCalledWith('test-only')
    expect(afterSetup).toHaveBeenCalledOnce()
  })
})

describe('registerVaultIpc reprompt gate', () => {
  const operationId = '70000000-0000-4000-8000-000000000001'
  function harness(): {
    event: unknown
    vault: Record<string, ReturnType<typeof vi.fn>>
    portability: {
      exportVault: ReturnType<typeof vi.fn>
      importVault: ReturnType<typeof vi.fn>
    }
    afterMutation: ReturnType<typeof vi.fn>
    setAuthorizationState: (state: { reprompt: 0 | 1; generation: number }) => void
  } {
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 7,
      mainFrame,
      getURL: () => mainFrame.url,
      send: vi.fn(),
      isDestroyed: () => false
    }
    const event = { sender: webContents, senderFrame: mainFrame }
    let authorizationState: { reprompt: 0 | 1; generation: number } = {
      reprompt: 1,
      generation: 3
    }
    const requireAttachmentAuthorization = (
      request: { id: string },
      validate?: (ids: readonly string[], state: { generation: number }) => boolean
    ): void => {
      if (
        authorizationState.reprompt === 1 &&
        !validate?.([request.id], { generation: authorizationState.generation })
      ) {
        throw new VaultError('REPROMPT_REQUIRED')
      }
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
      downloadAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return { canceled: false, fileName: 'document.txt' }
      }),
      uploadAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return {
          canceled: false,
          attachment: {
            id: 'new-attachment',
            fileName: 'upload.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        }
      }),
      deleteAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return { attachmentId: 'attachment-a' }
      }),
      fixLegacyAttachment: vi.fn(async (request, _report, validate) => {
        requireAttachmentAuthorization(request, validate)
        return {
          attachment: {
            id: 'fixed-attachment',
            fileName: 'legacy.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        }
      }),
      cancelAttachmentOperation: vi.fn(async () => ({ canceled: true })),
      createLogin: vi.fn(async (request) => ({ id: 'created', ...request })),
      cloneLogin: vi.fn(async () => ({ id: 'clone' })),
      archiveLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.map((id) => ({ id }))),
      unarchiveLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.map((id) => ({ id }))),
      deleteLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.length),
      restoreLogins: vi.fn(async ({ ids }: { ids: string[] }) => ids.map((id) => ({ id }))),
      deleteLoginsPermanently: vi.fn(async ({ ids }: { ids: string[] }) => ids.length),
      updateLogin: vi.fn(async () => ({ id: 'item-a' })),
      deleteLogin: vi.fn(async () => undefined),
      setLoginFavorite: vi.fn(async () => ({ id: 'item-a' })),
      moveLogin: vi.fn(async () => ({ id: 'item-a' })),
      getTotp: vi.fn(async () => ({ code: '123456', period: 30, remainingSeconds: 12 })),
      copyTotp: vi.fn(async () => undefined),
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
      generateSshKey: vi.fn(async () => ({
        privateKey: 'private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:fingerprint'
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
    vault.unlockedGeneration = vi.fn(async () => authorizationState.generation)
    vault.runUnlockedOperation = vi.fn(async (operation: (generation: number) => unknown) =>
      operation(authorizationState.generation)
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
    const afterMutation = vi.fn()
    registerVaultIpc({
      vault: vault as unknown as VaultService,
      portability: portability as unknown as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      sshKeyImportSessions: new SshKeyImportSessionStore({ readClipboard: () => '' }),
      getMainWindow: () =>
        ({ isDestroyed: () => false, webContents }) as unknown as ReturnType<
          Parameters<typeof registerVaultIpc>[0]['getMainWindow']
        >,
      repromptNow: () => 1_000,
      repromptRandomBytes: (size) => Buffer.alloc(size, 5),
      afterMutation
    })
    return {
      event,
      vault,
      portability,
      afterMutation,
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
    [IPC_CHANNELS.loginGetTotp, 'getTotp', { id: 'item-a' }],
    [IPC_CHANNELS.loginCopyTotp, 'copyTotp', { id: 'item-a' }],
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

  it.each([
    [
      IPC_CHANNELS.attachmentDownload,
      'downloadAttachment',
      { id: 'item-a', attachmentId: 'attachment-a', operationId }
    ],
    [IPC_CHANNELS.attachmentUpload, 'uploadAttachment', { id: 'item-a', operationId }],
    [
      IPC_CHANNELS.attachmentDelete,
      'deleteAttachment',
      { id: 'item-a', attachmentId: 'attachment-a', operationId }
    ],
    [
      IPC_CHANNELS.attachmentFixLegacy,
      'fixLegacyAttachment',
      { id: 'item-a', attachmentId: 'attachment-a', operationId }
    ]
  ])(
    'lets the attachment service reject %s without holding the IPC authorization mutex',
    async (channel, method, input) => {
      const { event, vault } = harness()
      await expect(electronMock.handlers.get(channel)!(event, input)).rejects.toThrow(
        'BEARWARDEN:REPROMPT_REQUIRED'
      )
      expect(vault[method]).toHaveBeenCalledWith(input, expect.any(Function), expect.any(Function))
      expect(vault.runAuthorizedOperation).not.toHaveBeenCalled()
    }
  )

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
    const getTotp = electronMock.handlers.get(IPC_CHANNELS.loginGetTotp)!
    const copyTotp = electronMock.handlers.get(IPC_CHANNELS.loginCopyTotp)!
    await expect(
      get(event, { id: 'item-a', authorizationToken: authorization.token })
    ).resolves.toEqual({ id: 'item-a' })
    await expect(
      getTotp(event, { id: 'item-a', authorizationToken: authorization.token })
    ).resolves.toEqual({ code: '123456', period: 30, remainingSeconds: 12 })
    await expect(
      copyTotp(event, { id: 'item-a', authorizationToken: authorization.token })
    ).resolves.toBeUndefined()

    await expect(
      get(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getHistory(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getTotp(event, { id: 'item-b', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    setAuthorizationState({ reprompt: 1, generation: 4 })
    await expect(
      get(event, { id: 'item-a', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
    await expect(
      getHistory(event, { id: 'item-a', authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
  })

  it('accepts only narrow exact TOTP requests', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    for (const [channel, method] of [
      [IPC_CHANNELS.loginGetTotp, 'getTotp'],
      [IPC_CHANNELS.loginCopyTotp, 'copyTotp']
    ] as const) {
      const handler = electronMock.handlers.get(channel)!
      await expect(handler(event, { id: 'item-a', extra: true })).rejects.toThrow(
        'BEARWARDEN:INVALID_INPUT'
      )
      expect(vault[method]).not.toHaveBeenCalled()
      await handler(event, { id: 'item-a' })
      expect(vault[method]).toHaveBeenCalledOnce()
      expect(vault[method]).toHaveBeenCalledWith({ id: 'item-a' })
    }
  })

  const batchOperations = [
    [IPC_CHANNELS.loginArchiveMany, 'archiveLogins'],
    [IPC_CHANNELS.loginUnarchiveMany, 'unarchiveLogins'],
    [IPC_CHANNELS.loginDeleteMany, 'deleteLogins'],
    [IPC_CHANNELS.loginRestoreMany, 'restoreLogins'],
    [IPC_CHANNELS.loginDeletePermanentlyMany, 'deleteLoginsPermanently']
  ] as const
  const batchIds = ['10000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002']

  it.each(batchOperations)(
    'binds %s to the exact batch set and invokes %s only once',
    async (channel, method) => {
      const { event, vault, afterMutation } = harness()
      const authorization = (await electronMock.handlers.get(IPC_CHANNELS.loginAuthorizeMany)!(
        event,
        { ids: batchIds, masterPassword: 'correct horse battery staple' }
      )) as { token: string }
      const handler = electronMock.handlers.get(channel)!
      const request = {
        ids: [...batchIds].reverse(),
        authorizationToken: authorization.token
      }

      await expect(handler(event, request)).resolves.toBeDefined()
      expect(vault[method]).toHaveBeenCalledTimes(1)
      expect(vault[method]).toHaveBeenCalledWith(request)
      expect(afterMutation).toHaveBeenCalledTimes(1)

      await expect(
        handler(event, {
          ids: [batchIds[0], '10000000-0000-4000-8000-000000000003'],
          authorizationToken: authorization.token
        })
      ).rejects.toThrow('BEARWARDEN:REPROMPT_REQUIRED')
      expect(vault[method]).toHaveBeenCalledTimes(1)
      expect(afterMutation).toHaveBeenCalledTimes(1)
    }
  )

  it.each(batchOperations)(
    'blocks protected %s before invoking %s without a batch token',
    async (channel, method) => {
      const { event, vault } = harness()
      await expect(electronMock.handlers.get(channel)!(event, { ids: batchIds })).rejects.toThrow(
        'BEARWARDEN:REPROMPT_REQUIRED'
      )
      expect(vault[method]).not.toHaveBeenCalled()
    }
  )

  it.each(batchOperations)(
    'rejects malformed exact batch requests on %s',
    async (channel, method) => {
      const { event, vault, setAuthorizationState } = harness()
      setAuthorizationState({ reprompt: 0, generation: 3 })
      const ids501 = Array.from(
        { length: 501 },
        (_, index) => `20000000-0000-4000-8000-${String(index).padStart(12, '0')}`
      )
      const handler = electronMock.handlers.get(channel)!
      for (const invalid of [
        { ids: [] },
        { ids: ids501 },
        { ids: [batchIds[0], batchIds[0]] },
        { ids: ['not-a-uuid'] },
        { ids: batchIds, extra: true }
      ]) {
        await expect(handler(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
      }
      expect(vault[method]).not.toHaveBeenCalled()
    }
  )

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

  it('keeps attachment download paths out of renderer IPC', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const download = electronMock.handlers.get(IPC_CHANNELS.attachmentDownload)!
    await expect(
      download(event, {
        id: 'item-a',
        attachmentId: 'attachment-a',
        operationId,
        path: '/tmp/renderer-controlled.txt'
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    await expect(
      download(event, { id: 'item-a', attachmentId: 'attachment-a', operationId })
    ).resolves.toEqual({ canceled: false, fileName: 'document.txt' })
    expect(vault.downloadAttachment).toHaveBeenCalledWith(
      { id: 'item-a', attachmentId: 'attachment-a', operationId },
      expect.any(Function),
      expect.any(Function)
    )
  })

  it('forwards only structured attachment progress to the invoking renderer', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const progress = {
      operationId,
      itemId: 'item-a',
      kind: 'download' as const,
      stage: 'downloading' as const,
      completedBytes: 6,
      totalBytes: 12
    }
    vault.downloadAttachment.mockImplementation(async (_request, report) => {
      report(progress)
      return { canceled: false, fileName: 'document.txt' }
    })

    await expect(
      electronMock.handlers.get(IPC_CHANNELS.attachmentDownload)!(event, {
        id: 'item-a',
        attachmentId: 'attachment-a',
        operationId
      })
    ).resolves.toEqual({ canceled: false, fileName: 'document.txt' })
    expect(
      (event as { sender: { send: ReturnType<typeof vi.fn> } }).sender.send
    ).toHaveBeenCalledWith(IPC_EVENTS.attachmentProgress, progress)
  })

  it('keeps upload paths, bytes, names, and sizes out of renderer IPC', async () => {
    const { event, vault, setAuthorizationState } = harness()
    setAuthorizationState({ reprompt: 0, generation: 3 })
    const upload = electronMock.handlers.get(IPC_CHANNELS.attachmentUpload)!
    for (const forbidden of [
      { path: '/tmp/private.txt' },
      { bytes: [1, 2, 3] },
      { fileName: 'private.txt' },
      { size: 3 }
    ]) {
      await expect(upload(event, { id: 'item-a', operationId, ...forbidden })).rejects.toThrow(
        'BEARWARDEN:INVALID_INPUT'
      )
    }
    await expect(upload(event, { id: 'item-a', operationId })).resolves.toMatchObject({
      canceled: false,
      attachment: { fileName: 'upload.txt' }
    })
    expect(vault.uploadAttachment).toHaveBeenCalledWith(
      { id: 'item-a', operationId },
      expect.any(Function),
      expect.any(Function)
    )
  })

  it('validates operation ids and exposes cancel only to the trusted exact channel', async () => {
    const { event, vault } = harness()
    const cancel = electronMock.handlers.get(IPC_CHANNELS.attachmentCancel)!
    await expect(cancel(event, { operationId: 'not-a-uuid' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    await expect(cancel(event, { operationId, extra: true })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    await expect(cancel(event, { operationId })).resolves.toEqual({ canceled: true })
    expect(vault.cancelAttachmentOperation).toHaveBeenCalledWith({ operationId })
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

  it('stages generated SSH private material in main and returns only a one-time handle', async () => {
    const { event, vault } = harness()
    const generate = electronMock.handlers.get(IPC_CHANNELS.sshKeyGenerate)!
    const create = electronMock.handlers.get(IPC_CHANNELS.sshKeyCreateImported)!

    const ready = await generate(event, undefined)
    expect(ready).toEqual({
      status: 'ready',
      token: expect.any(String),
      expiresAt: expect.any(Number),
      publicKey: 'ssh-ed25519 public-key',
      fingerprint: 'SHA256:fingerprint'
    })
    expect(JSON.stringify(ready)).not.toContain('private-key')
    expect(vault.generateSshKey).toHaveBeenCalledOnce()

    await expect(
      create(event, { name: 'Generated key', importToken: (ready as { token: string }).token })
    ).resolves.toMatchObject({ id: 'created', type: 'sshKey' })
    expect(vault.createLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        privateKey: 'private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:fingerprint'
      })
    )
    await expect(
      create(event, { name: 'Replay', importToken: (ready as { token: string }).token })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    await expect(
      generate(
        {
          ...(event as Record<string, unknown>),
          senderFrame: { url: 'https://untrusted.example.invalid' }
        },
        undefined
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')

    for (const invalid of [null, {}, { algorithm: 'ED25519' }]) {
      await expect(generate(event, invalid)).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    }
    expect(vault.generateSshKey).toHaveBeenCalledOnce()
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

describe('registerVaultIpc SSH clipboard imports', () => {
  function harness(): {
    event: { sender: { id: number }; senderFrame: { url: string } }
    secondEvent: { sender: { id: number }; senderFrame: { url: string } }
    useSecondSender: () => void
    vault: Record<string, ReturnType<typeof vi.fn>>
    setGeneration: (generation: number) => void
    setTargetType: (type: 'login' | 'sshKey') => void
    reads: () => number
    beforeLock: ReturnType<typeof vi.fn>
    afterMutation: ReturnType<typeof vi.fn>
  } {
    let reads = 0
    let generation = 9
    let targetType: 'login' | 'sshKey' = 'sshKey'
    let currentWindow: { isDestroyed: () => boolean; webContents: unknown }
    const mainFrame = { url: 'app://bearwarden/index.html' }
    const webContents = {
      id: 17,
      mainFrame,
      getURL: () => mainFrame.url,
      isDestroyed: () => false
    }
    const secondFrame = { url: 'app://bearwarden/index.html' }
    const secondWebContents = {
      id: 18,
      mainFrame: secondFrame,
      getURL: () => secondFrame.url,
      isDestroyed: () => false
    }
    currentWindow = { isDestroyed: () => false, webContents }
    const event = { sender: webContents, senderFrame: mainFrame }
    const secondEvent = { sender: secondWebContents, senderFrame: secondFrame }
    const sessions = new SshKeyImportSessionStore({
      readClipboard: () => {
        reads += 1
        return 'encrypted'
      },
      parser: {
        importSshKey: (key, password) => {
          if (key.toString('utf8') !== 'encrypted') throw new SshKeyImportError('ParsingError')
          if (!password) throw new SshKeyImportError('PasswordRequired')
          if (password.toString('utf8') !== 'correct passphrase') {
            throw new SshKeyImportError('WrongPassword')
          }
          return {
            privateKey: 'main-process-private-key',
            publicKey: 'ssh-ed25519 public-key',
            fingerprint: 'SHA256:main-process-fingerprint'
          }
        }
      }
    })
    const vault: Record<string, ReturnType<typeof vi.fn>> = {
      unlockedGeneration: vi.fn(async () => generation),
      runUnlockedOperation: vi.fn(async (operation) => operation(generation)),
      authorizeLogin: vi.fn(async () => generation),
      getLogin: vi.fn(async () => ({ type: targetType })),
      runAuthorizedOperation: vi.fn(async (validate, operation) =>
        operation((ids: readonly string[]) => {
          if (!validate(ids, { generation })) throw new VaultError('REPROMPT_REQUIRED')
        })
      ),
      createLogin: vi.fn(async (request) => ({
        id: 'created',
        type: request.type,
        publicKey: request.publicKey,
        fingerprint: request.fingerprint
      })),
      updateLogin: vi.fn(async (request) => ({
        id: request.id,
        type: 'sshKey',
        publicKey: request.publicKey,
        fingerprint: request.fingerprint
      })),
      lock: vi.fn(async () => ({ state: 'locked' }))
    }
    const beforeLock = vi.fn(() => sessions.clearAll())
    const afterMutation = vi.fn()
    registerVaultIpc({
      vault: vault as unknown as VaultService,
      portability: {} as Parameters<typeof registerVaultIpc>[0]['portability'],
      settings: {} as AppSettingsService,
      getMainWindow: () => currentWindow as never,
      sshKeyImportSessions: sessions,
      beforeLock,
      afterMutation,
      repromptNow: () => 1_000,
      repromptRandomBytes: (size) => Buffer.alloc(size, 1)
    })
    return {
      event,
      secondEvent,
      useSecondSender: () => {
        currentWindow = { isDestroyed: () => false, webContents: secondWebContents }
      },
      vault,
      setGeneration: (next) => {
        generation = next
      },
      setTargetType: (type) => {
        targetType = type
      },
      reads: () => reads,
      beforeLock,
      afterMutation
    }
  }

  it('reads the clipboard once and never returns imported private material to the renderer', async () => {
    const { event, reads, vault, afterMutation } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const create = electronMock.handlers.get(IPC_CHANNELS.sshKeyCreateImported)!

    await expect(
      begin(
        {
          ...(event as Record<string, unknown>),
          senderFrame: { url: 'https://untrusted.example.invalid' }
        },
        undefined
      )
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(reads()).toBe(0)

    const awaiting = (await begin(event, undefined)) as { status: string; token: string }
    expect(reads()).toBe(1)
    expect(awaiting).toMatchObject({ status: 'awaitingPassphrase' })
    expect(awaiting).not.toHaveProperty('privateKey')

    await expect(
      submit(event, { token: awaiting.token, passphrase: 'incorrect passphrase' })
    ).resolves.toEqual({ status: 'error', code: 'WrongPassword' })
    const ready = (await submit(event, {
      token: awaiting.token,
      passphrase: 'correct passphrase'
    })) as { status: string; token: string; publicKey: string; fingerprint: string }
    expect(ready).toMatchObject({
      status: 'ready',
      publicKey: 'ssh-ed25519 public-key',
      fingerprint: 'SHA256:main-process-fingerprint'
    })
    expect(ready).not.toHaveProperty('privateKey')

    const created = await create(event, {
      importToken: ready.token,
      name: 'Imported SSH key',
      type: 'login',
      privateKey: 'renderer-controlled-private-key',
      publicKey: 'renderer-controlled-public-key',
      fingerprint: 'renderer-controlled-fingerprint'
    })
    expect(vault.createLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'sshKey',
        privateKey: 'main-process-private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:main-process-fingerprint'
      })
    )
    expect(created).not.toHaveProperty('privateKey')
    expect(afterMutation).toHaveBeenCalledTimes(1)
    await expect(create(event, { importToken: ready.token, name: 'Again' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
  })

  it('strictly validates passphrases and binds sessions to the trusted sender and vault generation', async () => {
    const { event, secondEvent, useSecondSender, setGeneration } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const awaiting = (await begin(event, undefined)) as { token: string }

    await expect(submit(event, { token: awaiting.token, passphrase: '' })).rejects.toThrow(
      'BEARWARDEN:INVALID_INPUT'
    )
    useSecondSender()
    await expect(
      submit(secondEvent, { token: awaiting.token, passphrase: 'correct passphrase' })
    ).resolves.toEqual({ status: 'error', code: 'SessionUnavailable' })

    const next = (await begin(secondEvent, undefined)) as { token: string }
    setGeneration(10)
    await expect(
      submit(secondEvent, { token: next.token, passphrase: 'correct passphrase' })
    ).resolves.toEqual({ status: 'error', code: 'SessionUnavailable' })
  })

  it('clears import sessions before locking and keeps update reprompt authorization and mutation sync', async () => {
    const { event, vault, beforeLock, afterMutation } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const lock = electronMock.handlers.get(IPC_CHANNELS.vaultLock)!
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    const update = electronMock.handlers.get(IPC_CHANNELS.sshKeyUpdateImported)!

    const awaiting = (await begin(event, undefined)) as { token: string }
    const ready = (await submit(event, {
      token: awaiting.token,
      passphrase: 'correct passphrase'
    })) as { token: string }
    const authorization = (await authorize(event, {
      id: '70000000-0000-4000-8000-000000000001',
      masterPassword: 'correct horse battery staple'
    })) as { token: string }
    await expect(
      update(event, {
        id: '70000000-0000-4000-8000-000000000001',
        importToken: ready.token,
        authorizationToken: authorization.token,
        expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
      })
    ).resolves.toMatchObject({ type: 'sshKey' })
    expect(vault.updateLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        privateKey: 'main-process-private-key',
        publicKey: 'ssh-ed25519 public-key',
        fingerprint: 'SHA256:main-process-fingerprint'
      })
    )
    expect(afterMutation).toHaveBeenCalledTimes(1)

    const secondAwaiting = (await begin(event, undefined)) as { token: string }
    const secondReady = (await submit(event, {
      token: secondAwaiting.token,
      passphrase: 'correct passphrase'
    })) as { token: string }
    await lock(event, undefined)
    expect(beforeLock).toHaveBeenCalledTimes(1)
    const authorizationAfterLock = (await authorize(event, {
      id: '70000000-0000-4000-8000-000000000001',
      masterPassword: 'correct horse battery staple'
    })) as { token: string }
    await expect(
      update(event, {
        id: '70000000-0000-4000-8000-000000000001',
        importToken: secondReady.token,
        authorizationToken: authorizationAfterLock.token,
        expectedUpdatedAt: '2026-07-16T00:00:00.000Z'
      })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(vault.updateLogin).toHaveBeenCalledTimes(1)
    expect(afterMutation).toHaveBeenCalledTimes(1)
  })

  it('rejects a non-SSH update before consuming the imported token', async () => {
    const { event, setTargetType, afterMutation } = harness()
    const begin = electronMock.handlers.get(IPC_CHANNELS.sshKeyBeginImport)!
    const submit = electronMock.handlers.get(IPC_CHANNELS.sshKeySubmitImportPassphrase)!
    const authorize = electronMock.handlers.get(IPC_CHANNELS.loginAuthorize)!
    const update = electronMock.handlers.get(IPC_CHANNELS.sshKeyUpdateImported)!
    const id = '70000000-0000-4000-8000-000000000001'
    const awaiting = (await begin(event, undefined)) as { token: string }
    const ready = (await submit(event, {
      token: awaiting.token,
      passphrase: 'correct passphrase'
    })) as { token: string }
    const authorization = (await authorize(event, {
      id,
      masterPassword: 'correct horse battery staple'
    })) as { token: string }

    setTargetType('login')
    await expect(
      update(event, { id, importToken: ready.token, authorizationToken: authorization.token })
    ).rejects.toThrow('BEARWARDEN:INVALID_INPUT')
    expect(afterMutation).not.toHaveBeenCalled()

    setTargetType('sshKey')
    await expect(
      update(event, { id, importToken: ready.token, authorizationToken: authorization.token })
    ).resolves.toMatchObject({ type: 'sshKey' })
    expect(afterMutation).toHaveBeenCalledTimes(1)
  })
})
