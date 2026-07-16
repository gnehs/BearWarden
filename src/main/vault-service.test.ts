import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  BitwardenDirectError,
  type BitwardenDirectState,
  type BitwardenLoginDraft,
  type BitwardenLoginItem,
  type BitwardenSendItem,
  type BitwardenSyncClient
} from './bitwarden-direct'
import type { CustomFieldRequest, LoginView, VaultItemFields } from '../shared/vault-contract'
import { EncryptedVaultStore } from './encrypted-vault-store'
import {
  VaultService,
  type PasskeyVaultAuthorizationValidator,
  type PasskeyVaultCreateRequest,
  type PasskeyVaultCreateResult,
  type VaultAccountWebAuthnAssertionRequester,
  type VaultAccountWebAuthnRegistrationRequester,
  type VaultServiceOptions
} from './vault-service'
import { VaultAttachmentFileService } from './vault-attachment-files'
import { createPasskeyCredential } from './passkey-authenticator'
import { hashPasswordForPwnedLookup } from './pwned-passwords'
import { buildBitwardenJson } from './vault-portability-codec'
import { parseTwoFactorDirectoryTotpData } from './inactive-two-factor'
import type { AccountWebAuthnAssertion, AccountWebAuthnChallenge } from './account-webauthn-codec'
import type {
  AccountWebAuthnAttestation,
  AccountWebAuthnRegistrationChallenge
} from './account-webauthn-registration-codec'

const MASTER_PASSWORD = 'correct horse battery staple'
const ATTACHMENT_OPERATION_ID = '70000000-0000-4000-8000-000000000001'
const IDS = [
  '00000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-000000000002',
  '00000000-0000-4000-8000-000000000003',
  '00000000-0000-4000-8000-000000000004',
  '00000000-0000-4000-8000-000000000005',
  '00000000-0000-4000-8000-000000000006',
  '00000000-0000-4000-8000-000000000007',
  '00000000-0000-4000-8000-000000000008',
  '00000000-0000-4000-8000-000000000009',
  '00000000-0000-4000-8000-000000000010',
  '00000000-0000-4000-8000-000000000011',
  '00000000-0000-4000-8000-000000000012'
]

const temporaryDirectories: string[] = []

const emptyItemFields: VaultItemFields = {
  username: '',
  password: '',
  totp: '',
  uri: null,
  cardholderName: '',
  brand: '',
  number: '',
  expMonth: '',
  expYear: '',
  code: '',
  title: '',
  firstName: '',
  middleName: '',
  lastName: '',
  address1: '',
  address2: '',
  address3: '',
  city: '',
  state: '',
  postalCode: '',
  country: '',
  company: '',
  email: '',
  phone: '',
  ssn: '',
  identityUsername: '',
  passportNumber: '',
  licenseNumber: '',
  privateKey: '',
  publicKey: '',
  fingerprint: ''
}

function customFieldRequest(login: LoginView, index: number): CustomFieldRequest {
  const field = login.customFields[index]
  if (!field) throw new Error(`Missing custom field ${index}`)
  return {
    id: login.id,
    expectedUpdatedAt: login.updatedAt,
    source: { index, name: field.name, type: field.type, linkedId: field.linkedId }
  }
}

async function createHarness(options: VaultServiceOptions = {}): Promise<{
  directory: string
  filePath: string
  store: EncryptedVaultStore<unknown>
  service: VaultService
  copyText: ReturnType<typeof vi.fn>
  copySensitiveText: ReturnType<typeof vi.fn>
  openExternal: ReturnType<typeof vi.fn>
}> {
  const directory = await mkdtemp(join(tmpdir(), 'bearwarden-test-'))
  temporaryDirectories.push(directory)
  const filePath = join(directory, 'vault', 'vault.json')
  const copyText = vi.fn()
  const copySensitiveText = vi.fn()
  const openExternal = vi.fn()
  let idIndex = 0
  let clock = Date.parse('2026-07-14T00:00:00.000Z')
  const store = new EncryptedVaultStore<unknown>(filePath)
  const service = new VaultService(
    store,
    {
      copyText,
      copySensitiveText,
      openExternal
    },
    {
      createId: () => IDS[idIndex++]!,
      now: () => new Date((clock += 1_000)),
      ...options
    }
  )
  return { directory, filePath, store, service, copyText, copySensitiveText, openExternal }
}

const PASSKEY_RP_ID = 'login.example.invalid'

function createAccountWebAuthnChallenge(seed = 1): AccountWebAuthnChallenge {
  return {
    challenge: Buffer.alloc(32, seed).toString('base64url'),
    rpId: 'vault.example.invalid',
    allowCredentials: [
      {
        type: 'public-key',
        id: Buffer.alloc(32, seed + 1).toString('base64url'),
        transports: ['internal']
      }
    ],
    timeout: 60_000,
    userVerification: 'preferred',
    extensions: {}
  }
}

const ACCOUNT_WEBAUTHN_ASSERTION: AccountWebAuthnAssertion = {
  id: Buffer.alloc(32, 7).toString('base64url'),
  rawId: Buffer.alloc(32, 7).toString('base64url'),
  type: 'public-key',
  response: {
    clientDataJSON: Buffer.from('provider-7-client-data').toString('base64url'),
    authenticatorData: Buffer.from('provider-7-authenticator-data').toString('base64url'),
    signature: Buffer.from('provider-7-signature').toString('base64url'),
    userHandle: null
  },
  clientExtensionResults: {}
}

function createAccountWebAuthnRegistrationChallenge(
  seed = 11
): AccountWebAuthnRegistrationChallenge {
  return {
    rp: { id: 'vault.example.invalid', name: 'Example Vault' },
    user: {
      id: Buffer.alloc(32, seed).toString('base64url'),
      name: 'sync@example.invalid',
      displayName: 'Sync User'
    },
    challenge: Buffer.alloc(32, seed + 1).toString('base64url'),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [],
    authenticatorSelection: { userVerification: 'preferred' },
    attestation: 'none',
    extensions: {}
  }
}

const ACCOUNT_WEBAUTHN_ATTESTATION: AccountWebAuthnAttestation = {
  id: Buffer.alloc(32, 21).toString('base64url'),
  rawId: Buffer.alloc(32, 21).toString('base64url'),
  type: 'public-key',
  response: {
    clientDataJSON: Buffer.from('registration-client-data').toString('base64url'),
    attestationObject: Buffer.from('registration-attestation').toString('base64url')
  },
  clientExtensionResults: {},
  authenticatorAttachment: 'platform'
}

async function createVaultPasskey(
  service: VaultService,
  login: LoginView,
  overrides: Partial<PasskeyVaultCreateRequest> = {},
  validateAuthorization: PasskeyVaultAuthorizationValidator = () => true
): Promise<PasskeyVaultCreateResult> {
  const expectedGeneration = await service.unlockedGeneration()
  return service.createPasskey(
    {
      itemId: login.id,
      expectedUpdatedAt: login.updatedAt,
      expectedGeneration,
      rpId: PASSKEY_RP_ID,
      rpName: 'Example',
      userHandle: Buffer.from('opaque-test-user-handle'),
      userName: 'test-user',
      userDisplayName: 'Test User',
      discoverable: true,
      replaceExisting: false,
      requireUserVerification: false,
      userVerified: false,
      ...overrides
    },
    validateAuthorization
  )
}

function createSyncFake(initialState: BitwardenDirectState): BitwardenSyncClient & {
  remoteLogins: BitwardenLoginItem[]
  softDeletedIds: string[]
  restoredIds: string[]
  hardDeletedIds: string[]
  editedLoginIds: string[]
  downloadedAttachmentIds: string[]
  readonly loginPassword: string | null
} {
  let unlocked = false
  let loginPassword: string | null = null
  let state: BitwardenDirectState = structuredClone(initialState)
  const remoteFolders = [{ id: '90000000-0000-4000-8000-000000000001', name: 'Remote folder' }]
  const remoteLogins: BitwardenLoginItem[] = [
    {
      ...emptyItemFields,
      id: '90000000-0000-4000-8000-000000000002',
      type: 'login',
      organizationId: null,
      folderId: remoteFolders[0]!.id,
      name: 'Remote login',
      notes: null,
      favorite: false,
      username: 'remote@example.invalid',
      password: 'remote-test-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      uri: 'https://remote.example.invalid',
      uris: [{ uri: 'https://remote.example.invalid', match: null }],
      customFields: [
        { name: 'member-id', value: 'remote-member-42', type: 'text', linkedId: null },
        { name: 'recovery-code', value: 'remote-hidden-code', type: 'hidden', linkedId: null },
        { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
        { name: 'linked-username', value: '', type: 'linked', linkedId: 100 }
      ],
      passwordHistory: [],
      attachments: [],
      passkeys: [
        {
          credentialId: 'credential-id',
          keyType: 'public-key',
          keyAlgorithm: 'ECDSA',
          keyCurve: 'P-256',
          keyValue: 'fake-passkey-private-material',
          rpId: 'remote.example.invalid',
          userHandle: null,
          userName: 'remote@example.invalid',
          counter: '0',
          rpName: 'Remote example',
          userDisplayName: 'Test User',
          discoverable: true,
          creationDate: '2026-07-13T00:00:00.000Z'
        }
      ],
      creationDate: '2026-07-13T00:00:00.000Z',
      revisionDate: '2026-07-14T00:00:00.000Z',
      deletedAt: null,
      archivedAt: null,
      reprompt: 0
    }
  ]
  const fromDraft = (id: string, draft: BitwardenLoginDraft): BitwardenLoginItem => ({
    ...emptyItemFields,
    id,
    type: draft.type ?? 'login',
    organizationId: null,
    folderId: draft.folderId ?? null,
    name: draft.name,
    notes: draft.notes ?? null,
    favorite: draft.favorite ?? false,
    username: draft.username ?? '',
    password: draft.password ?? '',
    totp: draft.totp ?? '',
    uri: draft.uris?.[0]?.uri ?? draft.uri ?? null,
    uris:
      draft.uris?.map((entry) => ({ ...entry })) ??
      (draft.uri ? [{ uri: draft.uri, match: null }] : []),
    customFields: draft.customFields ?? [],
    passkeys: draft.passkeys ?? [],
    passwordHistory: draft.passwordHistory ?? [],
    attachments: [],
    creationDate: '2026-07-14T00:00:00.000Z',
    revisionDate: '2026-07-14T00:00:01.000Z',
    deletedAt: null,
    archivedAt: draft.archivedAt ?? null,
    reprompt: draft.reprompt ?? 0
  })

  const softDeletedIds: string[] = []
  const restoredIds: string[] = []
  const hardDeletedIds: string[] = []
  const editedLoginIds: string[] = []
  const downloadedAttachmentIds: string[] = []
  let equivalentDomainSettings = {
    equivalentDomains: [['remote.example.invalid', 'remote-login.example.invalid']],
    globalEquivalentDomains: [
      {
        type: 1,
        domains: ['google.com', 'gmail.com'],
        excluded: false
      }
    ]
  }
  const hardDeleteLogin = async (id: string): Promise<void> => {
    hardDeletedIds.push(id)
    const index = remoteLogins.findIndex((login) => login.id === id)
    if (index >= 0) remoteLogins.splice(index, 1)
  }

  return {
    remoteLogins,
    softDeletedIds,
    restoredIds,
    hardDeletedIds,
    editedLoginIds,
    downloadedAttachmentIds,
    get loginPassword() {
      return loginPassword
    },
    status: async () => ({
      status: state.session ? (unlocked ? 'unlocked' : 'locked') : 'unauthenticated'
    }),
    login: async (request) => {
      unlocked = true
      loginPassword = request.password
      state = {
        ...state,
        session: {
          accessToken: 'test-access-token',
          refreshToken: 'test-refresh-token',
          expiresAt: 1
        }
      }
    },
    unlock: async () => {
      unlocked = true
      if (!state.session) {
        state = {
          ...state,
          session: {
            accessToken: 'test-access-token-after-logout',
            refreshToken: 'test-refresh-token-after-logout',
            expiresAt: 2
          }
        }
      }
    },
    sync: async () => {
      state = {
        ...state,
        profileId: '90000000-0000-4000-8000-000000000099',
        securityStamp: 'test-security-stamp'
      }
    },
    notificationAccessToken: async () => {
      if (!state.session) throw new Error('missing fake session')
      return state.session.accessToken
    },
    getAccountBreachReport: async () => ({ status: 'complete', breaches: [] }),
    getAccountSecurityProfile: async () => ({
      id: state.profileId ?? '90000000-0000-4000-8000-000000000099',
      name: 'Sync User',
      email: 'sync@example.invalid',
      emailVerified: false,
      twoFactorEnabled: true
    }),
    getAccountDevices: async () => [
      {
        id: '91000000-0000-4000-8000-000000000001',
        name: 'Personal Mac',
        type: 7,
        createdAt: '2026-07-01T00:00:00.000Z',
        lastActivityAt: '2026-07-17T01:02:03.000Z',
        current: true,
        trusted: true,
        pendingAuthRequest: false
      }
    ],
    resendVerificationEmail: async () => undefined,
    getPersonalApiKey: async (_masterPassword, rotate) => ({
      clientId: 'user.90000000-0000-4000-8000-000000000099',
      clientSecret: rotate ? 'rotated-client-secret' : 'existing-client-secret',
      revisionDate: rotate ? '2026-07-16T00:01:00Z' : '2026-07-16T00:00:00Z'
    }),
    getTwoFactorProviders: async () => [
      { type: 0, enabled: true },
      { type: 1, enabled: true }
    ],
    disableTwoFactorProvider: async () => undefined,
    getTwoFactorRecoveryCode: async () => 'RECOVERY-CODE',
    beginAuthenticatorSetup: async () => ({
      enabled: false,
      key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      verificationMode: 'master-password' as const,
      userVerificationToken: null
    }),
    completeAuthenticatorSetup: async () => undefined,
    beginEmailTwoFactorSetup: async () => ({
      enabled: false,
      email: null,
      verificationMode: 'master-password' as const,
      userVerificationToken: null
    }),
    sendEmailTwoFactorSetup: async () => undefined,
    completeEmailTwoFactorSetup: async () => undefined,
    beginWebAuthnSetup: async () => ({
      enabled: true,
      keys: [{ id: 1, name: 'Existing security key', migrated: false }],
      registrationId: 2,
      registrationChallenge: createAccountWebAuthnRegistrationChallenge(),
      verificationMode: 'master-password' as const,
      userVerificationToken: null
    }),
    completeWebAuthnSetup: async () => undefined,
    deleteWebAuthnKey: async () => undefined,
    changeMasterPassword: async () => {
      unlocked = false
      state = { ...state, session: null }
    },
    getEquivalentDomainSettings: async () => structuredClone(equivalentDomainSettings),
    updateEquivalentDomainSettings: async (update) => {
      const excluded = new Set(update.excludedGlobalEquivalentDomains)
      equivalentDomainSettings = {
        equivalentDomains: structuredClone(update.equivalentDomains),
        globalEquivalentDomains: equivalentDomainSettings.globalEquivalentDomains.map((group) => ({
          ...group,
          domains: [...group.domains],
          excluded: excluded.has(group.type)
        }))
      }
    },
    listFolders: async () => remoteFolders.map((folder) => ({ ...folder })),
    listPersonalLogins: async () =>
      remoteLogins.map((login) => ({
        ...login,
        uris: login.uris.map((uri) => ({ ...uri })),
        customFields: login.customFields.map((field) => ({ ...field })),
        passkeys: login.passkeys.map((passkey) => ({ ...passkey })),
        attachments: login.attachments.map((attachment) => ({ ...attachment }))
      })),
    downloadAttachment: async (id, attachmentId) => {
      const attachment = remoteLogins
        .find((login) => login.id === id)
        ?.attachments.find((entry) => entry.id === attachmentId)
      if (!attachment) throw new Error('missing fake attachment')
      downloadedAttachmentIds.push(attachmentId)
      return {
        fileName: attachment.fileName,
        data: Buffer.from('fake attachment contents')
      }
    },
    uploadAttachment: async (id, fileName, data, _signal, onCommitted) => {
      const login = remoteLogins.find((entry) => entry.id === id)
      if (!login) throw new Error('missing fake login')
      const attachment = {
        id: `uploaded-attachment-${login.attachments.length + 1}`,
        fileName,
        size: data.length,
        sizeName: `${data.length} B`,
        legacy: false
      }
      login.attachments.push(attachment)
      login.revisionDate = '2026-07-16T00:00:00.000Z'
      onCommitted?.()
      return { ...attachment }
    },
    deleteAttachment: async (id, attachmentId, _signal, onCommitted) => {
      const login = remoteLogins.find((entry) => entry.id === id)
      if (!login) throw new Error('missing fake login')
      const index = login.attachments.findIndex((entry) => entry.id === attachmentId)
      if (index < 0) throw new Error('missing fake attachment')
      login.attachments.splice(index, 1)
      login.revisionDate = '2026-07-16T00:00:00.000Z'
      onCommitted?.()
    },
    upgradeLegacyAttachment: async (id, attachmentId, _signal, onCommitted) => {
      const login = remoteLogins.find((entry) => entry.id === id)
      const index = login?.attachments.findIndex((entry) => entry.id === attachmentId) ?? -1
      if (!login || index < 0 || !login.attachments[index]!.legacy) {
        throw new Error('missing fake legacy attachment')
      }
      const legacy = login.attachments[index]!
      const replacement = {
        ...legacy,
        id: `fixed-${legacy.id}`,
        legacy: false
      }
      login.attachments.splice(index, 1, replacement)
      login.revisionDate = '2026-07-16T00:00:00.000Z'
      onCommitted?.()
      return { ...replacement }
    },
    createFolder: async (name) => {
      const folder = { id: '90000000-0000-4000-8000-000000000003', name }
      remoteFolders.push(folder)
      return { ...folder }
    },
    editFolder: async (id, name) => {
      const folder = remoteFolders.find((candidate) => candidate.id === id)!
      folder.name = name
      return { ...folder }
    },
    deleteFolder: async (id) => {
      const index = remoteFolders.findIndex((folder) => folder.id === id)
      if (index >= 0) remoteFolders.splice(index, 1)
    },
    createLogin: async (draft) => {
      const login = fromDraft('90000000-0000-4000-8000-000000000004', draft)
      remoteLogins.push(login)
      return structuredClone(login)
    },
    editLogin: async (id, draft) => {
      editedLoginIds.push(id)
      const index = remoteLogins.findIndex((login) => login.id === id)
      const login = fromDraft(id, draft)
      remoteLogins[index] = login
      return structuredClone(login)
    },
    softDeleteLogin: async (id) => {
      softDeletedIds.push(id)
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.deletedAt = '2026-07-14T00:00:02.000Z'
    },
    restoreLogin: async (id) => {
      restoredIds.push(id)
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.deletedAt = null
    },
    archiveLogin: async (id) => {
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.archivedAt = '2026-07-14T00:00:03.000Z'
    },
    unarchiveLogin: async (id) => {
      const login = remoteLogins.find((candidate) => candidate.id === id)
      if (login) login.archivedAt = null
    },
    hardDeleteLogin,
    deleteLogin: hardDeleteLogin,
    lock: async () => {
      unlocked = false
    },
    logout: async () => {
      unlocked = false
      state = { ...state, session: null }
    },
    exportState: () => structuredClone(state)
  }
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true }))
  )
})

describe('VaultService encrypted local data', () => {
  it('changes remote then local master password, invalidates PIN, and clears sync session', async () => {
    let client!: ReturnType<typeof createSyncFake>
    const { service } = await createHarness({
      createSyncClient: (sync) => (client = createSyncFake(sync.state))
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    await service.enablePinUnlock({ pin: 'bear-2026', masterPassword: MASTER_PASSWORD })
    const remoteChange = vi.spyOn(client, 'changeMasterPassword')
    const request = {
      currentPassword: MASTER_PASSWORD,
      newPassword: 'replacement horse battery staple',
      hint: 'safe hint'
    }

    await service.changeMasterPassword(request)

    expect(remoteChange).toHaveBeenCalledTimes(1)
    expect(request).toEqual({ currentPassword: '', newPassword: '', hint: null })
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })
    await expect(service.masterPasswordChangeStatus()).resolves.toEqual({
      phase: null,
      needsReconnect: false,
      needsRemoteVerification: false
    })
    await expect(service.syncStatus()).resolves.toMatchObject({ state: 'locked' })
    await service.lock()
    await expect(service.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })
    await expect(service.unlock('replacement horse battery staple')).resolves.toEqual({
      state: 'unlocked'
    })
  })

  it('keeps an unknown remote outcome prepared and never retries the mutation', async () => {
    let mutationCalls = 0
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.changeMasterPassword = async () => {
          mutationCalls += 1
          throw new BitwardenDirectError('MASTER_PASSWORD_CHANGE_UNKNOWN')
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    const first = {
      currentPassword: MASTER_PASSWORD,
      newPassword: 'replacement horse battery staple'
    }
    await expect(service.changeMasterPassword(first)).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(first).toEqual({ currentPassword: '', newPassword: '', hint: null })
    expect(mutationCalls).toBe(1)
    await expect(service.status()).resolves.toEqual({ state: 'locked' })
    await service.unlock(MASTER_PASSWORD)
    await expect(service.masterPasswordChangeStatus()).resolves.toEqual({
      phase: 'prepared',
      needsReconnect: false,
      needsRemoteVerification: true
    })
    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(mutationCalls).toBe(1)
    const resolution = {
      currentPassword: MASTER_PASSWORD,
      newPassword: 'replacement horse battery staple'
    }
    await expect(service.resolveMasterPasswordChange(resolution)).resolves.toEqual({
      status: 'resolved'
    })
    expect(resolution).toEqual({ currentPassword: '', newPassword: '' })
    expect(mutationCalls).toBe(1)
    await service.lock()
    await expect(service.unlock('replacement horse battery staple')).resolves.toEqual({
      state: 'unlocked'
    })
  })

  it('clears prepared only after isolated proofs reject new and accept current, then permits retry', async () => {
    let acceptedPassword = MASTER_PASSWORD
    let mutationCalls = 0
    const proofClients: BitwardenSyncClient[] = []
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        const login = client.login.bind(client)
        client.login = async (request) => {
          if (request.password !== acceptedPassword) {
            throw new BitwardenDirectError('AUTH_REQUIRED')
          }
          await login(request)
        }
        client.changeMasterPassword = async (request) => {
          mutationCalls += 1
          if (mutationCalls === 1) throw new BitwardenDirectError('MASTER_PASSWORD_CHANGE_UNKNOWN')
          acceptedPassword = request.newPassword
        }
        proofClients.push(client)
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    await service.unlock(MASTER_PASSWORD)

    await expect(
      service.resolveMasterPasswordChange({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).resolves.toEqual({ status: 'remote-not-changed' })
    expect(new Set(proofClients.slice(-2)).size).toBe(2)
    await expect(service.masterPasswordChangeStatus()).resolves.toMatchObject({ phase: null })

    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'second replacement horse battery staple'
      })
    ).resolves.toBeUndefined()
    expect(mutationCalls).toBe(2)
  })

  it('retains prepared when isolated proofs reject both candidate passwords', async () => {
    let acceptedPassword = MASTER_PASSWORD
    let mutationCalls = 0
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        const login = client.login.bind(client)
        client.login = async (request) => {
          if (request.password !== acceptedPassword) {
            throw new BitwardenDirectError('AUTH_REQUIRED')
          }
          await login(request)
        }
        client.changeMasterPassword = async () => {
          mutationCalls += 1
          acceptedPassword = 'a different remote password'
          throw new BitwardenDirectError('MASTER_PASSWORD_CHANGE_UNKNOWN')
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    await service.unlock(MASTER_PASSWORD)

    await expect(
      service.resolveMasterPasswordChange({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).resolves.toEqual({ status: 'indeterminate' })
    await expect(service.masterPasswordChangeStatus()).resolves.toMatchObject({
      phase: 'prepared'
    })
    expect(mutationCalls).toBe(1)
  })

  it('rejects an unchanged master password before journaling or remote mutation', async () => {
    let mutationCalls = 0
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.changeMasterPassword = async () => {
          mutationCalls += 1
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })

    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: MASTER_PASSWORD
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(mutationCalls).toBe(0)
    await expect(service.masterPasswordChangeStatus()).resolves.toMatchObject({ phase: null })
  })

  it('does not call the remote mutation when the prepared journal cannot persist', async () => {
    let mutationCalls = 0
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.changeMasterPassword = async () => {
          mutationCalls += 1
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    vi.spyOn(store, 'write').mockRejectedValueOnce(new Error('injected prepared persist failure'))

    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toThrow('injected prepared persist failure')
    expect(mutationCalls).toBe(0)
    await expect(service.masterPasswordChangeStatus()).resolves.toMatchObject({ phase: null })
  })

  it('clears a prepared journal after a definitive remote rejection', async () => {
    let client!: ReturnType<typeof createSyncFake>
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        client = createSyncFake(sync.state)
        client.changeMasterPassword = async () => {
          throw new BitwardenDirectError('AUTH_REQUIRED')
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    await expect(
      service.changeMasterPassword({
        currentPassword: 'wrong horse battery staple',
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toMatchObject({ code: 'SYNC_AUTH_REQUIRED' })
    await expect(service.masterPasswordChangeStatus()).resolves.toEqual({
      phase: null,
      needsReconnect: false,
      needsRemoteVerification: false
    })
    await expect(service.status()).resolves.toEqual({ state: 'unlocked' })
  })

  it('resumes remote-confirmed without replaying the remote mutation after local rekey fails', async () => {
    let client!: ReturnType<typeof createSyncFake>
    const { service, store } = await createHarness({
      createSyncClient: (sync) => (client = createSyncFake(sync.state))
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    const remoteChange = vi.spyOn(client, 'changeMasterPassword')
    const realRekey = store.rekey.bind(store)
    vi.spyOn(store, 'rekey').mockRejectedValueOnce(new Error('injected local rekey failure'))
    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toThrow('injected local rekey failure')
    await expect(service.masterPasswordChangeStatus()).resolves.toMatchObject({
      phase: 'remote-confirmed'
    })
    vi.mocked(store.rekey).mockImplementation(realRekey)
    await service.changeMasterPassword({
      currentPassword: MASTER_PASSWORD,
      newPassword: 'replacement horse battery staple'
    })
    expect(remoteChange).toHaveBeenCalledTimes(1)
  })

  it('recovers a prepared journal after the remote-confirmed persist crashes without replaying', async () => {
    let mutationCalls = 0
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.changeMasterPassword = async () => {
          mutationCalls += 1
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    const write = store.write.bind(store)
    let writes = 0
    vi.spyOn(store, 'write').mockImplementation(async (...args) => {
      writes += 1
      if (writes === 2) throw new Error('injected confirmed persist crash')
      await write(...args)
    })

    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toThrow('injected confirmed persist crash')
    await service.unlock(MASTER_PASSWORD)
    await expect(service.masterPasswordChangeStatus()).resolves.toMatchObject({
      phase: 'prepared'
    })
    await expect(
      service.resolveMasterPasswordChange({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).resolves.toEqual({ status: 'resolved' })
    expect(mutationCalls).toBe(1)
  })

  it('resumes after local rekey succeeds but its journal persist crashes', async () => {
    let client!: ReturnType<typeof createSyncFake>
    const { service, store } = await createHarness({
      createSyncClient: (sync) => (client = createSyncFake(sync.state))
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    const remoteChange = vi.spyOn(client, 'changeMasterPassword')
    const write = store.write.bind(store)
    let writes = 0
    vi.spyOn(store, 'write').mockImplementation(async (...args) => {
      writes += 1
      if (writes === 3) throw new Error('injected local-rekeyed persist crash')
      await write(...args)
    })

    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toThrow('injected local-rekeyed persist crash')
    await expect(service.masterPasswordChangeStatus()).resolves.toMatchObject({
      phase: 'remote-confirmed'
    })
    await service.changeMasterPassword({
      currentPassword: MASTER_PASSWORD,
      newPassword: 'replacement horse battery staple'
    })
    expect(remoteChange).toHaveBeenCalledTimes(1)
  })

  it('clears local-rekeyed automatically after the final journal clear crashes', async () => {
    const { filePath, service, store } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state)
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    const write = store.write.bind(store)
    let writes = 0
    vi.spyOn(store, 'write').mockImplementation(async (...args) => {
      writes += 1
      if (writes === 4) throw new Error('injected final clear crash')
      await write(...args)
    })
    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toThrow('injected final clear crash')
    await service.lock()

    const reopened = new VaultService(
      new EncryptedVaultStore<unknown>(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: (sync) => createSyncFake(sync.state) }
    )
    await reopened.unlock('replacement horse battery staple')
    await expect(reopened.masterPasswordChangeStatus()).resolves.toMatchObject({ phase: null })
  })

  it.each([
    {
      label: 'extra journal property',
      mutate: (journal: Record<string, unknown>) => {
        journal.unexpected = true
      }
    },
    {
      label: 'mismatched account fingerprint',
      mutate: (journal: Record<string, unknown>) => {
        journal.accountFingerprint = '0'.repeat(64)
      }
    }
  ])('rejects a prepared journal with $label', async ({ mutate }) => {
    const { filePath, service, store } = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.changeMasterPassword = async () => {
          throw new BitwardenDirectError('MASTER_PASSWORD_CHANGE_UNKNOWN')
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: MASTER_PASSWORD
    })
    await expect(
      service.changeMasterPassword({
        currentPassword: MASTER_PASSWORD,
        newPassword: 'replacement horse battery staple'
      })
    ).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as { masterPasswordChange: Record<string, unknown> }
    expect(Object.keys(data.masterPasswordChange).sort()).toEqual([
      'accountFingerprint',
      'phase',
      'startedAt',
      'updatedAt'
    ])
    const serializedJournal = JSON.stringify(data.masterPasswordChange)
    expect(serializedJournal).not.toContain(MASTER_PASSWORD)
    expect(serializedJournal).not.toContain('replacement horse battery staple')
    expect(serializedJournal).not.toContain('sync@example.invalid')
    mutate(data.masterPasswordChange)
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })
  it('enables memory-only PIN unlock with fresh proof and preserves it across ordinary lock', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const enableRequest = { pin: 'bear-2026', masterPassword: MASTER_PASSWORD }

    await expect(service.enablePinUnlock(enableRequest)).resolves.toEqual({
      available: true,
      remainingAttempts: 5
    })
    expect(enableRequest).toEqual({ pin: '', masterPassword: '' })
    await expect(service.lock()).resolves.toEqual({ state: 'locked' })
    await expect(service.listLogins()).rejects.toMatchObject({ code: 'LOCKED' })
    expect(service.pinUnlockStatus()).toEqual({ available: true, remainingAttempts: 5 })

    const unlockRequest = { pin: 'bear-2026' }
    await expect(service.unlockWithPin(unlockRequest)).resolves.toEqual({ state: 'unlocked' })
    expect(unlockRequest.pin).toBe('')
    await expect(service.listLogins()).resolves.toEqual([])
  })

  it('requires a correct master-password proof and destroys PIN capability after five failures', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const wrongProof = { pin: 'bear-2026', masterPassword: 'wrong master password' }
    await expect(service.enablePinUnlock(wrongProof)).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })
    expect(wrongProof).toEqual({ pin: '', masterPassword: '' })
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })

    await service.enablePinUnlock({ pin: 'bear-2026', masterPassword: MASTER_PASSWORD })
    await service.lock()
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const request = { pin: `wrong-${attempt}` }
      await expect(service.unlockWithPin(request)).rejects.toMatchObject({ code: 'INVALID_PIN' })
      expect(request.pin).toBe('')
      expect(service.pinUnlockStatus()).toEqual({
        available: true,
        remainingAttempts: 5 - attempt
      })
    }
    await expect(service.unlockWithPin({ pin: 'wrong-5' })).rejects.toMatchObject({
      code: 'PIN_DISABLED'
    })
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })
    await expect(service.unlockWithPin({ pin: 'bear-2026' })).rejects.toMatchObject({
      code: 'PIN_DISABLED'
    })
  })

  it('invalidates PIN capability on lifecycle changes and races fail closed', async () => {
    const { service } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state)
    })
    await service.setup(MASTER_PASSWORD)

    const enableRequest = { pin: 'pending-pin', masterPassword: MASTER_PASSWORD }
    const pendingEnable = service.enablePinUnlock(enableRequest)
    const lockDuringEnable = service.lock()
    await expect(pendingEnable).rejects.toMatchObject({ code: 'LOCKED' })
    await expect(lockDuringEnable).resolves.toEqual({ state: 'locked' })
    expect(enableRequest).toEqual({ pin: '', masterPassword: '' })
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })
    await service.unlock(MASTER_PASSWORD)

    await service.enablePinUnlock({ pin: 'account-pin', masterPassword: MASTER_PASSWORD })
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })

    await service.enablePinUnlock({ pin: 'disconnect-pin', masterPassword: MASTER_PASSWORD })
    await service.disconnectSync()
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })

    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    await service.enablePinUnlock({ pin: 'logout-pin', masterPassword: MASTER_PASSWORD })
    await service.remoteLogoutSync()
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })

    await service.enablePinUnlock({ pin: 'race-pin', masterPassword: MASTER_PASSWORD })
    await service.lock()
    const unlockRequest = { pin: 'race-pin' }
    const pendingUnlock = service.unlockWithPin(unlockRequest)
    await vi.waitFor(() => expect(unlockRequest.pin).toBe(''))
    const pendingLock = service.lock()
    await expect(pendingUnlock).rejects.toMatchObject({ code: 'LOCKED' })
    await expect(pendingLock).resolves.toEqual({ state: 'locked' })
    expect(service.pinUnlockStatus()).toEqual({ available: true, remainingAttempts: 5 })

    await service.unlock(MASTER_PASSWORD)
    await service.enablePinUnlock({ pin: 'dispose-pin', masterPassword: MASTER_PASSWORD })
    service.dispose()
    expect(service.pinUnlockStatus()).toEqual({ available: false, remainingAttempts: 0 })
  })

  it('loads a synced login icon only through its configured server endpoint', async () => {
    const iconBytes = Uint8Array.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
      0x52, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20
    ])
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(iconBytes, { headers: { 'content-type': 'image/png' } }))
    const { service } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state),
      fetch: fetcher
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid/base',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!

    const [firstIcon, secondIcon] = await Promise.all([
      service.getWebsiteIcon({ id: login.id }),
      service.getWebsiteIcon({ id: login.id })
    ])
    expect(firstIcon).toMatch(/^data:image\/png;base64,/)
    expect(secondIcon).toBe(firstIcon)
    expect(fetcher).toHaveBeenCalledOnce()
    expect(String(fetcher.mock.calls[0]?.[0])).toBe(
      'https://vault.example.invalid/base/icons/remote.example.invalid/icon.png'
    )
    await service.getWebsiteIcon({ id: login.id })
    expect(fetcher).toHaveBeenCalledOnce()
  })

  it.each([true, false])(
    'retries connect once with provider 7 and explicit remember=%s',
    async (remember) => {
      const challenge = createAccountWebAuthnChallenge(1)
      const loginRequests: Parameters<BitwardenSyncClient['login']>[0][] = []
      const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
        async () => ACCOUNT_WEBAUTHN_ASSERTION
      )
      const { service } = await createHarness({
        requestAccountWebAuthnAssertion,
        createSyncClient: (sync) => {
          const client = createSyncFake(sync.state)
          const login = client.login.bind(client)
          client.login = async (request) => {
            loginRequests.push(request)
            if (loginRequests.length === 1) {
              throw new BitwardenDirectError('TWO_FACTOR_REQUIRED', challenge)
            }
            await login(request)
          }
          return client
        }
      })
      await service.setup(MASTER_PASSWORD)

      await expect(
        service.connectSync({
          serverUrl: 'https://vault.example.invalid/base/',
          email: 'sync@example.invalid',
          masterPassword: 'remote master password',
          webAuthnRemember: remember
        })
      ).resolves.toMatchObject({ configured: true, state: 'ready' })

      expect(loginRequests).toHaveLength(2)
      expect(loginRequests[0]!.twoFactor).toBeUndefined()
      expect(loginRequests[1]!.twoFactor).toEqual({
        method: 7,
        assertion: ACCOUNT_WEBAUTHN_ASSERTION,
        remember
      })
      expect(requestAccountWebAuthnAssertion).toHaveBeenCalledOnce()
      const connectorRequest = requestAccountWebAuthnAssertion.mock.calls[0]![0]
      expect(connectorRequest).toEqual({
        webVaultUrl: 'https://vault.example.invalid/base',
        challenge,
        remember,
        signal: expect.any(AbortSignal)
      })
      expect(connectorRequest.signal).toBe(loginRequests[0]!.signal)
      expect(connectorRequest.signal).toBe(loginRequests[1]!.signal)
      expect(connectorRequest.signal.aborted).toBe(false)

      const retained = JSON.stringify(service)
      expect(retained).not.toContain(challenge.challenge)
      expect(retained).not.toContain(ACCOUNT_WEBAUTHN_ASSERTION.response.signature)
      expect(Reflect.ownKeys(service)).not.toContain('webAuthnChallenge')
      expect(Reflect.ownKeys(service)).not.toContain('webAuthnAssertion')
    }
  )

  it('retries unlock once with the persisted exact Web Vault URL', async () => {
    const challenge = createAccountWebAuthnChallenge(3)
    const unlockRequests: Parameters<BitwardenSyncClient['unlock']>[0][] = []
    const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
      async () => ACCOUNT_WEBAUTHN_ASSERTION
    )
    let clientCount = 0
    const { service } = await createHarness({
      requestAccountWebAuthnAssertion,
      createSyncClient: (sync) => {
        clientCount += 1
        const client = createSyncFake(sync.state)
        if (clientCount === 2) {
          const unlock = client.unlock.bind(client)
          client.unlock = async (request) => {
            unlockRequests.push(request)
            if (unlockRequests.length === 1) {
              throw new BitwardenDirectError('TWO_FACTOR_REQUIRED', challenge)
            }
            await unlock(request)
          }
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://self-hosted.example.invalid/bitwarden',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    await service.remoteLogoutSync()

    await expect(
      service.unlockSync({
        masterPassword: 'remote master password',
        webAuthnRemember: false
      })
    ).resolves.toMatchObject({ configured: true, state: 'ready' })

    expect(unlockRequests).toHaveLength(2)
    expect(unlockRequests[0]!.twoFactor).toBeUndefined()
    expect(unlockRequests[1]!.twoFactor).toEqual({
      method: 7,
      assertion: ACCOUNT_WEBAUTHN_ASSERTION,
      remember: false
    })
    expect(requestAccountWebAuthnAssertion).toHaveBeenCalledWith({
      webVaultUrl: 'https://self-hosted.example.invalid/bitwarden',
      challenge,
      remember: false,
      signal: expect.any(AbortSignal)
    })
  })

  it('does not request provider 7 without both a callback and explicit remember choice', async () => {
    const challenge = createAccountWebAuthnChallenge(5)
    let missingCallbackLoginCalls = 0
    const missingCallbackHarness = await createHarness({
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.login = async () => {
          missingCallbackLoginCalls += 1
          throw new BitwardenDirectError('TWO_FACTOR_REQUIRED', challenge)
        }
        return client
      }
    })
    await missingCallbackHarness.service.setup(MASTER_PASSWORD)

    await expect(
      missingCallbackHarness.service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password',
        webAuthnRemember: true
      })
    ).rejects.toMatchObject({ code: 'SYNC_AUTH_REQUIRED', message: 'SYNC_AUTH_REQUIRED' })
    expect(missingCallbackLoginCalls).toBe(1)

    const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
      async () => ACCOUNT_WEBAUTHN_ASSERTION
    )
    let missingRememberLoginCalls = 0
    const missingRememberHarness = await createHarness({
      requestAccountWebAuthnAssertion,
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.login = async () => {
          missingRememberLoginCalls += 1
          throw new BitwardenDirectError('TWO_FACTOR_REQUIRED', challenge)
        }
        return client
      }
    })
    await missingRememberHarness.service.setup(MASTER_PASSWORD)

    await expect(
      missingRememberHarness.service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password'
      })
    ).rejects.toMatchObject({ code: 'SYNC_AUTH_REQUIRED', message: 'SYNC_AUTH_REQUIRED' })
    expect(missingRememberLoginCalls).toBe(1)
    expect(requestAccountWebAuthnAssertion).not.toHaveBeenCalled()
  })

  it('maps connector cancellation and timeout details to the stable generic sync error', async () => {
    const challenge = createAccountWebAuthnChallenge(7)
    const rawConnectorDetail = 'remote connector timeout: credential-secret-detail'
    const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
      async () => {
        throw new Error(rawConnectorDetail)
      }
    )
    let loginCalls = 0
    const { service } = await createHarness({
      requestAccountWebAuthnAssertion,
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.login = async () => {
          loginCalls += 1
          throw new BitwardenDirectError('TWO_FACTOR_REQUIRED', challenge)
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)

    let publicError: unknown
    try {
      await service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password',
        webAuthnRemember: true
      })
    } catch (error) {
      publicError = error
    }
    expect(publicError).toMatchObject({ code: 'SYNC_FAILED', message: 'SYNC_FAILED' })
    expect(String(publicError)).not.toContain(rawConnectorDetail)
    expect(JSON.stringify(await service.syncStatus())).not.toContain(rawConnectorDetail)
    expect(JSON.stringify(service)).not.toContain(challenge.challenge)
    expect(loginCalls).toBe(1)
    expect(requestAccountWebAuthnAssertion).toHaveBeenCalledOnce()
  })

  it.each(['lock', 'dispose'] as const)(
    'aborts a pending provider-7 connector when the service receives %s',
    async (action) => {
      const challenge = createAccountWebAuthnChallenge(action === 'lock' ? 9 : 11)
      let started!: () => void
      const didStart = new Promise<void>((resolve) => {
        started = resolve
      })
      let connectorSignal: AbortSignal | undefined
      const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
        async (request) => {
          connectorSignal = request.signal
          started()
          return new Promise<AccountWebAuthnAssertion>((_resolve, reject) => {
            request.signal.addEventListener(
              'abort',
              () => reject(new Error('connector aborted with raw detail')),
              { once: true }
            )
          })
        }
      )
      const { service } = await createHarness({
        requestAccountWebAuthnAssertion,
        createSyncClient: (sync) => {
          const client = createSyncFake(sync.state)
          client.login = async () => {
            throw new BitwardenDirectError('TWO_FACTOR_REQUIRED', challenge)
          }
          return client
        }
      })
      await service.setup(MASTER_PASSWORD)

      const pending = service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password',
        webAuthnRemember: false
      })
      const rejected = expect(pending).rejects.toMatchObject({ code: 'LOCKED', message: 'LOCKED' })
      await didStart
      if (action === 'lock') {
        await expect(service.lock()).resolves.toEqual({ state: 'locked' })
      } else {
        service.dispose()
      }

      await rejected
      expect(connectorSignal?.aborted).toBe(true)
      expect(requestAccountWebAuthnAssertion).toHaveBeenCalledOnce()
    }
  )

  it('does not loop or expose a second provider-7 challenge', async () => {
    const firstChallenge = createAccountWebAuthnChallenge(13)
    const secondChallenge = createAccountWebAuthnChallenge(15)
    const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
      async () => ACCOUNT_WEBAUTHN_ASSERTION
    )
    let loginCalls = 0
    const { service } = await createHarness({
      requestAccountWebAuthnAssertion,
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.login = async () => {
          loginCalls += 1
          throw new BitwardenDirectError(
            'TWO_FACTOR_REQUIRED',
            loginCalls === 1 ? firstChallenge : secondChallenge
          )
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)

    let publicError: unknown
    try {
      await service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password',
        webAuthnRemember: true
      })
    } catch (error) {
      publicError = error
    }

    expect(publicError).toMatchObject({ code: 'SYNC_AUTH_REQUIRED', message: 'SYNC_AUTH_REQUIRED' })
    expect(String(publicError)).not.toContain(firstChallenge.challenge)
    expect(String(publicError)).not.toContain(secondChallenge.challenge)
    expect(loginCalls).toBe(2)
    expect(requestAccountWebAuthnAssertion).toHaveBeenCalledOnce()
    expect(JSON.stringify(service)).not.toContain(firstChallenge.challenge)
    expect(JSON.stringify(service)).not.toContain(secondChallenge.challenge)
    expect(JSON.stringify(service)).not.toContain(ACCOUNT_WEBAUTHN_ASSERTION.response.signature)
  })

  it.each(['0', '1', '3'] as const)(
    'preserves legacy provider %s request behavior',
    async (twoFactorMethod) => {
      const loginRequests: Parameters<BitwardenSyncClient['login']>[0][] = []
      const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
        async () => ACCOUNT_WEBAUTHN_ASSERTION
      )
      const { service } = await createHarness({
        requestAccountWebAuthnAssertion,
        createSyncClient: (sync) => {
          const client = createSyncFake(sync.state)
          const login = client.login.bind(client)
          client.login = async (request) => {
            loginRequests.push(request)
            await login(request)
          }
          return client
        }
      })
      await service.setup(MASTER_PASSWORD)

      await service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password',
        twoFactorMethod,
        twoFactorCode: `legacy-${twoFactorMethod}`
      })

      expect(loginRequests).toHaveLength(1)
      expect(loginRequests[0]!.twoFactor).toEqual({
        method: Number(twoFactorMethod),
        code: `legacy-${twoFactorMethod}`
      })
      expect(requestAccountWebAuthnAssertion).not.toHaveBeenCalled()
    }
  )

  it('does not fall back from an explicitly selected legacy provider to provider 7', async () => {
    const challenge = createAccountWebAuthnChallenge(17)
    const requestAccountWebAuthnAssertion = vi.fn<VaultAccountWebAuthnAssertionRequester>(
      async () => ACCOUNT_WEBAUTHN_ASSERTION
    )
    let loginCalls = 0
    const { service } = await createHarness({
      requestAccountWebAuthnAssertion,
      createSyncClient: (sync) => {
        const client = createSyncFake(sync.state)
        client.login = async () => {
          loginCalls += 1
          throw new BitwardenDirectError('TWO_FACTOR_REQUIRED', challenge)
        }
        return client
      }
    })
    await service.setup(MASTER_PASSWORD)

    await expect(
      service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password',
        twoFactorMethod: '0',
        twoFactorCode: '123456',
        webAuthnRemember: true
      })
    ).rejects.toMatchObject({ code: 'SYNC_AUTH_REQUIRED' })
    expect(loginCalls).toBe(1)
    expect(requestAccountWebAuthnAssertion).not.toHaveBeenCalled()
  })

  it('pulls and pushes through the direct connector while encrypting its session at rest', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { copyText, filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)

    const connected = await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: ' remote master password '
    })
    expect(connected).toMatchObject({ state: 'ready', pulled: 2, pushed: 0, deleted: 0 })
    expect(fake!.loginPassword).toBe(' remote master password ')
    expect((await service.listFolders())[0]?.name).toBe('Remote folder')
    const local = (await service.listLogins())[0]!
    expect(await service.revealPassword({ id: local.id })).toBe('remote-test-secret')
    const localView = await service.getLogin({ id: local.id })
    expect(localView).toMatchObject({
      hasTotp: true,
      createdAt: '2026-07-13T00:00:00.000Z',
      updatedAt: '2026-07-14T00:00:00.000Z',
      passkeys: [expect.objectContaining({ rpId: 'remote.example.invalid' })],
      customFields: [
        { name: 'member-id', type: 'text', value: 'remote-member-42', linkedId: null },
        { name: 'recovery-code', type: 'hidden', value: null, linkedId: null },
        { name: 'remember-device', type: 'boolean', value: 'true', linkedId: null },
        { name: 'linked-username', type: 'linked', value: null, linkedId: 100 }
      ]
    })
    expect(localView).not.toHaveProperty('totp')
    expect(JSON.stringify(localView)).not.toContain('fake-passkey-private-material')

    await expect(service.revealCustomField(customFieldRequest(localView, 1))).resolves.toBe(
      'remote-hidden-code'
    )
    await service.copyCustomField(customFieldRequest(localView, 0))
    expect(copyText).toHaveBeenCalledWith('remote-member-42')
    await service.copyCustomField(customFieldRequest(localView, 3))
    expect(copyText).toHaveBeenCalledWith('remote@example.invalid')
    await expect(
      service.revealCustomField({
        id: local.id,
        expectedUpdatedAt: localView.updatedAt,
        source: { index: 4, name: 'missing', type: 'hidden', linkedId: null }
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.copyCustomField({
        id: local.id,
        expectedUpdatedAt: localView.updatedAt,
        source: { index: -1, name: 'missing', type: 'text', linkedId: null }
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    await service.updateLogin({ id: local.id, password: 'locally-changed-secret' })
    const synced = await service.syncNow()
    expect(synced.pushed).toBe(1)
    expect(fake!.remoteLogins[0]?.password).toBe('locally-changed-secret')
    expect(fake!.remoteLogins[0]?.customFields).toEqual([
      { name: 'member-id', value: 'remote-member-42', type: 'text', linkedId: null },
      { name: 'recovery-code', value: 'remote-hidden-code', type: 'hidden', linkedId: null },
      { name: 'remember-device', value: 'true', type: 'boolean', linkedId: null },
      { name: 'linked-username', value: '', type: 'linked', linkedId: 100 }
    ])

    const encryptedFile = await readFile(filePath, 'utf8')
    expect(encryptedFile).not.toContain('test-access-token')
    expect(encryptedFile).not.toContain('test-refresh-token')
    expect(encryptedFile).not.toContain('sync@example.invalid')
    expect(encryptedFile).not.toContain('locally-changed-secret')
    expect(encryptedFile).not.toContain('remote-login.example.invalid')

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    expect((await service.syncStatus()).state).toBe('locked')
    await expect(service.unlockSyncWithLocalPassword(MASTER_PASSWORD)).resolves.toMatchObject({
      configured: true,
      state: 'ready'
    })
  })

  it('persists organization collections and shared items without entering personal sync merge', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        const organizationId = '60000000-0000-4000-8000-000000000001'
        const collectionId = '70000000-0000-4000-8000-000000000001'
        const shared = {
          ...fake.remoteLogins[0]!,
          id: '80000000-0000-4000-8000-000000000001',
          organizationId,
          collectionIds: [collectionId],
          edit: true,
          viewPassword: false,
          delete: true,
          restore: false
        }
        fake.listOrganizations = async () => [
          {
            id: organizationId,
            name: 'Shared Team',
            status: 0,
            type: 0,
            enabled: true,
            identifier: 'shared-team',
            hasPublicAndPrivateKeys: false
          }
        ]
        fake.listCollections = async () => [
          {
            id: collectionId,
            organizationId,
            name: 'Shared Collection',
            externalId: null,
            readOnly: false,
            hidePasswords: false,
            manage: true,
            type: 0,
            assigned: true
          }
        ]
        fake.listOrganizationCiphers = async () => [structuredClone(shared)]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    await expect(service.listOrganizations()).resolves.toEqual([
      expect.objectContaining({ id: '60000000-0000-4000-8000-000000000001' })
    ])
    await expect(service.listCollections()).resolves.toEqual([
      expect.objectContaining({ id: '70000000-0000-4000-8000-000000000001' })
    ])
    const shared = (await service.listSharedLogins())[0]!
    expect(shared).toMatchObject({
      id: '80000000-0000-4000-8000-000000000001',
      organizationId: '60000000-0000-4000-8000-000000000001',
      collectionIds: ['70000000-0000-4000-8000-000000000001'],
      shared: true,
      viewPassword: false,
      delete: true
    })
    expect((await service.listLogins()).map((login) => login.id)).not.toContain(shared.id)
    await expect(service.getSharedLogin({ id: shared.id })).resolves.toMatchObject({
      id: shared.id,
      viewPassword: false,
      username: '',
      hasTotp: false
    })

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    await expect(service.listSharedLogins()).resolves.toHaveLength(1)
  })

  it('manages personal text Sends and keeps an existing password unless explicitly removed', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { copyText, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    const sendId = '50000000-0000-4000-8000-000000000001'
    let remote: BitwardenSendItem = {
      id: sendId,
      accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
      type: 'text',
      name: 'Share note',
      notes: null,
      text: 'secret text',
      hidden: false,
      maxAccessCount: null,
      accessCount: 0,
      revisionDate: '2026-07-16T00:00:00.000Z',
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      disabled: false,
      hideEmail: true,
      authType: 1,
      passwordProtected: true
    }
    fake!.createSend = async (draft) => {
      remote = { ...remote, ...draft, authType: 1, passwordProtected: true }
      return { ...remote }
    }
    fake!.updateSend = async (_id, draft) => {
      expect(draft.password).toBeUndefined()
      remote = { ...remote, ...draft }
      return { ...remote }
    }
    fake!.removeSendPassword = async () => {
      remote = { ...remote, authType: 2, passwordProtected: false }
      return { ...remote }
    }
    fake!.deleteSend = async () => undefined
    fake!.copySendLink = async (_id, copy) => copy('https://vault.example.invalid/#/send/link')

    const created = await service.createSend({
      name: remote.name,
      text: remote.text,
      password: 'send-password',
      deletionDate: remote.deletionDate
    })
    expect(created).toMatchObject({ id: sendId, passwordProtected: true })
    const updated = await service.updateSend({
      id: sendId,
      name: 'Updated note',
      text: remote.text,
      deletionDate: remote.deletionDate
    })
    expect(updated.name).toBe('Updated note')
    expect(updated.passwordProtected).toBe(true)
    await service.copySendLink({ id: sendId })
    expect(copyText).toHaveBeenCalledWith('https://vault.example.invalid/#/send/link')
    const withoutPassword = await service.removeSendPassword({ id: sendId })
    expect(withoutPassword.passwordProtected).toBe(false)
    await service.deleteSend({ id: sendId })
    await expect(service.listSends()).resolves.toEqual([])
  })

  it('creates a file Send from a main-process file selection and clears plaintext after upload', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    let receivedData: Buffer | null = null
    let savedData: Buffer | null = null
    const fileService = {
      chooseOpenFile: async () => ({ fileName: 'report.txt', size: 11 }),
      readSelectedFile: async () => Buffer.from('hello world'),
      chooseSavePath: async () => '/tmp/report.txt',
      write: async (_path: string, contents: Buffer) => {
        savedData = contents
      }
    } as unknown as VaultAttachmentFileService
    const { service } = await createHarness({
      attachmentFiles: fileService,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const remote: BitwardenSendItem = {
      id: '50000000-0000-4000-8000-000000000002',
      accessId: 'UAAAAAAAQABAAAAAAAAAAQ',
      type: 'file',
      name: 'Report Send',
      notes: null,
      text: '',
      file: {
        id: '0123456789abcdef0123456789abcdef',
        fileName: 'report.txt',
        size: 77,
        sizeName: '77 B'
      },
      hidden: false,
      maxAccessCount: null,
      accessCount: 0,
      revisionDate: '2026-07-16T00:00:00.000Z',
      expirationDate: null,
      deletionDate: '2026-07-30T00:00:00.000Z',
      disabled: false,
      hideEmail: true,
      authType: 2,
      passwordProtected: false
    }
    fake!.createFileSend = async (draft) => {
      receivedData = draft.data
      return { ...remote, file: { ...remote.file! } }
    }
    fake!.listSends = async () => [{ ...remote, file: { ...remote.file! } }]
    fake!.downloadFileSend = async () => ({
      fileName: remote.file!.fileName,
      data: Buffer.from('downloaded file')
    })

    const result = await service.createFileSend({
      operationId: ATTACHMENT_OPERATION_ID,
      name: remote.name,
      deletionDate: remote.deletionDate
    })
    expect(result).toMatchObject({ canceled: false, send: { id: remote.id, type: 'file' } })
    const captured = receivedData as Buffer | null
    if (!captured) throw new Error('file bytes were not passed to the connector')
    expect(Array.from(captured).every((byte) => byte === 0)).toBe(true)
    await expect(service.listSends()).resolves.toEqual([
      expect.objectContaining({ id: remote.id, type: 'file', file: remote.file })
    ])
    await expect(service.downloadFileSend({ id: remote.id, password: null })).resolves.toEqual({
      canceled: false,
      fileName: 'report.txt'
    })
    const saved = savedData as Buffer | null
    if (!saved) throw new Error('download bytes were not passed to the file writer')
    expect(Array.from(saved).every((byte) => byte === 0)).toBe(true)
  })

  it('leases encrypted notification credentials and preserves mappings across remote logout', async () => {
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state)
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid/base',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    await expect(service.notificationConnectionInfo()).resolves.toMatchObject({
      notificationsUrl: 'https://vault.example.invalid/base/notifications',
      accessToken: 'test-access-token',
      userId: '90000000-0000-4000-8000-000000000099',
      deviceIdentifier: expect.stringMatching(/^[0-9a-f-]{36}$/)
    })
    expect(await readFile(filePath, 'utf8')).not.toContain('test-access-token')

    await expect(service.remoteLogoutSync()).resolves.toMatchObject({
      configured: true,
      state: 'locked',
      serverUrl: 'https://vault.example.invalid/base'
    })
    await expect(service.notificationConnectionInfo()).resolves.toBeNull()
    expect(await service.listLogins()).toHaveLength(1)

    await expect(
      service.unlockSync({ masterPassword: 'remote master password' })
    ).resolves.toMatchObject({ configured: true, state: 'ready' })
    await expect(service.notificationConnectionInfo()).resolves.toMatchObject({
      accessToken: 'test-access-token-after-logout',
      userId: '90000000-0000-4000-8000-000000000099'
    })
    await expect(service.syncNow()).resolves.toMatchObject({ conflicts: 0 })
    expect(await service.listLogins()).toHaveLength(1)
  })

  it('aborts a late notification-token lease without reviving it after lock', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    let release!: () => void
    const waiting = new Promise<void>((resolve) => {
      release = resolve
    })
    const tokenLease = vi
      .spyOn(fake!, 'notificationAccessToken')
      .mockImplementation(async (signal) => {
        await waiting
        if (signal?.aborted) throw new BitwardenDirectError('ABORTED')
        return 'late-access-token'
      })
    const pending = service.notificationConnectionInfo()
    await vi.waitFor(() => expect(tokenLease).toHaveBeenCalledOnce())

    await service.lock()
    release()
    await expect(pending).resolves.toBeNull()
    await expect(service.status()).resolves.toEqual({ state: 'locked' })
  })

  it('refreshes, canonicalizes, confirms, and encrypts account equivalent-domain settings', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    const initial = await service.getEquivalentDomainSettings()
    expect(initial).toMatchObject({
      equivalentDomains: [['remote.example.invalid', 'remote-login.example.invalid']],
      globalEquivalentDomains: [{ type: 1, domains: ['google.com', 'gmail.com'], excluded: false }],
      revision: expect.stringMatching(/^[0-9a-f]{64}$/)
    })
    const update = vi.spyOn(fake!, 'updateEquivalentDomainSettings')
    const confirmed = await service.updateEquivalentDomainSettings({
      equivalentDomains: [
        [' HTTPS://WWW.Example.CO.UK/path ', 'example.co.uk'],
        ['bücher.example', 'BÜCHER.EXAMPLE'],
        ['127.0.0.1', 'localhost']
      ],
      excludedGlobalEquivalentDomains: [1],
      expectedRevision: initial.revision
    })

    expect(update).toHaveBeenCalledWith(
      {
        equivalentDomains: [['example.co.uk'], ['bücher.example'], ['127.0.0.1', 'localhost']],
        excludedGlobalEquivalentDomains: [1]
      },
      expect.any(AbortSignal)
    )
    expect(confirmed).toMatchObject({
      equivalentDomains: [['example.co.uk'], ['bücher.example'], ['127.0.0.1', 'localhost']],
      globalEquivalentDomains: [{ type: 1, domains: ['google.com', 'gmail.com'], excluded: true }],
      revision: expect.stringMatching(/^[0-9a-f]{64}$/)
    })
    expect(confirmed.revision).not.toBe(initial.revision)

    const encrypted = await readFile(filePath, 'utf8')
    expect(encrypted).not.toContain('example.co.uk')
    expect(encrypted).not.toContain('bücher.example')
  })

  it('rejects stale or unknown equivalent-domain replacements before writing', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const initial = await service.getEquivalentDomainSettings()
    const update = vi.spyOn(fake!, 'updateEquivalentDomainSettings')
    vi.spyOn(fake!, 'getEquivalentDomainSettings').mockResolvedValueOnce({
      equivalentDomains: [['changed.example.invalid']],
      globalEquivalentDomains: [{ type: 1, domains: ['google.com', 'gmail.com'], excluded: false }]
    })

    await expect(
      service.updateEquivalentDomainSettings({
        equivalentDomains: [['one.example.invalid']],
        excludedGlobalEquivalentDomains: [],
        expectedRevision: initial.revision
      })
    ).rejects.toMatchObject({ code: 'SYNC_CONFLICT' })
    expect(update).not.toHaveBeenCalled()

    const refreshed = await service.getEquivalentDomainSettings()
    await expect(
      service.updateEquivalentDomainSettings({
        equivalentDomains: [['one.example.invalid']],
        excludedGlobalEquivalentDomains: [999],
        expectedRevision: refreshed.revision
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(update).not.toHaveBeenCalled()
  })

  it('aborts an equivalent-domain refresh when the local vault locks', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    let started!: () => void
    const didStart = new Promise<void>((resolve) => {
      started = resolve
    })
    vi.spyOn(fake!, 'getEquivalentDomainSettings').mockImplementation(
      (signal) =>
        new Promise((_resolve, reject) => {
          started()
          signal?.addEventListener('abort', () => reject(new BitwardenDirectError('ABORTED')), {
            once: true
          })
        })
    )

    const pending = service.getEquivalentDomainSettings()
    const rejection = expect(pending).rejects.toMatchObject({ code: 'LOCKED' })
    await didStart
    await expect(service.lock()).resolves.toEqual({ state: 'locked' })
    await rejection
  })

  it('deletes one passkey atomically without returning private key material', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!
    const before = await service.getLogin({ id: login.id })

    const updated = await service.deletePasskey({
      id: login.id,
      credentialId: 'credential-id',
      expectedUpdatedAt: before.updatedAt
    })

    expect(updated.passkeys).toEqual([])
    expect(updated.updatedAt).not.toBe(before.updatedAt)
    expect(JSON.stringify(updated)).not.toContain('fake-passkey-private-material')
    await service.syncNow()
    expect(fake!.remoteLogins[0]!.passkeys).toEqual([])
    await service.lock()
    const reopened = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.getLogin({ id: login.id })).resolves.toMatchObject({ passkeys: [] })
  })

  it('rejects stale, missing, and ambiguous passkey deletion without changing the item', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.passkeys.push({ ...fake.remoteLogins[0]!.passkeys[0]! })
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!
    const before = await service.getLogin({ id: login.id })
    const write = vi.spyOn(store, 'write')

    await expect(
      service.deletePasskey({
        id: login.id,
        credentialId: 'credential-id',
        expectedUpdatedAt: '2026-01-01T00:00:00.000Z'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.deletePasskey({ id: login.id, credentialId: 'missing-credential' })
    ).rejects.toMatchObject({ code: 'NOT_FOUND' })
    await expect(
      service.deletePasskey({ id: login.id, credentialId: 'credential-id' })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(write).not.toHaveBeenCalled()
    await expect(service.getLogin({ id: login.id })).resolves.toEqual(before)
  })

  it('keeps a passkey when persistence fails during deletion', async () => {
    const { service, store } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state)
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins())[0]!
    vi.spyOn(store, 'write').mockRejectedValueOnce(new Error('injected persistence failure'))

    await expect(
      service.deletePasskey({ id: login.id, credentialId: 'credential-id' })
    ).rejects.toThrow('injected persistence failure')
    await expect(service.getLogin({ id: login.id })).resolves.toMatchObject({
      passkeys: [expect.objectContaining({ credentialId: 'credential-id' })]
    })
  })

  it('creates one passkey inside the authorized vault transaction and syncs it safely', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Passkey login',
      username: '',
      reprompt: 1
    })
    const generation = await service.unlockedGeneration()
    const authorize = vi.fn<PasskeyVaultAuthorizationValidator>(() => true)

    await expect(
      createVaultPasskey(service, login, {
        userVerified: false,
        requireUserVerification: true
      })
    ).rejects.toMatchObject({ code: 'REPROMPT_REQUIRED' })
    await expect(
      createVaultPasskey(
        service,
        login,
        { userVerified: true },
        vi.fn<PasskeyVaultAuthorizationValidator>(() => false)
      )
    ).rejects.toMatchObject({ code: 'REPROMPT_REQUIRED' })

    const created = await createVaultPasskey(
      service,
      login,
      { userVerified: true, requireUserVerification: true },
      authorize
    )

    expect(authorize).toHaveBeenCalledWith([login.id], { generation })
    expect(created.generation).toBe(generation)
    expect(created.publicKeyAlgorithm).toBe(-7)
    expect(created.item).toMatchObject({
      id: login.id,
      username: 'test-user',
      passkeys: [
        expect.objectContaining({
          credentialId: IDS[1],
          rpId: PASSKEY_RP_ID,
          discoverable: true
        })
      ]
    })
    expect(created.credentialId).toEqual(
      Uint8Array.from(Buffer.from(IDS[1]!.replaceAll('-', ''), 'hex'))
    )
    expect(JSON.stringify(created)).not.toContain('keyValue')
    expect(JSON.stringify(created)).not.toContain('PRIVATE KEY')

    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const pushed = fake!.remoteLogins.find((item) => item.name === 'Passkey login')
    expect(pushed?.passkeys).toHaveLength(1)
    expect(pushed?.passkeys[0]).toMatchObject({
      credentialId: IDS[1],
      rpId: PASSKEY_RP_ID,
      keyAlgorithm: 'ECDSA',
      keyCurve: 'P-256'
    })

    await service.lock()
    const reopened = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await reopened.unlock(MASTER_PASSWORD)
    const persisted = await reopened.discoverPasskeyCredentials({ rpId: PASSKEY_RP_ID })
    expect(persisted.credentials).toHaveLength(1)
    expect(JSON.stringify(persisted)).not.toContain('keyValue')
  })

  it('enforces exclude credentials, stale revisions, replacement intent, and one-passkey storage', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const first = await service.createLogin({ name: 'First login' })
    const firstPasskey = await createVaultPasskey(service, first)
    await service.archiveLogin({ id: first.id })

    const second = await service.createLogin({ name: 'Second login' })
    const secondPasskey = await createVaultPasskey(service, second, {
      excludeCredentialIds: [firstPasskey.credentialId]
    })
    const third = await service.createLogin({ name: 'Third login' })
    const write = vi.spyOn(store, 'write')

    await expect(
      createVaultPasskey(service, third, {
        excludeCredentialIds: [secondPasskey.credentialId]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      createVaultPasskey(service, secondPasskey.item, { replaceExisting: false })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      createVaultPasskey(service, secondPasskey.item, {
        expectedUpdatedAt: '2026-01-01T00:00:00.000Z',
        replaceExisting: true
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(write).not.toHaveBeenCalled()

    const replacement = await createVaultPasskey(service, secondPasskey.item, {
      replaceExisting: true
    })
    expect(replacement.item.passkeys).toHaveLength(1)
    expect(replacement.item.passkeys[0]!.credentialId).not.toBe(
      secondPasskey.item.passkeys[0]!.credentialId
    )
  })

  it('rolls back passkey creation when encrypted persistence fails', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Passkey login' })
    vi.spyOn(store, 'write').mockRejectedValueOnce(new Error('injected persistence failure'))

    await expect(createVaultPasskey(service, login)).rejects.toThrow('injected persistence failure')
    await expect(service.getLogin({ id: login.id })).resolves.toMatchObject({ passkeys: [] })
    await expect(
      service.discoverPasskeyCredentials({ rpId: PASSKEY_RP_ID })
    ).resolves.toMatchObject({ credentials: [] })
  })

  it('discovers renderer-safe atomic passkey creation targets from raw active login data', async () => {
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        const fake = createSyncFake(sync.state)
        const protectedLogin = fake.remoteLogins[0]!
        protectedLogin.name = 'Protected one-passkey login'
        protectedLogin.reprompt = 1
        protectedLogin.uri = 'https://remote.example.com'
        protectedLogin.uris = [{ uri: protectedLogin.uri, match: null }]
        fake.getEquivalentDomainSettings = async () => ({
          equivalentDomains: [['example.com', 'example.net']],
          globalEquivalentDomains: []
        })

        const noPasskey = structuredClone(protectedLogin)
        noPasskey.id = '90000000-0000-4000-8000-000000000005'
        noPasskey.name = 'Zero-passkey login'
        noPasskey.reprompt = 0
        noPasskey.passkeys = []
        noPasskey.uri = 'https://remote-login.example.net'
        noPasskey.uris = [{ uri: noPasskey.uri, match: null }]

        const unrelated = structuredClone(noPasskey)
        unrelated.id = '90000000-0000-4000-8000-000000000010'
        unrelated.name = 'Unrelated active login'
        unrelated.uri = 'https://unrelated.test'
        unrelated.uris = [{ uri: unrelated.uri, match: null }]

        const neverMatch = structuredClone(noPasskey)
        neverMatch.id = '90000000-0000-4000-8000-000000000011'
        neverMatch.name = 'Explicit never-match login'
        neverMatch.uri = 'https://remote.example.com'
        neverMatch.uris = [{ uri: neverMatch.uri, match: 5 }]

        const archived = structuredClone(protectedLogin)
        archived.id = '90000000-0000-4000-8000-000000000006'
        archived.archivedAt = '2026-07-14T01:00:00.000Z'

        const deleted = structuredClone(protectedLogin)
        deleted.id = '90000000-0000-4000-8000-000000000007'
        deleted.deletedAt = '2026-07-14T01:00:00.000Z'

        const nonLogin = structuredClone(protectedLogin)
        nonLogin.id = '90000000-0000-4000-8000-000000000008'
        nonLogin.type = 'card'

        const multiplePasskeys = structuredClone(protectedLogin)
        multiplePasskeys.id = '90000000-0000-4000-8000-000000000009'
        multiplePasskeys.name = 'Legacy multiple-passkey login'
        multiplePasskeys.passkeys = [
          structuredClone(protectedLogin.passkeys[0]!),
          structuredClone(protectedLogin.passkeys[0]!)
        ]

        fake.remoteLogins.push(
          noPasskey,
          unrelated,
          neverMatch,
          archived,
          deleted,
          nonLogin,
          multiplePasskeys
        )
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    const protectedItem = (await service.listLogins()).find(
      (item) => item.name === 'Protected one-passkey login'
    )
    const noPasskeyItem = (await service.listLogins()).find(
      (item) => item.name === 'Zero-passkey login'
    )
    if (!protectedItem || !noPasskeyItem) throw new Error('missing synced creation target')
    const generation = await service.unlockedGeneration()
    const discoveryRequest = {
      rpId: 'remote.example.com',
      origin: 'https://remote.example.com'
    }
    const discovered = await service.discoverPasskeyCreationTargets(discoveryRequest)

    expect(discovered.generation).toBe(generation)
    expect(discovered.targets).toEqual([
      {
        itemId: protectedItem.id,
        itemName: 'Protected one-passkey login',
        itemUpdatedAt: expect.any(String),
        reprompt: 1,
        existingPasskeyCount: 1
      },
      {
        itemId: noPasskeyItem.id,
        itemName: 'Zero-passkey login',
        itemUpdatedAt: expect.any(String),
        reprompt: 0,
        existingPasskeyCount: 0
      }
    ])
    expect(Object.keys(discovered.targets[0]!).sort()).toEqual([
      'existingPasskeyCount',
      'itemId',
      'itemName',
      'itemUpdatedAt',
      'reprompt'
    ])
    const serialized = JSON.stringify(discovered)
    expect(serialized).not.toContain('fake-passkey-private-material')
    expect(serialized).not.toContain('credential-id')
    expect(serialized).not.toContain('remote-test-secret')
    expect(serialized).not.toContain('keyValue')

    discovered.targets[0]!.itemName = 'mutated caller snapshot'
    const rediscovered = await service.discoverPasskeyCreationTargets(discoveryRequest)
    expect(rediscovered.generation).toBe(generation)
    expect(rediscovered.targets[0]).toMatchObject({ itemName: 'Protected one-passkey login' })
    await expect(
      service.discoverPasskeyCreationTargets({
        rpId: 'remote.example.com',
        origin: 'https://unrelated.test'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    await service.lock()
    await expect(service.discoverPasskeyCreationTargets(discoveryRequest)).rejects.toMatchObject({
      code: 'LOCKED'
    })
  })

  it('discovers exact-RP UUID and b64 IDs while excluding archived, deleted, and non-login items', async () => {
    const b64Id = Buffer.alloc(32, 0xa5)
    const uuidId = '52217b91-73f1-4fea-b3f2-54a7959fd5aa'
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        const fake = createSyncFake(sync.state)
        const base = fake.remoteLogins[0]!
        base.name = 'Discoverable b64'
        base.passkeys[0]!.credentialId = `b64.${b64Id.toString('base64url')}`
        base.passkeys[0]!.rpId = PASSKEY_RP_ID
        base.passkeys[0]!.discoverable = true

        const nonDiscoverable = structuredClone(base)
        nonDiscoverable.id = '90000000-0000-4000-8000-000000000005'
        nonDiscoverable.name = 'Allowed UUID'
        nonDiscoverable.passkeys[0]!.credentialId = uuidId
        nonDiscoverable.passkeys[0]!.discoverable = false
        const archived = structuredClone(base)
        archived.id = '90000000-0000-4000-8000-000000000006'
        archived.archivedAt = '2026-07-14T01:00:00.000Z'
        const deleted = structuredClone(base)
        deleted.id = '90000000-0000-4000-8000-000000000007'
        deleted.deletedAt = '2026-07-14T01:00:00.000Z'
        const card = structuredClone(base)
        card.id = '90000000-0000-4000-8000-000000000008'
        card.type = 'card'
        fake.remoteLogins.push(nonDiscoverable, archived, deleted, card)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    const discoverable = await service.discoverPasskeyCredentials({ rpId: PASSKEY_RP_ID })
    expect(discoverable.credentials).toHaveLength(1)
    expect(discoverable.credentials[0]).toMatchObject({
      itemName: 'Discoverable b64',
      credentialId: Uint8Array.from(b64Id),
      discoverable: true
    })
    const allowed = await service.discoverPasskeyCredentials({
      rpId: PASSKEY_RP_ID,
      allowCredentialIds: [Buffer.from(uuidId.replaceAll('-', ''), 'hex')]
    })
    expect(allowed.credentials).toHaveLength(1)
    expect(allowed.credentials[0]).toMatchObject({
      itemName: 'Allowed UUID',
      credentialId: Uint8Array.from(Buffer.from(uuidId.replaceAll('-', ''), 'hex')),
      discoverable: false
    })
    await expect(
      service.discoverPasskeyCredentials({ rpId: 'other.example.invalid' })
    ).resolves.toMatchObject({ credentials: [] })
    expect(JSON.stringify(discoverable)).not.toContain('fake-passkey-private-material')
  })

  it('fails closed when an exact-RP credential ID is ambiguous', async () => {
    const rawId = Buffer.alloc(24, 0x6c)
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        const fake = createSyncFake(sync.state)
        const base = fake.remoteLogins[0]!
        base.passkeys[0]!.credentialId = `b64.${rawId.toString('base64url')}`
        base.passkeys[0]!.rpId = PASSKEY_RP_ID
        const duplicate = structuredClone(base)
        duplicate.id = '90000000-0000-4000-8000-000000000005'
        duplicate.name = 'Duplicate credential'
        duplicate.passkeys[0]!.discoverable = false
        fake.remoteLogins.push(duplicate)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    await expect(service.discoverPasskeyCredentials({ rpId: PASSKEY_RP_ID })).rejects.toMatchObject(
      { code: 'INVALID_INPUT' }
    )
  })

  it('signs a verifiable assertion and atomically persists a non-zero counter', async () => {
    const softwareCredential = await createPasskeyCredential(
      {
        rpId: PASSKEY_RP_ID,
        rpName: 'Example',
        userHandle: Buffer.from('opaque-test-user-handle'),
        userName: 'test-user',
        userDisplayName: 'Test User',
        discoverable: false,
        userVerified: true
      },
      {
        uuid: () => '52217b91-73f1-4fea-b3f2-54a7959fd5aa',
        now: () => new Date('2026-07-14T00:00:00.000Z')
      }
    )
    softwareCredential.credential.counter = '7'
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.passkeys = [structuredClone(softwareCredential.credential)]
        fake.remoteLogins[0]!.reprompt = 1
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const login = (await service.listLogins()).find((item) => item.name === 'Remote login')!
    const view = await service.getLogin({ id: login.id })
    const generation = await service.unlockedGeneration()
    const clientDataHash = Buffer.alloc(32, 0x42)
    const authorize = vi.fn<PasskeyVaultAuthorizationValidator>(() => true)

    await expect(
      service.discoverPasskeyCredentials({ rpId: PASSKEY_RP_ID })
    ).resolves.toMatchObject({ credentials: [] })
    await expect(
      service.getPasskeyAssertion(
        {
          itemId: view.id,
          credentialId: softwareCredential.credentialId,
          expectedUpdatedAt: view.updatedAt,
          expectedGeneration: generation,
          rpId: PASSKEY_RP_ID,
          clientDataHash,
          requireUserVerification: true,
          userVerified: true
        },
        authorize
      )
    ).rejects.toMatchObject({ code: 'NOT_FOUND' })

    const assertion = await service.getPasskeyAssertion(
      {
        itemId: view.id,
        credentialId: softwareCredential.credentialId,
        expectedUpdatedAt: view.updatedAt,
        expectedGeneration: generation,
        rpId: PASSKEY_RP_ID,
        clientDataHash,
        allowCredentialIds: [softwareCredential.credentialId],
        requireUserVerification: true,
        userVerified: true
      },
      authorize
    )

    expect(authorize).toHaveBeenCalledWith([view.id], { generation })
    expect(assertion.counter).toBe('8')
    expect(assertion.didPersistCounter).toBe(true)
    expect(Buffer.from(assertion.authenticatorData).readUInt32BE(33)).toBe(8)
    expect(JSON.stringify(assertion)).not.toContain('keyValue')
    expect(
      verify(
        'sha256',
        Buffer.concat([Buffer.from(assertion.authenticatorData), clientDataHash]),
        createPublicKey({
          key: Buffer.from(softwareCredential.publicKey),
          format: 'der',
          type: 'spki'
        }),
        Buffer.from(assertion.signature)
      )
    ).toBe(true)

    await service.syncNow()
    expect(fake!.remoteLogins[0]!.passkeys[0]!.counter).toBe('8')
    await service.lock()
    const reopened = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await reopened.unlock(MASTER_PASSWORD)
    const persisted = await reopened.discoverPasskeyCredentials({
      rpId: PASSKEY_RP_ID,
      allowCredentialIds: [softwareCredential.credentialId]
    })
    const persistedCredential = persisted.credentials[0]!
    const nextAssertion = await reopened.getPasskeyAssertion(
      {
        itemId: persistedCredential.itemId,
        credentialId: persistedCredential.credentialId,
        expectedUpdatedAt: persistedCredential.itemUpdatedAt,
        expectedGeneration: persisted.generation,
        rpId: PASSKEY_RP_ID,
        clientDataHash: Buffer.alloc(32, 0x43),
        allowCredentialIds: [persistedCredential.credentialId],
        requireUserVerification: false,
        userVerified: false
      },
      () => true
    )
    expect(nextAssertion.counter).toBe('9')
  })

  it('does not persist a disabled zero counter after assertion', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Zero counter login' })
    const created = await createVaultPasskey(service, login)
    const write = vi.spyOn(store, 'write')

    const assertion = await service.getPasskeyAssertion(
      {
        itemId: created.item.id,
        credentialId: created.credentialId,
        expectedUpdatedAt: created.item.updatedAt,
        expectedGeneration: created.generation,
        rpId: PASSKEY_RP_ID,
        clientDataHash: Buffer.alloc(32, 0x44),
        allowCredentialIds: [created.credentialId],
        requireUserVerification: false,
        userVerified: false
      },
      () => true
    )

    expect(assertion.counter).toBe('0')
    expect(assertion.didPersistCounter).toBe(false)
    expect(Buffer.from(assertion.authenticatorData).readUInt32BE(33)).toBe(0)
    expect(write).not.toHaveBeenCalled()
    await expect(service.getLogin({ id: login.id })).resolves.toMatchObject({
      updatedAt: created.item.updatedAt
    })
  })

  it('rolls back failed counter persistence and rejects stale unlock epochs', async () => {
    const softwareCredential = await createPasskeyCredential(
      {
        rpId: PASSKEY_RP_ID,
        rpName: 'Example',
        userHandle: Buffer.from('opaque-test-user-handle'),
        userName: 'test-user',
        userDisplayName: 'Test User',
        discoverable: true,
        userVerified: false
      },
      {
        uuid: () => '52217b91-73f1-4fea-b3f2-54a7959fd5aa',
        now: () => new Date('2026-07-14T00:00:00.000Z')
      }
    )
    softwareCredential.credential.counter = '3'
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        const fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.passkeys = [structuredClone(softwareCredential.credential)]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const discovered = await service.discoverPasskeyCredentials({
      rpId: PASSKEY_RP_ID,
      allowCredentialIds: [softwareCredential.credentialId]
    })
    const selected = discovered.credentials[0]!
    const request = {
      itemId: selected.itemId,
      credentialId: selected.credentialId,
      expectedUpdatedAt: selected.itemUpdatedAt,
      expectedGeneration: discovered.generation,
      rpId: PASSKEY_RP_ID,
      clientDataHash: Buffer.alloc(32, 0x45),
      allowCredentialIds: [selected.credentialId],
      requireUserVerification: false,
      userVerified: false
    }
    const write = vi
      .spyOn(store, 'write')
      .mockRejectedValueOnce(new Error('injected persistence failure'))

    await expect(service.getPasskeyAssertion(request, () => true)).rejects.toThrow(
      'injected persistence failure'
    )
    write.mockRestore()
    const retry = await service.getPasskeyAssertion(request, () => true)
    expect(retry.counter).toBe('4')

    const beforeLock = await service.discoverPasskeyCredentials({
      rpId: PASSKEY_RP_ID,
      allowCredentialIds: [softwareCredential.credentialId]
    })
    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    await expect(
      service.getPasskeyAssertion(
        {
          ...request,
          expectedUpdatedAt: beforeLock.credentials[0]!.itemUpdatedAt,
          expectedGeneration: beforeLock.generation
        },
        () => true
      )
    ).rejects.toMatchObject({ code: 'LOCKED' })
  })

  it('does not publish an assertion when the vault is disposed during counter commit', async () => {
    const softwareCredential = await createPasskeyCredential(
      {
        rpId: PASSKEY_RP_ID,
        rpName: 'Example',
        userHandle: Buffer.from('opaque-test-user-handle'),
        userName: 'test-user',
        userDisplayName: 'Test User',
        discoverable: true,
        userVerified: false
      },
      {
        uuid: () => '52217b91-73f1-4fea-b3f2-54a7959fd5aa',
        now: () => new Date('2026-07-14T00:00:00.000Z')
      }
    )
    softwareCredential.credential.counter = '11'
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        const fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.passkeys = [structuredClone(softwareCredential.credential)]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const discovered = await service.discoverPasskeyCredentials({
      rpId: PASSKEY_RP_ID,
      allowCredentialIds: [softwareCredential.credentialId]
    })
    const selected = discovered.credentials[0]!
    vi.spyOn(store, 'write').mockImplementationOnce(async () => {
      service.dispose()
    })

    await expect(
      service.getPasskeyAssertion(
        {
          itemId: selected.itemId,
          credentialId: selected.credentialId,
          expectedUpdatedAt: selected.itemUpdatedAt,
          expectedGeneration: discovered.generation,
          rpId: PASSKEY_RP_ID,
          clientDataHash: Buffer.alloc(32, 0x46),
          allowCredentialIds: [selected.credentialId],
          requireUserVerification: false,
          userVerified: false
        },
        () => true
      )
    ).rejects.toMatchObject({ code: 'LOCKED' })
    await service.unlock(MASTER_PASSWORD)
    const unchanged = await service.discoverPasskeyCredentials({
      rpId: PASSKEY_RP_ID,
      allowCredentialIds: [softwareCredential.credentialId]
    })
    expect(unchanged.credentials[0]!.itemUpdatedAt).toBe(selected.itemUpdatedAt)
  })

  it('reconciles attachment-only remote changes without creating item conflicts', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.remoteLogins[0]!.attachments = [
      {
        id: 'attachment-id',
        fileName: 'remote-document.txt',
        size: 12,
        sizeName: '12 B',
        legacy: false
      }
    ]
    fake!.remoteLogins[0]!.revisionDate = '2026-07-14T04:00:00.000Z'

    await expect(service.syncNow()).resolves.toMatchObject({
      pulled: 0,
      pushed: 0,
      deleted: 0,
      conflicts: 0
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      updatedAt: '2026-07-14T04:00:00.000Z',
      attachmentCount: 1,
      attachments: [
        {
          id: 'attachment-id',
          fileName: 'remote-document.txt',
          size: 12,
          sizeName: '12 B',
          legacy: false
        }
      ]
    })
    expect((await service.listLogins())[0]?.attachmentCount).toBe(1)
    expect(await readFile(filePath, 'utf8')).not.toContain('remote-document.txt')

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachmentCount: 1,
      attachments: [expect.objectContaining({ fileName: 'remote-document.txt' })]
    })
  })

  it('downloads an attachment through a main-only picker and clears plaintext memory', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-download-test-'))
    temporaryDirectories.push(directory)
    const destination = join(directory, 'saved-document.txt')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => destination)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    let clearText: Buffer | undefined
    fake!.downloadAttachment = async () => {
      clearText = Buffer.from('fake attachment contents')
      return { fileName: 'document.txt', data: clearText }
    }

    await expect(
      service.downloadAttachment({
        id: local.id,
        attachmentId: 'attachment-id',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toEqual({ canceled: false, fileName: 'document.txt' })
    expect(await readFile(destination, 'utf8')).toBe('fake attachment contents')
    expect(clearText).toEqual(Buffer.alloc('fake attachment contents'.length))
    if (process.platform !== 'win32') expect((await stat(destination)).mode & 0o777).toBe(0o600)
  })

  it('writes streamed attachment plaintext and disposes its encrypted spool', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-download-stream-test-'))
    temporaryDirectories.push(directory)
    const destination = join(directory, 'streamed-document.txt')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => destination)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const dispose = vi.fn(async () => undefined)
    const streamedContents = 'fake streamed attachment contents'
    fake!.downloadAttachmentStream = vi.fn(async () => ({
      fileName: 'document.txt',
      data: {
        size: Buffer.byteLength(streamedContents),
        async *chunks() {
          yield Buffer.from('fake streamed ')
          yield Buffer.from('attachment contents')
        }
      },
      dispose
    }))

    await expect(
      service.downloadAttachment({
        id: local.id,
        attachmentId: 'attachment-id',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toEqual({ canceled: false, fileName: 'document.txt' })
    expect(await readFile(destination, 'utf8')).toBe(streamedContents)
    expect(fake!.downloadAttachmentStream).toHaveBeenCalledOnce()
    expect(dispose).toHaveBeenCalledOnce()
  })

  it('preflights native backup sizes, re-downloads for offset resume, and aborts on lock', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 99,
            sizeName: '99 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const produced: Buffer[] = []
    const dispose = vi.fn(async () => undefined)
    fake!.downloadAttachmentStream = vi.fn(async () => ({
      fileName: 'document.txt',
      data: {
        size: 6,
        async *chunks() {
          const first = Buffer.from('abc')
          const second = Buffer.from('def')
          produced.push(first, second)
          yield first
          yield second
        }
      },
      dispose
    }))

    const source = await service.createNativeAttachmentBackupSource(MASTER_PASSWORD)
    expect(source.attachments).toEqual([
      expect.objectContaining({ id: 'attachment-id', fileName: 'document.txt', size: 6 })
    ])
    expect(produced).toEqual([Buffer.alloc(3), Buffer.alloc(3)])

    const resumed: Buffer[] = []
    for await (const chunk of source.openAttachment(source.attachments[0]!, 3)) {
      resumed.push(Buffer.from(chunk))
      chunk.fill(0)
    }
    expect(Buffer.concat(resumed).toString()).toBe('def')
    expect(fake!.downloadAttachmentStream).toHaveBeenCalledTimes(2)
    expect(produced).toEqual([Buffer.alloc(3), Buffer.alloc(3), Buffer.alloc(3), Buffer.alloc(3)])

    await service.lock()
    await expect(async () => {
      for await (const chunk of source.openAttachment(source.attachments[0]!, 0)) chunk.fill(0)
    }).rejects.toMatchObject({ code: 'LOCKED' })
    source.dispose()
    expect(dispose).toHaveBeenCalledTimes(2)
  })

  it('rejects a native backup when a verified download changes its file name', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'expected.txt',
            size: 16,
            sizeName: '16 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    fake!.downloadAttachmentStream = vi.fn(async () => ({
      fileName: 'unexpected.txt',
      data: {
        size: 0,
        async *chunks(signal?: AbortSignal) {
          if (signal?.aborted) yield Buffer.alloc(0)
        }
      },
      dispose: vi.fn(async () => undefined)
    }))

    await expect(service.createNativeAttachmentBackupSource(MASTER_PASSWORD)).rejects.toMatchObject(
      { code: 'ATTACHMENT_FAILED' }
    )
  })

  it('cancels before downloading when the main-process save picker is dismissed', async () => {
    const chooseSavePath = vi.fn(async () => null)
    const attachmentFiles = new VaultAttachmentFileService({ chooseSavePath })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const downloadAttachment = vi.fn(fake!.downloadAttachment)
    fake!.downloadAttachment = downloadAttachment

    await expect(
      service.downloadAttachment({
        id: local.id,
        attachmentId: 'attachment-id',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toEqual({ canceled: true, fileName: 'document.txt' })
    expect(chooseSavePath).toHaveBeenCalledWith('document.txt')
    expect(downloadAttachment).not.toHaveBeenCalled()
  })

  it('allows lock to clear the vault while the native save picker remains open', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-download-picker-lock-'))
    temporaryDirectories.push(directory)
    const destination = join(directory, 'must-not-be-written.txt')
    let resolvePicker!: (path: string | null) => void
    const picker = new Promise<string | null>((resolve) => {
      resolvePicker = resolve
    })
    const chooseSavePath = vi.fn(() => picker)
    const attachmentFiles = new VaultAttachmentFileService({ chooseSavePath })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const download = service.downloadAttachment({
      id: local.id,
      attachmentId: 'attachment-id',
      operationId: ATTACHMENT_OPERATION_ID
    })
    await vi.waitFor(() => expect(chooseSavePath).toHaveBeenCalledOnce())

    const lockOutcome = await Promise.race([
      service.lock(),
      new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 250))
    ])
    expect(lockOutcome).toEqual({ state: 'locked' })
    resolvePicker(destination)
    await expect(download).rejects.toMatchObject({ code: 'LOCKED' })
    expect(fake!.downloadedAttachmentIds).toEqual([])
    expect(await readdir(directory)).toEqual([])
  })

  it('aborts an attachment download before lock and leaves no partial plaintext file', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-download-abort-'))
    temporaryDirectories.push(directory)
    const destination = join(directory, 'should-not-exist.txt')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => destination)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'attachment-id',
            fileName: 'document.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    let started!: () => void
    const didStart = new Promise<void>((resolve) => {
      started = resolve
    })
    fake!.downloadAttachment = async (_id, _attachmentId, signal) => {
      started()
      return new Promise<never>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new BitwardenDirectError('ABORTED')), {
          once: true
        })
      })
    }

    const download = service.downloadAttachment({
      id: local.id,
      attachmentId: 'attachment-id',
      operationId: ATTACHMENT_OPERATION_ID
    })
    await didStart
    const lock = service.lock()
    await expect(download).rejects.toMatchObject({ code: 'LOCKED' })
    await expect(lock).resolves.toEqual({ state: 'locked' })
    expect(await readdir(directory)).toEqual([])
  })

  it('uploads a main-only selected file, reconciles metadata, reports progress, and clears plaintext', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-test-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'upload.txt')
    await writeFile(source, 'fake upload contents')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    const readSelectedFile = attachmentFiles.readSelectedFile.bind(attachmentFiles)
    let clearText: Buffer | undefined
    vi.spyOn(attachmentFiles, 'readSelectedFile').mockImplementation(async (selection, signal) => {
      clearText = await readSelectedFile(selection, signal)
      return clearText
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const progress: string[] = []

    await expect(
      service.uploadAttachment({ id: local.id, operationId: ATTACHMENT_OPERATION_ID }, (event) =>
        progress.push(event.stage)
      )
    ).resolves.toMatchObject({
      canceled: false,
      attachment: { fileName: 'upload.txt', legacy: false }
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachments: [expect.objectContaining({ fileName: 'upload.txt', legacy: false })]
    })
    expect(progress).toEqual([
      'choosing-file',
      'reading-file',
      'reading-file',
      'encrypting',
      'uploading',
      'uploading',
      'syncing'
    ])
    expect(clearText).toEqual(Buffer.alloc('fake upload contents'.length))
    expect(fake!.remoteLogins[0]!.attachments).toHaveLength(1)
  })

  it('passes a bounded file source to streamed attachment upload', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-stream-test-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'streamed.txt')
    await writeFile(source, 'streamed upload contents')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    const readSelectedFile = vi.spyOn(attachmentFiles, 'readSelectedFile')
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.uploadAttachmentStream = vi.fn(async (id, fileName, source, signal, onCommitted) => {
      const chunks: Buffer[] = []
      for await (const chunk of source.chunks(signal)) chunks.push(Buffer.from(chunk))
      return fake!.uploadAttachment(id, fileName, Buffer.concat(chunks), signal, onCommitted)
    })

    await expect(
      service.uploadAttachment({ id: local.id, operationId: ATTACHMENT_OPERATION_ID })
    ).resolves.toMatchObject({
      canceled: false,
      attachment: { fileName: 'streamed.txt', legacy: false }
    })
    expect(fake!.uploadAttachmentStream).toHaveBeenCalledOnce()
    expect(readSelectedFile).not.toHaveBeenCalled()
  })

  it('allows lock to clear the vault while the native upload picker remains open', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-picker-lock-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'must-not-upload.txt')
    await writeFile(source, 'must not upload')
    let resolvePicker!: (path: string | null) => void
    const picker = new Promise<string | null>((resolve) => {
      resolvePicker = resolve
    })
    const chooseOpenFile = vi.fn(() => picker)
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const uploadAttachment = vi.fn(fake!.uploadAttachment)
    fake!.uploadAttachment = uploadAttachment
    const upload = service.uploadAttachment({
      id: local.id,
      operationId: ATTACHMENT_OPERATION_ID
    })
    await vi.waitFor(() => expect(chooseOpenFile).toHaveBeenCalledOnce())

    await expect(service.lock()).resolves.toEqual({ state: 'locked' })
    resolvePicker(source)
    await expect(upload).rejects.toMatchObject({ code: 'LOCKED' })
    expect(uploadAttachment).not.toHaveBeenCalled()
  })

  it('revalidates attachment reprompt authorization after the native picker closes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-reprompt-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'protected.txt')
    await writeFile(source, 'protected upload')
    let resolvePicker!: (path: string | null) => void
    const picker = new Promise<string | null>((resolve) => {
      resolvePicker = resolve
    })
    const chooseOpenFile = vi.fn(() => picker)
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.reprompt = 1
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const uploadAttachment = vi.fn(fake!.uploadAttachment)
    fake!.uploadAttachment = uploadAttachment
    let validations = 0
    const upload = service.uploadAttachment(
      { id: local.id, operationId: ATTACHMENT_OPERATION_ID },
      undefined,
      () => ++validations === 1
    )
    await vi.waitFor(() => expect(chooseOpenFile).toHaveBeenCalledOnce())

    resolvePicker(source)
    await expect(upload).rejects.toMatchObject({ code: 'REPROMPT_REQUIRED' })
    expect(validations).toBe(2)
    expect(uploadAttachment).not.toHaveBeenCalled()
  })

  it('deletes and fixes attachments only after server-authoritative reconciliation', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'modern-attachment',
            fileName: 'modern.txt',
            size: 12,
            sizeName: '12 B',
            legacy: false
          },
          {
            id: 'legacy-attachment',
            fileName: 'legacy.txt',
            size: 13,
            sizeName: '13 B',
            legacy: true
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!

    await expect(
      service.deleteAttachment({
        id: local.id,
        attachmentId: 'modern-attachment',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toEqual({ attachmentId: 'modern-attachment' })
    await expect(
      service.fixLegacyAttachment({
        id: local.id,
        attachmentId: 'legacy-attachment',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).resolves.toMatchObject({
      attachment: { id: 'fixed-legacy-attachment', fileName: 'legacy.txt', legacy: false }
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachments: [{ id: 'fixed-legacy-attachment', fileName: 'legacy.txt', legacy: false }]
    })
    await expect(
      service.fixLegacyAttachment({
        id: local.id,
        attachmentId: 'fixed-legacy-attachment',
        operationId: ATTACHMENT_OPERATION_ID
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('cancels an active attachment upload without changing local metadata', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-cancel-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'cancel.txt')
    await writeFile(source, 'cancel me')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    let started!: () => void
    const didStart = new Promise<void>((resolve) => {
      started = resolve
    })
    fake!.uploadAttachment = async (_id, _name, _data, signal) => {
      started()
      return new Promise<never>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new BitwardenDirectError('ABORTED')), {
          once: true
        })
      })
    }

    const upload = service.uploadAttachment({
      id: local.id,
      operationId: ATTACHMENT_OPERATION_ID
    })
    await didStart
    expect(
      service.cancelAttachmentOperation({
        operationId: '70000000-0000-4000-8000-000000000002'
      })
    ).toEqual({ canceled: false })
    expect(service.cancelAttachmentOperation({ operationId: ATTACHMENT_OPERATION_ID })).toEqual({
      canceled: true
    })
    await expect(upload).rejects.toMatchObject({ code: 'ATTACHMENT_CANCELED' })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({ attachments: [] })
    expect(fake!.remoteLogins[0]!.attachments).toEqual([])
  })

  it('refuses cancellation after the remote attachment commit point and persists success', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-commit-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'committed.txt')
    await writeFile(source, 'committed upload')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const originalUpload = fake!.uploadAttachment.bind(fake!)
    let signalCommitted!: () => void
    const didCommit = new Promise<void>((resolve) => {
      signalCommitted = resolve
    })
    let release!: () => void
    const holdAfterCommit = new Promise<void>((resolve) => {
      release = resolve
    })
    fake!.uploadAttachment = async (id, fileName, data, signal, onCommitted) => {
      const result = await originalUpload(id, fileName, data, signal, onCommitted)
      signalCommitted()
      await holdAfterCommit
      return result
    }

    const upload = service.uploadAttachment({
      id: local.id,
      operationId: ATTACHMENT_OPERATION_ID
    })
    await didCommit
    expect(service.cancelAttachmentOperation({ operationId: ATTACHMENT_OPERATION_ID })).toEqual({
      canceled: false
    })
    release()
    await expect(upload).resolves.toMatchObject({
      canceled: false,
      attachment: { fileName: 'committed.txt' }
    })
    await expect(service.getLogin({ id: local.id })).resolves.toMatchObject({
      attachments: [expect.objectContaining({ fileName: 'committed.txt' })]
    })
  })

  it.each([
    ['STORAGE_LIMIT', 'ATTACHMENT_STORAGE_LIMIT'],
    ['TOO_LARGE', 'ATTACHMENT_TOO_LARGE'],
    ['ATTACHMENT_REJECTED', 'ATTACHMENT_REJECTED'],
    ['NOT_FOUND', 'NOT_FOUND']
  ] as const)('maps server attachment %s failures to safe %s errors', async (remoteCode, code) => {
    const directory = await mkdtemp(join(tmpdir(), 'bearwarden-upload-quota-'))
    temporaryDirectories.push(directory)
    const source = join(directory, 'quota.txt')
    await writeFile(source, 'quota')
    const attachmentFiles = new VaultAttachmentFileService({
      chooseSavePath: vi.fn(async () => null),
      chooseOpenFile: vi.fn(async () => source)
    })
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      attachmentFiles,
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.uploadAttachment = async () => {
      throw new BitwardenDirectError(remoteCode)
    }

    await expect(
      service.uploadAttachment({ id: local.id, operationId: ATTACHMENT_OPERATION_ID })
    ).rejects.toMatchObject({ code })
  })

  it.each(['content changes', 'mapped item disappears'] as const)(
    'rejects a final remote refetch when the %s and leaves the vault unchanged',
    async (race) => {
      let fake: ReturnType<typeof createSyncFake> | null = null
      const { service, store } = await createHarness({
        createSyncClient: (sync) => {
          fake = createSyncFake(sync.state)
          return fake
        }
      })
      await service.setup(MASTER_PASSWORD)
      await service.connectSync({
        serverUrl: 'https://vault.example.invalid',
        email: 'sync@example.invalid',
        masterPassword: 'remote master password'
      })
      const local = (await service.listLogins())[0]!
      const listPersonalLogins = fake!.listPersonalLogins.bind(fake!)
      let calls = 0
      fake!.listPersonalLogins = async () => {
        const logins = await listPersonalLogins()
        calls += 1
        if (calls !== 2) return logins
        if (race === 'mapped item disappears') return []
        logins[0]!.password = 'third-party-race-secret'
        return logins
      }
      const write = vi.spyOn(store, 'write')

      await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
      expect(write).not.toHaveBeenCalled()
      await expect(service.revealPassword({ id: local.id })).resolves.toBe('remote-test-secret')
      expect((await service.getLogin({ id: local.id })).attachmentCount).toBe(0)
    }
  )

  it('preserves passkeys from both devices when an offline edit races a remote replacement', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!

    await service.updateLogin({ id: local.id, password: 'offline-device-password' })
    fake!.remoteLogins[0]!.passkeys = [
      {
        ...fake!.remoteLogins[0]!.passkeys[0]!,
        credentialId: 'other-device-credential',
        keyValue: 'other-device-private-material',
        creationDate: '2026-07-14T03:00:00.000Z'
      }
    ]
    fake!.remoteLogins[0]!.revisionDate = '2026-07-14T03:00:01.000Z'

    await expect(service.syncNow()).resolves.toMatchObject({ conflicts: 1 })

    expect(fake!.remoteLogins).toHaveLength(1)
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'remote-test-secret',
      passkeys: [expect.objectContaining({ credentialId: 'other-device-credential' })]
    })
    const localCopies = await service.listLogins()
    expect(localCopies).toHaveLength(2)
    expect(localCopies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'Remote login',
          passkeyCount: 1
        }),
        expect.objectContaining({
          name: expect.stringContaining('BearWarden conflict'),
          passkeyCount: 1
        })
      ])
    )
    const localDetails = await Promise.all(localCopies.map(({ id }) => service.getLogin({ id })))
    expect(localDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'Remote login',
          passkeys: [expect.objectContaining({ credentialId: 'other-device-credential' })]
        }),
        expect.objectContaining({
          name: expect.stringContaining('BearWarden conflict'),
          passkeys: [expect.objectContaining({ credentialId: 'credential-id' })]
        })
      ])
    )
    expect(JSON.stringify(localDetails)).not.toContain('private-material')

    await expect(service.syncNow()).resolves.toMatchObject({ conflicts: 0, pushed: 1 })
    const remoteConflict = fake!.remoteLogins.find((entry) =>
      entry.name.includes('BearWarden conflict')
    )
    expect(remoteConflict).toMatchObject({
      password: 'offline-device-password',
      passkeys: [expect.objectContaining({ credentialId: 'credential-id' })]
    })
  })

  it('syncs soft-delete, restore, content edits, and permanent deletion with distinct APIs', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const remoteId = fake!.remoteLogins[0]!.id

    await service.updateLogin({ id: local.id, password: 'changed-before-delete' })
    await service.deleteLogin({ id: local.id })
    await service.syncNow()
    expect(fake!.editedLoginIds).toContain(remoteId)
    expect(fake!.softDeletedIds).toEqual([remoteId])
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'changed-before-delete',
      deletedAt: expect.any(String)
    })

    await service.restoreLogin({ id: local.id })
    await service.syncNow()
    expect(fake!.restoredIds).toEqual([remoteId])
    expect(fake!.remoteLogins[0]!.deletedAt).toBeNull()

    await service.deleteLogin({ id: local.id })
    await service.deleteLoginPermanently({ id: local.id })
    await service.syncNow()
    expect(fake!.hardDeletedIds).toEqual([remoteId])
    expect(fake!.remoteLogins).toEqual([])
  })

  it('resumes a partially completed trash update after restart without reviving or duplicating it', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const createSpy = vi.spyOn(fake!, 'createLogin')
    const softDelete = fake!.softDeleteLogin.bind(fake)
    let failOnce = true
    fake!.softDeleteLogin = async (id, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected soft-delete failure')
      }
      await softDelete(id, signal)
    }

    await service.updateLogin({ id: local.id, password: 'changed-before-restart' })
    await service.archiveLogin({ id: local.id })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(fake!.remoteLogins).toMatchObject([
      {
        id: fake!.remoteLogins[0]!.id,
        password: 'changed-before-restart',
        archivedAt: expect.any(String),
        deletedAt: null
      }
    ])

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })

    expect(createSpy).not.toHaveBeenCalled()
    expect(fake!.remoteLogins).toHaveLength(1)
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'changed-before-restart',
      archivedAt: expect.any(String),
      deletedAt: expect.any(String)
    })
    expect(await reopened.listLogins()).toEqual([])
    expect(await reopened.listLogins({ deleted: true })).toMatchObject([{ id: local.id }])
  })

  it('resumes the maximum restore-unarchive-edit-delete chain after restart', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    await service.archiveLogin({ id: local.id })
    await service.deleteLogin({ id: local.id })
    await service.syncNow()

    const createSpy = vi.spyOn(fake!, 'createLogin')
    const edit = fake!.editLogin.bind(fake)
    let failOnce = true
    fake!.editLogin = async (id, draft, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected edit failure')
      }
      return edit(id, draft, signal)
    }
    await service.restoreLogin({ id: local.id })
    await service.unarchiveLogin({ id: local.id })
    await service.updateLogin({ id: local.id, password: 'changed-after-restore' })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'remote-test-secret',
      archivedAt: null,
      deletedAt: null
    })

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })

    expect(createSpy).not.toHaveBeenCalled()
    expect(fake!.remoteLogins).toHaveLength(1)
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'changed-after-restore',
      archivedAt: null,
      deletedAt: expect.any(String)
    })
    expect(await reopened.listLogins()).toEqual([])
    expect(await reopened.listLogins({ deleted: true })).toMatchObject([{ id: local.id }])
  })

  it('preserves a third-party remote edit made while a trash mutation is pending', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const softDelete = fake!.softDeleteLogin.bind(fake)
    let failOnce = true
    fake!.softDeleteLogin = async (id, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected soft-delete failure')
      }
      await softDelete(id, signal)
    }
    await service.updateLogin({ id: local.id, password: 'local-pending-change' })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })

    fake!.remoteLogins[0]!.password = 'third-party-remote-change'
    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 1 })

    expect(fake!.remoteLogins).toHaveLength(1)
    expect(fake!.remoteLogins[0]!.password).toBe('third-party-remote-change')
    const [remotePrimary] = await reopened.listLogins()
    expect(await reopened.revealPassword({ id: remotePrimary!.id })).toBe(
      'third-party-remote-change'
    )
    const [localConflict] = await reopened.listLogins({ deleted: true })
    expect(localConflict?.name).toContain('BearWarden conflict')
    await reopened.restoreLogin({ id: localConflict!.id })
    expect(await reopened.revealPassword({ id: localConflict!.id })).toBe('local-pending-change')
  })

  it('keeps permanent deletion final when a trash mutation was interrupted', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    const softDelete = fake!.softDeleteLogin.bind(fake)
    let failOnce = true
    fake!.softDeleteLogin = async (id, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected soft-delete failure')
      }
      await softDelete(id, signal)
    }
    await service.updateLogin({ id: local.id, password: 'must-not-revive' })
    await service.deleteLogin({ id: local.id })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    await service.deleteLoginPermanently({ id: local.id })

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })

    expect(fake!.hardDeletedIds).toContain('90000000-0000-4000-8000-000000000002')
    expect(fake!.remoteLogins).toEqual([])
    expect(await reopened.listLogins()).toEqual([])
    expect(await reopened.listLogins({ deleted: true })).toEqual([])
  })

  it('pulls a remote soft-delete into the local trash without hard-deleting content', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.remoteLogins[0]!.deletedAt = '2026-07-14T03:00:00.000Z'

    await expect(service.syncNow()).resolves.toMatchObject({ pulled: 1 })
    expect(await service.listLogins()).toEqual([])
    expect(await service.listLogins({ deleted: true })).toMatchObject([
      { id: local.id, deletedAt: '2026-07-14T03:00:00.000Z' }
    ])
    await expect(service.getLogin({ id: local.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.getWebsiteIcon({ id: local.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
  })

  it('rejects a malformed remote deletion date instead of treating a trashed item as active', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    fake!.remoteLogins[0]!.deletedAt = 'not-a-date'

    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(await service.listLogins({ deleted: true })).toEqual([])
  })

  it('rejects a malformed remote archive date instead of changing its visibility', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!
    fake!.remoteLogins[0]!.archivedAt = 'not-a-date'

    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(await service.listLogins()).toMatchObject([{ id: local.id, archivedAt: null }])
    expect(await service.listLogins({ archived: true })).toEqual([])
  })

  it.each([
    {
      label: 'more than 1,000 passkeys',
      mutate: (login: BitwardenLoginItem) => {
        const passkey = login.passkeys[0]!
        login.passkeys = Array.from({ length: 1_001 }, () => ({ ...passkey }))
      }
    },
    {
      label: 'a passkey field longer than 4,096 characters',
      mutate: (login: BitwardenLoginItem) => {
        login.passkeys[0]!.credentialId = 'x'.repeat(4_097)
      }
    },
    {
      label: 'a non-canonical passkey creation date',
      mutate: (login: BitwardenLoginItem) => {
        login.passkeys[0]!.creationDate = '2026-07-13T00:00:00Z'
      }
    }
  ])('rejects remote $label atomically and leaves a reopenable vault', async ({ mutate }) => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service, store } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    mutate(fake!.remoteLogins[0]!)
    const write = vi.spyOn(store, 'write')

    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(write).not.toHaveBeenCalled()

    await service.lock()
    const reopened = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
    const [intact] = await reopened.listLogins()
    expect(intact?.passkeyCount).toBe(1)
    await expect(reopened.getLogin({ id: intact!.id })).resolves.toMatchObject({
      passkeys: [expect.objectContaining({ credentialId: 'credential-id' })]
    })
  })

  it('persists only authenticated ciphertext with owner-only permissions', async () => {
    const { filePath, service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Example',
      username: 'bear@example.invalid',
      password: 'canary-secret-value',
      uri: 'https://example.com'
    })

    const contents = await readFile(filePath, 'utf8')
    expect(contents).toContain('bearwarden-vault')
    expect(contents).not.toContain(MASTER_PASSWORD)
    expect(contents).not.toContain('canary-secret-value')
    expect(contents).not.toContain('bear@example.invalid')

    const envelope = JSON.parse(contents) as { kdf: { salt: string } }
    const authenticatedSalt = envelope.kdf.salt
    envelope.kdf.salt = Buffer.alloc(16, 1).toString('base64')
    await writeFile(filePath, JSON.stringify(envelope), { mode: 0o600 })
    await expect(
      service.updateLogin({ id: login.id, notes: 'still available' })
    ).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
    expect(
      (JSON.parse(await readFile(filePath, 'utf8')) as { kdf: { salt: string } }).kdf.salt
    ).not.toBe(authenticatedSalt)

    if (process.platform !== 'win32') {
      expect((await stat(filePath)).mode & 0o777).toBe(0o600)
    }
  })

  it('exports full non-trash data and imports it as durable remapped copies', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Shared' })
    const original = await service.createLogin({
      name: 'Portable account',
      username: 'sample-user',
      password: 'old-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      folderId: folder.id,
      favorite: true,
      reprompt: 1,
      uris: [
        { uri: 'https://example.invalid', match: 0 },
        { uri: 'https://mobile.example.invalid', match: 3 }
      ],
      customFields: [
        { source: null, name: 'recovery', type: 'hidden', value: 'sample-code', linkedId: null }
      ]
    })
    await service.updateLogin({ id: original.id, password: 'new-secret' })
    await service.archiveLogin({ id: original.id })
    const deleted = await service.createLogin({ name: 'Deleted account', password: 'trash-secret' })
    await service.deleteLogin({ id: deleted.id })

    await expect(service.exportPortableSnapshot('incorrect master password')).rejects.toMatchObject(
      {
        code: 'INVALID_MASTER_PASSWORD'
      }
    )
    const exported = await service.exportPortableSnapshot(MASTER_PASSWORD)
    expect(exported.skippedTrashItems).toBe(1)
    expect(exported.snapshot.folders).toHaveLength(1)
    expect(exported.snapshot.items).toHaveLength(1)
    expect(exported.snapshot.items[0]).toMatchObject({
      id: original.id,
      name: 'Portable account',
      username: 'sample-user',
      password: 'new-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      archivedAt: expect.any(String),
      reprompt: 1,
      uris: [
        { uri: 'https://example.invalid', match: 0 },
        { uri: 'https://mobile.example.invalid', match: 3 }
      ],
      customFields: [{ name: 'recovery', value: 'sample-code', type: 'hidden' }],
      passwordHistory: [{ password: 'old-secret' }]
    })

    await expect(
      service.importPortableSnapshot(exported.snapshot, exported.skippedTrashItems, MASTER_PASSWORD)
    ).resolves.toEqual({ importedFolders: 1, importedItems: 1, skippedTrashItems: 1 })

    const folders = await service.listFolders()
    expect(folders.map((entry) => entry.name)).toEqual(['Shared', 'Shared (Imported)'])
    const archived = await service.listLogins({ archived: true })
    expect(archived).toHaveLength(2)
    const imported = archived.find((entry) => entry.id !== original.id)!
    expect(imported.folderId).toBe(folders[1]!.id)
    expect(imported.id).not.toBe(original.id)

    const roundTrip = await service.exportPortableSnapshot(MASTER_PASSWORD)
    expect(roundTrip.snapshot.items.find((entry) => entry.id === imported.id)).toMatchObject({
      password: 'new-secret',
      customFields: [{ name: 'recovery', value: 'sample-code' }],
      passwordHistory: [{ password: 'old-secret' }]
    })

    await service.lock()
    await service.unlock(MASTER_PASSWORD)
    expect((await service.listFolders()).map((entry) => entry.name)).toEqual([
      'Shared',
      'Shared (Imported)'
    ])
    expect(await service.listLogins({ archived: true })).toHaveLength(2)
  })

  it('keeps imports atomic when validation or persistence fails', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Existing' })
    await service.createLogin({ name: 'Existing account', folderId: folder.id })
    const exported = await service.exportPortableSnapshot(MASTER_PASSWORD)
    const foldersBefore = await service.listFolders()
    const itemsBefore = await service.listLogins()
    const write = vi.spyOn(store, 'write')

    await expect(
      service.importPortableSnapshot({ folders: [], items: [] }, 3, MASTER_PASSWORD)
    ).resolves.toEqual({ importedFolders: 0, importedItems: 0, skippedTrashItems: 3 })
    expect(write).not.toHaveBeenCalled()

    const invalid = structuredClone(exported.snapshot)
    invalid.items[0]!.folderId = IDS[11]!
    await expect(service.importPortableSnapshot(invalid, 0, MASTER_PASSWORD)).rejects.toMatchObject(
      { code: 'INVALID_INPUT' }
    )
    expect(write).not.toHaveBeenCalled()
    expect(await service.listFolders()).toEqual(foldersBefore)
    expect(await service.listLogins()).toEqual(itemsBefore)

    write.mockRejectedValueOnce(new Error('simulated write failure'))
    await expect(
      service.importPortableSnapshot(exported.snapshot, 0, MASTER_PASSWORD)
    ).rejects.toThrow('simulated write failure')
    expect(write).toHaveBeenCalledOnce()
    expect(await service.listFolders()).toEqual(foldersBefore)
    expect(await service.listLogins()).toEqual(itemsBefore)
  })

  it('restores native attachment items before streaming uploads and records only safe progress', async () => {
    const sourceHarness = await createHarness()
    await sourceHarness.service.setup(MASTER_PASSWORD)
    const sourceItem = await sourceHarness.service.createLogin({
      name: 'Native restore item',
      username: 'restore-user'
    })
    const exported = await sourceHarness.service.exportPortableSnapshot(MASTER_PASSWORD)
    const contents = Buffer.from('fake attachment contents')
    const digest = createHash('sha256').update(contents).digest('hex')
    const preview = {
      createdAt: '2026-07-17T00:00:00.000Z',
      vaultJson: buildBitwardenJson(exported.snapshot),
      attachments: [
        {
          id: 'source-attachment-1',
          itemId: sourceItem.id,
          fileName: 'restored.txt',
          size: contents.length
        }
      ],
      attachmentDigests: [digest],
      archiveFingerprint: 'a'.repeat(64),
      attachmentBytes: contents.length
    }

    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    fake!.uploadAttachmentStream = vi.fn(async (id, fileName, source, signal, onCommitted) => {
      const chunks: Buffer[] = []
      for await (const chunk of source.chunks(signal)) chunks.push(Buffer.from(chunk))
      return fake!.uploadAttachment(id, fileName, Buffer.concat(chunks), signal, onCommitted)
    })

    const trashArchive = JSON.parse(preview.vaultJson) as {
      items: Array<Record<string, unknown>>
    }
    trashArchive.items.push({
      ...trashArchive.items[0]!,
      id: 'trash-source-item',
      deletedDate: '2026-07-17T00:00:00.000Z'
    })
    await expect(
      service.beginNativeAttachmentRestore(
        { ...preview, vaultJson: JSON.stringify(trashArchive) },
        MASTER_PASSWORD
      )
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    await expect(service.beginNativeAttachmentRestore(preview, MASTER_PASSWORD)).resolves.toEqual({
      phase: 'syncing-items',
      totalItems: 1,
      mappedItems: 0,
      totalAttachments: 1,
      uploadedAttachments: 0,
      needsReconciliationAttachments: 0,
      totalBytes: contents.length,
      completedBytes: 0
    })
    await expect(
      service.clearCompletedNativeAttachmentRestore(preview.archiveFingerprint)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.syncNativeAttachmentRestoreItems(preview.archiveFingerprint)
    ).resolves.toMatchObject({ phase: 'restoring-attachments', mappedItems: 1 })
    await expect(
      service.clearCompletedNativeAttachmentRestore(preview.archiveFingerprint)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.uploadNativeAttachmentRestoreEntry(
        preview.archiveFingerprint,
        { sourceItemId: sourceItem.id, sourceAttachmentId: 'source-attachment-1' },
        {
          size: contents.length,
          chunks: async function* () {
            yield Buffer.from(contents)
          }
        }
      )
    ).resolves.toMatchObject({
      phase: 'complete',
      uploadedAttachments: 1,
      completedBytes: contents.length
    })
    const summary = await service.nativeAttachmentRestoreStatus()
    expect(JSON.stringify(summary)).not.toContain(sourceItem.id)
    expect(JSON.stringify(summary)).not.toContain(digest)
    expect(JSON.stringify(summary)).not.toContain(preview.archiveFingerprint)
    await expect(
      service.clearCompletedNativeAttachmentRestore('f'.repeat(64))
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.clearCompletedNativeAttachmentRestore(preview.archiveFingerprint)
    ).resolves.toBeUndefined()
    await expect(service.nativeAttachmentRestoreStatus()).resolves.toBeNull()
    await expect(
      service.beginNativeAttachmentRestore(preview, MASTER_PASSWORD)
    ).resolves.toMatchObject({ phase: 'syncing-items', totalItems: 1 })
  })

  it('reconciles a response-lost native attachment by authoritative plaintext size and digest', async () => {
    const sourceHarness = await createHarness()
    await sourceHarness.service.setup(MASTER_PASSWORD)
    const sourceItem = await sourceHarness.service.createLogin({ name: 'Response lost restore' })
    const exported = await sourceHarness.service.exportPortableSnapshot(MASTER_PASSWORD)
    const contents = Buffer.from('fake attachment contents')
    const preview = {
      createdAt: '2026-07-17T00:00:00.000Z',
      vaultJson: buildBitwardenJson(exported.snapshot),
      attachments: [
        {
          id: 'source-attachment-2',
          itemId: sourceItem.id,
          fileName: 'response-lost.txt',
          size: contents.length
        }
      ],
      attachmentDigests: [createHash('sha256').update(contents).digest('hex')],
      archiveFingerprint: 'b'.repeat(64),
      attachmentBytes: contents.length
    }
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    await service.beginNativeAttachmentRestore(preview, MASTER_PASSWORD)
    await service.syncNativeAttachmentRestoreItems(preview.archiveFingerprint)
    fake!.uploadAttachmentStream = vi.fn(async (id, fileName, source, signal) => {
      const chunks: Buffer[] = []
      for await (const chunk of source.chunks(signal)) chunks.push(Buffer.from(chunk))
      await fake!.uploadAttachment(id, fileName, Buffer.concat(chunks), signal)
      throw new Error('response lost')
    })
    const key = { sourceItemId: sourceItem.id, sourceAttachmentId: 'source-attachment-2' }
    await expect(
      service.uploadNativeAttachmentRestoreEntry(preview.archiveFingerprint, key, {
        size: contents.length,
        chunks: async function* () {
          yield Buffer.from(contents)
        }
      })
    ).rejects.toMatchObject({ code: 'ATTACHMENT_FAILED' })
    await expect(service.nativeAttachmentRestoreStatus()).resolves.toMatchObject({
      phase: 'needs-reconciliation',
      needsReconciliationAttachments: 1
    })
    await expect(
      service.clearCompletedNativeAttachmentRestore(preview.archiveFingerprint)
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.reconcileNativeAttachmentRestoreEntry(preview.archiveFingerprint, key)
    ).resolves.toMatchObject({
      outcome: 'uploaded',
      summary: { phase: 'complete', uploadedAttachments: 1 }
    })
  })

  it('keeps native restore reconciliation conflicted when upload proof or its remote item is absent', async () => {
    const sourceHarness = await createHarness()
    await sourceHarness.service.setup(MASTER_PASSWORD)
    const sourceItem = await sourceHarness.service.createLogin({ name: 'Missing remote proof' })
    const exported = await sourceHarness.service.exportPortableSnapshot(MASTER_PASSWORD)
    const contents = Buffer.from('remote proof contents')
    const preview = {
      createdAt: '2026-07-17T00:00:00.000Z',
      vaultJson: buildBitwardenJson(exported.snapshot),
      attachments: [
        {
          id: 'source-attachment-remote-proof',
          itemId: sourceItem.id,
          fileName: 'remote-proof.txt',
          size: contents.length
        }
      ],
      attachmentDigests: [createHash('sha256').update(contents).digest('hex')],
      archiveFingerprint: 'd'.repeat(64),
      attachmentBytes: contents.length
    }
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    await service.beginNativeAttachmentRestore(preview, MASTER_PASSWORD)
    await service.syncNativeAttachmentRestoreItems(preview.archiveFingerprint)
    fake!.uploadAttachmentStream = vi.fn(async () => ({
      id: 'unconfirmed-upload',
      fileName: 'remote-proof.txt',
      size: contents.length,
      sizeName: `${contents.length} B`,
      legacy: false
    }))
    const key = {
      sourceItemId: sourceItem.id,
      sourceAttachmentId: 'source-attachment-remote-proof'
    }
    await expect(
      service.uploadNativeAttachmentRestoreEntry(preview.archiveFingerprint, key, {
        size: contents.length,
        chunks: async function* () {
          yield Buffer.from(contents)
        }
      })
    ).rejects.toMatchObject({ code: 'ATTACHMENT_FAILED' })
    const restoredRemoteIndex = fake!.remoteLogins.findIndex(
      (login) => login.name === 'Missing remote proof'
    )
    expect(restoredRemoteIndex).toBeGreaterThanOrEqual(0)
    fake!.remoteLogins.splice(restoredRemoteIndex, 1)
    await expect(
      service.reconcileNativeAttachmentRestoreEntry(preview.archiveFingerprint, key)
    ).resolves.toMatchObject({
      outcome: 'conflict',
      summary: { phase: 'needs-reconciliation', needsReconciliationAttachments: 1 }
    })
  })

  it('keeps PIN unlock locked when interrupted native-restore recovery cannot persist', async () => {
    const sourceHarness = await createHarness()
    await sourceHarness.service.setup(MASTER_PASSWORD)
    const sourceItem = await sourceHarness.service.createLogin({ name: 'Interrupted restore' })
    const exported = await sourceHarness.service.exportPortableSnapshot(MASTER_PASSWORD)
    const contents = Buffer.from('fake attachment contents')
    const preview = {
      createdAt: '2026-07-17T00:00:00.000Z',
      vaultJson: buildBitwardenJson(exported.snapshot),
      attachments: [
        {
          id: 'source-attachment-3',
          itemId: sourceItem.id,
          fileName: 'interrupted.txt',
          size: contents.length
        }
      ],
      attachmentDigests: [createHash('sha256').update(contents).digest('hex')],
      archiveFingerprint: 'c'.repeat(64),
      attachmentBytes: contents.length
    }
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    await service.beginNativeAttachmentRestore(preview, MASTER_PASSWORD)
    await service.syncNativeAttachmentRestoreItems(preview.archiveFingerprint)
    await service.enablePinUnlock({ pin: 'restore-pin', masterPassword: MASTER_PASSWORD })
    fake!.uploadAttachmentStream = vi.fn(async () => {
      throw new Error('upload failed')
    })
    const originalWrite = store.write.bind(store)
    const uploadWrites = vi.spyOn(store, 'write')
    uploadWrites.mockImplementationOnce(originalWrite).mockRejectedValueOnce(new Error('disk full'))
    await expect(
      service.uploadNativeAttachmentRestoreEntry(
        preview.archiveFingerprint,
        { sourceItemId: sourceItem.id, sourceAttachmentId: 'source-attachment-3' },
        {
          size: contents.length,
          chunks: async function* () {
            yield Buffer.from(contents)
          }
        }
      )
    ).rejects.toThrow('disk full')
    uploadWrites.mockRestore()
    await service.lock()

    const recoveryWrite = vi.spyOn(store, 'write').mockRejectedValueOnce(new Error('still full'))
    await expect(service.unlockWithPin({ pin: 'restore-pin' })).rejects.toThrow('still full')
    await expect(service.status()).resolves.toEqual({ state: 'locked' })
    expect(service.pinUnlockStatus()).toEqual({ available: true, remainingAttempts: 5 })
    recoveryWrite.mockRestore()
    await expect(service.unlockWithPin({ pin: 'restore-pin' })).resolves.toEqual({
      state: 'unlocked'
    })
    await expect(service.nativeAttachmentRestoreStatus()).resolves.toMatchObject({
      phase: 'needs-reconciliation',
      needsReconciliationAttachments: 1
    })
  })

  it('supports folder and login CRUD without returning passwords from list or get', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const personal = await service.createFolder({ name: 'Personal' })
    const work = await service.createFolder({ name: 'Work' })
    expect((await service.reorderFolders({ orderedIds: [work.id, personal.id] }))[0]?.id).toBe(
      work.id
    )

    const login = await service.createLogin({
      name: 'Example',
      username: 'bear',
      password: 'secret',
      folderId: personal.id
    })
    expect('password' in login).toBe(false)
    expect('password' in (await service.listLogins())[0]!).toBe(false)
    expect('password' in (await service.getLogin({ id: login.id }))).toBe(false)

    await service.updateLogin({ id: login.id, folderId: work.id, favorite: true })
    expect(await service.getLogin({ id: login.id })).toMatchObject({
      folderId: work.id,
      favorite: true
    })

    await service.deleteFolder({ id: work.id })
    expect((await service.getLogin({ id: login.id })).folderId).toBeNull()
    await service.deleteLogin({ id: login.id })
    expect(await service.listLogins()).toEqual([])
  })

  it('reports active password health without persisting, changing generation, or exposing secrets', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const weak = await service.createLogin({
      name: 'Weak account',
      username: 'health-user-canary',
      password: '123'
    })
    const reusedFirst = await service.createLogin({
      name: 'Shared first',
      password: 'A very long reusable test passphrase 2026!'
    })
    const reusedSecond = await service.createLogin({
      name: 'Shared second',
      password: 'A very long reusable test passphrase 2026!'
    })
    const protectedLogin = await service.createLogin({
      name: 'Protected account',
      username: 'protected-user-canary',
      password: 'protected-password-canary',
      reprompt: 1,
      uris: [{ uri: 'http://protected.example/private?token=protected-uri-canary', match: null }]
    })
    const unsecured = await service.createLogin({
      name: 'Unsecured account',
      username: '',
      password: '',
      uris: [{ uri: 'http://localhost:8080/private?token=unsecured-uri-canary', match: null }]
    })
    const archived = await service.createLogin({
      name: 'Archived account',
      password: 'archived-password-canary'
    })
    const trashed = await service.createLogin({
      name: 'Trashed account',
      password: 'trashed-password-canary'
    })
    await service.archiveLogin({ id: archived.id })
    await service.deleteLogin({ id: trashed.id })

    const internalData = (service as unknown as { data: { logins: { id: string }[] } | null }).data
    const rawProtected = internalData?.logins.find((login) => login.id === protectedLogin.id)
    expect(rawProtected).toBeDefined()
    Object.defineProperties(rawProtected!, {
      password: {
        get: () => {
          throw new Error('health must not read a protected password')
        }
      },
      username: {
        get: () => {
          throw new Error('health must not read a protected username')
        }
      },
      uris: {
        get: () => {
          throw new Error('health must not read protected URIs')
        }
      }
    })
    Object.defineProperty(internalData!, 'sharedLogins', {
      get: () => {
        throw new Error('personal health must not read shared organization items')
      }
    })

    const beforeGeneration = await service.unlockedGeneration()
    const write = vi.spyOn(store, 'write')
    const report = await service.getHealthReport()

    expect(report.generatedAt).toMatch(/^2026-07-14T/)
    expect(report.totals).toEqual({
      analyzedCount: 3,
      weakPasswordCount: 1,
      reusedPasswordCount: 2,
      unsecuredWebsiteCount: 1,
      protectedSkippedCount: 1
    })
    expect(report.weakPasswords).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: weak.id, score: expect.any(Number) })])
    )
    expect(report.reusedPasswords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: reusedFirst.id, reuseCount: 2 }),
        expect.objectContaining({ id: reusedSecond.id, reuseCount: 2 })
      ])
    )
    expect(report.unsecuredWebsites).toEqual([{ id: unsecured.id, name: 'Unsecured account' }])
    const reportedIds = new Set([
      ...report.weakPasswords.map((finding) => finding.id),
      ...report.reusedPasswords.map((finding) => finding.id),
      ...report.unsecuredWebsites.map((finding) => finding.id)
    ])
    expect(reportedIds).not.toContain(protectedLogin.id)
    expect(reportedIds).not.toContain(archived.id)
    expect(reportedIds).not.toContain(trashed.id)
    const rendererPayload = JSON.stringify(report)
    for (const secret of [
      '123',
      'A very long reusable test passphrase 2026!',
      'protected-password-canary',
      'protected-uri-canary',
      'unsecured-uri-canary',
      'localhost:8080',
      'archived-password-canary',
      'trashed-password-canary'
    ]) {
      expect(rendererPayload).not.toContain(secret)
    }
    expect(write).not.toHaveBeenCalled()
    expect(await service.unlockedGeneration()).toBe(beforeGeneration)
  })

  it('reports inactive 2FA for personal logins without crossing unrelated secrets', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const zulu = await service.createLogin({
      name: 'Zulu account',
      password: 'password-canary',
      notes: 'notes-canary',
      customFields: [
        {
          source: null,
          name: 'field-canary',
          value: 'value-canary',
          type: 'text',
          linkedId: null
        }
      ],
      uris: [{ uri: 'https://login.example.com/private?token=uri-canary', match: null }]
    })
    const alpha = await service.createLogin({
      name: 'Alpha account',
      uris: [{ uri: 'https://example.com/login', match: null }]
    })

    const internalData = (
      service as unknown as {
        data: {
          logins: Array<Record<string, unknown> & { id: string }>
          sharedLogins: unknown[]
        } | null
      }
    ).data!
    for (const id of [zulu.id, alpha.id]) {
      const raw = internalData.logins.find((login) => login.id === id)!
      Object.defineProperties(raw, {
        password: {
          get: () => {
            throw new Error('inactive 2FA must not read passwords')
          }
        },
        notes: {
          get: () => {
            throw new Error('inactive 2FA must not read notes')
          }
        },
        customFields: {
          get: () => {
            throw new Error('inactive 2FA must not read custom fields')
          }
        },
        passkeys: {
          get: () => {
            throw new Error('inactive 2FA must not read passkeys')
          }
        }
      })
    }
    internalData.sharedLogins.push({
      id: 'shared-canary',
      type: 'login',
      name: 'Organization canary',
      totp: '',
      deletedAt: null,
      archivedAt: null,
      uris: [{ uri: 'https://example.com' }]
    })

    const dataset = parseTwoFactorDirectoryTotpData({
      'example.com': {
        methods: ['totp'],
        documentation: 'https://help.example.com/two-factor'
      }
    })
    const generation = await service.unlockedGeneration()
    const write = vi.spyOn(store, 'write')
    const report = await service.getInactiveTwoFactorReport(dataset)

    expect(report).toEqual({
      analyzedCount: 2,
      excludedTotpCount: 0,
      excludedDeletedCount: 0,
      excludedArchivedCount: 0,
      findings: [
        {
          id: alpha.id,
          name: 'Alpha account',
          matchedDomain: 'example.com',
          documentationUrl: 'https://help.example.com/two-factor'
        },
        {
          id: zulu.id,
          name: 'Zulu account',
          matchedDomain: 'example.com',
          documentationUrl: 'https://help.example.com/two-factor'
        }
      ]
    })
    const serialized = JSON.stringify(report)
    for (const forbidden of [
      'password-canary',
      'notes-canary',
      'field-canary',
      'value-canary',
      'uri-canary',
      'shared-canary',
      'Organization canary'
    ]) {
      expect(serialized).not.toContain(forbidden)
    }
    expect(write).not.toHaveBeenCalled()
    expect(await service.unlockedGeneration()).toBe(generation)
  })

  it('counts TOTP, trash, and archive exclusions without reading their URIs', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const totp = await service.createLogin({
      name: 'TOTP account',
      totp: 'totp-seed-canary',
      uris: [{ uri: 'https://example.com/totp-canary', match: null }]
    })
    const archived = await service.createLogin({
      name: 'Archived account',
      uris: [{ uri: 'https://example.com/archive-canary', match: null }]
    })
    const trashed = await service.createLogin({
      name: 'Trashed account',
      uris: [{ uri: 'https://example.com/trash-canary', match: null }]
    })
    await service.archiveLogin({ id: archived.id })
    // Bitwarden trash can retain archive state; trash takes precedence in report accounting.
    await service.archiveLogin({ id: trashed.id })
    await service.deleteLogin({ id: trashed.id })

    const internalLogins = (
      service as unknown as { data: { logins: Array<Record<string, unknown> & { id: string }> } }
    ).data.logins
    for (const id of [totp.id, archived.id, trashed.id]) {
      const raw = internalLogins.find((login) => login.id === id)!
      Object.defineProperty(raw, 'uris', {
        get: () => {
          throw new Error('excluded login URIs must not be read')
        }
      })
    }

    const report = await service.getInactiveTwoFactorReport(
      parseTwoFactorDirectoryTotpData({ 'example.com': { methods: ['totp'] } })
    )
    expect(report).toEqual({
      analyzedCount: 0,
      excludedTotpCount: 1,
      excludedDeletedCount: 1,
      excludedArchivedCount: 1,
      findings: []
    })
    expect(JSON.stringify(report)).not.toMatch(/(?:seed|archive|trash)-canary/u)
  })

  it('checks exposed passwords through padded hash ranges without exposing protected or raw data', async () => {
    const exposedPassword = 'password'
    const safePassword = 'A unique test-only passphrase that is not in the mocked range'
    const exposedHash = hashPasswordForPwnedLookup(exposedPassword)
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      const url = String(input)
      const line = url.endsWith(exposedHash.slice(0, 5))
        ? `${exposedHash.slice(5)}:42`
        : `${'0'.repeat(35)}:0`
      return new Response(`${line}\r\n`, {
        status: 200,
        headers: { 'content-type': 'text/plain' }
      })
    })
    const { service, store } = await createHarness({ fetch: fetcher })
    await service.setup(MASTER_PASSWORD)
    const exposedFirst = await service.createLogin({
      name: 'Exposed first',
      username: 'visible-user',
      password: exposedPassword
    })
    const exposedSecond = await service.createLogin({
      name: 'Exposed second',
      password: exposedPassword
    })
    await service.createLogin({ name: 'Safe account', password: safePassword })
    const protectedLogin = await service.createLogin({
      name: 'Protected account',
      username: 'protected-user-canary',
      password: 'protected-password-canary',
      reprompt: 1
    })
    const archived = await service.createLogin({
      name: 'Archived account',
      password: 'archived-password-canary'
    })
    const trashed = await service.createLogin({
      name: 'Trashed account',
      password: 'trashed-password-canary'
    })
    await service.archiveLogin({ id: archived.id })
    await service.deleteLogin({ id: trashed.id })

    const internalData = (service as unknown as { data: { logins: { id: string }[] } | null }).data
    const rawProtected = internalData?.logins.find((login) => login.id === protectedLogin.id)
    Object.defineProperties(rawProtected!, {
      password: {
        get: () => {
          throw new Error('exposed report must not read a protected password')
        }
      },
      username: {
        get: () => {
          throw new Error('exposed report must not read a protected username')
        }
      }
    })

    const write = vi.spyOn(store, 'write')
    const generation = await service.unlockedGeneration()
    const report = await service.getExposedPasswordReport()

    expect(report.totals).toEqual({
      analyzedCount: 3,
      exposedPasswordCount: 2,
      protectedSkippedCount: 1
    })
    expect(report.exposedPasswords).toEqual([
      { id: exposedFirst.id, name: 'Exposed first', subtitle: 'visible-user', exposedCount: 42 },
      { id: exposedSecond.id, name: 'Exposed second', subtitle: '', exposedCount: 42 }
    ])
    expect(fetcher).toHaveBeenCalledTimes(2)
    for (const [input, init] of fetcher.mock.calls) {
      expect(String(input)).toMatch(/^https:\/\/api\.pwnedpasswords\.com\/range\/[A-F0-9]{5}$/u)
      expect(new Headers(init?.headers).has('authorization')).toBe(false)
    }
    const payload = JSON.stringify(report)
    for (const forbidden of [
      exposedPassword,
      safePassword,
      exposedHash,
      'protected-password-canary',
      'protected-user-canary',
      'archived-password-canary',
      'trashed-password-canary'
    ]) {
      expect(payload).not.toContain(forbidden)
    }
    expect(write).not.toHaveBeenCalled()
    expect(await service.unlockedGeneration()).toBe(generation)
  })

  it('fails the complete exposed report on HIBP errors and supports explicit cancellation', async () => {
    const failedFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response('service unavailable', {
        status: 503,
        headers: { 'content-type': 'text/plain' }
      })
    )
    const failedHarness = await createHarness({ fetch: failedFetch })
    await failedHarness.service.setup(MASTER_PASSWORD)
    await failedHarness.service.createLogin({ name: 'Candidate', password: 'password' })
    await expect(failedHarness.service.getExposedPasswordReport()).rejects.toMatchObject({
      code: 'HEALTH_CHECK_FAILED'
    })

    const pendingFetch = vi.fn<typeof fetch>().mockImplementation(
      async (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal
          if (signal?.aborted) {
            reject(signal.reason)
            return
          }
          signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
        })
    )
    const pendingHarness = await createHarness({ fetch: pendingFetch })
    await pendingHarness.service.setup(MASTER_PASSWORD)
    await pendingHarness.service.createLogin({ name: 'Candidate', password: 'password' })
    const operation = pendingHarness.service.getExposedPasswordReport()
    const canceledExpectation = expect(operation).rejects.toMatchObject({
      code: 'HEALTH_CHECK_FAILED'
    })
    await vi.waitFor(() => expect(pendingFetch).toHaveBeenCalledOnce())
    expect(pendingHarness.service.cancelExposedPasswordReport()).toBe(true)
    expect(pendingHarness.service.cancelExposedPasswordReport()).toBe(false)
    await canceledExpectation

    const lockFetch = vi.fn<typeof fetch>().mockImplementation(
      async (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init?.signal?.reason), {
            once: true
          })
        })
    )
    const lockHarness = await createHarness({ fetch: lockFetch })
    await lockHarness.service.setup(MASTER_PASSWORD)
    await lockHarness.service.createLogin({ name: 'Candidate', password: 'password' })
    const lockOperation = lockHarness.service.getExposedPasswordReport()
    const lockExpectation = expect(lockOperation).rejects.toMatchObject({ code: 'LOCKED' })
    await vi.waitFor(() => expect(lockFetch).toHaveBeenCalledOnce())
    await expect(lockHarness.service.lock()).resolves.toEqual({ state: 'locked' })
    await lockExpectation
  })

  it('does not hold the vault mutex during HIBP I/O and discards a report after vault changes', async () => {
    const hash = hashPasswordForPwnedLookup('password')
    let finishRequest!: () => void
    const fetcher = vi.fn<typeof fetch>().mockImplementation(
      async () =>
        new Promise<Response>((resolve) => {
          finishRequest = () =>
            resolve(
              new Response(`${hash.slice(5)}:7\r\n`, {
                status: 200,
                headers: { 'content-type': 'text/plain' }
              })
            )
        })
    )
    const { service } = await createHarness({ fetch: fetcher })
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Candidate', password: 'password' })

    const operation = service.getExposedPasswordReport()
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledOnce())
    await expect(
      service.updateLogin({ id: login.id, name: 'Changed while checking' })
    ).resolves.toMatchObject({ id: login.id, name: 'Changed while checking' })
    finishRequest()

    await expect(operation).rejects.toMatchObject({ code: 'HEALTH_CHECK_FAILED' })
  })

  it('queries account breaches only through the configured connector and preserves unavailable', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service, store } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await expect(
      service.getAccountBreachReport({ email: 'member@example.invalid' })
    ).rejects.toMatchObject({ code: 'SYNC_AUTH_REQUIRED' })
    await expect(service.getAccountBreachReport({ email: 'not-an-email' })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const accountReport = vi.spyOn(fake!, 'getAccountBreachReport').mockResolvedValueOnce({
      status: 'complete',
      breaches: [
        {
          name: 'ExampleBreach',
          title: 'Example Breach',
          domain: 'example.invalid',
          breachDate: '2026-01-02',
          addedDate: '2026-01-03T00:00:00Z',
          pwnCount: 123,
          dataClasses: ['Email addresses', 'Passwords'],
          isVerified: true
        }
      ]
    })
    const write = vi.spyOn(store, 'write')

    await expect(
      service.getAccountBreachReport({ email: '  MEMBER@EXAMPLE.INVALID  ' })
    ).resolves.toEqual({
      generatedAt: expect.stringMatching(/^2026-07-14T/u),
      status: 'complete',
      breaches: [
        {
          name: 'ExampleBreach',
          title: 'Example Breach',
          domain: 'example.invalid',
          breachDate: '2026-01-02',
          addedDate: '2026-01-03T00:00:00Z',
          pwnCount: 123,
          dataClasses: ['Email addresses', 'Passwords'],
          isVerified: true
        }
      ]
    })
    expect(accountReport).toHaveBeenCalledWith('member@example.invalid', expect.any(AbortSignal))
    expect(write).not.toHaveBeenCalled()

    accountReport.mockResolvedValueOnce({
      status: 'unavailable',
      reason: 'server-hibp-unconfigured'
    })
    await expect(
      service.getAccountBreachReport({ email: 'other@example.invalid' })
    ).resolves.toEqual({
      generatedAt: expect.stringMatching(/^2026-07-14T/u),
      status: 'unavailable',
      reason: 'server-hibp-unconfigured',
      breaches: []
    })
  })

  it('exposes a bounded account security profile and resends verification through the connector', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await expect(service.getAccountSecurityProfile()).rejects.toMatchObject({
      code: 'SYNC_AUTH_REQUIRED'
    })
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const profile = vi.spyOn(fake!, 'getAccountSecurityProfile')
    const resend = vi.spyOn(fake!, 'resendVerificationEmail')

    await expect(service.getAccountSecurityProfile()).resolves.toEqual({
      name: 'Sync User',
      email: 'sync@example.invalid',
      emailVerified: false,
      twoFactorEnabled: true
    })
    await expect(service.resendAccountVerificationEmail()).resolves.toBeUndefined()
    expect(profile).toHaveBeenCalledOnce()
    expect(resend).toHaveBeenCalledOnce()

    profile.mockImplementation(
      async (signal) =>
        new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
        })
    )
    const pending = service.getAccountSecurityProfile()
    const locked = expect(pending).rejects.toMatchObject({ code: 'LOCKED' })
    await vi.waitFor(() => expect(profile).toHaveBeenCalledTimes(2))
    await expect(service.lock()).resolves.toEqual({ state: 'locked' })
    await locked
  })

  it('returns only renderer-safe account device fields and preserves unavailable', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const devices = vi.spyOn(fake!, 'getAccountDevices')

    const result = await service.getAccountDevices()
    expect(result).toEqual({
      status: 'available',
      devices: [
        {
          name: 'Personal Mac',
          type: 7,
          createdAt: '2026-07-01T00:00:00.000Z',
          lastActivityAt: '2026-07-17T01:02:03.000Z',
          current: true,
          trusted: true,
          pendingAuthRequest: false
        }
      ]
    })
    expect(JSON.stringify(result)).not.toContain('91000000-0000-4000-8000-000000000001')
    expect(devices).toHaveBeenCalledWith(expect.any(AbortSignal))

    devices.mockRejectedValueOnce(new BitwardenDirectError('NOT_FOUND'))
    await expect(service.getAccountDevices()).resolves.toEqual({ status: 'unavailable' })

    fake!.getAccountDevices = undefined
    await expect(service.getAccountDevices()).resolves.toEqual({ status: 'unavailable' })
  })

  it('aborts an in-flight account devices request when the vault locks', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const devices = vi.spyOn(fake!, 'getAccountDevices').mockImplementation(
      async (signal) =>
        new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
        })
    )

    const pending = service.getAccountDevices()
    const locked = expect(pending).rejects.toMatchObject({ code: 'LOCKED' })
    await vi.waitFor(() => expect(devices).toHaveBeenCalledOnce())
    await expect(service.lock()).resolves.toEqual({ state: 'locked' })
    await locked
  })

  it('copies personal API credentials only in main and requires explicit rotation confirmation', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service, copyText, copySensitiveText } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const getApiKey = vi.spyOn(fake!, 'getPersonalApiKey')

    await expect(service.copyAccountApiClientId()).resolves.toBeUndefined()
    expect(copyText).toHaveBeenCalledWith('user.90000000-0000-4000-8000-000000000099')

    const viewRequest = {
      masterPassword: 'remote master password',
      rotate: false,
      confirmRotation: false
    }
    await expect(service.copyPersonalApiKey(viewRequest)).resolves.toEqual({
      rotated: false,
      revisionDate: '2026-07-16T00:00:00Z'
    })
    expect(viewRequest.masterPassword).toBe('')
    expect(copySensitiveText).toHaveBeenLastCalledWith('existing-client-secret', 30)

    const rotateRequest = {
      masterPassword: 'remote master password',
      rotate: true,
      confirmRotation: true
    }
    await expect(service.copyPersonalApiKey(rotateRequest)).resolves.toEqual({
      rotated: true,
      revisionDate: '2026-07-16T00:01:00Z'
    })
    expect(copySensitiveText).toHaveBeenLastCalledWith('rotated-client-secret', 30)
    expect(getApiKey).toHaveBeenNthCalledWith(
      2,
      'remote master password',
      true,
      expect.any(AbortSignal)
    )

    for (const invalid of [
      { masterPassword: 'password', rotate: true, confirmRotation: false },
      { masterPassword: 'password', rotate: false, confirmRotation: true }
    ]) {
      await expect(service.copyPersonalApiKey(invalid)).rejects.toMatchObject({
        code: 'INVALID_INPUT'
      })
      expect(invalid.masterPassword).toBe('')
    }
    expect(getApiKey).toHaveBeenCalledTimes(2)

    getApiKey.mockRejectedValueOnce(new BitwardenDirectError('USER_VERIFICATION_FAILED'))
    await expect(
      service.copyPersonalApiKey({
        masterPassword: 'wrong password',
        rotate: false,
        confirmRotation: false
      })
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })

    getApiKey.mockRejectedValueOnce(new BitwardenDirectError('API_KEY_ROTATION_UNKNOWN'))
    await expect(
      service.copyPersonalApiKey({
        masterPassword: 'remote master password',
        rotate: true,
        confirmRotation: true
      })
    ).rejects.toMatchObject({ code: 'API_KEY_ROTATION_UNKNOWN' })
    expect(copySensitiveText).toHaveBeenCalledTimes(2)
  })

  it('lists 2FA providers and copies the recovery code only through the sensitive clipboard', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service, copySensitiveText } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const recovery = vi.spyOn(fake!, 'getTwoFactorRecoveryCode')

    await expect(service.getTwoFactorStatus()).resolves.toEqual([
      { type: 0, enabled: true },
      { type: 1, enabled: true }
    ])
    const request = { masterPassword: 'remote master password' }
    await expect(service.copyTwoFactorRecoveryCode(request)).resolves.toBeUndefined()
    expect(request.masterPassword).toBe('')
    expect(recovery).toHaveBeenCalledWith('remote master password', expect.any(AbortSignal))
    expect(copySensitiveText).toHaveBeenCalledWith('RECOVERY-CODE', 30)

    recovery.mockRejectedValueOnce(new BitwardenDirectError('USER_VERIFICATION_FAILED'))
    await expect(
      service.copyTwoFactorRecoveryCode({ masterPassword: 'wrong password' })
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })
    expect(copySensitiveText).toHaveBeenCalledOnce()
  })

  it('disables only personal 2FA providers with a consumed fresh proof', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const disable = vi.spyOn(fake!, 'disableTwoFactorProvider')
    const request = {
      type: 0 as const,
      masterPassword: 'remote master password',
      confirm: true as const
    }

    await expect(service.disableTwoFactorProvider(request)).resolves.toBeUndefined()
    expect(request.masterPassword).toBe('')
    expect(disable).toHaveBeenCalledWith(0, 'remote master password', expect.any(AbortSignal))

    for (const invalid of [
      { type: 2 as 0, masterPassword: 'password', confirm: true as const },
      { type: 1 as const, masterPassword: 'password', confirm: false as true },
      { type: 1 as const, masterPassword: '', confirm: true as const }
    ]) {
      await expect(service.disableTwoFactorProvider(invalid)).rejects.toMatchObject({
        code: 'INVALID_INPUT'
      })
      expect(invalid.masterPassword).toBe('')
    }
    expect(disable).toHaveBeenCalledOnce()

    disable.mockRejectedValueOnce(new BitwardenDirectError('USER_VERIFICATION_FAILED'))
    await expect(
      service.disableTwoFactorProvider({
        type: 1,
        masterPassword: 'wrong password',
        confirm: true
      })
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })

    disable.mockRejectedValueOnce(new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN'))
    await expect(
      service.disableTwoFactorProvider({
        type: 1,
        masterPassword: 'remote master password',
        confirm: true
      })
    ).rejects.toMatchObject({ code: 'TWO_FACTOR_MUTATION_UNKNOWN' })
  })

  it('aborts an in-flight 2FA disable when the vault locks', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    vi.spyOn(fake!, 'disableTwoFactorProvider').mockImplementation(
      async (_type, _masterPassword, signal) =>
        new Promise<void>((_resolve, reject) => {
          signal?.addEventListener(
            'abort',
            () => reject(new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')),
            { once: true }
          )
        })
    )

    const request = {
      type: 0 as const,
      masterPassword: 'remote master password',
      confirm: true as const
    }
    const pending = service.disableTwoFactorProvider(request)
    await vi.waitFor(() => expect(request.masterPassword).toBe(''))
    await service.lock()
    await expect(pending).rejects.toMatchObject({ code: 'LOCKED' })
  })

  it('keeps WebAuthn enrollment as one fresh main-only transaction and returns only safe keys', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const registrationRequester = vi.fn<VaultAccountWebAuthnRegistrationRequester>(async () =>
      structuredClone(ACCOUNT_WEBAUTHN_ATTESTATION)
    )
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      },
      requestAccountWebAuthnRegistration: registrationRequester
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const begin = vi.spyOn(fake!, 'beginWebAuthnSetup')
    let observedCompletion: unknown
    const complete = vi
      .spyOn(fake!, 'completeWebAuthnSetup')
      .mockImplementation(async (completion) => {
        observedCompletion = structuredClone(completion)
      })

    const listRequest = { masterPassword: 'fresh list password' }
    const keys = await service.listAccountWebAuthnKeys(listRequest)
    expect(listRequest.masterPassword).toBe('')
    expect(keys).toEqual([{ id: 1, name: 'Existing security key', migrated: false }])
    expect(Object.keys(keys[0]!).sort()).toEqual(['id', 'migrated', 'name'])
    expect(JSON.stringify(keys)).not.toMatch(/challenge|token|attestation|credential/iu)

    const enrollRequest = {
      masterPassword: 'fresh enrollment password',
      name: 'Laptop platform key'
    }
    await expect(service.enrollAccountWebAuthnKey(enrollRequest)).resolves.toBeUndefined()
    expect(enrollRequest).toEqual({ masterPassword: '', name: '' })
    expect(begin).toHaveBeenCalledTimes(2)
    expect(begin).toHaveBeenNthCalledWith(1, 'fresh list password', expect.any(AbortSignal))
    expect(begin).toHaveBeenNthCalledWith(2, 'fresh enrollment password', expect.any(AbortSignal))
    expect(registrationRequester).toHaveBeenCalledWith({
      webVaultUrl: 'https://vault.example.invalid',
      challenge: expect.objectContaining({ challenge: expect.any(String) }),
      signal: expect.any(AbortSignal)
    })
    expect(observedCompletion).toMatchObject({
      id: 2,
      name: 'Laptop platform key',
      verificationMode: 'master-password',
      masterPassword: 'fresh enrollment password',
      attestation: ACCOUNT_WEBAUTHN_ATTESTATION
    })
    expect(complete).toHaveBeenCalledWith(
      {
        id: 2,
        name: '',
        verificationMode: 'master-password',
        masterPassword: '',
        attestation: {
          id: '',
          rawId: '',
          type: 'public-key',
          response: { clientDataJSON: '', attestationObject: '' },
          clientExtensionResults: {},
          authenticatorAttachment: null
        }
      },
      expect.any(AbortSignal)
    )
  })

  it('removes WebAuthn keys with explicit confirmation and maps stable account errors', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      },
      requestAccountWebAuthnRegistration: async () => structuredClone(ACCOUNT_WEBAUTHN_ATTESTATION)
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const remove = vi.spyOn(fake!, 'deleteWebAuthnKey')
    const request = { id: 1, masterPassword: 'fresh removal password', confirm: true as const }
    await expect(service.removeAccountWebAuthnKey(request)).resolves.toBeUndefined()
    expect(request).toEqual({ id: 1, masterPassword: '', confirm: true })
    expect(remove).toHaveBeenCalledWith(1, 'fresh removal password', expect.any(AbortSignal))

    const unconfirmed = { id: 1, masterPassword: 'must clear', confirm: false as true }
    await expect(service.removeAccountWebAuthnKey(unconfirmed)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(unconfirmed.masterPassword).toBe('')

    vi.spyOn(fake!, 'beginWebAuthnSetup').mockRejectedValueOnce(
      new BitwardenDirectError('USER_VERIFICATION_FAILED')
    )
    await expect(
      service.listAccountWebAuthnKeys({ masterPassword: 'wrong password' })
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })

    remove.mockRejectedValueOnce(new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN'))
    await expect(
      service.removeAccountWebAuthnKey({
        id: 1,
        masterPassword: 'fresh removal password',
        confirm: true
      })
    ).rejects.toMatchObject({ code: 'TWO_FACTOR_MUTATION_UNKNOWN' })
  })

  it('aborts and generation-binds WebAuthn enrollment before any stale completion', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    let releaseRegistration!: (value: AccountWebAuthnAttestation) => void
    let registrationSignal: AbortSignal | undefined
    const requester = vi.fn<VaultAccountWebAuthnRegistrationRequester>(
      ({ signal }) =>
        new Promise((resolve) => {
          registrationSignal = signal
          releaseRegistration = resolve
        })
    )
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      },
      requestAccountWebAuthnRegistration: requester
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const complete = vi.spyOn(fake!, 'completeWebAuthnSetup')
    const pending = service.enrollAccountWebAuthnKey({
      masterPassword: 'fresh enrollment password',
      name: 'Stale key'
    })
    await vi.waitFor(() => expect(requester).toHaveBeenCalledOnce())
    await service.lock()
    expect(registrationSignal?.aborted).toBe(true)
    releaseRegistration(structuredClone(ACCOUNT_WEBAUTHN_ATTESTATION))
    await expect(pending).rejects.toMatchObject({ code: 'LOCKED' })
    expect(complete).not.toHaveBeenCalled()
  })

  it('interrupts WebAuthn enrollment when a sync operation takes ownership', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    let registrationSignal: AbortSignal | undefined
    const requester = vi.fn<VaultAccountWebAuthnRegistrationRequester>(
      ({ signal }) =>
        new Promise((_resolve, reject) => {
          registrationSignal = signal
          signal.addEventListener('abort', () => reject(new Error('sync interrupted')), {
            once: true
          })
        })
    )
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      },
      requestAccountWebAuthnRegistration: requester
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const complete = vi.spyOn(fake!, 'completeWebAuthnSetup')
    const pending = service.enrollAccountWebAuthnKey({
      masterPassword: 'fresh enrollment password',
      name: 'Interrupted key'
    })
    await vi.waitFor(() => expect(requester).toHaveBeenCalledOnce())

    await expect(service.syncNow()).resolves.toMatchObject({ conflicts: 0 })
    expect(registrationSignal?.aborted).toBe(true)
    await expect(pending).rejects.toMatchObject({ code: 'LOCKED' })
    expect(complete).not.toHaveBeenCalled()
  })

  it('uses expiring single-use authenticator sessions without exposing server capabilities', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service, copySensitiveText } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const begin = vi.spyOn(fake!, 'beginAuthenticatorSetup')
    const complete = vi.spyOn(fake!, 'completeAuthenticatorSetup')

    const beginRequest = { masterPassword: 'remote master password' }
    const setup = await service.beginAccountAuthenticatorSetup(beginRequest)
    expect(beginRequest.masterPassword).toBe('')
    expect(setup.sessionId).toMatch(/^[0-9a-f-]{36}$/)
    expect(setup).toMatchObject({
      key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      requiresMasterPassword: true
    })
    expect(JSON.stringify(setup)).not.toContain('userVerificationToken')
    expect(begin).toHaveBeenCalledWith('remote master password', expect.any(AbortSignal))

    await service.copyAccountAuthenticatorKey({ sessionId: setup.sessionId })
    expect(copySensitiveText).toHaveBeenCalledWith(setup.key, 30)
    const completeRequest = {
      sessionId: setup.sessionId,
      token: '123456',
      masterPassword: 'remote master password'
    }
    await expect(
      service.completeAccountAuthenticatorSetup(completeRequest)
    ).resolves.toBeUndefined()
    expect(completeRequest).toMatchObject({ token: '', masterPassword: '' })
    expect(complete).toHaveBeenCalledWith(
      {
        key: '',
        token: '',
        verificationMode: 'master-password',
        masterPassword: ''
      },
      expect.any(AbortSignal)
    )
    await expect(
      service.completeAccountAuthenticatorSetup({
        sessionId: setup.sessionId,
        token: '123456',
        masterPassword: 'remote master password'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const abandoned = await service.beginAccountAuthenticatorSetup({
      masterPassword: 'remote master password'
    })
    await service.lock()
    await expect(
      service.copyAccountAuthenticatorKey({ sessionId: abandoned.sessionId })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(copySensitiveText).toHaveBeenCalledOnce()
  })

  it('binds official authenticator capabilities to main and reports ambiguous mutations', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    vi.spyOn(fake!, 'beginAuthenticatorSetup').mockResolvedValue({
      enabled: false,
      key: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      verificationMode: 'server-token',
      userVerificationToken: 'main-only-capability'
    })
    const complete = vi
      .spyOn(fake!, 'completeAuthenticatorSetup')
      .mockRejectedValueOnce(new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN'))

    const setup = await service.beginAccountAuthenticatorSetup({
      masterPassword: 'remote master password'
    })
    expect(setup.requiresMasterPassword).toBe(false)
    expect(JSON.stringify(setup)).not.toContain('main-only-capability')
    await expect(
      service.completeAccountAuthenticatorSetup({ sessionId: setup.sessionId, token: '654321' })
    ).rejects.toMatchObject({ code: 'TWO_FACTOR_MUTATION_UNKNOWN' })
    expect(complete).toHaveBeenCalledWith(
      {
        key: '',
        token: '',
        verificationMode: 'server-token',
        userVerificationToken: ''
      },
      expect.any(AbortSignal)
    )
  })

  it('uses a phased Email 2FA session with fresh Vaultwarden proofs', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const begin = vi.spyOn(fake!, 'beginEmailTwoFactorSetup')
    const send = vi.spyOn(fake!, 'sendEmailTwoFactorSetup')
    const complete = vi.spyOn(fake!, 'completeEmailTwoFactorSetup')

    const beginRequest = { masterPassword: 'remote master password' }
    const setup = await service.beginAccountEmailTwoFactorSetup(beginRequest)
    expect(beginRequest.masterPassword).toBe('')
    expect(setup).toMatchObject({ requiresMasterPassword: true })
    expect(JSON.stringify(setup)).not.toContain('userVerificationToken')
    expect(begin).toHaveBeenCalledWith('remote master password', expect.any(AbortSignal))

    await expect(
      service.completeAccountEmailTwoFactorSetup({
        sessionId: setup.sessionId,
        token: '123456',
        masterPassword: 'remote master password'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const sendRequest = {
      sessionId: setup.sessionId,
      email: 'factor@example.test',
      masterPassword: 'fresh send password'
    }
    await service.sendAccountEmailTwoFactorSetup(sendRequest)
    expect(sendRequest).toMatchObject({ email: '', masterPassword: '' })
    expect(send).toHaveBeenCalledWith(
      {
        email: '',
        verificationMode: 'master-password',
        masterPassword: ''
      },
      expect.any(AbortSignal)
    )
    await expect(
      service.sendAccountEmailTwoFactorSetup({
        sessionId: setup.sessionId,
        email: 'factor@example.test',
        masterPassword: 'must not replay'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const completeRequest = {
      sessionId: setup.sessionId,
      token: '123456',
      masterPassword: 'fresh complete password'
    }
    await service.completeAccountEmailTwoFactorSetup(completeRequest)
    expect(completeRequest).toMatchObject({ token: '', masterPassword: '' })
    expect(complete).toHaveBeenCalledWith(
      {
        email: '',
        token: '',
        verificationMode: 'master-password',
        masterPassword: ''
      },
      expect.any(AbortSignal)
    )
    await expect(
      service.completeAccountEmailTwoFactorSetup({
        sessionId: setup.sessionId,
        token: '123456',
        masterPassword: 'must not replay'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('consumes official Email 2FA sessions when send outcome is unknown', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    vi.spyOn(fake!, 'beginEmailTwoFactorSetup').mockResolvedValue({
      enabled: false,
      email: null,
      verificationMode: 'server-token',
      userVerificationToken: 'main-only-email-capability'
    })
    vi.spyOn(fake!, 'sendEmailTwoFactorSetup').mockRejectedValueOnce(
      new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
    )
    vi.spyOn(fake!, 'completeEmailTwoFactorSetup').mockRejectedValueOnce(
      new BitwardenDirectError('TWO_FACTOR_MUTATION_UNKNOWN')
    )

    const setup = await service.beginAccountEmailTwoFactorSetup({
      masterPassword: 'remote master password'
    })
    expect(setup.requiresMasterPassword).toBe(false)
    expect(JSON.stringify(setup)).not.toContain('main-only-email-capability')
    await expect(
      service.sendAccountEmailTwoFactorSetup({
        sessionId: setup.sessionId,
        email: 'factor@example.test'
      })
    ).rejects.toMatchObject({ code: 'TWO_FACTOR_MUTATION_UNKNOWN' })
    await expect(
      service.sendAccountEmailTwoFactorSetup({
        sessionId: setup.sessionId,
        email: 'factor@example.test'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const completionSetup = await service.beginAccountEmailTwoFactorSetup({
      masterPassword: 'remote master password'
    })
    await service.sendAccountEmailTwoFactorSetup({
      sessionId: completionSetup.sessionId,
      email: 'factor@example.test'
    })
    await expect(
      service.completeAccountEmailTwoFactorSetup({
        sessionId: completionSetup.sessionId,
        token: '123456'
      })
    ).rejects.toMatchObject({ code: 'TWO_FACTOR_MUTATION_UNKNOWN' })
    await expect(
      service.completeAccountEmailTwoFactorSetup({
        sessionId: completionSetup.sessionId,
        token: '123456'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('fails closed for enabled, expired, or locked Email 2FA setup sessions', async () => {
    let currentTime = Date.parse('2026-07-16T00:00:00.000Z')
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      now: () => new Date(currentTime),
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    vi.spyOn(fake!, 'beginEmailTwoFactorSetup').mockResolvedValueOnce({
      enabled: true,
      email: 'factor@example.test',
      verificationMode: 'server-token',
      userVerificationToken: 'must-be-discarded'
    })
    await expect(
      service.beginAccountEmailTwoFactorSetup({ masterPassword: 'remote master password' })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const expired = await service.beginAccountEmailTwoFactorSetup({
      masterPassword: 'remote master password'
    })
    currentTime += 5 * 60 * 1_000 + 1
    await expect(
      service.sendAccountEmailTwoFactorSetup({
        sessionId: expired.sessionId,
        email: 'factor@example.test',
        masterPassword: 'fresh password'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    const abandoned = await service.beginAccountEmailTwoFactorSetup({
      masterPassword: 'remote master password'
    })
    await service.lock()
    await expect(
      service.sendAccountEmailTwoFactorSetup({
        sessionId: abandoned.sessionId,
        email: 'factor@example.test',
        masterPassword: 'fresh password'
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('opens only the fixed HIBP attribution URL after verifying the vault is unlocked', async () => {
    const { service, openExternal } = await createHarness()
    await expect(service.openHibpWebsite()).rejects.toMatchObject({ code: 'LOCKED' })
    await service.setup(MASTER_PASSWORD)

    await expect(service.openHibpWebsite()).resolves.toBeUndefined()
    expect(openExternal).toHaveBeenCalledOnce()
    expect(openExternal).toHaveBeenCalledWith('https://haveibeenpwned.com/')
  })

  it('cancels account-breach I/O, releases the mutex, and fails closed on auth or lock changes', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const accountReport = vi.spyOn(fake!, 'getAccountBreachReport')
    accountReport.mockImplementationOnce(
      async (_email, signal) =>
        new Promise((_resolve, reject) => {
          if (signal?.aborted) {
            reject(new BitwardenDirectError('ABORTED'))
            return
          }
          signal?.addEventListener('abort', () => reject(new BitwardenDirectError('ABORTED')), {
            once: true
          })
        })
    )
    const canceled = service.getAccountBreachReport({ email: 'cancel@example.invalid' })
    const canceledExpectation = expect(canceled).rejects.toMatchObject({
      code: 'HEALTH_CHECK_FAILED'
    })
    await vi.waitFor(() => expect(accountReport).toHaveBeenCalledOnce())
    await expect(service.listLogins()).resolves.toEqual(expect.any(Array))
    expect(service.cancelAccountBreachReport()).toBe(true)
    expect(service.cancelAccountBreachReport()).toBe(false)
    await canceledExpectation

    accountReport.mockRejectedValueOnce(new BitwardenDirectError('AUTH_REQUIRED'))
    await expect(
      service.getAccountBreachReport({ email: 'auth@example.invalid' })
    ).rejects.toMatchObject({ code: 'SYNC_AUTH_REQUIRED' })

    accountReport.mockImplementationOnce(
      async (_email, signal) =>
        new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new BitwardenDirectError('ABORTED')), {
            once: true
          })
        })
    )
    const locked = service.getAccountBreachReport({ email: 'lock@example.invalid' })
    const lockedExpectation = expect(locked).rejects.toMatchObject({ code: 'LOCKED' })
    await vi.waitFor(() => expect(accountReport).toHaveBeenCalledTimes(3))
    await service.lock()
    await lockedExpectation
  })

  it('keeps deleted items in trash, blocks ordinary mutations, and restores or purges them', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Trash test' })
    const first = await service.createLogin({
      type: 'secureNote',
      name: 'First',
      folderId: folder.id,
      notes: 'trash-summary-secret-canary'
    })
    const second = await service.createLogin({ name: 'Second' })

    await service.deleteLogin({ id: first.id })
    expect(await service.listLogins()).toMatchObject([{ id: second.id, deletedAt: null }])
    const [trashed] = await service.listLogins({ deleted: true })
    expect(trashed).toMatchObject({
      id: first.id,
      subtitle: '',
      username: '',
      uri: null,
      deletedAt: expect.any(String)
    })
    expect(JSON.stringify(trashed)).not.toContain('trash-summary-secret-canary')
    await expect(service.getLogin({ id: first.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.updateLogin({ id: first.id, name: 'Blocked' })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.setLoginFavorite({ id: first.id, favorite: true })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.moveLogin({ id: first.id, folderId: null })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.revealPassword({ id: first.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyPassword({ id: first.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const restored = await service.restoreLogin({ id: first.id })
    expect(restored.deletedAt).toBeNull()
    expect((await service.listLogins()).map((login) => login.id)).toContain(first.id)

    await service.deleteLogin({ id: first.id })
    await service.deleteLoginPermanently({ id: first.id })
    await expect(service.getLogin({ id: first.id })).rejects.toMatchObject({ code: 'NOT_FOUND' })
    await service.deleteLogin({ id: second.id })
    await expect(service.emptyTrash()).resolves.toBe(1)
    expect(await service.listLogins({ deleted: true })).toEqual([])
  })

  it('clones an active item locally, preserves supported fields, and excludes passkeys', async () => {
    let fake: ReturnType<typeof createSyncFake> | undefined
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        fake.remoteLogins[0]!.attachments = [
          {
            id: 'source-attachment',
            fileName: 'source-only.txt',
            size: 1,
            sizeName: '1 B',
            legacy: false
          }
        ]
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const source = (await service.listLogins())[0]!
    const sourceBefore = await service.getLogin({ id: source.id })

    const cloned = await service.cloneLogin({ id: source.id })
    expect(cloned).toMatchObject({
      id: expect.not.stringMatching(new RegExp(`^${source.id}$`)),
      name: 'Remote login - Clone',
      type: sourceBefore.type,
      folderId: sourceBefore.folderId,
      favorite: sourceBefore.favorite,
      notes: sourceBefore.notes,
      passkeys: [],
      attachments: [],
      customFields: sourceBefore.customFields
    })
    expect(cloned.lastUsedAt).toBeNull()
    expect(await service.getLogin({ id: source.id })).toEqual(sourceBefore)
    await expect(service.revealPassword({ id: cloned.id })).resolves.toBe('remote-test-secret')
    await expect(
      service.revealEditorSecrets({ id: cloned.id, expectedUpdatedAt: cloned.updatedAt })
    ).resolves.toMatchObject({
      fields: { password: 'remote-test-secret', totp: 'JBSWY3DPEHPK3PXP' },
      customFields: [expect.objectContaining({ value: 'remote-hidden-code' })]
    })

    await expect(service.syncNow()).resolves.toMatchObject({ pushed: 1 })
    const remoteClone = fake!.remoteLogins.find((login) => login.name === 'Remote login - Clone')
    expect(remoteClone).toMatchObject({
      folderId: fake!.remoteLogins[0]!.folderId,
      favorite: false,
      notes: null,
      passkeys: [],
      attachments: []
    })
    expect(sourceBefore.attachments).toHaveLength(1)
    expect(fake!.remoteLogins[0]!.passkeys).toHaveLength(1)
  })

  it('rejects cloning from trash and keeps the clone suffix within the item name limit', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const source = await service.createLogin({ name: 'x'.repeat(256) })
    const cloned = await service.cloneLogin({ id: source.id })
    expect(cloned.name).toHaveLength(256)
    expect(cloned.name).toBe(`${'x'.repeat(248)} - Clone`)

    await service.deleteLogin({ id: source.id })
    await expect(service.cloneLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const emojiSource = await service.createLogin({ name: '😀'.repeat(128) })
    const emojiClone = await service.cloneLogin({ id: emojiSource.id })
    expect(emojiClone.name).toHaveLength(256)
    expect(emojiClone.name).toBe(`${'😀'.repeat(124)} - Clone`)
  })

  it('archives active items, keeps them readable, and restores their prior vault behavior', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Archive' })
    const source = await service.createLogin({
      name: 'Archived login',
      folderId: folder.id,
      favorite: true,
      password: 'archive-secret'
    })

    const archived = await service.archiveLogin({ id: source.id })
    expect(archived.archivedAt).toEqual(expect.any(String))
    expect(await service.listLogins()).toEqual([])
    expect(await service.listLogins({ archived: true })).toMatchObject([
      { id: source.id, archivedAt: archived.archivedAt, favorite: true }
    ])
    await expect(service.getLogin({ id: source.id })).resolves.toMatchObject({
      id: source.id,
      folderId: folder.id,
      archivedAt: archived.archivedAt
    })
    await expect(service.revealPassword({ id: source.id })).resolves.toBe('archive-secret')

    const cloned = await service.cloneLogin({ id: source.id })
    expect(cloned).toMatchObject({ archivedAt: archived.archivedAt, passkeys: [] })
    await expect(service.archiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    const unarchived = await service.unarchiveLogin({ id: source.id })
    expect(unarchived.archivedAt).toBeNull()
    expect(await service.listLogins()).toMatchObject([{ id: source.id }])
    await expect(service.unarchiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    await service.deleteLogin({ id: source.id })
    await expect(service.archiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.unarchiveLogin({ id: source.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
  })

  it('mutates login lifecycle batches atomically with one timestamp and one write', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const first = await service.createLogin({ name: 'First batch item' })
    const second = await service.createLogin({ name: 'Second batch item' })
    const write = vi.spyOn(store, 'write')

    const archived = await service.archiveLogins({ ids: [first.id, second.id] })
    expect(new Set(archived.map((login) => login.archivedAt))).toHaveLength(1)
    expect(new Set(archived.map((login) => login.updatedAt))).toHaveLength(1)
    expect(write).toHaveBeenCalledOnce()

    write.mockClear()
    const unarchived = await service.unarchiveLogins({ ids: [first.id, second.id] })
    expect(unarchived.every((login) => login.archivedAt === null)).toBe(true)
    expect(new Set(unarchived.map((login) => login.updatedAt))).toHaveLength(1)
    expect(write).toHaveBeenCalledOnce()

    await service.archiveLogin({ id: first.id })
    const firstArchivedAt = (await service.getLogin({ id: first.id })).archivedAt
    write.mockClear()
    await expect(service.deleteLogins({ ids: [first.id, second.id] })).resolves.toBe(2)
    const trashed = await service.listLogins({ deleted: true })
    expect(new Set(trashed.map((login) => login.deletedAt))).toHaveLength(1)
    expect(trashed.find((login) => login.id === first.id)?.archivedAt).toBe(firstArchivedAt)
    expect(write).toHaveBeenCalledOnce()

    write.mockClear()
    const restored = await service.restoreLogins({ ids: [first.id, second.id] })
    expect(new Set(restored.map((login) => login.updatedAt))).toHaveLength(1)
    expect(restored.find((login) => login.id === first.id)?.archivedAt).toBe(firstArchivedAt)
    expect(restored.find((login) => login.id === second.id)?.archivedAt).toBeNull()
    expect(write).toHaveBeenCalledOnce()

    await service.deleteLogins({ ids: [first.id, second.id] })
    write.mockClear()
    await expect(service.deleteLoginsPermanently({ ids: [first.id, second.id] })).resolves.toBe(2)
    expect(write).toHaveBeenCalledOnce()
    expect(await service.listLogins({ deleted: true })).toEqual([])
  })

  it('rejects invalid login batches without writes or partial lifecycle changes', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const first = await service.createLogin({ name: 'First validation item' })
    const second = await service.createLogin({ name: 'Second validation item' })
    const write = vi.spyOn(store, 'write')
    const oversizedIds = Array.from(
      { length: 501 },
      (_, index) => `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`
    )

    await expect(service.archiveLogins({ ids: [] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: oversizedIds.slice(0, 500) })).rejects.toMatchObject({
      code: 'NOT_FOUND'
    })
    await expect(service.archiveLogins({ ids: oversizedIds })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: [first.id, 'not-a-uuid'] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: [first.id, first.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.archiveLogins({ ids: [first.id, IDS[10]!] })).rejects.toMatchObject({
      code: 'NOT_FOUND'
    })
    expect(write).not.toHaveBeenCalled()
    expect((await service.listLogins()).map((login) => login.id)).toEqual([first.id, second.id])
  })

  it('validates every batch item state before changing any login', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const first = await service.createLogin({ name: 'Active batch item' })
    const second = await service.createLogin({ name: 'Archived batch item' })
    await service.archiveLogin({ id: second.id })
    const write = vi.spyOn(store, 'write')

    await expect(service.archiveLogins({ ids: [first.id, second.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.unarchiveLogins({ ids: [second.id, first.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(write).not.toHaveBeenCalled()
    expect((await service.getLogin({ id: first.id })).archivedAt).toBeNull()
    expect((await service.getLogin({ id: second.id })).archivedAt).not.toBeNull()

    await service.deleteLogin({ id: first.id })
    write.mockClear()
    await expect(service.deleteLogins({ ids: [second.id, first.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.restoreLogins({ ids: [first.id, second.id] })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(
      service.deleteLoginsPermanently({ ids: [first.id, second.id] })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(write).not.toHaveBeenCalled()
    expect((await service.listLogins({ deleted: true })).map((login) => login.id)).toEqual([
      first.id
    ])
    expect((await service.listLogins({ archived: true })).map((login) => login.id)).toEqual([
      second.id
    ])
  })

  it('records a tombstone for every permanently deleted login in a batch', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const first = (await service.listLogins())[0]!
    const second = await service.createLogin({ name: 'Second mapped batch item' })
    await service.syncNow()
    const remoteIds = fake!.remoteLogins.map((login) => login.id)

    await service.deleteLogins({ ids: [first.id, second.id] })
    await expect(service.deleteLoginsPermanently({ ids: [first.id, second.id] })).resolves.toBe(2)
    await service.syncNow()

    expect(fake!.hardDeletedIds).toEqual(expect.arrayContaining(remoteIds))
    expect(fake!.hardDeletedIds).toHaveLength(2)
    expect(fake!.remoteLogins).toEqual([])
  })

  it('syncs archive atomically and resumes an interrupted content-plus-unarchive', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const { filePath, service } = await createHarness({
      createSyncClient: (sync) => {
        fake ??= createSyncFake(sync.state)
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    const local = (await service.listLogins())[0]!

    await service.updateLogin({ id: local.id, password: 'archive-after-edit' })
    await service.archiveLogin({ id: local.id })
    await expect(service.syncNow()).resolves.toMatchObject({ conflicts: 0, pushed: 1 })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'archive-after-edit',
      archivedAt: expect.any(String)
    })
    await expect(service.listLogins({ archived: true })).resolves.toMatchObject([
      { id: local.id, archivedAt: expect.any(String) }
    ])

    const edit = fake!.editLogin.bind(fake)
    let failOnce = true
    fake!.editLogin = async (id, draft, signal) => {
      if (failOnce) {
        failOnce = false
        throw new Error('injected edit after unarchive failure')
      }
      return edit(id, draft, signal)
    }
    await service.unarchiveLogin({ id: local.id })
    await service.updateLogin({ id: local.id, password: 'unarchive-after-edit' })
    await expect(service.syncNow()).rejects.toMatchObject({ code: 'SYNC_FAILED' })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'archive-after-edit',
      archivedAt: null
    })

    service.dispose()
    const reopened = new VaultService(
      new EncryptedVaultStore(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { createSyncClient: () => fake! }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await expect(reopened.syncNow()).resolves.toMatchObject({ conflicts: 0 })
    expect(fake!.remoteLogins[0]).toMatchObject({
      password: 'unarchive-after-edit',
      archivedAt: null
    })
    expect(await reopened.listLogins()).toMatchObject([{ id: local.id, archivedAt: null }])
  })

  it('tracks actual copy/open use but not reveal, without changing content updatedAt', async () => {
    const { service, copyText, openExternal } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const alpha = await service.createLogin({
      name: 'Alpha',
      username: 'a',
      password: 'alpha-secret',
      uri: 'https://alpha.example'
    })
    const zeta = await service.createLogin({
      name: 'Zeta',
      username: 'z',
      password: 'zeta-secret',
      uri: 'https://zeta.example'
    })

    expect((await service.listLogins()).map((login) => login.name)).toEqual(['Alpha', 'Zeta'])
    expect(await service.revealPassword({ id: zeta.id })).toBe('zeta-secret')
    expect((await service.getLogin({ id: zeta.id })).lastUsedAt).toBeNull()

    const originalUpdatedAt = (await service.getLogin({ id: zeta.id })).updatedAt
    await service.copyPassword({ id: zeta.id })
    expect(copyText).toHaveBeenCalledWith('zeta-secret')
    expect((await service.listLogins())[0]?.id).toBe(zeta.id)
    expect((await service.getLogin({ id: zeta.id })).updatedAt).toBe(originalUpdatedAt)

    const alphaUpdatedAt = (await service.getLogin({ id: alpha.id })).updatedAt
    await service.copyUsername({ id: alpha.id })
    expect(copyText).toHaveBeenCalledWith('a')

    await service.openLoginUri({ id: alpha.id })
    expect(openExternal).toHaveBeenCalledWith('https://alpha.example/')
    expect((await service.listLogins())[0]?.id).toBe(alpha.id)
    expect((await service.getLogin({ id: alpha.id })).updatedAt).toBe(alphaUpdatedAt)
  })

  it('searches only inside the requested scope without indexing protected item secrets', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const scopedFolder = await service.createFolder({ name: 'Scoped' })
    const otherFolder = await service.createFolder({ name: 'Other' })
    const active = await service.createLogin({
      type: 'secureNote',
      name: 'Active note',
      notes: 'quokka searchable body',
      folderId: scopedFolder.id
    })
    const outside = await service.createLogin({
      type: 'secureNote',
      name: 'Outside note',
      notes: 'quokka searchable body',
      folderId: otherFolder.id
    })
    const archived = await service.createLogin({
      name: 'Archive Quokka',
      folderId: scopedFolder.id
    })
    await service.archiveLogin({ id: archived.id })
    const deleted = await service.createLogin({
      name: 'Trash Quokka',
      notes: 'trash-protected-secret',
      folderId: scopedFolder.id
    })
    await service.deleteLogin({ id: deleted.id })
    const protectedItem = await service.createLogin({
      type: 'secureNote',
      name: 'Protected safe name',
      notes: 'quokka-protected-secret',
      folderId: scopedFolder.id,
      reprompt: 1
    })
    const generation = await service.unlockedGeneration()
    const write = vi.spyOn(store, 'write')

    await expect(
      service.listLogins({ folderId: scopedFolder.id, query: 'quokka' })
    ).resolves.toEqual([expect.objectContaining({ id: active.id })])
    await expect(
      service.listLogins({ folderId: otherFolder.id, query: 'quokka' })
    ).resolves.toEqual([expect.objectContaining({ id: outside.id })])
    await expect(
      service.listLogins({ folderId: scopedFolder.id, archived: true, query: 'archive quokka' })
    ).resolves.toEqual([expect.objectContaining({ id: archived.id })])
    await expect(
      service.listLogins({ folderId: scopedFolder.id, deleted: true, query: 'trash quokka' })
    ).resolves.toEqual([expect.objectContaining({ id: deleted.id })])
    await expect(
      service.listLogins({
        folderId: scopedFolder.id,
        deleted: true,
        query: 'trash-protected-secret'
      })
    ).resolves.toEqual([])
    await expect(
      service.listLogins({ folderId: scopedFolder.id, query: 'quokka-protected-secret' })
    ).resolves.toEqual([])
    await expect(
      service.listLogins({ folderId: scopedFolder.id, query: 'protected safe' })
    ).resolves.toEqual([
      expect.objectContaining({
        id: protectedItem.id,
        subtitle: '',
        username: '',
        uri: null
      })
    ])
    await expect(
      service.listLogins({ folderId: scopedFolder.id, query: '' })
    ).resolves.toHaveLength(2)
    await expect(service.listLogins({ query: 7 as never })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.listLogins({ query: 'x'.repeat(1_025) })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(await service.unlockedGeneration()).toBe(generation)
    expect(write).not.toHaveBeenCalled()
  })

  it('generates and copies TOTP in the main process without exposing its seed', async () => {
    const { service, copyText } = await createHarness({ now: () => new Date(59_000) })
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'TOTP example',
      username: 'test-user',
      password: 'test-password',
      totp: 'JBSWY3DPEHPK3PXP'
    })

    expect(login).toMatchObject({ hasTotp: true, passkeys: [] })
    expect(login).not.toHaveProperty('totp')
    await expect(service.getTotp({ id: login.id })).resolves.toEqual({
      code: '996554',
      period: 30,
      remainingSeconds: 1
    })
    await service.copyTotp({ id: login.id })
    expect(copyText).toHaveBeenCalledWith('996554')

    const cleared = await service.updateLogin({ id: login.id, totp: '' })
    expect(cleared.hasTotp).toBe(false)
    await expect(service.getTotp({ id: login.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
  })

  it('generates official Steam and custom-period TOTP vectors at a fixed instant', async () => {
    const { service, copyText } = await createHarness({
      now: () => new Date('2023-01-01T00:00:00.000Z')
    })
    await service.setup(MASTER_PASSWORD)
    const steam = await service.createLogin({
      name: 'Steam test vector',
      totp: 'steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ'
    })
    const custom = await service.createLogin({
      name: 'Custom TOTP test vector',
      totp: 'otpauth://totp/example.invalid?secret=WQIQ25BRKZYCJVYP&digits=8&period=60'
    })

    await expect(service.getTotp({ id: steam.id })).resolves.toEqual({
      code: '7W6CJ',
      period: 30,
      remainingSeconds: 30
    })
    await expect(service.getTotp({ id: custom.id })).resolves.toEqual({
      code: '97730364',
      period: 60,
      remainingSeconds: 60
    })

    await service.copyTotp({ id: steam.id })
    await service.copyTotp({ id: custom.id })
    expect(copyText).toHaveBeenNthCalledWith(1, '7W6CJ')
    expect(copyText).toHaveBeenNthCalledWith(2, '97730364')
  })

  it('preserves opaque TOTP values through create, update, and sync but refuses to use them', async () => {
    let fake: ReturnType<typeof createSyncFake> | null = null
    const remoteOpaqueTotp = 'vaultwarden-opaque://totp?format=future'
    const createdOpaqueTotp = 'future-totp://created?format=opaque'
    const updatedOpaqueTotp = 'future-totp://updated?format=opaque'
    const { service, copyText } = await createHarness({
      createSyncClient: (sync) => {
        fake = createSyncFake(sync.state)
        fake.remoteLogins[0]!.totp = remoteOpaqueTotp
        return fake
      }
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })

    const remote = (await service.listLogins())[0]!
    await expect(
      service.revealEditorSecrets({ id: remote.id, expectedUpdatedAt: remote.updatedAt })
    ).resolves.toMatchObject({ fields: { totp: remoteOpaqueTotp } })
    await expect(service.getTotp({ id: remote.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyTotp({ id: remote.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })

    const created = await service.createLogin({
      name: 'Opaque TOTP item',
      totp: createdOpaqueTotp
    })
    await expect(
      service.revealEditorSecrets({ id: created.id, expectedUpdatedAt: created.updatedAt })
    ).resolves.toMatchObject({ fields: { totp: createdOpaqueTotp } })
    const updated = await service.updateLogin({ id: created.id, totp: updatedOpaqueTotp })
    await expect(
      service.revealEditorSecrets({ id: updated.id, expectedUpdatedAt: updated.updatedAt })
    ).resolves.toMatchObject({ fields: { totp: updatedOpaqueTotp } })
    await expect(service.getTotp({ id: updated.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyTotp({ id: updated.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(copyText).not.toHaveBeenCalled()

    await expect(service.syncNow()).resolves.toMatchObject({ pushed: 1 })
    expect(fake!.remoteLogins.find((login) => login.name === 'Opaque TOTP item')?.totp).toBe(
      updatedOpaqueTotp
    )
  })

  it('zeroes the active key on lock and accepts canonically equivalent passwords', async () => {
    const { filePath, service } = await createHarness()
    const decomposedPassword = `secure-password-${'e\u0301'}`
    const composedPassword = `secure-password-${'é'}`
    await service.setup(decomposedPassword)
    await service.createLogin({ name: 'Example', username: '', password: 'secret' })
    await service.lock()
    expect(await service.status()).toEqual({ state: 'locked' })
    await expect(service.listLogins()).rejects.toMatchObject({ code: 'LOCKED' })

    const secondService = new VaultService(new EncryptedVaultStore(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(secondService.unlock('definitely the wrong password')).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })
    await expect(secondService.unlock(composedPassword)).resolves.toEqual({ state: 'unlocked' })
    expect((await secondService.listLogins())[0]?.name).toBe('Example')
  })

  it('rejects authenticated ciphertext tampering', async () => {
    const { filePath, service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Example', username: '', password: 'secret' })
    await service.lock()

    const envelope = JSON.parse(await readFile(filePath, 'utf8')) as { ciphertext: string }
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64')
    ciphertext[0] = ciphertext[0]! ^ 1
    envelope.ciphertext = ciphertext.toString('base64')
    ciphertext.fill(0)
    await writeFile(filePath, JSON.stringify(envelope), { mode: 0o600 })

    await expect(service.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'INVALID_MASTER_PASSWORD'
    })
    expect(await service.status()).toEqual({ state: 'locked' })
  })

  it('rejects non-http URLs without marking the login as used', async () => {
    const { service, openExternal } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Unsafe',
      username: '',
      password: '',
      uri: 'file:///tmp/not-allowed'
    })
    await expect(service.openLoginUri({ id: login.id })).rejects.toMatchObject({
      code: 'INVALID_URL'
    })
    expect(openExternal).not.toHaveBeenCalled()
    expect((await service.getLogin({ id: login.id })).lastUsedAt).toBeNull()
  })

  it('stores all five item types without exposing sensitive fields in list or detail responses', async () => {
    const { service, copyText } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const folder = await service.createFolder({ name: 'Private' })
    const card = await service.createLogin({
      type: 'card',
      name: 'Test card',
      cardholderName: 'Test holder',
      brand: 'visa',
      number: '4242424242424242',
      expMonth: '12',
      expYear: '2030',
      code: '123',
      folderId: folder.id
    })
    const identity = await service.createLogin({
      type: 'identity',
      name: 'Test identity',
      firstName: 'Test',
      lastName: 'Person',
      email: 'person@example.invalid',
      ssn: '123-45-6789',
      identityUsername: 'identity-user'
    })
    const note = await service.createLogin({
      type: 'secureNote',
      name: 'Test note',
      notes: 'private note body'
    })
    const sshKey = await service.createLogin({
      type: 'sshKey',
      name: 'Test SSH key',
      privateKey: '-----BEGIN PRIVATE KEY-----\nprivate-test-key\n-----END PRIVATE KEY-----',
      publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest key@example.invalid',
      fingerprint: 'SHA256:test'
    })

    expect((await service.listLogins()).map((item) => item.type)).toEqual([
      'card',
      'identity',
      'secureNote',
      'sshKey'
    ])
    expect((await service.listLogins()).find((item) => item.id === card.id)).toMatchObject({
      subtitle: '•••• 4242',
      username: '',
      uri: null
    })
    expect((await service.listLogins()).find((item) => item.id === note.id)).toMatchObject({
      subtitle: 'private note body'
    })
    expect(await service.getLogin({ id: note.id })).toMatchObject({
      type: 'secureNote',
      notes: 'private note body'
    })
    const multilineNote = `\n${'A'.repeat(100)}\nsecond line`
    await service.updateLogin({ id: note.id, notes: multilineNote })
    expect((await service.listLogins()).find((item) => item.id === note.id)?.subtitle).toBe(
      `${'A'.repeat(80)}…`
    )
    expect((await service.getLogin({ id: note.id })).notes).toBe(multilineNote)
    const emojiNote = `${'A'.repeat(79)}👨‍👩‍👧‍👦B`
    await service.updateLogin({ id: note.id, notes: emojiNote })
    expect((await service.listLogins()).find((item) => item.id === note.id)?.subtitle).toBe(
      `${'A'.repeat(79)}👨‍👩‍👧‍👦…`
    )
    await service.updateLogin({ id: note.id, notes: ' \r\n \n' })
    expect((await service.listLogins()).find((item) => item.id === note.id)?.subtitle).toBe('')
    expect('number' in card).toBe(false)
    expect('code' in card).toBe(false)
    expect('ssn' in identity).toBe(false)
    expect('privateKey' in sshKey).toBe(false)
    expect(await service.getLogin({ id: sshKey.id })).not.toHaveProperty('privateKey')
    expect(await service.revealSecret({ id: card.id, field: 'number' })).toBe('4242424242424242')
    await service.copyField({ id: identity.id, field: 'identityUsername' })
    expect(copyText).toHaveBeenCalledWith('identity-user')
    expect(await service.revealSecret({ id: sshKey.id, field: 'privateKey' })).toContain(
      'private-test-key'
    )
    await service.updateLogin({ id: card.id, number: '5555555555554444', code: '999' })
    expect(await service.revealSecret({ id: card.id, field: 'number' })).toBe('5555555555554444')
    await service.moveLogin({ id: card.id, folderId: null })
    expect((await service.getLogin({ id: card.id })).folderId).toBeNull()
    await service.deleteLogin({ id: note.id })
    expect((await service.listLogins()).map((item) => item.id)).not.toContain(note.id)
  })

  it('reveals a complete editor secret snapshot for every item type', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Login secrets',
      password: 'login-secret',
      totp: 'JBSWY3DPEHPK3PXP',
      customFields: [
        { source: null, name: 'recovery', type: 'hidden', value: 'custom-secret', linkedId: null }
      ]
    })
    const card = await service.createLogin({
      type: 'card',
      name: 'Card secrets',
      number: '4111111111111111',
      code: '123'
    })
    const identity = await service.createLogin({
      type: 'identity',
      name: 'Identity secrets',
      ssn: 'identity-secret',
      passportNumber: 'passport-secret',
      licenseNumber: 'license-secret'
    })
    const note = await service.createLogin({ type: 'secureNote', name: 'No secrets' })
    const sshKey = await service.createLogin({
      type: 'sshKey',
      name: 'SSH secret',
      privateKey: 'private-key-secret'
    })

    await expect(
      service.revealEditorSecrets({ id: login.id, expectedUpdatedAt: login.updatedAt })
    ).resolves.toEqual({
      fields: { password: 'login-secret', totp: 'JBSWY3DPEHPK3PXP' },
      customFields: [
        {
          source: { index: 0, name: 'recovery', type: 'hidden', linkedId: null },
          value: 'custom-secret'
        }
      ]
    })
    await expect(
      service.revealEditorSecrets({ id: card.id, expectedUpdatedAt: card.updatedAt })
    ).resolves.toEqual({
      fields: { number: '4111111111111111', code: '123' },
      customFields: []
    })
    await expect(
      service.revealEditorSecrets({ id: identity.id, expectedUpdatedAt: identity.updatedAt })
    ).resolves.toEqual({
      fields: {
        ssn: 'identity-secret',
        passportNumber: 'passport-secret',
        licenseNumber: 'license-secret'
      },
      customFields: []
    })
    await expect(
      service.revealEditorSecrets({ id: note.id, expectedUpdatedAt: note.updatedAt })
    ).resolves.toEqual({ fields: {}, customFields: [] })
    await expect(
      service.revealEditorSecrets({ id: sshKey.id, expectedUpdatedAt: sshKey.updatedAt })
    ).resolves.toEqual({ fields: { privateKey: 'private-key-secret' }, customFields: [] })

    await service.updateLogin({ id: login.id, name: 'Updated login secrets' })
    await expect(
      service.revealEditorSecrets({ id: login.id, expectedUpdatedAt: login.updatedAt })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('ignores empty fields from other item types while preserving active field clears', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const editorFields = { ...emptyItemFields }
    const itemTypes = ['login', 'card', 'identity', 'secureNote', 'sshKey'] as const
    const created: LoginView[] = []

    for (const type of itemTypes) {
      created.push(
        await service.createLogin({
          type,
          name: `${type} editor payload`,
          ...editorFields,
          ...(type === 'login' ? { username: 'before-clear', password: 'secret' } : {})
        })
      )
    }

    expect(created.map((item) => item.type)).toEqual(itemTypes)
    const login = created[0]!

    await expect(
      service.updateLogin({
        id: login.id,
        ...editorFields,
        username: ''
      })
    ).resolves.toMatchObject({ username: '' })
    await expect(service.revealPassword({ id: login.id })).resolves.toBe('')

    await expect(
      service.updateLogin({ id: login.id, cardholderName: 'cross-type value' })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('creates all four custom field types without exposing hidden or linked values', async () => {
    const { service, copyText } = await createHarness()
    await service.setup(MASTER_PASSWORD)

    const login = await service.createLogin({
      name: 'Custom fields',
      username: 'linked-user',
      customFields: [
        { source: null, name: 'member-id', type: 'text', value: 'member-42', linkedId: null },
        { source: null, name: 'recovery', type: 'hidden', value: 'secret-42', linkedId: null },
        { source: null, name: 'enabled', type: 'boolean', value: 'true', linkedId: null },
        { source: null, name: 'account', type: 'linked', value: null, linkedId: 100 }
      ]
    })

    expect(login.customFields).toEqual([
      { name: 'member-id', type: 'text', value: 'member-42', linkedId: null },
      { name: 'recovery', type: 'hidden', value: null, linkedId: null },
      { name: 'enabled', type: 'boolean', value: 'true', linkedId: null },
      { name: 'account', type: 'linked', value: null, linkedId: 100 }
    ])
    await expect(service.revealCustomField(customFieldRequest(login, 1))).resolves.toBe('secret-42')
    await service.copyCustomField(customFieldRequest(login, 3))
    expect(copyText).toHaveBeenCalledWith('linked-user')
  })

  it('updates, deletes, and reorders custom fields as one complete array', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Custom fields',
      customFields: [
        { source: null, name: 'first', type: 'text', value: '1', linkedId: null },
        { source: null, name: 'delete-me', type: 'text', value: '2', linkedId: null },
        { source: null, name: 'last', type: 'boolean', value: 'false', linkedId: null }
      ]
    })

    const updated = await service.updateLogin({
      id: login.id,
      customFields: [
        {
          source: { index: 2, name: 'last', type: 'boolean', linkedId: null },
          name: 'last-first',
          type: 'boolean',
          value: 'true',
          linkedId: null
        },
        {
          source: { index: 0, name: 'first', type: 'text', linkedId: null },
          name: 'first-second',
          type: 'text',
          value: 'updated',
          linkedId: null
        },
        { source: null, name: 'new-third', type: 'text', value: '3', linkedId: null }
      ]
    })

    expect(updated.customFields).toEqual([
      { name: 'last-first', type: 'boolean', value: 'true', linkedId: null },
      { name: 'first-second', type: 'text', value: 'updated', linkedId: null },
      { name: 'new-third', type: 'text', value: '3', linkedId: null }
    ])
  })

  it('records password and changed hidden fields in official order and caps history at five', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({
      name: 'History',
      password: 'password-zero',
      customFields: [
        { source: null, name: 'alpha', type: 'hidden', value: 'alpha-secret', linkedId: null },
        { source: null, name: 'beta', type: 'hidden', value: 'beta-secret', linkedId: null }
      ]
    })
    expect(created.passwordHistoryCount).toBe(0)
    expect(created).not.toHaveProperty('passwordHistory')

    const updated = await service.updateLogin({
      id: created.id,
      password: 'password-one',
      customFields: [
        {
          source: { index: 1, name: 'beta', type: 'hidden', linkedId: null },
          name: 'renamed-beta',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })
    expect(updated.passwordHistoryCount).toBe(3)
    expect(
      (await service.getPasswordHistory({ id: created.id })).map((entry) => entry.password)
    ).toEqual(['beta: beta-secret', 'alpha: alpha-secret', 'password-zero'])

    for (const password of ['password-two', 'password-three', 'password-four']) {
      await service.updateLogin({ id: created.id, password })
    }
    expect(
      (await service.getPasswordHistory({ id: created.id })).map((entry) => entry.password)
    ).toEqual([
      'password-three',
      'password-two',
      'password-one',
      'beta: beta-secret',
      'alpha: alpha-secret'
    ])
    await service.updateLogin({ id: created.id, password: 'password-three' })
    await service.updateLogin({ id: created.id, password: 'password-four' })
    expect(
      (await service.getPasswordHistory({ id: created.id })).map((entry) => entry.password)
    ).toEqual(['password-three', 'password-four', 'password-three', 'password-two', 'password-one'])
  })

  it('restores a stale-safe password-history entry and records the replaced password', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({ name: 'Restore history', password: 'old-secret' })
    const updated = await service.updateLogin({ id: created.id, password: 'current-secret' })
    const [entry] = await service.getPasswordHistory({ id: created.id })
    expect(entry).toMatchObject({ password: 'old-secret' })

    const restored = await service.restorePasswordHistory({
      id: created.id,
      index: 0,
      lastUsedDate: entry!.lastUsedDate,
      expectedUpdatedAt: updated.updatedAt
    })
    await expect(service.revealPassword({ id: created.id })).resolves.toBe('old-secret')
    await expect(service.getPasswordHistory({ id: created.id })).resolves.toMatchObject([
      { password: 'current-secret' },
      { password: 'old-secret', lastUsedDate: entry!.lastUsedDate }
    ])
    await expect(
      service.restorePasswordHistory({
        id: created.id,
        index: 0,
        lastUsedDate: entry!.lastUsedDate,
        expectedUpdatedAt: updated.updatedAt
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(restored.updatedAt).not.toBe(updated.updatedAt)
  })

  it('consumes duplicate hidden fields as a multiset when recording removed secrets', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({
      name: 'Duplicate hidden history',
      password: 'old-password',
      customFields: [
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null },
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null }
      ]
    })

    await service.updateLogin({
      id: created.id,
      password: 'new-password',
      customFields: [
        {
          source: { index: 0, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })
    expect(await service.getPasswordHistory({ id: created.id })).toMatchObject([
      { password: 'duplicate: same-secret' },
      { password: 'old-password' }
    ])

    const renamed = await service.createLogin({
      name: 'Changed duplicates',
      customFields: [
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null },
        { source: null, name: 'duplicate', type: 'hidden', value: 'same-secret', linkedId: null }
      ]
    })
    await service.updateLogin({
      id: renamed.id,
      customFields: [
        {
          source: { index: 0, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'renamed',
          type: 'hidden',
          value: null,
          linkedId: null
        },
        {
          source: { index: 1, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'text',
          value: 'visible-value',
          linkedId: null
        }
      ]
    })
    expect(await service.getPasswordHistory({ id: renamed.id })).toMatchObject([
      { password: 'duplicate: same-secret' },
      { password: 'duplicate: same-secret' }
    ])
  })

  it('starts clones with empty history, retains archive/trash history, and rejects trash reads', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({ name: 'Lifecycle history', password: 'old-secret' })
    await service.updateLogin({ id: created.id, password: 'new-secret' })
    const clone = await service.cloneLogin({ id: created.id })
    expect(clone.passwordHistoryCount).toBe(0)
    await expect(service.getPasswordHistory({ id: clone.id })).resolves.toEqual([])

    await service.archiveLogin({ id: created.id })
    await expect(service.getPasswordHistory({ id: created.id })).resolves.toMatchObject([
      { password: 'old-secret' }
    ])
    await service.deleteLogin({ id: created.id })
    await expect(service.getPasswordHistory({ id: created.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await service.restoreLogin({ id: created.id })
    await expect(service.getPasswordHistory({ id: created.id })).resolves.toMatchObject([
      { password: 'old-secret' }
    ])
  })

  it('rejects reveal and copy requests from a stale custom field snapshot', async () => {
    const { service, copyText } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const original = await service.createLogin({
      name: 'Stale reads',
      customFields: [
        { source: null, name: 'duplicate', type: 'hidden', value: 'first-secret', linkedId: null },
        { source: null, name: 'duplicate', type: 'hidden', value: 'second-secret', linkedId: null }
      ]
    })
    const staleFirst = customFieldRequest(original, 0)

    await service.updateLogin({
      id: original.id,
      customFields: [
        {
          source: { index: 1, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'hidden',
          value: null,
          linkedId: null
        },
        {
          source: { index: 0, name: 'duplicate', type: 'hidden', linkedId: null },
          name: 'duplicate',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })

    await expect(service.revealCustomField(staleFirst)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(service.copyCustomField(staleFirst)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    expect(copyText).not.toHaveBeenCalled()
  })

  it('rejects an editor save when the item revision changed after its snapshot', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const snapshot = await service.createLogin({
      name: 'Concurrent edit',
      customFields: [
        { source: null, name: 'environment', type: 'text', value: 'old', linkedId: null }
      ]
    })
    await service.updateLogin({
      id: snapshot.id,
      customFields: [
        {
          source: { index: 0, name: 'environment', type: 'text', linkedId: null },
          name: 'environment',
          type: 'text',
          value: 'newer',
          linkedId: null
        }
      ]
    })

    await expect(
      service.updateLogin({
        id: snapshot.id,
        expectedUpdatedAt: snapshot.updatedAt,
        name: 'Stale overwrite',
        customFields: [
          {
            source: { index: 0, name: 'environment', type: 'text', linkedId: null },
            name: 'environment',
            type: 'text',
            value: 'old',
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(service.getLogin({ id: snapshot.id })).resolves.toMatchObject({
      name: 'Concurrent edit',
      customFields: [{ name: 'environment', value: 'newer' }]
    })
  })

  it('preserves an existing hidden value only for a hidden-to-hidden null update and can clear it', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Hidden field',
      customFields: [
        { source: null, name: 'secret', type: 'hidden', value: 'keep-me', linkedId: null }
      ]
    })

    await service.updateLogin({
      id: login.id,
      customFields: [
        {
          source: { index: 0, name: 'secret', type: 'hidden', linkedId: null },
          name: 'renamed-secret',
          type: 'hidden',
          value: null,
          linkedId: null
        }
      ]
    })
    await expect(
      service.revealCustomField(customFieldRequest(await service.getLogin({ id: login.id }), 0))
    ).resolves.toBe('keep-me')

    await expect(
      service.updateLogin({
        id: login.id,
        customFields: [
          {
            source: { index: 0, name: 'renamed-secret', type: 'hidden', linkedId: null },
            name: 'not-hidden',
            type: 'text',
            value: null,
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.revealCustomField(customFieldRequest(await service.getLogin({ id: login.id }), 0))
    ).resolves.toBe('keep-me')

    await service.updateLogin({
      id: login.id,
      customFields: [
        {
          source: { index: 0, name: 'renamed-secret', type: 'hidden', linkedId: null },
          name: 'renamed-secret',
          type: 'hidden',
          value: '',
          linkedId: null
        }
      ]
    })
    await expect(
      service.revealCustomField(customFieldRequest(await service.getLogin({ id: login.id }), 0))
    ).resolves.toBe('')
  })

  it('rejects stale or duplicated custom field sources without applying any part of the update', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({
      name: 'Atomic fields',
      customFields: [
        { source: null, name: 'first', type: 'text', value: '1', linkedId: null },
        { source: null, name: 'second', type: 'text', value: '2', linkedId: null }
      ]
    })
    const before = await service.getLogin({ id: login.id })
    const write = vi.spyOn(store, 'write')

    await expect(
      service.updateLogin({
        id: login.id,
        customFields: [
          {
            source: { index: 0, name: 'first', type: 'text', linkedId: null },
            name: 'changed',
            type: 'text',
            value: 'changed',
            linkedId: null
          },
          {
            source: { index: 1, name: 'stale-name', type: 'text', linkedId: null },
            name: 'second',
            type: 'text',
            value: 'changed',
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })

    expect(write).not.toHaveBeenCalled()
    expect(await service.getLogin({ id: login.id })).toEqual(before)

    await expect(
      service.updateLogin({
        id: login.id,
        customFields: [
          {
            source: { index: 0, name: 'first', type: 'text', linkedId: null },
            name: 'first',
            type: 'text',
            value: '1',
            linkedId: null
          },
          {
            source: { index: 0, name: 'first', type: 'text', linkedId: null },
            name: 'duplicate',
            type: 'text',
            value: '2',
            linkedId: null
          }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('rejects invalid linked targets, boolean values, null values, and custom field limits', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)

    await expect(
      service.createLogin({
        type: 'card',
        name: 'Invalid linked field',
        customFields: [
          { source: null, name: 'login-only', type: 'linked', value: null, linkedId: 100 }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Invalid linked value',
        customFields: [
          { source: null, name: 'username', type: 'linked', value: 'discard-me', linkedId: 100 }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Invalid boolean field',
        customFields: [
          { source: null, name: 'enabled', type: 'boolean', value: 'yes', linkedId: null }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Invalid null field',
        customFields: [{ source: null, name: 'text', type: 'text', value: null, linkedId: null }]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too long',
        customFields: [
          { source: null, name: 'value', type: 'text', value: 'x'.repeat(5_001), linkedId: null }
        ]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too many',
        customFields: Array.from({ length: 1_001 }, (_, index) => ({
          source: null,
          name: `field-${index}`,
          type: 'text' as const,
          value: '',
          linkedId: null
        }))
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('moves multiple logins atomically', async () => {
    const { service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const source = await service.createFolder({ name: 'Source' })
    const destination = await service.createFolder({ name: 'Destination' })
    const first = await service.createLogin({ name: 'First', folderId: source.id })
    const second = await service.createLogin({ name: 'Second', folderId: source.id })
    const write = vi.spyOn(store, 'write')

    const moved = await service.moveLogins({
      ids: [first.id, second.id],
      folderId: destination.id
    })

    expect(moved.map((login) => login.id)).toEqual([first.id, second.id])
    expect(moved.every((login) => login.folderId === destination.id)).toBe(true)
    expect(new Set(moved.map((login) => login.updatedAt))).toHaveLength(1)
    expect(write).toHaveBeenCalledOnce()
    expect(
      (await service.listLogins({ folderId: destination.id })).map((login) => login.id)
    ).toEqual([first.id, second.id])
  })

  it('does not partially move logins when any id is invalid or missing', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const source = await service.createFolder({ name: 'Source' })
    const destination = await service.createFolder({ name: 'Destination' })
    const first = await service.createLogin({ name: 'First', folderId: source.id })
    const second = await service.createLogin({ name: 'Second', folderId: source.id })
    const original = await service.listLogins()

    await expect(
      service.moveLogins({ ids: [first.id, 'not-a-uuid'], folderId: destination.id })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    expect(await service.listLogins()).toEqual(original)

    await expect(
      service.moveLogins({ ids: [first.id, IDS[5]!], folderId: destination.id })
    ).rejects.toMatchObject({ code: 'NOT_FOUND' })
    expect(await service.listLogins()).toEqual(original)
    expect((await service.getLogin({ id: second.id })).folderId).toBe(source.id)
  })

  it('migrates V1 through V11 login records to V14 items', async () => {
    for (const version of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] as const) {
      const directory = await mkdtemp(join(tmpdir(), 'bearwarden-migration-test-'))
      temporaryDirectories.push(directory)
      const filePath = join(directory, 'vault', 'vault.json')
      const createdAt = '2026-07-14T00:00:00.000Z'
      const legacyData = {
        version,
        createdAt,
        updatedAt: createdAt,
        folders: [],
        logins: [
          {
            ...emptyItemFields,
            id: IDS[0],
            type: 'login',
            name: `Legacy V${version}`,
            username: 'legacy-user',
            password: 'legacy-secret',
            uri: 'https://legacy.example.invalid',
            notes: null,
            folderId: null,
            favorite: false,
            lastUsedAt: null,
            createdAt,
            updatedAt: createdAt,
            ...(version >= 7 ? { deletedAt: null } : {}),
            ...(version >= 9 ? { archivedAt: null } : {}),
            ...(version >= 10 ? { reprompt: 0 } : {}),
            ...(version >= 11
              ? {
                  uris: [{ uri: 'https://legacy.example.invalid', match: null }],
                  passwordHistory: [
                    {
                      password: 'untrusted-pre-v12-history',
                      lastUsedDate: '2026-07-13T00:00:00.000Z'
                    }
                  ]
                }
              : {}),
            passkeys: [],
            ...(version >= 6 ? { customFields: [] } : {})
          }
        ],
        ...(version === 1
          ? {}
          : {
              sync: {
                provider: 'bitwarden',
                serverUrl: 'https://vault.example.invalid',
                email: 'legacy@example.invalid',
                state:
                  version === 2
                    ? null
                    : {
                        session: null,
                        deviceIdentifier: IDS[1],
                        profileId: null,
                        securityStamp: null
                      },
                lastSyncAt: null,
                folderMappings: [],
                loginMappings: [],
                folderTombstones: [],
                loginTombstones: []
              }
            })
      }
      const store = new EncryptedVaultStore<unknown>(filePath)
      const material = await store.initialize(MASTER_PASSWORD, legacyData)
      material.key.fill(0)
      material.salt.fill(0)
      const service = new VaultService(store, { copyText: vi.fn(), openExternal: vi.fn() })

      await expect(service.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
      const migrated = (await service.listLogins())[0]!
      expect(migrated).toMatchObject({
        type: 'login',
        username: 'legacy-user',
        deletedAt: null,
        archivedAt: null,
        reprompt: 0,
        uri: 'https://legacy.example.invalid',
        uris: [{ uri: 'https://legacy.example.invalid', match: null }]
      })
      await expect(service.getLogin({ id: migrated.id })).resolves.toMatchObject({
        customFields: [],
        passwordHistoryCount: 0
      })
      await expect(service.getPasswordHistory({ id: migrated.id })).resolves.toEqual([])
      await expect(service.generatorHistory()).resolves.toEqual([])
      expect(await service.revealPassword({ id: migrated.id })).toBe('legacy-secret')
      await service.lock()
      const unlocked = await store.unlock(MASTER_PASSWORD)
      expect((unlocked.data as { version: number }).version).toBe(19)
      unlocked.key.fill(0)
      unlocked.salt.fill(0)
    }
  }, 15_000)

  it('tracks encrypted local generator history, deduplicates, copies safely, and retains it across lock', async () => {
    const { copyText, filePath, service, store } = await createHarness({ randomInt: () => 0 })
    await service.setup(MASTER_PASSWORD)

    const password = await service.generateCredential({ algorithm: 'password', options: {} })
    await service.copyGeneratorHistory(password.historyLocator)
    expect(copyText).toHaveBeenLastCalledWith(password.credential)

    const write = vi.spyOn(store, 'write')
    const duplicate = await service.generateCredential({ algorithm: 'password', options: {} })
    expect(duplicate.credential).toBe(password.credential)
    expect(duplicate.historyLocator).toEqual(password.historyLocator)
    expect(write).not.toHaveBeenCalled()

    const passphrase = await service.generateCredential({ algorithm: 'passphrase', options: {} })
    const username = await service.generateCredential({
      algorithm: 'username',
      options: { capitalize: true, includeNumber: true }
    })
    const subaddress = await service.generateCredential({
      algorithm: 'subaddress',
      email: 'bear@example.invalid'
    })
    const catchall = await service.generateCredential({
      algorithm: 'catchall',
      domain: 'example.invalid'
    })
    expect(passphrase.credential).toBe('abacus-abacus-abacus-abacus-abacus-abacus')
    expect(username.credential).toBe('Abacus0000')
    expect(subaddress.credential).toBe('bear+aaaaaaaa@example.invalid')
    expect(catchall.credential).toBe('aaaaaaaa@example.invalid')

    const history = await service.generatorHistory()
    expect(history.map((entry) => entry.algorithm)).toEqual([
      'catchall',
      'subaddress',
      'username',
      'passphrase',
      'password'
    ])
    await expect(service.copyGeneratorHistory(password.historyLocator)).rejects.toMatchObject({
      code: 'INVALID_INPUT'
    })
    await expect(
      service.copyGeneratorHistory({
        index: 4,
        generationDate: password.generationDate,
        category: password.category,
        algorithm: password.algorithm
      })
    ).resolves.toBeUndefined()

    const encrypted = await readFile(filePath, 'utf8')
    for (const secret of history.map((entry) => entry.credential)) {
      expect(encrypted).not.toContain(secret)
    }
    await service.lock()
    await expect(service.generatorHistory()).rejects.toMatchObject({ code: 'LOCKED' })
    await service.unlock(MASTER_PASSWORD)
    expect(await service.generatorHistory()).toEqual(history)
    await service.clearGeneratorHistory()
    await expect(service.generatorHistory()).resolves.toEqual([])
  })

  it('generates transient SSH key material only while unlocked without recording history', async () => {
    const { service, store } = await createHarness()

    await expect(service.generateSshKey()).rejects.toMatchObject({ code: 'LOCKED' })
    await service.setup(MASTER_PASSWORD)
    const write = vi.spyOn(store, 'write')
    const historyBefore = await service.generatorHistory()

    const generated = await service.generateSshKey()

    expect(generated).toEqual({
      privateKey: expect.any(String),
      publicKey: expect.any(String),
      fingerprint: expect.any(String)
    })
    expect(generated.privateKey).not.toBe('')
    expect(generated.publicKey).not.toBe('')
    expect(generated.fingerprint).not.toBe('')
    await expect(service.generatorHistory()).resolves.toEqual(historyBefore)
    expect(write).not.toHaveBeenCalled()

    await service.lock()
    await expect(service.generateSshKey()).rejects.toMatchObject({ code: 'LOCKED' })
  })

  it('caps generator history at 200 newest exact entries', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as {
      generatorHistory: Array<{
        credential: string
        category: 'password'
        generationDate: number
        algorithm: 'password'
      }>
    }
    data.generatorHistory = Array.from({ length: 200 }, (_, index) => ({
      credential: `historical-${index}`,
      category: 'password',
      generationDate: index,
      algorithm: 'password'
    }))
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(
      new EncryptedVaultStore<unknown>(filePath),
      { copyText: vi.fn(), openExternal: vi.fn() },
      { randomInt: () => 0 }
    )
    await reopened.unlock(MASTER_PASSWORD)
    await reopened.generateCredential({ algorithm: 'catchall', domain: 'example.invalid' })
    const history = await reopened.generatorHistory()
    expect(history).toHaveLength(200)
    expect(history[0]).toMatchObject({
      credential: 'aaaaaaaa@example.invalid',
      category: 'email',
      algorithm: 'catchall'
    })
    expect(history.at(-1)?.credential).toBe('historical-198')
  })

  it('migrates V12 to an empty encrypted V16 generator history and Send cache', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as Record<string, unknown>
    data.version = 12
    delete data.generatorHistory
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopenedStore = new EncryptedVaultStore<unknown>(filePath)
    const reopened = new VaultService(reopenedStore, {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
    await expect(reopened.generatorHistory()).resolves.toEqual([])
    await reopened.lock()
    const migrated = await reopenedStore.unlock(MASTER_PASSWORD)
    expect(migrated.data).toMatchObject({
      version: 19,
      generatorHistory: [],
      sends: [],
      nativeAttachmentRestore: null
    })
    migrated.key.fill(0)
    migrated.salt.fill(0)
  })

  it('migrates V13 login records to V16 with empty attachment metadata and Send cache', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Pre-attachment item' })
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as {
      version: number
      logins: Array<Record<string, unknown>>
    }
    data.version = 13
    for (const storedLogin of data.logins) delete storedLogin.attachments
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopenedStore = new EncryptedVaultStore<unknown>(filePath)
    const reopened = new VaultService(reopenedStore, {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
    await expect(reopened.getLogin({ id: login.id })).resolves.toMatchObject({
      attachmentCount: 0,
      attachments: []
    })
    await reopened.lock()
    const migrated = await reopenedStore.unlock(MASTER_PASSWORD)
    expect(migrated.data).toMatchObject({
      version: 19,
      logins: [expect.objectContaining({ attachments: [] })],
      sends: []
    })
    migrated.key.fill(0)
    migrated.salt.fill(0)
  })

  it('migrates V14 sync data to V16 with no cached equivalent-domain settings or Sends', async () => {
    const { filePath, service, store } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state)
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as {
      version: number
      sync: Record<string, unknown>
    }
    data.version = 14
    delete data.sync.domainSettings
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopenedStore = new EncryptedVaultStore<unknown>(filePath)
    const reopened = new VaultService(reopenedStore, {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).resolves.toEqual({ state: 'unlocked' })
    await reopened.lock()
    const migrated = await reopenedStore.unlock(MASTER_PASSWORD)
    expect(migrated.data).toMatchObject({
      version: 19,
      sync: { domainSettings: null }
    })
    migrated.key.fill(0)
    migrated.salt.fill(0)
  })

  it('rejects malformed V15 equivalent-domain data as a corrupt vault', async () => {
    const { filePath, service, store } = await createHarness({
      createSyncClient: (sync) => createSyncFake(sync.state)
    })
    await service.setup(MASTER_PASSWORD)
    await service.connectSync({
      serverUrl: 'https://vault.example.invalid',
      email: 'sync@example.invalid',
      masterPassword: 'remote master password'
    })
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as {
      sync: { domainSettings: { equivalentDomains: string[][] } }
    }
    data.sync.domainSettings.equivalentDomains = [['bad,domain.example']]
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })

  it.each([
    {
      label: 'more than 200 entries',
      value: Array.from({ length: 201 }, (_, index) => ({
        credential: `generated-${index}`,
        category: 'password',
        generationDate: index,
        algorithm: 'password'
      }))
    },
    {
      label: 'a duplicate credential',
      value: [
        { credential: 'same', category: 'password', generationDate: 1, algorithm: 'password' },
        { credential: 'same', category: 'password', generationDate: 2, algorithm: 'password' }
      ]
    },
    {
      label: 'an oversized credential',
      value: [
        {
          credential: 'x'.repeat(513),
          category: 'password',
          generationDate: 1,
          algorithm: 'password'
        }
      ]
    },
    {
      label: 'an unknown key',
      value: [
        {
          credential: 'generated',
          category: 'password',
          generationDate: 1,
          algorithm: 'password',
          future: true
        }
      ]
    },
    {
      label: 'a category and algorithm mismatch',
      value: [
        {
          credential: 'generated',
          category: 'email',
          generationDate: 1,
          algorithm: 'password'
        }
      ]
    }
  ])('rejects generator history with $label in the V13 schema', async ({ value }) => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.lock()
    const unlocked = await store.unlock(MASTER_PASSWORD)
    ;(unlocked.data as { generatorHistory: unknown }).generatorHistory = value
    await store.write(unlocked.data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })

  it('rejects an invalid deletedAt value in the current vault schema', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Corrupt date test' })
    await service.lock()

    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as { logins: Array<{ deletedAt: unknown }> }
    data.logins[0]!.deletedAt = 'not-an-iso-date'
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })

  it.each([
    {
      label: 'more than five entries',
      value: Array.from({ length: 6 }, (_, index) => ({
        password: `old-${index}`,
        lastUsedDate: '2026-07-14T00:00:00.000Z'
      }))
    },
    {
      label: 'an unknown key',
      value: [
        {
          password: 'old',
          lastUsedDate: '2026-07-14T00:00:00.000Z',
          future: true
        }
      ]
    },
    {
      label: 'an empty password',
      value: [{ password: '', lastUsedDate: '2026-07-14T00:00:00.000Z' }]
    },
    {
      label: 'a non-canonical date',
      value: [{ password: 'old', lastUsedDate: '2026-07-14' }]
    }
  ])('rejects password history with $label in the V12 schema', async ({ value }) => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Corrupt history' })
    await service.lock()

    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as { logins: Array<{ passwordHistory: unknown }> }
    data.logins[0]!.passwordHistory = value
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })

  it('round-trips reprompt metadata and verifies the local master-password proof', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const protectedLogin = await service.createLogin({
      name: 'Protected item',
      username: 'private-user',
      uri: 'https://private.example.invalid',
      reprompt: 1
    })

    expect(await service.listLogins()).toEqual([
      expect.objectContaining({
        id: protectedLogin.id,
        reprompt: 1,
        username: '',
        uri: null,
        subtitle: ''
      })
    ])
    await expect(
      service.authorizeLogin({ id: protectedLogin.id, masterPassword: MASTER_PASSWORD })
    ).resolves.toBeTypeOf('number')
    await expect(
      service.authorizeLogin({ id: protectedLogin.id, masterPassword: 'wrong password' })
    ).rejects.toMatchObject({ code: 'INVALID_MASTER_PASSWORD' })

    const clone = await service.cloneLogin({ id: protectedLogin.id })
    expect(clone.reprompt).toBe(1)
    const updated = await service.updateLogin({ id: protectedLogin.id, reprompt: 0 })
    expect(updated.reprompt).toBe(0)
  })

  it('stores ordered URI match rows, keeps the primary alias, and addresses secondary rows', async () => {
    const { copyText, openExternal, service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const created = await service.createLogin({
      name: 'Multiple websites',
      username: 'multi-user',
      uri: 'https://primary.example.invalid',
      uris: [
        { uri: 'https://primary.example.invalid', match: 0 },
        { uri: '^https://accounts\\.example\\.invalid/', match: 4 },
        { uri: 'https://never.example.invalid', match: 5 }
      ]
    })

    expect(created.uri).toBe('https://primary.example.invalid')
    expect(created.uris).toEqual([
      { uri: 'https://primary.example.invalid', match: 0 },
      { uri: '^https://accounts\\.example\\.invalid/', match: 4 },
      { uri: 'https://never.example.invalid', match: 5 }
    ])
    await service.copyField({ id: created.id, field: 'uri', uriIndex: 1 })
    expect(copyText).toHaveBeenLastCalledWith('^https://accounts\\.example\\.invalid/')
    await service.openLoginUri({ id: created.id, uriIndex: 2 })
    expect(openExternal).toHaveBeenLastCalledWith('https://never.example.invalid/')
    await expect(service.openLoginUri({ id: created.id, uriIndex: 1 })).rejects.toMatchObject({
      code: 'INVALID_URL'
    })

    const clone = await service.cloneLogin({ id: created.id })
    await service.updateLogin({
      id: created.id,
      uris: [{ uri: 'https://changed.example.invalid', match: 3 }],
      uri: 'https://changed.example.invalid'
    })
    expect(clone.uris).toHaveLength(3)
    expect((await service.getLogin({ id: clone.id })).uris[0]?.uri).toBe(
      'https://primary.example.invalid'
    )
  })

  it('rejects blank, oversized, over-cap, and alias-inconsistent local URI rows', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await expect(
      service.createLogin({ name: 'Blank URI', uris: [{ uri: '  ', match: null }] })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Alias mismatch',
        uri: 'https://one.example.invalid',
        uris: [{ uri: 'https://two.example.invalid', match: null }]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too long',
        uris: [{ uri: 'x'.repeat(4_097), match: null }]
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
    await expect(
      service.createLogin({
        name: 'Too many',
        uris: Array.from({ length: 1_001 }, (_, index) => ({
          uri: `https://${index}.example.invalid`,
          match: null
        }))
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('keeps authorization and the protected operation atomic against a queued reprompt change', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Race target', password: 'race-secret' })
    let releaseOperation!: () => void
    const operationGate = new Promise<void>((resolve) => {
      releaseOperation = resolve
    })
    let authorized = false
    const protectedOperation = service.runAuthorizedOperation(
      () => false,
      async (authorize) => {
        authorize([login.id])
        authorized = true
        await operationGate
        return service.revealPassword({ id: login.id })
      }
    )
    await vi.waitFor(() => expect(authorized).toBe(true))
    const enableReprompt = service.updateLogin({ id: login.id, reprompt: 1 })
    releaseOperation()
    await expect(protectedOperation).resolves.toBe('race-secret')
    await expect(enableReprompt).resolves.toMatchObject({ reprompt: 1 })

    await expect(
      service.runAuthorizedOperation(
        () => false,
        async (authorize) => {
          authorize([login.id])
          return service.revealPassword({ id: login.id })
        }
      )
    ).rejects.toMatchObject({ code: 'REPROMPT_REQUIRED' })
  })

  it('expires inherited reentrant context after the outer exclusive operation completes', async () => {
    const { service } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    const login = await service.createLogin({ name: 'Context target' })
    let releaseLate!: () => void
    const lateGate = new Promise<void>((resolve) => {
      releaseLate = resolve
    })
    let lateRead!: Promise<LoginView>
    await service.runAuthorizedOperation(
      () => true,
      async (authorize) => {
        authorize([])
        lateRead = lateGate.then(() => service.getLogin({ id: login.id }))
      }
    )

    let releaseBlocker!: () => void
    let blockerEntered = false
    const blocker = service.runAuthorizedOperation(
      () => true,
      async (authorize) => {
        authorize([])
        blockerEntered = true
        await new Promise<void>((resolve) => {
          releaseBlocker = resolve
        })
      }
    )
    await vi.waitFor(() => expect(blockerEntered).toBe(true))
    let lateResolved = false
    void lateRead.then(() => {
      lateResolved = true
    })
    releaseLate()
    await Promise.resolve()
    await Promise.resolve()
    expect(lateResolved).toBe(false)
    releaseBlocker()
    await blocker
    await expect(lateRead).resolves.toMatchObject({ id: login.id })
  })

  it('rejects an invalid reprompt value in the current V11 schema', async () => {
    const { filePath, service, store } = await createHarness()
    await service.setup(MASTER_PASSWORD)
    await service.createLogin({ name: 'Corrupt reprompt test' })
    await service.lock()

    const unlocked = await store.unlock(MASTER_PASSWORD)
    const data = unlocked.data as { logins: Array<{ reprompt: unknown }> }
    data.logins[0]!.reprompt = 2
    await store.write(data, unlocked.key, unlocked.salt)
    unlocked.key.fill(0)
    unlocked.salt.fill(0)

    const reopened = new VaultService(new EncryptedVaultStore<unknown>(filePath), {
      copyText: vi.fn(),
      openExternal: vi.fn()
    })
    await expect(reopened.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'CORRUPT_VAULT'
    })
  })
})
