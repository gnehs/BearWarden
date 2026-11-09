import { randomInt as nodeRandomInt, randomUUID } from 'node:crypto'
import { BitwardenDirectError, type BitwardenSyncClient } from './bitwarden-direct'
import { EncryptedVaultStore } from './encrypted-vault-store'
import { type EncryptedImageCache } from './encrypted-image-cache'
import type { VaultAttachmentFileService } from './vault-attachment-files'
import { cloneData } from './vault/vault-data-parsing'
import { VaultGeneratorService } from './vault/generator-service'
import { VaultSendService } from './vault/send-service'
import { VaultCore } from './vault/core'
import { cloneGeneratorHistory } from './vault/generator-history'
import type {
  PersistedSyncData,
  VaultPlatform,
  VaultAccountWebAuthnAssertionRequester,
  VaultAccountWebAuthnRegistrationRequester,
  VaultServiceOptions
} from './vault/types'
import { currentBitwardenPolicySet, assertSendMutationAllowed } from './vault/policy'
import { VaultSyncSession } from './vault/sync-session'
import { VaultFolders } from './vault/folders'
import { VaultHealth } from './vault/health'
import { VaultListings } from './vault/listings'
import { VaultPasswordHistory } from './vault/password-history-service'
import { VaultAttachments } from './vault/attachments'
import { VaultPortability } from './vault/portability'
import { VaultSharedItems } from './vault/shared-items'
import { VaultItemAuthorization } from './vault/item-authorization'
import { VaultItems } from './vault/items'
import { VaultIntegrations } from './vault/integrations'
import { VaultWebsiteIcons } from './vault/website-icons'
import { VaultAccountSecurity } from './vault/account-security'
import { VaultPinUnlockState } from './vault/pin-unlock-state'
import { VaultSyncEngine } from './vault/sync-engine'
import { VaultSyncService } from './vault/sync-service'
import { VaultMasterPasswordChange } from './vault/master-password-change-service'
import { VaultUnlock } from './vault/unlock'

/**
 * Owns the vault's mutable runtime state, persistence transaction boundary, and sync engine.
 * Feature layers extend this class so every operation shares one mutex, generation, and cleanup
 * lifecycle; this module must never import a higher service layer.
 */
export class VaultServiceBase {
  protected readonly generatorService: VaultGeneratorService
  protected readonly sendService: VaultSendService
  protected readonly createSyncClient: (sync: PersistedSyncData) => BitwardenSyncClient
  protected readonly fetch: typeof fetch
  protected readonly attachmentFiles: VaultAttachmentFileService | null
  protected readonly requestAccountWebAuthnAssertion: VaultAccountWebAuthnAssertionRequester | null
  protected readonly requestAccountWebAuthnRegistration: VaultAccountWebAuthnRegistrationRequester | null
  protected readonly imageCache: EncryptedImageCache | null
  protected readonly core: VaultCore
  protected readonly syncSession: VaultSyncSession
  protected readonly folders: VaultFolders
  protected readonly health: VaultHealth
  protected readonly listings: VaultListings
  protected readonly passwordHistory: VaultPasswordHistory
  protected readonly attachments: VaultAttachments
  protected readonly portability: VaultPortability
  protected readonly sharedItems: VaultSharedItems
  protected readonly authorization: VaultItemAuthorization
  protected readonly items: VaultItems
  protected readonly integrations: VaultIntegrations
  protected readonly websiteIcons: VaultWebsiteIcons
  protected readonly accountSecurity: VaultAccountSecurity
  protected readonly pinUnlock: VaultPinUnlockState
  protected readonly syncEngine: VaultSyncEngine
  protected readonly sync: VaultSyncService
  protected readonly masterPasswordChange: VaultMasterPasswordChange
  protected readonly unlocking: VaultUnlock

  constructor(
    protected readonly store: EncryptedVaultStore<unknown>,
    protected readonly platform: VaultPlatform,
    options: VaultServiceOptions = {}
  ) {
    this.core = new VaultCore(store, {
      now: options.now ?? (() => new Date()),
      createId: options.createId ?? randomUUID
    })
    this.core.registerResource({
      clear: () => {
        this.generatorService.clearRuntimeState()
      }
    })
    this.fetch = options.fetch ?? fetch
    this.attachmentFiles = options.attachmentFiles ?? null
    this.imageCache = options.imageCache ?? null
    this.requestAccountWebAuthnAssertion = options.requestAccountWebAuthnAssertion ?? null
    this.requestAccountWebAuthnRegistration = options.requestAccountWebAuthnRegistration ?? null
    this.createSyncClient =
      options.createSyncClient ??
      (() => {
        throw new BitwardenDirectError('INVALID_RESPONSE')
      })
    this.generatorService = new VaultGeneratorService({
      now: this.core.now,
      createId: options.createId ?? randomUUID,
      randomInt: options.randomInt ?? nodeRandomInt,
      copyText: (text) => this.platform.copyText(text),
      exclusive: (operation) => this.core.exclusive(operation),
      assertUnlocked: () => {
        this.core.requireData()
      },
      readPolicySet: () => currentBitwardenPolicySet(this.core.requireData()),
      readHistory: () => this.core.requireData().generatorHistory,
      commitHistory: async (history) => {
        const current = this.core.requireData()
        const next = cloneData(current)
        next.generatorHistory = cloneGeneratorHistory(history)
        next.updatedAt = this.core.nowIso()
        await this.core.commit(next)
      }
    })
    this.sendService = new VaultSendService({
      attachmentFiles: this.attachmentFiles,
      exclusive: (operation) => this.core.exclusive(operation),
      readData: () => this.core.requireData(),
      requireSyncData: () => this.syncSession.requireSyncData(),
      getSyncClient: (sync) => this.syncSession.getOrCreateSyncClient(sync),
      currentGeneration: () => this.core.generation,
      startSyncOperation: () => this.syncSession.startSyncOperation(),
      finishSyncOperation: (abort) => this.syncSession.finishSyncOperation(abort),
      commitData: (data, generation) => this.core.commit(data, generation),
      nowIso: () => this.core.nowIso(),
      clearSyncError: () => this.syncSession.clearSyncErrorState(),
      mapSyncError: (error) => this.syncSession.mapSyncError(error),
      copyText: (text) => this.platform.copyText(text),
      assertMutationAllowed: () => assertSendMutationAllowed(this.core.requireData())
    })
    this.syncSession = new VaultSyncSession(
      this.core,
      this.createSyncClient,
      this.requestAccountWebAuthnAssertion
    )
    this.folders = new VaultFolders(this.core)
    this.health = new VaultHealth(this.core, this.syncSession, this.platform, this.fetch)
    this.listings = new VaultListings(this.core, this.syncSession)
    this.passwordHistory = new VaultPasswordHistory(this.core, this.platform)
    this.attachments = new VaultAttachments(
      this.core,
      this.syncSession,
      this.attachmentFiles,
      this.imageCache
    )
    this.portability = new VaultPortability(this.core, this.syncSession, {
      performSync: (data, client, signal) => this.syncEngine.performSync(data, client, signal)
    })
    this.sharedItems = new VaultSharedItems(this.core, this.syncSession, this.platform)
    this.authorization = new VaultItemAuthorization(this.core)
    this.items = new VaultItems(this.core, this.platform)
    this.integrations = new VaultIntegrations(this.core, this.authorization)
    this.websiteIcons = new VaultWebsiteIcons(this.core, this.fetch, this.imageCache)
    this.accountSecurity = new VaultAccountSecurity(
      this.core,
      this.syncSession,
      this.health,
      this.platform,
      this.requestAccountWebAuthnRegistration
    )
    this.pinUnlock = new VaultPinUnlockState()
    this.syncEngine = new VaultSyncEngine(this.core, this.syncSession, this.pinUnlock)
    this.sync = new VaultSyncService(
      this.core,
      this.syncSession,
      this.syncEngine,
      this.pinUnlock,
      this.health
    )
    this.masterPasswordChange = new VaultMasterPasswordChange(
      this.core,
      this.syncSession,
      this.pinUnlock
    )
    this.unlocking = new VaultUnlock(this.core, this.store, this.syncSession, this.pinUnlock)
  }
}
