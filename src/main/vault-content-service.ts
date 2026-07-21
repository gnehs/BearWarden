import { createHash } from 'node:crypto'
import type {
  FolderCreateRequest,
  FolderDeleteRequest,
  FolderReorderRequest,
  FolderUpdateRequest,
  FolderView,
  LoginIdRequest,
  LoginListRequest,
  LoginPrefetchRequest,
  PasswordHistoryEntryRequest,
  PasswordHistoryRestoreRequest,
  LoginSummary,
  LoginView,
  OrganizationView,
  CollectionView,
  SharedLoginListRequest,
  SharedLoginSummary,
  SharedLoginView,
  EmergencyAccessView,
  VaultPasswordHistoryEntry,
  VaultPasswordHistoryView,
  VaultHealthExposedReport,
  VaultHealthAccountBreachReport,
  VaultHealthAccountBreachRequest,
  VaultHealthReport,
  SendCreateRequest,
  SendFileCreateRequest,
  SendFileCreateResult,
  SendFileDownloadRequest,
  SendFileDownloadResult,
  SendUpdateRequest,
  SendIdRequest,
  SendView
} from '../shared/vault-contract'
import { MAX_LOGIN_PREFETCH_IDS, MAX_LOGIN_SEARCH_QUERY_LENGTH } from '../shared/vault-contract'
import { BitwardenDirectError, type BitwardenSyncClient } from './bitwarden-direct'
import { searchVaultItems } from './vault-search'
import { analyzeVaultHealth, type VaultHealthItem } from './vault-health'
import { hashPasswordsForPwnedLookup, PwnedPasswordsClient } from './pwned-passwords'
import {
  analyzeInactiveTwoFactor,
  type InactiveTwoFactorInput,
  type InactiveTwoFactorReport,
  type TwoFactorDirectoryDataset
} from './inactive-two-factor'
import { VaultError } from './vault-errors'
import { MAX_NAME_LENGTH, MAX_PASSWORD_HISTORY } from './vault/limits'
import { assertUuid, normalizeRequiredString } from './vault/parse-primitives'
import {
  toSummary,
  toSharedSummary,
  toVaultSearchItem,
  toView,
  toSharedView,
  compareText
} from './vault/views'
import { recordSyncDeletion } from './vault/sync-data-parsing'
import { emergencyAccessViewFromRemote } from './vault/org-collection-parsing'
import { clonePasswordHistory } from './vault/password-history'
import type { StoredLogin } from './vault/types'
import {
  type ItemReadAuthorizationValidator,
  type ExposedPasswordSnapshot
} from './vault-service-base'
import { VaultAccountService } from './vault-account-service'

/** Vault queries and local content domains: sends, folders, health, and password history. */
export class VaultContentService extends VaultAccountService {
  listSends(): Promise<SendView[]> {
    return this.sendService.list()
  }

  createSend(request: SendCreateRequest): Promise<SendView> {
    return this.sendService.create(request)
  }

  async createFileSend(request: SendFileCreateRequest): Promise<SendFileCreateResult> {
    return this.sendService.createFile(request)
  }

  async downloadFileSend(request: SendFileDownloadRequest): Promise<SendFileDownloadResult> {
    return this.sendService.downloadFile(request)
  }

  updateSend(request: SendUpdateRequest): Promise<SendView> {
    return this.sendService.update(request)
  }

  removeSendPassword(request: SendIdRequest): Promise<SendView> {
    return this.sendService.removePassword(request)
  }

  deleteSend(request: SendIdRequest): Promise<void> {
    return this.sendService.delete(request)
  }

  copySendLink(request: SendIdRequest): Promise<void> {
    return this.sendService.copyLink(request)
  }

  listFolders(): Promise<FolderView[]> {
    return this.exclusive(async () =>
      this.requireData()
        .folders.map((folder) => ({ ...folder }))
        .sort((left, right) => left.position - right.position || compareText(left.name, right.name))
    )
  }

  createFolder(request: FolderCreateRequest): Promise<FolderView> {
    return this.mutate((data, now) => {
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      this.assertUniqueFolderName(data, name)
      const folder: FolderView = {
        id: this.validatedNewId(),
        name,
        position: data.folders.length,
        createdAt: now,
        updatedAt: now
      }
      data.folders.push(folder)
      return { ...folder }
    })
  }

  updateFolder(request: FolderUpdateRequest): Promise<FolderView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const folder = this.findFolder(data, request.id)
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      this.assertUniqueFolderName(data, name, folder.id)
      folder.name = name
      folder.updatedAt = now
      return { ...folder }
    })
  }

  deleteFolder(request: FolderDeleteRequest): Promise<void> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      this.findFolder(data, request.id)
      recordSyncDeletion(data.sync, 'folder', request.id)
      data.folders = data.folders
        .filter((folder) => folder.id !== request.id)
        .sort((left, right) => left.position - right.position)
        .map((folder, position) => ({ ...folder, position }))
      data.logins.forEach((login) => {
        if (login.folderId === request.id) {
          login.folderId = null
          login.updatedAt = now
        }
      })
    })
  }

  reorderFolders(request: FolderReorderRequest): Promise<FolderView[]> {
    return this.mutate((data, now) => {
      if (!Array.isArray(request.orderedIds) || request.orderedIds.length !== data.folders.length) {
        throw new VaultError('INVALID_INPUT')
      }
      request.orderedIds.forEach(assertUuid)
      const uniqueIds = new Set(request.orderedIds)
      if (
        uniqueIds.size !== data.folders.length ||
        data.folders.some((folder) => !uniqueIds.has(folder.id))
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      const foldersById = new Map(data.folders.map((folder) => [folder.id, folder]))
      data.folders = request.orderedIds.map((id, position) => ({
        ...foldersById.get(id)!,
        position,
        updatedAt: now
      }))
      return data.folders.map((folder) => ({ ...folder }))
    })
  }

  /**
   * Runs password-health analysis under the vault mutex. Raw password material is adapted only
   * for unprotected active logins and never leaves this method.
   */
  getHealthReport(): Promise<VaultHealthReport> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const summaryById = new Map<string, { id: string; name: string; subtitle: string }>()
      const candidates: VaultHealthItem[] = []

      for (const login of data.logins) {
        // Archive and trash are not current credentials. Filter before building any core input.
        if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null)
          continue

        if (login.reprompt === 1) {
          // Do not even read protected password or username fields at this boundary.
          candidates.push({
            id: login.id,
            type: login.type,
            name: login.name,
            reprompt: 1
          })
          continue
        }

        // Health findings never need a URI. Avoid `toSummary`, whose fallback subtitle may contain
        // a complete URI including a private path or query when the username is empty.
        summaryById.set(login.id, { id: login.id, name: login.name, subtitle: login.username })
        candidates.push({
          id: login.id,
          type: login.type,
          name: login.name,
          password: login.password,
          username: login.username,
          uris: login.uris.map(({ uri }) => ({ uri })),
          reprompt: 0
        })
      }

      const analysis = analyzeVaultHealth(candidates)
      const weakPasswords = analysis.weakPasswords.flatMap((finding) => {
        const summary = summaryById.get(finding.id)
        return summary
          ? [
              {
                id: summary.id,
                name: summary.name,
                subtitle: summary.subtitle,
                score: finding.score
              }
            ]
          : []
      })
      const reusedPasswords = analysis.reusedPasswords.flatMap((finding) => {
        const summary = summaryById.get(finding.id)
        return summary
          ? [
              {
                id: summary.id,
                name: summary.name,
                subtitle: summary.subtitle,
                reuseCount: finding.reuseCount
              }
            ]
          : []
      })
      const unsecuredWebsites = analysis.unsecuredWebsites.map(({ id, name }) => ({ id, name }))

      return {
        generatedAt: this.nowIso(),
        totals: {
          analyzedCount: analysis.analyzedCount,
          weakPasswordCount: weakPasswords.length,
          reusedPasswordCount: reusedPasswords.length,
          unsecuredWebsiteCount: unsecuredWebsites.length,
          protectedSkippedCount: analysis.protectedSkippedCount
        },
        weakPasswords,
        reusedPasswords,
        unsecuredWebsites
      }
    })
  }

  /**
   * Adapts personal login metadata to the main-only inactive-2FA core under one unlocked epoch.
   * Secret fields and organization-owned items never cross this boundary.
   */
  getInactiveTwoFactorReport(dataset: TwoFactorDirectoryDataset): Promise<InactiveTwoFactorReport> {
    return this.exclusive(async () => {
      const generation = this.generation
      const data = this.requireData()
      const inputs: InactiveTwoFactorInput[] = []

      for (const login of data.logins) {
        if (login.type !== 'login') continue
        const hasTotp = Boolean(login.totp)
        const isDeleted = login.deletedAt !== null
        const isArchived = login.archivedAt !== null
        inputs.push({
          id: login.id,
          name: login.name,
          hasTotp,
          isDeleted,
          isArchived,
          // Avoid reading even URI metadata for lifecycle/TOTP exclusions.
          uris: hasTotp || isDeleted || isArchived ? [] : login.uris.map(({ uri }) => uri)
        })
      }

      const report = analyzeInactiveTwoFactor(inputs, dataset)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      return report
    })
  }

  /**
   * Runs an explicit HIBP Pwned Passwords check without holding the vault mutex during network
   * I/O. Only SHA-1 range material leaves the initial snapshot, and only five-character prefixes
   * are sent to HIBP by the fixed-origin client.
   */
  async getExposedPasswordReport(): Promise<VaultHealthExposedReport> {
    const snapshot = await this.exclusive(async () => this.captureExposedPasswordSnapshot())
    const active = this.activeExposedPasswordOperation
    if (
      active &&
      !active.abort.signal.aborted &&
      active.generation === snapshot.generation &&
      active.revision === snapshot.revision
    ) {
      snapshot.hashes.fill('')
      return active.promise
    }

    active?.abort.abort()
    const abort = new AbortController()
    const client = new PwnedPasswordsClient({ fetch: this.fetch })
    const promise = this.resolveExposedPasswordSnapshot(snapshot, client, abort.signal).finally(
      () => {
        snapshot.hashes.fill('')
        if (this.activeExposedPasswordOperation?.promise === promise) {
          this.activeExposedPasswordOperation = null
        }
      }
    )
    this.activeExposedPasswordOperation = {
      generation: snapshot.generation,
      revision: snapshot.revision,
      abort,
      promise
    }
    return promise
  }

  cancelExposedPasswordReport(): boolean {
    const active = this.activeExposedPasswordOperation
    if (!active || active.abort.signal.aborted) return false
    active.abort.abort()
    return true
  }

  /**
   * Queries the configured Vaultwarden HIBP proxy without holding the vault mutex during network
   * I/O. Unlike the password range report, this explicitly discloses the complete address through
   * the configured server, so callers must only invoke it after a user action.
   */
  async getAccountBreachReport(
    request: VaultHealthAccountBreachRequest
  ): Promise<VaultHealthAccountBreachReport> {
    const snapshot = await this.exclusive(async () => {
      const email = this.normalizeAccountBreachEmail(request.email)
      const sync = this.requireSyncData()
      return {
        generation: this.generation,
        email,
        client: this.getOrCreateSyncClient(sync)
      }
    })
    const active = this.activeAccountBreachOperation
    if (
      active &&
      !active.abort.signal.aborted &&
      active.generation === snapshot.generation &&
      active.email === snapshot.email &&
      active.client === snapshot.client
    ) {
      return active.promise
    }

    active?.abort.abort()
    const abort = new AbortController()
    const promise = this.resolveAccountBreachReport(
      snapshot.generation,
      snapshot.client,
      snapshot.email,
      abort.signal
    ).finally(() => {
      if (this.activeAccountBreachOperation?.promise === promise) {
        this.activeAccountBreachOperation = null
      }
    })
    this.activeAccountBreachOperation = { ...snapshot, abort, promise }
    return promise
  }

  cancelAccountBreachReport(): boolean {
    const active = this.activeAccountBreachOperation
    if (!active || active.abort.signal.aborted) return false
    active.abort.abort()
    return true
  }

  async openHibpWebsite(): Promise<void> {
    await this.exclusive(async () => this.requireData())
    await this.platform.openExternal('https://haveibeenpwned.com/')
  }

  private normalizeAccountBreachEmail(value: unknown): string {
    const email = normalizeRequiredString(value, 254).toLowerCase()
    const firstAt = email.indexOf('@')
    if (
      /\s/u.test(email) ||
      firstAt <= 0 ||
      firstAt !== email.lastIndexOf('@') ||
      firstAt === email.length - 1
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return email
  }

  private async resolveAccountBreachReport(
    generation: number,
    client: BitwardenSyncClient,
    email: string,
    signal: AbortSignal
  ): Promise<VaultHealthAccountBreachReport> {
    let report: Awaited<ReturnType<BitwardenSyncClient['getAccountBreachReport']>>
    try {
      report = await client.getAccountBreachReport(email, signal)
    } catch (error) {
      return this.exclusive(async () => {
        this.requireData()
        if (generation !== this.generation) throw new VaultError('LOCKED')
        if (this.syncClient !== client || !this.requireData().sync) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'AUTH_REQUIRED') {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        throw new VaultError('HEALTH_CHECK_FAILED')
      })
    }

    return this.exclusive(async () => {
      this.requireData()
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (this.syncClient !== client || !this.requireData().sync) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (report.status === 'unavailable') {
        return {
          generatedAt: this.nowIso(),
          status: 'unavailable',
          reason: report.reason,
          breaches: []
        }
      }
      return {
        generatedAt: this.nowIso(),
        status: 'complete',
        breaches: report.breaches.map((breach) => ({
          name: breach.name,
          title: breach.title,
          domain: breach.domain,
          breachDate: breach.breachDate,
          addedDate: breach.addedDate,
          pwnCount: breach.pwnCount,
          dataClasses: [...breach.dataClasses],
          isVerified: breach.isVerified
        }))
      }
    })
  }

  private captureExposedPasswordSnapshot(): ExposedPasswordSnapshot {
    const data = this.requireData()
    const passwords: string[] = []
    const candidates: ExposedPasswordSnapshot['candidates'][number][] = []
    let protectedSkippedCount = 0

    for (const login of data.logins) {
      if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null) continue
      if (login.reprompt === 1) {
        // A protected item's password and username are outside this report's read boundary.
        protectedSkippedCount += 1
        continue
      }
      if (!login.password) continue

      const summary = toSummary(login)
      candidates.push({ id: summary.id, name: summary.name, subtitle: summary.subtitle })
      passwords.push(login.password)
    }

    try {
      const hashes = hashPasswordsForPwnedLookup(passwords)
      const revisionHash = createHash('sha256')
      revisionHash.update(String(protectedSkippedCount), 'utf8')
      for (let index = 0; index < candidates.length; index += 1) {
        const candidate = candidates[index]!
        for (const value of [candidate.id, candidate.name, candidate.subtitle, hashes[index]!]) {
          revisionHash.update(String(Buffer.byteLength(value, 'utf8')), 'utf8')
          revisionHash.update(':', 'utf8')
          revisionHash.update(value, 'utf8')
          revisionHash.update(';', 'utf8')
        }
      }
      return {
        generation: this.generation,
        revision: revisionHash.digest('hex'),
        candidates,
        hashes,
        protectedSkippedCount
      }
    } catch {
      throw new VaultError('HEALTH_CHECK_FAILED')
    } finally {
      passwords.fill('')
    }
  }

  private async resolveExposedPasswordSnapshot(
    snapshot: ExposedPasswordSnapshot,
    client: PwnedPasswordsClient,
    signal: AbortSignal
  ): Promise<VaultHealthExposedReport> {
    let counts: number[]
    try {
      counts = await client.lookupSha1Hashes(snapshot.hashes, signal)
    } catch {
      return this.exclusive(async () => {
        this.requireData()
        if (snapshot.generation !== this.generation) throw new VaultError('LOCKED')
        throw new VaultError('HEALTH_CHECK_FAILED')
      })
    }

    return this.exclusive(async () => {
      this.requireData()
      if (snapshot.generation !== this.generation) throw new VaultError('LOCKED')
      const currentSnapshot = this.captureExposedPasswordSnapshot()
      try {
        if (currentSnapshot.revision !== snapshot.revision) {
          throw new VaultError('HEALTH_CHECK_FAILED')
        }
      } finally {
        currentSnapshot.hashes.fill('')
      }

      const exposedPasswords = snapshot.candidates
        .flatMap((candidate, index) => {
          const exposedCount = counts[index] ?? 0
          return exposedCount > 0 ? [{ ...candidate, exposedCount }] : []
        })
        .sort((first, second) => second.exposedCount - first.exposedCount)

      return {
        generatedAt: this.nowIso(),
        totals: {
          analyzedCount: snapshot.candidates.length,
          exposedPasswordCount: exposedPasswords.length,
          protectedSkippedCount: snapshot.protectedSkippedCount
        },
        exposedPasswords
      }
    })
  }

  listLogins(request: LoginListRequest = {}): Promise<LoginSummary[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const sort = request.sort ?? 'recent'
      if (sort !== 'recent' && sort !== 'name' && sort !== 'frequency') {
        throw new VaultError('INVALID_INPUT')
      }
      if (
        request.query !== undefined &&
        (typeof request.query !== 'string' || request.query.length > MAX_LOGIN_SEARCH_QUERY_LENGTH)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.deleted !== undefined && typeof request.deleted !== 'boolean') {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.archived !== undefined && typeof request.archived !== 'boolean') {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.deleted === true && request.archived === true)
        throw new VaultError('INVALID_INPUT')
      if (request.folderId !== undefined && request.folderId !== null) {
        assertUuid(request.folderId)
        this.findFolder(data, request.folderId)
      }

      const scoped = data.logins.filter(
        (login) =>
          (request.deleted === true
            ? login.deletedAt !== null
            : request.archived === true
              ? login.deletedAt === null && login.archivedAt !== null
              : login.deletedAt === null && login.archivedAt === null) &&
          (request.folderId === undefined || login.folderId === request.folderId)
      )
      const filtered =
        request.query === undefined
          ? scoped
          : (() => {
              const matchingIds = new Set(
                searchVaultItems(scoped.map(toVaultSearchItem), request.query).map(
                  (searchable) => searchable.id
                )
              )
              return scoped.filter((login) => matchingIds.has(login.id))
            })()
      return filtered.map(toSummary).sort((left, right) => {
        if (sort === 'frequency' && left.usageCount !== right.usageCount) {
          return right.usageCount - left.usageCount
        }
        if (sort === 'recent' || sort === 'frequency') {
          if (left.lastUsedAt && right.lastUsedAt && left.lastUsedAt !== right.lastUsedAt) {
            return right.lastUsedAt.localeCompare(left.lastUsedAt)
          }
          if (left.lastUsedAt && !right.lastUsedAt) return -1
          if (!left.lastUsedAt && right.lastUsedAt) return 1
        }
        return compareText(left.name, right.name) || left.id.localeCompare(right.id)
      })
    })
  }

  listOrganizations(): Promise<OrganizationView[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      return data.organizations.map((organization) => ({ ...organization }))
    })
  }

  listCollections(organizationId?: string): Promise<CollectionView[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      if (organizationId !== undefined) assertUuid(organizationId)
      return data.collections
        .filter(
          (collection) =>
            organizationId === undefined || collection.organizationId === organizationId
        )
        .map((collection) => ({ ...collection }))
    })
  }

  listSharedLogins(request: SharedLoginListRequest = {}): Promise<SharedLoginSummary[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      if (
        request.sort !== undefined &&
        request.sort !== 'recent' &&
        request.sort !== 'name' &&
        request.sort !== 'frequency'
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (
        request.query !== undefined &&
        (typeof request.query !== 'string' || request.query.length > MAX_LOGIN_SEARCH_QUERY_LENGTH)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.organizationId !== undefined) assertUuid(request.organizationId)
      if (request.collectionId !== undefined) assertUuid(request.collectionId)
      const scoped = data.sharedLogins.filter(
        (login) =>
          login.deletedAt === null &&
          login.archivedAt === null &&
          (request.organizationId === undefined ||
            login.organizationId === request.organizationId) &&
          (request.collectionId === undefined || login.collectionIds.includes(request.collectionId))
      )
      const filtered =
        request.query === undefined
          ? scoped
          : (() => {
              const matchingIds = new Set(
                searchVaultItems(scoped.map(toVaultSearchItem), request.query).map(
                  (searchable) => searchable.id
                )
              )
              return scoped.filter((login) => matchingIds.has(login.id))
            })()
      return filtered.map(toSharedSummary).sort((left, right) => {
        if (request.sort === 'frequency' && left.usageCount !== right.usageCount) {
          return right.usageCount - left.usageCount
        }
        return request.sort === 'name' || request.sort === 'frequency'
          ? compareText(left.name, right.name) || left.id.localeCompare(right.id)
          : right.updatedAt.localeCompare(left.updatedAt) || left.id.localeCompare(right.id)
      })
    })
  }

  getSharedLogin(request: LoginIdRequest): Promise<SharedLoginView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.requireData().sharedLogins.find((candidate) => candidate.id === request.id)
      if (!login || login.deletedAt !== null || login.archivedAt !== null) {
        throw new VaultError('NOT_FOUND')
      }
      return toSharedView(login)
    })
  }

  listEmergencyAccess(): Promise<EmergencyAccessView[]> {
    return this.exclusive(async () => {
      const sync = this.requireSyncData()
      const client = this.getOrCreateSyncClient(sync)
      if (!client.listEmergencyAccess) return []
      try {
        const entries = await client.listEmergencyAccess()
        return entries.map(emergencyAccessViewFromRemote)
      } catch (error) {
        throw this.mapSyncError(error)
      }
    })
  }

  getLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      return toView(login)
    })
  }

  /**
   * Hydrates one viewport from a synchronous committed snapshot. Protected and inactive items
   * are omitted so speculative reads never cross a reprompt boundary.
   */
  async prefetchLogins(request: LoginPrefetchRequest): Promise<LoginView[]> {
    if (
      !Array.isArray(request.ids) ||
      request.ids.length === 0 ||
      request.ids.length > MAX_LOGIN_PREFETCH_IDS ||
      new Set(request.ids).size !== request.ids.length
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    request.ids.forEach(assertUuid)
    // Writers clone, persist, then atomically replace this.data. This synchronous projection can
    // therefore read the last committed snapshot without waiting behind network-bound sync work.
    const loginsById = new Map(this.requireFastReadData().logins.map((login) => [login.id, login]))
    return request.ids.flatMap((id) => {
      const login = loginsById.get(id)
      return login && login.deletedAt === null && login.archivedAt === null && login.reprompt === 0
        ? [toView(login)]
        : []
    })
  }

  async getPasswordHistory(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryEntry[]> {
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    return clonePasswordHistory(login.passwordHistory)
  }

  async getPasswordHistoryView(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryView> {
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    return {
      expectedUpdatedAt: login.updatedAt,
      entries: login.passwordHistory.map(({ lastUsedDate }) => ({ lastUsedDate }))
    }
  }

  async revealPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string> {
    return this.passwordHistoryEntry(request, validateAuthorization).password
  }

  async copyPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<void> {
    const entry = this.passwordHistoryEntry(request, validateAuthorization)
    await this.platform.copyText(entry.password)
  }

  private passwordHistoryLogin(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): StoredLogin {
    assertUuid(request.id)
    // History is cloned synchronously from the last committed snapshot so a background sync
    // cannot leave the explicit reveal action waiting behind network I/O. Lock starts by
    // blocking fast reads, and authorization is validated before this turn can yield.
    const login = this.findLogin(this.requireFastReadData(), request.id)
    if (
      (login.reprompt === 1 || login.deletedAt !== null) &&
      !validateAuthorization?.([login.id], { generation: this.generation })
    ) {
      throw new VaultError('REPROMPT_REQUIRED')
    }
    return login
  }

  private passwordHistoryEntry(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): VaultPasswordHistoryEntry {
    if (
      !Number.isSafeInteger(request.index) ||
      request.index < 0 ||
      request.index >= MAX_PASSWORD_HISTORY ||
      typeof request.lastUsedDate !== 'string' ||
      !Number.isFinite(Date.parse(request.lastUsedDate)) ||
      typeof request.expectedUpdatedAt !== 'string' ||
      !Number.isFinite(Date.parse(request.expectedUpdatedAt))
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    const login = this.passwordHistoryLogin(request, validateAuthorization)
    if (login.updatedAt !== request.expectedUpdatedAt) throw new VaultError('INVALID_INPUT')
    const entry = login.passwordHistory[request.index]
    if (!entry || entry.lastUsedDate !== request.lastUsedDate) {
      throw new VaultError('INVALID_INPUT')
    }
    return entry
  }

  restorePasswordHistory(request: PasswordHistoryRestoreRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      if (
        !Number.isSafeInteger(request.index) ||
        request.index < 0 ||
        request.index >= MAX_PASSWORD_HISTORY ||
        typeof request.lastUsedDate !== 'string' ||
        !Number.isFinite(Date.parse(request.lastUsedDate)) ||
        typeof request.expectedUpdatedAt !== 'string'
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.type !== 'login' || login.updatedAt !== request.expectedUpdatedAt) {
        throw new VaultError('INVALID_INPUT')
      }
      const entry = login.passwordHistory[request.index]
      if (
        !entry ||
        entry.lastUsedDate !== request.lastUsedDate ||
        entry.password === login.password
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const previousPassword = login.password
      const previousHistory = clonePasswordHistory(login.passwordHistory)
      login.password = entry.password
      login.passwordHistory = (
        previousPassword.length > 0
          ? [{ password: previousPassword, lastUsedDate: now }, ...previousHistory]
          : previousHistory
      ).slice(0, MAX_PASSWORD_HISTORY)
      login.passwordRevisionDate = now
      login.updatedAt = now
      return toView(login)
    })
  }
}
