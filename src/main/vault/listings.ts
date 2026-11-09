import type { VaultCore } from './core'
import type { VaultSyncSession } from './sync-session'
import type {
  LoginIdRequest,
  LoginListRequest,
  LoginPrefetchRequest,
  LoginSummary,
  LoginView,
  OrganizationView,
  CollectionView,
  SharedLoginListRequest,
  SharedLoginSummary,
  SharedLoginView,
  EmergencyAccessView
} from '../../shared/vault-contract'
import { MAX_LOGIN_PREFETCH_IDS, MAX_LOGIN_SEARCH_QUERY_LENGTH } from '../../shared/vault-contract'
import { searchVaultItems } from '../vault-search'
import { VaultError } from '../vault-errors'
import { assertUuid } from './parse-primitives'
import {
  toSummary,
  toSharedSummary,
  toVaultSearchItem,
  toView,
  toSharedView,
  compareText
} from './views'
import { emergencyAccessViewFromRemote } from './org-collection-parsing'
import { findFolder, findLogin, assertActiveLogin } from './data-lookup'

/**
 * Read-only item queries: personal and shared item lists and views, organizations, collections
 * and emergency access.
 */
export class VaultListings {
  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession
  ) {}

  async listLogins(request: LoginListRequest = {}): Promise<LoginSummary[]> {
    const data = this.core.requireFastReadData()
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
    if (request.deleted === true && request.archived === true) throw new VaultError('INVALID_INPUT')
    if (request.folderId !== undefined && request.folderId !== null) {
      assertUuid(request.folderId)
      findFolder(data, request.folderId)
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
  }

  async listOrganizations(): Promise<OrganizationView[]> {
    return this.core
      .requireFastReadData()
      .organizations.map((organization) => ({ ...organization }))
  }

  async listCollections(organizationId?: string): Promise<CollectionView[]> {
    const data = this.core.requireFastReadData()
    if (organizationId !== undefined) assertUuid(organizationId)
    return data.collections
      .filter(
        (collection) => organizationId === undefined || collection.organizationId === organizationId
      )
      .map((collection) => ({ ...collection }))
  }

  async listSharedLogins(request: SharedLoginListRequest = {}): Promise<SharedLoginSummary[]> {
    const data = this.core.requireFastReadData()
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
        (request.organizationId === undefined || login.organizationId === request.organizationId) &&
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
      // Unlike personal items, shared items have no usage to sort by: sync replaces them wholesale
      // and their reveal and copy paths record none, so the server revision is their recency.
      return request.sort === 'name' || request.sort === 'frequency'
        ? compareText(left.name, right.name) || left.id.localeCompare(right.id)
        : right.updatedAt.localeCompare(left.updatedAt) || left.id.localeCompare(right.id)
    })
  }

  getSharedLogin(request: LoginIdRequest): Promise<SharedLoginView> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const login = this.core
        .requireData()
        .sharedLogins.find((candidate) => candidate.id === request.id)
      if (!login || login.deletedAt !== null || login.archivedAt !== null) {
        throw new VaultError('NOT_FOUND')
      }
      return toSharedView(login)
    })
  }

  listEmergencyAccess(): Promise<EmergencyAccessView[]> {
    return this.core.exclusive(async () => {
      const sync = this.syncSession.requireSyncData()
      const client = this.syncSession.getOrCreateSyncClient(sync)
      if (!client.listEmergencyAccess) return []
      try {
        const entries = await client.listEmergencyAccess()
        return entries.map(emergencyAccessViewFromRemote)
      } catch (error) {
        throw this.syncSession.mapSyncError(error)
      }
    })
  }

  getLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const login = findLogin(this.core.requireData(), request.id)
      assertActiveLogin(login)
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
    const loginsById = new Map(
      this.core.requireFastReadData().logins.map((login) => [login.id, login])
    )
    return request.ids.flatMap((id) => {
      const login = loginsById.get(id)
      return login && login.deletedAt === null && login.archivedAt === null && login.reprompt === 0
        ? [toView(login)]
        : []
    })
  }
}
