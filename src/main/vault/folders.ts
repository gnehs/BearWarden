import type {
  FolderCreateRequest,
  FolderDeleteRequest,
  FolderReorderRequest,
  FolderReparentRequest,
  FolderUpdateRequest,
  FolderView
} from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { MAX_NAME_LENGTH } from './limits'
import { assertUuid, normalizeRequiredString } from './parse-primitives'
import { compareText } from './views'
import { recordSyncDeletion } from './sync-data-parsing'
import type { VaultData } from './types'
import { findFolder, assertUniqueFolderName } from './data-lookup'
import type { VaultCore } from './core'

/** Personal folder tree operations: listing, create, rename, reparent, reorder and delete. */
export class VaultFolders {
  constructor(private readonly core: VaultCore) {}

  async listFolders(): Promise<FolderView[]> {
    return this.core
      .requireFastReadData()
      .folders.map((folder) => ({ ...folder }))
      .sort((left, right) => left.position - right.position || compareText(left.name, right.name))
  }

  createFolder(request: FolderCreateRequest): Promise<FolderView> {
    return this.core.mutate((data, now) => {
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      assertUniqueFolderName(data, name)
      const folder: FolderView = {
        id: this.core.validatedNewId(),
        name,
        position: data.folders.length,
        createdAt: now,
        updatedAt: now
      }
      data.folders.push(folder)
      return { ...folder }
    })
  }

  updateFolder(request: FolderUpdateRequest): Promise<FolderView[]> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const folder = findFolder(data, request.id)
      const name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      if (name === folder.name) return data.folders.map((candidate) => ({ ...candidate }))

      return this.renameFolderSubtree(data, folder, name, now)
    })
  }

  reparentFolder(request: FolderReparentRequest): Promise<FolderView[]> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const folder = findFolder(data, request.id)
      if (request.parentId !== null) assertUuid(request.parentId)
      const parent = request.parentId === null ? null : findFolder(data, request.parentId)
      if (parent && (parent.id === folder.id || parent.name.startsWith(`${folder.name}/`))) {
        throw new VaultError('INVALID_INPUT')
      }

      const folderNames = new Set(data.folders.map((candidate) => candidate.name))
      const hasCompleteParentChain = (name: string): boolean => {
        const path = name.split('/')
        return (
          path.length <= 1 ||
          (path.every((segment) => segment.length > 0) &&
            path
              .slice(0, -1)
              .every((_, index) => folderNames.has(path.slice(0, index + 1).join('/'))))
        )
      }
      if (
        !hasCompleteParentChain(folder.name) ||
        (parent && !hasCompleteParentChain(parent.name))
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const segments = folder.name.split('/')
      const leafName = segments.at(-1)!
      const nextRootName = normalizeRequiredString(
        parent ? `${parent.name}/${leafName}` : leafName,
        MAX_NAME_LENGTH
      )
      if (nextRootName === folder.name) {
        return data.folders.map((candidate) => ({ ...candidate }))
      }

      return this.renameFolderSubtree(data, folder, nextRootName, now)
    })
  }

  private renameFolderSubtree(
    data: VaultData,
    folder: FolderView,
    nextRootName: string,
    now: string
  ): FolderView[] {
    const sourcePrefix = `${folder.name}/`
    const affected = data.folders.filter(
      (candidate) => candidate.id === folder.id || candidate.name.startsWith(sourcePrefix)
    )
    const affectedIds = new Set(affected.map((candidate) => candidate.id))
    const occupiedNames = new Set(
      data.folders
        .filter((candidate) => !affectedIds.has(candidate.id))
        .map((candidate) => candidate.name.toLocaleLowerCase('en-US'))
    )
    const nextNames = new Map<string, string>()

    for (const candidate of affected) {
      const suffix = candidate.id === folder.id ? '' : candidate.name.slice(folder.name.length)
      const nextName = normalizeRequiredString(`${nextRootName}${suffix}`, MAX_NAME_LENGTH)
      const normalizedName = nextName.toLocaleLowerCase('en-US')
      if (occupiedNames.has(normalizedName)) throw new VaultError('DUPLICATE_NAME')
      occupiedNames.add(normalizedName)
      nextNames.set(candidate.id, nextName)
    }

    data.folders = data.folders.map((candidate) =>
      nextNames.has(candidate.id)
        ? { ...candidate, name: nextNames.get(candidate.id)!, updatedAt: now }
        : candidate
    )
    return data.folders.map((candidate) => ({ ...candidate }))
  }

  deleteFolder(request: FolderDeleteRequest): Promise<void> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      findFolder(data, request.id)
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
    return this.core.mutate((data, now) => {
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
}
