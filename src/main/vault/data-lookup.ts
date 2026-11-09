import type { FolderView, LoginBatchRequest } from '../../shared/vault-contract'
import { MAX_LOGIN_BATCH_IDS } from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { MAX_NAME_LENGTH } from './limits'
import { assertUuid } from './parse-primitives'
import type { StoredLogin, VaultData } from './types'

export function findFolder(data: VaultData, id: string): FolderView {
  const folder = data.folders.find((candidate) => candidate.id === id)
  if (!folder) throw new VaultError('NOT_FOUND')
  return folder
}

export function findLogin(data: VaultData, id: string): StoredLogin {
  const login = data.logins.find((candidate) => candidate.id === id)
  if (!login) throw new VaultError('NOT_FOUND')
  return login
}

export function resolveLoginBatch(
  data: VaultData,
  request: LoginBatchRequest,
  assertState: (login: StoredLogin) => void
): StoredLogin[] {
  if (
    !Array.isArray(request.ids) ||
    request.ids.length === 0 ||
    request.ids.length > MAX_LOGIN_BATCH_IDS
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  request.ids.forEach(assertUuid)
  if (new Set(request.ids).size !== request.ids.length) {
    throw new VaultError('INVALID_INPUT')
  }
  const logins = request.ids.map((id) => findLogin(data, id))
  logins.forEach(assertState)
  return logins
}

export function assertActiveLogin(login: StoredLogin): void {
  if (login.deletedAt !== null) throw new VaultError('INVALID_INPUT')
}

export function normalizeFolderId(data: VaultData, folderId: unknown): string | null {
  if (folderId === undefined || folderId === null) return null
  assertUuid(folderId)
  findFolder(data, folderId)
  return folderId
}

export function assertUniqueFolderName(data: VaultData, name: string): void {
  const normalized = name.toLocaleLowerCase('en-US')
  if (data.folders.some((folder) => folder.name.toLocaleLowerCase('en-US') === normalized)) {
    throw new VaultError('DUPLICATE_NAME')
  }
}

export function uniqueImportedFolderName(data: VaultData, requestedName: string): string {
  const existing = new Set(data.folders.map((folder) => folder.name.toLocaleLowerCase('en-US')))
  if (!existing.has(requestedName.toLocaleLowerCase('en-US'))) return requestedName

  for (let copy = 1; copy <= data.folders.length + 1; copy += 1) {
    const suffix = copy === 1 ? ' (Imported)' : ` (Imported ${copy})`
    const codePoints = Array.from(requestedName)
    while (codePoints.join('').length > MAX_NAME_LENGTH - suffix.length) codePoints.pop()
    const candidate = `${codePoints.join('')}${suffix}`
    if (!existing.has(candidate.toLocaleLowerCase('en-US'))) return candidate
  }
  throw new VaultError('INVALID_INPUT')
}

export function assertExpectedPasskeyRevision(
  login: StoredLogin,
  value: unknown
): asserts value is string {
  if (typeof value !== 'string' || value !== login.updatedAt) {
    throw new VaultError('INVALID_INPUT')
  }
}
