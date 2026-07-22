import type { FolderView } from '../../../shared/vault-contract'

export interface VaultFolderHierarchyRow {
  folder: FolderView
  label: string
  depth: number
  parentId: string | null
  hasChildren: boolean
}

export interface VaultFolderFormValue {
  name: string
  parentId: string
}

export type VaultFolderMovePlan =
  | { kind: 'move'; folders: FolderView[] }
  | { kind: 'noop' }
  | {
      kind: 'invalid'
      reason:
        | 'missing-source'
        | 'missing-parent'
        | 'malformed'
        | 'descendant'
        | 'duplicate'
        | 'name-too-long'
    }

export const MAX_VAULT_FOLDER_NAME_LENGTH = 256

function folderPathSegments(name: string): string[] | null {
  const segments = name.split('/')
  return segments.length > 1 && segments.every((segment) => segment.length > 0) ? segments : null
}

function hasCompleteParentChain(name: string, folderNames: ReadonlySet<string>): boolean {
  const segments = folderPathSegments(name)
  return Boolean(
    segments &&
    segments
      .slice(0, -1)
      .every((_, index) => folderNames.has(segments.slice(0, index + 1).join('/')))
  )
}

/** Applies Bitwarden's slash-path convention and returns a tree in pre-order. */
export function vaultFolderHierarchyRows(
  folders: readonly FolderView[]
): VaultFolderHierarchyRow[] {
  const folderNames = new Set(folders.map((folder) => folder.name))
  const folderByName = new Map(folders.map((folder) => [folder.name, folder]))
  const childrenByParentId = new Map<string, FolderView[]>()
  const roots: FolderView[] = []

  for (const folder of folders) {
    const segments = folderPathSegments(folder.name)
    if (!segments || !hasCompleteParentChain(folder.name, folderNames)) {
      roots.push(folder)
      continue
    }

    const parentName = segments.slice(0, -1).join('/')
    const parent = folderByName.get(parentName)
    if (!parent) {
      roots.push(folder)
      continue
    }
    const children = childrenByParentId.get(parent.id) ?? []
    children.push(folder)
    childrenByParentId.set(parent.id, children)
  }

  const rows: VaultFolderHierarchyRow[] = []
  const append = (folder: FolderView, depth: number, parentId: string | null): void => {
    const children = childrenByParentId.get(folder.id) ?? []
    const segments = folderPathSegments(folder.name)
    rows.push({
      folder,
      label: depth > 0 && segments ? segments.at(-1)! : folder.name,
      depth,
      parentId,
      hasChildren: children.length > 0
    })
    for (const child of children) append(child, depth + 1, folder.id)
  }

  for (const root of roots) append(root, 0, null)
  return rows
}

export function visibleVaultFolderHierarchyRows(
  rows: readonly VaultFolderHierarchyRow[],
  collapsedFolderIds: ReadonlySet<string>
): VaultFolderHierarchyRow[] {
  let hiddenBelowDepth: number | null = null

  return rows.filter((row) => {
    if (hiddenBelowDepth !== null && row.depth > hiddenBelowDepth) return false
    hiddenBelowDepth = null
    if (row.hasChildren && collapsedFolderIds.has(row.folder.id)) {
      hiddenBelowDepth = row.depth
    }
    return true
  })
}

export function vaultFolderAggregateCounts(
  rows: readonly VaultFolderHierarchyRow[],
  directCounts: ReadonlyMap<string | null, number>
): ReadonlyMap<string, number> {
  const totals = new Map<string, number>()

  for (let index = rows.length - 1; index >= 0; index -= 1) {
    const row = rows[index]
    const total = (directCounts.get(row.folder.id) ?? 0) + (totals.get(row.folder.id) ?? 0)
    totals.set(row.folder.id, total)
    if (row.parentId) totals.set(row.parentId, (totals.get(row.parentId) ?? 0) + total)
  }

  return totals
}

export function vaultFolderVisibleItemCount(
  row: VaultFolderHierarchyRow,
  expanded: boolean,
  directCounts: ReadonlyMap<string | null, number>,
  aggregateCounts: ReadonlyMap<string, number>
): number {
  return row.hasChildren && !expanded
    ? (aggregateCounts.get(row.folder.id) ?? 0)
    : (directCounts.get(row.folder.id) ?? 0)
}

export function vaultFolderFormValue(
  folder: FolderView | undefined,
  folders: readonly FolderView[]
): VaultFolderFormValue {
  if (!folder) return { name: '', parentId: '' }

  const separatorIndex = folder.name.lastIndexOf('/')
  const folderNames = new Set(folders.map((candidate) => candidate.name))
  if (
    separatorIndex <= 0 ||
    separatorIndex === folder.name.length - 1 ||
    !hasCompleteParentChain(folder.name, folderNames)
  ) {
    return { name: folder.name, parentId: '' }
  }

  const parentName = folder.name.slice(0, separatorIndex)
  const parent = folders.find((candidate) => candidate.name === parentName)
  return parent
    ? { name: folder.name.slice(separatorIndex + 1), parentId: parent.id }
    : { name: folder.name, parentId: '' }
}

export function vaultFolderParentCandidates(
  folders: readonly FolderView[],
  folder?: FolderView
): FolderView[] {
  return vaultFolderParentCandidateRows(folders, folder).map((row) => row.folder)
}

export function vaultFolderParentCandidateRows(
  folders: readonly FolderView[],
  folder?: FolderView
): VaultFolderHierarchyRow[] {
  const folderNames = new Set(folders.map((candidate) => candidate.name))
  const descendantPrefix = folder ? `${folder.name}/` : null
  return vaultFolderHierarchyRows(folders).filter(
    ({ folder: candidate }) =>
      candidate.id !== folder?.id &&
      (!descendantPrefix || !candidate.name.startsWith(descendantPrefix)) &&
      candidate.name.length < MAX_VAULT_FOLDER_NAME_LENGTH - 1 &&
      (!folderPathSegments(candidate.name) || hasCompleteParentChain(candidate.name, folderNames))
  )
}

export function composeVaultFolderName(
  name: string,
  parentId: string,
  folders: readonly FolderView[]
): string | null {
  if (!parentId) return name
  const parent = folders.find((folder) => folder.id === parentId)
  return parent ? `${parent.name}/${name}` : null
}

export function isVaultFolderNameDuplicate(
  name: string,
  folders: readonly FolderView[],
  excludedId?: string
): boolean {
  const normalizedName = name.toLocaleLowerCase('en-US')
  return folders.some(
    (folder) =>
      folder.id !== excludedId && folder.name.toLocaleLowerCase('en-US') === normalizedName
  )
}

export function planVaultFolderMove(
  folders: readonly FolderView[],
  sourceId: string,
  parentId: string | null
): VaultFolderMovePlan {
  const source = folders.find((folder) => folder.id === sourceId)
  if (!source) return { kind: 'invalid', reason: 'missing-source' }

  const sourceForm = vaultFolderFormValue(source, folders)
  if (source.name.includes('/') && !sourceForm.parentId) {
    return { kind: 'invalid', reason: 'malformed' }
  }

  if (parentId !== null) {
    const parent = folders.find((folder) => folder.id === parentId)
    if (!parent) return { kind: 'invalid', reason: 'missing-parent' }
    if (parent.id === source.id || parent.name.startsWith(`${source.name}/`)) {
      return { kind: 'invalid', reason: 'descendant' }
    }
    if (
      !vaultFolderParentCandidates(folders, source).some((candidate) => candidate.id === parentId)
    ) {
      return { kind: 'invalid', reason: 'malformed' }
    }
  }

  const nextRootName = composeVaultFolderName(sourceForm.name, parentId ?? '', folders)
  if (!nextRootName) return { kind: 'invalid', reason: 'missing-parent' }
  if (nextRootName === source.name) return { kind: 'noop' }

  const sourcePrefix = `${source.name}/`
  const affectedIds = new Set(
    folders
      .filter((folder) => folder.id === source.id || folder.name.startsWith(sourcePrefix))
      .map((folder) => folder.id)
  )
  const occupiedNames = new Set(
    folders
      .filter((folder) => !affectedIds.has(folder.id))
      .map((folder) => folder.name.toLocaleLowerCase('en-US'))
  )
  const movedFolders: FolderView[] = []

  for (const folder of folders) {
    if (!affectedIds.has(folder.id)) {
      movedFolders.push(folder)
      continue
    }
    const suffix = folder.id === source.id ? '' : folder.name.slice(source.name.length)
    const name = `${nextRootName}${suffix}`
    if (name.length > MAX_VAULT_FOLDER_NAME_LENGTH) {
      return { kind: 'invalid', reason: 'name-too-long' }
    }
    const normalizedName = name.toLocaleLowerCase('en-US')
    if (occupiedNames.has(normalizedName)) return { kind: 'invalid', reason: 'duplicate' }
    occupiedNames.add(normalizedName)
    movedFolders.push({ ...folder, name })
  }

  return { kind: 'move', folders: movedFolders }
}
