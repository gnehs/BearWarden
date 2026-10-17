import { arrayMove } from '@dnd-kit/sortable'
import { parse } from 'tldts'
import type {
  VaultCustomFieldType,
  VaultLoginUri,
  VaultUriMatch
} from '../../../shared/vault-contract'

export function canSelectCustomFieldType(
  type: VaultCustomFieldType,
  options: { canUseLinked: boolean; canEditSecrets: boolean }
): boolean {
  return (
    (type !== 'linked' || options.canUseLinked) && (type !== 'hidden' || options.canEditSecrets)
  )
}

export type EditorLoginUri = VaultLoginUri & {
  /** Renderer-only identity for stable drag-and-drop keys. Removed before IPC submission. */
  clientId: string
}

export function reorderEditorItemsByClientId<T extends { clientId: string }>(
  items: T[],
  activeId: string,
  overId: string
): T[] {
  const oldIndex = items.findIndex((entry) => entry.clientId === activeId)
  const newIndex = items.findIndex((entry) => entry.clientId === overId)
  if (oldIndex < 0 || newIndex < 0 || oldIndex === newIndex) return items

  return arrayMove(items, oldIndex, newIndex)
}

export function reorderEditorUris(
  uris: EditorLoginUri[],
  activeId: string,
  overId: string
): { uri: string | null; uris: EditorLoginUri[] } {
  const reordered = reorderEditorItemsByClientId(uris, activeId, overId)
  return { uris: reordered, uri: reordered[0]?.uri ?? null }
}

export type UriMatchOptionValue = 'default' | `${VaultUriMatch}`

export function uriMatchOptionValue(match: VaultUriMatch | null): UriMatchOptionValue {
  return match === null ? 'default' : `${match}`
}

interface UriMatchRecognizedParts {
  leading: string
  recognized: string | null
  trailing: string
}

function recognizedBaseDomain(uri: string): string | null {
  try {
    const parsed = parse(uri, { allowPrivateDomains: true, validHosts: ['localhost'] })
    return parsed.isIp || parsed.hostname === 'localhost' ? parsed.hostname : parsed.domain
  } catch {
    return null
  }
}

function recognizedHost(uri: string): string | null {
  const withProtocol = uri.includes('://') ? uri : uri.includes('.') ? `http://${uri}` : null
  if (!withProtocol) return null
  try {
    return new URL(withProtocol).host || null
  } catch {
    return null
  }
}

export function uriMatchRecognizedParts(
  value: UriMatchOptionValue,
  rawUri: string
): UriMatchRecognizedParts {
  const trimmedUri = rawUri.trim()
  if (!trimmedUri) return { leading: '', recognized: null, trailing: '' }
  const matchesWholeUri = value === '2' || value === '3' || value === '4'
  const uri = matchesWholeUri ? rawUri : trimmedUri

  const recognized = matchesWholeUri
    ? uri
    : value === '1'
      ? recognizedHost(trimmedUri)
      : value === '5'
        ? null
        : recognizedBaseDomain(trimmedUri)
  if (!recognized) return { leading: uri, recognized: null, trailing: '' }

  const start = uri.toLocaleLowerCase('en-US').indexOf(recognized.toLocaleLowerCase('en-US'))
  if (start < 0) return { leading: uri, recognized: null, trailing: '' }
  const end = start + recognized.length
  return {
    leading: uri.slice(0, start),
    recognized: uri.slice(start, end),
    trailing: uri.slice(end)
  }
}
