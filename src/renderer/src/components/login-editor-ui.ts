import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import { arrayMove } from '@dnd-kit/sortable'
import { parse } from 'tldts'
import type { VaultCustomFieldType, VaultLoginUri } from '../../../shared/vault-contract'

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

export function editorHeaderContent(
  typeLabel: string,
  itemName: string | null
): { eyebrow: string; heading: string; typeBadge: string | null } {
  return itemName === null
    ? { eyebrow: i18n._(msg`New item`), heading: typeLabel, typeBadge: null }
    : { eyebrow: i18n._(msg`Edit ${typeLabel}`), heading: itemName, typeBadge: typeLabel }
}

// Keep module initialization locale-independent. Labels are created inside LoginEditor after
// Lingui has activated the selected catalog, while these values remain safe to import at startup.
export const uriMatchOptionValues = ['default', '0', '1', '2', '3', '4', '5'] as const

export type UriMatchOptionValue = (typeof uriMatchOptionValues)[number]

export interface UriMatchRecognizedParts {
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
  const uri = value === '2' || value === '3' || value === '4' ? rawUri : trimmedUri

  const recognized =
    value === 'default' || value === '0'
      ? recognizedBaseDomain(trimmedUri)
      : value === '1'
        ? recognizedHost(trimmedUri)
        : value === '2' || value === '3' || value === '4'
          ? uri
          : null
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

export function uriMatchExample(value: UriMatchOptionValue, rawUri: string): string {
  const uri = rawUri.trim()
  if (!uri) return i18n._(msg`Enter a URL to show a matching example`)

  switch (value) {
    case 'default':
      return i18n._(msg`${uri} → Determined by account settings ○URL△`)
    case '0':
      return i18n._(msg`${uri} ≈ ○URL△ with the same base domain`)
    case '1':
      return i18n._(msg`${uri} ≈ ○path△ on the same host`)
    case '2':
      return i18n._(msg`${uri} ≈ ${uri}○△`)
    case '3':
      return i18n._(msg`${uri} = ${uri}; ○△ does not match`)
    case '4':
      return i18n._(msg`${uri} → Matches ○URL△ that satisfies the rule`)
    case '5':
      return i18n._(msg`${uri} ≠ every ○URL△`)
  }
}
