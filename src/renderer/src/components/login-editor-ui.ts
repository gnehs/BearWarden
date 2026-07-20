import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'

export function editorHeaderContent(
  typeLabel: string,
  itemName: string | null
): { eyebrow: string; heading: string; typeBadge: string | null } {
  return itemName === null
    ? { eyebrow: i18n._(msg`New item`), heading: typeLabel, typeBadge: null }
    : { eyebrow: i18n._(msg`Edit ${typeLabel}`), heading: itemName, typeBadge: typeLabel }
}

export const uriMatchOptions = [
  {
    value: 'default',
    label: i18n._(msg`Account default`)
  },
  {
    value: '0',
    label: i18n._(msg`Base domain`)
  },
  {
    value: '1',
    label: i18n._(msg`Host`)
  },
  {
    value: '2',
    label: i18n._(msg`Starts with`)
  },
  {
    value: '3',
    label: i18n._(msg`Exact match`)
  },
  {
    value: '4',
    label: i18n._(msg`Regular expression`)
  },
  {
    value: '5',
    label: i18n._(msg`Never match`)
  }
] as const

export type UriMatchOptionValue = (typeof uriMatchOptions)[number]['value']

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
