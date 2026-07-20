import { msg } from '@lingui/core/macro'
import { i18n } from '../i18n'

/** The date buckets used by the vault list. */
export type ItemDateGroupKey = 'today' | 'yesterday' | 'thisWeek' | 'older'

export interface ItemDateGroup<T> {
  key: ItemDateGroupKey
  label: string
  items: T[]
}

/** The minimum date fields needed to group a vault item. */
export interface ItemDateFields {
  lastUsedAt?: string | null
  updatedAt?: string | null
}

export type ItemDateSource = 'activity' | 'updatedAt'

const GROUP_DEFINITIONS: ReadonlyArray<Pick<ItemDateGroup<never>, 'key'>> = [
  { key: 'today' },
  { key: 'yesterday' },
  { key: 'thisWeek' },
  { key: 'older' }
]

function itemDateGroupLabel(key: ItemDateGroupKey): string {
  switch (key) {
    case 'today':
      return i18n._(msg`Today`)
    case 'yesterday':
      return i18n._(msg`Yesterday`)
    case 'thisWeek':
      return i18n._(msg`This week`)
    case 'older':
      return i18n._(msg`Earlier`)
  }
}

function startOfLocalDay(value: Date): Date {
  return new Date(value.getFullYear(), value.getMonth(), value.getDate())
}

/** Returns Monday 00:00 in the same local week as `value`. */
function startOfLocalWeek(value: Date): Date {
  const day = value.getDay()
  const daysSinceMonday = (day + 6) % 7
  const start = startOfLocalDay(value)
  start.setDate(start.getDate() - daysSinceMonday)
  return start
}

function parseDate(value: string | null | undefined): Date | null {
  const candidate = value?.trim()
  if (!candidate) return null

  const timestamp = Date.parse(candidate)
  return Number.isNaN(timestamp) ? null : new Date(timestamp)
}

function parseItemDate(item: ItemDateFields, source: ItemDateSource): Date | null {
  if (source === 'updatedAt') return parseDate(item.updatedAt)
  // A malformed last-used timestamp should not hide a valid updated timestamp.
  return parseDate(item.lastUsedAt) ?? parseDate(item.updatedAt)
}

function groupKeyForDate(value: Date | null, now: Date): ItemDateGroupKey {
  if (!value) return 'older'

  const today = startOfLocalDay(now)
  const yesterday = new Date(today)
  yesterday.setDate(yesterday.getDate() - 1)
  const thisWeek = startOfLocalWeek(now)

  if (value >= today) return 'today'
  if (value >= yesterday) return 'yesterday'
  if (value >= thisWeek) return 'thisWeek'
  return 'older'
}

/**
 * Groups items into calendar buckets without sorting them.
 *
 * The returned groups always follow the order Today, Yesterday, This Week, Earlier and
 * include empty groups so callers can render a consistent section structure.
 * `now` is injectable to keep callers and tests deterministic.
 */
export function groupItemsByDate<T extends ItemDateFields>(
  items: readonly T[],
  now: Date = new Date(),
  source: ItemDateSource = 'activity'
): ItemDateGroup<T>[] {
  const groups = new Map<ItemDateGroupKey, T[]>()
  for (const definition of GROUP_DEFINITIONS) groups.set(definition.key, [])

  for (const item of items) {
    groups.get(groupKeyForDate(parseItemDate(item, source), now))?.push(item)
  }

  return GROUP_DEFINITIONS.map(({ key }) => ({
    key,
    label: itemDateGroupLabel(key),
    items: groups.get(key) ?? []
  }))
}
