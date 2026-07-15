import { describe, expect, it } from 'vitest'
import { groupItemsByDate } from './item-date-groups'

interface TestItem {
  id: string
  lastUsedAt?: string | null
  updatedAt?: string | null
}

const now = new Date(2026, 6, 15, 14, 30)

function idsFor(group: ReturnType<typeof groupItemsByDate<TestItem>>[number]): string[] {
  return group.items.map((item) => item.id)
}

describe('groupItemsByDate', () => {
  it('groups by last use with local calendar boundaries', () => {
    const groups = groupItemsByDate<TestItem>(
      [
        { id: 'today', lastUsedAt: '2026-07-15T08:00:00' },
        { id: 'yesterday', lastUsedAt: '2026-07-14T23:59:00' },
        { id: 'this-week', lastUsedAt: '2026-07-13T00:00:00' },
        { id: 'older', lastUsedAt: '2026-07-12T23:59:00' }
      ],
      now
    )

    expect(groups.map((group) => group.label)).toEqual(['今天', '昨天', '本週', '較早'])
    expect(groups.map(idsFor)).toEqual([['today'], ['yesterday'], ['this-week'], ['older']])
  })

  it('falls back to updatedAt when lastUsedAt is missing or invalid', () => {
    const groups = groupItemsByDate<TestItem>(
      [
        { id: 'missing', lastUsedAt: null, updatedAt: '2026-07-15T10:00:00' },
        { id: 'blank', lastUsedAt: '  ', updatedAt: '2026-07-14T10:00:00' },
        { id: 'invalid', lastUsedAt: 'not-a-date', updatedAt: '2026-07-13T10:00:00' },
        { id: 'no-date', lastUsedAt: null, updatedAt: null }
      ],
      now
    )

    expect(groups.map(idsFor)).toEqual([['missing'], ['blank'], ['invalid'], ['no-date']])
  })

  it('keeps the input order within every group and does not mutate the input', () => {
    const items: TestItem[] = [
      { id: 'today-first', lastUsedAt: '2026-07-15T09:00:00' },
      { id: 'older', lastUsedAt: '2026-07-01T09:00:00' },
      { id: 'today-second', lastUsedAt: '2026-07-15T08:00:00' }
    ]
    const original = [...items]

    const groups = groupItemsByDate(items, now)

    expect(groups.map(idsFor)).toEqual([['today-first', 'today-second'], [], [], ['older']])
    expect(items).toEqual(original)
  })

  it('uses Monday as the start of the local week', () => {
    const sunday = new Date(2026, 6, 19, 12, 0)
    const groups = groupItemsByDate<TestItem>(
      [
        { id: 'sunday', lastUsedAt: '2026-07-19T09:00:00' },
        { id: 'monday', lastUsedAt: '2026-07-13T09:00:00' },
        { id: 'previous-sunday', lastUsedAt: '2026-07-12T09:00:00' }
      ],
      sunday
    )

    expect(groups.map(idsFor)).toEqual([['sunday'], [], ['monday'], ['previous-sunday']])
  })

  it('can group recent-modified sorting strictly by updatedAt', () => {
    const groups = groupItemsByDate<TestItem>(
      [
        {
          id: 'recently-used-but-older-edit',
          lastUsedAt: '2026-07-15T09:00:00',
          updatedAt: '2026-07-01T09:00:00'
        }
      ],
      now,
      'updatedAt'
    )

    expect(groups.map(idsFor)).toEqual([[], [], [], ['recently-used-but-older-edit']])
  })
})
