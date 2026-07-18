import { describe, expect, it } from 'vitest'
import { quickAccessDropAction, quickAccessDropIds } from './VaultShell-dnd'

describe('quickAccessDropAction', () => {
  it('maps active items to each quick-access action', () => {
    expect(quickAccessDropAction(quickAccessDropIds.favorites, 'active')).toBe('favorites')
    expect(quickAccessDropAction(quickAccessDropIds.archive, 'active')).toBe('archive')
    expect(quickAccessDropAction(quickAccessDropIds.trash, 'active')).toBe('trash')
  })

  it('only allows archived items to move to the trash', () => {
    expect(quickAccessDropAction(quickAccessDropIds.favorites, 'archive')).toBeNull()
    expect(quickAccessDropAction(quickAccessDropIds.archive, 'archive')).toBeNull()
    expect(quickAccessDropAction(quickAccessDropIds.trash, 'archive')).toBe('trash')
  })

  it('ignores unrelated drop targets', () => {
    expect(quickAccessDropAction('folder:none', 'active')).toBeNull()
    expect(quickAccessDropAction('folder-id', 'archive')).toBeNull()
  })
})
