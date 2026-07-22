import { describe, expect, it } from 'vitest'
import {
  folderHierarchyDragIntent,
  folderRootDropId,
  itemDropPreviewDescription,
  precisePointerCollisionDetection,
  quickAccessDropAction,
  quickAccessDropIds
} from './VaultShell-dnd'
import type { CollisionDetection } from '@dnd-kit/core'

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

describe('itemDropPreviewDescription', () => {
  const folders = [{ id: 'folder-work', name: '工作' }]

  it('describes quick-access destinations', () => {
    expect(
      itemDropPreviewDescription({
        overId: quickAccessDropIds.favorites,
        itemState: 'active',
        folders,
        count: 1
      })
    ).toBe('加入我的最愛')
    expect(
      itemDropPreviewDescription({
        overId: quickAccessDropIds.archive,
        itemState: 'active',
        folders,
        count: 3
      })
    ).toBe('將 3 個項目移至封存')
    expect(
      itemDropPreviewDescription({
        overId: quickAccessDropIds.trash,
        itemState: 'archive',
        folders,
        count: 1
      })
    ).toBe('移至垃圾桶')
  })

  it('describes named and unfiled folder destinations', () => {
    expect(
      itemDropPreviewDescription({
        overId: 'folder-work',
        itemState: 'active',
        folders,
        count: 1
      })
    ).toBe('移至「工作」')
    expect(
      itemDropPreviewDescription({
        overId: 'folder:none',
        itemState: 'active',
        folders,
        count: 2
      })
    ).toBe('將 2 個項目移至「未分類」')
  })

  it('returns no destination text outside a valid drop target', () => {
    expect(
      itemDropPreviewDescription({ overId: null, itemState: 'active', folders, count: 1 })
    ).toBeNull()
    expect(
      itemDropPreviewDescription({
        overId: quickAccessDropIds.favorites,
        itemState: 'archive',
        folders,
        count: 1
      })
    ).toBeNull()
  })
})

describe('precisePointerCollisionDetection', () => {
  const rect = (
    left: number,
    top: number,
    width = 100,
    height = 40
  ): {
    left: number
    top: number
    width: number
    height: number
    right: number
    bottom: number
  } => ({
    left,
    top,
    width,
    height,
    right: left + width,
    bottom: top + height
  })
  const topRect = rect(0, 0)
  const bottomRect = rect(0, 100)
  const droppableContainers = [
    { id: 'top', disabled: false },
    { id: 'bottom', disabled: false }
  ]
  const baseArgs = {
    active: { id: 'active' },
    collisionRect: rect(400, 105, 20, 20),
    droppableRects: new Map([
      ['top', topRect],
      ['bottom', bottomRect]
    ]),
    droppableContainers
  } as unknown as Parameters<CollisionDetection>[0]

  it('does not infer a pointer target from vertical proximity', () => {
    expect(
      precisePointerCollisionDetection({
        ...baseArgs,
        pointerCoordinates: { x: 410, y: 115 }
      })
    ).toEqual([])
  })

  it('accepts a pointer only while it is inside the destination', () => {
    expect(
      precisePointerCollisionDetection({
        ...baseArgs,
        pointerCoordinates: { x: 20, y: 120 }
      })[0]?.id
    ).toBe('bottom')
  })

  it('keeps closest-center navigation for the keyboard sensor', () => {
    expect(precisePointerCollisionDetection({ ...baseArgs, pointerCoordinates: null })[0]?.id).toBe(
      'bottom'
    )
  })
})

describe('folderHierarchyDragIntent', () => {
  it('keeps vertical movement available for folder reordering', () => {
    expect(folderHierarchyDragIntent('folder-2', 17)).toBeNull()
    expect(folderHierarchyDragIntent('folder-2', -17)).toBeNull()
  })

  it('uses rightward movement to choose a parent folder', () => {
    expect(folderHierarchyDragIntent('folder-2', 18)).toEqual({ parentId: 'folder-2' })
  })

  it('uses leftward movement to move a folder to the root', () => {
    expect(folderHierarchyDragIntent('folder-2', -18)).toEqual({ parentId: null })
  })

  it('uses the explicit root target without requiring horizontal movement', () => {
    expect(folderHierarchyDragIntent(folderRootDropId, 0)).toEqual({ parentId: null })
  })
})
