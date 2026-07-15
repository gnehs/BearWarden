import { describe, expect, it } from 'vitest'
import {
  normalizeItemSelection,
  updateItemSelection,
  type ItemSelectionState
} from './item-selection'

const orderedIds = ['a', 'b', 'c', 'd', 'e']

function state(
  selectedIds: readonly string[] = [],
  anchorId: string | null = null,
  activeId: string | null = null
): ItemSelectionState {
  return { selectedIds: new Set(selectedIds), anchorId, activeId }
}

describe('updateItemSelection', () => {
  it('replaces the selection with a normal click', () => {
    const result = updateItemSelection({
      ...state(['a', 'c'], 'a', 'c'),
      orderedIds,
      targetId: 'd'
    })

    expect(result).toEqual(state(['d'], 'd', 'd'))
  })

  it('adds and removes with the toggle modifier used by Ctrl and Meta', () => {
    const added = updateItemSelection({
      ...state(['b'], 'b', 'b'),
      orderedIds,
      targetId: 'd',
      toggle: true
    })
    const removed = updateItemSelection({
      ...added,
      orderedIds,
      targetId: 'd',
      toggle: true
    })

    expect(added).toEqual(state(['b', 'd'], 'd', 'd'))
    expect(removed).toEqual(state(['b'], 'b', 'b'))
  })

  it('replaces the selection with an inclusive Shift range in either direction', () => {
    const forward = updateItemSelection({
      ...state(['b'], 'b', 'b'),
      orderedIds,
      targetId: 'd',
      range: true
    })
    const backward = updateItemSelection({
      ...state(['d'], 'd', 'd'),
      orderedIds,
      targetId: 'b',
      range: true
    })

    expect(forward).toEqual(state(['b', 'c', 'd'], 'b', 'd'))
    expect(backward).toEqual(state(['b', 'c', 'd'], 'd', 'b'))
  })

  it('unions Ctrl or Meta Shift ranges with the existing selection', () => {
    const result = updateItemSelection({
      ...state(['a', 'c'], 'c', 'c'),
      orderedIds,
      targetId: 'e',
      toggle: true,
      range: true
    })

    expect(result).toEqual(state(['a', 'c', 'd', 'e'], 'c', 'e'))
  })

  it('falls back from an invalid range anchor to the active item, then the target', () => {
    const activeFallback = updateItemSelection({
      ...state(['b'], 'missing', 'b'),
      orderedIds,
      targetId: 'd',
      range: true
    })
    const targetFallback = updateItemSelection({
      ...state([], 'missing', 'also-missing'),
      orderedIds,
      targetId: 'd',
      range: true
    })

    expect(activeFallback).toEqual(state(['b', 'c', 'd'], 'b', 'd'))
    expect(targetFallback).toEqual(state(['d'], 'd', 'd'))
  })

  it('moves the active item to the final remaining selected ID when it is toggled off', () => {
    const result = updateItemSelection({
      ...state(['a', 'c', 'e'], 'a', 'c'),
      orderedIds,
      targetId: 'c',
      toggle: true
    })

    expect(result).toEqual(state(['a', 'e'], 'a', 'e'))
  })
})

describe('normalizeItemSelection', () => {
  it('prunes filtered or deleted items and safely repairs active and anchor IDs', () => {
    const result = normalizeItemSelection({
      ...state(['a', 'b', 'deleted', 'd'], 'deleted', 'b'),
      orderedIds: ['a', 'd']
    })

    expect(result).toEqual(state(['a', 'd'], 'd', 'd'))
  })

  it('keeps valid cursors while ordering selected IDs by the allowed item order', () => {
    const result = normalizeItemSelection({
      ...state(['d', 'a'], 'a', 'd'),
      orderedIds
    })

    expect(result).toEqual(state(['a', 'd'], 'a', 'd'))
  })
})
