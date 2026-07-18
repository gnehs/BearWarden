import { describe, expect, it } from 'vitest'
import { virtualRowScrollOffsets, visibleVirtualIndexes } from './virtualized-range'

describe('visibleVirtualIndexes', () => {
  const rows = [
    { index: 0, start: 0, end: 66 },
    { index: 1, start: 66, end: 132 },
    { index: 2, start: 132, end: 198 },
    { index: 3, start: 198, end: 264 }
  ]

  it('excludes rendered overscan rows outside the viewport', () => {
    expect(visibleVirtualIndexes(rows, 70, 100)).toEqual([1, 2])
  })

  it('does not treat a row touching the viewport boundary as visible', () => {
    expect(visibleVirtualIndexes(rows, 66, 66)).toEqual([1])
  })

  it('waits until the viewport has a measured size', () => {
    expect(visibleVirtualIndexes(rows, 0, 0)).toEqual([])
  })
})

describe('virtualRowScrollOffsets', () => {
  it('places an item one item-row below the viewport top', () => {
    expect(virtualRowScrollOffsets([66, 66, 66, 66], 66)).toEqual([0, 0, 66, 132])
  })

  it('accounts for group headers and clamps near the start', () => {
    expect(virtualRowScrollOffsets([31, 66, 66], 66)).toEqual([0, 0, 31])
  })
})
