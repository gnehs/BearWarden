import { describe, expect, it } from 'vitest'
import type { FolderView } from '../../../shared/vault-contract'
import {
  composeVaultFolderName,
  isVaultFolderNameDuplicate,
  planVaultFolderMove,
  vaultFolderAggregateCounts,
  vaultFolderFormValue,
  vaultFolderHierarchyRows,
  vaultFolderParentCandidateRows,
  vaultFolderParentCandidates,
  vaultFolderVisibleItemCount,
  visibleVaultFolderHierarchyRows
} from './vault-folder-tree'

function folder(id: string, name: string, position: number): FolderView {
  return {
    id,
    name,
    position,
    createdAt: '2026-07-22T00:00:00.000Z',
    updatedAt: '2026-07-22T00:00:00.000Z'
  }
}

describe('vault folder hierarchy', () => {
  it('shows slash-delimited folders as children when every parent exists', () => {
    const rows = vaultFolderHierarchyRows([
      folder('finance', '金融', 0),
      folder('bank', '金融/銀行', 1),
      folder('card', '金融/信用卡', 2)
    ])

    expect(rows.map(({ folder: value, label, depth }) => [value.id, label, depth])).toEqual([
      ['finance', '金融', 0],
      ['bank', '銀行', 1],
      ['card', '信用卡', 1]
    ])
  })

  it('supports deep nesting only when intermediate parents exist', () => {
    const complete = vaultFolderHierarchyRows([
      folder('a', 'A', 0),
      folder('ab', 'A/B', 1),
      folder('abc', 'A/B/C', 2)
    ])
    const missingIntermediate = vaultFolderHierarchyRows([
      folder('a', 'A', 0),
      folder('abc', 'A/B/C', 1)
    ])

    expect(complete[2]).toMatchObject({ label: 'C', depth: 2 })
    expect(missingIntermediate[1]).toMatchObject({ label: 'A/B/C', depth: 0 })
  })

  it('keeps the complete name when the direct parent does not exist', () => {
    const rows = vaultFolderHierarchyRows([
      folder('bank', '金融/銀行', 0),
      folder('card', '金融/信用卡', 1)
    ])

    expect(rows.map(({ label, depth }) => [label, depth])).toEqual([
      ['金融/銀行', 0],
      ['金融/信用卡', 0]
    ])
  })

  it('keeps malformed slash names as flat folders', () => {
    const rows = vaultFolderHierarchyRows([
      folder('leading', '/金融', 0),
      folder('empty', '金融//銀行', 1),
      folder('trailing', '金融/', 2)
    ])

    expect(rows.map(({ label, depth }) => [label, depth])).toEqual([
      ['/金融', 0],
      ['金融//銀行', 0],
      ['金融/', 0]
    ])
  })

  it('places every child immediately after its parent while preserving sibling order', () => {
    const rows = vaultFolderHierarchyRows([
      folder('bank', '金融/銀行', 0),
      folder('travel', '旅行', 1),
      folder('finance', '金融', 2),
      folder('card', '金融/信用卡', 3),
      folder('visa', '金融/信用卡/Visa', 4)
    ])

    expect(rows.map(({ folder: value }) => value.id)).toEqual([
      'travel',
      'finance',
      'bank',
      'card',
      'visa'
    ])
    expect(rows.map(({ parentId, hasChildren }) => [parentId, hasChildren])).toEqual([
      [null, false],
      [null, true],
      ['finance', false],
      ['finance', true],
      ['card', false]
    ])
  })

  it('hides the complete descendant subtree of a collapsed folder', () => {
    const rows = vaultFolderHierarchyRows([
      folder('finance', '金融', 0),
      folder('bank', '金融/銀行', 1),
      folder('card', '金融/信用卡', 2),
      folder('visa', '金融/信用卡/Visa', 3),
      folder('travel', '旅行', 4)
    ])

    expect(
      visibleVaultFolderHierarchyRows(rows, new Set(['finance'])).map((row) => row.folder.id)
    ).toEqual(['finance', 'travel'])
    expect(
      visibleVaultFolderHierarchyRows(rows, new Set(['card'])).map((row) => row.folder.id)
    ).toEqual(['finance', 'bank', 'card', 'travel'])
  })

  it('aggregates direct item counts through every descendant', () => {
    const rows = vaultFolderHierarchyRows([
      folder('finance', '金融', 0),
      folder('bank', '金融/銀行', 1),
      folder('card', '金融/信用卡', 2),
      folder('visa', '金融/信用卡/Visa', 3),
      folder('travel', '旅行', 4)
    ])
    const counts = vaultFolderAggregateCounts(
      rows,
      new Map<string | null, number>([
        ['finance', 1],
        ['bank', 2],
        ['card', 3],
        ['visa', 4],
        ['travel', 5]
      ])
    )

    expect(Object.fromEntries(counts)).toEqual({
      finance: 10,
      bank: 2,
      card: 7,
      visa: 4,
      travel: 5
    })
    expect(vaultFolderVisibleItemCount(rows[0], true, new Map([['finance', 1]]), counts)).toBe(1)
    expect(vaultFolderVisibleItemCount(rows[0], false, new Map([['finance', 1]]), counts)).toBe(10)
    expect(vaultFolderVisibleItemCount(rows[1], false, new Map([['bank', 2]]), counts)).toBe(2)
  })
})

describe('vault folder form', () => {
  const folders = [
    folder('finance', '金融', 0),
    folder('bank', '金融/銀行', 1),
    folder('cards', '金融/信用卡', 2),
    folder('visa', '金融/信用卡/Visa', 3),
    folder('travel', '旅行', 4)
  ]

  it('separates an existing direct parent from the editable leaf name', () => {
    expect(vaultFolderFormValue(folders[1], folders)).toEqual({
      name: '銀行',
      parentId: 'finance'
    })
  })

  it('keeps the complete name when its direct parent is missing', () => {
    const orphan = folder('orphan', '工作/開發/前端', 5)
    expect(vaultFolderFormValue(orphan, folders)).toEqual({
      name: '工作/開發/前端',
      parentId: ''
    })
  })

  it('keeps the complete name when an ancestor above the direct parent is missing', () => {
    const incompleteFolders = [
      folder('development', '工作/開發', 0),
      folder('frontend', '工作/開發/前端', 1)
    ]

    expect(vaultFolderFormValue(incompleteFolders[1], incompleteFolders)).toEqual({
      name: '工作/開發/前端',
      parentId: ''
    })
  })

  it('excludes the edited folder and all descendants from parent candidates', () => {
    expect(vaultFolderParentCandidates(folders, folders[2]).map((value) => value.id)).toEqual([
      'finance',
      'bank',
      'travel'
    ])
  })

  it('returns parent candidates in tree order with leaf labels and depths', () => {
    const unordered = [
      folder('card', '金融/信用卡', 0),
      folder('travel', '旅行', 1),
      folder('finance', '金融', 2),
      folder('visa', '金融/信用卡/Visa', 3),
      folder('bank', '金融/銀行', 4)
    ]

    expect(
      vaultFolderParentCandidateRows(unordered).map(({ folder: value, label, depth }) => [
        value.id,
        label,
        depth
      ])
    ).toEqual([
      ['travel', '旅行', 0],
      ['finance', '金融', 0],
      ['card', '信用卡', 1],
      ['visa', 'Visa', 2],
      ['bank', '銀行', 1]
    ])
    expect(
      vaultFolderParentCandidateRows(unordered, unordered[2]).map((row) => row.folder.id)
    ).toEqual(['travel'])
  })

  it('does not mistake a similarly prefixed sibling for a descendant', () => {
    const values = [folder('a', 'A', 0), folder('ab', 'AB', 1), folder('child', 'A/B', 2)]
    expect(vaultFolderParentCandidates(values, values[0]).map((value) => value.id)).toEqual(['ab'])
  })

  it('omits orphaned and too-long folders that cannot become valid parents', () => {
    const values = [
      folder('orphan', 'A/B', 0),
      folder('long', 'L'.repeat(255), 1),
      folder('valid', 'Valid', 2)
    ]
    expect(vaultFolderParentCandidates(values).map((value) => value.id)).toEqual(['valid'])
  })

  it('composes the persisted slash path from the selected parent', () => {
    expect(composeVaultFolderName('銀行', 'finance', folders)).toBe('金融/銀行')
    expect(composeVaultFolderName('銀行', '', folders)).toBe('銀行')
    expect(composeVaultFolderName('銀行', 'missing', folders)).toBeNull()
  })

  it('detects case-insensitive duplicate full paths while excluding the edited folder', () => {
    expect(isVaultFolderNameDuplicate('金融/銀行', folders)).toBe(true)
    expect(isVaultFolderNameDuplicate('金融/銀行', folders, 'bank')).toBe(false)
    expect(isVaultFolderNameDuplicate('FINANCE', [folder('finance', 'finance', 0)])).toBe(true)
  })
})

describe('vault folder move planning', () => {
  const values = [
    folder('a', 'A', 0),
    folder('ab', 'A/B', 1),
    folder('abc', 'A/B/C', 2),
    folder('x', 'X', 3)
  ]

  it('moves a complete subtree beneath a new parent without changing its order', () => {
    const plan = planVaultFolderMove(values, 'ab', 'x')

    expect(plan.kind).toBe('move')
    if (plan.kind !== 'move') return
    expect(plan.folders.map(({ id, name, position }) => [id, name, position])).toEqual([
      ['a', 'A', 0],
      ['ab', 'X/B', 1],
      ['abc', 'X/B/C', 2],
      ['x', 'X', 3]
    ])
  })

  it('moves a subtree back to the root', () => {
    const plan = planVaultFolderMove(values, 'ab', null)

    expect(plan.kind).toBe('move')
    if (plan.kind !== 'move') return
    expect(plan.folders.map(({ name }) => name)).toEqual(['A', 'B', 'B/C', 'X'])
  })

  it('rejects self, descendant, duplicate, malformed, and overlong destinations', () => {
    expect(planVaultFolderMove(values, 'a', 'a')).toMatchObject({
      kind: 'invalid',
      reason: 'descendant'
    })
    expect(planVaultFolderMove(values, 'a', 'abc')).toMatchObject({
      kind: 'invalid',
      reason: 'descendant'
    })
    expect(
      planVaultFolderMove([...values, folder('duplicate', 'X/B', 4)], 'ab', 'x')
    ).toMatchObject({ kind: 'invalid', reason: 'duplicate' })
    expect(
      planVaultFolderMove([folder('orphan', 'A/B', 0), folder('x', 'X', 1)], 'orphan', 'x')
    ).toMatchObject({ kind: 'invalid', reason: 'malformed' })
    expect(
      planVaultFolderMove(
        [folder('source', 'S', 0), folder('child', `S/${'C'.repeat(254)}`, 1), folder('x', 'X', 2)],
        'source',
        'x'
      )
    ).toMatchObject({ kind: 'invalid', reason: 'name-too-long' })
  })

  it('treats the current parent and an already-root folder as no-ops', () => {
    expect(planVaultFolderMove(values, 'ab', 'a')).toEqual({ kind: 'noop' })
    expect(planVaultFolderMove(values, 'x', null)).toEqual({ kind: 'noop' })
  })
})
