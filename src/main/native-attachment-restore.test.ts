import { describe, expect, it } from 'vitest'
import {
  assertNativeAttachmentRestoreBinding,
  beginNativeAttachmentRestoreAttempt,
  bindNativeAttachmentRestoreRemoteItem,
  completeNativeAttachmentRestoreAttempt,
  createNativeAttachmentRestoreJournal,
  failNativeAttachmentRestoreAttempt,
  nextNativeAttachmentRestoreAttachment,
  parseNativeAttachmentRestoreJournal,
  parseNativeAttachmentRestoreJournalJson,
  reconcileNativeAttachmentRestoreMissing,
  reconcileNativeAttachmentRestoreUploaded,
  recoverInterruptedNativeAttachmentRestore,
  serializeNativeAttachmentRestoreJournal,
  type NativeAttachmentRestoreJournal,
  type NativeAttachmentRestorePlan
} from './native-attachment-restore'

const ARCHIVE_FINGERPRINT = 'a'.repeat(64)
const ACCOUNT_FINGERPRINT = 'b'.repeat(64)
const FIRST_LOCAL_ID = '11111111-1111-4111-8111-111111111111'
const SECOND_LOCAL_ID = '22222222-2222-4222-8222-222222222222'
const FIRST_REMOTE_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const SECOND_REMOTE_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const CREATED_AT = '2026-07-17T01:00:00.000Z'
const T1 = '2026-07-17T01:01:00.000Z'
const T2 = '2026-07-17T01:02:00.000Z'
const T3 = '2026-07-17T01:03:00.000Z'
const T4 = '2026-07-17T01:04:00.000Z'

function plan(): NativeAttachmentRestorePlan {
  return {
    archiveFingerprint: ARCHIVE_FINGERPRINT,
    accountFingerprint: ACCOUNT_FINGERPRINT,
    createdAt: CREATED_AT,
    items: [
      { sourceItemId: 'source-item-1', localItemId: FIRST_LOCAL_ID },
      { sourceItemId: 'source-item-2', localItemId: SECOND_LOCAL_ID }
    ],
    attachments: [
      {
        sourceItemId: 'source-item-1',
        sourceAttachmentId: 'source-attachment-1',
        fileName: 'first.txt',
        size: 5,
        digest: 'c'.repeat(64)
      },
      {
        sourceItemId: 'source-item-2',
        sourceAttachmentId: 'source-attachment-2',
        fileName: 'second.txt',
        size: 7,
        digest: 'd'.repeat(64)
      }
    ]
  }
}

function syncedJournal(): NativeAttachmentRestoreJournal {
  let journal = createNativeAttachmentRestoreJournal(plan())
  journal = bindNativeAttachmentRestoreRemoteItem(journal, 'source-item-1', FIRST_REMOTE_ID, T1)
  return bindNativeAttachmentRestoreRemoteItem(journal, 'source-item-2', SECOND_REMOTE_ID, T2)
}

describe('native attachment restore journal', () => {
  it('creates a versioned serializable journal without archive capabilities or plaintext', () => {
    const journal = createNativeAttachmentRestoreJournal(plan())
    expect(journal).toMatchObject({
      version: 1,
      archiveFingerprint: ARCHIVE_FINGERPRINT,
      accountFingerprint: ACCOUNT_FINGERPRINT,
      phase: 'syncing-items',
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
      items: [
        { sourceItemId: 'source-item-1', localItemId: FIRST_LOCAL_ID, remoteItemId: null },
        { sourceItemId: 'source-item-2', localItemId: SECOND_LOCAL_ID, remoteItemId: null }
      ],
      attachments: [
        { status: 'pending', remoteAttachmentId: null },
        { status: 'pending', remoteAttachmentId: null }
      ]
    })
    expect(Object.isFrozen(journal)).toBe(true)
    expect(Object.isFrozen(journal.items)).toBe(true)
    expect(Object.isFrozen(journal.attachments[0])).toBe(true)

    const serialized = serializeNativeAttachmentRestoreJournal(journal)
    expect(serialized).not.toMatch(/path|password|vaultJson|key/i)
    expect(parseNativeAttachmentRestoreJournalJson(serialized)).toEqual(journal)
  })

  it('binds each imported item once and exposes only the first safe pending attachment', () => {
    let journal = createNativeAttachmentRestoreJournal(plan())
    expect(nextNativeAttachmentRestoreAttachment(journal)).toBeNull()
    journal = bindNativeAttachmentRestoreRemoteItem(journal, 'source-item-1', FIRST_REMOTE_ID, T1)
    expect(journal.phase).toBe('syncing-items')
    journal = bindNativeAttachmentRestoreRemoteItem(journal, 'source-item-2', SECOND_REMOTE_ID, T2)
    expect(journal.phase).toBe('restoring-attachments')
    expect(nextNativeAttachmentRestoreAttachment(journal)).toMatchObject({
      sourceAttachmentId: 'source-attachment-1',
      localItemId: FIRST_LOCAL_ID,
      status: 'pending'
    })
    expect(
      assertNativeAttachmentRestoreBinding(journal, ARCHIVE_FINGERPRINT, ACCOUNT_FINGERPRINT)
    ).toEqual(journal)
  })

  it('allows only pending-attempting-uploaded transitions and completes monotonically', () => {
    let journal = syncedJournal()
    journal = beginNativeAttachmentRestoreAttempt(
      journal,
      { sourceItemId: 'source-item-1', sourceAttachmentId: 'source-attachment-1' },
      T3
    )
    expect(journal.attachments[0]!.status).toBe('attempting')
    journal = completeNativeAttachmentRestoreAttempt(
      journal,
      { sourceItemId: 'source-item-1', sourceAttachmentId: 'source-attachment-1' },
      'remote-attachment-1',
      T3
    )
    expect(journal.phase).toBe('restoring-attachments')
    journal = beginNativeAttachmentRestoreAttempt(
      journal,
      { sourceItemId: 'source-item-2', sourceAttachmentId: 'source-attachment-2' },
      T4
    )
    journal = completeNativeAttachmentRestoreAttempt(
      journal,
      { sourceItemId: 'source-item-2', sourceAttachmentId: 'source-attachment-2' },
      'remote-attachment-2',
      T4
    )
    expect(journal.phase).toBe('complete')
    expect(nextNativeAttachmentRestoreAttachment(journal)).toBeNull()
  })

  it('turns a crash-interrupted attempt into reconciliation instead of retrying it', () => {
    let journal = beginNativeAttachmentRestoreAttempt(
      syncedJournal(),
      { sourceItemId: 'source-item-1', sourceAttachmentId: 'source-attachment-1' },
      T3
    )
    journal = recoverInterruptedNativeAttachmentRestore(journal, T4)
    expect(journal).toMatchObject({
      phase: 'needs-reconciliation',
      attachments: [{ status: 'needs-reconciliation', remoteAttachmentId: null }, {}]
    })
    expect(nextNativeAttachmentRestoreAttachment(journal)).toBeNull()

    journal = reconcileNativeAttachmentRestoreMissing(
      journal,
      { sourceItemId: 'source-item-1', sourceAttachmentId: 'source-attachment-1' },
      T4
    )
    expect(journal.phase).toBe('restoring-attachments')
    expect(journal.attachments[0]!.status).toBe('pending')
  })

  it('records a known ambiguous remote attachment and accepts only the same reconciled id', () => {
    const key = { sourceItemId: 'source-item-1', sourceAttachmentId: 'source-attachment-1' }
    let journal = beginNativeAttachmentRestoreAttempt(syncedJournal(), key, T3)
    journal = failNativeAttachmentRestoreAttempt(journal, key, 'candidate-attachment', T4)
    expect(journal).toMatchObject({
      phase: 'needs-reconciliation',
      attachments: [
        { status: 'needs-reconciliation', remoteAttachmentId: 'candidate-attachment' },
        {}
      ]
    })
    expect(() =>
      reconcileNativeAttachmentRestoreUploaded(journal, key, 'different-attachment', T4)
    ).toThrowError(/INVALID_INPUT/)
    journal = reconcileNativeAttachmentRestoreUploaded(journal, key, 'candidate-attachment', T4)
    expect(journal.attachments[0]).toMatchObject({
      status: 'uploaded',
      remoteAttachmentId: 'candidate-attachment'
    })
    expect(journal.phase).toBe('restoring-attachments')
  })

  it('rejects skipped, repeated, conflicting, and time-regressing transitions', () => {
    const initial = createNativeAttachmentRestoreJournal(plan())
    const firstKey = {
      sourceItemId: 'source-item-1',
      sourceAttachmentId: 'source-attachment-1'
    }
    const secondKey = {
      sourceItemId: 'source-item-2',
      sourceAttachmentId: 'source-attachment-2'
    }
    expect(() => beginNativeAttachmentRestoreAttempt(initial, firstKey, T1)).toThrowError(
      /INVALID_INPUT/
    )
    expect(() =>
      bindNativeAttachmentRestoreRemoteItem(
        initial,
        'source-item-1',
        FIRST_REMOTE_ID,
        '2025-01-01T00:00:00.000Z'
      )
    ).toThrowError(/INVALID_INPUT/)

    const synced = syncedJournal()
    expect(() => beginNativeAttachmentRestoreAttempt(synced, secondKey, T3)).toThrowError(
      /INVALID_INPUT/
    )
    expect(() =>
      completeNativeAttachmentRestoreAttempt(synced, firstKey, 'remote', T3)
    ).toThrowError(/INVALID_INPUT/)
    const attempting = beginNativeAttachmentRestoreAttempt(synced, firstKey, T3)
    expect(() => beginNativeAttachmentRestoreAttempt(attempting, firstKey, T3)).toThrowError(
      /INVALID_INPUT/
    )
    expect(() =>
      assertNativeAttachmentRestoreBinding(attempting, 'e'.repeat(64), ACCOUNT_FINGERPRINT)
    ).toThrowError(/INVALID_INPUT/)
  })

  it('rejects malformed invariants, forbidden fields, and prototype-bearing input', () => {
    const valid = JSON.parse(
      serializeNativeAttachmentRestoreJournal(createNativeAttachmentRestoreJournal(plan()))
    ) as Record<string, unknown>
    for (const field of ['path', 'password', 'key', 'vaultJson']) {
      expect(() =>
        parseNativeAttachmentRestoreJournal({ ...valid, [field]: 'secret' })
      ).toThrowError(/INVALID_INPUT/)
    }
    expect(() => parseNativeAttachmentRestoreJournal({ ...valid, version: 2 })).toThrowError(
      /INVALID_INPUT/
    )
    expect(() => parseNativeAttachmentRestoreJournal({ ...valid, phase: 'complete' })).toThrowError(
      /INVALID_INPUT/
    )
    expect(() =>
      parseNativeAttachmentRestoreJournalJson(
        serializeNativeAttachmentRestoreJournal(
          createNativeAttachmentRestoreJournal(plan())
        ).replace(/"version":1/, '"version":1,"__proto__":{"polluted":true}')
      )
    ).toThrowError(/INVALID_INPUT/)

    const inherited = Object.assign(Object.create({ version: 1 }), valid)
    expect(() => parseNativeAttachmentRestoreJournal(inherited)).toThrowError(/INVALID_INPUT/)
    const symbolBearing = { ...valid }
    Object.defineProperty(symbolBearing, Symbol('secret'), { enumerable: false, value: 'secret' })
    expect(() => parseNativeAttachmentRestoreJournal(symbolBearing)).toThrowError(/INVALID_INPUT/)
    const explosive = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('hostile proxy')
        }
      }
    )
    expect(() => parseNativeAttachmentRestoreJournal(explosive)).toThrowError(/INVALID_INPUT/)
    const pollutedPlan = Object.assign(Object.create({ password: 'secret' }), plan())
    expect(() => createNativeAttachmentRestoreJournal(pollutedPlan)).toThrowError(/INVALID_INPUT/)

    const attempting = beginNativeAttachmentRestoreAttempt(
      syncedJournal(),
      { sourceItemId: 'source-item-1', sourceAttachmentId: 'source-attachment-1' },
      T3
    )
    const mixed = JSON.parse(serializeNativeAttachmentRestoreJournal(attempting)) as {
      phase: string
      attachments: Array<{ status: string }>
    }
    mixed.phase = 'needs-reconciliation'
    mixed.attachments[1]!.status = 'needs-reconciliation'
    expect(() => parseNativeAttachmentRestoreJournal(mixed)).toThrowError(/INVALID_INPUT/)
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined()
  })

  it('enforces identity, filename, digest, size, count, and duplicate bounds', () => {
    const base = plan()
    const invalidPlans: NativeAttachmentRestorePlan[] = [
      { ...base, archiveFingerprint: 'A'.repeat(64) },
      { ...base, items: [{ sourceItemId: '', localItemId: FIRST_LOCAL_ID }] },
      {
        ...base,
        items: [
          { sourceItemId: 'duplicate', localItemId: FIRST_LOCAL_ID },
          { sourceItemId: 'duplicate', localItemId: SECOND_LOCAL_ID }
        ],
        attachments: []
      },
      {
        ...base,
        attachments: [{ ...base.attachments[0]!, fileName: 'bad\0name' }]
      },
      {
        ...base,
        attachments: [{ ...base.attachments[0]!, fileName: `bad${String.fromCharCode(0xd800)}` }]
      },
      {
        ...base,
        attachments: [{ ...base.attachments[0]!, size: 500 * 1024 * 1024 + 1 }]
      },
      {
        ...base,
        attachments: [{ ...base.attachments[0]!, digest: 'not-a-digest' }]
      },
      {
        ...base,
        attachments: [
          base.attachments[0]!,
          { ...base.attachments[0]!, sourceAttachmentId: 'other' }
        ]
      }
    ]
    for (const invalidPlan of invalidPlans) {
      expect(() => createNativeAttachmentRestoreJournal(invalidPlan)).toThrowError(/INVALID_INPUT/)
    }
    expect(() =>
      createNativeAttachmentRestoreJournal({ ...base, items: Array(40_001).fill(base.items[0]) })
    ).toThrowError(/INVALID_INPUT/)
    expect(() =>
      createNativeAttachmentRestoreJournal({
        ...base,
        attachments: Array(100_001).fill(base.attachments[0])
      })
    ).toThrowError(/INVALID_INPUT/)
  })
})
