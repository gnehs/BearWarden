import { describe, expect, it } from 'vitest'
import {
  completeSyncMetadata,
  fingerprintLogin,
  planSync,
  type SyncFolder,
  type SyncLogin,
  type SyncMetadata,
  type SyncSnapshot
} from './sync-merge'

function login(
  id: string,
  name = 'Example',
  password = 'secret',
  folderId: string | null = null
): SyncLogin {
  return {
    type: 'login',
    id,
    name,
    username: 'bear@example.invalid',
    password,
    totp: '',
    uri: 'https://example.invalid',
    notes: null,
    folderId,
    favorite: false,
    lastUsedAt: null,
    cardholderName: '',
    brand: '',
    number: '',
    expMonth: '',
    expYear: '',
    code: '',
    title: '',
    firstName: '',
    middleName: '',
    lastName: '',
    address1: '',
    address2: '',
    address3: '',
    city: '',
    state: '',
    postalCode: '',
    country: '',
    company: '',
    email: '',
    phone: '',
    ssn: '',
    identityUsername: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    publicKey: '',
    fingerprint: '',
    passkeys: []
  }
}

function snapshot(
  logins: SyncLogin[] = [],
  folders: SyncFolder[] = [],
  tombstones: SyncSnapshot['tombstones'] = { folders: [], logins: [] }
): SyncSnapshot {
  return { folders, logins, tombstones }
}

describe('planSync', () => {
  it('is idempotent for linked unchanged content and ignores lastUsedAt', () => {
    const local = { ...login('local-1'), lastUsedAt: '2026-07-14T00:00:00.000Z' }
    const remote = { ...login('remote-1'), lastUsedAt: null }
    const baseFingerprint = fingerprintLogin(local)
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [{ localId: local.id, remoteId: remote.id, baseFingerprint }]
    }
    const plan = planSync(snapshot([local]), snapshot([remote]), metadata)
    expect(plan.actions).toEqual([])
    expect(plan.nextMetadata.loginLinks).toEqual(metadata.loginLinks)
  })

  it('plans local-only pushes, remote-only pulls, and completes create links', () => {
    const localOnly = planSync(snapshot([login('local-1')]), snapshot())
    expect(localOnly.actions).toMatchObject([
      { kind: 'push-create', entity: 'login', pendingKey: 'login:push-create:local-1' }
    ])
    expect(
      completeSyncMetadata(localOnly, [
        { actionId: 'login:push-create:local-1', remoteId: 'remote-created' }
      ]).loginLinks
    ).toMatchObject([{ localId: 'local-1', remoteId: 'remote-created' }])

    const remoteOnly = planSync(snapshot(), snapshot([login('remote-1')]))
    expect(remoteOnly.actions).toMatchObject([
      { kind: 'pull-create', entity: 'login', pendingKey: 'login:pull-create:remote-1' }
    ])
    expect(
      completeSyncMetadata(remoteOnly, [
        { actionId: 'login:pull-create:remote-1', localId: 'local-created' }
      ]).loginLinks
    ).toMatchObject([{ localId: 'local-created', remoteId: 'remote-1' }])
  })

  it('deduplicates only unique equal content on first sync', () => {
    const unique = planSync(snapshot([login('local-1')]), snapshot([login('remote-1')]))
    expect(unique.actions).toEqual([])
    expect(unique.nextMetadata.loginLinks).toHaveLength(1)

    const duplicates = planSync(
      snapshot([login('local-1'), login('local-2')]),
      snapshot([login('remote-1')])
    )
    expect(duplicates.actions.filter((action) => action.entity === 'login')).toHaveLength(3)
    expect(duplicates.nextMetadata.loginLinks).toEqual([])
  })

  it('propagates local and remote deletions using tombstones and base fingerprints', () => {
    const original = login('local-1')
    const baseFingerprint = fingerprintLogin(original)
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [{ localId: 'local-1', remoteId: 'remote-1', baseFingerprint }]
    }
    const localDelete = planSync(
      snapshot([], [], {
        folders: [],
        logins: [{ id: 'local-1', deletedAt: '2026-07-14T00:00:00.000Z' }]
      }),
      snapshot([login('remote-1')]),
      metadata
    )
    expect(localDelete.actions).toMatchObject([
      { kind: 'delete-remote', entity: 'login', remoteId: 'remote-1' }
    ])
    expect(completeSyncMetadata(localDelete, []).loginLinks).toEqual([])

    const remoteDelete = planSync(snapshot([original]), snapshot(), metadata)
    expect(remoteDelete.actions).toMatchObject([
      { kind: 'delete-local', entity: 'login', localId: 'local-1' }
    ])
    expect(completeSyncMetadata(remoteDelete, []).loginLinks).toEqual([])
  })

  it('preserves a remote modification after a local delete as a linked conflict copy', () => {
    const base = login('local-1')
    const remoteEdit = login('remote-1', 'Remote edit', 'remote-secret')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: 'local-1', remoteId: 'remote-1', baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const firstPlan = planSync(
      snapshot([], [], {
        folders: [],
        logins: [{ id: 'local-1', deletedAt: '2026-07-14T00:00:00.000Z' }]
      }),
      snapshot([remoteEdit]),
      metadata
    )
    expect(firstPlan.actions).toMatchObject([
      {
        kind: 'conflict-copy',
        entity: 'login',
        reason: 'local-deleted',
        resolution: 'deleted-primary-linked-conflict-copy',
        pendingKey: 'login:conflict-local-deleted:remote-1'
      }
    ])
    const action = firstPlan.actions[0]!
    if (action.kind !== 'conflict-copy') throw new Error('Expected conflict action')
    const completed = completeSyncMetadata(firstPlan, [
      { actionId: action.actionId, localId: 'local-conflict' }
    ])
    expect(completed.loginLinks).toMatchObject([
      { localId: 'local-conflict', remoteId: 'remote-1' }
    ])

    const localConflict = { ...remoteEdit, id: 'local-conflict', name: action.conflictName }
    const remoteConflict = { ...remoteEdit, name: action.conflictName }
    const nextPlan = planSync(snapshot([localConflict]), snapshot([remoteConflict]), completed)
    expect(nextPlan.actions).toEqual([])
  })

  it('preserves a local modification after a remote delete as a linked conflict copy', () => {
    const base = login('local-1')
    const localEdit = login('local-1', 'Local edit', 'local-secret')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: 'local-1', remoteId: 'remote-1', baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const firstPlan = planSync(snapshot([localEdit]), snapshot(), metadata)
    expect(firstPlan.actions).toMatchObject([
      {
        kind: 'conflict-copy',
        entity: 'login',
        reason: 'remote-deleted',
        resolution: 'deleted-primary-linked-conflict-copy',
        pendingKey: 'login:conflict-remote-deleted:local-1'
      }
    ])
    const action = firstPlan.actions[0]!
    if (action.kind !== 'conflict-copy') throw new Error('Expected conflict action')
    const completed = completeSyncMetadata(firstPlan, [
      { actionId: action.actionId, remoteId: 'remote-conflict' }
    ])
    expect(completed.loginLinks).toMatchObject([
      { localId: 'local-1', remoteId: 'remote-conflict' }
    ])

    const localConflict = { ...localEdit, name: action.conflictName }
    const remoteConflict = { ...localEdit, id: 'remote-conflict', name: action.conflictName }
    const nextPlan = planSync(snapshot([localConflict]), snapshot([remoteConflict]), completed)
    expect(nextPlan.actions).toEqual([])
  })

  it('emits a no-data-loss conflict copy when both sides changed', () => {
    const base = login('base-id')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: 'local-1', remoteId: 'remote-1', baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const plan = planSync(
      snapshot([login('local-1', 'Local edit', 'local-secret')]),
      snapshot([login('remote-1', 'Remote edit', 'remote-secret')]),
      metadata
    )
    expect(plan.actions).toMatchObject([
      {
        kind: 'conflict-copy',
        entity: 'login',
        reason: 'both-modified',
        local: { password: 'local-secret' },
        remote: { password: 'remote-secret' }
      }
    ])
  })

  it('uses an executor-reported fingerprint when completing an update', () => {
    const base = login('local-1')
    const localEdit = login('local-1', 'Edited')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: 'local-1', remoteId: 'remote-1', baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const plan = planSync(snapshot([localEdit]), snapshot([login('remote-1')]), metadata)
    const update = plan.actions[0]!
    expect(update).toMatchObject({ kind: 'push-update', entity: 'login' })
    const completed = completeSyncMetadata(plan, [
      { actionId: update.actionId, fingerprint: 'executor-fingerprint' }
    ])
    expect(completed.loginLinks).toEqual([
      {
        localId: 'local-1',
        remoteId: 'remote-1',
        baseFingerprint: 'executor-fingerprint'
      }
    ])
  })

  it('orders folder creates before logins and exposes pending folder mappings', () => {
    const plan = planSync(
      snapshot(
        [login('local-login', 'Example', 'secret', 'local-folder')],
        [{ id: 'local-folder', name: 'Personal' }]
      ),
      snapshot()
    )
    expect(plan.actions).toMatchObject([
      {
        kind: 'push-create',
        entity: 'folder',
        pendingKey: 'folder:push-create:local-folder'
      },
      {
        kind: 'push-create',
        entity: 'login',
        remoteFolder: { id: null, pendingKey: 'folder:push-create:local-folder' }
      }
    ])
  })

  it('includes the item type and every persisted item field in content fingerprints', () => {
    const base = login('local-1')
    const baseFingerprint = fingerprintLogin(base)
    expect(fingerprintLogin({ ...base, type: 'card' })).not.toBe(baseFingerprint)

    const fields = [
      'username',
      'password',
      'uri',
      'cardholderName',
      'brand',
      'number',
      'expMonth',
      'expYear',
      'code',
      'title',
      'firstName',
      'middleName',
      'lastName',
      'address1',
      'address2',
      'address3',
      'city',
      'state',
      'postalCode',
      'country',
      'company',
      'email',
      'phone',
      'ssn',
      'identityUsername',
      'passportNumber',
      'licenseNumber',
      'privateKey',
      'publicKey',
      'fingerprint'
    ] as const
    for (const field of fields) {
      expect(fingerprintLogin({ ...base, [field]: `changed-${field}` })).not.toBe(baseFingerprint)
    }
  })

  it('never links otherwise-identical items whose types differ', () => {
    const local = login('local-1')
    const remote = { ...login('remote-1'), type: 'secureNote' as const }
    const plan = planSync(snapshot([local]), snapshot([remote]))
    expect(plan.actions).toMatchObject([
      { kind: 'push-create', entity: 'login', local: { id: 'local-1', type: 'login' } },
      { kind: 'pull-create', entity: 'login', remote: { id: 'remote-1', type: 'secureNote' } }
    ])
    expect(plan.nextMetadata.loginLinks).toEqual([])
  })
})
