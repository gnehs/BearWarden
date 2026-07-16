import { describe, expect, it } from 'vitest'
import {
  completeSyncMetadata,
  fingerprintLogin,
  legacyCustomFieldBaselineUpgrades,
  legacyLoginFingerprint,
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
    uris: [{ uri: 'https://example.invalid', match: null }],
    notes: null,
    folderId,
    favorite: false,
    lastUsedAt: null,
    deletedAt: null,
    archivedAt: null,
    reprompt: 0,
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
    passkeys: [],
    customFields: [],
    passwordHistory: []
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
    expect(
      fingerprintLogin({
        ...local,
        passwordHistory: [{ password: 'old-secret', lastUsedDate: '2026-07-14T00:00:00.000Z' }]
      })
    ).not.toBe(baseFingerprint)
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

  it('plans soft-delete and restore transitions as linked updates', () => {
    const base = login('local-1')
    const remote = login('remote-1')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: base.id, remoteId: remote.id, baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const localDeleted = {
      ...base,
      deletedAt: '2026-07-14T01:00:00.000Z',
      password: 'changed-before-delete'
    }
    expect(fingerprintLogin(localDeleted)).not.toBe(fingerprintLogin(base))
    expect(planSync(snapshot([localDeleted]), snapshot([remote]), metadata).actions).toMatchObject([
      {
        kind: 'push-update',
        entity: 'login',
        local: { deletedAt: localDeleted.deletedAt },
        remote: { deletedAt: null },
        contentChanged: true
      }
    ])

    const remoteDeleted = {
      ...remote,
      deletedAt: '2026-07-14T02:00:00.000Z'
    }
    expect(planSync(snapshot([base]), snapshot([remoteDeleted]), metadata).actions).toMatchObject([
      {
        kind: 'pull-update',
        entity: 'login',
        remote: { deletedAt: remoteDeleted.deletedAt }
      }
    ])
  })

  it('treats archive timestamps as a boolean state and plans archive transitions as updates', () => {
    const base = login('local-1')
    const remote = login('remote-1')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: base.id, remoteId: remote.id, baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const archived = { ...base, archivedAt: '2026-07-14T01:00:00.000Z' }
    const remotelyArchivedLater = {
      ...remote,
      archivedAt: '2026-07-14T02:00:00.000Z'
    }

    expect(fingerprintLogin(archived)).not.toBe(fingerprintLogin(base))
    expect(fingerprintLogin(archived)).toBe(fingerprintLogin(remotelyArchivedLater))
    expect(planSync(snapshot([archived]), snapshot([remote]), metadata).actions).toMatchObject([
      {
        kind: 'push-update',
        entity: 'login',
        local: { archivedAt: archived.archivedAt },
        remote: { archivedAt: null },
        contentChanged: false
      }
    ])
    expect(
      planSync(snapshot([base]), snapshot([remotelyArchivedLater]), metadata).actions
    ).toMatchObject([
      {
        kind: 'pull-update',
        entity: 'login',
        remote: { archivedAt: remotelyArchivedLater.archivedAt }
      }
    ])
  })

  it('fingerprints and synchronizes master-password reprompt metadata', () => {
    const local = login('local-1')
    const remote = login('remote-1')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: local.id, remoteId: remote.id, baseFingerprint: fingerprintLogin(local) }
      ]
    }
    const protectedLocal = { ...local, reprompt: 1 as const }

    expect(fingerprintLogin(protectedLocal)).not.toBe(fingerprintLogin(local))
    expect(
      planSync(snapshot([protectedLocal]), snapshot([remote]), metadata).actions
    ).toMatchObject([
      {
        kind: 'push-update',
        entity: 'login',
        local: { reprompt: 1 },
        remote: { reprompt: 0 },
        contentChanged: true
      }
    ])
  })

  it('creates a conflict copy when a local soft-delete races a remote content edit', () => {
    const base = login('local-1')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: base.id, remoteId: 'remote-1', baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const plan = planSync(
      snapshot([{ ...base, deletedAt: '2026-07-14T01:00:00.000Z' }]),
      snapshot([login('remote-1', 'Remote edit')]),
      metadata
    )

    expect(plan.actions).toMatchObject([
      {
        kind: 'conflict-copy',
        entity: 'login',
        reason: 'both-modified',
        local: { deletedAt: '2026-07-14T01:00:00.000Z' },
        remote: { name: 'Remote edit', deletedAt: null }
      }
    ])
  })

  it('does not resurrect a soft-deleted item after either side permanently deletes it', () => {
    const base = login('local-1')
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: base.id, remoteId: 'remote-1', baseFingerprint: fingerprintLogin(base) }
      ]
    }
    const localSoftDeleted = {
      ...base,
      deletedAt: '2026-07-14T01:00:00.000Z'
    }
    expect(planSync(snapshot([localSoftDeleted]), snapshot(), metadata).actions).toMatchObject([
      { kind: 'delete-local', entity: 'login', localId: base.id }
    ])

    const remoteSoftDeleted = {
      ...login('remote-1'),
      deletedAt: '2026-07-14T02:00:00.000Z'
    }
    expect(
      planSync(
        snapshot([], [], {
          folders: [],
          logins: [{ id: base.id, deletedAt: '2026-07-14T03:00:00.000Z' }]
        }),
        snapshot([remoteSoftDeleted]),
        metadata
      ).actions
    ).toMatchObject([{ kind: 'delete-remote', entity: 'login', remoteId: 'remote-1' }])
  })

  it('does not upload an item deleted before its first successful sync', () => {
    const localDeleted = {
      ...login('local-1'),
      deletedAt: '2026-07-14T01:00:00.000Z'
    }

    expect(planSync(snapshot([localDeleted]), snapshot()).actions).toEqual([])
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
    expect(fingerprintLogin({ ...base, uri: 'compatibility-alias-only' })).toBe(baseFingerprint)
    expect(
      fingerprintLogin({
        ...base,
        uri: 'https://secondary.example.invalid',
        uris: [
          { uri: 'https://secondary.example.invalid', match: null },
          { uri: 'https://example.invalid', match: 3 }
        ]
      })
    ).not.toBe(baseFingerprint)
  })

  it('detects a change made only to custom fields in fingerprints and plans', () => {
    const base = login('local-1')
    const legacyBase: Partial<SyncLogin> = { ...base }
    delete legacyBase.customFields
    const remote = { ...base, id: 'remote-1' }
    const changedCustomFields = [
      { name: 'environment', value: 'production', type: 'text' as const, linkedId: null }
    ]
    const changed = { ...base, customFields: changedCustomFields }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        { localId: base.id, remoteId: remote.id, baseFingerprint: fingerprintLogin(base) }
      ]
    }

    expect(fingerprintLogin(legacyBase as SyncLogin)).toBe(fingerprintLogin(base))
    expect(fingerprintLogin(changed)).not.toBe(fingerprintLogin(base))
    expect(planSync(snapshot([changed]), snapshot([remote]), metadata).actions).toMatchObject([
      {
        kind: 'push-update',
        entity: 'login',
        remoteId: remote.id,
        local: { customFields: changedCustomFields }
      }
    ])
  })

  it('adopts remotely untracked custom fields before planning an offline local edit', () => {
    const original = login('local-1')
    const local = { ...original, name: 'Locally renamed' }
    const remote = {
      ...original,
      id: 'remote-1',
      customFields: [
        { name: 'member-id', value: 'remote-42', type: 'text' as const, linkedId: null }
      ],
      passwordHistory: [{ password: 'remote-old', lastUsedDate: '2026-07-13T00:00:00.000Z' }]
    }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: local.id,
          remoteId: remote.id,
          baseFingerprint: fingerprintLogin(original)
        }
      ]
    }

    const [upgrade] = legacyCustomFieldBaselineUpgrades(
      snapshot([local]),
      snapshot([remote]),
      metadata
    )
    expect(upgrade).toMatchObject({
      localId: local.id,
      remoteId: remote.id,
      customFields: remote.customFields,
      passwordHistory: remote.passwordHistory,
      baseFingerprint: fingerprintLogin(remote)
    })
    const upgradedLocal = {
      ...local,
      customFields: upgrade!.customFields,
      passwordHistory: upgrade!.passwordHistory!
    }
    const upgradedMetadata: SyncMetadata = {
      ...metadata,
      loginLinks: [{ ...metadata.loginLinks[0]!, baseFingerprint: upgrade!.baseFingerprint }]
    }
    expect(
      planSync(snapshot([upgradedLocal]), snapshot([remote]), upgradedMetadata).actions
    ).toMatchObject([
      { kind: 'push-update', entity: 'login', local: { customFields: remote.customFields } }
    ])
  })

  it('pulls, pushes, and conflicts on password-history changes', () => {
    const original = login('local-1')
    const remoteBase = { ...original, id: 'remote-1' }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: original.id,
          remoteId: remoteBase.id,
          baseFingerprint: fingerprintLogin(original)
        }
      ]
    }
    const history = [{ password: 'old-secret', lastUsedDate: '2026-07-13T00:00:00.000Z' }]
    expect(
      planSync(
        snapshot([{ ...original, passwordHistory: history }]),
        snapshot([remoteBase]),
        metadata
      ).actions
    ).toMatchObject([{ kind: 'push-update', entity: 'login' }])
    expect(
      planSync(
        snapshot([original]),
        snapshot([{ ...remoteBase, passwordHistory: history }]),
        metadata
      ).actions
    ).toMatchObject([{ kind: 'pull-update', entity: 'login' }])

    const local = {
      ...original,
      passwordHistory: [{ password: 'local-old', lastUsedDate: '2026-07-13T00:00:00.000Z' }]
    }
    const remote = {
      ...remoteBase,
      passwordHistory: [{ password: 'remote-old', lastUsedDate: '2026-07-13T00:00:00.000Z' }]
    }
    expect(
      legacyCustomFieldBaselineUpgrades(snapshot([local]), snapshot([remote]), metadata)
    ).toEqual([])
    expect(planSync(snapshot([local]), snapshot([remote]), metadata).actions).toMatchObject([
      { kind: 'conflict-copy', entity: 'login', reason: 'both-modified' }
    ])
  })

  it('preserves an offline password edit when another device adds a passkey', () => {
    const original = login('local-1')
    const remoteBase = { ...original, id: 'remote-1' }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: original.id,
          remoteId: remoteBase.id,
          baseFingerprint: fingerprintLogin(original)
        }
      ]
    }
    const local = { ...original, password: 'offline-password-edit' }
    const remotePasskey = {
      credentialId: 'remote-device-credential',
      keyType: 'public-key',
      keyAlgorithm: 'ECDSA',
      keyCurve: 'P-256',
      keyValue: 'remote-device-private-material',
      rpId: 'example.invalid',
      userHandle: 'remote-user-handle',
      userName: 'bear@example.invalid',
      counter: '0',
      rpName: 'Example',
      userDisplayName: 'Bear',
      discoverable: true,
      creationDate: '2026-07-14T01:00:00.000Z'
    }
    const remote = { ...remoteBase, passkeys: [remotePasskey] }

    const plan = planSync(snapshot([local]), snapshot([remote]), metadata)

    expect(plan.actions).toMatchObject([
      {
        kind: 'conflict-copy',
        entity: 'login',
        reason: 'both-modified',
        resolution: 'remote-primary-local-copy',
        local: { password: 'offline-password-edit', passkeys: [] },
        remote: { password: 'secret', passkeys: [remotePasskey] }
      }
    ])
    expect(plan.nextMetadata.loginLinks).toMatchObject([
      { localId: original.id, remoteId: remote.id, baseFingerprint: fingerprintLogin(remote) }
    ])
  })

  it('keeps both independently-created passkeys when two offline devices edit one login', () => {
    const original = login('local-1')
    const remoteBase = { ...original, id: 'remote-1' }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: original.id,
          remoteId: remoteBase.id,
          baseFingerprint: fingerprintLogin(original)
        }
      ]
    }
    const passkey = (device: 'local' | 'remote'): SyncLogin['passkeys'][number] => ({
      credentialId: `${device}-device-credential`,
      keyType: 'public-key',
      keyAlgorithm: 'ECDSA',
      keyCurve: 'P-256',
      keyValue: `${device}-device-private-material`,
      rpId: 'example.invalid',
      userHandle: `${device}-user-handle`,
      userName: 'bear@example.invalid',
      counter: '0',
      rpName: 'Example',
      userDisplayName: 'Bear',
      discoverable: true,
      creationDate: device === 'local' ? '2026-07-14T01:00:00.000Z' : '2026-07-14T02:00:00.000Z'
    })
    const local = { ...original, passkeys: [passkey('local')] }
    const remote = { ...remoteBase, passkeys: [passkey('remote')] }

    const [action] = planSync(snapshot([local]), snapshot([remote]), metadata).actions

    expect(action).toMatchObject({
      kind: 'conflict-copy',
      entity: 'login',
      reason: 'both-modified',
      local: { passkeys: [expect.objectContaining({ credentialId: 'local-device-credential' })] },
      remote: { passkeys: [expect.objectContaining({ credentialId: 'remote-device-credential' })] }
    })
    expect(JSON.stringify(action)).toContain('local-device-private-material')
    expect(JSON.stringify(action)).toContain('remote-device-private-material')
  })

  it('ignores server revision timestamps but tracks passkey credential mutations', () => {
    const original = login('local-1')
    const passkey = {
      credentialId: 'credential-id',
      keyType: 'public-key',
      keyAlgorithm: 'ECDSA',
      keyCurve: 'P-256',
      keyValue: 'private-material',
      rpId: 'example.invalid',
      userHandle: null,
      userName: 'bear@example.invalid',
      counter: '0',
      rpName: 'Example',
      userDisplayName: 'Bear',
      discoverable: true,
      creationDate: '2026-07-14T01:00:00.000Z'
    }
    const withPasskey = { ...original, passkeys: [passkey] }

    expect(
      fingerprintLogin({
        ...withPasskey,
        updatedAt: '2099-01-01T00:00:00.000Z'
      })
    ).toBe(fingerprintLogin(withPasskey))
    expect(
      fingerprintLogin({
        ...withPasskey,
        passkeys: [{ ...passkey, credentialId: 'replacement-credential-id' }]
      })
    ).not.toBe(fingerprintLogin(withPasskey))
  })

  it('adopts V12 history when both sides already share tracked custom fields', () => {
    const customFields = [{ name: 'tracked', value: 'same', type: 'text' as const, linkedId: null }]
    const original = { ...login('local-1'), customFields }
    const local = { ...original, name: 'Offline rename' }
    const remote = {
      ...original,
      id: 'remote-1',
      passwordHistory: [{ password: 'remote-old', lastUsedDate: '2026-07-13T00:00:00.000Z' }]
    }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: local.id,
          remoteId: remote.id,
          baseFingerprint: fingerprintLogin(original)
        }
      ]
    }
    expect(
      legacyCustomFieldBaselineUpgrades(snapshot([local]), snapshot([remote]), metadata)
    ).toMatchObject([
      {
        customFields,
        passwordHistory: remote.passwordHistory,
        baseFingerprint: fingerprintLogin(remote)
      }
    ])
  })

  it('upgrades a V10 URI baseline before pushing local URI and reprompt edits', () => {
    const original = login('local-1')
    const local = {
      ...original,
      uri: 'https://local.invalid',
      uris: [{ uri: 'https://local.invalid', match: 2 as const }],
      reprompt: 1 as const
    }
    const remote = { ...original, id: 'remote-1' }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: local.id,
          remoteId: remote.id,
          baseFingerprint: legacyLoginFingerprint(original)
        }
      ]
    }

    const [upgrade] = legacyCustomFieldBaselineUpgrades(
      snapshot([local]),
      snapshot([remote]),
      metadata
    )
    expect(upgrade).toMatchObject({
      localId: local.id,
      remoteId: remote.id,
      baseFingerprint: fingerprintLogin(remote)
    })
    expect(upgrade).not.toHaveProperty('uris')
    expect(upgrade).not.toHaveProperty('reprompt')
    expect(
      planSync(snapshot([local]), snapshot([remote]), {
        ...metadata,
        loginLinks: [{ ...metadata.loginLinks[0]!, baseFingerprint: upgrade!.baseFingerprint }]
      }).actions
    ).toMatchObject([{ kind: 'push-update', entity: 'login', remoteId: remote.id }])
  })

  it('upgrades a V10 baseline for remote-only primary URI and default-field adoption', () => {
    const original = login('local-1')
    const metadata = (remoteId: string): SyncMetadata => ({
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: original.id,
          remoteId,
          baseFingerprint: legacyLoginFingerprint(original)
        }
      ]
    })
    const remotePrimary = {
      ...original,
      id: 'remote-primary',
      uri: 'https://remote.invalid',
      uris: [{ uri: 'https://remote.invalid', match: null }]
    }
    const [primaryUpgrade] = legacyCustomFieldBaselineUpgrades(
      snapshot([original]),
      snapshot([remotePrimary]),
      metadata(remotePrimary.id)
    )
    expect(primaryUpgrade?.baseFingerprint).toBe(fingerprintLogin(original))
    expect(
      planSync(snapshot([original]), snapshot([remotePrimary]), {
        ...metadata(remotePrimary.id),
        loginLinks: [
          {
            ...metadata(remotePrimary.id).loginLinks[0]!,
            baseFingerprint: primaryUpgrade!.baseFingerprint
          }
        ]
      }).actions
    ).toMatchObject([{ kind: 'pull-update', entity: 'login', remote: remotePrimary }])

    const remoteDefaults = {
      ...original,
      id: 'remote-defaults',
      uris: [...original.uris, { uri: 'https://second.invalid', match: 3 as const }],
      reprompt: 1 as const
    }
    const [defaultUpgrade] = legacyCustomFieldBaselineUpgrades(
      snapshot([original]),
      snapshot([remoteDefaults]),
      metadata(remoteDefaults.id)
    )
    expect(defaultUpgrade).toMatchObject({
      uris: remoteDefaults.uris,
      reprompt: 1,
      baseFingerprint: fingerprintLogin(remoteDefaults)
    })
  })

  it('keeps a V10 baseline when both sides added different URI state', () => {
    const original = login('local-1')
    const local = {
      ...original,
      uris: [...original.uris, { uri: 'https://local-extra.invalid', match: 1 as const }],
      reprompt: 1 as const
    }
    const remote = {
      ...original,
      id: 'remote-1',
      uris: [...original.uris, { uri: 'https://remote-extra.invalid', match: 4 as const }],
      reprompt: 1 as const
    }
    const metadata: SyncMetadata = {
      version: 1,
      folderLinks: [],
      loginLinks: [
        {
          localId: local.id,
          remoteId: remote.id,
          baseFingerprint: legacyLoginFingerprint(original)
        }
      ]
    }

    expect(
      legacyCustomFieldBaselineUpgrades(snapshot([local]), snapshot([remote]), metadata)
    ).toEqual([])
    expect(planSync(snapshot([local]), snapshot([remote]), metadata).actions).toMatchObject([
      {
        kind: 'conflict-copy',
        entity: 'login',
        reason: 'both-modified',
        local: { uris: local.uris },
        remote: { uris: remote.uris }
      }
    ])
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
