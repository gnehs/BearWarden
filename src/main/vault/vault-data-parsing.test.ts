import { describe, expect, it } from 'vitest'
import { BITWARDEN_POLICY_TYPE, type BitwardenPolicySet } from '../bitwarden-policy'
import { VaultError } from '../vault-errors'
import { MAX_OAUTH_CLIENT_ID_BYTES, MAX_OPAQUE_AUTH_TOKEN_BYTES } from './limits'
import { cloneData, parseStoredBitwardenPolicySet, parseVaultData } from './vault-data-parsing'

const POLICY_ID = '11111111-1111-4111-8111-111111111111'
const ORGANIZATION_ID = '22222222-2222-4222-8222-222222222222'
const DEVICE_ID = '33333333-3333-4333-8333-333333333333'

function policySet(): BitwardenPolicySet {
  return {
    source: 'policiesNew',
    applicableOrganizationIds: [ORGANIZATION_ID],
    policies: [
      {
        id: POLICY_ID,
        organizationId: ORGANIZATION_ID,
        type: BITWARDEN_POLICY_TYPE.RestrictedItemTypes,
        typeName: 'RestrictedItemTypes',
        enabled: true,
        canToggleState: false,
        revisionDate: '2026-07-23T01:02:03.1234567Z',
        execution: 'actionable',
        data: { kind: 'restrictedItemTypes', cipherTypes: [3, 5] }
      }
    ]
  }
}

function vaultData(state: Record<string, unknown>): Record<string, unknown> {
  return {
    version: 23,
    createdAt: '2026-07-23T00:00:00.000Z',
    updatedAt: '2026-07-23T00:00:00.000Z',
    folders: [],
    logins: [],
    organizations: [],
    collections: [],
    sharedLogins: [],
    sends: [],
    generatorHistory: [],
    sync: {
      provider: 'bitwarden',
      serverUrl: 'https://vault.example.test',
      email: 'person@example.test',
      state: {
        session: null,
        deviceIdentifier: DEVICE_ID,
        profileId: null,
        securityStamp: null,
        ...state
      },
      lastSyncAt: null,
      folderMappings: [],
      loginMappings: [],
      folderTombstones: [],
      loginTombstones: [],
      pendingLoginMutation: null,
      pendingLoginImport: null,
      pendingPersonalVaultPurge: null,
      domainSettings: null
    },
    nativeAttachmentRestore: null,
    masterPasswordChange: null
  }
}

describe('stored Bitwarden policy parsing', () => {
  it('strictly reconstructs and independently clones the safe policy subset', () => {
    const input = policySet()
    const parsed = parseStoredBitwardenPolicySet(input)

    expect(parsed).toEqual(input)
    expect(parsed).not.toBe(input)
    expect(parsed.policies).not.toBe(input.policies)
    expect(parsed.policies[0]?.data).not.toBe(input.policies[0]?.data)
    expect(parsed.applicableOrganizationIds).not.toBe(input.applicableOrganizationIds)
  })

  it('accepts only the closed parse-failure marker and never retains arbitrary payloads', () => {
    expect(
      parseStoredBitwardenPolicySet({
        source: 'none',
        policies: [],
        parseFailure: 'invalid-response'
      })
    ).toEqual({ source: 'none', policies: [], parseFailure: 'invalid-response' })

    for (const value of [
      { ...policySet(), rawPayload: { secret: 'do-not-store' } },
      { source: 'none', policies: [], parseFailure: 'server-message' },
      {
        ...policySet(),
        policies: [{ ...policySet().policies[0], data: { arbitrary: 'do-not-store' } }]
      }
    ]) {
      expect(() => parseStoredBitwardenPolicySet(value)).toThrowError(VaultError)
    }
  })

  it('rejects inconsistent metadata and untrusted object mechanics', () => {
    const wrongName = policySet()
    wrongName.policies[0]!.typeName = 'DisableSend'
    expect(() => parseStoredBitwardenPolicySet(wrongName)).toThrowError(VaultError)

    const duplicateMembership = policySet()
    duplicateMembership.applicableOrganizationIds = [ORGANIZATION_ID, ORGANIZATION_ID]
    expect(() => parseStoredBitwardenPolicySet(duplicateMembership)).toThrowError(VaultError)

    const accessor = { source: 'none', policies: [] as unknown[] }
    Object.defineProperty(accessor, 'parseFailure', {
      enumerable: true,
      get: () => 'invalid-response'
    })
    expect(() => parseStoredBitwardenPolicySet(accessor)).toThrowError(VaultError)
  })

  it('migrates an older encrypted state without policySet to a safe empty snapshot', () => {
    const parsed = parseVaultData(vaultData({}))
    expect(parsed.sync?.state.policySet).toEqual({ source: 'none', policies: [] })
  })

  it('parses and clones policySet through encrypted vault data without sharing nested arrays', () => {
    const parsed = parseVaultData(vaultData({ policySet: policySet() }))
    const cloned = cloneData(parsed)

    expect(cloned.sync?.state.policySet).toEqual(policySet())
    expect(cloned.sync?.state.policySet).not.toBe(parsed.sync?.state.policySet)
    expect(cloned.sync?.state.policySet?.policies).not.toBe(parsed.sync?.state.policySet?.policies)
    expect(cloned.sync?.state.policySet?.applicableOrganizationIds).not.toBe(
      parsed.sync?.state.policySet?.applicableOrganizationIds
    )
  })
})

describe('stored sync unlock material parsing', () => {
  it('migrates missing material and accepts bounded canonical account keys', () => {
    expect(parseVaultData(vaultData({})).sync?.unlockMaterial).toBeNull()

    const input = vaultData({})
    const sync = input.sync as Record<string, unknown>
    sync.unlockMaterial = {
      accountKey: Buffer.alloc(64, 7).toString('base64'),
      wrappedKeyFingerprint: Buffer.alloc(32, 9).toString('base64')
    }
    expect(parseVaultData(input).sync?.unlockMaterial).toEqual(sync.unlockMaterial)
  })

  it('rejects malformed, oversized, and non-canonical unlock material', () => {
    for (const unlockMaterial of [
      { accountKey: 'not-base64', wrappedKeyFingerprint: Buffer.alloc(32).toString('base64') },
      {
        accountKey: Buffer.alloc(4_097).toString('base64'),
        wrappedKeyFingerprint: Buffer.alloc(32).toString('base64')
      },
      {
        accountKey: Buffer.alloc(64).toString('base64'),
        wrappedKeyFingerprint: Buffer.alloc(31).toString('base64')
      },
      {
        accountKey: Buffer.alloc(64).toString('base64'),
        wrappedKeyFingerprint: Buffer.alloc(32).toString('base64'),
        extra: 'rejected'
      }
    ]) {
      const input = vaultData({})
      ;(input.sync as Record<string, unknown>).unlockMaterial = unlockMaterial
      expect(() => parseVaultData(input)).toThrowError(VaultError)
    }
  })
})

describe('stored Bitwarden Direct state parsing', () => {
  it('roundtrips the canonical persisted session and remembered two-factor token', () => {
    const session = {
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresAt: 1_800_000_000_000,
      clientId: 'user.11111111-1111-4111-8111-111111111111'
    }
    const parsed = parseVaultData(
      vaultData({
        session,
        rememberedTwoFactorToken: 'remembered-device-token'
      })
    )

    expect(parsed.sync?.state).toMatchObject({
      session,
      rememberedTwoFactorToken: 'remembered-device-token',
      deviceIdentifier: DEVICE_ID,
      profileId: null,
      securityStamp: null
    })
  })

  it('canonicalizes a legacy session two-factor token without retaining a duplicate secret', () => {
    const input = vaultData({
      session: {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresAt: 1_800_000_000_000,
        clientId: 'desktop',
        twoFactorToken: 'legacy-remembered-token'
      }
    })
    const parsed = parseVaultData(input)

    expect(parsed.sync?.state.rememberedTwoFactorToken).toBe('legacy-remembered-token')
    expect(parsed.sync?.state.session).toEqual({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresAt: 1_800_000_000_000,
      clientId: 'desktop'
    })
    expect(parsed.sync?.state.session).not.toHaveProperty('twoFactorToken')
  })

  it('accepts the HTTP token and OAuth client ID boundaries', () => {
    const boundaryToken = 't'.repeat(MAX_OPAQUE_AUTH_TOKEN_BYTES)
    const boundaryClientId = `u${'x'.repeat(MAX_OAUTH_CLIENT_ID_BYTES - 1)}`
    const parsed = parseVaultData(
      vaultData({
        session: {
          accessToken: boundaryToken,
          refreshToken: boundaryToken,
          expiresAt: 1,
          clientId: boundaryClientId
        },
        rememberedTwoFactorToken: boundaryToken
      })
    )

    expect(parsed.sync?.state.session?.accessToken).toHaveLength(MAX_OPAQUE_AUTH_TOKEN_BYTES)
    expect(parsed.sync?.state.session?.refreshToken).toHaveLength(MAX_OPAQUE_AUTH_TOKEN_BYTES)
    expect(parsed.sync?.state.session?.clientId).toHaveLength(MAX_OAUTH_CLIENT_ID_BYTES)
    expect(parsed.sync?.state.rememberedTwoFactorToken).toHaveLength(MAX_OPAQUE_AUTH_TOKEN_BYTES)
  })

  it('rejects oversized, control-bearing, or malformed persisted authentication values', () => {
    const oversizedToken = 't'.repeat(MAX_OPAQUE_AUTH_TOKEN_BYTES + 1)
    const oversizedClientId = `u${'x'.repeat(MAX_OAUTH_CLIENT_ID_BYTES)}`
    const cases = [
      { session: { accessToken: oversizedToken, refreshToken: 'refresh', expiresAt: 1 } },
      { session: { accessToken: 'access', refreshToken: oversizedToken, expiresAt: 1 } },
      {
        session: {
          accessToken: 'access',
          refreshToken: 'refresh',
          expiresAt: 1,
          clientId: oversizedClientId
        }
      },
      {
        session: {
          accessToken: 'access',
          refreshToken: 'refresh',
          expiresAt: 1,
          clientId: 'invalid client'
        }
      },
      {
        session: {
          accessToken: 'access\nheader',
          refreshToken: 'refresh',
          expiresAt: 1
        }
      },
      {
        session: {
          accessToken: ' access',
          refreshToken: 'refresh',
          expiresAt: 1
        }
      },
      {
        session: {
          accessToken: 'access\u2028token',
          refreshToken: 'refresh',
          expiresAt: 1
        }
      },
      { rememberedTwoFactorToken: oversizedToken },
      { rememberedTwoFactorToken: 'remembered\u007f-token' }
    ]

    for (const state of cases) {
      expect(() => parseVaultData(vaultData(state))).toThrowError(VaultError)
    }
  })

  it('applies token limits in UTF-8 bytes instead of JavaScript code units', () => {
    const withinBoundary = 'é'.repeat(MAX_OPAQUE_AUTH_TOKEN_BYTES / 2)
    const overBoundary = `${withinBoundary}é`

    expect(
      parseVaultData(vaultData({ rememberedTwoFactorToken: withinBoundary })).sync?.state
        .rememberedTwoFactorToken
    ).toBe(withinBoundary)
    expect(() =>
      parseVaultData(vaultData({ rememberedTwoFactorToken: overBoundary }))
    ).toThrowError(VaultError)
  })
})
