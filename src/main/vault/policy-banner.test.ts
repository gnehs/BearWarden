import { describe, expect, it } from 'vitest'
import type { OrganizationView } from '../../shared/vault-contract'
import {
  BITWARDEN_POLICY_TYPE,
  type BitwardenPolicyMetadata,
  type OrganizationUserNotificationPolicyMetadata
} from '../bitwarden-policy'
import type { VaultCore, VaultSessionResource } from './core'
import { policyBannerKey, visiblePolicyBanner, VaultPolicyBanner } from './policy-banner'
import type { VaultData } from './types'

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'

function banner(
  overrides: Partial<OrganizationUserNotificationPolicyMetadata> = {}
): OrganizationUserNotificationPolicyMetadata {
  return {
    kind: 'organizationUserNotification',
    header: 'Heads up',
    description: 'Rotate your credentials',
    buttonText: null,
    showAfterEveryLogin: false,
    ...overrides
  }
}

function policy(
  id: string,
  organizationId: string,
  overrides: Partial<BitwardenPolicyMetadata> = {}
): BitwardenPolicyMetadata {
  return {
    id,
    organizationId,
    type: BITWARDEN_POLICY_TYPE.OrganizationUserNotification,
    typeName: 'OrganizationUserNotification',
    enabled: true,
    canToggleState: true,
    revisionDate: '2026-07-01T00:00:00.000Z',
    execution: 'actionable',
    data: banner(),
    ...overrides
  }
}

function organization(id: string, overrides: Partial<OrganizationView> = {}): OrganizationView {
  return {
    id,
    name: id,
    status: 2,
    type: 2,
    enabled: true,
    identifier: null,
    hasPublicAndPrivateKeys: true,
    ...overrides
  }
}

function vault(
  policies: BitwardenPolicyMetadata[],
  options: {
    organizations?: OrganizationView[]
    applicable?: string[]
    dismissals?: string[]
  } = {}
): VaultData {
  return {
    organizations: options.organizations ?? [organization(ORG_A), organization(ORG_B)],
    policyBannerDismissals: options.dismissals ?? [],
    sync: {
      state: {
        policySet: {
          source: 'policiesNew',
          policies,
          applicableOrganizationIds: options.applicable ?? [ORG_A, ORG_B]
        }
      }
    }
  } as unknown as VaultData
}

const P1 = '11111111-1111-4111-8111-111111111111'
const P2 = '22222222-2222-4222-8222-222222222222'
const noSession = new Set<string>()

describe('visiblePolicyBanner', () => {
  it('shows an enabled banner of a confirmed organization', () => {
    const current = policy(P1, ORG_A)
    expect(visiblePolicyBanner(vault([current]), noSession)).toEqual({
      key: policyBannerKey(current),
      header: 'Heads up',
      description: 'Rotate your credentials',
      buttonText: null,
      showAfterEveryLogin: false
    })
  })

  it.each([
    ['disabled', policy(P1, ORG_A, { enabled: false }), {}],
    ['malformed', policy(P1, ORG_A, { execution: 'malformed', data: null }), {}],
    ['empty', policy(P1, ORG_A, { data: banner({ description: '' }) }), {}],
    ['not applicable to the member', policy(P1, ORG_A), { applicable: [ORG_B] }],
    [
      'from an invited organization',
      policy(P1, ORG_A),
      { organizations: [organization(ORG_A, { status: 0 })] }
    ],
    [
      'from a revoked organization',
      policy(P1, ORG_A),
      { organizations: [organization(ORG_A, { status: -1 })] }
    ],
    [
      'from a disabled organization',
      policy(P1, ORG_A),
      { organizations: [organization(ORG_A, { enabled: false })] }
    ]
  ])('hides a banner that is %s', (_name, current, options) => {
    expect(visiblePolicyBanner(vault([current], options), noSession)).toBeNull()
  })

  it('shows only the most recently revised banner and never stacks organizations', () => {
    const older = policy(P1, ORG_A, { revisionDate: '2026-07-01T00:00:00.000Z' })
    const newer = policy(P2, ORG_B, {
      revisionDate: '2026-08-01T00:00:00.000Z',
      data: banner({ description: 'Newest' })
    })
    expect(visiblePolicyBanner(vault([older, newer]), noSession)?.description).toBe('Newest')
    expect(visiblePolicyBanner(vault([newer, older]), noSession)?.description).toBe('Newest')
  })

  it('prefers a dated policy over one from a server that sends no revision date', () => {
    const undated = policy(P1, ORG_A, { revisionDate: null })
    const dated = policy(P2, ORG_B, { data: banner({ description: 'Dated' }) })
    expect(visiblePolicyBanner(vault([undated, dated]), noSession)?.description).toBe('Dated')
  })

  describe('dismissal', () => {
    it('stays hidden after dismissal until the policy revision changes', () => {
      const original = policy(P1, ORG_A)
      const dismissals = [policyBannerKey(original)]
      expect(visiblePolicyBanner(vault([original], { dismissals }), noSession)).toBeNull()

      const edited = policy(P1, ORG_A, { revisionDate: '2026-07-02T00:00:00.000Z' })
      expect(visiblePolicyBanner(vault([edited], { dismissals }), noSession)).not.toBeNull()
    })

    it('keeps an undated policy dismissed because its key never changes', () => {
      const undated = policy(P1, ORG_A, { revisionDate: null })
      expect(policyBannerKey(undated)).toBe(`${ORG_A}:${P1}:`)
      expect(
        visiblePolicyBanner(vault([undated], { dismissals: [policyBannerKey(undated)] }), noSession)
      ).toBeNull()
    })

    it('does not let another organization or policy share a dismissal', () => {
      const dismissals = [policyBannerKey(policy(P1, ORG_A))]
      expect(
        visiblePolicyBanner(vault([policy(P2, ORG_B)], { dismissals }), noSession)
      ).not.toBeNull()
    })

    it('ignores the persisted dismissal of a show-after-every-login banner', () => {
      const everyLogin = policy(P1, ORG_A, { data: banner({ showAfterEveryLogin: true }) })
      const key = policyBannerKey(everyLogin)
      const data = vault([everyLogin], { dismissals: [key] })
      expect(visiblePolicyBanner(data, noSession)).not.toBeNull()
      expect(visiblePolicyBanner(data, new Set([key]))).toBeNull()
    })

    it('does not let a session dismissal hide a once-only banner', () => {
      const once = policy(P1, ORG_A)
      expect(visiblePolicyBanner(vault([once]), new Set([policyBannerKey(once)]))).not.toBeNull()
    })
  })
})

function createService(initial: VaultData): {
  service: VaultPolicyBanner
  persisted: () => string[]
  lock: () => void
} {
  let data = initial
  const resources: VaultSessionResource[] = []
  const core = {
    registerResource: (resource: VaultSessionResource) => resources.push(resource),
    requireData: () => data,
    requireFastReadData: () => data,
    exclusive: async <T>(operation: () => Promise<T>) => operation(),
    mutate: async (mutation: (next: VaultData, now: string) => void) => {
      const next = structuredClone(data)
      mutation(next, '2026-07-01T00:00:00.000Z')
      data = next
    }
  } as unknown as VaultCore
  return {
    service: new VaultPolicyBanner(core),
    persisted: () => data.policyBannerDismissals,
    lock: () => resources.forEach((resource) => resource.clear?.())
  }
}

describe('VaultPolicyBanner', () => {
  it('persists a dismissal so the banner stays hidden on the next read', async () => {
    const current = policy(P1, ORG_A)
    const { service, persisted } = createService(vault([current]))
    const shown = await service.get()
    expect(shown).not.toBeNull()

    await service.dismiss(shown!.key)

    expect(persisted()).toEqual([policyBannerKey(current)])
    await expect(service.get()).resolves.toBeNull()
  })

  it('ignores a dismissal of a revision that is no longer the visible banner', async () => {
    const { service, persisted } = createService(vault([policy(P1, ORG_A)]))

    await service.dismiss(`${ORG_A}:${P1}:2025-01-01T00:00:00.000Z`)

    expect(persisted()).toEqual([])
    await expect(service.get()).resolves.not.toBeNull()
  })

  it('keeps only the newest dismissals within the bound', async () => {
    const stale = Array.from({ length: 16 }, (_, index) => `old-${index}`)
    const current = policy(P1, ORG_A)
    const { service, persisted } = createService(vault([current], { dismissals: stale }))

    await service.dismiss(policyBannerKey(current))

    expect(persisted()).toHaveLength(16)
    expect(persisted().at(-1)).toBe(policyBannerKey(current))
    expect(persisted()).not.toContain('old-0')
  })

  it('hides a show-after-every-login banner for the session only and returns after lock', async () => {
    const everyLogin = policy(P1, ORG_A, { data: banner({ showAfterEveryLogin: true }) })
    const { service, persisted, lock } = createService(vault([everyLogin]))

    await service.dismiss(policyBannerKey(everyLogin))
    await expect(service.get()).resolves.toBeNull()
    expect(persisted()).toEqual([])

    lock()
    await expect(service.get()).resolves.not.toBeNull()
  })
})
