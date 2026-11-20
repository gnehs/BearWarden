import type { PolicyBannerView } from '../../shared/vault-contract'
import {
  BITWARDEN_POLICY_TYPE,
  type BitwardenPolicyMetadata,
  type OrganizationUserNotificationPolicyMetadata
} from '../bitwarden-policy'
import type { VaultCore } from './core'
import { MAX_POLICY_BANNER_DISMISSALS } from './limits'
import type { VaultData } from './types'

/** Organization member statuses that receive policies: Accepted (1) and Confirmed (2). */
const POLICY_MEMBER_STATUSES = new Set([1, 2])

interface BannerCandidate {
  policy: BitwardenPolicyMetadata
  data: OrganizationUserNotificationPolicyMetadata
}

/**
 * Dismissal identity: the same policy edited again carries a new `revisionDate` and therefore
 * a new key. A server that sends no revision date keeps one stable key per policy.
 */
export function policyBannerKey(policy: BitwardenPolicyMetadata): string {
  return `${policy.organizationId}:${policy.id}:${policy.revisionDate ?? ''}`
}

function revisionTime(policy: BitwardenPolicyMetadata): number {
  return policy.revisionDate === null ? Number.NEGATIVE_INFINITY : Date.parse(policy.revisionDate)
}

/**
 * Mirrors the official clients: only the most recently revised enabled banner policy of an
 * organization the user belongs to is considered; banners from several organizations never stack.
 * Unknown membership or policy applicability hides the banner, since it is informational only.
 */
function latestBannerCandidate(data: VaultData): BannerCandidate | null {
  const policySet = data.sync?.state.policySet
  if (!policySet || policySet.parseFailure) return null
  const applicable = new Set(policySet.applicableOrganizationIds ?? [])
  const memberOrganizations = new Set(
    data.organizations
      .filter(
        (organization) =>
          organization.enabled &&
          organization.status !== null &&
          POLICY_MEMBER_STATUSES.has(organization.status)
      )
      .map((organization) => organization.id)
  )
  let latest: BannerCandidate | null = null
  for (const policy of policySet.policies) {
    if (
      policy.type !== BITWARDEN_POLICY_TYPE.OrganizationUserNotification ||
      !policy.enabled ||
      policy.execution !== 'actionable' ||
      policy.data?.kind !== 'organizationUserNotification' ||
      policy.data.description === '' ||
      !applicable.has(policy.organizationId) ||
      !memberOrganizations.has(policy.organizationId)
    ) {
      continue
    }
    if (latest === null || revisionTime(policy) > revisionTime(latest.policy)) {
      latest = { policy, data: policy.data }
    }
  }
  return latest
}

/**
 * Resolves the banner to show. A `showAfterEveryLogin` banner ignores the persisted dismissal and
 * is hidden only for the current unlocked session; any other banner stays dismissed until its
 * policy revision changes.
 */
export function visiblePolicyBanner(
  data: VaultData,
  sessionDismissedKeys: ReadonlySet<string>
): PolicyBannerView | null {
  const candidate = latestBannerCandidate(data)
  if (candidate === null) return null
  const key = policyBannerKey(candidate.policy)
  const dismissed = candidate.data.showAfterEveryLogin
    ? sessionDismissedKeys.has(key)
    : data.policyBannerDismissals.includes(key)
  if (dismissed) return null
  return {
    key,
    header: candidate.data.header,
    description: candidate.data.description,
    buttonText: candidate.data.buttonText,
    showAfterEveryLogin: candidate.data.showAfterEveryLogin
  }
}

export class VaultPolicyBanner {
  private readonly sessionDismissedKeys = new Set<string>()

  constructor(private readonly core: VaultCore) {
    core.registerResource({ clear: () => this.sessionDismissedKeys.clear() })
  }

  async get(): Promise<PolicyBannerView | null> {
    return visiblePolicyBanner(this.core.requireFastReadData(), this.sessionDismissedKeys)
  }

  /** Dismisses only the banner the user saw; a newer revision that arrived meanwhile stays visible. */
  async dismiss(key: string): Promise<void> {
    await this.core.exclusive(async () => {
      const shown = visiblePolicyBanner(this.core.requireData(), this.sessionDismissedKeys)
      if (shown === null || shown.key !== key) return
      this.sessionDismissedKeys.add(key)
      if (shown.showAfterEveryLogin) return
      await this.core.mutate((data) => {
        data.policyBannerDismissals = [
          ...data.policyBannerDismissals.filter((existing) => existing !== key),
          key
        ].slice(-MAX_POLICY_BANNER_DISMISSALS)
      })
    })
  }
}
