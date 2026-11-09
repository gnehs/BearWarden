import type { VaultItemType } from '../../shared/vault-contract'
import {
  BITWARDEN_POLICY_TYPE,
  policyEnforcementDecision,
  type BitwardenPolicyMetadata,
  type BitwardenPolicySet,
  type PolicyEnforcementDecision
} from '../bitwarden-policy'
import { VaultError } from '../vault-errors'
import type { VaultData } from './types'

/** Returns only the safe, encrypted-at-rest policy snapshot for the active Bitwarden account. */
export function currentBitwardenPolicySet(data: VaultData): BitwardenPolicySet {
  return data.sync?.state.policySet ?? { source: 'none', policies: [] }
}

/**
 * Resolves a policy only against organization memberships that explicitly reported
 * `usePolicies: true`. Missing applicability metadata cannot be treated as an exemption.
 */
export function bitwardenPolicyDecision(type: number, data: VaultData): PolicyEnforcementDecision {
  const policySet = currentBitwardenPolicySet(data)
  if (policySet.parseFailure) {
    return { state: 'fail-closed', reason: 'malformed-policy', policies: [] }
  }
  const candidates = policySet.policies.filter((policy) => policy.enabled && policy.type === type)
  if (candidates.length > 0 && policySet.applicableOrganizationIds === undefined) {
    return { state: 'fail-closed', reason: 'unsupported-policy', policies: candidates }
  }
  return policyEnforcementDecision(
    policySet,
    type,
    new Set(policySet.applicableOrganizationIds ?? [])
  )
}

export function assertBitwardenPolicyDoesNotBlock(type: number, data: VaultData): void {
  const decision = bitwardenPolicyDecision(type, data)
  if (decision.state !== 'not-applicable') throw new VaultError('POLICY_RESTRICTED')
}

export function assertSendMutationAllowed(data: VaultData): void {
  assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.DisableSend, data)
  const controls = bitwardenPolicyDecision(BITWARDEN_POLICY_TYPE.SendControls, data)
  if (controls.state === 'fail-closed') throw new VaultError('POLICY_RESTRICTED')
  if (
    controls.state === 'enforce' &&
    controls.policies.some(
      (policy) => policy.data?.kind !== 'sendControls' || policy.data.disableSend
    )
  ) {
    throw new VaultError('POLICY_RESTRICTED')
  }
}

export function assertPersonalItemTypeAllowed(type: VaultItemType, data: VaultData): void {
  const wireType: Record<VaultItemType, number> = {
    login: 1,
    secureNote: 2,
    card: 3,
    identity: 4,
    sshKey: 5
  }
  const decision = bitwardenPolicyDecision(BITWARDEN_POLICY_TYPE.RestrictedItemTypes, data)
  if (decision.state === 'not-applicable') return
  if (decision.state === 'fail-closed') throw new VaultError('POLICY_RESTRICTED')
  if (
    decision.policies.some(
      (policy) =>
        policy.data?.kind !== 'restrictedItemTypes' ||
        policy.data.cipherTypes.includes(wireType[type])
    )
  ) {
    throw new VaultError('POLICY_RESTRICTED')
  }
}

export function maximumVaultTimeoutMinutes(policies: readonly BitwardenPolicyMetadata[]): number {
  let maximum = Number.POSITIVE_INFINITY
  for (const policy of policies) {
    if (policy.data?.kind !== 'maximumVaultTimeout' || policy.data.action === 'logOut') return 1
    maximum = Math.min(maximum, policy.data.minutes)
  }
  return Number.isFinite(maximum) ? maximum : 1
}
