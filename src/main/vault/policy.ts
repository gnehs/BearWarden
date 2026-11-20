import type { VaultItemType } from '../../shared/vault-contract'
import {
  BITWARDEN_POLICY_TYPE,
  policyEnforcementDecision,
  type BitwardenPolicyMetadata,
  type BitwardenPolicySet,
  type PolicyEnforcementDecision
} from '../bitwarden-policy'
import { VaultError } from '../vault-errors'
import { WIRE_TYPE_BY_ITEM_TYPE } from './item-fields'
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
  const decision = bitwardenPolicyDecision(BITWARDEN_POLICY_TYPE.RestrictedItemTypes, data)
  if (decision.state === 'not-applicable') return
  if (decision.state === 'fail-closed') throw new VaultError('POLICY_RESTRICTED')
  if (
    decision.policies.some(
      (policy) =>
        policy.data?.kind !== 'restrictedItemTypes' ||
        policy.data.cipherTypes.includes(WIRE_TYPE_BY_ITEM_TYPE[type])
    )
  ) {
    throw new VaultError('POLICY_RESTRICTED')
  }
}

/** Cipher types that official clients create only behind the `pm-32009-new-item-types` flag. */
const FLAGGED_ITEM_TYPES: ReadonlySet<VaultItemType> = new Set([
  'bankAccount',
  'driversLicense',
  'passport'
])

/**
 * Creation gate for item types an older server would reject on push. Synced items of these types
 * stay readable and editable; only adding new ones waits for the server flag. A local vault that
 * has never connected has no server to reject them.
 */
export function newItemTypesAvailable(data: VaultData): boolean {
  return data.sync === null || data.sync.state.newItemTypesEnabled === true
}

export function assertServerAcceptsNewItemType(type: VaultItemType, data: VaultData): void {
  if (FLAGGED_ITEM_TYPES.has(type) && !newItemTypesAvailable(data)) {
    throw new VaultError('ITEM_TYPE_UNSUPPORTED')
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
