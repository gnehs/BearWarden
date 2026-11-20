import { describe, expect, it } from 'vitest'
import type { VaultItemType } from '../../shared/vault-contract'
import { BITWARDEN_POLICY_TYPE } from '../bitwarden-policy'
import { assertPersonalItemTypeAllowed } from './policy'
import type { VaultData } from './types'

const ORGANIZATION_ID = '60000000-0000-4000-8000-000000000001'

function restrictedVault(cipherTypes: number[]): VaultData {
  return {
    sync: {
      state: {
        policySet: {
          source: 'policiesNew',
          applicableOrganizationIds: [ORGANIZATION_ID],
          policies: [
            {
              id: 'a0000000-0000-4000-8000-000000000001',
              organizationId: ORGANIZATION_ID,
              type: BITWARDEN_POLICY_TYPE.RestrictedItemTypes,
              typeName: 'RestrictedItemTypes',
              enabled: true,
              canToggleState: false,
              revisionDate: null,
              execution: 'actionable',
              data: { kind: 'restrictedItemTypes', cipherTypes }
            }
          ]
        }
      }
    }
  } as unknown as VaultData
}

describe('assertPersonalItemTypeAllowed', () => {
  it.each<[VaultItemType, number]>([
    ['bankAccount', 6],
    ['driversLicense', 7],
    ['passport', 8]
  ])('blocks %s when RestrictedItemTypes lists cipher type %i', (type, wireType) => {
    expect(() => assertPersonalItemTypeAllowed(type, restrictedVault([wireType]))).toThrow(
      expect.objectContaining({ code: 'POLICY_RESTRICTED' })
    )
  })

  it('allows the new types that the policy does not list', () => {
    const data = restrictedVault([6])
    expect(() => assertPersonalItemTypeAllowed('driversLicense', data)).not.toThrow()
    expect(() => assertPersonalItemTypeAllowed('passport', data)).not.toThrow()
    expect(() => assertPersonalItemTypeAllowed('card', data)).not.toThrow()
  })
})
