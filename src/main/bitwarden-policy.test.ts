import { describe, expect, it } from 'vitest'
import {
  BITWARDEN_POLICY_TYPE,
  BitwardenPolicyParseError,
  parseBitwardenPolicySync,
  policyEnforcementDecision,
  unenforcedEnabledPolicies
} from './bitwarden-policy'

const POLICY_ID = '11111111-1111-4111-8111-111111111111'
const ORGANIZATION_ID = '22222222-2222-4222-8222-222222222222'

function policy(type: number, data?: unknown): Record<string, unknown> {
  return {
    Id: POLICY_ID,
    OrganizationId: ORGANIZATION_ID,
    Type: type,
    Data: data,
    Enabled: true,
    CanToggleState: false,
    RevisionDate: '2026-07-23T00:00:00.1234567Z'
  }
}

describe('Bitwarden organization policy parser', () => {
  it('prefers a non-empty PoliciesNew response and falls back when it is empty', () => {
    const modern = parseBitwardenPolicySync({
      PoliciesNew: [policy(BITWARDEN_POLICY_TYPE.DisableSend)],
      Policies: [policy(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin)]
    })
    expect(modern.source).toBe('policiesNew')
    expect(modern.policies.map((entry) => entry.type)).toEqual([BITWARDEN_POLICY_TYPE.DisableSend])

    const legacy = parseBitwardenPolicySync({
      PoliciesNew: [],
      Policies: [policy(BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin)]
    })
    expect(legacy.source).toBe('policies')
    expect(legacy.policies.map((entry) => entry.type)).toEqual([
      BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin
    ])
  })

  it('normalizes only bounded actionable data and discards unrecognized payload fields', () => {
    const result = parseBitwardenPolicySync({
      PoliciesNew: [
        policy(BITWARDEN_POLICY_TYPE.PasswordGenerator, {
          overridePasswordType: 'password',
          minLength: 20,
          useUpper: true,
          minNumbers: 2,
          secretOrganizationMessage: 'must not persist'
        }),
        policy(BITWARDEN_POLICY_TYPE.MaximumVaultTimeout, {
          Minutes: 30,
          Type: 'custom',
          Action: 'lock',
          ignored: { deeply: 'nested' }
        })
      ]
    })

    expect(result.policies).toMatchObject([
      {
        execution: 'actionable',
        data: {
          kind: 'passwordGenerator',
          overridePasswordType: 'password',
          minLength: 20,
          useUppercase: true,
          useLowercase: false,
          numberCount: 2
        }
      },
      {
        execution: 'actionable',
        data: {
          kind: 'maximumVaultTimeout',
          minutes: 30,
          timeoutType: 'custom',
          action: 'lock'
        }
      }
    ])
    expect(JSON.stringify(result)).not.toContain('secretOrganizationMessage')
    expect(JSON.stringify(result)).not.toContain('deeply')
  })

  it('retains the current SendControls disable flag for enforcement', () => {
    const disabled = parseBitwardenPolicySync({
      PoliciesNew: [policy(BITWARDEN_POLICY_TYPE.SendControls, { disableSend: true })]
    })
    expect(disabled.policies).toMatchObject([
      {
        execution: 'actionable',
        data: { kind: 'sendControls', disableSend: true }
      }
    ])

    const enabled = parseBitwardenPolicySync({
      PoliciesNew: [policy(BITWARDEN_POLICY_TYPE.SendControls, { disableSend: false })]
    })
    expect(enabled.policies[0]?.data).toEqual({ kind: 'sendControls', disableSend: false })
  })

  it('uses the official legacy Card restriction and normalizes bounded cipher types', () => {
    const result = parseBitwardenPolicySync({
      Policies: [
        policy(BITWARDEN_POLICY_TYPE.RestrictedItemTypes, null),
        {
          ...policy(BITWARDEN_POLICY_TYPE.RestrictedItemTypes, [5, 3, 5]),
          Id: '33333333-3333-4333-8333-333333333333'
        }
      ]
    })
    expect(result.policies.map((entry) => entry.data)).toEqual([
      { kind: 'restrictedItemTypes', cipherTypes: [3] },
      { kind: 'restrictedItemTypes', cipherTypes: [3, 5] }
    ])
  })

  it('retains only safe identity metadata for known unsupported and future policy types', () => {
    const result = parseBitwardenPolicySync({
      Policies: [
        policy(BITWARDEN_POLICY_TYPE.OrganizationUserNotification, {
          message: 'private organization announcement'
        }),
        {
          ...policy(42_000, { arbitrary: 'future secret data' }),
          Id: '44444444-4444-4444-8444-444444444444'
        }
      ]
    })
    expect(result.policies).toMatchObject([
      {
        typeName: 'OrganizationUserNotification',
        execution: 'unsupported',
        data: null
      },
      { type: 42_000, typeName: null, execution: 'unknown', data: null }
    ])
    expect(JSON.stringify(result)).not.toContain('private organization announcement')
    expect(JSON.stringify(result)).not.toContain('future secret data')
    expect(unenforcedEnabledPolicies(result)).toHaveLength(2)
    expect(
      policyEnforcementDecision(result, BITWARDEN_POLICY_TYPE.OrganizationUserNotification)
    ).toMatchObject({ state: 'fail-closed', reason: 'unsupported-policy' })
    expect(policyEnforcementDecision(result, 42_000)).toMatchObject({
      state: 'fail-closed',
      reason: 'unknown-policy'
    })
  })

  it('marks malformed actionable data for fail-closed handling without retaining it', () => {
    const result = parseBitwardenPolicySync({
      Policies: [
        policy(BITWARDEN_POLICY_TYPE.MaximumVaultTimeout, { minutes: 0 }),
        {
          ...policy(BITWARDEN_POLICY_TYPE.RestrictedItemTypes, [3, 999]),
          Id: '55555555-5555-4555-8555-555555555555'
        }
      ]
    })
    expect(result.policies).toMatchObject([
      { execution: 'malformed', data: null },
      { execution: 'malformed', data: null }
    ])
    expect(policyEnforcementDecision(result, BITWARDEN_POLICY_TYPE.MaximumVaultTimeout)).toEqual(
      expect.objectContaining({ state: 'fail-closed', reason: 'malformed-policy' })
    )
  })

  it('gates only enabled and applicable policies after membership filtering', () => {
    const result = parseBitwardenPolicySync({
      Policies: [
        policy(BITWARDEN_POLICY_TYPE.DisableSend),
        {
          ...policy(BITWARDEN_POLICY_TYPE.DisableSend),
          Id: '66666666-6666-4666-8666-666666666666',
          OrganizationId: '77777777-7777-4777-8777-777777777777',
          Enabled: false
        }
      ]
    })
    expect(policyEnforcementDecision(result, BITWARDEN_POLICY_TYPE.DisableSend)).toMatchObject({
      state: 'enforce',
      policies: [{ organizationId: ORGANIZATION_ID }]
    })
    expect(
      policyEnforcementDecision(
        result,
        BITWARDEN_POLICY_TYPE.DisableSend,
        new Set(['88888888-8888-4888-8888-888888888888'])
      )
    ).toEqual({ state: 'not-applicable', policies: [] })
  })

  it('rejects ambiguous aliases, invalid identifiers, unbounded counts, and invalid dates', () => {
    expect(() =>
      parseBitwardenPolicySync({
        Policies: [{ ...policy(BITWARDEN_POLICY_TYPE.DisableSend), enabled: true }]
      })
    ).toThrow(BitwardenPolicyParseError)
    expect(() =>
      parseBitwardenPolicySync({
        Policies: [
          {
            ...policy(BITWARDEN_POLICY_TYPE.DisableSend),
            OrganizationId: 'not-a-guid'
          }
        ]
      })
    ).toThrow(BitwardenPolicyParseError)
    expect(() =>
      parseBitwardenPolicySync({
        Policies: [
          {
            ...policy(BITWARDEN_POLICY_TYPE.DisableSend),
            RevisionDate: 'yesterday'
          }
        ]
      })
    ).toThrow(BitwardenPolicyParseError)
    expect(() =>
      parseBitwardenPolicySync({
        Policies: Array.from({ length: 257 }, () => policy(BITWARDEN_POLICY_TYPE.DisableSend))
      })
    ).toThrowError(new BitwardenPolicyParseError('POLICY_LIMIT_EXCEEDED'))
  })
})
