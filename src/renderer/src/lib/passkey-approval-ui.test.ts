import { describe, expect, it } from 'vitest'
import type { PasskeyApprovalPrompt } from '../../../shared/vault-contract'
import {
  canApprovePasskeyApproval,
  hasPasskeyApprovalChoice,
  initialPasskeyApprovalChoice,
  initialPasskeyApprovalVerificationMethod,
  isPasskeyApprovalExpired,
  passkeyApprovalResponseVerificationMethod,
  requiresPasskeyApprovalPasswordVerification
} from './passkey-approval-ui'

function prompt(overrides: Partial<PasskeyApprovalPrompt> = {}): PasskeyApprovalPrompt {
  return {
    requestId: 'request-1',
    expiresAt: 2_000,
    kind: 'get',
    rpId: 'login.example.invalid',
    rpName: 'Example',
    userVerification: 'preferred',
    choices: [{ id: 'choice-1', label: 'Example account', requiresReprompt: false }],
    verificationMethods: ['touch-id', 'master-password'],
    ...overrides
  }
}

describe('Passkey approval renderer policy', () => {
  it('selects its only credential and prefers Touch ID for actual UV', () => {
    expect(initialPasskeyApprovalChoice(prompt())).toBe('choice-1')
    expect(initialPasskeyApprovalChoice(prompt({ choices: [] }))).toBeUndefined()
    expect(initialPasskeyApprovalVerificationMethod(prompt())).toBe('touch-id')
    expect(
      initialPasskeyApprovalVerificationMethod(prompt({ verificationMethods: ['master-password'] }))
    ).toBe('master-password')
    expect(
      initialPasskeyApprovalVerificationMethod(prompt({ userVerification: 'discouraged' }))
    ).toBeUndefined()
  })

  it('fails closed for invalid credential selections and unavailable verification methods', () => {
    const request = prompt()
    expect(hasPasskeyApprovalChoice(request, 'choice-1')).toBe(true)
    expect(hasPasskeyApprovalChoice(request, 'other-choice')).toBe(false)
    expect(
      canApprovePasskeyApproval(
        request,
        {
          selectedChoiceId: 'choice-1',
          verificationMethod: 'touch-id',
          masterPassword: ''
        },
        1_000
      )
    ).toBe(true)
    expect(
      canApprovePasskeyApproval(
        request,
        {
          selectedChoiceId: 'choice-1',
          masterPassword: ''
        },
        1_000
      )
    ).toBe(false)
    expect(
      canApprovePasskeyApproval(
        prompt({ verificationMethods: ['master-password'] }),
        {
          selectedChoiceId: 'choice-1',
          verificationMethod: 'touch-id',
          masterPassword: ''
        },
        1_000
      )
    ).toBe(false)
    expect(
      canApprovePasskeyApproval(
        prompt({ choices: [] }),
        {
          verificationMethod: 'touch-id',
          masterPassword: ''
        },
        1_000
      )
    ).toBe(false)
    expect(
      canApprovePasskeyApproval(
        request,
        {
          selectedChoiceId: 'choice-1',
          verificationMethod: 'master-password',
          masterPassword: ''
        },
        1_000
      )
    ).toBe(false)
    expect(
      canApprovePasskeyApproval(
        request,
        {
          selectedChoiceId: 'choice-1',
          verificationMethod: 'master-password',
          masterPassword: 'x'.repeat(1_025)
        },
        1_000
      )
    ).toBe(false)
  })

  it.each(['required', 'preferred'] as const)(
    'accepts an available actual UV method for %s verification',
    (userVerification) => {
      const request = prompt({ userVerification, verificationMethods: ['master-password'] })
      expect(
        canApprovePasskeyApproval(
          request,
          {
            selectedChoiceId: 'choice-1',
            verificationMethod: 'master-password',
            masterPassword: 'correct horse'
          },
          1_000
        )
      ).toBe(true)
      expect(passkeyApprovalResponseVerificationMethod(request, 'master-password')).toBe(
        'master-password'
      )
    }
  )

  it('keeps discouraged UV as none while independently enforcing a protected choice reprompt', () => {
    const request = prompt({
      userVerification: 'discouraged',
      choices: [{ id: 'choice-1', label: 'Protected account', requiresReprompt: true }]
    })
    expect(requiresPasskeyApprovalPasswordVerification(request, 'choice-1', undefined)).toBe(true)
    expect(passkeyApprovalResponseVerificationMethod(request, 'touch-id')).toBe('none')
    expect(
      canApprovePasskeyApproval(
        request,
        {
          selectedChoiceId: 'choice-1',
          masterPassword: ''
        },
        1_000
      )
    ).toBe(false)
    expect(
      canApprovePasskeyApproval(
        request,
        {
          selectedChoiceId: 'choice-1',
          masterPassword: 'correct horse'
        },
        1_000
      )
    ).toBe(true)
  })

  it('fails closed when the request has expired', () => {
    const request = prompt()
    expect(isPasskeyApprovalExpired(request, 2_000)).toBe(true)
    expect(
      canApprovePasskeyApproval(
        request,
        {
          selectedChoiceId: 'choice-1',
          verificationMethod: 'touch-id',
          masterPassword: ''
        },
        2_000
      )
    ).toBe(false)
  })
})
