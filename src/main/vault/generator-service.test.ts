import { describe, expect, it, vi } from 'vitest'
import {
  BITWARDEN_POLICY_TYPE,
  type BitwardenPolicyMetadata,
  type BitwardenPolicySet,
  type PasswordGeneratorPolicyMetadata
} from '../bitwarden-policy'
import { VaultGeneratorService } from './generator-service'

const ORGANIZATION_ID = '11111111-1111-4111-8111-111111111111'

const EMPTY_POLICIES: BitwardenPolicySet = { source: 'none', policies: [] }

function metadata(
  id: string,
  data: Partial<Omit<PasswordGeneratorPolicyMetadata, 'kind'>> = {}
): BitwardenPolicyMetadata {
  return {
    id,
    organizationId: ORGANIZATION_ID,
    type: BITWARDEN_POLICY_TYPE.PasswordGenerator,
    typeName: 'PasswordGenerator',
    enabled: true,
    canToggleState: false,
    revisionDate: null,
    execution: 'actionable',
    data: {
      kind: 'passwordGenerator',
      overridePasswordType: '',
      minLength: 0,
      useUppercase: false,
      useLowercase: false,
      useNumbers: false,
      numberCount: 0,
      useSpecial: false,
      specialCount: 0,
      minNumberWords: 0,
      capitalize: false,
      includeNumber: false,
      ...data
    }
  }
}

function createService(
  readPolicySet: () => BitwardenPolicySet = () => EMPTY_POLICIES
): VaultGeneratorService {
  let id = 0
  return new VaultGeneratorService({
    now: () => new Date('2026-07-23T00:00:00.000Z'),
    createId: () => `00000000-0000-4000-8000-${String(++id).padStart(12, '0')}`,
    randomInt: () => 0,
    copyText: vi.fn(),
    exclusive: async (operation) => operation(),
    assertUnlocked: vi.fn(),
    readPolicySet,
    readHistory: () => [],
    commitHistory: vi.fn()
  })
}

describe('VaultGeneratorService password generator policy', () => {
  it('combines enabled policies using the official least-privilege rules', async () => {
    const service = createService(() => ({
      source: 'policiesNew',
      applicableOrganizationIds: [ORGANIZATION_ID],
      policies: [
        metadata('22222222-2222-4222-8222-222222222222', {
          overridePasswordType: 'passphrase',
          minLength: 16,
          useUppercase: true,
          numberCount: 2
        }),
        metadata('33333333-3333-4333-8333-333333333333', {
          overridePasswordType: 'password',
          minLength: 18,
          useLowercase: true,
          useSpecial: true,
          specialCount: 3
        })
      ]
    }))

    const result = await service.generateCredential({
      algorithm: 'passphrase',
      options: { wordCount: 4 }
    })

    expect(result.algorithm).toBe('password')
    expect(result.credential).toHaveLength(18)
    expect(result.credential).toMatch(/[A-Z]/u)
    expect(result.credential).toMatch(/[a-z]/u)
    expect((result.credential.match(/[0-9]/gu) ?? []).length).toBeGreaterThanOrEqual(2)
    expect((result.credential.match(/[!@#$%^&*]/gu) ?? []).length).toBeGreaterThanOrEqual(3)
  })

  it('enforces passphrase override, word count, capitalization, and number inclusion', async () => {
    const service = createService(() => ({
      source: 'policies',
      applicableOrganizationIds: [ORGANIZATION_ID],
      policies: [
        metadata('22222222-2222-4222-8222-222222222222', {
          overridePasswordType: 'passphrase',
          minNumberWords: 8,
          capitalize: true,
          includeNumber: true
        })
      ]
    }))

    const result = await service.generateCredential({ algorithm: 'password', options: {} })

    expect(result.algorithm).toBe('passphrase')
    expect(result.credential.split('-')).toHaveLength(8)
    expect(result.credential).toMatch(/^Abacus0(?:-Abacus){7}$/u)
  })

  it('retains stricter valid request options while adding policy-required classes', async () => {
    const service = createService(() => ({
      source: 'policies',
      applicableOrganizationIds: [ORGANIZATION_ID],
      policies: [
        metadata('22222222-2222-4222-8222-222222222222', {
          minLength: 20,
          useUppercase: true,
          specialCount: 2
        })
      ]
    }))

    const result = await service.generateCredential({
      algorithm: 'password',
      options: { length: 25, uppercase: false, special: true, minSpecial: 4 }
    })

    expect(result.credential).toHaveLength(25)
    expect(result.credential).toMatch(/[A-Z]/u)
    expect((result.credential.match(/[!@#$%^&*]/gu) ?? []).length).toBeGreaterThanOrEqual(4)
  })

  it('does not let an override sanitize an invalid original request', async () => {
    const service = createService(() => ({
      source: 'policies',
      applicableOrganizationIds: [ORGANIZATION_ID],
      policies: [
        metadata('22222222-2222-4222-8222-222222222222', {
          overridePasswordType: 'passphrase'
        })
      ]
    }))

    await expect(
      service.generateCredential({
        algorithm: 'password',
        options: { uppercase: false, minUppercase: 1 }
      })
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })

  it('fails closed for malformed policy metadata and unsupported policy limits', async () => {
    const malformed: BitwardenPolicyMetadata = {
      ...metadata('22222222-2222-4222-8222-222222222222'),
      execution: 'malformed',
      data: null
    }
    const malformedService = createService(() => ({
      source: 'policies',
      applicableOrganizationIds: [ORGANIZATION_ID],
      policies: [malformed]
    }))
    await expect(
      malformedService.generateCredential({ algorithm: 'password', options: {} })
    ).rejects.toMatchObject({ code: 'POLICY_RESTRICTED' })

    const beyondLocalLimit = createService(() => ({
      source: 'policies',
      applicableOrganizationIds: [ORGANIZATION_ID],
      policies: [
        metadata('33333333-3333-4333-8333-333333333333', {
          numberCount: 10
        })
      ]
    }))
    await expect(
      beyondLocalLimit.generateCredential({ algorithm: 'password', options: {} })
    ).rejects.toMatchObject({ code: 'POLICY_RESTRICTED' })
  })

  it('fails closed when policy parsing or membership applicability is unavailable', async () => {
    const parseFailure = createService(() => ({
      source: 'none',
      policies: [],
      parseFailure: 'invalid-response'
    }))
    await expect(
      parseFailure.generateCredential({ algorithm: 'passphrase', options: {} })
    ).rejects.toMatchObject({ code: 'POLICY_RESTRICTED' })

    const missingApplicability = createService(() => ({
      source: 'policies',
      policies: [metadata('22222222-2222-4222-8222-222222222222', { minLength: 20 })]
    }))
    await expect(
      missingApplicability.generateCredential({ algorithm: 'password', options: {} })
    ).rejects.toMatchObject({ code: 'POLICY_RESTRICTED' })
  })

  it('does not enforce a policy from an exempt organization membership', async () => {
    const service = createService(() => ({
      source: 'policies',
      applicableOrganizationIds: [],
      policies: [
        metadata('22222222-2222-4222-8222-222222222222', {
          overridePasswordType: 'passphrase',
          minNumberWords: 20
        })
      ]
    }))

    await expect(
      service.generateCredential({ algorithm: 'password', options: { length: 14 } })
    ).resolves.toMatchObject({
      algorithm: 'password',
      credential: expect.stringMatching(/^.{14}$/u)
    })
  })

  it('does not apply password generator policy failures to username generation', async () => {
    const malformed: BitwardenPolicyMetadata = {
      ...metadata('22222222-2222-4222-8222-222222222222'),
      execution: 'malformed',
      data: null
    }
    const service = createService(() => ({ source: 'policies', policies: [malformed] }))

    await expect(
      service.generateCredential({ algorithm: 'username', options: {} })
    ).resolves.toMatchObject({ algorithm: 'username', credential: 'abacus' })
  })
})
