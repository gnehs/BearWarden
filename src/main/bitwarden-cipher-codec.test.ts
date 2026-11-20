import { describe, expect, it } from 'vitest'
import type { VaultItemType } from '../shared/vault-contract'
import {
  decryptBitwardenCipherBlob,
  decryptBitwardenString,
  encryptBitwardenCipherBlob,
  encryptBitwardenString
} from './bitwarden-crypto'
import {
  decryptLogin,
  encryptLoginRequest,
  type ResolvedBitwardenDraft
} from './bitwarden-cipher-codec'
import type { JsonObject } from './bitwarden-http'
import { emptyItemFields } from './vault/item-fields'

const USER_KEY = Buffer.alloc(64, 7)
const PROFILE_ID = '10000000-0000-4000-8000-000000000001'
const CIPHER_ID = '30000000-0000-4000-8000-000000000006'
const ACCOUNT = { userKey: USER_KEY, requireProfileId: () => PROFILE_ID }

const PAYLOADS = {
  bankAccount: {
    wireType: 6,
    fields: {
      bankName: 'Example Bank',
      nameOnAccount: 'Test Person',
      accountType: 'checking',
      accountNumber: '000123456789',
      routingNumber: '021000021',
      branchNumber: '001',
      pin: '2468',
      swiftCode: 'EXAMPLEXXX',
      iban: 'GB33BUKB20201555555555',
      bankContactPhone: '+1 555 0100'
    }
  },
  driversLicense: {
    wireType: 7,
    fields: {
      firstName: 'Test',
      middleName: 'Middle',
      lastName: 'Person',
      dateOfBirth: '1990-01-31',
      licenseNumber: 'D1234567',
      issuingCountry: 'US',
      issuingState: 'CA',
      issueDate: '2020-02-01',
      expirationDate: '2028-02-01',
      issuingAuthority: 'DMV',
      licenseClass: 'C'
    }
  },
  passport: {
    wireType: 8,
    fields: {
      surname: 'Person',
      givenName: 'Test',
      dateOfBirth: '1990-01-31',
      sex: 'X',
      birthPlace: 'Taipei',
      nationality: 'Taiwanese',
      issuingCountry: 'TW',
      passportNumber: 'P1234567',
      passportType: 'P',
      nationalIdentificationNumber: 'A123456789',
      issuingAuthority: 'Ministry of Foreign Affairs',
      issueDate: '2021-03-04',
      expirationDate: '2031-03-03'
    }
  }
} as const satisfies Partial<
  Record<VaultItemType, { wireType: number; fields: Record<string, string> }>
>

type NewItemType = keyof typeof PAYLOADS
const NEW_ITEM_TYPES = Object.keys(PAYLOADS) as NewItemType[]

function legacyCipher(type: NewItemType): JsonObject {
  const { wireType, fields } = PAYLOADS[type]
  return {
    id: CIPHER_ID,
    type: wireType,
    organizationId: null,
    folderId: null,
    name: encryptBitwardenString(`Synced ${type}`, USER_KEY),
    notes: null,
    favorite: false,
    key: null,
    [type]: {
      ...Object.fromEntries(
        Object.entries(fields).map(([name, value]) => [
          name,
          encryptBitwardenString(value, USER_KEY)
        ])
      ),
      futureTypedField: 'preserve-me'
    },
    fields: null,
    passwordHistory: null,
    revisionDate: '2026-11-01T00:00:00.000Z',
    deletedDate: null
  }
}

function blobCipher(type: NewItemType): JsonObject {
  const { wireType, fields } = PAYLOADS[type]
  return {
    id: CIPHER_ID,
    type: wireType,
    organizationId: null,
    folderId: null,
    name: encryptBitwardenString('', USER_KEY),
    notes: null,
    favorite: false,
    key: null,
    fields: null,
    data: encryptBitwardenCipherBlob(
      {
        name: `Blob ${type}`,
        notes: null,
        typeData: { type, ...fields, futureTypedField: { preserve: true } },
        futureRootField: 'preserve-root'
      },
      USER_KEY
    ),
    revisionDate: '2026-11-01T00:00:00.000Z',
    deletedDate: null
  }
}

function draft(
  type: NewItemType,
  overrides: Partial<ResolvedBitwardenDraft> = {}
): ResolvedBitwardenDraft {
  return {
    ...emptyItemFields(),
    ...PAYLOADS[type].fields,
    type,
    name: `Draft ${type}`,
    notes: null,
    folderId: null,
    favorite: false,
    archivedAt: null,
    reprompt: 0,
    uris: [],
    customFields: [],
    passkeys: [],
    passwordHistory: [],
    passwordRevisionDate: null,
    autofillOnPageLoad: null,
    totpChanged: false,
    customFieldsChanged: false,
    passkeysChanged: false,
    passwordHistoryChanged: false,
    ...overrides
  } satisfies ResolvedBitwardenDraft
}

describe.each(NEW_ITEM_TYPES)('%s cipher codec', (type) => {
  it('decrypts every official field from a legacy cipher', () => {
    expect(decryptLogin(legacyCipher(type), USER_KEY)).toMatchObject({
      id: CIPHER_ID,
      type,
      name: `Synced ${type}`,
      ...PAYLOADS[type].fields
    })
  })

  it('decrypts every official field from a sealed cipher blob', () => {
    expect(decryptLogin(blobCipher(type), USER_KEY)).toMatchObject({
      type,
      name: `Blob ${type}`,
      ...PAYLOADS[type].fields
    })
  })

  it('encrypts a new item under the official wire type and payload key', () => {
    const request = encryptLoginRequest(draft(type), USER_KEY, null, ACCOUNT)
    expect(request.type).toBe(PAYLOADS[type].wireType)
    const payload = request[type] as JsonObject
    for (const [name, value] of Object.entries(PAYLOADS[type].fields)) {
      expect(payload[name]).not.toBe(value)
      expect(decryptBitwardenString(payload[name] as string, USER_KEY)).toBe(value)
    }
  })

  it('preserves unknown payload fields when editing a legacy cipher', () => {
    const existing = legacyCipher(type)
    const request = encryptLoginRequest(
      draft(type, { name: 'Edited' }),
      USER_KEY,
      existing,
      ACCOUNT
    )
    expect((request[type] as JsonObject).futureTypedField).toBe('preserve-me')
    expect(request.lastKnownRevisionDate).toBe('2026-11-01T00:00:00.000Z')
  })

  it('preserves unknown blob fields when editing a sealed cipher blob', () => {
    const request = encryptLoginRequest(
      draft(type, { name: 'Edited blob' }),
      USER_KEY,
      blobCipher(type),
      ACCOUNT
    )
    const content = decryptBitwardenCipherBlob(request.data as string, USER_KEY) as JsonObject
    expect(content).toMatchObject({
      name: 'Edited blob',
      futureRootField: 'preserve-root',
      typeData: { type, ...PAYLOADS[type].fields, futureTypedField: { preserve: true } }
    })
  })
})

describe('cipher type boundaries', () => {
  it('still rejects a cipher type newer than passport', () => {
    expect(() => decryptLogin({ ...legacyCipher('passport'), type: 9 }, USER_KEY)).toThrow()
  })
})
