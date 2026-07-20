import {
  VAULT_LINKED_FIELD_IDS_BY_TYPE,
  type VaultCustomField,
  type VaultCustomFieldSource,
  type VaultCustomFieldUpdate,
  type VaultItemFields,
  type VaultItemType
} from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import {
  MAX_CUSTOM_FIELDS,
  MAX_CUSTOM_FIELD_NAME_LENGTH,
  MAX_CUSTOM_FIELD_VALUE_LENGTH
} from './limits'
import { isRecord } from './parse-primitives'
import type { StoredLogin } from './types'

export function parseCustomField(value: unknown): VaultCustomField {
  if (!isRecord(value)) throw new VaultError('CORRUPT_VAULT')
  if (
    typeof value.name !== 'string' ||
    value.name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
    typeof value.value !== 'string' ||
    value.value.length > MAX_CUSTOM_FIELD_VALUE_LENGTH ||
    (value.type !== 'text' &&
      value.type !== 'hidden' &&
      value.type !== 'boolean' &&
      value.type !== 'linked') ||
    (value.linkedId !== null &&
      (!Number.isSafeInteger(value.linkedId) || (value.linkedId as number) < 0))
  ) {
    throw new VaultError('CORRUPT_VAULT')
  }
  return {
    name: value.name,
    value: value.value,
    type: value.type,
    linkedId: value.linkedId as number | null
  }
}

export function cloneCustomFields(fields: readonly VaultCustomField[]): VaultCustomField[] {
  return fields.map((field) => ({ ...field }))
}

export function normalizeCustomFields(
  existing: readonly VaultCustomField[],
  updates: unknown,
  itemType: VaultItemType
): VaultCustomField[] {
  if (!Array.isArray(updates) || updates.length > MAX_CUSTOM_FIELDS) {
    throw new VaultError('INVALID_INPUT')
  }

  const linkedIds = VAULT_LINKED_FIELD_IDS_BY_TYPE[itemType] as readonly number[]
  const sourceIndexes = new Set<number>()

  return updates.map((candidate): VaultCustomField => {
    if (!isRecord(candidate)) throw new VaultError('INVALID_INPUT')
    const update = candidate as unknown as VaultCustomFieldUpdate
    if (
      typeof update.name !== 'string' ||
      update.name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
      (update.type !== 'text' &&
        update.type !== 'hidden' &&
        update.type !== 'boolean' &&
        update.type !== 'linked') ||
      (update.value !== null &&
        (typeof update.value !== 'string' ||
          update.value.length > MAX_CUSTOM_FIELD_VALUE_LENGTH)) ||
      (update.linkedId !== null && (!Number.isSafeInteger(update.linkedId) || update.linkedId < 0))
    ) {
      throw new VaultError('INVALID_INPUT')
    }

    let sourceField: VaultCustomField | null = null
    if (update.source !== null) {
      if (!isRecord(update.source)) throw new VaultError('INVALID_INPUT')
      const { index, name, type, linkedId } = update.source
      if (
        !Number.isSafeInteger(index) ||
        index < 0 ||
        sourceIndexes.has(index) ||
        typeof name !== 'string' ||
        name.length > MAX_CUSTOM_FIELD_NAME_LENGTH ||
        (type !== 'text' && type !== 'hidden' && type !== 'boolean' && type !== 'linked') ||
        (linkedId !== null && (!Number.isSafeInteger(linkedId) || linkedId < 0))
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      sourceIndexes.add(index)
      sourceField = existing[index] ?? null
      if (
        !sourceField ||
        sourceField.name !== name ||
        sourceField.type !== type ||
        sourceField.linkedId !== linkedId
      ) {
        throw new VaultError('INVALID_INPUT')
      }
    }

    if (update.type === 'linked') {
      if (
        update.value !== null ||
        update.linkedId === null ||
        !linkedIds.includes(update.linkedId)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      return { name: update.name, type: update.type, value: '', linkedId: update.linkedId }
    }
    if (update.linkedId !== null) throw new VaultError('INVALID_INPUT')

    if (update.value === null) {
      if (update.type !== 'hidden' || sourceField?.type !== 'hidden') {
        throw new VaultError('INVALID_INPUT')
      }
      return { name: update.name, type: update.type, value: sourceField.value, linkedId: null }
    }
    if (update.type === 'boolean' && update.value !== 'true' && update.value !== 'false') {
      throw new VaultError('INVALID_INPUT')
    }
    return { name: update.name, type: update.type, value: update.value, linkedId: null }
  })
}

export function customFieldFromSource(
  login: StoredLogin,
  source: VaultCustomFieldSource
): VaultCustomField {
  const { index } = source
  if (!Number.isSafeInteger(index) || index < 0 || index >= login.customFields.length) {
    throw new VaultError('INVALID_INPUT')
  }
  const field = login.customFields[index]!
  if (
    field.name !== source.name ||
    field.type !== source.type ||
    field.linkedId !== source.linkedId
  ) {
    throw new VaultError('INVALID_INPUT')
  }
  return field
}

export function linkedCustomFieldValue(login: StoredLogin, linkedId: number | null): string {
  if (login.type === 'login') {
    if (linkedId === 100) return login.username
    if (linkedId === 101) return login.password
  } else if (login.type === 'card') {
    const fields: Partial<Record<number, keyof VaultItemFields>> = {
      300: 'cardholderName',
      301: 'expMonth',
      302: 'expYear',
      303: 'code',
      304: 'brand',
      305: 'number'
    }
    const field = linkedId === null ? undefined : fields[linkedId]
    if (field) return String(login[field] ?? '')
  } else if (login.type === 'identity') {
    if (linkedId === 418) {
      return [login.title, login.firstName, login.middleName, login.lastName]
        .filter(Boolean)
        .join(' ')
    }
    const fields: Partial<Record<number, keyof VaultItemFields>> = {
      400: 'title',
      401: 'middleName',
      402: 'address1',
      403: 'address2',
      404: 'address3',
      405: 'city',
      406: 'state',
      407: 'postalCode',
      408: 'country',
      409: 'company',
      410: 'email',
      411: 'phone',
      412: 'ssn',
      413: 'identityUsername',
      414: 'passportNumber',
      415: 'licenseNumber',
      416: 'firstName',
      417: 'lastName'
    }
    const field = linkedId === null ? undefined : fields[linkedId]
    if (field) return String(login[field] ?? '')
  }
  throw new VaultError('INVALID_INPUT')
}

export function customFieldValue(login: StoredLogin, field: VaultCustomField): string {
  return field.type === 'linked' ? linkedCustomFieldValue(login, field.linkedId) : field.value
}
