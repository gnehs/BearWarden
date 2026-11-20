import type {
  LoginSummary,
  LoginView,
  SharedLoginSummary,
  SharedLoginView,
  VaultCustomFieldView,
  VaultItemType
} from '../../shared/vault-contract'
import { toLoginSummary, toSharedLoginSummary } from '../../shared/login-summary'
import { toPasskeyView } from '../passkey'
import { VaultError } from '../vault-errors'
import { fingerprintLogin, type SyncLogin } from '../sync-merge'
import type { VaultSearchItem } from '../vault-search'
import { cloneAttachments } from './attachments-parsing'
import { cloneLoginUris } from './login-uris'
import type { StoredLogin, StoredSharedLogin } from './types'

export function toSummary(login: StoredLogin): LoginSummary {
  return toLoginSummary(describeLogin(login))
}

export function toSharedSummary(login: StoredSharedLogin): SharedLoginSummary {
  return toSharedLoginSummary({
    ...describeLogin(login),
    organizationId: login.organizationId,
    collectionIds: login.collectionIds,
    shared: true,
    edit: login.edit,
    viewPassword: login.viewPassword,
    delete: login.delete,
    restore: login.restore
  })
}

/** Mirrors the official clients' per-type `subTitle`; secrets never appear beyond a card's last four. */
const SUBTITLE_BY_TYPE: Record<VaultItemType, (login: StoredLogin) => string> = {
  login: (login) => login.username || login.uri || '',
  card: (login) => (login.number.length >= 4 ? `•••• ${login.number.slice(-4)}` : login.brand),
  identity: (login) => joinPresent([login.firstName, login.lastName], ' '),
  secureNote: (login) => summarizeSecureNote(login.notes),
  sshKey: (login) => login.fingerprint || 'SSH key',
  bankAccount: (login) => login.bankName,
  driversLicense: (login) =>
    joinPresent([joinPresent([login.firstName, login.lastName], ' '), login.issuingState], ', '),
  passport: (login) =>
    joinPresent([joinPresent([login.givenName, login.surname], ' '), login.issuingCountry], ', ')
}

function joinPresent(parts: readonly string[], separator: string): string {
  return parts.filter(Boolean).join(separator)
}

function describeLogin(login: StoredLogin): LoginSummary {
  const subtitle = SUBTITLE_BY_TYPE[login.type](login)
  return {
    id: login.id,
    type: login.type,
    name: login.name,
    subtitle,
    username: login.username,
    uri: login.uri,
    uris: login.uris,
    cardBrand: login.brand,
    hasTotp: Boolean(login.totp),
    passkeyCount: login.passkeys.length,
    passwordHistoryCount: login.passwordHistory.length,
    attachmentCount: login.attachments.length,
    folderId: login.folderId,
    favorite: login.favorite,
    usageCount: login.usageCount,
    lastUsedAt: login.lastUsedAt,
    createdAt: login.createdAt,
    updatedAt: login.updatedAt,
    deletedAt: login.deletedAt,
    archivedAt: login.archivedAt,
    reprompt: login.reprompt
  }
}

export function toVaultSearchItem(login: StoredLogin): VaultSearchItem {
  const protectedItem = login.reprompt === 1 || login.deletedAt !== null
  const searchable: VaultSearchItem = {
    id: login.id,
    type: login.type,
    name: login.name,
    reprompt: login.reprompt,
    protected: protectedItem
  }
  if (protectedItem) return searchable

  const summary = toSummary(login)
  return {
    ...searchable,
    subtitle: summary.subtitle,
    notes: login.notes ?? '',
    customFields: login.customFields.map(({ name, value, type }) => ({ name, value, type })),
    attachments: login.attachments.map(({ fileName }) => ({ fileName })),
    ...(login.type === 'login'
      ? {
          username: login.username,
          uri: login.uri,
          uris: login.uris.map(({ uri }) => ({ uri }))
        }
      : {})
  }
}

function summarizeSecureNote(notes: string | null): string {
  const firstLine =
    notes
      ?.split(/\r\n?|\n/u)
      .map((line) => line.trim())
      .find(Boolean) ?? ''
  const graphemes = Array.from(
    new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(firstLine),
    (segment) => segment.segment
  )
  if (graphemes.length <= 80) return firstLine
  return `${graphemes.slice(0, 80).join('')}…`
}

export function toView(login: StoredLogin): LoginView {
  return {
    ...toSummary(login),
    passwordUpdatedAt:
      login.type === 'login' && login.password.length > 0
        ? (validRemoteDate(login.passwordRevisionDate) ?? null)
        : null,
    // This method is only exposed through the main-process authorization gate. Restore fields
    // intentionally redacted from protected list summaries.
    username: login.type === 'login' ? login.username : '',
    uri: login.type === 'login' ? login.uri : null,
    uris: login.type === 'login' ? cloneLoginUris(login.uris) : [],
    notes: login.notes,
    hasTotp: Boolean(login.totp),
    passkeys: login.passkeys.map(toPasskeyView),
    customFields: login.customFields.map((field): VaultCustomFieldView => ({
      ...field,
      value: field.type === 'hidden' || field.type === 'linked' ? null : field.value
    })),
    attachments: cloneAttachments(login.attachments),
    cardholderName: login.cardholderName,
    brand: login.brand,
    expMonth: login.expMonth,
    expYear: login.expYear,
    title: login.title,
    firstName: login.firstName,
    middleName: login.middleName,
    lastName: login.lastName,
    address1: login.address1,
    address2: login.address2,
    address3: login.address3,
    city: login.city,
    state: login.state,
    postalCode: login.postalCode,
    country: login.country,
    company: login.company,
    email: login.email,
    phone: login.phone,
    identityUsername: login.identityUsername,
    publicKey: login.publicKey,
    fingerprint: login.fingerprint,
    bankName: login.bankName,
    nameOnAccount: login.nameOnAccount,
    accountType: login.accountType,
    routingNumber: login.routingNumber,
    branchNumber: login.branchNumber,
    bankContactPhone: login.bankContactPhone,
    dateOfBirth: login.dateOfBirth,
    issuingCountry: login.issuingCountry,
    issuingState: login.issuingState,
    issueDate: login.issueDate,
    expirationDate: login.expirationDate,
    issuingAuthority: login.issuingAuthority,
    licenseClass: login.licenseClass,
    surname: login.surname,
    givenName: login.givenName,
    sex: login.sex,
    birthPlace: login.birthPlace,
    nationality: login.nationality,
    passportType: login.passportType
  }
}

export function toSharedView(login: StoredSharedLogin): SharedLoginView {
  const view = toView(login)
  const safeView = login.viewPassword
    ? view
    : {
        ...view,
        hasTotp: false,
        customFields: view.customFields.map((field) =>
          field.type === 'hidden' ? { ...field, value: null } : field
        )
      }
  return {
    ...safeView,
    organizationId: login.organizationId,
    collectionIds: [...login.collectionIds],
    shared: true,
    edit: login.edit,
    viewPassword: login.viewPassword,
    delete: login.delete,
    restore: login.restore
  }
}

export function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLocaleLowerCase('en-US')
  const normalizedRight = right.toLocaleLowerCase('en-US')
  if (normalizedLeft < normalizedRight) return -1
  if (normalizedLeft > normalizedRight) return 1
  return 0
}

export function validRemoteDate(value: string | null): string | undefined {
  return value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : undefined
}

export function validRemoteDeletedDate(value: string | null): string | null {
  if (value === null) return null
  const parsed = validRemoteDate(value)
  if (!parsed) throw new VaultError('SYNC_FAILED')
  return parsed
}

export function validRemoteArchivedDate(value: string | null): string | null {
  if (value === null) return null
  const parsed = validRemoteDate(value)
  if (!parsed) throw new VaultError('SYNC_FAILED')
  return parsed
}

export function isCompositeRemoteLoginUpdate(
  desired: SyncLogin,
  current: SyncLogin,
  contentChanged: boolean
): boolean {
  const desiredDeleted = desired.deletedAt !== null
  const currentDeleted = current.deletedAt !== null
  const desiredArchived = desired.archivedAt !== null
  const currentArchived = current.archivedAt !== null
  let steps = contentChanged ? 1 : 0
  if (currentDeleted && (!desiredDeleted || contentChanged)) steps += 1
  if (currentArchived && !desiredArchived) steps += 1
  if (!contentChanged && desiredArchived && !currentArchived) steps += 1
  if (desiredDeleted && (!currentDeleted || contentChanged)) steps += 1
  return steps > 1
}

export function sameLoginContentExceptFolder(left: SyncLogin, right: SyncLogin): boolean {
  return (
    fingerprintLogin({ ...left, folderId: null, deletedAt: null, archivedAt: null }, null) ===
    fingerprintLogin({ ...right, folderId: null, deletedAt: null, archivedAt: null }, null)
  )
}
