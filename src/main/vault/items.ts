import type { VaultCore } from './core'
import type {
  LoginIdRequest,
  EditorSecretsRequest,
  EditorSecretsView,
  CustomFieldRequest,
  ItemFieldRequest,
  LoginCreateRequest,
  LoginBatchRequest,
  LoginFavoriteRequest,
  LoginOpenUriRequest,
  PasskeyDeleteRequest,
  LoginMoveRequest,
  LoginMoveManyRequest,
  LoginSummary,
  LoginUpdateRequest,
  LoginView,
  VaultSecretField,
  TotpCodeView
} from '../../shared/vault-contract'
import { BITWARDEN_POLICY_TYPE } from '../bitwarden-policy'
import { VaultError } from '../vault-errors'
import { assertUuid, normalizeRequiredString, normalizeNullableString } from './parse-primitives'
import { cloneData } from './vault-data-parsing'
import {
  assertNoPendingPersonalVaultPurge,
  recordSyncDeletion,
  assertNoPendingLoginImport
} from './sync-data-parsing'
import {
  cloneCustomFields,
  normalizeCustomFields,
  customFieldFromSource,
  customFieldValue
} from './custom-fields'
import {
  cloneLoginUris,
  uriAlias,
  createRequestUris,
  updateRequestUris,
  loginUriAt
} from './login-uris'
import type { StoredLogin, VaultPlatform } from './types'
import { findLogin, assertActiveLogin, resolveLoginBatch, normalizeFolderId } from './data-lookup'
import { assertBitwardenPolicyDoesNotBlock, assertPersonalItemTypeAllowed } from './policy'
import { MAX_LOGIN_BATCH_IDS } from '../../shared/vault-contract'
import { generateTotp } from '../totp'
import { MAX_NAME_LENGTH, MAX_NOTES_LENGTH, MAX_ITEM_FIELD_LENGTH } from './limits'
import { toSummary, toView } from './views'
import { cloneItemName } from './login-parsing'
import {
  EDITOR_SECRET_FIELDS_BY_TYPE,
  emptyItemFields,
  normalizeItemFieldsForStorage,
  normalizeItemType,
  normalizeReprompt,
  applyItemFields,
  assertSecretField,
  assertCopyField
} from './item-fields'
import { passwordHistoryAfterEdit } from './password-history'

/** Personal vault items: create, clone, edit, archive, trash, restore, move and favorite, and the reveal, copy, TOTP and open operations that record item usage. */
export class VaultItems {
  constructor(
    private readonly core: VaultCore,
    private readonly platform: VaultPlatform
  ) {}

  createLogin(request: LoginCreateRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      const folderId = normalizeFolderId(data, request.folderId)
      const type = normalizeItemType(request.type ?? 'login')
      assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.OrganizationDataOwnership, data)
      assertPersonalItemTypeAllowed(type, data)
      const fields = emptyItemFields()
      applyItemFields(fields, request, type)
      const uris = createRequestUris(request, type)
      fields.uri = uriAlias(uris)
      const customFields = normalizeCustomFields([], request.customFields ?? [], type)
      const login: StoredLogin = {
        id: this.core.validatedNewId(),
        type,
        name: normalizeRequiredString(request.name, MAX_NAME_LENGTH),
        notes: normalizeNullableString(request.notes, MAX_NOTES_LENGTH),
        folderId,
        favorite: request.favorite ?? false,
        usageCount: 0,
        lastUsedAt: null,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        archivedAt: null,
        reprompt: normalizeReprompt(request.reprompt ?? 0),
        passkeys: [],
        customFields,
        passwordHistory: [],
        passwordRevisionDate: null,
        autofillOnPageLoad: null,
        attachments: [],
        uris,
        ...fields
      }
      if (typeof login.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
      data.logins.push(login)
      return toView(login)
    })
  }

  cloneLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const source = findLogin(data, request.id)
      assertActiveLogin(source)
      assertBitwardenPolicyDoesNotBlock(BITWARDEN_POLICY_TYPE.OrganizationDataOwnership, data)
      assertPersonalItemTypeAllowed(source.type, data)
      const clone: StoredLogin = {
        id: this.core.validatedNewId(),
        type: source.type,
        name: cloneItemName(source.name),
        notes: source.notes,
        folderId: source.folderId,
        favorite: source.favorite,
        usageCount: 0,
        lastUsedAt: null,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        archivedAt: source.archivedAt,
        reprompt: source.reprompt,
        // Bitwarden does not clone passkeys, whose private material must remain bound to the source.
        passkeys: [],
        customFields: cloneCustomFields(source.customFields),
        passwordHistory: [],
        passwordRevisionDate: source.passwordRevisionDate,
        autofillOnPageLoad: source.autofillOnPageLoad,
        attachments: [],
        uris: cloneLoginUris(source.uris),
        // Deliberately build the stored shape instead of spreading the source so future
        // attachment fields cannot accidentally become part of the clone.
        ...normalizeItemFieldsForStorage(source)
      }
      data.logins.push(clone)
      return toView(clone)
    })
  }

  archiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.archivedAt !== null) throw new VaultError('INVALID_INPUT')
      login.archivedAt = now
      login.updatedAt = now
      return toView(login)
    })
  }

  archiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.core.mutate((data, now) => {
      const logins = resolveLoginBatch(data, request, (login) => {
        assertActiveLogin(login)
        if (login.archivedAt !== null) throw new VaultError('INVALID_INPUT')
      })
      return logins.map((login) => {
        login.archivedAt = now
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  unarchiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.archivedAt === null) throw new VaultError('INVALID_INPUT')
      login.archivedAt = null
      login.updatedAt = now
      return toView(login)
    })
  }

  unarchiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.core.mutate((data, now) => {
      const logins = resolveLoginBatch(data, request, (login) => {
        assertActiveLogin(login)
        if (login.archivedAt === null) throw new VaultError('INVALID_INPUT')
      })
      return logins.map((login) => {
        login.archivedAt = null
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  updateLogin(request: LoginUpdateRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      assertPersonalItemTypeAllowed(login.type, data)
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const previousPassword = login.password
      const previousHistory = login.passwordHistory
      const previousCustomFields = login.customFields
      // Normalize the complete post-save set first. Partial editor updates can preserve hidden
      // values that never entered renderer state and therefore must not create false history.
      const nextCustomFields =
        request.customFields === undefined
          ? cloneCustomFields(login.customFields)
          : normalizeCustomFields(login.customFields, request.customFields, login.type)
      if (request.name !== undefined)
        login.name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      applyItemFields(login, request, login.type)
      login.uris = updateRequestUris(request, login)
      login.uri = uriAlias(login.uris)
      if (request.notes !== undefined) {
        login.notes = normalizeNullableString(request.notes, MAX_NOTES_LENGTH)
      }
      if (request.folderId !== undefined) {
        login.folderId = normalizeFolderId(data, request.folderId)
      }
      if (request.favorite !== undefined) {
        if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
        login.favorite = request.favorite
      }
      if (request.reprompt !== undefined) login.reprompt = normalizeReprompt(request.reprompt)
      if (request.customFields !== undefined) login.customFields = nextCustomFields
      login.passwordHistory = passwordHistoryAfterEdit({
        previousHistory,
        retiredPassword:
          login.type === 'login' &&
          request.password !== undefined &&
          previousPassword.length > 0 &&
          login.password !== previousPassword
            ? previousPassword
            : null,
        previousCustomFields,
        nextCustomFields,
        lastUsedDate: () => now
      })
      if (
        login.type === 'login' &&
        request.password !== undefined &&
        login.password !== previousPassword
      ) {
        login.passwordRevisionDate = now
      }
      login.updatedAt = now
      return toView(login)
    })
  }

  deletePasskey(request: PasskeyDeleteRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      if (
        typeof request.credentialId !== 'string' ||
        request.credentialId.length === 0 ||
        request.credentialId.length > MAX_ITEM_FIELD_LENGTH
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (login.type !== 'login') throw new VaultError('INVALID_INPUT')
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const matchingIndexes = login.passkeys.flatMap((passkey, index) =>
        passkey.credentialId === request.credentialId ? [index] : []
      )
      if (matchingIndexes.length === 0) throw new VaultError('NOT_FOUND')
      if (matchingIndexes.length !== 1) throw new VaultError('INVALID_INPUT')
      login.passkeys.splice(matchingIndexes[0]!, 1)
      login.updatedAt = now
      return toView(login)
    })
  }

  deleteLogin(request: LoginIdRequest): Promise<void> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      login.deletedAt = now
      login.updatedAt = now
    })
  }

  deleteLogins(request: LoginBatchRequest): Promise<number> {
    return this.core.mutate((data, now) => {
      const logins = resolveLoginBatch(data, request, (login) => assertActiveLogin(login))
      for (const login of logins) {
        login.deletedAt = now
        login.updatedAt = now
      }
      return logins.length
    })
  }

  restoreLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const login = findLogin(data, request.id)
      if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      login.deletedAt = null
      login.updatedAt = now
      return toView(login)
    })
  }

  restoreLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.core.mutate((data, now) => {
      const logins = resolveLoginBatch(data, request, (login) => {
        if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      })
      return logins.map((login) => {
        login.deletedAt = null
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  deleteLoginPermanently(request: LoginIdRequest): Promise<void> {
    return this.core.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      assertUuid(request.id)
      const login = findLogin(data, request.id)
      if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      recordSyncDeletion(data.sync, 'login', request.id)
      data.logins = data.logins.filter((candidate) => candidate.id !== request.id)
    })
  }

  deleteLoginsPermanently(request: LoginBatchRequest): Promise<number> {
    return this.core.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      const logins = resolveLoginBatch(data, request, (login) => {
        if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      })
      for (const login of logins) recordSyncDeletion(data.sync, 'login', login.id)
      const deletedIds = new Set(logins.map((login) => login.id))
      data.logins = data.logins.filter((login) => !deletedIds.has(login.id))
      return logins.length
    })
  }

  emptyTrash(): Promise<number> {
    return this.core.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      const deleted = data.logins.filter((login) => login.deletedAt !== null)
      for (const login of deleted) recordSyncDeletion(data.sync, 'login', login.id)
      const deletedIds = new Set(deleted.map((login) => login.id))
      data.logins = data.logins.filter((login) => !deletedIds.has(login.id))
      return deleted.length
    })
  }

  setLoginFavorite(request: LoginFavoriteRequest): Promise<LoginSummary> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      login.favorite = request.favorite
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogin(request: LoginMoveRequest): Promise<LoginSummary> {
    return this.core.mutate((data, now) => {
      assertUuid(request.id)
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      login.folderId = normalizeFolderId(data, request.folderId)
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogins(request: LoginMoveManyRequest): Promise<LoginSummary[]> {
    return this.core.mutate((data, now) => {
      if (
        !Array.isArray(request.ids) ||
        request.ids.length === 0 ||
        request.ids.length > MAX_LOGIN_BATCH_IDS
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      request.ids.forEach(assertUuid)
      if (new Set(request.ids).size !== request.ids.length) {
        throw new VaultError('INVALID_INPUT')
      }

      const folderId = normalizeFolderId(data, request.folderId)
      const logins = request.ids.map((id) => findLogin(data, id))
      logins.forEach((login) => assertActiveLogin(login))
      return logins.map((login) => {
        login.folderId = folderId
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  revealPassword(request: LoginIdRequest): Promise<string> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const login = findLogin(this.core.requireData(), request.id)
      assertActiveLogin(login)
      assertSecretField(login.type, 'password')
      return login.password
    })
  }

  revealEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const login = findLogin(this.core.requireData(), request.id)
      assertActiveLogin(login)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')

      const fields: EditorSecretsView['fields'] = {}
      for (const field of EDITOR_SECRET_FIELDS_BY_TYPE[login.type]) {
        Object.assign(fields, { [field]: login[field] })
      }
      const customFields = login.customFields.flatMap((field, index) =>
        field.type === 'hidden'
          ? [
              {
                source: {
                  index,
                  name: field.name,
                  type: field.type,
                  linkedId: field.linkedId
                },
                value: field.value
              }
            ]
          : []
      )
      return { fields, customFields }
    })
  }

  revealSecret(request: ItemFieldRequest): Promise<string> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const login = findLogin(this.core.requireData(), request.id)
      assertActiveLogin(login)
      assertSecretField(login.type, request.field as VaultSecretField)
      return login[request.field] as string
    })
  }

  revealCustomField(request: CustomFieldRequest): Promise<string> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const login = findLogin(this.core.requireData(), request.id)
      assertActiveLogin(login)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const field = customFieldFromSource(login, request.source)
      if (field.type !== 'hidden') throw new VaultError('INVALID_INPUT')
      return field.value
    })
  }

  copyPassword(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertSecretField(login.type, 'password')
      await this.platform.copyText(login.password)
    })
  }

  getTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const login = findLogin(this.core.requireData(), request.id)
      assertActiveLogin(login)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      return generateTotp(login.totp, this.core.now())
    })
  }

  copyTotp(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(generateTotp(login.totp, this.core.now()).code)
    })
  }

  copyField(request: ItemFieldRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, request.field)
      const value =
        request.field === 'uri'
          ? loginUriAt(login, request.uriIndex)
          : request.field === 'cardExpiration'
            ? [login.expMonth, login.expYear].filter(Boolean).join(' / ')
            : login[request.field]
      if (typeof value !== 'string' || value.length === 0) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  copyCustomField(request: CustomFieldRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const value = customFieldValue(login, customFieldFromSource(login, request.source))
      if (!value) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  copyUsername(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, 'username')
      await this.platform.copyText(login.username)
    })
  }

  openLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      assertCopyField(login.type, 'uri')
      const selectedUri = loginUriAt(login, request.uriIndex)
      let url: URL
      try {
        url = new URL(selectedUri)
      } catch {
        throw new VaultError('INVALID_URL')
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new VaultError('INVALID_URL')
      }
      await this.platform.openExternal(url.toString())
    })
  }

  private useLogin<T>(
    request: LoginIdRequest,
    operation: (login: StoredLogin) => Promise<T>
  ): Promise<T> {
    return this.core.exclusive(async () => {
      assertUuid(request.id)
      const current = this.core.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const currentLogin = findLogin(current, request.id)
      assertActiveLogin(currentLogin)
      const result = await operation(currentLogin)
      const next = cloneData(current)
      const usedLogin = findLogin(next, request.id)
      const now = this.core.nowIso()
      usedLogin.usageCount = Math.min(Number.MAX_SAFE_INTEGER, usedLogin.usageCount + 1)
      usedLogin.lastUsedAt = now
      next.updatedAt = now
      await this.core.commit(next)
      return result
    })
  }
}
