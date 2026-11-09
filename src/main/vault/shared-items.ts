import type { VaultCore } from './core'
import type { VaultSyncSession } from './sync-session'
import type {
  EditorSecretsRequest,
  EditorSecretsView,
  CustomFieldRequest,
  ItemFieldRequest,
  LoginIdRequest,
  LoginOpenUriRequest,
  SharedLoginCreateRequest,
  SharedLoginUpdateRequest,
  SharedLoginView,
  VaultSecretField,
  TotpCodeView
} from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { generateTotp } from '../totp'
import { MAX_NAME_LENGTH, MAX_NOTES_LENGTH } from './limits'
import { passwordHistoryAfterEdit } from './password-history'
import { assertUuid, normalizeRequiredString, normalizeNullableString } from './parse-primitives'
import { cloneData } from './vault-data-parsing'
import { toSharedView } from './views'
import {
  cloneCustomFields,
  normalizeCustomFields,
  customFieldFromSource,
  customFieldValue
} from './custom-fields'
import { uriAlias, createRequestUris, updateRequestUris, loginUriAt } from './login-uris'
import {
  EDITOR_SECRET_FIELDS_BY_TYPE,
  emptyItemFields,
  normalizeItemType,
  applyItemFields,
  assertSecretField,
  assertCopyField
} from './item-fields'
import type { StoredSharedLogin, VaultPlatform } from './types'
import { remoteDraft } from './sync-snapshots'
import { sharedLoginFromRemote } from './local-records'

/**
 * Organization-shared items: create and update through the server, and reveal, copy, TOTP and
 * open operations gated by the item's view and edit permissions.
 */
export class VaultSharedItems {
  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession,
    private readonly platform: VaultPlatform
  ) {}

  createSharedLogin(request: SharedLoginCreateRequest): Promise<SharedLoginView> {
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      if (!current.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
      if (
        !current.organizations.some((organization) => organization.id === request.organizationId)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.collectionIds.length < 1) throw new VaultError('INVALID_INPUT')
      const collectionIds = new Set(request.collectionIds)
      if (collectionIds.size !== request.collectionIds.length) throw new VaultError('INVALID_INPUT')
      const collections = request.collectionIds.map((collectionId) => {
        const collection = current.collections.find((candidate) => candidate.id === collectionId)
        if (!collection || collection.organizationId !== request.organizationId) {
          throw new VaultError('INVALID_INPUT')
        }
        return collection
      })
      const client = this.syncSession.getOrCreateSyncClient(current.sync)
      if (!client.createOrganizationCipher) throw new VaultError('SYNC_FAILED')

      const type = normalizeItemType(request.type ?? 'login')
      const fields = emptyItemFields()
      applyItemFields(fields, request, type)
      const uris = createRequestUris(request, type)
      fields.uri = uriAlias(uris)
      const customFields = normalizeCustomFields([], request.customFields ?? [], type)
      const now = this.core.nowIso()
      const login: StoredSharedLogin = {
        id: this.core.validatedNewId(),
        type,
        name: normalizeRequiredString(request.name, MAX_NAME_LENGTH),
        notes: normalizeNullableString(request.notes, MAX_NOTES_LENGTH),
        folderId: null,
        favorite: false,
        usageCount: 0,
        lastUsedAt: null,
        createdAt: now,
        updatedAt: now,
        deletedAt: null,
        archivedAt: null,
        reprompt: 0,
        passkeys: [],
        customFields,
        passwordHistory: [],
        passwordRevisionDate: null,
        autofillOnPageLoad: null,
        attachments: [],
        uris,
        organizationId: request.organizationId,
        collectionIds: [...collectionIds],
        shared: true,
        edit: true,
        viewPassword: true,
        delete: true,
        restore: false,
        ...fields
      }

      const generation = this.core.generation
      const abort = this.syncSession.startSyncOperation()
      let remote
      try {
        remote = await client.createOrganizationCipher(
          request.organizationId,
          [...collectionIds],
          remoteDraft(login, null),
          abort.signal
        )
      } catch (error) {
        if (
          abort.signal.aborted ||
          generation !== this.core.generation ||
          this.syncSession.syncClient !== client
        ) {
          throw new VaultError('LOCKED')
        }
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
      }
      if (generation !== this.core.generation || this.syncSession.syncClient !== client) {
        throw new VaultError('LOCKED')
      }
      const created = sharedLoginFromRemote(this.core, remote)
      const remoteCollectionIds = new Set(created.collectionIds)
      if (
        created.organizationId !== request.organizationId ||
        request.collectionIds.some((collectionId) => !remoteCollectionIds.has(collectionId))
      ) {
        throw new VaultError('SYNC_FAILED')
      }
      created.collectionIds = collections.map((collection) => collection.id)
      const next = cloneData(current)
      next.sharedLogins.push(created)
      next.updatedAt = this.core.nowIso()
      await this.core.commit(next, generation)
      return toSharedView(created)
    })
  }

  private findEditableSharedLogin(id: string): StoredSharedLogin {
    assertUuid(id)
    const login = this.core.requireData().sharedLogins.find((candidate) => candidate.id === id)
    if (
      !login ||
      login.deletedAt !== null ||
      login.archivedAt !== null ||
      !login.edit ||
      login.reprompt !== 0
    ) {
      throw new VaultError('NOT_FOUND')
    }
    return login
  }

  private findReadableSharedLogin(id: string): StoredSharedLogin {
    assertUuid(id)
    const login = this.core.requireData().sharedLogins.find((candidate) => candidate.id === id)
    if (
      !login ||
      login.deletedAt !== null ||
      login.archivedAt !== null ||
      !login.viewPassword ||
      login.reprompt !== 0
    ) {
      throw new VaultError('NOT_FOUND')
    }
    return login
  }

  revealSharedSecret(request: ItemFieldRequest): Promise<string> {
    return this.core.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      assertSecretField(login.type, request.field as VaultSecretField)
      return login[request.field] as string
    })
  }

  revealSharedEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.core.exclusive(async () => {
      const login = this.findEditableSharedLogin(request.id)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      if (!login.viewPassword) return { fields: {}, customFields: [] }

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

  updateSharedLogin(request: SharedLoginUpdateRequest): Promise<SharedLoginView> {
    return this.core.exclusive(async () => {
      const current = this.core.requireData()
      const login = this.findEditableSharedLogin(request.id)
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (!current.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
      const client = this.syncSession.getOrCreateSyncClient(current.sync)
      if (!client.editOrganizationCipher) throw new VaultError('SYNC_FAILED')

      const desired = structuredClone(login)
      const previousPassword = desired.password
      const previousHiddenFields = desired.customFields.filter((field) => field.type === 'hidden')
      const nextCustomFields =
        request.customFields === undefined
          ? cloneCustomFields(desired.customFields)
          : normalizeCustomFields(desired.customFields, request.customFields, desired.type)
      if (!login.viewPassword) {
        const secretFields = EDITOR_SECRET_FIELDS_BY_TYPE[login.type]
        if (secretFields.some((field) => request[field] !== undefined)) {
          throw new VaultError('INVALID_INPUT')
        }
        const nextHiddenFields = nextCustomFields.filter((field) => field.type === 'hidden')
        if (
          nextHiddenFields.length !== previousHiddenFields.length ||
          nextHiddenFields.some(
            (field, index) =>
              field.name !== previousHiddenFields[index]?.name ||
              field.value !== previousHiddenFields[index]?.value ||
              field.linkedId !== previousHiddenFields[index]?.linkedId
          )
        ) {
          throw new VaultError('INVALID_INPUT')
        }
      }

      if (request.name !== undefined)
        desired.name = normalizeRequiredString(request.name, MAX_NAME_LENGTH)
      applyItemFields(desired, request, desired.type)
      desired.uris = updateRequestUris(request, desired)
      desired.uri = uriAlias(desired.uris)
      if (request.notes !== undefined) {
        desired.notes = normalizeNullableString(request.notes, MAX_NOTES_LENGTH)
      }
      const previousCustomFields = desired.customFields
      if (request.customFields !== undefined) desired.customFields = nextCustomFields
      const retiresPassword =
        desired.type === 'login' &&
        request.password !== undefined &&
        previousPassword.length > 0 &&
        desired.password !== previousPassword
      desired.passwordHistory = passwordHistoryAfterEdit({
        previousHistory: desired.passwordHistory,
        retiredPassword: retiresPassword ? previousPassword : null,
        previousCustomFields,
        nextCustomFields,
        lastUsedDate: () => this.core.nowIso()
      })
      if (retiresPassword) desired.passwordRevisionDate = this.core.nowIso()

      const generation = this.core.generation
      const abort = this.syncSession.startSyncOperation()
      let remote
      try {
        remote = await client.editOrganizationCipher(
          login.id,
          remoteDraft(desired, login.folderId),
          abort.signal
        )
      } catch (error) {
        if (
          abort.signal.aborted ||
          generation !== this.core.generation ||
          this.syncSession.syncClient !== client
        ) {
          throw new VaultError('LOCKED')
        }
        throw this.syncSession.mapSyncError(error)
      } finally {
        this.syncSession.finishSyncOperation(abort)
      }
      if (generation !== this.core.generation || this.syncSession.syncClient !== client) {
        throw new VaultError('LOCKED')
      }
      const updated = sharedLoginFromRemote(this.core, remote)
      updated.usageCount = login.usageCount
      updated.lastUsedAt = login.lastUsedAt
      const next = cloneData(current)
      const index = next.sharedLogins.findIndex((candidate) => candidate.id === login.id)
      if (index < 0) throw new VaultError('NOT_FOUND')
      next.sharedLogins[index] = updated
      next.updatedAt = this.core.nowIso()
      await this.core.commit(next, generation)
      return toSharedView(updated)
    })
  }

  copySharedField(request: ItemFieldRequest): Promise<void> {
    return this.core.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
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

  revealSharedCustomField(request: CustomFieldRequest): Promise<string> {
    return this.core.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const field = customFieldFromSource(login, request.source)
      if (field.type !== 'hidden') throw new VaultError('INVALID_INPUT')
      return field.value
    })
  }

  copySharedCustomField(request: CustomFieldRequest): Promise<void> {
    return this.core.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const value = customFieldValue(login, customFieldFromSource(login, request.source))
      if (!value) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  getSharedTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.core.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      return generateTotp(login.totp, this.core.now())
    })
  }

  copySharedTotp(request: LoginIdRequest): Promise<void> {
    return this.core.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(generateTotp(login.totp, this.core.now()).code)
    })
  }

  openSharedLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.core.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
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
}
