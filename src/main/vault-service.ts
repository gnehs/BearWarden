import type {
  EditorSecretsRequest,
  EditorSecretsView,
  CredentialGeneratorRequest,
  CredentialGeneratorResult,
  CustomFieldRequest,
  ItemFieldRequest,
  GeneratedCredentialCopyRequest,
  GeneratorHistoryEntry,
  GeneratorHistoryLocator,
  LoginCreateRequest,
  LoginAuthorizeRequest,
  LoginAuthorizeManyRequest,
  LoginBatchRequest,
  LoginFavoriteRequest,
  LoginIdRequest,
  LoginOpenUriRequest,
  PasskeyDeleteRequest,
  LoginMoveRequest,
  LoginMoveManyRequest,
  LoginSummary,
  LoginUpdateRequest,
  LoginView,
  SharedLoginCreateRequest,
  SharedLoginUpdateRequest,
  SharedLoginView,
  VaultPasswordHistoryEntry,
  VaultReprompt,
  VaultSecretField,
  TotpCodeView
} from '../shared/vault-contract'
import { MAX_LOGIN_AUTHORIZE_MANY_IDS, MAX_LOGIN_MOVE_MANY_IDS } from '../shared/vault-contract'
import { VaultError } from './vault-errors'
import { BITWARDEN_POLICY_TYPE } from './bitwarden-policy'
import {
  createPasskeyCredential as createSoftwarePasskeyCredential,
  getPasskeyAssertion as createSoftwarePasskeyAssertion
} from './passkey-authenticator'
import { generateTotp } from './totp'
import type { SshKeyMaterial } from './ssh-key'
import { signSshAgentData as createSshAgentSignature } from './ssh-agent-crypto'
import { SSH_AGENT_MAX_MESSAGE_LENGTH } from './ssh-agent-protocol'
import {
  fetchWebsiteIconDataUrl,
  parseWebsiteHostname,
  resolveWebsiteIconUrl
} from './website-icon'
import { createUriMatchBudget, loginUrisMatch } from './uri-matcher'
import type {
  AutofillAuthorizationValidator,
  AutofillCredentialConsumer,
  AutofillDiscoveryResult,
  AutofillExecutionRequest
} from './autofill'
import { validatePasskeyOrigin } from './passkey-origin-validation'
import {
  MAX_MASTER_PASSWORD_LENGTH,
  MAX_NAME_LENGTH,
  MAX_URI_LENGTH,
  MAX_NOTES_LENGTH,
  MAX_ITEM_FIELD_LENGTH,
  MAX_PASSWORD_HISTORY
} from './vault/limits'
import {
  assertUuid,
  normalizeRequiredString,
  normalizeNullableString
} from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import { toSharedView, toSummary, toView, compareText } from './vault/views'
import {
  recordSyncDeletion,
  assertNoPendingLoginImport,
  assertNoPendingPersonalVaultPurge
} from './vault/sync-data-parsing'
import { cloneItemName } from './vault/login-parsing'
import {
  normalizePasskeyRpId,
  normalizePasskeyCredentialId,
  normalizePasskeyCredentialIds,
  assertPasskeyApproval,
  findPasskeyVaultMatches,
  activeVaultContainsCredentialId
} from './vault/passkey-parsing'
import {
  cloneCustomFields,
  normalizeCustomFields,
  customFieldFromSource,
  customFieldValue
} from './vault/custom-fields'
import {
  cloneLoginUris,
  uriAlias,
  createRequestUris,
  updateRequestUris,
  loginUriAt
} from './vault/login-uris'
import {
  EDITOR_SECRET_FIELDS_BY_TYPE,
  emptyItemFields,
  normalizeItemFieldsForStorage,
  normalizeItemType,
  normalizeReprompt,
  applyItemFields,
  assertSecretField,
  assertCopyField
} from './vault/item-fields'
import { parseSupportedSshAgentPublicKeyBlob, sshAgentFingerprint } from './vault/ssh-helpers'
import { clonePasswordHistory } from './vault/password-history'
import type {
  StoredLogin,
  StoredSharedLogin,
  SshAgentVaultIdentity,
  SshAgentVaultSignRequest,
  SshAgentVaultSignResult,
  SshAgentVaultAuthorizationValidator,
  PasskeyVaultAuthorizationValidator,
  PasskeyVaultDiscoveryRequest,
  PasskeyVaultDiscoveryResult,
  PasskeyVaultCreationTarget,
  PasskeyVaultCreationTargetDiscoveryResult,
  PasskeyVaultCreationTargetDiscoveryRequest,
  PasskeyVaultCreateRequest,
  PasskeyVaultCreateResult,
  PasskeyVaultAssertionRequest,
  PasskeyVaultAssertionResult
} from './vault/types'
import type { ItemReadAuthorizationValidator } from './vault-service-base'
import { VaultTransferService } from './vault-transfer-service'

export type {
  PersistedSyncData,
  VaultMasterPasswordChangeStatus,
  VaultMasterPasswordChangeRequest,
  VaultMasterPasswordChangeResolutionRequest,
  VaultMasterPasswordChangeResolution,
  VaultPlatform,
  VaultAccountWebAuthnRequest,
  VaultAccountWebAuthnAssertionRequester,
  VaultAccountWebAuthnRegistrationRequest,
  VaultAccountWebAuthnRegistrationRequester,
  VaultServiceOptions,
  VaultExportSnapshot,
  VaultNativeAttachmentBackupSource,
  VaultNativeAttachmentRestoreSummary,
  SshAgentVaultIdentity,
  SshAgentVaultSignRequest,
  SshAgentVaultSignResult,
  SshAgentVaultAuthorizationValidator,
  PasskeyVaultAuthorizationValidator,
  PasskeyVaultCredentialCandidate,
  PasskeyVaultDiscoveryRequest,
  PasskeyVaultDiscoveryResult,
  PasskeyVaultCreationTarget,
  PasskeyVaultCreationTargetDiscoveryResult,
  PasskeyVaultCreationTargetDiscoveryRequest,
  PasskeyVaultCreateRequest,
  PasskeyVaultCreateResult,
  PasskeyVaultAssertionRequest,
  PasskeyVaultAssertionResult
} from './vault/types'

/** Stable public entry point for item, autofill, passkey, SSH, and generator operations. */
export class VaultService extends VaultTransferService {
  createSharedLogin(request: SharedLoginCreateRequest): Promise<SharedLoginView> {
    return this.exclusive(async () => {
      const current = this.requireData()
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
      const client = this.getOrCreateSyncClient(current.sync)
      if (!client.createOrganizationCipher) throw new VaultError('SYNC_FAILED')

      const type = normalizeItemType(request.type ?? 'login')
      const fields = emptyItemFields()
      applyItemFields(fields, request, type)
      const uris = createRequestUris(request, type)
      fields.uri = uriAlias(uris)
      const customFields = normalizeCustomFields([], request.customFields ?? [], type)
      const now = this.nowIso()
      const login: StoredSharedLogin = {
        id: this.validatedNewId(),
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

      const generation = this.generation
      const abort = this.startSyncOperation()
      let remote
      try {
        remote = await client.createOrganizationCipher(
          request.organizationId,
          [...collectionIds],
          this.remoteDraft(login, null),
          abort.signal
        )
      } catch (error) {
        if (abort.signal.aborted || generation !== this.generation || this.syncClient !== client) {
          throw new VaultError('LOCKED')
        }
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
      if (generation !== this.generation || this.syncClient !== client) {
        throw new VaultError('LOCKED')
      }
      const created = this.sharedLoginFromRemote(remote)
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
      next.updatedAt = this.nowIso()
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return toSharedView(created)
    })
  }

  private findEditableSharedLogin(id: string): StoredSharedLogin {
    assertUuid(id)
    const login = this.requireData().sharedLogins.find((candidate) => candidate.id === id)
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
    const login = this.requireData().sharedLogins.find((candidate) => candidate.id === id)
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
    return this.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      assertSecretField(login.type, request.field as VaultSecretField)
      return login[request.field] as string
    })
  }

  revealSharedEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.exclusive(async () => {
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
    return this.exclusive(async () => {
      const current = this.requireData()
      const login = this.findEditableSharedLogin(request.id)
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (!current.sync) throw new VaultError('SYNC_AUTH_REQUIRED')
      const client = this.getOrCreateSyncClient(current.sync)
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
      if (request.customFields !== undefined) desired.customFields = nextCustomFields
      if (
        desired.type === 'login' &&
        request.password !== undefined &&
        previousPassword.length > 0 &&
        desired.password !== previousPassword
      ) {
        desired.passwordHistory = [
          { password: previousPassword, lastUsedDate: this.nowIso() },
          ...desired.passwordHistory
        ].slice(0, MAX_PASSWORD_HISTORY)
        desired.passwordRevisionDate = this.nowIso()
      }

      const generation = this.generation
      const abort = this.startSyncOperation()
      let remote
      try {
        remote = await client.editOrganizationCipher(
          login.id,
          this.remoteDraft(desired, login.folderId),
          abort.signal
        )
      } catch (error) {
        if (abort.signal.aborted || generation !== this.generation || this.syncClient !== client) {
          throw new VaultError('LOCKED')
        }
        throw this.mapSyncError(error)
      } finally {
        this.finishSyncOperation(abort)
      }
      if (generation !== this.generation || this.syncClient !== client) {
        throw new VaultError('LOCKED')
      }
      const updated = this.sharedLoginFromRemote(remote)
      updated.usageCount = login.usageCount
      updated.lastUsedAt = login.lastUsedAt
      const next = cloneData(current)
      const index = next.sharedLogins.findIndex((candidate) => candidate.id === login.id)
      if (index < 0) throw new VaultError('NOT_FOUND')
      next.sharedLogins[index] = updated
      next.updatedAt = this.nowIso()
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return toSharedView(updated)
    })
  }

  copySharedField(request: ItemFieldRequest): Promise<void> {
    return this.exclusive(async () => {
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
    return this.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const field = customFieldFromSource(login, request.source)
      if (field.type !== 'hidden') throw new VaultError('INVALID_INPUT')
      return field.value
    })
  }

  copySharedCustomField(request: CustomFieldRequest): Promise<void> {
    return this.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (request.expectedUpdatedAt !== login.updatedAt) throw new VaultError('INVALID_INPUT')
      const value = customFieldValue(login, customFieldFromSource(login, request.source))
      if (!value) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(value)
    })
  }

  getSharedTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      return generateTotp(login.totp, this.now())
    })
  }

  copySharedTotp(request: LoginIdRequest): Promise<void> {
    return this.exclusive(async () => {
      const login = this.findReadableSharedLogin(request.id)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(generateTotp(login.totp, this.now()).code)
    })
  }

  openSharedLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.exclusive(async () => {
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

  generateCredential(request: CredentialGeneratorRequest): Promise<CredentialGeneratorResult> {
    return this.generatorService.generateCredential(request)
  }

  copyGeneratedCredential(request: GeneratedCredentialCopyRequest): Promise<void> {
    return this.generatorService.copyGeneratedCredential(request)
  }

  generateSshKey(): Promise<SshKeyMaterial> {
    return this.generatorService.generateSshKey()
  }

  generatorHistory(): Promise<GeneratorHistoryEntry[]> {
    return this.generatorService.history()
  }

  clearGeneratorHistory(): Promise<void> {
    return this.generatorService.clearHistory()
  }

  copyGeneratorHistory(request: GeneratorHistoryLocator): Promise<void> {
    return this.generatorService.copyHistory(request)
  }

  loginAuthorizationState(request: LoginIdRequest): Promise<{
    reprompt: VaultReprompt
    generation: number
  }> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      return { reprompt: login.reprompt, generation: this.generation }
    })
  }

  /**
   * Returns a point-in-time public identity snapshot for the main-process SSH Agent. Invalid or
   * unsupported public keys are omitted rather than allowing unusable identities onto the wire.
   */
  listSshAgentIdentities(): Promise<SshAgentVaultIdentity[]> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const generation = this.generation
      const identities: SshAgentVaultIdentity[] = []
      for (const login of data.logins) {
        if (login.type !== 'sshKey' || login.deletedAt !== null || login.archivedAt !== null) {
          continue
        }
        const publicKeyBlob = parseSupportedSshAgentPublicKeyBlob(login.publicKey)
        if (!publicKeyBlob) continue
        identities.push({
          itemId: login.id,
          name: login.name,
          publicKeyBlob,
          fingerprint: sshAgentFingerprint(publicKeyBlob),
          reprompt: login.reprompt,
          generation
        })
      }
      return identities
    })
  }

  /**
   * Signs inside the vault mutex after atomically re-checking the item and its reprompt policy.
   * The validator is intentionally synchronous so an approval capability cannot be raced by sync.
   */
  signSshAgentRequest(
    request: SshAgentVaultSignRequest,
    validateAuthorization: SshAgentVaultAuthorizationValidator
  ): Promise<SshAgentVaultSignResult> {
    return this.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      if (
        !Buffer.isBuffer(request.publicKeyBlob) ||
        request.publicKeyBlob.length === 0 ||
        request.publicKeyBlob.length > SSH_AGENT_MAX_MESSAGE_LENGTH ||
        !Buffer.isBuffer(request.data) ||
        request.data.length > SSH_AGENT_MAX_MESSAGE_LENGTH ||
        (request.rsaHash !== undefined &&
          request.rsaHash !== 'sha256' &&
          request.rsaHash !== 'sha512') ||
        !Number.isSafeInteger(request.expectedGeneration) ||
        request.expectedGeneration < 0
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      if (request.expectedGeneration !== this.generation) throw new VaultError('LOCKED')

      const matches = this.requireData().logins.filter((login) => {
        if (login.type !== 'sshKey' || login.deletedAt !== null || login.archivedAt !== null) {
          return false
        }
        return parseSupportedSshAgentPublicKeyBlob(login.publicKey)?.equals(request.publicKeyBlob)
      })
      if (matches.length === 0) throw new VaultError('NOT_FOUND')
      // The public key is the protocol identifier. Refuse an ambiguous duplicate instead of
      // accidentally selecting the copy with the weaker reprompt policy.
      if (matches.length !== 1) throw new VaultError('INVALID_INPUT')
      const login = matches[0]!

      authorize([login.id])
      const signature = createSshAgentSignature(
        login.privateKey,
        request.publicKeyBlob,
        request.data,
        request.rsaHash
      )
      if (request.expectedGeneration !== this.generation) throw new VaultError('LOCKED')
      return {
        itemId: login.id,
        generation: this.generation,
        algorithm: signature.algorithm,
        signature: signature.signature
      }
    })
  }

  /**
   * Main-process authorization boundary. The validator must be synchronous: keeping it and the
   * nested service operation in this same exclusive section prevents sync from enabling reprompt
   * between the check and secret access.
   */
  runAuthorizedOperation<T>(
    validate: (ids: readonly string[], state: { generation: number }) => boolean,
    operation: (authorize: (ids: readonly string[]) => void) => Promise<T>
  ): Promise<T> {
    return this.exclusive(async () => {
      let didAuthorize = false
      const authorize = (ids: readonly string[]): void => {
        didAuthorize = true
        let requiresReprompt = false
        for (const id of ids) {
          assertUuid(id)
          const login = this.findLogin(this.requireData(), id)
          if (login.reprompt === 1) requiresReprompt = true
        }
        if (requiresReprompt && !validate(ids, { generation: this.generation })) {
          throw new VaultError('REPROMPT_REQUIRED')
        }
      }
      const result = await operation(authorize)
      if (!didAuthorize) throw new VaultError('INTERNAL_ERROR')
      return result
    })
  }

  authorizeLogin(request: LoginAuthorizeRequest): Promise<number> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      this.findLogin(this.requireData(), request.id)
      if (typeof request.masterPassword !== 'string') throw new VaultError('INVALID_INPUT')
      const candidate = request.masterPassword.normalize('NFC')
      if (candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      const generation = this.generation
      if (!this.key || !this.salt) throw new VaultError('LOCKED')
      const valid = await this.store.verifyMasterPassword(candidate, this.key, this.salt)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (!valid) throw new VaultError('INVALID_MASTER_PASSWORD')
      return generation
    })
  }

  authorizeLogins(request: LoginAuthorizeManyRequest): Promise<number> {
    return this.exclusive(async () => {
      if (
        !Array.isArray(request.ids) ||
        request.ids.length === 0 ||
        request.ids.length > MAX_LOGIN_AUTHORIZE_MANY_IDS ||
        new Set(request.ids).size !== request.ids.length
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      for (const id of request.ids) {
        assertUuid(id)
        this.findLogin(this.requireData(), id)
      }
      if (typeof request.masterPassword !== 'string') throw new VaultError('INVALID_INPUT')
      const candidate = request.masterPassword.normalize('NFC')
      if (candidate.length > MAX_MASTER_PASSWORD_LENGTH) {
        throw new VaultError('INVALID_MASTER_PASSWORD')
      }
      const generation = this.generation
      if (!this.key || !this.salt) throw new VaultError('LOCKED')
      const valid = await this.store.verifyMasterPassword(candidate, this.key, this.salt)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (!valid) throw new VaultError('INVALID_MASTER_PASSWORD')
      return generation
    })
  }

  createLogin(request: LoginCreateRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      const folderId = this.normalizeFolderId(data, request.folderId)
      const type = normalizeItemType(request.type ?? 'login')
      this.assertBitwardenPolicyDoesNotBlock(
        BITWARDEN_POLICY_TYPE.OrganizationDataOwnership,
        'POLICY_RESTRICTED',
        data
      )
      this.assertPersonalItemTypeAllowed(type, data)
      const fields = emptyItemFields()
      applyItemFields(fields, request, type)
      const uris = createRequestUris(request, type)
      fields.uri = uriAlias(uris)
      const customFields = normalizeCustomFields([], request.customFields ?? [], type)
      const login: StoredLogin = {
        id: this.validatedNewId(),
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
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const source = this.findLogin(data, request.id)
      this.assertActiveLogin(source)
      this.assertBitwardenPolicyDoesNotBlock(
        BITWARDEN_POLICY_TYPE.OrganizationDataOwnership,
        'POLICY_RESTRICTED',
        data
      )
      this.assertPersonalItemTypeAllowed(source.type, data)
      const clone: StoredLogin = {
        id: this.validatedNewId(),
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
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.archivedAt !== null) throw new VaultError('INVALID_INPUT')
      login.archivedAt = now
      login.updatedAt = now
      return toView(login)
    })
  }

  archiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => {
        this.assertActiveLogin(login)
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
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (login.archivedAt === null) throw new VaultError('INVALID_INPUT')
      login.archivedAt = null
      login.updatedAt = now
      return toView(login)
    })
  }

  unarchiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => {
        this.assertActiveLogin(login)
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
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      this.assertPersonalItemTypeAllowed(login.type, data)
      if (
        request.expectedUpdatedAt !== undefined &&
        (typeof request.expectedUpdatedAt !== 'string' ||
          request.expectedUpdatedAt !== login.updatedAt)
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const previousPassword = login.password
      const previousHistory = clonePasswordHistory(login.passwordHistory)
      const previousHiddenFields = login.customFields.filter(
        (field) => field.type === 'hidden' && field.name.length > 0 && field.value.length > 0
      )
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
        login.folderId = this.normalizeFolderId(data, request.folderId)
      }
      if (request.favorite !== undefined) {
        if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
        login.favorite = request.favorite
      }
      if (request.reprompt !== undefined) login.reprompt = normalizeReprompt(request.reprompt)
      if (request.customFields !== undefined) login.customFields = nextCustomFields
      const newHistory: VaultPasswordHistoryEntry[] = []
      if (
        login.type === 'login' &&
        request.password !== undefined &&
        previousPassword.length > 0 &&
        login.password !== previousPassword
      ) {
        newHistory.unshift({ password: previousPassword, lastUsedDate: now })
      }
      const consumedNextHiddenFields = new Set<number>()
      for (const field of previousHiddenFields) {
        const unchangedIndex = nextCustomFields.findIndex(
          (candidate, index) =>
            !consumedNextHiddenFields.has(index) &&
            candidate.type === 'hidden' &&
            candidate.name === field.name &&
            candidate.value === field.value
        )
        if (unchangedIndex >= 0) {
          consumedNextHiddenFields.add(unchangedIndex)
        } else {
          newHistory.unshift({ password: `${field.name}: ${field.value}`, lastUsedDate: now })
        }
      }
      login.passwordHistory = [...newHistory, ...previousHistory].slice(0, MAX_PASSWORD_HISTORY)
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
    return this.mutate((data, now) => {
      assertUuid(request.id)
      if (
        typeof request.credentialId !== 'string' ||
        request.credentialId.length === 0 ||
        request.credentialId.length > MAX_ITEM_FIELD_LENGTH
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
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

  /**
   * Discovers URL matches without exposing passwords. The URL is validated and matching stays in
   * main so a compromised renderer cannot ask for a broad vault search disguised as AutoFill.
   */
  discoverAutofillCandidates(targetUrl: string): Promise<AutofillDiscoveryResult> {
    return this.exclusive(async () => {
      let canonicalUrl: string
      try {
        const parsed = new URL(targetUrl)
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          throw new VaultError('INVALID_INPUT')
        }
        parsed.username = ''
        parsed.password = ''
        canonicalUrl = parsed.toString()
      } catch (error) {
        if (error instanceof VaultError) throw error
        throw new VaultError('INVALID_INPUT')
      }
      if (canonicalUrl.length > MAX_URI_LENGTH) throw new VaultError('INVALID_INPUT')

      const data = this.requireData()
      const hostname = new URL(canonicalUrl).hostname
      const matchBudget = createUriMatchBudget()
      const usageCounts = new Map(data.logins.map((login) => [login.id, login.usageCount]))
      const candidates = data.logins.flatMap((login) => {
        if (
          login.type !== 'login' ||
          login.deletedAt !== null ||
          login.archivedAt !== null ||
          !loginUrisMatch(
            login.uris,
            canonicalUrl,
            data.sync?.domainSettings ?? null,
            0,
            matchBudget
          )
        ) {
          return []
        }
        return [
          {
            id: login.id,
            name: login.name,
            // Preserve the existing reprompt privacy rule used by vault summaries.
            username: login.reprompt === 1 ? '' : login.username,
            hostname,
            reprompt: login.reprompt,
            updatedAt: login.updatedAt
          }
        ]
      })
      candidates.sort((left, right) => {
        const usageDifference = (usageCounts.get(right.id) ?? 0) - (usageCounts.get(left.id) ?? 0)
        return usageDifference || compareText(left.name, right.name)
      })
      return { generation: this.generation, targetUrl: canonicalUrl, candidates }
    })
  }

  /**
   * Atomically revalidates the URL match and revision, authorizes reprompt, consumes credentials
   * inside main, and records usage only after the native fill succeeds.
   */
  performAutofill(
    request: AutofillExecutionRequest,
    validateAuthorization: AutofillAuthorizationValidator,
    consume: AutofillCredentialConsumer
  ): Promise<void> {
    return this.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      if (
        !Number.isSafeInteger(request.expectedGeneration) ||
        request.expectedGeneration < 0 ||
        request.expectedGeneration !== this.generation
      ) {
        throw new VaultError('LOCKED')
      }
      assertUuid(request.itemId)
      if (typeof request.expectedUpdatedAt !== 'string') throw new VaultError('INVALID_INPUT')

      let canonicalUrl: string
      try {
        const parsed = new URL(request.targetUrl)
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          throw new VaultError('INVALID_INPUT')
        }
        parsed.username = ''
        parsed.password = ''
        canonicalUrl = parsed.toString()
      } catch (error) {
        if (error instanceof VaultError) throw error
        throw new VaultError('INVALID_INPUT')
      }
      if (canonicalUrl.length > MAX_URI_LENGTH) throw new VaultError('INVALID_INPUT')

      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const login = this.findLogin(current, request.itemId)
      this.assertActiveLogin(login)
      if (
        login.type !== 'login' ||
        login.archivedAt !== null ||
        login.updatedAt !== request.expectedUpdatedAt ||
        !loginUrisMatch(
          login.uris,
          canonicalUrl,
          current.sync?.domainSettings ?? null,
          0,
          createUriMatchBudget()
        )
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      authorize([login.id])
      const generation = this.generation
      await consume({ username: login.username, password: login.password })
      if (generation !== this.generation) throw new VaultError('LOCKED')

      const next = cloneData(current)
      const usedLogin = this.findLogin(next, login.id)
      const now = this.nowIso()
      usedLogin.usageCount = Math.min(Number.MAX_SAFE_INTEGER, usedLogin.usageCount + 1)
      usedLogin.lastUsedAt = now
      next.updatedAt = now
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
    })
  }

  /** Main-process-only discovery. It deliberately returns metadata rather than stored keys. */
  discoverPasskeyCredentials(
    request: PasskeyVaultDiscoveryRequest
  ): Promise<PasskeyVaultDiscoveryResult> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const rpId = normalizePasskeyRpId(request.rpId)
      const allowCredentialIds = normalizePasskeyCredentialIds(request.allowCredentialIds)
      const matches = findPasskeyVaultMatches(data, rpId, allowCredentialIds)
      return {
        generation: this.generation,
        credentials: matches.map(({ login, passkey, credentialId }) => ({
          itemId: login.id,
          itemName: login.name,
          itemUpdatedAt: login.updatedAt,
          reprompt: login.reprompt,
          credentialId: Uint8Array.from(credentialId),
          rpId: passkey.rpId,
          userHandle: passkey.userHandle,
          userName: passkey.userName,
          userDisplayName: passkey.userDisplayName,
          discoverable: passkey.discoverable
        }))
      }
    })
  }

  /**
   * Returns one atomic unlocked-vault snapshot for a passkey-create picker. Read raw stored
   * logins rather than list summaries: protected summaries intentionally redact passkey counts.
   */
  discoverPasskeyCreationTargets(
    request: PasskeyVaultCreationTargetDiscoveryRequest
  ): Promise<PasskeyVaultCreationTargetDiscoveryResult> {
    return this.exclusive(async () => {
      const data = this.requireData()
      const rpId = normalizePasskeyRpId(request.rpId)
      let targetUri: string
      try {
        targetUri = validatePasskeyOrigin({ origin: request.origin, rpId }).origin
      } catch {
        throw new VaultError('INVALID_INPUT')
      }
      const targets: PasskeyVaultCreationTarget[] = []
      const matchBudget = createUriMatchBudget()
      for (const login of data.logins) {
        if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null) {
          continue
        }
        if (
          !loginUrisMatch(login.uris, targetUri, data.sync?.domainSettings ?? null, 0, matchBudget)
        ) {
          continue
        }
        // Bitwarden permits only one passkey per login item. Legacy/corrupt multi-passkey items
        // are excluded fail-closed instead of offering an ambiguous replacement target.
        if (login.passkeys.length > 1) continue
        const existingPasskeyCount: 0 | 1 = login.passkeys.length === 0 ? 0 : 1
        targets.push({
          itemId: login.id,
          itemName: login.name,
          itemUpdatedAt: login.updatedAt,
          reprompt: login.reprompt,
          existingPasskeyCount
        })
      }
      return { generation: this.generation, targets }
    })
  }

  /**
   * Creates and persists a software-authenticator credential without allowing its private key to
   * leave this service. The validator and userVerified value must come from a main-process
   * ceremony coordinator.
   */
  createPasskey(
    request: PasskeyVaultCreateRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultCreateResult> {
    return this.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.assertExpectedPasskeyGeneration(request.expectedGeneration)
      assertUuid(request.itemId)
      const next = cloneData(current)
      const login = this.findLogin(next, request.itemId)
      this.assertActiveLogin(login)
      if (login.type !== 'login' || login.archivedAt !== null) {
        throw new VaultError('INVALID_INPUT')
      }
      this.assertExpectedPasskeyRevision(login, request.expectedUpdatedAt)
      if (typeof request.replaceExisting !== 'boolean') throw new VaultError('INVALID_INPUT')
      if (login.passkeys.length > 1 || (login.passkeys.length === 1 && !request.replaceExisting)) {
        throw new VaultError('INVALID_INPUT')
      }
      assertPasskeyApproval(request.requireUserVerification, request.userVerified)
      const rpId = normalizePasskeyRpId(request.rpId)
      const excludeCredentialIds = normalizePasskeyCredentialIds(request.excludeCredentialIds)
      if (
        excludeCredentialIds.some((credentialId) =>
          activeVaultContainsCredentialId(current, rpId, credentialId)
        )
      ) {
        throw new VaultError('INVALID_INPUT')
      }

      authorize([login.id])
      const generation = this.generation
      const now = this.nowIso()
      const created = await createSoftwarePasskeyCredential(
        {
          rpId,
          rpName: request.rpName,
          userHandle: request.userHandle,
          userName: request.userName,
          userDisplayName: request.userDisplayName,
          discoverable: request.discoverable,
          userVerified: request.userVerified,
          userPresent: true
        },
        {
          uuid: () => this.validatedNewId(),
          now: () => new Date(now)
        }
      )
      if (generation !== this.generation) throw new VaultError('LOCKED')
      const credentialId = Buffer.from(created.credentialId)
      if (activeVaultContainsCredentialId(current, rpId, credentialId)) {
        throw new VaultError('INVALID_INPUT')
      }

      login.passkeys = [created.credential]
      if (login.username.length === 0) login.username = created.credential.userName ?? ''
      login.updatedAt = now
      next.updatedAt = now
      await this.persist(next)
      if (generation !== this.generation) throw new VaultError('LOCKED')
      this.data = next
      return {
        item: toView(login),
        generation,
        credentialId: Uint8Array.from(created.credentialId),
        attestationObject: Uint8Array.from(created.attestationObject),
        authenticatorData: Uint8Array.from(created.authenticatorData),
        publicKey: Uint8Array.from(created.publicKey),
        publicKeyAlgorithm: created.publicKeyAlgorithm
      }
    })
  }

  /** Signs one assertion and atomically commits an enabled signature counter. */
  getPasskeyAssertion(
    request: PasskeyVaultAssertionRequest,
    validateAuthorization: PasskeyVaultAuthorizationValidator
  ): Promise<PasskeyVaultAssertionResult> {
    return this.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      const current = this.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.assertExpectedPasskeyGeneration(request.expectedGeneration)
      assertUuid(request.itemId)
      const rpId = normalizePasskeyRpId(request.rpId)
      const requestedCredentialId = normalizePasskeyCredentialId(request.credentialId)
      const allowCredentialIds = normalizePasskeyCredentialIds(request.allowCredentialIds)
      const matches = findPasskeyVaultMatches(current, rpId, allowCredentialIds)
      const selected = matches.filter(
        (match) =>
          match.login.id === request.itemId && match.credentialId.equals(requestedCredentialId)
      )
      if (selected.length === 0) throw new VaultError('NOT_FOUND')
      if (selected.length !== 1) throw new VaultError('INVALID_INPUT')
      const match = selected[0]!
      this.assertExpectedPasskeyRevision(match.login, request.expectedUpdatedAt)
      assertPasskeyApproval(request.requireUserVerification, request.userVerified)

      authorize([match.login.id])
      const generation = this.generation
      const assertion = await createSoftwarePasskeyAssertion({
        credential: match.passkey,
        rpId,
        clientDataHash: request.clientDataHash,
        userVerified: request.userVerified,
        userPresent: true
      })
      if (generation !== this.generation) throw new VaultError('LOCKED')
      if (assertion.counter !== match.passkey.counter) {
        const next = cloneData(current)
        const nextLogin = this.findLogin(next, match.login.id)
        const nextPasskey = nextLogin.passkeys[match.passkeyIndex]
        if (
          nextPasskey === undefined ||
          nextPasskey.credentialId !== match.passkey.credentialId ||
          nextPasskey.counter !== match.passkey.counter
        ) {
          throw new VaultError('LOCKED')
        }
        const now = this.nowIso()
        nextPasskey.counter = assertion.counter
        nextLogin.updatedAt = now
        next.updatedAt = now
        await this.persist(next)
        if (generation !== this.generation) throw new VaultError('LOCKED')
        this.data = next
      }
      return {
        itemId: match.login.id,
        generation,
        credentialId: Uint8Array.from(assertion.credentialId),
        userHandle: assertion.userHandle === null ? null : Uint8Array.from(assertion.userHandle),
        authenticatorData: Uint8Array.from(assertion.authenticatorData),
        signature: Uint8Array.from(assertion.signature),
        counter: assertion.counter,
        didPersistCounter: assertion.counter !== match.passkey.counter
      }
    })
  }

  deleteLogin(request: LoginIdRequest): Promise<void> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      login.deletedAt = now
      login.updatedAt = now
    })
  }

  deleteLogins(request: LoginBatchRequest): Promise<number> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => this.assertActiveLogin(login))
      for (const login of logins) {
        login.deletedAt = now
        login.updatedAt = now
      }
      return logins.length
    })
  }

  restoreLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      login.deletedAt = null
      login.updatedAt = now
      return toView(login)
    })
  }

  restoreLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      const logins = this.resolveLoginBatch(data, request, (login) => {
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
    return this.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      recordSyncDeletion(data.sync, 'login', request.id)
      data.logins = data.logins.filter((candidate) => candidate.id !== request.id)
    })
  }

  deleteLoginsPermanently(request: LoginBatchRequest): Promise<number> {
    return this.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      const logins = this.resolveLoginBatch(data, request, (login) => {
        if (login.deletedAt === null) throw new VaultError('INVALID_INPUT')
      })
      for (const login of logins) recordSyncDeletion(data.sync, 'login', login.id)
      const deletedIds = new Set(logins.map((login) => login.id))
      data.logins = data.logins.filter((login) => !deletedIds.has(login.id))
      return logins.length
    })
  }

  emptyTrash(): Promise<number> {
    return this.mutate((data) => {
      assertNoPendingLoginImport(data.sync)
      const deleted = data.logins.filter((login) => login.deletedAt !== null)
      for (const login of deleted) recordSyncDeletion(data.sync, 'login', login.id)
      const deletedIds = new Set(deleted.map((login) => login.id))
      data.logins = data.logins.filter((login) => !deletedIds.has(login.id))
      return deleted.length
    })
  }

  setLoginFavorite(request: LoginFavoriteRequest): Promise<LoginSummary> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      if (typeof request.favorite !== 'boolean') throw new VaultError('INVALID_INPUT')
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      login.favorite = request.favorite
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogin(request: LoginMoveRequest): Promise<LoginSummary> {
    return this.mutate((data, now) => {
      assertUuid(request.id)
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      login.folderId = this.normalizeFolderId(data, request.folderId)
      login.updatedAt = now
      return toSummary(login)
    })
  }

  moveLogins(request: LoginMoveManyRequest): Promise<LoginSummary[]> {
    return this.mutate((data, now) => {
      if (
        !Array.isArray(request.ids) ||
        request.ids.length === 0 ||
        request.ids.length > MAX_LOGIN_MOVE_MANY_IDS
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      request.ids.forEach(assertUuid)
      if (new Set(request.ids).size !== request.ids.length) {
        throw new VaultError('INVALID_INPUT')
      }

      const folderId = this.normalizeFolderId(data, request.folderId)
      const logins = request.ids.map((id) => this.findLogin(data, id))
      logins.forEach((login) => this.assertActiveLogin(login))
      return logins.map((login) => {
        login.folderId = folderId
        login.updatedAt = now
        return toSummary(login)
      })
    })
  }

  revealPassword(request: LoginIdRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      assertSecretField(login.type, 'password')
      return login.password
    })
  }

  revealEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
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
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      assertSecretField(login.type, request.field as VaultSecretField)
      return login[request.field] as string
    })
  }

  revealCustomField(request: CustomFieldRequest): Promise<string> {
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
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
    return this.exclusive(async () => {
      assertUuid(request.id)
      const login = this.findLogin(this.requireData(), request.id)
      this.assertActiveLogin(login)
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      return generateTotp(login.totp, this.now())
    })
  }

  copyTotp(request: LoginIdRequest): Promise<void> {
    return this.useLogin(request, async (login) => {
      if (login.type !== 'login' || !login.totp) throw new VaultError('INVALID_INPUT')
      await this.platform.copyText(generateTotp(login.totp, this.now()).code)
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

  async getWebsiteIcon(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string | null> {
    const iconUrl = (() => {
      assertUuid(request.id)
      const data = this.requireFastReadData()
      const login = this.findLogin(data, request.id)
      this.assertActiveLogin(login)
      if (
        login.reprompt === 1 &&
        !validateAuthorization?.([login.id], { generation: this.generation })
      ) {
        throw new VaultError('REPROMPT_REQUIRED')
      }
      if (login.type !== 'login' || !login.uri || !data.sync) return null
      const hostname = parseWebsiteHostname(login.uri)
      return hostname ? resolveWebsiteIconUrl(data.sync.serverUrl, hostname) : null
    })()
    if (!iconUrl) return null

    const cacheKey = iconUrl.toString()
    if (this.websiteIconCache.has(cacheKey)) return this.websiteIconCache.get(cacheKey) ?? null
    const existingRequest = this.websiteIconRequests.get(cacheKey)
    if (existingRequest) return existingRequest

    const generation = this.generation
    const pendingRequest = fetchWebsiteIconDataUrl(iconUrl, this.fetch)
      .then((dataUrl) => {
        if (generation !== this.generation) return null
        if (this.websiteIconCache.size >= 128) {
          const oldestKey = this.websiteIconCache.keys().next().value
          if (oldestKey) this.websiteIconCache.delete(oldestKey)
        }
        this.websiteIconCache.set(cacheKey, dataUrl)
        return dataUrl
      })
      .finally(() => {
        if (this.websiteIconRequests.get(cacheKey) === pendingRequest) {
          this.websiteIconRequests.delete(cacheKey)
        }
      })
    this.websiteIconRequests.set(cacheKey, pendingRequest)
    return pendingRequest
  }
}
