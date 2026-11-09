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
  TotpCodeView,
  SendCreateRequest,
  SendFileCreateRequest,
  SendFileCreateResult,
  SendFileDownloadRequest,
  SendFileDownloadResult,
  SendIdRequest,
  SendUpdateRequest,
  SendView,
  FolderCreateRequest,
  FolderDeleteRequest,
  FolderReorderRequest,
  FolderReparentRequest,
  FolderUpdateRequest,
  FolderView,
  VaultHealthExposedReport,
  VaultHealthAccountBreachReport,
  VaultHealthAccountBreachRequest,
  VaultHealthReport,
  LoginListRequest,
  LoginPrefetchRequest,
  OrganizationView,
  CollectionView,
  SharedLoginListRequest,
  SharedLoginSummary,
  EmergencyAccessView,
  PasswordHistoryEntryRequest,
  PasswordHistoryRestoreRequest,
  VaultPasswordHistoryView,
  AttachmentProgressEvent,
  CardCoverPreviewResult,
  AttachmentCancelRequest,
  AttachmentCancelResult,
  AttachmentDeleteRequest,
  AttachmentDeleteResult,
  AttachmentDownloadRequest,
  AttachmentDownloadResult,
  AttachmentFixLegacyRequest,
  AttachmentFixLegacyResult,
  AttachmentPreviewRequest,
  AttachmentPreviewResult,
  AttachmentUploadCardCoverRequest,
  AttachmentUploadRequest,
  AttachmentUploadResult,
  VaultImportResult
} from '../shared/vault-contract'
import { VaultError } from './vault-errors'
import {
  createPasskeyCredential as createSoftwarePasskeyCredential,
  getPasskeyAssertion as createSoftwarePasskeyAssertion
} from './passkey-authenticator'
import type { SshKeyMaterial } from './ssh-key'
import { signSshAgentData as createSshAgentSignature } from './ssh-agent-crypto'
import { SSH_AGENT_MAX_MESSAGE_LENGTH } from './ssh-agent-protocol'
import {
  fetchWebsiteIcon,
  parseWebsiteHostname,
  resolveWebsiteIconUrl,
  websiteIconDataUrl
} from './website-icon'
import { clearImageCacheKeys } from './encrypted-image-cache'
import { createUriMatchBudget, loginUrisMatch } from './uri-matcher'
import type {
  AutofillAuthorizationValidator,
  AutofillCredentialConsumer,
  AutofillDiscoveryResult,
  AutofillExecutionRequest
} from './autofill'
import { validatePasskeyOrigin } from './passkey-origin-validation'
import { MAX_URI_LENGTH } from './vault/limits'
import { assertUuid } from './vault/parse-primitives'
import { cloneData } from './vault/vault-data-parsing'
import { toView, compareText } from './vault/views'
import { assertNoPendingPersonalVaultPurge } from './vault/sync-data-parsing'
import {
  normalizePasskeyRpId,
  normalizePasskeyCredentialId,
  normalizePasskeyCredentialIds,
  assertPasskeyApproval,
  findPasskeyVaultMatches,
  activeVaultContainsCredentialId
} from './vault/passkey-parsing'
import { parseSupportedSshAgentPublicKeyBlob, sshAgentFingerprint } from './vault/ssh-helpers'
import type {
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
  PasskeyVaultAssertionResult,
  VaultData,
  ItemReadAuthorizationValidator,
  AttachmentAuthorizationValidator,
  VaultExportSnapshot,
  VaultNativeAttachmentBackupSource,
  VaultNativeAttachmentRestoreSummary
} from './vault/types'
import { VaultAccountService } from './vault-account-service'
import { findLogin, assertActiveLogin, assertExpectedPasskeyRevision } from './vault/data-lookup'
import type { InactiveTwoFactorReport, TwoFactorDirectoryDataset } from './inactive-two-factor'
import type { PortableVaultSnapshot } from './vault-portability-codec'
import type { NativeAttachmentRestoreAttachmentKey } from './native-attachment-restore'
import type { NativeAttachmentBackupPreview } from './native-attachment-backup'
import type { BitwardenAttachmentByteSource } from './bitwarden-attachment-stream'
export type {
  VaultAccountWebAuthnAssertionRequester,
  VaultAccountWebAuthnRegistrationRequester,
  VaultServiceOptions,
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

const WEBSITE_ICON_TTL_MS = 7 * 24 * 60 * 60 * 1000
const WEBSITE_ICON_MISSING_TTL_MS = 24 * 60 * 60 * 1000
const WEBSITE_ICON_RETRY_MS = 10 * 60 * 1000

/** Stable public entry point for item, autofill, passkey, SSH, and generator operations. */
export class VaultService extends VaultAccountService {
  /**
   * Test-only view of the committed in-memory snapshot, for planting records the public API cannot
   * create and trapping reads of protected fields. Production code must not call it.
   */
  committedSnapshotForTesting(): VaultData | null {
    return this.core.currentData()
  }

  createSharedLogin(request: SharedLoginCreateRequest): Promise<SharedLoginView> {
    return this.sharedItems.createSharedLogin(request)
  }

  revealSharedSecret(request: ItemFieldRequest): Promise<string> {
    return this.sharedItems.revealSharedSecret(request)
  }

  revealSharedEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.sharedItems.revealSharedEditorSecrets(request)
  }

  updateSharedLogin(request: SharedLoginUpdateRequest): Promise<SharedLoginView> {
    return this.sharedItems.updateSharedLogin(request)
  }

  copySharedField(request: ItemFieldRequest): Promise<void> {
    return this.sharedItems.copySharedField(request)
  }

  revealSharedCustomField(request: CustomFieldRequest): Promise<string> {
    return this.sharedItems.revealSharedCustomField(request)
  }

  copySharedCustomField(request: CustomFieldRequest): Promise<void> {
    return this.sharedItems.copySharedCustomField(request)
  }

  getSharedTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.sharedItems.getSharedTotp(request)
  }

  copySharedTotp(request: LoginIdRequest): Promise<void> {
    return this.sharedItems.copySharedTotp(request)
  }

  openSharedLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.sharedItems.openSharedLoginUri(request)
  }

  listSends(): Promise<SendView[]> {
    return this.sendService.list()
  }

  createSend(request: SendCreateRequest): Promise<SendView> {
    return this.sendService.create(request)
  }

  async createFileSend(request: SendFileCreateRequest): Promise<SendFileCreateResult> {
    return this.sendService.createFile(request)
  }

  async downloadFileSend(request: SendFileDownloadRequest): Promise<SendFileDownloadResult> {
    return this.sendService.downloadFile(request)
  }

  updateSend(request: SendUpdateRequest): Promise<SendView> {
    return this.sendService.update(request)
  }

  removeSendPassword(request: SendIdRequest): Promise<SendView> {
    return this.sendService.removePassword(request)
  }

  deleteSend(request: SendIdRequest): Promise<void> {
    return this.sendService.delete(request)
  }

  copySendLink(request: SendIdRequest): Promise<void> {
    return this.sendService.copyLink(request)
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

  /**
   * Returns a point-in-time public identity snapshot for the main-process SSH Agent. Invalid or
   * unsupported public keys are omitted rather than allowing unusable identities onto the wire.
   */
  listSshAgentIdentities(): Promise<SshAgentVaultIdentity[]> {
    return this.core.exclusive(async () => {
      const data = this.core.requireData()
      const generation = this.core.generation
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
    return this.authorization.runAuthorizedOperation(validateAuthorization, async (authorize) => {
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
      if (request.expectedGeneration !== this.core.generation) throw new VaultError('LOCKED')

      const matches = this.core.requireData().logins.filter((login) => {
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
      if (request.expectedGeneration !== this.core.generation) throw new VaultError('LOCKED')
      return {
        itemId: login.id,
        generation: this.core.generation,
        algorithm: signature.algorithm,
        signature: signature.signature
      }
    })
  }

  runAuthorizedOperation<T>(
    validate: (ids: readonly string[], state: { generation: number }) => boolean,
    operation: (authorize: (ids: readonly string[]) => void) => Promise<T>
  ): Promise<T> {
    return this.authorization.runAuthorizedOperation(validate, operation)
  }

  authorizeLogin(request: LoginAuthorizeRequest): Promise<number> {
    return this.authorization.authorizeLogin(request)
  }

  authorizeLogins(request: LoginAuthorizeManyRequest): Promise<number> {
    return this.authorization.authorizeLogins(request)
  }

  createLogin(request: LoginCreateRequest): Promise<LoginView> {
    return this.items.createLogin(request)
  }

  cloneLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.cloneLogin(request)
  }

  archiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.archiveLogin(request)
  }

  archiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.items.archiveLogins(request)
  }

  unarchiveLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.unarchiveLogin(request)
  }

  unarchiveLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.items.unarchiveLogins(request)
  }

  updateLogin(request: LoginUpdateRequest): Promise<LoginView> {
    return this.items.updateLogin(request)
  }

  deletePasskey(request: PasskeyDeleteRequest): Promise<LoginView> {
    return this.items.deletePasskey(request)
  }

  /**
   * Discovers URL matches without exposing passwords. The URL is validated and matching stays in
   * main so a compromised renderer cannot ask for a broad vault search disguised as AutoFill.
   */
  discoverAutofillCandidates(targetUrl: string): Promise<AutofillDiscoveryResult> {
    return this.core.exclusive(async () => {
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

      const data = this.core.requireData()
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
      return { generation: this.core.generation, targetUrl: canonicalUrl, candidates }
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
    return this.authorization.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      if (
        !Number.isSafeInteger(request.expectedGeneration) ||
        request.expectedGeneration < 0 ||
        request.expectedGeneration !== this.core.generation
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

      const current = this.core.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      const login = findLogin(current, request.itemId)
      assertActiveLogin(login)
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
      const generation = this.core.generation
      await consume({ username: login.username, password: login.password })
      if (generation !== this.core.generation) throw new VaultError('LOCKED')

      const next = cloneData(current)
      const usedLogin = findLogin(next, login.id)
      const now = this.core.nowIso()
      usedLogin.usageCount = Math.min(Number.MAX_SAFE_INTEGER, usedLogin.usageCount + 1)
      usedLogin.lastUsedAt = now
      next.updatedAt = now
      await this.core.commit(next, generation)
    })
  }

  /** Main-process-only discovery. It deliberately returns metadata rather than stored keys. */
  discoverPasskeyCredentials(
    request: PasskeyVaultDiscoveryRequest
  ): Promise<PasskeyVaultDiscoveryResult> {
    return this.core.exclusive(async () => {
      const data = this.core.requireData()
      const rpId = normalizePasskeyRpId(request.rpId)
      const allowCredentialIds = normalizePasskeyCredentialIds(request.allowCredentialIds)
      const matches = findPasskeyVaultMatches(data, rpId, allowCredentialIds)
      return {
        generation: this.core.generation,
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
    return this.core.exclusive(async () => {
      const data = this.core.requireData()
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
      return { generation: this.core.generation, targets }
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
    return this.authorization.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      const current = this.core.requireData()
      assertNoPendingPersonalVaultPurge(current.sync)
      this.assertExpectedPasskeyGeneration(request.expectedGeneration)
      assertUuid(request.itemId)
      const next = cloneData(current)
      const login = findLogin(next, request.itemId)
      assertActiveLogin(login)
      if (login.type !== 'login' || login.archivedAt !== null) {
        throw new VaultError('INVALID_INPUT')
      }
      assertExpectedPasskeyRevision(login, request.expectedUpdatedAt)
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
      const generation = this.core.generation
      const now = this.core.nowIso()
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
          uuid: () => this.core.validatedNewId(),
          now: () => new Date(now)
        }
      )
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      const credentialId = Buffer.from(created.credentialId)
      if (activeVaultContainsCredentialId(current, rpId, credentialId)) {
        throw new VaultError('INVALID_INPUT')
      }

      login.passkeys = [created.credential]
      if (login.username.length === 0) login.username = created.credential.userName ?? ''
      login.updatedAt = now
      next.updatedAt = now
      await this.core.commit(next, generation)
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
    return this.authorization.runAuthorizedOperation(validateAuthorization, async (authorize) => {
      const current = this.core.requireData()
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
      assertExpectedPasskeyRevision(match.login, request.expectedUpdatedAt)
      assertPasskeyApproval(request.requireUserVerification, request.userVerified)

      authorize([match.login.id])
      const generation = this.core.generation
      const assertion = await createSoftwarePasskeyAssertion({
        credential: match.passkey,
        rpId,
        clientDataHash: request.clientDataHash,
        userVerified: request.userVerified,
        userPresent: true
      })
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      if (assertion.counter !== match.passkey.counter) {
        const next = cloneData(current)
        const nextLogin = findLogin(next, match.login.id)
        const nextPasskey = nextLogin.passkeys[match.passkeyIndex]
        if (
          nextPasskey === undefined ||
          nextPasskey.credentialId !== match.passkey.credentialId ||
          nextPasskey.counter !== match.passkey.counter
        ) {
          throw new VaultError('LOCKED')
        }
        const now = this.core.nowIso()
        nextPasskey.counter = assertion.counter
        nextLogin.updatedAt = now
        next.updatedAt = now
        await this.core.commit(next, generation)
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
    return this.items.deleteLogin(request)
  }

  deleteLogins(request: LoginBatchRequest): Promise<number> {
    return this.items.deleteLogins(request)
  }

  restoreLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.items.restoreLogin(request)
  }

  restoreLogins(request: LoginBatchRequest): Promise<LoginSummary[]> {
    return this.items.restoreLogins(request)
  }

  deleteLoginPermanently(request: LoginIdRequest): Promise<void> {
    return this.items.deleteLoginPermanently(request)
  }

  deleteLoginsPermanently(request: LoginBatchRequest): Promise<number> {
    return this.items.deleteLoginsPermanently(request)
  }

  emptyTrash(): Promise<number> {
    return this.items.emptyTrash()
  }

  setLoginFavorite(request: LoginFavoriteRequest): Promise<LoginSummary> {
    return this.items.setLoginFavorite(request)
  }

  moveLogin(request: LoginMoveRequest): Promise<LoginSummary> {
    return this.items.moveLogin(request)
  }

  moveLogins(request: LoginMoveManyRequest): Promise<LoginSummary[]> {
    return this.items.moveLogins(request)
  }

  revealPassword(request: LoginIdRequest): Promise<string> {
    return this.items.revealPassword(request)
  }

  revealEditorSecrets(request: EditorSecretsRequest): Promise<EditorSecretsView> {
    return this.items.revealEditorSecrets(request)
  }

  revealSecret(request: ItemFieldRequest): Promise<string> {
    return this.items.revealSecret(request)
  }

  revealCustomField(request: CustomFieldRequest): Promise<string> {
    return this.items.revealCustomField(request)
  }

  copyPassword(request: LoginIdRequest): Promise<void> {
    return this.items.copyPassword(request)
  }

  getTotp(request: LoginIdRequest): Promise<TotpCodeView> {
    return this.items.getTotp(request)
  }

  copyTotp(request: LoginIdRequest): Promise<void> {
    return this.items.copyTotp(request)
  }

  copyField(request: ItemFieldRequest): Promise<void> {
    return this.items.copyField(request)
  }

  copyCustomField(request: CustomFieldRequest): Promise<void> {
    return this.items.copyCustomField(request)
  }

  copyUsername(request: LoginIdRequest): Promise<void> {
    return this.items.copyUsername(request)
  }

  openLoginUri(request: LoginOpenUriRequest): Promise<void> {
    return this.items.openLoginUri(request)
  }

  async getWebsiteIcon(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string | null> {
    const iconUrl = (() => {
      assertUuid(request.id)
      const data = this.core.requireFastReadData()
      const login = findLogin(data, request.id)
      assertActiveLogin(login)
      if (
        login.reprompt === 1 &&
        !validateAuthorization?.([login.id], { generation: this.core.generation })
      ) {
        throw new VaultError('REPROMPT_REQUIRED')
      }
      if (login.type !== 'login' || !login.uri || !data.sync) return null
      const hostname = parseWebsiteHostname(login.uri)
      return hostname ? resolveWebsiteIconUrl(data.sync.serverUrl, hostname) : null
    })()
    if (!iconUrl) return null

    const cacheKey = iconUrl.toString()
    const cached = this.websiteIconCache.get(cacheKey)
    if (cached) return cached.value
    const existingRequest = this.websiteIconRequests.get(cacheKey)
    if (existingRequest) return existingRequest

    const pendingRequest = this.loadWebsiteIcon(cacheKey, iconUrl).finally(() => {
      if (this.websiteIconRequests.get(cacheKey) === pendingRequest) {
        this.websiteIconRequests.delete(cacheKey)
      }
    })
    this.websiteIconRequests.set(cacheKey, pendingRequest)
    return pendingRequest
  }

  /** Memory LRU miss: try the encrypted disk cache, then a concurrency-limited fetch. */
  private async loadWebsiteIcon(cacheKey: string, iconUrl: URL): Promise<string | null> {
    const generation = this.core.generation
    const keys = this.imageCacheKeys()
    const abort = new AbortController()
    this.imageRequestAborts.add(abort)
    try {
      const stored = keys ? await this.imageCache?.read(keys, 'website-icon', cacheKey) : null
      if (generation !== this.core.generation) return null
      const storedValue =
        stored?.mediaType && stored.data ? websiteIconDataUrl(stored.mediaType, stored.data) : null
      stored?.data?.fill(0)
      const storedTtl = stored?.mediaType ? WEBSITE_ICON_TTL_MS : WEBSITE_ICON_MISSING_TTL_MS
      if (stored && stored.storedAt + storedTtl > this.core.now().getTime()) {
        this.rememberWebsiteIcon(cacheKey, storedValue, storedTtl)
        return storedValue
      }

      let result: Awaited<ReturnType<typeof fetchWebsiteIcon>>
      try {
        result = await this.websiteIconFetches.run(
          () => fetchWebsiteIcon(iconUrl, this.fetch, abort.signal),
          abort.signal
        )
      } catch {
        return null
      }
      if (generation !== this.core.generation) return null

      if (result.kind === 'failed') {
        // Keep showing a stale icon instead of a letter, and retry the network later.
        if (stored) this.rememberWebsiteIcon(cacheKey, storedValue, WEBSITE_ICON_RETRY_MS)
        return storedValue
      }
      const storedAt = this.core.now().getTime()
      const value =
        result.kind === 'icon' ? websiteIconDataUrl(result.mediaType, result.data) : null
      if (keys) {
        void this.imageCache?.write(keys, 'website-icon', cacheKey, {
          mediaType: result.kind === 'icon' ? result.mediaType : null,
          data: result.kind === 'icon' ? result.data : null,
          storedAt
        })
      }
      this.rememberWebsiteIcon(
        cacheKey,
        value,
        result.kind === 'icon' ? WEBSITE_ICON_TTL_MS : WEBSITE_ICON_MISSING_TTL_MS
      )
      return value
    } finally {
      this.imageRequestAborts.delete(abort)
      if (keys) clearImageCacheKeys(keys)
    }
  }

  private rememberWebsiteIcon(cacheKey: string, value: string | null, ttlMs: number): void {
    this.websiteIconCache.set(cacheKey, value, { size: value?.length ?? 0, ttlMs })
  }

  listFolders(): Promise<FolderView[]> {
    return this.folders.listFolders()
  }

  createFolder(request: FolderCreateRequest): Promise<FolderView> {
    return this.folders.createFolder(request)
  }

  updateFolder(request: FolderUpdateRequest): Promise<FolderView[]> {
    return this.folders.updateFolder(request)
  }

  reparentFolder(request: FolderReparentRequest): Promise<FolderView[]> {
    return this.folders.reparentFolder(request)
  }

  deleteFolder(request: FolderDeleteRequest): Promise<void> {
    return this.folders.deleteFolder(request)
  }

  reorderFolders(request: FolderReorderRequest): Promise<FolderView[]> {
    return this.folders.reorderFolders(request)
  }

  getHealthReport(): Promise<VaultHealthReport> {
    return this.health.getHealthReport()
  }

  getInactiveTwoFactorReport(dataset: TwoFactorDirectoryDataset): Promise<InactiveTwoFactorReport> {
    return this.health.getInactiveTwoFactorReport(dataset)
  }

  getExposedPasswordReport(): Promise<VaultHealthExposedReport> {
    return this.health.getExposedPasswordReport()
  }

  cancelExposedPasswordReport(): boolean {
    return this.health.cancelExposedPasswordReport()
  }

  getAccountBreachReport(
    request: VaultHealthAccountBreachRequest
  ): Promise<VaultHealthAccountBreachReport> {
    return this.health.getAccountBreachReport(request)
  }

  cancelAccountBreachReport(): boolean {
    return this.health.cancelAccountBreachReport()
  }

  openHibpWebsite(): Promise<void> {
    return this.health.openHibpWebsite()
  }

  listLogins(request: LoginListRequest = {}): Promise<LoginSummary[]> {
    return this.listings.listLogins(request)
  }

  listOrganizations(): Promise<OrganizationView[]> {
    return this.listings.listOrganizations()
  }

  listCollections(organizationId?: string): Promise<CollectionView[]> {
    return this.listings.listCollections(organizationId)
  }

  listSharedLogins(request: SharedLoginListRequest = {}): Promise<SharedLoginSummary[]> {
    return this.listings.listSharedLogins(request)
  }

  getSharedLogin(request: LoginIdRequest): Promise<SharedLoginView> {
    return this.listings.getSharedLogin(request)
  }

  listEmergencyAccess(): Promise<EmergencyAccessView[]> {
    return this.listings.listEmergencyAccess()
  }

  getLogin(request: LoginIdRequest): Promise<LoginView> {
    return this.listings.getLogin(request)
  }

  prefetchLogins(request: LoginPrefetchRequest): Promise<LoginView[]> {
    return this.listings.prefetchLogins(request)
  }

  getPasswordHistory(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryEntry[]> {
    return this.passwordHistory.getPasswordHistory(request, validateAuthorization)
  }

  getPasswordHistoryView(
    request: LoginIdRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<VaultPasswordHistoryView> {
    return this.passwordHistory.getPasswordHistoryView(request, validateAuthorization)
  }

  revealPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<string> {
    return this.passwordHistory.revealPasswordHistory(request, validateAuthorization)
  }

  copyPasswordHistory(
    request: PasswordHistoryEntryRequest,
    validateAuthorization?: ItemReadAuthorizationValidator
  ): Promise<void> {
    return this.passwordHistory.copyPasswordHistory(request, validateAuthorization)
  }

  restorePasswordHistory(request: PasswordHistoryRestoreRequest): Promise<LoginView> {
    return this.passwordHistory.restorePasswordHistory(request)
  }

  downloadAttachment(
    request: AttachmentDownloadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDownloadResult> {
    return this.attachments.downloadAttachment(request, reportProgress, validateAuthorization)
  }

  getCardCoverPreview(
    request: LoginIdRequest,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<CardCoverPreviewResult | null> {
    return this.attachments.getCardCoverPreview(request, validateAuthorization)
  }

  previewAttachment(
    request: AttachmentPreviewRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentPreviewResult> {
    return this.attachments.previewAttachment(request, reportProgress, validateAuthorization)
  }

  uploadAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    return this.attachments.uploadAttachment(request, reportProgress, validateAuthorization)
  }

  uploadCardCoverAttachment(
    request: AttachmentUploadCardCoverRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    return this.attachments.uploadCardCoverAttachment(
      request,
      reportProgress,
      validateAuthorization
    )
  }

  uploadCardCoverFileAttachment(
    request: AttachmentUploadRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentUploadResult> {
    return this.attachments.uploadCardCoverFileAttachment(
      request,
      reportProgress,
      validateAuthorization
    )
  }

  deleteAttachment(
    request: AttachmentDeleteRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentDeleteResult> {
    return this.attachments.deleteAttachment(request, reportProgress, validateAuthorization)
  }

  fixLegacyAttachment(
    request: AttachmentFixLegacyRequest,
    reportProgress?: (progress: AttachmentProgressEvent) => void,
    validateAuthorization?: AttachmentAuthorizationValidator
  ): Promise<AttachmentFixLegacyResult> {
    return this.attachments.fixLegacyAttachment(request, reportProgress, validateAuthorization)
  }

  cancelAttachmentOperation(request: AttachmentCancelRequest): AttachmentCancelResult {
    return this.attachments.cancelAttachmentOperation(request)
  }

  verifyPortabilityOwner(masterPassword: string): Promise<void> {
    return this.portability.verifyPortabilityOwner(masterPassword)
  }

  exportPortableSnapshot(masterPassword: string): Promise<VaultExportSnapshot> {
    return this.portability.exportPortableSnapshot(masterPassword)
  }

  createNativeAttachmentBackupSource(
    masterPassword: string,
    options: { includeLoginWireMetadata?: boolean } = {}
  ): Promise<VaultNativeAttachmentBackupSource> {
    return this.portability.createNativeAttachmentBackupSource(masterPassword, options)
  }

  nativeAttachmentRestoreStatus(): Promise<VaultNativeAttachmentRestoreSummary | null> {
    return this.portability.nativeAttachmentRestoreStatus()
  }

  clearCompletedNativeAttachmentRestore(archiveFingerprint: string): Promise<void> {
    return this.portability.clearCompletedNativeAttachmentRestore(archiveFingerprint)
  }

  beginNativeAttachmentRestore(
    preview: NativeAttachmentBackupPreview,
    masterPassword: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.portability.beginNativeAttachmentRestore(preview, masterPassword)
  }

  syncNativeAttachmentRestoreItems(
    archiveFingerprint: string
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.portability.syncNativeAttachmentRestoreItems(archiveFingerprint)
  }

  uploadNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey,
    source: BitwardenAttachmentByteSource
  ): Promise<VaultNativeAttachmentRestoreSummary> {
    return this.portability.uploadNativeAttachmentRestoreEntry(archiveFingerprint, key, source)
  }

  reconcileNativeAttachmentRestoreEntry(
    archiveFingerprint: string,
    key: NativeAttachmentRestoreAttachmentKey
  ): Promise<{
    outcome: 'uploaded' | 'missing' | 'conflict'
    summary: VaultNativeAttachmentRestoreSummary
  }> {
    return this.portability.reconcileNativeAttachmentRestoreEntry(archiveFingerprint, key)
  }

  importPortableSnapshot(
    snapshot: PortableVaultSnapshot,
    skippedTrashItems: number,
    masterPassword: string
  ): Promise<Omit<VaultImportResult, 'canceled'>> {
    return this.portability.importPortableSnapshot(snapshot, skippedTrashItems, masterPassword)
  }
}
