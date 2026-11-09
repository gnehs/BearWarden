import type { VaultCore } from './core'
import type { AuthorizedOperationRunner } from './item-authorization'
import { VaultError } from '../vault-errors'
import { cloneData } from './vault-data-parsing'
import { assertNoPendingPersonalVaultPurge } from './sync-data-parsing'
import { findLogin, assertActiveLogin, assertExpectedPasskeyRevision } from './data-lookup'
import {
  createPasskeyCredential as createSoftwarePasskeyCredential,
  getPasskeyAssertion as createSoftwarePasskeyAssertion
} from '../passkey-authenticator'
import { signSshAgentData as createSshAgentSignature } from '../ssh-agent-crypto'
import { SSH_AGENT_MAX_MESSAGE_LENGTH } from '../ssh-agent-protocol'
import { createUriMatchBudget, loginUrisMatch } from '../uri-matcher'
import type {
  AutofillAuthorizationValidator,
  AutofillCredentialConsumer,
  AutofillDiscoveryResult,
  AutofillExecutionRequest
} from '../autofill'
import { validatePasskeyOrigin } from '../passkey-origin-validation'
import { MAX_URI_LENGTH } from './limits'
import { assertUuid } from './parse-primitives'
import { toView, compareText } from './views'
import {
  normalizePasskeyRpId,
  normalizePasskeyCredentialId,
  normalizePasskeyCredentialIds,
  assertPasskeyApproval,
  findPasskeyVaultMatches,
  activeVaultContainsCredentialId
} from './passkey-parsing'
import { parseSupportedSshAgentPublicKeyBlob, sshAgentFingerprint } from './ssh-helpers'
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
  PasskeyVaultAssertionResult
} from './types'

/**
 * Credential consumers outside the vault UI: browser autofill, passkey discovery, creation and
 * assertion, and the SSH agent. Operations that use a secret run through the authorized-operation
 * gate.
 */
export class VaultIntegrations {
  constructor(
    private readonly core: VaultCore,
    private readonly authorization: AuthorizedOperationRunner
  ) {}

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

  private assertExpectedPasskeyGeneration(value: unknown): asserts value is number {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new VaultError('INVALID_INPUT')
    }
    if (value !== this.core.generation) throw new VaultError('LOCKED')
  }
}
