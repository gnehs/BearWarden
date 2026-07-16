import type { SshAgentPromptBehavior } from '../shared/vault-contract'
import type {
  SshAgentVaultAuthorizationValidator,
  SshAgentVaultIdentity,
  SshAgentVaultSignRequest,
  SshAgentVaultSignResult
} from './vault-service'
import type {
  SshAgentApprovalHandler,
  SshAgentApprovalRequest,
  SshAgentListRequest,
  SshAgentProvider,
  SshAgentSignRequest,
  SshAgentSignature
} from './ssh-agent-server'
import type { SshAgentIdentity } from './ssh-agent-protocol'

const DEFAULT_GRANT_TTL_MS = 60_000
const MAX_PENDING_GRANTS = 128

export interface SshAgentCoordinatorVault {
  listSshAgentIdentities(): Promise<SshAgentVaultIdentity[]>
  signSshAgentRequest(
    request: SshAgentVaultSignRequest,
    validateAuthorization: SshAgentVaultAuthorizationValidator
  ): Promise<SshAgentVaultSignResult>
}

/** Public metadata that may cross the main-to-renderer boundary. */
export interface SshAgentRendererApprovalRequest {
  requestId: string
  itemId: string
  itemName: string
  fingerprint: string
  promptBehavior: SshAgentPromptBehavior
  requiresAgentApproval: boolean
  requiresReprompt: boolean
  processName: string | undefined
  forwarded: boolean
  hostFingerprint: string | undefined
  namespace: 'git' | 'file' | 'unsupported' | undefined
  rsaHash: 'sha256' | 'sha512' | undefined
}

export interface SshAgentRendererApprovalResult {
  approved: boolean
  /** Opaque main-process capability issued by the existing reprompt flow. */
  authorizationToken?: string
}

export interface SshAgentCoordinatorOptions {
  vault: SshAgentCoordinatorVault
  waitForUnlock: (signal: AbortSignal) => Promise<boolean | void>
  focusWindow: () => void | Promise<void>
  getSettings: () => { sshAgentPromptBehavior: SshAgentPromptBehavior }
  /**
   * The bridge that implements this callback must reject pending promises when the renderer
   * reloads or the vault locks. The coordinator still checks its lock epoch before granting.
   */
  requestRendererApproval: (
    request: SshAgentRendererApprovalRequest,
    signal: AbortSignal
  ) => Promise<SshAgentRendererApprovalResult>
  validateAuthorizationToken: (token: string, itemId: string, generation: number) => boolean
  now?: () => number
  grantTtlMs?: number
}

interface CachedIdentity extends SshAgentVaultIdentity {
  publicKeyBlob: Buffer
}

interface SigningGrant {
  requestId: string
  itemId: string
  publicKeyBlob: Buffer
  generation: number
  lockEpoch: number
  cacheEpoch: number
  expiresAt: number
  authorizationToken: string | undefined
  flags: number
  rsaHash: 'sha256' | 'sha512' | undefined
  namespace: 'git' | 'file' | 'unsupported' | undefined
  processName: string | undefined
  forwarded: boolean
  hostFingerprint: string | undefined
}

function abortError(): Error {
  const error = new Error('SSH_AGENT_REQUEST_ABORTED')
  error.name = 'AbortError'
  return error
}

async function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw abortError()
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(abortError())
    signal.addEventListener('abort', onAbort, { once: true })
    operation.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort))
  })
}

function cloneIdentity(identity: SshAgentVaultIdentity): CachedIdentity {
  return { ...identity, publicKeyBlob: Buffer.from(identity.publicKeyBlob) }
}

function sameOptional(left: string | undefined, right: string | undefined): boolean {
  return left === right
}

/**
 * Joins the SSH wire server to the vault without allowing private key material into either the
 * coordinator or renderer. Approval creates a short-lived, one-use grant; the vault revalidates
 * the identity, unlocked generation, and reprompt capability atomically when it signs.
 */
export class SshAgentCoordinator {
  readonly provider: SshAgentProvider
  readonly approvalHandler: SshAgentApprovalHandler

  private readonly now: () => number
  private readonly grantTtlMs: number
  private identities: CachedIdentity[] = []
  private readonly rememberedApprovals = new Set<string>()
  private readonly grants = new Map<string, SigningGrant>()
  private readonly approvalsInProgress = new Set<string>()
  private locked = true
  private hasUnlocked = false
  private lockEpoch = 0
  private cacheEpoch = 0

  constructor(private readonly options: SshAgentCoordinatorOptions) {
    this.now = options.now ?? Date.now
    this.grantTtlMs = options.grantTtlMs ?? DEFAULT_GRANT_TTL_MS
    if (!Number.isSafeInteger(this.grantTtlMs) || this.grantTtlMs < 1) {
      throw new Error('INVALID_SSH_AGENT_GRANT_TTL')
    }
    this.provider = {
      listIdentities: (request) => this.listIdentities(request),
      sign: (request) => this.sign(request)
    }
    this.approvalHandler = { approveSign: (request) => this.approveSign(request) }
  }

  /** Refresh after unlock and after an SSH-key mutation or sync. */
  async refreshIdentities(): Promise<void> {
    const next = (await this.options.vault.listSshAgentIdentities()).map(cloneIdentity)
    this.identities = next
    this.locked = false
    this.hasUnlocked = true
    this.cacheEpoch += 1
    this.grants.clear()

    const validRemembered = new Set<string>()
    for (const remembered of this.rememberedApprovals) {
      if (next.some((identity) => remembered.startsWith(`${identityKey(identity)}\0`))) {
        validRemembered.add(remembered)
      }
    }
    this.rememberedApprovals.clear()
    for (const remembered of validRemembered) this.rememberedApprovals.add(remembered)
  }

  async onUnlocked(): Promise<void> {
    await this.refreshIdentities()
  }

  /** Lock retains public identity metadata, but destroys every authorization capability. */
  onLocked(): void {
    this.locked = true
    this.lockEpoch += 1
    this.grants.clear()
    this.rememberedApprovals.clear()
  }

  /** Logout/account changes must not expose the previous account's public identities. */
  reset(): void {
    this.onLocked()
    this.hasUnlocked = false
    this.identities = []
    this.cacheEpoch += 1
  }

  private async listIdentities(request: SshAgentListRequest): Promise<readonly SshAgentIdentity[]> {
    if (this.locked && !this.hasUnlocked) await this.unlockAndRefresh(request.signal)
    if (request.signal.aborted) throw abortError()
    return this.identities.map((identity) => ({
      keyBlob: Buffer.from(identity.publicKeyBlob),
      comment: identity.name
    }))
  }

  private async approveSign(request: SshAgentApprovalRequest): Promise<boolean> {
    this.removeExpiredGrants()
    if (!validRequestId(request.requestId) || request.signal.aborted) return false
    if (
      this.grants.has(request.requestId) ||
      this.approvalsInProgress.has(request.requestId) ||
      this.grants.size + this.approvalsInProgress.size >= MAX_PENDING_GRANTS
    ) {
      return false
    }
    this.approvalsInProgress.add(request.requestId)
    try {
      let identity = this.findExactIdentity(request.publicKeyBlob)
      if (this.locked) {
        // After-first-unlock, a key absent from the public cache is known to be invalid. Do not
        // wake the vault or show a misleading dialog for it.
        if (this.hasUnlocked && !identity) return false
        await this.unlockAndRefresh(request.signal)
        identity = this.findExactIdentity(request.publicKeyBlob)
      } else if (!identity) {
        // An unlocked vault may have changed before its mutation notification reaches us.
        await this.refreshIdentities()
        identity = this.findExactIdentity(request.publicKeyBlob)
      }
      if (!identity || request.signal.aborted) return false

      const approvalEpoch = this.lockEpoch
      const promptBehavior = this.options.getSettings().sshAgentPromptBehavior
      const scope = approvalScope(request)
      const rememberedKey = scope ? `${identityKey(identity)}\0${scope}` : undefined
      const isRemembered =
        promptBehavior === 'rememberUntilLock' &&
        rememberedKey !== undefined &&
        this.rememberedApprovals.has(rememberedKey)
      const requiresAgentApproval =
        promptBehavior === 'always' || (promptBehavior === 'rememberUntilLock' && !isRemembered)
      const requiresReprompt = identity.reprompt === 1
      const requiresRenderer = requiresAgentApproval || requiresReprompt
      let authorizationToken: string | undefined

      if (requiresRenderer) {
        const response = await abortable(
          this.options.requestRendererApproval(
            {
              requestId: request.requestId,
              itemId: identity.itemId,
              itemName: identity.name,
              fingerprint: identity.fingerprint,
              promptBehavior,
              requiresAgentApproval,
              requiresReprompt,
              processName: request.connection.processName,
              forwarded: request.connection.session.forwarded,
              hostFingerprint: request.connection.session.hostFingerprint,
              namespace: request.namespace,
              rsaHash: request.rsaHash
            },
            request.signal
          ),
          request.signal
        )
        if (!response.approved || (requiresReprompt && !response.authorizationToken)) return false
        authorizationToken = response.authorizationToken
        if (
          promptBehavior === 'rememberUntilLock' &&
          requiresAgentApproval &&
          rememberedKey !== undefined
        ) {
          this.rememberedApprovals.add(rememberedKey)
        }
      }

      if (request.signal.aborted || this.locked || approvalEpoch !== this.lockEpoch) return false
      if (!this.isCurrentIdentity(identity)) return false
      this.grants.set(request.requestId, {
        requestId: request.requestId,
        itemId: identity.itemId,
        publicKeyBlob: Buffer.from(identity.publicKeyBlob),
        generation: identity.generation,
        lockEpoch: this.lockEpoch,
        cacheEpoch: this.cacheEpoch,
        expiresAt: this.now() + this.grantTtlMs,
        authorizationToken,
        flags: request.flags,
        rsaHash: request.rsaHash,
        namespace: request.namespace,
        processName: request.connection.processName,
        forwarded: request.connection.session.forwarded,
        hostFingerprint: request.connection.session.hostFingerprint
      })
      return true
    } catch {
      this.grants.delete(request.requestId)
      return false
    } finally {
      this.approvalsInProgress.delete(request.requestId)
    }
  }

  private async sign(request: SshAgentSignRequest): Promise<SshAgentSignature | undefined> {
    this.removeExpiredGrants()
    const grant = this.grants.get(request.requestId)
    // Consume before any validation or await. A failed attempt can never be replayed.
    this.grants.delete(request.requestId)
    if (
      !grant ||
      request.signal.aborted ||
      this.locked ||
      grant.expiresAt <= this.now() ||
      grant.lockEpoch !== this.lockEpoch ||
      grant.cacheEpoch !== this.cacheEpoch ||
      !grant.publicKeyBlob.equals(request.publicKeyBlob) ||
      grant.flags !== request.flags ||
      grant.rsaHash !== request.rsaHash ||
      grant.namespace !== request.namespace ||
      !sameOptional(grant.processName, request.connection.processName) ||
      grant.forwarded !== request.connection.session.forwarded ||
      !sameOptional(grant.hostFingerprint, request.connection.session.hostFingerprint)
    ) {
      return undefined
    }
    const identity = this.findExactIdentity(request.publicKeyBlob)
    if (
      !identity ||
      identity.itemId !== grant.itemId ||
      identity.generation !== grant.generation ||
      !this.isCurrentIdentity(identity)
    ) {
      return undefined
    }

    try {
      const result = await abortable(
        this.options.vault.signSshAgentRequest(
          {
            publicKeyBlob: Buffer.from(request.publicKeyBlob),
            data: Buffer.from(request.data),
            rsaHash: request.rsaHash,
            expectedGeneration: grant.generation
          },
          (ids, state) =>
            ids.length === 1 &&
            ids[0] === grant.itemId &&
            state.generation === grant.generation &&
            grant.authorizationToken !== undefined &&
            this.options.validateAuthorizationToken(
              grant.authorizationToken,
              grant.itemId,
              state.generation
            )
        ),
        request.signal
      )
      if (
        result.itemId !== grant.itemId ||
        result.generation !== grant.generation ||
        this.locked ||
        grant.lockEpoch !== this.lockEpoch
      ) {
        return undefined
      }
      return { algorithm: result.algorithm, signature: Buffer.from(result.signature) }
    } catch {
      return undefined
    }
  }

  private async unlockAndRefresh(signal: AbortSignal): Promise<void> {
    await Promise.resolve(this.options.focusWindow())
    const unlocked = await abortable(this.options.waitForUnlock(signal), signal)
    if (unlocked === false || signal.aborted) throw abortError()
    await abortable(this.options.vault.listSshAgentIdentities(), signal).then((identities) => {
      this.identities = identities.map(cloneIdentity)
      this.locked = false
      this.hasUnlocked = true
      this.cacheEpoch += 1
      this.grants.clear()
      this.rememberedApprovals.clear()
    })
  }

  private findExactIdentity(publicKeyBlob: Buffer): CachedIdentity | undefined {
    const matches = this.identities.filter((identity) =>
      identity.publicKeyBlob.equals(publicKeyBlob)
    )
    return matches.length === 1 ? matches[0] : undefined
  }

  private isCurrentIdentity(expected: CachedIdentity): boolean {
    const current = this.findExactIdentity(expected.publicKeyBlob)
    return (
      current?.itemId === expected.itemId &&
      current.generation === expected.generation &&
      current.reprompt === expected.reprompt
    )
  }

  private removeExpiredGrants(): void {
    const now = this.now()
    for (const [requestId, grant] of this.grants) {
      if (grant.expiresAt <= now) this.grants.delete(requestId)
    }
  }
}

function validRequestId(requestId: string): boolean {
  return typeof requestId === 'string' && requestId.length > 0 && requestId.length <= 128
}

function identityKey(identity: Pick<CachedIdentity, 'itemId' | 'publicKeyBlob'>): string {
  return `${identity.itemId}\0${identity.publicKeyBlob.toString('base64')}`
}

function approvalScope(request: SshAgentApprovalRequest): string | undefined {
  if (!request.connection.session.forwarded) return 'local'
  const fingerprint = request.connection.session.hostFingerprint
  return fingerprint ? `host:${fingerprint}` : undefined
}
