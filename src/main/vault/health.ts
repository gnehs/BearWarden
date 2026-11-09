import { createHash } from 'node:crypto'
import type {
  VaultHealthAccountBreachReport,
  VaultHealthAccountBreachRequest,
  VaultHealthExposedReport,
  VaultHealthReport
} from '../../shared/vault-contract'
import { BitwardenDirectError, type BitwardenSyncClient } from '../bitwarden-direct'
import {
  analyzeInactiveTwoFactor,
  type InactiveTwoFactorInput,
  type InactiveTwoFactorReport,
  type TwoFactorDirectoryDataset
} from '../inactive-two-factor'
import { hashPasswordsForPwnedLookup, PwnedPasswordsClient } from '../pwned-passwords'
import { VaultError } from '../vault-errors'
import { analyzeVaultHealth, type VaultHealthItem } from '../vault-health'
import type { VaultCore } from './core'
import { normalizeRequiredString } from './parse-primitives'
import type { VaultSyncSession } from './sync-session'
import type { VaultPlatform } from './types'
import { toSummary } from './views'

interface ExposedPasswordSnapshot {
  readonly generation: number
  readonly revision: string
  readonly candidates: readonly {
    id: string
    name: string
    subtitle: string
  }[]
  readonly hashes: string[]
  readonly protectedSkippedCount: number
}

interface ActiveExposedPasswordOperation {
  readonly generation: number
  readonly revision: string
  readonly abort: AbortController
  readonly promise: Promise<VaultHealthExposedReport>
}

interface ActiveAccountBreachOperation {
  readonly generation: number
  readonly email: string
  readonly client: BitwardenSyncClient
  readonly abort: AbortController
  readonly promise: Promise<VaultHealthAccountBreachReport>
}

/** The account-breach lease other modules observe without reaching into health state. */
export interface AccountBreachReports {
  cancelAccountBreachReport(): boolean
  hasActiveAccountBreachReport(): boolean
}

/**
 * Vault health reports: weak and reused passwords, inactive 2FA, exposed passwords and account
 * breaches. The exposed-password and account-breach reports run off the mutex and are deduplicated
 * while one for the same snapshot is in flight.
 */
export class VaultHealth implements AccountBreachReports {
  private activeExposedPasswordOperation: ActiveExposedPasswordOperation | null = null
  private activeAccountBreachOperation: ActiveAccountBreachOperation | null = null

  constructor(
    private readonly core: VaultCore,
    private readonly syncSession: VaultSyncSession,
    private readonly platform: VaultPlatform,
    private readonly fetch: typeof globalThis.fetch
  ) {
    core.registerResource({
      abort: () => {
        this.activeExposedPasswordOperation?.abort.abort()
        this.activeAccountBreachOperation?.abort.abort()
      },
      clear: () => {
        this.activeExposedPasswordOperation = null
        this.activeAccountBreachOperation = null
      }
    })
  }

  /** True from the start of an account-breach report until it settles, even after an abort. */
  hasActiveAccountBreachReport(): boolean {
    return this.activeAccountBreachOperation !== null
  }

  /**
   * Runs password-health analysis under the vault mutex. Raw password material is adapted only
   * for unprotected active logins and never leaves this method.
   */
  getHealthReport(): Promise<VaultHealthReport> {
    return this.core.exclusive(async () => {
      const data = this.core.requireData()
      const summaryById = new Map<string, { id: string; name: string; subtitle: string }>()
      const candidates: VaultHealthItem[] = []

      for (const login of data.logins) {
        // Archive and trash are not current credentials. Filter before building any core input.
        if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null)
          continue

        if (login.reprompt === 1) {
          // Do not even read protected password or username fields at this boundary.
          candidates.push({
            id: login.id,
            type: login.type,
            name: login.name,
            reprompt: 1
          })
          continue
        }

        // Health findings never need a URI. Avoid `toSummary`, whose fallback subtitle may contain
        // a complete URI including a private path or query when the username is empty.
        summaryById.set(login.id, { id: login.id, name: login.name, subtitle: login.username })
        candidates.push({
          id: login.id,
          type: login.type,
          name: login.name,
          password: login.password,
          username: login.username,
          uris: login.uris.map(({ uri }) => ({ uri })),
          reprompt: 0
        })
      }

      const analysis = analyzeVaultHealth(candidates)
      const weakPasswords = analysis.weakPasswords.flatMap((finding) => {
        const summary = summaryById.get(finding.id)
        return summary
          ? [
              {
                id: summary.id,
                name: summary.name,
                subtitle: summary.subtitle,
                score: finding.score
              }
            ]
          : []
      })
      const reusedPasswords = analysis.reusedPasswords.flatMap((finding) => {
        const summary = summaryById.get(finding.id)
        return summary
          ? [
              {
                id: summary.id,
                name: summary.name,
                subtitle: summary.subtitle,
                reuseCount: finding.reuseCount
              }
            ]
          : []
      })
      const unsecuredWebsites = analysis.unsecuredWebsites.map(({ id, name }) => ({ id, name }))

      return {
        generatedAt: this.core.nowIso(),
        totals: {
          analyzedCount: analysis.analyzedCount,
          weakPasswordCount: weakPasswords.length,
          reusedPasswordCount: reusedPasswords.length,
          unsecuredWebsiteCount: unsecuredWebsites.length,
          protectedSkippedCount: analysis.protectedSkippedCount
        },
        weakPasswords,
        reusedPasswords,
        unsecuredWebsites
      }
    })
  }

  /**
   * Adapts personal login metadata to the main-only inactive-2FA core under one unlocked epoch.
   * Secret fields and organization-owned items never cross this boundary.
   */
  getInactiveTwoFactorReport(dataset: TwoFactorDirectoryDataset): Promise<InactiveTwoFactorReport> {
    return this.core.exclusive(async () => {
      const generation = this.core.generation
      const data = this.core.requireData()
      const inputs: InactiveTwoFactorInput[] = []

      for (const login of data.logins) {
        if (login.type !== 'login') continue
        const hasTotp = Boolean(login.totp)
        const isDeleted = login.deletedAt !== null
        const isArchived = login.archivedAt !== null
        inputs.push({
          id: login.id,
          name: login.name,
          hasTotp,
          isDeleted,
          isArchived,
          // Avoid reading even URI metadata for lifecycle/TOTP exclusions.
          uris: hasTotp || isDeleted || isArchived ? [] : login.uris.map(({ uri }) => uri)
        })
      }

      const report = analyzeInactiveTwoFactor(inputs, dataset)
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      return report
    })
  }

  /**
   * Runs an explicit HIBP Pwned Passwords check without holding the vault mutex during network
   * I/O. Only SHA-1 range material leaves the initial snapshot, and only five-character prefixes
   * are sent to HIBP by the fixed-origin client.
   */
  async getExposedPasswordReport(): Promise<VaultHealthExposedReport> {
    const snapshot = await this.core.exclusive(async () => this.captureExposedPasswordSnapshot())
    const active = this.activeExposedPasswordOperation
    if (
      active &&
      !active.abort.signal.aborted &&
      active.generation === snapshot.generation &&
      active.revision === snapshot.revision
    ) {
      snapshot.hashes.fill('')
      return active.promise
    }

    active?.abort.abort()
    const abort = new AbortController()
    const client = new PwnedPasswordsClient({ fetch: this.fetch })
    const promise = this.resolveExposedPasswordSnapshot(snapshot, client, abort.signal).finally(
      () => {
        snapshot.hashes.fill('')
        if (this.activeExposedPasswordOperation?.promise === promise) {
          this.activeExposedPasswordOperation = null
        }
      }
    )
    this.activeExposedPasswordOperation = {
      generation: snapshot.generation,
      revision: snapshot.revision,
      abort,
      promise
    }
    return promise
  }

  cancelExposedPasswordReport(): boolean {
    const active = this.activeExposedPasswordOperation
    if (!active || active.abort.signal.aborted) return false
    active.abort.abort()
    return true
  }

  /**
   * Queries the configured Vaultwarden HIBP proxy without holding the vault mutex during network
   * I/O. Unlike the password range report, this explicitly discloses the complete address through
   * the configured server, so callers must only invoke it after a user action.
   */
  async getAccountBreachReport(
    request: VaultHealthAccountBreachRequest
  ): Promise<VaultHealthAccountBreachReport> {
    const snapshot = await this.core.exclusive(async () => {
      const email = this.normalizeAccountBreachEmail(request.email)
      const sync = this.syncSession.requireSyncData()
      return {
        generation: this.core.generation,
        email,
        client: this.syncSession.getOrCreateSyncClient(sync)
      }
    })
    const active = this.activeAccountBreachOperation
    if (
      active &&
      !active.abort.signal.aborted &&
      active.generation === snapshot.generation &&
      active.email === snapshot.email &&
      active.client === snapshot.client
    ) {
      return active.promise
    }

    active?.abort.abort()
    const abort = new AbortController()
    const promise = this.resolveAccountBreachReport(
      snapshot.generation,
      snapshot.client,
      snapshot.email,
      abort.signal
    ).finally(() => {
      if (this.activeAccountBreachOperation?.promise === promise) {
        this.activeAccountBreachOperation = null
      }
    })
    this.activeAccountBreachOperation = { ...snapshot, abort, promise }
    return promise
  }

  cancelAccountBreachReport(): boolean {
    const active = this.activeAccountBreachOperation
    if (!active || active.abort.signal.aborted) return false
    active.abort.abort()
    return true
  }

  async openHibpWebsite(): Promise<void> {
    await this.core.exclusive(async () => this.core.requireData())
    await this.platform.openExternal('https://haveibeenpwned.com/')
  }

  private normalizeAccountBreachEmail(value: unknown): string {
    const email = normalizeRequiredString(value, 254).toLowerCase()
    const firstAt = email.indexOf('@')
    if (
      /\s/u.test(email) ||
      firstAt <= 0 ||
      firstAt !== email.lastIndexOf('@') ||
      firstAt === email.length - 1
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    return email
  }

  private async resolveAccountBreachReport(
    generation: number,
    client: BitwardenSyncClient,
    email: string,
    signal: AbortSignal
  ): Promise<VaultHealthAccountBreachReport> {
    let report: Awaited<ReturnType<BitwardenSyncClient['getAccountBreachReport']>>
    try {
      report = await client.getAccountBreachReport(email, signal)
    } catch (error) {
      return this.core.exclusive(async () => {
        this.core.requireData()
        if (generation !== this.core.generation) throw new VaultError('LOCKED')
        if (this.syncSession.syncClient !== client || !this.core.requireData().sync) {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        if (error instanceof BitwardenDirectError && error.code === 'AUTH_REQUIRED') {
          throw new VaultError('SYNC_AUTH_REQUIRED')
        }
        throw new VaultError('HEALTH_CHECK_FAILED')
      })
    }

    return this.core.exclusive(async () => {
      this.core.requireData()
      if (generation !== this.core.generation) throw new VaultError('LOCKED')
      if (this.syncSession.syncClient !== client || !this.core.requireData().sync) {
        throw new VaultError('SYNC_AUTH_REQUIRED')
      }
      if (report.status === 'unavailable') {
        return {
          generatedAt: this.core.nowIso(),
          status: 'unavailable',
          reason: report.reason,
          breaches: []
        }
      }
      return {
        generatedAt: this.core.nowIso(),
        status: 'complete',
        breaches: report.breaches.map((breach) => ({
          name: breach.name,
          title: breach.title,
          domain: breach.domain,
          breachDate: breach.breachDate,
          addedDate: breach.addedDate,
          pwnCount: breach.pwnCount,
          dataClasses: [...breach.dataClasses],
          isVerified: breach.isVerified
        }))
      }
    })
  }

  private captureExposedPasswordSnapshot(): ExposedPasswordSnapshot {
    const data = this.core.requireData()
    const passwords: string[] = []
    const candidates: ExposedPasswordSnapshot['candidates'][number][] = []
    let protectedSkippedCount = 0

    for (const login of data.logins) {
      if (login.type !== 'login' || login.deletedAt !== null || login.archivedAt !== null) continue
      if (login.reprompt === 1) {
        // A protected item's password and username are outside this report's read boundary.
        protectedSkippedCount += 1
        continue
      }
      if (!login.password) continue

      const summary = toSummary(login)
      candidates.push({ id: summary.id, name: summary.name, subtitle: summary.subtitle })
      passwords.push(login.password)
    }

    try {
      const hashes = hashPasswordsForPwnedLookup(passwords)
      const revisionHash = createHash('sha256')
      revisionHash.update(String(protectedSkippedCount), 'utf8')
      for (let index = 0; index < candidates.length; index += 1) {
        const candidate = candidates[index]!
        for (const value of [candidate.id, candidate.name, candidate.subtitle, hashes[index]!]) {
          revisionHash.update(String(Buffer.byteLength(value, 'utf8')), 'utf8')
          revisionHash.update(':', 'utf8')
          revisionHash.update(value, 'utf8')
          revisionHash.update(';', 'utf8')
        }
      }
      return {
        generation: this.core.generation,
        revision: revisionHash.digest('hex'),
        candidates,
        hashes,
        protectedSkippedCount
      }
    } catch {
      throw new VaultError('HEALTH_CHECK_FAILED')
    } finally {
      passwords.fill('')
    }
  }

  private async resolveExposedPasswordSnapshot(
    snapshot: ExposedPasswordSnapshot,
    client: PwnedPasswordsClient,
    signal: AbortSignal
  ): Promise<VaultHealthExposedReport> {
    let counts: number[]
    try {
      counts = await client.lookupSha1Hashes(snapshot.hashes, signal)
    } catch {
      return this.core.exclusive(async () => {
        this.core.requireData()
        if (snapshot.generation !== this.core.generation) throw new VaultError('LOCKED')
        throw new VaultError('HEALTH_CHECK_FAILED')
      })
    }

    return this.core.exclusive(async () => {
      this.core.requireData()
      if (snapshot.generation !== this.core.generation) throw new VaultError('LOCKED')
      const currentSnapshot = this.captureExposedPasswordSnapshot()
      try {
        if (currentSnapshot.revision !== snapshot.revision) {
          throw new VaultError('HEALTH_CHECK_FAILED')
        }
      } finally {
        currentSnapshot.hashes.fill('')
      }

      const exposedPasswords = snapshot.candidates
        .flatMap((candidate, index) => {
          const exposedCount = counts[index] ?? 0
          return exposedCount > 0 ? [{ ...candidate, exposedCount }] : []
        })
        .sort((first, second) => second.exposedCount - first.exposedCount)

      return {
        generatedAt: this.core.nowIso(),
        totals: {
          analyzedCount: snapshot.candidates.length,
          exposedPasswordCount: exposedPasswords.length,
          protectedSkippedCount: snapshot.protectedSkippedCount
        },
        exposedPasswords
      }
    })
  }
}
