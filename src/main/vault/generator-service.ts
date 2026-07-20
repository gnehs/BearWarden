import type {
  CredentialGeneratorRequest,
  CredentialGeneratorResult,
  GeneratedCredentialCopyRequest,
  GeneratorCredentialAlgorithm,
  GeneratorHistoryEntry,
  GeneratorHistoryLocator
} from '../../shared/vault-contract'
import {
  generateCatchAllEmail,
  generatePassphrase,
  generatePassword,
  generatePlusAddressedEmail,
  generateRandomWordUsername,
  type RandomInt
} from '../credential-generator'
import { loadEffLongWordlist } from '../eff-wordlist'
import { generateSshKeyMaterial, type SshKeyMaterial } from '../ssh-key'
import { VaultError } from '../vault-errors'
import {
  cloneGeneratorHistory,
  generatorCategoryForAlgorithm,
  isGeneratorAlgorithm,
  isGeneratorCategory
} from './generator-history'
import {
  GENERATED_CREDENTIAL_TOKEN_TTL_MS,
  MAX_GENERATED_CREDENTIAL_LENGTH,
  MAX_GENERATOR_HISTORY,
  MAX_PENDING_GENERATED_CREDENTIALS
} from './limits'
import { assertUuid } from './parse-primitives'

interface PendingGeneratedCredential {
  readonly entry: GeneratorHistoryEntry & { algorithm: GeneratorCredentialAlgorithm }
  readonly expiresAt: number
}

export interface VaultGeneratorServiceDependencies {
  readonly now: () => Date
  readonly createId: () => string
  readonly randomInt: RandomInt
  readonly copyText: (text: string) => void | Promise<void>
  readonly exclusive: <T>(operation: () => Promise<T>) => Promise<T>
  readonly assertUnlocked: () => void
  readonly readHistory: () => readonly GeneratorHistoryEntry[]
  readonly commitHistory: (history: readonly GeneratorHistoryEntry[]) => Promise<void>
}

export class VaultGeneratorService {
  private readonly pendingGeneratedCredentials = new Map<string, PendingGeneratedCredential>()

  constructor(private readonly dependencies: VaultGeneratorServiceDependencies) {}

  generateCredential(request: CredentialGeneratorRequest): Promise<CredentialGeneratorResult> {
    return this.dependencies.exclusive(async () => {
      this.dependencies.assertUnlocked()
      let credential: string
      const algorithm = request.algorithm
      if (algorithm === 'password') {
        credential = generatePassword(request.options, this.dependencies.randomInt)
      } else if (algorithm === 'passphrase') {
        credential = generatePassphrase(
          request.options,
          loadEffLongWordlist(),
          this.dependencies.randomInt
        )
      } else if (algorithm === 'username') {
        credential = generateRandomWordUsername(
          request.options,
          loadEffLongWordlist(),
          this.dependencies.randomInt
        )
      } else if (algorithm === 'subaddress') {
        credential = generatePlusAddressedEmail(request.email, this.dependencies.randomInt)
      } else if (algorithm === 'catchall') {
        credential = generateCatchAllEmail(request.domain, this.dependencies.randomInt)
      } else {
        throw new VaultError('INVALID_INPUT')
      }
      if (credential.length === 0 || credential.length > MAX_GENERATED_CREDENTIAL_LENGTH) {
        throw new VaultError('INTERNAL_ERROR')
      }

      const generated: GeneratorHistoryEntry & { algorithm: GeneratorCredentialAlgorithm } = {
        credential,
        category: generatorCategoryForAlgorithm(algorithm),
        generationDate: this.nowTimestamp(),
        algorithm
      }
      this.removeExpiredGeneratedCredentials()
      while (this.pendingGeneratedCredentials.size >= MAX_PENDING_GENERATED_CREDENTIALS) {
        const oldestToken = this.pendingGeneratedCredentials.keys().next().value
        if (oldestToken === undefined) break
        this.pendingGeneratedCredentials.delete(oldestToken)
      }
      const copyToken = this.dependencies.createId()
      this.pendingGeneratedCredentials.set(copyToken, {
        entry: generated,
        expiresAt: this.dependencies.now().getTime() + GENERATED_CREDENTIAL_TOKEN_TTL_MS
      })
      return { ...generated, copyToken }
    })
  }

  copyGeneratedCredential(request: GeneratedCredentialCopyRequest): Promise<void> {
    return this.dependencies.exclusive(async () => {
      assertUuid(request.token)
      this.dependencies.assertUnlocked()
      this.removeExpiredGeneratedCredentials()
      const pending = this.pendingGeneratedCredentials.get(request.token)
      if (!pending) throw new VaultError('INVALID_INPUT')

      const current = this.dependencies.readHistory()
      if (!current.some((entry) => entry.credential === pending.entry.credential)) {
        const next = [{ ...pending.entry }, ...cloneGeneratorHistory(current)].slice(
          0,
          MAX_GENERATOR_HISTORY
        )
        await this.dependencies.commitHistory(next)
      }
      await this.dependencies.copyText(pending.entry.credential)
    })
  }

  generateSshKey(): Promise<SshKeyMaterial> {
    return this.dependencies.exclusive(async () => {
      this.dependencies.assertUnlocked()
      return generateSshKeyMaterial()
    })
  }

  history(): Promise<GeneratorHistoryEntry[]> {
    return this.dependencies.exclusive(async () =>
      cloneGeneratorHistory(this.dependencies.readHistory())
    )
  }

  clearHistory(): Promise<void> {
    return this.dependencies.exclusive(async () => {
      if (this.dependencies.readHistory().length === 0) return
      await this.dependencies.commitHistory([])
    })
  }

  copyHistory(request: GeneratorHistoryLocator): Promise<void> {
    return this.dependencies.exclusive(async () => {
      if (
        !Number.isSafeInteger(request.index) ||
        request.index < 0 ||
        !Number.isSafeInteger(request.generationDate) ||
        !isGeneratorCategory(request.category) ||
        (request.algorithm !== undefined && !isGeneratorAlgorithm(request.algorithm))
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      const entry = this.dependencies.readHistory()[request.index]
      if (
        !entry ||
        entry.generationDate !== request.generationDate ||
        entry.category !== request.category ||
        entry.algorithm !== request.algorithm
      ) {
        throw new VaultError('INVALID_INPUT')
      }
      await this.dependencies.copyText(entry.credential)
    })
  }

  clearRuntimeState(): void {
    this.pendingGeneratedCredentials.clear()
  }

  private removeExpiredGeneratedCredentials(): void {
    const now = this.dependencies.now().getTime()
    for (const [token, pending] of this.pendingGeneratedCredentials) {
      if (pending.expiresAt <= now) this.pendingGeneratedCredentials.delete(token)
    }
  }

  private nowTimestamp(): number {
    const value = this.dependencies.now()
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new VaultError('INTERNAL_ERROR')
    }
    return Date.parse(value.toISOString())
  }
}
