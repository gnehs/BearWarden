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
  PASSPHRASE_DEFAULTS,
  PASSWORD_DEFAULTS,
  type RandomInt
} from '../credential-generator'
import {
  BITWARDEN_POLICY_TYPE,
  policyEnforcementDecision,
  type BitwardenPolicySet,
  type PasswordGeneratorPolicyMetadata
} from '../bitwarden-policy'
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
  readonly readPolicySet: () => BitwardenPolicySet
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
      let policyApplied = false
      let algorithm: GeneratorCredentialAlgorithm = request.algorithm
      if (request.algorithm === 'password') {
        // Validate the renderer request independently before applying policy. Otherwise a policy
        // could accidentally turn a contradictory request (for example uppercase=false with a
        // positive minimum) into a valid one and weaken the IPC validation boundary.
        generatePassword(request.options, () => 0)
        const policy = this.passwordGeneratorPolicy()
        policyApplied = policy !== null
        algorithm = this.effectivePasswordAlgorithm(request.algorithm, policy)
        credential = this.generateUnderPolicy(policyApplied, () =>
          algorithm === 'passphrase'
            ? generatePassphrase(
                this.passphraseOptions({}, policy),
                loadEffLongWordlist(),
                this.dependencies.randomInt
              )
            : generatePassword(
                this.passwordOptions(request.options, policy),
                this.dependencies.randomInt
              )
        )
      } else if (request.algorithm === 'passphrase') {
        // A one-word validation list exercises every request option without needlessly validating
        // the complete EFF list twice. Production generation below still uses the vetted list.
        generatePassphrase(request.options, ['validation'], () => 0)
        const policy = this.passwordGeneratorPolicy()
        policyApplied = policy !== null
        algorithm = this.effectivePasswordAlgorithm(request.algorithm, policy)
        credential = this.generateUnderPolicy(policyApplied, () =>
          algorithm === 'password'
            ? generatePassword(this.passwordOptions({}, policy), this.dependencies.randomInt)
            : generatePassphrase(
                this.passphraseOptions(request.options, policy),
                loadEffLongWordlist(),
                this.dependencies.randomInt
              )
        )
      } else if (request.algorithm === 'username') {
        credential = generateRandomWordUsername(
          request.options,
          loadEffLongWordlist(),
          this.dependencies.randomInt
        )
      } else if (request.algorithm === 'subaddress') {
        credential = generatePlusAddressedEmail(request.email, this.dependencies.randomInt)
      } else if (request.algorithm === 'catchall') {
        credential = generateCatchAllEmail(request.domain, this.dependencies.randomInt)
      } else {
        throw new VaultError('INVALID_INPUT')
      }
      if (credential.length === 0 || credential.length > MAX_GENERATED_CREDENTIAL_LENGTH) {
        throw new VaultError(policyApplied ? 'POLICY_RESTRICTED' : 'INTERNAL_ERROR')
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

  private generateUnderPolicy<T>(policyApplied: boolean, generate: () => T): T {
    try {
      return generate()
    } catch (error) {
      if (policyApplied) throw new VaultError('POLICY_RESTRICTED')
      throw error
    }
  }

  private passwordGeneratorPolicy(): PasswordGeneratorPolicyMetadata | null {
    const policySet = this.dependencies.readPolicySet()
    if (policySet.parseFailure !== undefined) throw new VaultError('POLICY_RESTRICTED')
    const hasEnabledGeneratorPolicy = policySet.policies.some(
      (policy) => policy.enabled && policy.type === BITWARDEN_POLICY_TYPE.PasswordGenerator
    )
    if (hasEnabledGeneratorPolicy && policySet.applicableOrganizationIds === undefined) {
      // Applicability resolves the official membership exemptions. Applying every organization
      // policy when that context is absent would be incorrect; ignoring them would be unsafe.
      throw new VaultError('POLICY_RESTRICTED')
    }
    const decision = policyEnforcementDecision(
      policySet,
      BITWARDEN_POLICY_TYPE.PasswordGenerator,
      new Set(policySet.applicableOrganizationIds ?? [])
    )
    if (decision.state === 'not-applicable') return null
    if (decision.state === 'fail-closed') throw new VaultError('POLICY_RESTRICTED')

    const combined: PasswordGeneratorPolicyMetadata = {
      kind: 'passwordGenerator',
      overridePasswordType: '',
      minLength: 0,
      useUppercase: false,
      useLowercase: false,
      useNumbers: false,
      numberCount: 0,
      useSpecial: false,
      specialCount: 0,
      minNumberWords: 0,
      capitalize: false,
      includeNumber: false
    }
    for (const entry of decision.policies) {
      if (entry.data?.kind !== 'passwordGenerator') throw new VaultError('POLICY_RESTRICTED')
      const data = entry.data
      combined.minLength = Math.max(combined.minLength, data.minLength)
      combined.useUppercase ||= data.useUppercase
      combined.useLowercase ||= data.useLowercase
      combined.useNumbers ||= data.useNumbers
      combined.numberCount = Math.max(combined.numberCount, data.numberCount)
      combined.useSpecial ||= data.useSpecial
      combined.specialCount = Math.max(combined.specialCount, data.specialCount)
      combined.minNumberWords = Math.max(combined.minNumberWords, data.minNumberWords)
      combined.capitalize ||= data.capitalize
      combined.includeNumber ||= data.includeNumber
      // Official clients prefer a password override over passphrase, independent of policy order.
      if (
        data.overridePasswordType === 'password' ||
        (data.overridePasswordType === 'passphrase' && combined.overridePasswordType === '')
      ) {
        combined.overridePasswordType = data.overridePasswordType
      }
    }
    return combined
  }

  private effectivePasswordAlgorithm(
    requested: GeneratorCredentialAlgorithm,
    policy: PasswordGeneratorPolicyMetadata | null
  ): GeneratorCredentialAlgorithm {
    if (requested !== 'password' && requested !== 'passphrase') return requested
    return policy?.overridePasswordType || requested
  }

  private passwordOptions(
    options: Extract<CredentialGeneratorRequest, { algorithm: 'password' }>['options'],
    policy: PasswordGeneratorPolicyMetadata | null
  ): Extract<CredentialGeneratorRequest, { algorithm: 'password' }>['options'] {
    if (!policy) return options

    const uppercase = policy.useUppercase || (options.uppercase ?? PASSWORD_DEFAULTS.uppercase)
    const lowercase = policy.useLowercase || (options.lowercase ?? PASSWORD_DEFAULTS.lowercase)
    const numbers =
      policy.useNumbers || policy.numberCount > 0 || (options.numbers ?? PASSWORD_DEFAULTS.numbers)
    const special =
      policy.useSpecial || policy.specialCount > 0 || (options.special ?? PASSWORD_DEFAULTS.special)
    const minUppercase = Math.max(
      options.minUppercase ?? (uppercase ? PASSWORD_DEFAULTS.minUppercase : 0),
      policy.useUppercase ? 1 : 0
    )
    const minLowercase = Math.max(
      options.minLowercase ?? (lowercase ? PASSWORD_DEFAULTS.minLowercase : 0),
      policy.useLowercase ? 1 : 0
    )
    const minNumber = Math.max(
      options.minNumber ?? (numbers ? PASSWORD_DEFAULTS.minNumbers : 0),
      policy.numberCount,
      policy.useNumbers ? 1 : 0
    )
    const minSpecial = Math.max(
      options.minSpecial ?? (special ? PASSWORD_DEFAULTS.minSpecial : 0),
      policy.specialCount,
      policy.useSpecial ? 1 : 0
    )
    const requiredLength = minUppercase + minLowercase + minNumber + minSpecial
    const length = Math.max(
      options.length ?? PASSWORD_DEFAULTS.length,
      policy.minLength,
      requiredLength
    )
    return {
      ...options,
      length,
      uppercase,
      lowercase,
      numbers,
      special,
      minUppercase,
      minLowercase,
      minNumber,
      minSpecial
    }
  }

  private passphraseOptions(
    options: Extract<CredentialGeneratorRequest, { algorithm: 'passphrase' }>['options'],
    policy: PasswordGeneratorPolicyMetadata | null
  ): Extract<CredentialGeneratorRequest, { algorithm: 'passphrase' }>['options'] {
    if (!policy) return options
    return {
      ...options,
      wordCount: Math.max(
        options.wordCount ?? PASSPHRASE_DEFAULTS.wordCount,
        policy.minNumberWords
      ),
      capitalize: policy.capitalize || (options.capitalize ?? PASSPHRASE_DEFAULTS.capitalize),
      includeNumber:
        policy.includeNumber || (options.includeNumber ?? PASSPHRASE_DEFAULTS.includeNumber)
    }
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
