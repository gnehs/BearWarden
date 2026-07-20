import type {
  GeneratorCredentialAlgorithm,
  GeneratorCredentialCategory,
  GeneratorHistoryEntry
} from '../../shared/vault-contract'
import { VaultError } from '../vault-errors'
import { MAX_GENERATED_CREDENTIAL_LENGTH, MAX_GENERATOR_HISTORY } from './limits'
import { isRecord } from './parse-primitives'

export function generatorCategoryForAlgorithm(
  algorithm: GeneratorCredentialAlgorithm
): GeneratorCredentialCategory {
  if (algorithm === 'password' || algorithm === 'passphrase') return 'password'
  if (algorithm === 'username') return 'username'
  return 'email'
}

export function isGeneratorCategory(value: unknown): value is GeneratorCredentialCategory {
  return value === 'password' || value === 'username' || value === 'email'
}

export function isGeneratorAlgorithm(value: unknown): value is GeneratorCredentialAlgorithm {
  return (
    value === 'password' ||
    value === 'passphrase' ||
    value === 'username' ||
    value === 'subaddress' ||
    value === 'catchall'
  )
}

export function parseGeneratorHistory(value: unknown): GeneratorHistoryEntry[] {
  if (!Array.isArray(value) || value.length > MAX_GENERATOR_HISTORY) {
    throw new VaultError('CORRUPT_VAULT')
  }
  const credentials = new Set<string>()
  return value.map((entry) => {
    if (!isRecord(entry)) throw new VaultError('CORRUPT_VAULT')
    const keys = Object.keys(entry)
    if (
      keys.some(
        (key) =>
          key !== 'credential' &&
          key !== 'category' &&
          key !== 'generationDate' &&
          key !== 'algorithm'
      ) ||
      !Object.hasOwn(entry, 'credential') ||
      !Object.hasOwn(entry, 'category') ||
      !Object.hasOwn(entry, 'generationDate') ||
      typeof entry.credential !== 'string' ||
      entry.credential.length === 0 ||
      entry.credential.length > MAX_GENERATED_CREDENTIAL_LENGTH ||
      credentials.has(entry.credential) ||
      !isGeneratorCategory(entry.category) ||
      typeof entry.generationDate !== 'number' ||
      !Number.isSafeInteger(entry.generationDate) ||
      entry.generationDate < 0 ||
      entry.generationDate > 8_640_000_000_000_000 ||
      (entry.algorithm !== undefined &&
        (!isGeneratorAlgorithm(entry.algorithm) ||
          generatorCategoryForAlgorithm(entry.algorithm) !== entry.category))
    ) {
      throw new VaultError('CORRUPT_VAULT')
    }
    credentials.add(entry.credential)
    return {
      credential: entry.credential,
      category: entry.category,
      generationDate: entry.generationDate,
      ...(entry.algorithm === undefined ? {} : { algorithm: entry.algorithm })
    }
  })
}

export function cloneGeneratorHistory(
  entries: readonly GeneratorHistoryEntry[]
): GeneratorHistoryEntry[] {
  return entries.map((entry) => ({ ...entry }))
}
