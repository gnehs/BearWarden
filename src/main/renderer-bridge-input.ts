import { IPC_ERROR_PREFIX } from '../shared/vault-contract'

export function publicInvalidInput(): Error {
  return new Error(`${IPC_ERROR_PREFIX}INVALID_INPUT`)
}

export function exactRecord(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw publicInvalidInput()
  }
  const record = value as Record<string, unknown>
  if (Object.keys(record).some((key) => !allowed.includes(key))) throw publicInvalidInput()
  return record
}
