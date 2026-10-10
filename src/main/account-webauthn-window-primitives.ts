/** Shared by the main-process WebAuthn windows and their sandboxed preloads; keep it import-free. */

export const ACCOUNT_WEBAUTHN_CAPABILITY_PATTERN = /^[A-Za-z0-9_-]{32,128}$/u

export function strictRecord(
  value: unknown,
  keys: readonly string[]
): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) return null
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const ownKeys = Reflect.ownKeys(descriptors)
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some(
        (key) => typeof key !== 'string' || !keys.includes(key) || !('value' in descriptors[key]!)
      )
    ) {
      return null
    }
    const snapshot = Object.create(null) as Record<string, unknown>
    for (const key of keys) snapshot[key] = descriptors[key]!.value
    return snapshot
  } catch {
    return null
  }
}

export function uniqueArgument(prefix: string): string | null {
  const values = process.argv.filter((argument) => argument.startsWith(prefix))
  if (values.length !== 1) return null
  const value = values[0]!.slice(prefix.length)
  return value.length > 0 ? value : null
}

export function containsUnsafePathSyntax(raw: string): boolean {
  return /(?:^|\/)(?:\.{1,2})(?:\/|$)|%2e|%2f|%5c|\\/iu.test(raw)
}
