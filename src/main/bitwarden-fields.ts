/**
 * Bitwarden serializes response fields in PascalCase and Vaultwarden in camelCase. Response
 * parsers read fields through these accessors so both spellings resolve one way.
 */

function matchingKeys(record: object, name: string): string[] {
  const normalized = name.toLocaleLowerCase('en-US')
  const keys = Object.hasOwn(record, name) ? [name] : []
  for (const key of Object.keys(record)) {
    if (key !== name && key.toLocaleLowerCase('en-US') === normalized) keys.push(key)
  }
  return keys
}

/**
 * Reads `name` under any letter casing. The exact spelling wins over other spellings, and a
 * non-null value wins over null, matching `record.name ?? record.Name`.
 */
export function readField<T>(record: Readonly<Record<string, T>>, name: string): T | undefined {
  if (Object.hasOwn(record, name)) {
    const value = record[name]
    if (value !== null && value !== undefined) return value
  }
  let fallback: T | undefined
  for (const key of matchingKeys(record, name)) {
    const value = record[key]
    if (value !== null && value !== undefined) return value
    fallback ??= value
  }
  return fallback
}

/** Reads `name` under any letter casing and calls `onAmbiguous` when two spellings are present. */
export function readUnambiguousField<T>(
  record: Readonly<Record<string, T>>,
  name: string,
  onAmbiguous: () => never
): T | undefined {
  const keys = matchingKeys(record, name)
  if (keys.length > 1) onAmbiguous()
  return keys.length === 0 ? undefined : record[keys[0]!]
}
