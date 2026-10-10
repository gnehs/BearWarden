export type PlainRecord = Record<string, unknown>

export function plainRecord(value: unknown): value is PlainRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return Reflect.ownKeys(descriptors).every((key) => {
    if (typeof key !== 'string') return false
    const descriptor = descriptors[key]!
    return (
      descriptor.enumerable === true &&
      'value' in descriptor &&
      descriptor.get === undefined &&
      descriptor.set === undefined
    )
  })
}

export function exactKeys(
  value: PlainRecord,
  required: readonly string[],
  optional: readonly string[] = []
): boolean {
  const keys = Object.keys(value)
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) && keys.every((key) => allowed.has(key))
}
