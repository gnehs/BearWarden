export function describeError(
  error: unknown,
  messages: Record<string, string>,
  unknownError: string,
  fallbackError: string
): string {
  if (!(error instanceof Error)) return unknownError
  const code = Object.keys(messages).find((key) => error.message.includes(key))
  return code ? messages[code] : fallbackError
}

export function isRepromptRequired(error: unknown): boolean {
  return error instanceof Error && error.message.includes('REPROMPT_REQUIRED')
}
