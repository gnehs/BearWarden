export interface AutofillPickerChoice {
  id: string
  name: string
  username: string
  uri?: string | null
  hostname?: string | null
  reprompt: boolean | 0 | 1
}

export function autofillPickerHostname(choice: AutofillPickerChoice): string {
  const suppliedHostname = choice.hostname?.trim()
  if (suppliedHostname) return suppliedHostname

  const uri = choice.uri?.trim()
  if (!uri) return ''

  try {
    return new URL(uri).hostname
  } catch {
    return ''
  }
}

export function autofillPickerSearchValue(choice: AutofillPickerChoice): string {
  return [choice.name, choice.username, autofillPickerHostname(choice)]
    .map((part) => part.trim())
    .filter(Boolean)
    .join(' ')
}
