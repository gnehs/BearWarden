export type AuthenticationSource = 'setup' | 'unlock'

export function shouldPromptSyncSetup(source: AuthenticationSource): boolean {
  return source === 'setup'
}

export function shouldShowSyncSetupPrompt(pending: boolean, statusLoaded: boolean): boolean {
  return pending && statusLoaded
}
