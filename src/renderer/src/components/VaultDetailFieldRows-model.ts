export function canRevealSecretsOnHover(
  sharedItem: { viewPassword: boolean; reprompt: 0 | 1 } | null
): boolean {
  return sharedItem === null || (sharedItem.viewPassword && sharedItem.reprompt === 0)
}
