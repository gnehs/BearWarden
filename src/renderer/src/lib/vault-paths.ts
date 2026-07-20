export const vaultPagePaths = [
  '/vault',
  '/vault/settings',
  '/vault/health',
  '/vault/sends',
  '/vault/organizations',
  '/vault/emergency-access'
] as const

export type VaultPagePath = (typeof vaultPagePaths)[number]

const vaultPagePathSet = new Set<string>(vaultPagePaths)

function normalizePathname(pathname: string): string {
  return pathname.replace(/\/+$/, '') || '/'
}

export function isVaultPagePath(pathname: string): boolean {
  return vaultPagePathSet.has(normalizePathname(pathname))
}

export function vaultPagePathFromPathname(pathname: string): VaultPagePath {
  const normalizedPathname = normalizePathname(pathname)
  return vaultPagePaths.find((path) => path === normalizedPathname) ?? '/vault'
}
