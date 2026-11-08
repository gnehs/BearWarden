import type { LoginSummary, LoginView } from '../../../shared/vault-contract'

const detailCacheLimit = 48

export function mergeCachedSummary(cache: Map<string, LoginView>, summary: LoginSummary): void {
  const cached = cache.get(summary.id)
  if (cached) cache.set(summary.id, mergeLoginSummary(cached, summary))
}

export function mergeLoginSummary(login: LoginView, summary: LoginSummary): LoginView {
  if (summary.reprompt === 0 || summary.deletedAt) return { ...login, ...summary }
  return {
    ...login,
    id: summary.id,
    type: summary.type,
    name: summary.name,
    folderId: summary.folderId,
    favorite: summary.favorite,
    usageCount: summary.usageCount,
    lastUsedAt: summary.lastUsedAt,
    createdAt: summary.createdAt,
    updatedAt: summary.updatedAt,
    deletedAt: summary.deletedAt,
    archivedAt: summary.archivedAt,
    reprompt: summary.reprompt,
    passwordHistoryCount: summary.passwordHistoryCount,
    attachmentCount: summary.attachmentCount
  }
}

export function cacheLoginDetail(cache: Map<string, LoginView>, login: LoginView): void {
  cache.delete(login.id)
  while (cache.size >= detailCacheLimit) {
    const oldestId = cache.keys().next().value
    if (!oldestId) break
    cache.delete(oldestId)
  }
  cache.set(login.id, login)
}

export function firstAuthorizationToken(
  ids: readonly string[],
  tokenFor: (id: string) => string | undefined
): string | undefined {
  for (const id of ids) {
    const token = tokenFor(id)
    if (token) return token
  }
  return undefined
}

export function authorizationTokenField(token: string | undefined): {
  authorizationToken?: string
} {
  return token ? { authorizationToken: token } : {}
}
