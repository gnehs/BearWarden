import type { LoginSummary, SharedLoginSummary } from './vault-contract'

/**
 * The single list-summary projection for main and renderer. Re-prompt and trashed items never
 * expose identifiers in the item list; authorized detail views restore them separately.
 */
export function toLoginSummary(source: LoginSummary): LoginSummary {
  if (source.deletedAt !== null || source.reprompt === 1) {
    return {
      id: source.id,
      type: source.type,
      name: source.name,
      subtitle: '',
      username: '',
      uri: null,
      uris: [],
      ...(source.type === 'login' ? { hasTotp: false, passkeyCount: 0 } : {}),
      passwordHistoryCount: source.passwordHistoryCount,
      attachmentCount: source.attachmentCount,
      folderId: source.folderId,
      favorite: source.deletedAt === null ? source.favorite : false,
      usageCount: source.deletedAt === null ? source.usageCount : 0,
      lastUsedAt: source.deletedAt === null ? source.lastUsedAt : null,
      createdAt: source.createdAt,
      updatedAt: source.updatedAt,
      deletedAt: source.deletedAt,
      archivedAt: source.archivedAt,
      reprompt: source.reprompt
    }
  }
  return {
    id: source.id,
    type: source.type,
    name: source.name,
    subtitle: source.subtitle,
    username: source.type === 'login' ? source.username : '',
    uri: source.type === 'login' ? source.uri : null,
    uris: source.type === 'login' ? source.uris.map((entry) => ({ ...entry })) : [],
    ...(source.type === 'card' && source.cardBrand !== undefined
      ? { cardBrand: source.cardBrand }
      : {}),
    ...(source.type === 'login'
      ? { hasTotp: source.hasTotp ?? false, passkeyCount: source.passkeyCount ?? 0 }
      : {}),
    passwordHistoryCount: source.passwordHistoryCount,
    attachmentCount: source.attachmentCount,
    folderId: source.folderId,
    favorite: source.favorite,
    usageCount: source.usageCount,
    lastUsedAt: source.lastUsedAt,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
    deletedAt: source.deletedAt,
    archivedAt: source.archivedAt,
    reprompt: source.reprompt
  }
}

export function toSharedLoginSummary(source: SharedLoginSummary): SharedLoginSummary {
  const summary = toLoginSummary(source)
  const safeSummary = source.viewPassword
    ? summary
    : {
        ...summary,
        subtitle: '',
        username: '',
        ...(summary.cardBrand !== undefined ? { cardBrand: undefined } : {}),
        ...(summary.hasTotp !== undefined ? { hasTotp: false } : {})
      }
  return {
    ...safeSummary,
    organizationId: source.organizationId,
    collectionIds: [...source.collectionIds],
    shared: true,
    edit: source.edit,
    viewPassword: source.viewPassword,
    delete: source.delete,
    restore: source.restore
  }
}
