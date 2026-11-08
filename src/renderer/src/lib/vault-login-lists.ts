import type { BearWardenAPI, LoginSummary } from '../../../shared/vault-contract'

export type LoginListApi = Pick<BearWardenAPI['logins'], 'list'>

/**
 * Lists active, archived and trashed personal logins as one sequence. The main process
 * lists each state separately, so every caller that needs the whole vault goes through here.
 */
export async function listLoginsInAllStates(
  logins: LoginListApi,
  query?: string
): Promise<LoginSummary[]> {
  const base = query === undefined ? { sort: 'name' as const } : { sort: 'name' as const, query }
  const [activeItems, archivedItems, deletedItems] = await Promise.all([
    logins.list(base),
    logins.list({ ...base, archived: true }),
    logins.list({ ...base, deleted: true })
  ])
  return [...activeItems, ...archivedItems, ...deletedItems]
}
