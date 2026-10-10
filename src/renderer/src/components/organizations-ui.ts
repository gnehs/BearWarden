import type { LoginSummary, SharedLoginSummary } from '../../../shared/vault-contract'

export function isSharedLoginSummary(item: LoginSummary): item is SharedLoginSummary {
  return 'shared' in item && item.shared === true
}

export interface LatestRequestGuard {
  next(): number
  invalidate(): void
  isCurrent(requestId: number): boolean
}

export function createLatestRequestGuard(): LatestRequestGuard {
  let latestRequestId = 0
  return {
    next: () => ++latestRequestId,
    invalidate: () => {
      latestRequestId += 1
    },
    isCurrent: (requestId) => requestId === latestRequestId
  }
}
