import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { createStore, useStore, type StoreApi } from 'zustand'
import type { LoginView } from '../../../shared/vault-contract'
import { isCardCoverAttachment } from '../../../shared/card-cover'

/** Concurrent website icon IPC requests; queued rows that scroll away are dropped first. */
const MAX_WEBSITE_ICON_REQUESTS = 6
/** A missing icon may have been a transient failure, so it is asked for again after this. */
const WEBSITE_ICON_RETRY_MS = 2 * 60 * 1000

export interface WebsiteIconEntry {
  dataUrl: string | null
  loadedAt: number
}

export interface VaultImageState {
  /** Keyed by hostname: every item on the same site shares one icon. */
  websiteIcons: ReadonlyMap<string, WebsiteIconEntry>
  /** Keyed by item id. */
  cardCovers: ReadonlyMap<string, string>
}

export interface VaultImageActions {
  /** Registers a mounted row's interest in an icon and returns its release callback. */
  requestWebsiteIcon: (hostname: string, itemId: string) => () => void
  prefetchCardCover: (login: LoginView) => void
  rememberCardCover: (login: LoginView, attachmentId: string, dataUrl: string) => void
  invalidateCardCover: (itemId: string) => void
  clear: () => void
  activate: () => void
  dispose: () => void
}

export type VaultImageStore = VaultImageState & VaultImageActions
export type VaultImageStoreApi = StoreApi<VaultImageStore>

function createInitialState(): VaultImageState {
  return { websiteIcons: new Map(), cardCovers: new Map() }
}

function cardCoverRequestKey(login: LoginView, attachmentId: string): string {
  return `${login.updatedAt}:${attachmentId}`
}

/**
 * Session-scoped cache of decoded vault images. It survives list refreshes and remounts, but is
 * dropped on lock (the vault shell unmounts) and never persisted; responses that arrive after
 * `clear` or `dispose` are discarded through the epoch check.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function createVaultImageStore(options: { now?: () => number } = {}): VaultImageStoreApi {
  const now = options.now ?? (() => Date.now())

  return createStore<VaultImageStore>()((set, get) => {
    let active = true
    let epoch = 0
    // hostname -> item id -> number of mounted rows waiting for it, in request order.
    const waitingIcons = new Map<string, Map<string, number>>()
    const inFlightIcons = new Set<string>()
    // item id -> request key of the cover that is loading or loaded.
    const coverRequestKeys = new Map<string, string>()

    const isCurrent = (requestEpoch: number): boolean => active && requestEpoch === epoch

    const setWebsiteIcon = (hostname: string, dataUrl: string | null): void => {
      set((state) => {
        const next = new Map(state.websiteIcons)
        next.set(hostname, { dataUrl, loadedAt: now() })
        return { websiteIcons: next }
      })
    }

    const setCardCover = (itemId: string, dataUrl: string): void => {
      set((state) => {
        if (state.cardCovers.get(itemId) === dataUrl) return state
        const next = new Map(state.cardCovers)
        next.set(itemId, dataUrl)
        return { cardCovers: next }
      })
    }

    const pumpWebsiteIcons = (): void => {
      while (inFlightIcons.size < MAX_WEBSITE_ICON_REQUESTS) {
        const next = waitingIcons.entries().next().value
        if (!next) return
        const [hostname, itemIds] = next
        waitingIcons.delete(hostname)
        const itemId = itemIds.keys().next().value
        if (!itemId) continue
        inFlightIcons.add(hostname)
        const requestEpoch = epoch
        void window.bearwarden.logins
          .getWebsiteIcon({ id: itemId })
          .then(
            (dataUrl) => {
              if (isCurrent(requestEpoch)) setWebsiteIcon(hostname, dataUrl)
            },
            () => {
              if (isCurrent(requestEpoch)) setWebsiteIcon(hostname, null)
            }
          )
          .finally(() => {
            if (requestEpoch !== epoch) return
            inFlightIcons.delete(hostname)
            if (active) pumpWebsiteIcons()
          })
      }
    }

    const resetRequests = (): void => {
      epoch += 1
      waitingIcons.clear()
      inFlightIcons.clear()
      coverRequestKeys.clear()
    }

    return {
      ...createInitialState(),
      requestWebsiteIcon: (hostname, itemId) => {
        const noop = (): void => undefined
        if (!active) return noop
        const cached = get().websiteIcons.get(hostname)
        if (
          cached &&
          (cached.dataUrl !== null || now() - cached.loadedAt < WEBSITE_ICON_RETRY_MS)
        ) {
          return noop
        }
        if (inFlightIcons.has(hostname)) return noop

        const itemIds = waitingIcons.get(hostname) ?? new Map<string, number>()
        itemIds.set(itemId, (itemIds.get(itemId) ?? 0) + 1)
        waitingIcons.set(hostname, itemIds)
        const requestEpoch = epoch
        pumpWebsiteIcons()

        return () => {
          if (requestEpoch !== epoch) return
          const waiting = waitingIcons.get(hostname)
          const count = waiting?.get(itemId)
          if (!waiting || count === undefined) return
          if (count > 1) waiting.set(itemId, count - 1)
          else waiting.delete(itemId)
          if (waiting.size === 0) waitingIcons.delete(hostname)
        }
      },
      prefetchCardCover: (login) => {
        if (
          !active ||
          login.type !== 'card' ||
          login.reprompt !== 0 ||
          login.deletedAt !== null ||
          login.archivedAt !== null
        ) {
          return
        }
        const cover = login.attachments.find((attachment) =>
          isCardCoverAttachment(attachment.fileName)
        )
        if (!cover) return
        const requestKey = cardCoverRequestKey(login, cover.id)
        if (coverRequestKeys.get(login.id) === requestKey) return
        coverRequestKeys.set(login.id, requestKey)
        const requestEpoch = epoch

        void window.bearwarden.logins
          .getCardCoverPreview({ id: login.id })
          .then((result) => {
            if (!isCurrent(requestEpoch) || coverRequestKeys.get(login.id) !== requestKey) return
            if (!result || result.attachmentId !== cover.id) {
              // Nothing to show yet (for example sync is not configured); allow a later retry.
              coverRequestKeys.delete(login.id)
              return
            }
            setCardCover(login.id, result.dataUrl)
          })
          .catch(() => {
            if (isCurrent(requestEpoch) && coverRequestKeys.get(login.id) === requestKey) {
              coverRequestKeys.delete(login.id)
            }
          })
      },
      rememberCardCover: (login, attachmentId, dataUrl) => {
        if (!active) return
        coverRequestKeys.set(login.id, cardCoverRequestKey(login, attachmentId))
        setCardCover(login.id, dataUrl)
      },
      invalidateCardCover: (itemId) => {
        coverRequestKeys.delete(itemId)
        set((state) => {
          if (!state.cardCovers.has(itemId)) return state
          const next = new Map(state.cardCovers)
          next.delete(itemId)
          return { cardCovers: next }
        })
      },
      clear: () => {
        resetRequests()
        set(createInitialState())
      },
      activate: () => {
        active = true
      },
      dispose: () => {
        active = false
        resetRequests()
        set(createInitialState())
      }
    }
  })
}

const VaultImageStoreContext = createContext<VaultImageStoreApi | null>(null)

export function VaultImageStoreProvider({ children }: { children: ReactNode }): React.JSX.Element {
  const [store] = useState(() => createVaultImageStore())

  useEffect(() => {
    store.getState().activate()
    return () => store.getState().dispose()
  }, [store])

  return <VaultImageStoreContext.Provider value={store}>{children}</VaultImageStoreContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useVaultImageStore<T>(selector: (state: VaultImageStore) => T): T {
  const store = useContext(VaultImageStoreContext)
  if (!store) throw new Error('Vault image store must be used within a VaultImageStoreProvider')
  return useStore(store, selector)
}

// Outside the vault shell (for example isolated component tests) icons simply fall back to the
// site initial. This inert store is never activated, so it never issues IPC requests.
let inertStore: VaultImageStoreApi | null = null
function getInertStore(): VaultImageStoreApi {
  if (!inertStore) {
    inertStore = createVaultImageStore()
    inertStore.getState().dispose()
  }
  return inertStore
}

/** Returns the cached icon for `hostname`, requesting it while the calling row is mounted. */
// eslint-disable-next-line react-refresh/only-export-components
export function useWebsiteIconDataUrl(
  itemId: string,
  hostname: string,
  enabled: boolean
): string | null {
  const store = useContext(VaultImageStoreContext) ?? getInertStore()
  const dataUrl = useStore(store, (state) =>
    hostname ? (state.websiteIcons.get(hostname)?.dataUrl ?? null) : null
  )

  useEffect(() => {
    if (!enabled || !hostname) return
    return store.getState().requestWebsiteIcon(hostname, itemId)
  }, [enabled, hostname, itemId, store])

  return enabled ? dataUrl : null
}
