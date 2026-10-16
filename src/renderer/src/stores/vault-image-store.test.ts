import { afterEach, describe, expect, it, vi } from 'vitest'
import type { CardCoverPreviewResult, LoginView } from '../../../shared/vault-contract'
import { createVaultImageStore } from './vault-image-store'

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

const flush = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0))

function stubLogins(logins: {
  getWebsiteIcon?: (request: { id: string }) => Promise<string | null>
  getCardCoverPreview?: (request: { id: string }) => Promise<CardCoverPreviewResult | null>
}): void {
  vi.stubGlobal('window', { bearwarden: { logins } })
}

function cardLogin(id: string, updatedAt: string, coverId = 'cover-1'): LoginView {
  return {
    id,
    type: 'card',
    reprompt: 0,
    deletedAt: null,
    archivedAt: null,
    updatedAt,
    attachments: [{ id: coverId, fileName: 'cover.jpg', size: 4, sizeName: '4 B', legacy: false }]
  } as unknown as LoginView
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('vault image store', () => {
  it('shares one icon request per hostname and keeps it across remounts', async () => {
    const getWebsiteIcon = vi.fn(async () => 'data:image/png;base64,AA==')
    stubLogins({ getWebsiteIcon })
    const store = createVaultImageStore()

    const releaseFirst = store.getState().requestWebsiteIcon('example.com', 'item-1')
    store.getState().requestWebsiteIcon('example.com', 'item-2')
    await flush()
    releaseFirst()
    store.getState().requestWebsiteIcon('example.com', 'item-3')

    expect(getWebsiteIcon).toHaveBeenCalledOnce()
    expect(store.getState().websiteIcons.get('example.com')?.dataUrl).toBe(
      'data:image/png;base64,AA=='
    )
  })

  it('limits concurrent icon requests and drops queued rows that unmounted', async () => {
    const pending = new Map<string, ReturnType<typeof deferred<string | null>>>()
    const getWebsiteIcon = vi.fn((request: { id: string }) => {
      const next = deferred<string | null>()
      pending.set(request.id, next)
      return next.promise
    })
    stubLogins({ getWebsiteIcon })
    const store = createVaultImageStore()

    const releases = Array.from({ length: 8 }, (_, index) =>
      store.getState().requestWebsiteIcon(`site-${index}.example`, `item-${index}`)
    )
    expect(getWebsiteIcon).toHaveBeenCalledTimes(6)
    releases[6]!()
    pending.get('item-0')!.resolve(null)
    await flush()

    expect(getWebsiteIcon).toHaveBeenCalledTimes(7)
    expect(getWebsiteIcon).toHaveBeenLastCalledWith({ id: 'item-7' })
  })

  it('retries a missing icon only after the retry window', async () => {
    let now = 0
    const getWebsiteIcon = vi.fn(async () => null)
    stubLogins({ getWebsiteIcon })
    const store = createVaultImageStore({ now: () => now })

    store.getState().requestWebsiteIcon('example.com', 'item-1')
    await flush()
    store.getState().requestWebsiteIcon('example.com', 'item-1')
    expect(getWebsiteIcon).toHaveBeenCalledOnce()

    now = 3 * 60 * 1000
    store.getState().requestWebsiteIcon('example.com', 'item-1')
    expect(getWebsiteIcon).toHaveBeenCalledTimes(2)
  })

  it('keeps card covers until the item or its cover changes', async () => {
    const getCardCoverPreview = vi.fn(async () => ({
      attachmentId: 'cover-1',
      mediaType: 'image/jpeg' as const,
      dataUrl: 'data:image/jpeg;base64,AA=='
    }))
    stubLogins({ getCardCoverPreview })
    const store = createVaultImageStore()

    store.getState().prefetchCardCover(cardLogin('card-1', '2026-01-01'))
    await flush()
    store.getState().prefetchCardCover(cardLogin('card-1', '2026-01-01'))
    expect(getCardCoverPreview).toHaveBeenCalledOnce()
    expect(store.getState().cardCovers.get('card-1')).toBe('data:image/jpeg;base64,AA==')

    store.getState().prefetchCardCover(cardLogin('card-1', '2026-02-01'))
    expect(getCardCoverPreview).toHaveBeenCalledTimes(2)
  })

  it('retries a failed card cover and ignores responses after dispose', async () => {
    const response = deferred<CardCoverPreviewResult | null>()
    const getCardCoverPreview = vi
      .fn<(request: { id: string }) => Promise<CardCoverPreviewResult | null>>()
      .mockRejectedValueOnce(new Error('SYNC_FAILED'))
      .mockReturnValueOnce(response.promise)
    stubLogins({ getCardCoverPreview })
    const store = createVaultImageStore()

    store.getState().prefetchCardCover(cardLogin('card-1', '2026-01-01'))
    await flush()
    store.getState().prefetchCardCover(cardLogin('card-1', '2026-01-01'))
    expect(getCardCoverPreview).toHaveBeenCalledTimes(2)

    store.getState().dispose()
    response.resolve({
      attachmentId: 'cover-1',
      mediaType: 'image/jpeg',
      dataUrl: 'data:image/jpeg;base64,AA=='
    })
    await flush()
    expect(store.getState().cardCovers.size).toBe(0)
  })
})
