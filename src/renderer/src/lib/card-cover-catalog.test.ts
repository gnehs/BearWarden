import { afterEach, describe, expect, it, vi } from 'vitest'

describe('fetchCardCoverCatalog', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.resetModules()
  })

  it('reuses the in-memory catalog request when no abort signal is supplied', async () => {
    const payload = [
      {
        id: 'card-1',
        name: 'Rewards Card',
        bankName: 'Bank',
        faces: [
          {
            id: 'front',
            name: 'Front',
            imageUrl: 'https://tw-card-catalog.gnehs.net/assets/cards/card-1.webp'
          }
        ]
      }
    ]
    const fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue(payload)
    })
    vi.stubGlobal('fetch', fetch)

    const { fetchCardCoverCatalog } = await import('./card-cover-catalog')
    const first = await fetchCardCoverCatalog()
    const second = await fetchCardCoverCatalog()

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(first).toEqual(second)
    expect(first).toHaveLength(1)
  })

  it('clears a failed catalog request so the next load can retry', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: vi.fn()
      })
      .mockResolvedValueOnce({
        ok: true,
        json: vi.fn().mockResolvedValue([])
      })
    vi.stubGlobal('fetch', fetch)

    const { fetchCardCoverCatalog } = await import('./card-cover-catalog')
    await expect(fetchCardCoverCatalog()).rejects.toThrow('503')
    await expect(fetchCardCoverCatalog()).resolves.toEqual([])

    expect(fetch).toHaveBeenCalledTimes(2)
  })
})
