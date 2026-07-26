const CARD_COVER_CATALOG_BASE_URL = 'https://tw-card-catalog.gnehs.net'
const CARD_COVER_CATALOG_ENDPOINT = `${CARD_COVER_CATALOG_BASE_URL}/data/v1/cards-expanded.json`
const CATALOG_CACHE_TTL_MS = 10 * 60 * 1000

interface CatalogBank {
  name?: unknown
  shortName?: unknown
}

interface CatalogFace {
  id?: unknown
  name?: unknown
  imageUrl?: unknown
  isDefault?: unknown
}

interface CatalogCard {
  id?: unknown
  name?: unknown
  bank?: unknown
  bankName?: unknown
  bankShortName?: unknown
  faceUrl?: unknown
  faces?: unknown
}

export interface CardCoverCatalogEntry {
  id: string
  cardId: string
  cardName: string
  bankName: string
  faceName: string
  imageUrl: string
  sourceUrl: string
}

let catalogCache:
  | {
      expiresAt: number
      promise: Promise<CardCoverCatalogEntry[]>
    }
  | undefined

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function catalogAssetUrl(value: unknown): string | null {
  const raw = stringValue(value)
  if (!raw) return null
  try {
    const url = new URL(raw, CARD_COVER_CATALOG_BASE_URL)
    if (
      url.origin !== CARD_COVER_CATALOG_BASE_URL ||
      !url.pathname.startsWith('/assets/cards/') ||
      !/\.(?:jpe?g|webp)$/i.test(url.pathname)
    ) {
      return null
    }
    return url.toString()
  } catch {
    return null
  }
}

function catalogBank(card: CatalogCard): CatalogBank {
  return card.bank && typeof card.bank === 'object' ? (card.bank as CatalogBank) : {}
}

function normalizeCatalogEntry(card: CatalogCard, face: CatalogFace): CardCoverCatalogEntry | null {
  const cardId = stringValue(card.id)
  const cardName = stringValue(card.name)
  const bank = catalogBank(card)
  const bankName =
    stringValue(bank.shortName) ||
    stringValue(bank.name) ||
    stringValue(card.bankShortName) ||
    stringValue(card.bankName)
  const faceName = stringValue(face.name)
  const sourceUrl = catalogAssetUrl(face.imageUrl ?? card.faceUrl)
  if (!cardId || !cardName || !sourceUrl) return null
  return {
    id: stringValue(face.id) || `${cardId}:${sourceUrl}`,
    cardId,
    cardName,
    bankName,
    faceName,
    imageUrl: sourceUrl,
    sourceUrl
  }
}

export async function fetchCardCoverCatalog(
  signal?: AbortSignal
): Promise<CardCoverCatalogEntry[]> {
  const now = Date.now()
  if (!signal && catalogCache && catalogCache.expiresAt > now) return catalogCache.promise
  if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')

  const request = fetch(CARD_COVER_CATALOG_ENDPOINT, { signal }).then(async (response) => {
    if (!response.ok) throw new Error(`Card catalog request failed: ${response.status}`)
    const payload = (await response.json()) as unknown
    if (!Array.isArray(payload)) return []

    const entries: CardCoverCatalogEntry[] = []
    const seen = new Set<string>()
    for (const card of payload) {
      if (!card || typeof card !== 'object') continue
      const catalogCard = card as CatalogCard
      const faces = Array.isArray(catalogCard.faces)
        ? catalogCard.faces
        : [{ imageUrl: catalogCard.faceUrl }]
      for (const face of faces) {
        if (!face || typeof face !== 'object') continue
        const entry = normalizeCatalogEntry(catalogCard, face as CatalogFace)
        if (!entry || seen.has(entry.id)) continue
        seen.add(entry.id)
        entries.push(entry)
      }
    }
    return entries
  })

  if (!signal) {
    const cachedPromise = request.catch((error) => {
      if (catalogCache?.promise === cachedPromise) catalogCache = undefined
      throw error
    })
    catalogCache = {
      expiresAt: now + CATALOG_CACHE_TTL_MS,
      promise: cachedPromise
    }
    return catalogCache.promise
  }

  return request
}

export function filterCardCoverCatalog(
  entries: readonly CardCoverCatalogEntry[],
  query: string
): CardCoverCatalogEntry[] {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean)
  if (terms.length === 0) return entries.slice(0, 80)
  return entries
    .filter((entry) => {
      const haystack = `${entry.bankName} ${entry.cardName} ${entry.faceName}`.toLocaleLowerCase()
      return terms.every((term) => haystack.includes(term))
    })
    .slice(0, 80)
}
