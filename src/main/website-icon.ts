const MAX_ICON_BYTES = 512 * 1024
const ICON_TIMEOUT_MS = 5_000

const CLOUD_VAULT_HOSTS = new Set([
  'bitwarden.com',
  'vault.bitwarden.com',
  'bitwarden.eu',
  'vault.bitwarden.eu'
])

const SUPPORTED_IMAGE_TYPES = new Set(['image/png', 'image/x-icon', 'image/vnd.microsoft.icon'])
const MAX_ICON_DIMENSION = 1024

export function parseWebsiteHostname(uri: string): string | null {
  try {
    const url = new URL(uri)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    return url.hostname.toLocaleLowerCase('en-US').replace(/\.$/, '') || null
  } catch {
    return null
  }
}

export function resolveWebsiteIconUrl(serverUrl: string, hostname: string): URL | null {
  try {
    const server = new URL(serverUrl)
    const loopback =
      server.hostname === 'localhost' ||
      server.hostname === '127.0.0.1' ||
      server.hostname === '[::1]'
    if (server.protocol !== 'https:' && !(server.protocol === 'http:' && loopback)) return null
    if (CLOUD_VAULT_HOSTS.has(server.hostname.toLocaleLowerCase('en-US'))) {
      return new URL(`https://icons.bitwarden.net/${encodeURIComponent(hostname)}/icon.png`)
    }

    const basePath = server.pathname.replace(/\/+$/, '')
    server.pathname = `${basePath}/icons/${encodeURIComponent(hostname)}/icon.png`
    server.search = ''
    server.hash = ''
    return server
  } catch {
    return null
  }
}

function hasImageSignature(bytes: Uint8Array, mimeType: string): boolean {
  if (mimeType === 'image/png') {
    if (
      bytes.length < 24 ||
      bytes[0] !== 0x89 ||
      bytes[1] !== 0x50 ||
      bytes[2] !== 0x4e ||
      bytes[3] !== 0x47 ||
      bytes[4] !== 0x0d ||
      bytes[5] !== 0x0a ||
      bytes[6] !== 0x1a ||
      bytes[7] !== 0x0a ||
      String.fromCharCode(...bytes.slice(12, 16)) !== 'IHDR'
    ) {
      return false
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const width = view.getUint32(16)
    const height = view.getUint32(20)
    return width > 0 && height > 0 && width <= MAX_ICON_DIMENSION && height <= MAX_ICON_DIMENSION
  }

  if (
    bytes.length < 22 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x00 ||
    bytes[2] !== 0x01 ||
    bytes[3] !== 0x00
  ) {
    return false
  }
  const count = bytes[4]! | (bytes[5]! << 8)
  if (count === 0 || count > 32 || bytes.length < 6 + count * 16) return false
  for (let index = 0; index < count; index += 1) {
    const offset = 6 + index * 16
    const width = bytes[offset] === 0 ? 256 : bytes[offset]!
    const height = bytes[offset + 1] === 0 ? 256 : bytes[offset + 1]!
    if (width > MAX_ICON_DIMENSION || height > MAX_ICON_DIMENSION) return false
  }
  return true
}

async function readBodyWithLimit(
  response: Response,
  abort: AbortController
): Promise<Uint8Array | null> {
  const reader = response.body?.getReader()
  if (!reader) return null
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.length
      if (length > MAX_ICON_BYTES) {
        abort.abort()
        return null
      }
      chunks.push(value)
    }
  } finally {
    await reader.cancel().catch(() => undefined)
  }

  const result = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

export async function fetchWebsiteIconDataUrl(
  iconUrl: URL,
  fetcher: typeof fetch = fetch
): Promise<string | null> {
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), ICON_TIMEOUT_MS)
  timer.unref?.()

  try {
    const response = await fetcher(iconUrl, {
      method: 'GET',
      redirect: 'manual',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      headers: { Accept: 'image/png,image/x-icon;q=0.8' },
      signal: abort.signal
    })
    if (!response.ok || response.status < 200 || response.status >= 300) return null

    const mimeType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
    if (!mimeType || !SUPPORTED_IMAGE_TYPES.has(mimeType)) return null

    const declaredLength = Number(response.headers.get('content-length'))
    if (Number.isFinite(declaredLength) && declaredLength > MAX_ICON_BYTES) return null

    const bytes = await readBodyWithLimit(response, abort)
    if (!bytes || bytes.length === 0 || !hasImageSignature(bytes, mimeType)) {
      return null
    }
    return `data:${mimeType};base64,${Buffer.from(bytes).toString('base64')}`
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}
