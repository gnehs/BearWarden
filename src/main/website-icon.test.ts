import { describe, expect, it, vi } from 'vitest'
import {
  fetchWebsiteIconDataUrl,
  parseWebsiteHostname,
  resolveWebsiteIconUrl
} from './website-icon'

const PNG_HEADER = Uint8Array.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20
])

describe('website icons', () => {
  it('accepts only web URLs and normalizes the hostname', () => {
    expect(parseWebsiteHostname('https://WWW.Example.COM./sign-in')).toBe('www.example.com')
    expect(parseWebsiteHostname('javascript:alert(1)')).toBeNull()
    expect(parseWebsiteHostname('not a url')).toBeNull()
  })

  it('uses the official cloud endpoint and the configured Vaultwarden origin', () => {
    expect(resolveWebsiteIconUrl('https://vault.bitwarden.com', 'example.com')?.toString()).toBe(
      'https://icons.bitwarden.net/example.com/icon.png'
    )
    expect(
      resolveWebsiteIconUrl('https://vault.example.invalid/base/', 'example.com')?.toString()
    ).toBe('https://vault.example.invalid/base/icons/example.com/icon.png')
  })

  it('returns only validated raster images and refuses redirects or mislabeled content', async () => {
    const validFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(PNG_HEADER, { headers: { 'content-type': 'image/png' } }))
    await expect(
      fetchWebsiteIconDataUrl(new URL('https://icons.example.invalid/icon.png'), validFetch)
    ).resolves.toBe(`data:image/png;base64,${Buffer.from(PNG_HEADER).toString('base64')}`)

    const redirectFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        new Response(null, { status: 302, headers: { location: 'https://other.invalid' } })
      )
    await expect(
      fetchWebsiteIconDataUrl(new URL('https://icons.example.invalid/icon.png'), redirectFetch)
    ).resolves.toBeNull()

    const htmlFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response('<svg></svg>', { headers: { 'content-type': 'image/png' } }))
    await expect(
      fetchWebsiteIconDataUrl(new URL('https://icons.example.invalid/icon.png'), htmlFetch)
    ).resolves.toBeNull()

    const oversizedFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(new Uint8Array(512 * 1024 + 1), {
        headers: { 'content-type': 'image/png' }
      })
    )
    await expect(
      fetchWebsiteIconDataUrl(new URL('https://icons.example.invalid/icon.png'), oversizedFetch)
    ).resolves.toBeNull()
  })
})
