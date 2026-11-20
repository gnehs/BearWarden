import { describe, expect, it, vi } from 'vitest'
import {
  createAuthRequestResponseNudgeFactory,
  type AnonymousHubConnection
} from './bitwarden-anonymous-hub'

function fakeConnection(): AnonymousHubConnection & {
  push: () => void
  url: string
  stop: ReturnType<typeof vi.fn>
} {
  const handlers = new Map<string, () => void>()
  return {
    url: '',
    start: vi.fn(async () => undefined),
    stop: vi.fn(async () => undefined),
    on: (name, handler) => handlers.set(name, handler),
    push: () => handlers.get('AuthRequestResponseRecieved')?.()
  }
}

describe('auth request response nudges', () => {
  it('connects to the anonymous hub with the request id as the token', () => {
    const connection = fakeConnection()
    const urls: string[] = []
    const open = createAuthRequestResponseNudgeFactory((url) => {
      urls.push(url)
      return connection
    })
    open('https://vault.example.test/notifications', '93000000-0000-4000-8000-000000000001')
    expect(urls).toEqual([
      'https://vault.example.test/notifications/anonymous-hub?Token=93000000-0000-4000-8000-000000000001'
    ])
    expect(connection.start).toHaveBeenCalledOnce()
  })

  it('wakes a waiting poll once per push and remembers a push that arrived early', async () => {
    const connection = fakeConnection()
    const nudge = createAuthRequestResponseNudgeFactory(() => connection)('https://x', 'id')
    let woke = 0
    void nudge.next().then(() => (woke += 1))
    connection.push()
    await Promise.resolve()
    expect(woke).toBe(1)

    connection.push()
    await expect(nudge.next()).resolves.toBeUndefined()

    const pending = nudge.next()
    nudge.close()
    await expect(pending).resolves.toBeUndefined()
    expect(connection.stop).toHaveBeenCalledOnce()
  })
})
