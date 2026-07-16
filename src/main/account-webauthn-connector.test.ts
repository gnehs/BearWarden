import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  AccountWebAuthnCodecError,
  serializeAccountWebAuthnAssertion
} from './account-webauthn-codec'
import {
  AccountWebAuthnConnectorError,
  createAccountWebAuthnConnectorSession,
  type AccountWebAuthnConnectorMessageContext,
  type AccountWebAuthnConnectorSession
} from './account-webauthn-connector'

const CHALLENGE = Buffer.alloc(32, 0x31).toString('base64url')
const CREDENTIAL_ID = Buffer.alloc(32, 0x32).toString('base64url')
const CLIENT_DATA = Buffer.from('{"type":"webauthn.get"}').toString('base64url')
const AUTHENTICATOR_DATA = Buffer.alloc(37, 1).toString('base64url')
const SIGNATURE = Buffer.alloc(70, 2).toString('base64url')

function challenge(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    challenge: CHALLENGE,
    rpId: 'vault.example.com',
    allowCredentials: [{ id: CREDENTIAL_ID, type: 'public-key' }],
    timeout: 60_000,
    userVerification: 'preferred',
    extensions: { uvm: true },
    ...overrides
  }
}

function officialAssertion(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: 'public-key',
    extensions: { appid: false, uvm: [[1, 2, 3]] },
    response: {
      authenticatorData: AUTHENTICATOR_DATA,
      clientDataJson: CLIENT_DATA,
      signature: SIGNATURE
    },
    ...overrides
  }
}

function createSession(
  overrides: Partial<Parameters<typeof createAccountWebAuthnConnectorSession>[0]> = {}
): {
  session: AccountWebAuthnConnectorSession
  source: object
  context: AccountWebAuthnConnectorMessageContext
} {
  const source = (overrides.expectedSource ?? {}) as object
  const capability = overrides.capability ?? {}
  const epoch = overrides.epoch ?? 7
  const session = createAccountWebAuthnConnectorSession({
    webVaultUrl: 'https://vault.example.com/',
    parentUrl: 'app://bearwarden/webauthn-wrapper.html',
    challenge: challenge(),
    expectedSource: source,
    capability,
    epoch,
    timeoutMs: 30_000,
    ...overrides
  })
  return {
    session,
    source,
    context: { origin: session.origin, source, epoch, capability }
  }
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code })
}

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('account WebAuthn connector URLs', () => {
  it('builds the fixed HTTPS connector page with bounded v1 data and parent params', async () => {
    const parentUrl = 'app://bearwarden/webauthn-wrapper.html'
    const { session } = createSession({ parentUrl })
    const url = new URL(session.connectorUrl!)
    expect(`${url.origin}${url.pathname}`).toBe('https://vault.example.com/webauthn-connector.html')
    expect([...url.searchParams.keys()].sort()).toEqual(['data', 'parent', 'v'])
    expect(url.searchParams.get('v')).toBe('1')
    expect(url.searchParams.get('parent')).toBe(parentUrl)
    expect(
      JSON.parse(Buffer.from(url.searchParams.get('data')!, 'base64').toString('utf8'))
    ).toEqual(challenge())
    const terminal = session.result.catch((error) => error)
    session.dispose()
    await expect(terminal).resolves.toMatchObject({ code: 'DISPOSED' })
    expect(session.connectorUrl).toBeNull()
  })

  it('requires an exact HTTPS origin and rejects navigation-style targets', () => {
    for (const webVaultUrl of [
      'http://localhost:8080/',
      'https://vault.example.com/elsewhere',
      'https://vault.example.com/?next=https://evil.example/',
      'https://vault.example.com/#/login',
      'https://user:secret@vault.example.com/',
      'https://vault.example.com/%2e/',
      'javascript:alert(1)'
    ]) {
      expect(() => createSession({ webVaultUrl })).toThrowError(
        expect.objectContaining({ code: 'INVALID_CONFIGURATION' })
      )
    }
  })

  it('allows only local file or exact BearWarden app parents', async () => {
    for (const parentUrl of [
      'https://bearwarden.example/wrapper',
      'app://attacker/webauthn-wrapper.html',
      'app://bearwarden/webauthn-wrapper.html?redirect=evil',
      'file://attacker/share/wrapper.html',
      'file:///tmp/../secret.html',
      'file:///tmp/%2e%2e/secret.html'
    ]) {
      expect(() => createSession({ parentUrl })).toThrowError(
        expect.objectContaining({ code: 'INVALID_CONFIGURATION' })
      )
    }
    const session = createSession({ parentUrl: 'file:///opt/bearwarden/wrapper.html' }).session
    const terminal = session.result.catch(() => undefined)
    session.dispose()
    await terminal
  })
})

describe('account WebAuthn connector messages', () => {
  it('parses official direct strings only after exact origin/source/epoch/capability binding', async () => {
    const { session, context } = createSession()
    expect(session.handleMessage('info|ready', context)).toBe('ready')
    expect(session.ready).toBe(true)
    expect(session.handleMessage('info|ready', context)).toBe('ignored')
    const success = `success|${JSON.stringify(officialAssertion())}`
    expect(session.handleMessage(success, { ...context, source: {} })).toBe('ignored')
    expect(session.handleMessage(success, { ...context, origin: 'https://evil.example' })).toBe(
      'ignored'
    )
    expect(session.handleMessage(success, { ...context, epoch: 8 })).toBe('ignored')
    expect(session.handleMessage(success, { ...context, capability: {} })).toBe('ignored')
    expect(session.handleMessage(success, context)).toBe('settled')
    const assertion = await session.result
    expect(assertion).toMatchObject({ id: CREDENTIAL_ID })
    expect(session.connectorUrl).toBeNull()
    expect(() => serializeAccountWebAuthnAssertion(assertion)).not.toThrow()
  })

  it('accepts a valid success and rejects duplicate or late messages', async () => {
    const { session, context } = createSession()
    const success = `success|${JSON.stringify(officialAssertion())}`
    expect(session.handleMessage(success, context)).toBe('settled')
    session.cancel()
    session.dispose()
    expect(session.handleMessage('error|late failure', context)).toBe('ignored')
    await expect(session.result).resolves.toMatchObject({ id: CREDENTIAL_ID })
  })

  it('maps bounded remote errors to a stable code without leaking the reason', async () => {
    const { session, context } = createSession()
    expect(session.handleMessage('error|User cancelled', context)).toBe('settled')
    await expectCode(session.result, 'REMOTE_ERROR')
    await expect(session.result).rejects.not.toThrow('User cancelled')
  })

  it.each([
    `success|${JSON.stringify(officialAssertion({ extra: true }))}`,
    `success|${JSON.stringify(officialAssertion({ response: { authenticatorData: AUTHENTICATOR_DATA, clientDataJson: 'not+base64', signature: SIGNATURE } }))}`,
    'success|{"id":',
    'error|bad\nreason',
    'info|not-ready'
  ])('terminates safely on malformed same-session protocol', async (data) => {
    const { session, context } = createSession()
    expect(session.handleMessage(data, context)).toBe('settled')
    await expectCode(session.result, 'INVALID_MESSAGE')
  })

  it('rejects untrusted envelopes and accessor contexts without invoking getters', async () => {
    const { session, context } = createSession()
    expect(session.handleMessage({ data: 'info|ready', ...context }, context)).toBe('settled')
    await expectCode(session.result, 'INVALID_MESSAGE')

    const second = createSession()
    let getterCalls = 0
    const accessorContext = Object.create(null) as Record<string, unknown>
    for (const key of ['origin', 'source', 'epoch', 'capability']) {
      Object.defineProperty(accessorContext, key, {
        enumerable: true,
        get: () => {
          getterCalls += 1
          return context[key as keyof typeof context]
        }
      })
    }
    expect(second.session.handleMessage('info|ready', accessorContext)).toBe('ignored')
    expect(getterCalls).toBe(0)
    second.session.dispose()
    await second.session.result.catch(() => undefined)
  })
})

describe('account WebAuthn connector lifecycle', () => {
  it('times out and rejects all late messages', async () => {
    vi.useFakeTimers()
    const { session, context } = createSession({ timeoutMs: 25 })
    const result = session.result.catch((error) => error)
    await vi.advanceTimersByTimeAsync(25)
    await expect(result).resolves.toMatchObject({ code: 'TIMEOUT' })
    expect(session.handleMessage(`success|${JSON.stringify(officialAssertion())}`, context)).toBe(
      'ignored'
    )
  })

  it.each([
    ['cancel', 'CANCELLED'],
    ['dispose', 'DISPOSED']
  ] as const)('%s is idempotent and terminal', async (method, code) => {
    const { session } = createSession()
    const result = session.result.catch((error) => error)
    session[method]()
    session[method]()
    await expect(result).resolves.toMatchObject({ code })
  })

  it('honors an already-aborted signal', async () => {
    const abort = new AbortController()
    abort.abort()
    const { session } = createSession({ signal: abort.signal })
    await expectCode(session.result, 'ABORTED')
  })

  it('does not confuse codec errors with connector errors', () => {
    expect(AccountWebAuthnCodecError).not.toBe(AccountWebAuthnConnectorError)
  })
})
