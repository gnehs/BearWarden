import { describe, expect, it } from 'vitest'
import {
  PasskeyOriginValidationError,
  type PasskeyOriginValidationErrorCode,
  validatePasskeyOrigin
} from './passkey-origin-validation'

function expectOriginError(
  input: Parameters<typeof validatePasskeyOrigin>[0],
  code: PasskeyOriginValidationErrorCode
): void {
  try {
    validatePasskeyOrigin(input)
    throw new Error(`Expected ${code}`)
  } catch (error) {
    expect(error).toBeInstanceOf(PasskeyOriginValidationError)
    expect((error as PasskeyOriginValidationError).code).toBe(code)
    expect((error as Error).message).toBe(code)
  }
}

describe('passkey origin validation', () => {
  it('canonicalizes an HTTPS origin, RP ID, IDNA host and ports', () => {
    expect(validatePasskeyOrigin({ origin: 'HTTPS://LOGIN.FAß.DE:443', rpId: 'FAß.DE' })).toEqual({
      origin: 'https://login.xn--fa-hia.de',
      rpId: 'xn--fa-hia.de',
      hostname: 'login.xn--fa-hia.de',
      port: null,
      registrableDomain: 'xn--fa-hia.de'
    })

    expect(
      validatePasskeyOrigin({ origin: 'https://login.example.com:8443', rpId: 'EXAMPLE.COM' })
    ).toMatchObject({
      origin: 'https://login.example.com:8443',
      rpId: 'example.com',
      port: '8443'
    })

    expect(
      validatePasskeyOrigin({
        origin: 'https://xn--fa-hia.de',
        rpId: 'faß.de'
      })
    ).toMatchObject({ rpId: 'xn--fa-hia.de', hostname: 'xn--fa-hia.de' })
  })

  it('accepts exact, parent and nested RP IDs but rejects a more specific or evil suffix', () => {
    expect(
      validatePasskeyOrigin({ origin: 'https://login.example.com', rpId: 'login.example.com' })
    ).toMatchObject({ rpId: 'login.example.com' })
    expect(
      validatePasskeyOrigin({ origin: 'https://deep.login.example.com', rpId: 'example.com' })
    ).toMatchObject({ rpId: 'example.com', registrableDomain: 'example.com' })
    expect(
      validatePasskeyOrigin({ origin: 'https://deep.login.example.com', rpId: 'login.example.com' })
    ).toMatchObject({ rpId: 'login.example.com' })

    expectOriginError(
      { origin: 'https://example.com', rpId: 'login.example.com' },
      'RP_ID_MISMATCH'
    )
    expectOriginError(
      { origin: 'https://evilaccounts.example.com', rpId: 'accounts.example.com' },
      'RP_ID_MISMATCH'
    )
    expectOriginError(
      { origin: 'https://example.com.evil.test', rpId: 'example.com' },
      'RP_ID_MISMATCH'
    )
  })

  it('uses the private PSL and rejects public or private suffixes as RP IDs', () => {
    expect(
      validatePasskeyOrigin({ origin: 'https://bar.foo.github.io', rpId: 'foo.github.io' })
    ).toMatchObject({ registrableDomain: 'foo.github.io' })

    for (const [origin, rpId] of [
      ['https://shop.example.co.uk', 'co.uk'],
      ['https://foo.github.io', 'github.io'],
      ['https://example.com', 'com']
    ]) {
      expectOriginError({ origin: origin!, rpId: rpId! }, 'INVALID_RP_ID')
    }
  })

  it('allows only exact localhost for the HTTP development exception', () => {
    expect(validatePasskeyOrigin({ origin: 'http://LOCALHOST:8080', rpId: 'LOCALHOST' })).toEqual({
      origin: 'http://localhost:8080',
      rpId: 'localhost',
      hostname: 'localhost',
      port: '8080',
      registrableDomain: null
    })
    expect(validatePasskeyOrigin({ origin: 'https://localhost:443', rpId: 'localhost' })).toEqual({
      origin: 'https://localhost',
      rpId: 'localhost',
      hostname: 'localhost',
      port: null,
      registrableDomain: null
    })

    expectOriginError({ origin: 'http://sub.localhost:8080', rpId: 'localhost' }, 'INVALID_ORIGIN')
    expectOriginError({ origin: 'https://localhost', rpId: 'example.com' }, 'RP_ID_MISMATCH')
  })

  it('rejects insecure, opaque, IP and non-origin URL inputs', () => {
    for (const origin of [
      'http://example.com',
      'data:text/plain,hello',
      'https://127.0.0.1',
      'https://[::1]',
      'https://user:password@example.com',
      'https://example.com/',
      'https://example.com/login',
      'https://example.com?next=login',
      'https://example.com#login'
    ]) {
      expectOriginError({ origin, rpId: 'example.com' }, 'INVALID_ORIGIN')
    }

    for (const rpId of [
      '127.0.0.1',
      'https://example.com',
      'example.com:443',
      'example.com/path',
      'example.com.',
      'bad_label.example.com'
    ]) {
      expectOriginError({ origin: 'https://example.com', rpId }, 'INVALID_RP_ID')
    }
  })

  it('rejects cross-origin ceremonies and related-origin fallback', () => {
    expectOriginError(
      { origin: 'https://login.example.com', rpId: 'example.com', crossOrigin: true },
      'CROSS_ORIGIN_UNSUPPORTED'
    )
    expectOriginError(
      { origin: 'https://accounts.example.net', rpId: 'accounts.example.com' },
      'RP_ID_MISMATCH'
    )
  })

  it('returns runtime-immutable canonical metadata', () => {
    const result = validatePasskeyOrigin({
      origin: 'https://login.example.com',
      rpId: 'example.com'
    })

    expect(Object.isFrozen(result)).toBe(true)
    expect(() => {
      ;(result as { origin: string }).origin = 'https://evil.example'
    }).toThrow(TypeError)
    expect(result.origin).toBe('https://login.example.com')
  })

  it('fails closed for malformed provider input', () => {
    expectOriginError(null as never, 'INVALID_INPUT')
    expectOriginError(
      { origin: 'https://example.com', rpId: 'example.com', crossOrigin: 'false' as never },
      'INVALID_INPUT'
    )
    expectOriginError({ origin: '' as string, rpId: 'example.com' }, 'INVALID_ORIGIN')
    expectOriginError({ origin: 'https://example.com', rpId: '' }, 'INVALID_RP_ID')
  })
})
