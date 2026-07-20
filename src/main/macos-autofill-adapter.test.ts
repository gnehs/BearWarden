import { describe, expect, it } from 'vitest'
import { MacOSAutofillError, parseMacOSBrowserContext } from './macos-autofill-adapter'

function context(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    ok: true,
    pid: 42,
    bundleIdentifier: 'com.apple.Safari',
    browser: 'safari',
    url: 'https://example.test/login',
    focus: {
      editable: true,
      secure: false,
      x: 10,
      y: 20,
      width: 200,
      height: 32,
      ...overrides
    }
  })
}

describe('macOS AutoFill context parser', () => {
  it('normalizes omitted optional AX role fields to null', () => {
    expect(parseMacOSBrowserContext(context()).focus).toMatchObject({
      role: null,
      subrole: null,
      editable: true,
      secure: false
    })
  })

  it('preserves role metadata when the helper provides it', () => {
    expect(
      parseMacOSBrowserContext(context({ role: 'AXTextField', subrole: 'AXSecureTextField' })).focus
    ).toMatchObject({ role: 'AXTextField', subrole: 'AXSecureTextField' })
  })

  it('rejects malformed optional role metadata', () => {
    expect(() => parseMacOSBrowserContext(context({ subrole: 7 }))).toThrowError(
      new MacOSAutofillError('INVALID_HELPER_RESPONSE')
    )
  })
})
