import { describe, expect, it } from 'vitest'
import {
  MacOSAutofillError,
  parseMacOSBrowserContext,
  resolveMacOSAutofillHelperPath
} from './macos-autofill-adapter'

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

function expectInvalidContext(value: string): void {
  expect(() => parseMacOSBrowserContext(value)).toThrowError(
    new MacOSAutofillError('INVALID_HELPER_RESPONSE')
  )
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
    expectInvalidContext(context({ subrole: 7 }))
  })

  it('rejects malformed JSON', () => {
    expectInvalidContext('{"ok":true')
  })

  it('rejects unknown top-level and focus fields', () => {
    const withUnknownTopLevelField = JSON.parse(context()) as Record<string, unknown>
    withUnknownTopLevelField.debug = true

    expectInvalidContext(JSON.stringify(withUnknownTopLevelField))
    expectInvalidContext(context({ debug: true }))
  })

  it.each([
    ['zero pid', context(), '"pid":42', '"pid":0'],
    ['fractional pid', context(), '"pid":42', '"pid":1.5'],
    ['unsafe pid', context(), '"pid":42', '"pid":9007199254740992'],
    ['non-finite coordinate', context(), '"x":10', '"x":1e400']
  ])('rejects an invalid number: %s', (_label, value, target, replacement) => {
    expectInvalidContext(value.replace(target, replacement))
  })

  it.each(['file:///tmp/login', 'javascript:alert(1)', 'not a URL'])(
    'rejects a non-HTTP(S) URL: %s',
    (url) => {
      const value = JSON.parse(context()) as Record<string, unknown>
      value.url = url
      expectInvalidContext(JSON.stringify(value))
    }
  )

  it('normalizes valid HTTP(S) URLs', () => {
    const value = JSON.parse(context()) as Record<string, unknown>
    value.url = 'HTTPS://EXAMPLE.TEST:443/login'

    expect(parseMacOSBrowserContext(JSON.stringify(value)).url).toBe('https://example.test/login')
  })
})

describe('macOS AutoFill helper path', () => {
  it('uses the standard nested helper location in a packaged app', () => {
    expect(
      resolveMacOSAutofillHelperPath(true, '/Applications/BearWarden.app/Contents/Resources', '')
    ).toBe(
      '/Applications/BearWarden.app/Contents/Helpers/BearWarden Autofill Helper.app/Contents/MacOS/bearwarden-macos-autofill'
    )
  })

  it('uses the generated helper bundle during development', () => {
    expect(resolveMacOSAutofillHelperPath(false, '', '/repo')).toBe(
      '/repo/resources/bin/BearWarden Autofill Helper.app/Contents/MacOS/bearwarden-macos-autofill'
    )
  })
})
