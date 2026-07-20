import { describe, expect, it, vi } from 'vitest'
import {
  applyVaultTimeoutCustomFields,
  autofillStatusPresentation,
  contentProtectionDescription,
  settingsCategories,
  vaultTimeoutCustomFields,
  vaultTimeoutCustomValidationMessage,
  vaultTimeoutItems,
  vaultTimeoutSelectValue
} from './SettingsPage'

describe('AutoFill setup status', () => {
  const base = {
    available: true,
    enabled: true,
    shortcutRegistered: true,
    accessibilityTrusted: true
  } as const

  it('distinguishes unsupported, disabled, shortcut conflict, permission, and ready states', () => {
    const presentations = [
      autofillStatusPresentation(false, { ...base, available: false }),
      autofillStatusPresentation(false, base),
      autofillStatusPresentation(true, { ...base, shortcutRegistered: false }),
      autofillStatusPresentation(true, { ...base, accessibilityTrusted: false }),
      autofillStatusPresentation(true, base)
    ]

    expect(presentations.map(({ variant }) => variant)).toEqual([
      'secondary',
      'secondary',
      'destructive',
      'destructive',
      'default'
    ])
    expect(new Set(presentations.map(({ label }) => label)).size).toBe(presentations.length)
  })
})

describe('content protection guidance', () => {
  it('warns that enabling capture protection can hide the window in remote sessions', () => {
    expect(contentProtectionDescription).toMatch(/Windows Remote Desktop/i)
    expect(contentProtectionDescription).toMatch(/taskbar icon/i)
    expect(contentProtectionDescription).toMatch(/turn this option off/i)
  })
})

describe('settings category navigation', () => {
  it('groups related settings into focused pages', () => {
    expect(settingsCategories.map(({ id }) => id)).toEqual([
      'general',
      'security',
      'privacy',
      'accounts',
      'tools',
      'about'
    ])
    expect(settingsCategories.every(({ label }) => label.length > 0)).toBe(true)
  })
})

describe('vault timeout settings UI', () => {
  it('renders a non-preset inactivity policy as Custom and preserves its split fields', () => {
    expect(vaultTimeoutSelectValue({ type: 'appInactivity', minutes: 61 })).toBe('custom')
    expect(vaultTimeoutCustomFields({ type: 'appInactivity', minutes: 61 })).toEqual({
      hours: '1',
      minutes: '1'
    })
  })

  it('keeps restart locking explicit and never offers a Never option', () => {
    expect(vaultTimeoutSelectValue({ type: 'onRestart' })).toBe('onRestart')
    expect(vaultTimeoutSelectValue({ type: 'appInactivity', minutes: 240 })).toBe('240')
    expect(vaultTimeoutItems.find((item) => item.value === 'onRestart')?.label).toBeTruthy()
    expect(vaultTimeoutItems.map((item) => item.value)).not.toContain('never')
  })

  it('offers the fixed five-minute system-idle policy without custom fields', () => {
    expect(vaultTimeoutSelectValue({ type: 'systemIdle' })).toBe('systemIdle')
    expect(vaultTimeoutItems.find((item) => item.value === 'systemIdle')?.label).toMatch(/5/)
  })

  it.each([
    ['0', '0', /at least 1 minute/i],
    ['0', '60', /0 and 59/i],
    ['8760', '1', /8,?760 hours/i]
  ])('shows an error for invalid %s:%s and does not update settings', (hours, minutes, message) => {
    const onUpdate = vi.fn(async () => undefined)

    expect(applyVaultTimeoutCustomFields(hours, minutes, onUpdate)).toMatch(message)
    expect(onUpdate).not.toHaveBeenCalled()
  })

  it.each([
    ['0', '1', 1],
    ['0', '59', 59],
    ['8760', '0', 525_600]
  ])(
    'applies valid custom timeout %s:%s only when explicitly requested',
    (hours, minutes, total) => {
      const onUpdate = vi.fn(async () => undefined)

      expect(applyVaultTimeoutCustomFields(hours, minutes, onUpdate)).toBeNull()
      expect(onUpdate).toHaveBeenCalledOnce()
      expect(onUpdate).toHaveBeenCalledWith({
        vaultTimeoutPolicy: { type: 'appInactivity', minutes: total }
      })
    }
  )

  it('has no validation message for the 240-minute preset value', () => {
    expect(vaultTimeoutCustomValidationMessage('4', '0')).toBeNull()
  })
})
