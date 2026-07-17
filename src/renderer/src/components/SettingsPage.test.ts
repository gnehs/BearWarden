import { describe, expect, it, vi } from 'vitest'
import {
  applyVaultTimeoutCustomFields,
  vaultTimeoutCustomFields,
  vaultTimeoutCustomValidationMessage,
  vaultTimeoutItems,
  vaultTimeoutSelectValue
} from './SettingsPage'

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
    expect(vaultTimeoutItems.map((item) => item.label)).toContain('App 重新啟動時鎖定')
    expect(vaultTimeoutItems.map((item) => item.label).join('')).not.toContain('永不')
  })

  it('offers the fixed five-minute system-idle policy without custom fields', () => {
    expect(vaultTimeoutSelectValue({ type: 'systemIdle' })).toBe('systemIdle')
    expect(vaultTimeoutItems).toContainEqual({
      label: '系統閒置 5 分鐘',
      value: 'systemIdle'
    })
  })

  it.each([
    ['0', '0', '至少'],
    ['0', '60', '0 到 59'],
    ['8760', '1', '最長']
  ])('shows an error for invalid %s:%s and does not update settings', (hours, minutes, message) => {
    const onUpdate = vi.fn(async () => undefined)

    expect(applyVaultTimeoutCustomFields(hours, minutes, onUpdate)).toContain(message)
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
