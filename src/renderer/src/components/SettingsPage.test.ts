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
    expect(autofillStatusPresentation(false, { ...base, available: false }).label).toBe('僅 macOS')
    expect(autofillStatusPresentation(false, base).label).toBe('未啟用')
    expect(autofillStatusPresentation(true, { ...base, shortcutRegistered: false }).label).toBe(
      '快捷鍵衝突'
    )
    expect(autofillStatusPresentation(true, { ...base, accessibilityTrusted: false }).label).toBe(
      '需要權限'
    )
    expect(autofillStatusPresentation(true, base).label).toBe('可使用')
  })
})

describe('content protection guidance', () => {
  it('warns that enabling capture protection can hide the window in remote sessions', () => {
    expect(contentProtectionDescription).toContain('Windows 遠端桌面')
    expect(contentProtectionDescription).toContain('工作列圖示')
    expect(contentProtectionDescription).toContain('關閉此選項')
  })
})

describe('settings category navigation', () => {
  it('groups related settings into focused pages', () => {
    expect(settingsCategories.map(({ label }) => label)).toEqual([
      '一般',
      '安全與解鎖',
      '隱私',
      '帳號與同步',
      '工具與資料',
      '關於'
    ])
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
