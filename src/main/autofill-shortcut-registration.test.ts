import { describe, expect, it, vi } from 'vitest'
import { AutofillShortcutRegistration } from './autofill-shortcut-registration'

describe('AutofillShortcutRegistration', () => {
  it('registers the new shortcut before releasing the previous shortcut', () => {
    const calls: string[] = []
    const registration = new AutofillShortcutRegistration(
      {
        register: vi.fn((shortcut: string) => {
          calls.push(`register:${shortcut}`)
          return true
        }),
        unregister: vi.fn((shortcut: string) => calls.push(`unregister:${shortcut}`))
      },
      'Control+\\',
      vi.fn()
    )

    expect(registration.apply(true, 'Control+\\')).toBe(true)
    expect(registration.apply(true, 'Command+Control+K')).toBe(true)
    expect(calls).toEqual([
      'register:Control+\\',
      'register:Command+Control+K',
      'unregister:Control+\\'
    ])
  })

  it('keeps the previous shortcut active when a replacement is occupied', () => {
    const unregister = vi.fn()
    const register = vi.fn((shortcut: string) => shortcut === 'Control+\\')
    const registration = new AutofillShortcutRegistration(
      { register, unregister },
      'Control+\\',
      vi.fn()
    )

    registration.apply(true, 'Control+\\')
    expect(registration.apply(true, 'Command+Control+K')).toBe(false)
    expect(registration.registered).toBe(false)
    expect(unregister).not.toHaveBeenCalled()
    expect(registration.apply(true, 'Control+\\')).toBe(true)
    expect(registration.registered).toBe(true)
  })

  it('unregisters the active shortcut when disabled', () => {
    const unregister = vi.fn()
    const registration = new AutofillShortcutRegistration(
      { register: vi.fn(() => true), unregister },
      'Control+\\',
      vi.fn()
    )

    registration.apply(true, 'Control+\\')
    expect(registration.apply(false, 'Control+\\')).toBe(true)
    expect(unregister).toHaveBeenCalledWith('Control+\\')
    expect(registration.registered).toBe(false)
  })
})
