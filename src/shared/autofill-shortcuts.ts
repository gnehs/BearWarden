export const AUTOFILL_SHORTCUTS = [
  'Control+\\',
  'Control+Shift+\\',
  'Command+Control+\\',
  'Command+Alt+\\',
  'Command+Control+K'
] as const

export type AutofillShortcut = (typeof AUTOFILL_SHORTCUTS)[number]

export const DEFAULT_AUTOFILL_SHORTCUT: AutofillShortcut = 'Control+\\'

export function isAutofillShortcut(value: unknown): value is AutofillShortcut {
  return typeof value === 'string' && AUTOFILL_SHORTCUTS.includes(value as AutofillShortcut)
}
