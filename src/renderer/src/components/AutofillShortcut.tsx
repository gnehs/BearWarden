import { Kbd, KbdGroup } from '@renderer/components/ui/kbd'
import { useLingui } from '@lingui/react/macro'
import type { AutofillShortcut as AutofillShortcutValue } from '../../../shared/autofill-shortcuts'

const shortcutKeys: Record<AutofillShortcutValue, readonly string[]> = {
  'Control+\\': ['Ctrl', '\\'],
  'Control+Shift+\\': ['Ctrl', 'Shift', '\\'],
  'Command+Control+\\': ['⌘', 'Ctrl', '\\'],
  'Command+Alt+\\': ['⌘', 'Option', '\\'],
  'Command+Control+K': ['⌘', 'Ctrl', 'K']
}

export default function AutofillShortcut({
  shortcut
}: {
  shortcut: AutofillShortcutValue
}): React.JSX.Element {
  const { t } = useLingui()
  const accessibleLabel =
    shortcut === 'Control+\\'
      ? t`Control plus backslash`
      : shortcut === 'Control+Shift+\\'
        ? t`Control plus Shift plus backslash`
        : shortcut === 'Command+Control+\\'
          ? t`Command plus Control plus backslash`
          : shortcut === 'Command+Alt+\\'
            ? t`Command plus Option plus backslash`
            : t`Command plus Control plus K`

  return (
    <KbdGroup aria-label={accessibleLabel}>
      {shortcutKeys[shortcut].map((key, index) => (
        <Kbd aria-hidden="true" key={`${key}-${index}`}>
          {key}
        </Kbd>
      ))}
    </KbdGroup>
  )
}
