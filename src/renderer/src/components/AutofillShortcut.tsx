import { Kbd, KbdGroup } from '@renderer/components/ui/kbd'
import { useLingui } from '@lingui/react/macro'

export default function AutofillShortcut(): React.JSX.Element {
  const { t } = useLingui()

  return (
    <KbdGroup aria-label={t`Ctrl plus backslash`}>
      <Kbd aria-hidden="true">Ctrl</Kbd>
      <Kbd aria-hidden="true">{'\\'}</Kbd>
    </KbdGroup>
  )
}
