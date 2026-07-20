import { Kbd, KbdGroup } from '@renderer/components/ui/kbd'

export default function AutofillShortcut(): React.JSX.Element {
  return (
    <KbdGroup aria-label="Ctrl 加反斜線">
      <Kbd aria-hidden="true">Ctrl</Kbd>
      <Kbd aria-hidden="true">{'\\'}</Kbd>
    </KbdGroup>
  )
}
