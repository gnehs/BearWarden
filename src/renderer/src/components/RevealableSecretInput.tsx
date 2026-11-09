import type { ComponentProps } from 'react'
import { useLingui } from '@lingui/react/macro'
import { Eye, EyeOff } from 'lucide-react'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput
} from '@renderer/components/ui/input-group'

interface RevealableSecretInputProps extends Omit<ComponentProps<typeof InputGroupInput>, 'type'> {
  label: string
  visible: boolean
  onVisibleChange: (visible: boolean) => void
}

function RevealableSecretInput({
  label,
  visible,
  onVisibleChange,
  disabled,
  ...inputProps
}: RevealableSecretInputProps): React.JSX.Element {
  const { t } = useLingui()
  return (
    <InputGroup>
      <InputGroupInput {...inputProps} type={visible ? 'text' : 'password'} disabled={disabled} />
      <InputGroupAddon align="inline-end">
        <InputGroupButton
          size="icon-xs"
          aria-label={visible ? t`Hide ${label}` : t`Show ${label}`}
          aria-pressed={visible}
          onClick={() => onVisibleChange(!visible)}
          disabled={disabled}
        >
          {visible ? <EyeOff /> : <Eye />}
        </InputGroupButton>
      </InputGroupAddon>
    </InputGroup>
  )
}

export default RevealableSecretInput
