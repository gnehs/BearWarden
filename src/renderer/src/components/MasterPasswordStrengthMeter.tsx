import { msg } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import type { MessageDescriptor } from '@lingui/core'
import { useMasterPasswordStrength } from '@renderer/hooks/use-master-password-strength'
import type { MasterPasswordStrengthLevel } from '@renderer/lib/master-password-strength'
import { cn } from '@renderer/lib/utils'

const SEGMENT_COUNT = 4

const toneClassNames: Record<MasterPasswordStrengthLevel['tone'], string> = {
  destructive: 'bg-destructive',
  warning: 'bg-amber-500',
  success: 'bg-primary'
}

const strengthLabels: Record<MasterPasswordStrengthLevel['segments'], MessageDescriptor> = {
  1: msg({
    message: 'Weak',
    context: 'master-password-strength',
    comment:
      'Strength label for the master password being chosen on the vault setup screen, beside the strength bar. Lowest level. Not the vault health report.'
  }),
  2: msg({
    message: 'Fair',
    context: 'master-password-strength',
    comment:
      'Strength label for the master password being chosen on the vault setup screen, beside the strength bar. Second level, adequate but improvable.'
  }),
  3: msg({
    message: 'Good',
    context: 'master-password-strength',
    comment:
      'Strength label for the master password being chosen on the vault setup screen, beside the strength bar. Third level, a solid password.'
  }),
  4: msg({
    message: 'Strong',
    context: 'master-password-strength',
    comment:
      'Strength label for the master password being chosen on the vault setup screen, beside the strength bar. Highest level.'
  })
}

function MasterPasswordStrengthMeter({ password }: { password: string }): React.JSX.Element {
  const { i18n } = useLingui()
  const level = useMasterPasswordStrength(password)
  return (
    <div className="empty:hidden" role="status" aria-live="polite">
      {level && (
        <div className="flex items-center gap-2">
          <div className="flex flex-1 gap-1" aria-hidden="true">
            {Array.from({ length: SEGMENT_COUNT }, (_, index) => (
              <span
                key={index}
                className={cn(
                  'h-1.5 flex-1 rounded-full',
                  index < level.segments ? toneClassNames[level.tone] : 'bg-border'
                )}
              />
            ))}
          </div>
          <span className="text-muted-foreground text-xs">
            {i18n._(strengthLabels[level.segments])}
          </span>
        </div>
      )}
    </div>
  )
}

export default MasterPasswordStrengthMeter
