import { Trans } from '@lingui/react/macro'
import { Info } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger
} from '@renderer/components/ui/collapsible'
import AutofillShortcut from './AutofillShortcut'
import type { AutofillShortcut as AutofillShortcutValue } from '../../../shared/autofill-shortcuts'

export function AutofillAccessibilityGuide({
  shortcut,
  troubleshootingOpen = false
}: {
  shortcut: AutofillShortcutValue
  troubleshootingOpen?: boolean
}): React.JSX.Element {
  return (
    <Alert role="note">
      <Info />
      <AlertTitle role="heading" aria-level={3}>
        <Trans>Set up Accessibility permission</Trans>
      </AlertTitle>
      <AlertDescription className="flex flex-col gap-2">
        <ol className="flex list-decimal flex-col gap-1 pl-4">
          <li>
            <Trans>Click “Request accessibility permission” below.</Trans>
          </li>
          <li>
            <Trans>
              In System Settings → Privacy &amp; Security → Accessibility, turn on BearWarden. If it
              is missing, click + and select BearWarden from Applications.
            </Trans>
          </li>
          <li>
            <Trans>Return to BearWarden and click “Check again”.</Trans>
          </li>
        </ol>
        <p>
          <Trans>
            macOS grants broad Accessibility access to control the computer. BearWarden uses it only
            to read and fill supported browsers when you press{' '}
            <AutofillShortcut shortcut={shortcut} />.
          </Trans>
        </p>
        <Collapsible defaultOpen={troubleshootingOpen}>
          <CollapsibleTrigger render={<Button variant="outline" size="sm" />}>
            <Trans>Already enabled but still not working?</Trans>
          </CollapsibleTrigger>
          <CollapsibleContent className="pt-2">
            <Trans>
              After updating BearWarden: if the system switch is already on but this page still says
              “Permission required”, select BearWarden in the Accessibility list, click − to remove
              the old entry, then return here and request permission again.
            </Trans>
          </CollapsibleContent>
        </Collapsible>
      </AlertDescription>
    </Alert>
  )
}
