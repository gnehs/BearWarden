import { Construction } from 'lucide-react'
import { useLingui } from '@lingui/react/macro'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'

interface FeatureUnderConstructionNoticeProps {
  children: React.ReactNode
}

function FeatureUnderConstructionNotice({
  children
}: FeatureUnderConstructionNoticeProps): React.JSX.Element {
  const { t } = useLingui()

  return (
    <Alert variant="warning">
      <Construction aria-hidden="true" />
      <AlertTitle>{t`Under construction`}</AlertTitle>
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  )
}

export default FeatureUnderConstructionNotice
