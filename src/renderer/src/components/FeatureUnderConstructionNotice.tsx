import { Construction } from 'lucide-react'
import { useLingui } from '@lingui/react/macro'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'
import { AuxiliaryPageContent } from './AuxiliaryPageLayout'

interface FeatureUnderConstructionNoticeProps {
  children: React.ReactNode
}

function FeatureUnderConstructionNotice({
  children
}: FeatureUnderConstructionNoticeProps): React.JSX.Element {
  const { t } = useLingui()

  return (
    <AuxiliaryPageContent className="mb-4">
      <Alert className="col-span-full">
        <Construction aria-hidden="true" />
        <AlertTitle>{t`Under construction`}</AlertTitle>
        <AlertDescription>{children}</AlertDescription>
      </Alert>
    </AuxiliaryPageContent>
  )
}

export default FeatureUnderConstructionNotice
