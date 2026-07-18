import { Construction } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@renderer/components/ui/alert'

interface FeatureUnderConstructionNoticeProps {
  children: React.ReactNode
}

function FeatureUnderConstructionNotice({
  children
}: FeatureUnderConstructionNoticeProps): React.JSX.Element {
  return (
    <div className="settings-layout mb-4">
      <Alert className="col-span-full">
        <Construction aria-hidden="true" />
        <AlertTitle>施工中</AlertTitle>
        <AlertDescription>{children}</AlertDescription>
      </Alert>
    </div>
  )
}

export default FeatureUnderConstructionNotice
