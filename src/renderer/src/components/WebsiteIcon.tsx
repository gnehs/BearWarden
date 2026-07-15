import { Globe2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

interface WebsiteIconProps {
  id: string
  uri: string | null
  enabled: boolean
}

function websiteLabel(uri: string | null): string {
  if (!uri) return ''
  try {
    return new URL(uri).hostname.replace(/^www\./i, '')
  } catch {
    return ''
  }
}

function WebsiteIcon({ id, uri, enabled }: WebsiteIconProps): React.JSX.Element {
  const label = useMemo(() => websiteLabel(uri), [uri])
  const requestKey = `${id}:${label}`
  const [loaded, setLoaded] = useState<{ key: string; dataUrl: string | null } | null>(null)

  useEffect(() => {
    if (!enabled || !label) return
    let active = true
    void window.bearwarden.logins.getWebsiteIcon({ id }).then(
      (dataUrl) => {
        if (active) setLoaded({ key: requestKey, dataUrl })
      },
      () => {
        if (active) setLoaded({ key: requestKey, dataUrl: null })
      }
    )
    return () => {
      active = false
    }
  }, [enabled, id, label, requestKey])

  const dataUrl = enabled && loaded?.key === requestKey ? loaded.dataUrl : null
  if (dataUrl) {
    return <img className="website-icon-image" src={dataUrl} alt="" draggable={false} />
  }
  if (label) {
    return (
      <span className="website-icon-fallback">{label.slice(0, 1).toLocaleUpperCase('en-US')}</span>
    )
  }
  return <Globe2 size="1em" />
}

export default WebsiteIcon
