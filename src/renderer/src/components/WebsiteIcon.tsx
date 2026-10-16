import { Globe2 } from 'lucide-react'
import { useMemo } from 'react'
import { useWebsiteIconDataUrl } from '../stores/vault-image-store'

interface WebsiteIconProps {
  id: string
  uri: string | null
  enabled: boolean
}

function parseWebsite(uri: string | null): { hostname: string; label: string } {
  if (!uri) return { hostname: '', label: '' }
  try {
    const url = new URL(uri)
    const label = url.hostname.replace(/^www\./i, '')
    // Mirrors the main process icon lookup so items on the same site share one cache entry.
    const hostname =
      url.protocol === 'http:' || url.protocol === 'https:'
        ? url.hostname.toLocaleLowerCase('en-US').replace(/\.$/, '')
        : ''
    return { hostname, label }
  } catch {
    return { hostname: '', label: '' }
  }
}

function WebsiteIcon({ id, uri, enabled }: WebsiteIconProps): React.JSX.Element {
  const { hostname, label } = useMemo(() => parseWebsite(uri), [uri])
  const dataUrl = useWebsiteIconDataUrl(id, hostname, enabled)

  if (dataUrl) {
    return (
      <img
        className="block size-full bg-[var(--website-icon-background)] object-contain"
        src={dataUrl}
        alt=""
        decoding="async"
        draggable={false}
      />
    )
  }
  if (label) {
    return (
      <span className="text-sm font-black uppercase">
        {label.slice(0, 1).toLocaleUpperCase('en-US')}
      </span>
    )
  }
  return <Globe2 size="1em" />
}

export default WebsiteIcon
