import { useEffect, useState } from 'react'
import { Toaster as Sonner, type ToasterProps } from 'sonner'
import {
  CircleCheckIcon,
  CircleXIcon,
  InfoIcon,
  TriangleAlertIcon,
  OctagonXIcon,
  Loader2Icon
} from 'lucide-react'
import { cn } from '@renderer/lib/utils'

const currentTheme = (): ToasterProps['theme'] =>
  document.documentElement.classList.contains('dark') ||
  document.documentElement.dataset.theme === 'dark'
    ? 'dark'
    : 'light'

const Toaster = ({
  theme: themeProp,
  className,
  closeButton = true,
  containerAriaLabel = '通知',
  duration = 3_500,
  gap = 10,
  icons,
  mobileOffset = 12,
  offset = 18,
  style,
  toastOptions,
  visibleToasts = 4,
  ...props
}: ToasterProps) => {
  const [theme, setTheme] = useState<ToasterProps['theme']>(currentTheme)

  useEffect(() => {
    const observer = new MutationObserver(() => setTheme(currentTheme()))
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class', 'data-theme']
    })
    return () => observer.disconnect()
  }, [])

  return (
    <Sonner
      theme={themeProp ?? theme}
      className={cn('toaster group', className)}
      closeButton={closeButton}
      containerAriaLabel={containerAriaLabel}
      duration={duration}
      gap={gap}
      mobileOffset={mobileOffset}
      offset={offset}
      visibleToasts={visibleToasts}
      icons={{
        success: <CircleCheckIcon />,
        info: <InfoIcon />,
        warning: <TriangleAlertIcon />,
        error: <OctagonXIcon />,
        loading: <Loader2Icon className="animate-spin" />,
        close: <CircleXIcon />,
        ...icons
      }}
      style={
        {
          '--normal-bg': 'var(--popover)',
          '--normal-text': 'var(--popover-foreground)',
          '--normal-border': 'var(--border)',
          '--border-radius': 'var(--radius)',
          ...style
        } as React.CSSProperties
      }
      toastOptions={{
        closeButtonAriaLabel: '關閉通知',
        ...toastOptions,
        classNames: {
          toast: 'cn-toast',
          title: 'cn-toast-title',
          description: 'cn-toast-description',
          content: 'cn-toast-content',
          icon: 'cn-toast-icon',
          closeButton: 'cn-toast-close-button',
          success: 'cn-toast-success',
          info: 'cn-toast-info',
          warning: 'cn-toast-warning',
          error: 'cn-toast-error',
          loading: 'cn-toast-loading',
          ...toastOptions?.classNames
        }
      }}
      {...props}
    />
  )
}

export { Toaster }
