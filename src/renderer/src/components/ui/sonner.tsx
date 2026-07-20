import { useEffect, useState } from 'react'
import { useLingui } from '@lingui/react/macro'
import { Toaster as Sonner, type ToasterProps } from 'sonner'
import {
  CircleCheckIcon,
  InfoIcon,
  TriangleAlertIcon,
  OctagonXIcon,
  Loader2Icon,
  XIcon
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
  containerAriaLabel,
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
  const { t } = useLingui()
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
      containerAriaLabel={containerAriaLabel ?? t`Notifications`}
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
        close: <XIcon />,
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
        closeButtonAriaLabel: toastOptions?.closeButtonAriaLabel ?? t`Close notification`,
        ...toastOptions,
        classNames: {
          toast:
            'cn-toast !items-center !gap-2.5 !px-3.5 !py-3 has-[.cn-toast-close-button]:!pr-10',
          title: '!text-popover-foreground !text-[13px] !font-medium !leading-5',
          description: '!text-muted-foreground !text-xs !leading-[1.45]',
          content: '!min-w-0 !gap-0.5',
          icon: 'cn-toast-icon !m-0 !shrink-0 !text-primary [&>svg]:block [&>svg]:size-4 [&>svg]:!m-0',
          closeButton:
            'cn-toast-close-button !top-1/2 !right-2.5 !left-auto !grid !size-6 !-translate-y-1/2 !transform-none !place-items-center !border-0 !bg-transparent !p-0 !text-muted-foreground !shadow-none !leading-none hover:!bg-muted hover:!text-foreground focus-visible:!ring-2 focus-visible:!ring-ring/50 [&>svg]:block [&>svg]:size-4 [&>svg]:!m-0',
          info: '[&_.cn-toast-icon]:!text-foreground',
          warning: '[&_.cn-toast-icon]:!text-foreground',
          error: '[&_.cn-toast-icon]:!text-destructive',
          loading: '[&_.cn-toast-icon]:!text-foreground',
          ...toastOptions?.classNames
        }
      }}
      {...props}
    />
  )
}

export { Toaster }
