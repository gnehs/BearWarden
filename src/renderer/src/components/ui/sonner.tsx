import { useEffect, useState } from 'react'
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
        close: <XIcon />,
        ...icons
      }}
      style={
        {
          '--width': '360px',
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
          toast:
            'cn-toast !w-[min(360px,calc(100vw-24px))] !min-h-0 !items-start !gap-3 !px-3.5 !py-3 !border-[color-mix(in_oklch,var(--border)_78%,transparent)] !rounded-[calc(var(--radius)+2px)] !text-popover-foreground !bg-[color-mix(in_oklch,var(--popover)_94%,transparent)] !shadow-[inset_0_1px_0_color-mix(in_oklch,var(--shadow-color)_5%,transparent),0_10px_30px_color-mix(in_oklch,var(--shadow-color)_16%,transparent)] backdrop-blur-[18px] backdrop-saturate-[1.2]',
          title: '!text-popover-foreground !text-[13px] !font-semibold !leading-[1.45]',
          description: '!text-muted-foreground !text-xs !leading-[1.45]',
          content: '!min-w-0 !gap-0.5 !pr-5',
          icon: 'cn-toast-icon !grid !size-7 !m-0 ![flex:0_0_28px] !place-content-center !place-items-center !rounded-[calc(var(--radius)-2px)] !text-primary !bg-[color-mix(in_oklch,var(--primary)_12%,transparent)] [&>svg]:block [&>svg]:size-4 [&>svg]:!m-0',
          closeButton:
            'cn-toast-close-button !top-2.5 !right-2.5 !left-auto !grid !size-6 !p-0 !place-items-center !translate-y-0 !border-0 !text-muted-foreground !bg-transparent !shadow-none !leading-none hover:!text-foreground hover:!bg-muted focus-visible:!ring-2 focus-visible:!ring-ring/50 [&>svg]:block [&>svg]:size-4 [&>svg]:!m-0',
          info: '[&_.cn-toast-icon]:!text-foreground [&_.cn-toast-icon]:!bg-muted',
          warning: '[&_.cn-toast-icon]:!text-foreground [&_.cn-toast-icon]:!bg-muted',
          error:
            '[&_.cn-toast-icon]:!text-destructive [&_.cn-toast-icon]:!bg-[color-mix(in_oklch,var(--destructive)_12%,transparent)]',
          loading: '[&_.cn-toast-icon]:!text-foreground [&_.cn-toast-icon]:!bg-muted',
          ...toastOptions?.classNames
        }
      }}
      {...props}
    />
  )
}

export { Toaster }
