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
          toast:
            'has-[.cn-toast-close-button]:!pr-10 !min-h-[50px] !gap-2.5 !px-3 !py-2.5 !border-[color-mix(in_oklch,var(--border)_78%,transparent)] !rounded-[calc(var(--radius)+2px)] !text-popover-foreground !bg-[color-mix(in_oklch,var(--popover)_92%,transparent)] !shadow-[inset_0_1px_0_color-mix(in_oklch,var(--shadow-color)_5%,transparent),0_12px_36px_color-mix(in_oklch,var(--shadow-color)_20%,transparent)] backdrop-blur-[18px] backdrop-saturate-[1.25]',
          title: '!text-popover-foreground !text-[12px] !font-[650] !leading-[1.45]',
          description: '!text-muted-foreground !text-[11px] !leading-[1.4]',
          content: '!gap-0.5',
          icon: 'cn-toast-icon !grid !size-[26px] !m-0 ![flex:0_0_26px] !place-content-center !place-items-center !rounded-[calc(var(--radius)-2px)] !text-primary !bg-[color-mix(in_oklch,var(--primary)_12%,transparent)] [&>svg]:block [&>svg]:size-[15px] [&>svg]:!m-0',
          closeButton:
            'cn-toast-close-button !top-1/2 !right-2 !left-auto !grid !size-6 !p-0 !place-items-center !-translate-y-1/2 !border-transparent !text-muted-foreground !bg-transparent !leading-none hover:!text-foreground hover:!bg-muted [&>svg]:block [&>svg]:size-[15px] [&>svg]:!m-0',
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
