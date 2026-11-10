'use client'

import { Tabs as TabsPrimitive } from '@base-ui/react/tabs'
import { cva, type VariantProps } from 'class-variance-authority'
import { createContext, useContext } from 'react'

import { cn } from '@renderer/lib/utils'

const TabsOrientationContext = createContext<TabsPrimitive.Root.Orientation>('horizontal')
const TabsListMotionContext = createContext(false)

function Tabs({ className, orientation = 'horizontal', ...props }: TabsPrimitive.Root.Props) {
  return (
    <TabsOrientationContext.Provider value={orientation}>
      <TabsPrimitive.Root
        data-slot="tabs"
        data-orientation={orientation}
        orientation={orientation}
        className={cn('group/tabs flex gap-2 data-horizontal:flex-col', className)}
        {...props}
      />
    </TabsOrientationContext.Provider>
  )
}

const tabsListVariants = cva(
  'group/tabs-list text-muted-foreground inline-flex w-fit items-center justify-center rounded-xl p-[3px] group-data-horizontal/tabs:h-9 group-data-vertical/tabs:h-fit group-data-vertical/tabs:flex-col group-data-vertical/tabs:rounded-3xl data-[variant=list]:rounded-none',
  {
    variants: {
      variant: {
        default: 'bg-(--segment-track)',
        list: 'gap-0.5 bg-transparent p-0'
      }
    },
    defaultVariants: {
      variant: 'default'
    }
  }
)

function TabsList({
  children,
  className,
  sliding = false,
  variant = 'default',
  ...props
}: TabsPrimitive.List.Props &
  VariantProps<typeof tabsListVariants> & {
    sliding?: boolean
  }) {
  const orientation = useContext(TabsOrientationContext)
  const motionEnabled = sliding && orientation === 'horizontal'

  return (
    <TabsListMotionContext.Provider value={motionEnabled}>
      <TabsPrimitive.List
        data-slot="tabs-list"
        data-variant={variant}
        className={cn(tabsListVariants({ variant }), motionEnabled && 'relative', className)}
        {...props}
      >
        {children}
        {motionEnabled && (
          <TabsPrimitive.Indicator
            data-slot="tabs-indicator"
            className="pointer-events-none absolute top-[3px] left-0 z-0 h-[calc(100%-6px)] w-[var(--active-tab-width,0px)] [transform:translateX(var(--active-tab-left,0px))] rounded-[0.5625rem] bg-[var(--tabs-pill-bg)] shadow-(--segment-thumb-shadow) transition-[transform,width] duration-[var(--tabs-dur)] ease-[var(--tabs-ease)] will-change-[transform,width] motion-reduce:!transition-none"
            aria-hidden="true"
          />
        )}
      </TabsPrimitive.List>
    </TabsListMotionContext.Provider>
  )
}

function TabsTrigger({ className, ...props }: TabsPrimitive.Tab.Props) {
  const sliding = useContext(TabsListMotionContext)

  return (
    <TabsPrimitive.Tab
      data-slot="tabs-trigger"
      className={cn(
        "text-muted-foreground hover:text-foreground focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:outline-ring dark:text-muted-foreground dark:hover:text-foreground relative inline-flex h-[calc(100%-1px)] flex-1 items-center justify-center gap-1.5 rounded-[0.5625rem] border border-transparent px-3 py-0.5 text-sm font-medium whitespace-nowrap group-data-vertical/tabs:w-full group-data-vertical/tabs:justify-start focus-visible:ring-[3px] focus-visible:outline-1 disabled:pointer-events-none disabled:opacity-50 has-data-[icon=inline-end]:pr-1 has-data-[icon=inline-start]:pl-1 aria-disabled:pointer-events-none aria-disabled:opacity-50 group-data-[variant=default]/tabs-list:data-active:shadow-(--segment-thumb-shadow) group-data-[variant=list]/tabs-list:data-active:shadow-none [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        !sliding && 'transition-all',
        'group-data-[variant=list]/tabs-list:hover:bg-muted/60 group-data-[variant=list]/tabs-list:data-active:bg-muted group-data-[variant=list]/tabs-list:rounded-lg',
        'data-active:text-foreground dark:data-active:text-foreground data-active:bg-(--segment-thumb)',
        sliding &&
          'relative z-1 transition-[color] duration-[var(--tabs-dur)] ease-[var(--tabs-ease)] after:hidden data-active:bg-transparent data-active:shadow-none motion-reduce:!transition-none dark:data-active:border-transparent dark:data-active:bg-transparent',
        className
      )}
      {...props}
    />
  )
}

function TabsContent({ className, ...props }: TabsPrimitive.Panel.Props) {
  return (
    <TabsPrimitive.Panel
      data-slot="tabs-content"
      className={cn('flex-1 text-sm outline-none', className)}
      {...props}
    />
  )
}

export { Tabs, TabsList, TabsTrigger, TabsContent, tabsListVariants }
