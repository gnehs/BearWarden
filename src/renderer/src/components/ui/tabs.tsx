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
  'group/tabs-list text-muted-foreground inline-flex w-fit items-center justify-center rounded-full p-1 group-data-horizontal/tabs:h-10 group-data-vertical/tabs:h-fit group-data-vertical/tabs:flex-col group-data-vertical/tabs:rounded-3xl data-[variant=line]:rounded-none',
  {
    variants: {
      variant: {
        default: 'bg-(--segment-track) shadow-(--inset-shadow)',
        line: 'gap-1 bg-transparent'
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
            className="group-data-[variant=line]/tabs-list:bg-foreground pointer-events-none absolute top-1 left-0 z-0 h-[calc(100%-0.5rem)] w-[var(--active-tab-width,0px)] [transform:translateX(var(--active-tab-left,0px))] rounded-full bg-[var(--tabs-pill-bg)] shadow-(--segment-thumb-shadow) transition-[transform,width] duration-[var(--tabs-dur)] ease-[var(--tabs-ease)] will-change-[transform,width] group-data-[variant=line]/tabs-list:top-auto group-data-[variant=line]/tabs-list:bottom-0 group-data-[variant=line]/tabs-list:h-0.5 group-data-[variant=line]/tabs-list:rounded-none group-data-[variant=line]/tabs-list:shadow-none motion-reduce:!transition-none"
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
        "text-foreground/60 hover:text-foreground focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:outline-ring dark:text-muted-foreground dark:hover:text-foreground relative inline-flex h-[calc(100%-1px)] flex-1 items-center justify-center gap-1.5 rounded-full border border-transparent px-3 py-0.5 text-sm font-medium whitespace-nowrap group-data-vertical/tabs:w-full group-data-vertical/tabs:justify-start focus-visible:ring-[3px] focus-visible:outline-1 disabled:pointer-events-none disabled:opacity-50 has-data-[icon=inline-end]:pr-1 has-data-[icon=inline-start]:pl-1 aria-disabled:pointer-events-none aria-disabled:opacity-50 group-data-[variant=default]/tabs-list:data-active:shadow-(--segment-thumb-shadow) group-data-[variant=line]/tabs-list:data-active:shadow-none [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        !sliding && 'transition-all',
        'group-data-[variant=line]/tabs-list:bg-transparent group-data-[variant=line]/tabs-list:data-active:bg-transparent dark:group-data-[variant=line]/tabs-list:data-active:border-transparent dark:group-data-[variant=line]/tabs-list:data-active:bg-transparent',
        'data-active:text-foreground dark:data-active:text-foreground data-active:bg-(--segment-thumb)',
        'after:bg-foreground after:absolute after:opacity-0 after:transition-opacity group-data-horizontal/tabs:after:inset-x-0 group-data-horizontal/tabs:after:bottom-[-5px] group-data-horizontal/tabs:after:h-0.5 group-data-vertical/tabs:after:inset-y-0 group-data-vertical/tabs:after:-right-1 group-data-vertical/tabs:after:w-0.5 group-data-[variant=line]/tabs-list:data-active:after:opacity-100',
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
