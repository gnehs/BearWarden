import type * as React from 'react'
import { DialogContent, DialogFooter, DialogHeader } from '@renderer/components/ui/dialog'
import { cn } from '@renderer/lib/utils'

export function ModalContent({
  className,
  ...props
}: React.ComponentProps<typeof DialogContent>): React.JSX.Element {
  return (
    <DialogContent
      className={cn(
        'border-border m-auto max-h-[calc(100%-48px)] w-[min(calc(100%-32px),470px)] max-w-[min(calc(100%-32px),470px)] gap-0 overflow-hidden rounded-2xl border bg-[var(--panel)] p-0 text-[var(--text)] shadow-[var(--shadow)] max-[680px]:w-[min(calc(100%-20px),470px)] max-[680px]:max-w-[min(calc(100%-20px),470px)]',
        className
      )}
      {...props}
    />
  )
}

export function ModalHeader({
  hasDescription = false,
  className,
  ...props
}: React.ComponentProps<typeof DialogHeader> & { hasDescription?: boolean }): React.JSX.Element {
  return (
    <DialogHeader
      className={cn(
        'flex flex-row justify-between gap-3.5 border-b px-[18px] pt-[18px] pb-3.5',
        hasDescription ? 'items-start' : 'items-center',
        className
      )}
      {...props}
    />
  )
}

export function ModalBody({ className, ...props }: React.ComponentProps<'div'>): React.JSX.Element {
  return <div className={cn('grid gap-[13px] px-[18px] py-[17px]', className)} {...props} />
}

export function ModalFooter({
  split = false,
  className,
  ...props
}: React.ComponentProps<typeof DialogFooter> & { split?: boolean }): React.JSX.Element {
  return (
    <DialogFooter
      className={cn(
        'mx-0 mb-0 items-center gap-2 border-t bg-[var(--panel-muted)] px-[18px] py-3',
        split ? 'justify-between max-[430px]:flex-col max-[430px]:items-stretch' : 'justify-end',
        className
      )}
      {...props}
    />
  )
}

export function ModalActionGroup({
  className,
  ...props
}: React.ComponentProps<'div'>): React.JSX.Element {
  return <div className={cn('flex gap-2 max-[430px]:justify-end', className)} {...props} />
}
