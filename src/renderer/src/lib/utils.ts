import { clsx, type ClassValue } from 'clsx'
import type { SetStateAction } from 'react'
import { extendTailwindMerge } from 'tailwind-merge'

// The concentric container radii from main.css must override other `rounded-*` classes.
const twMerge = extendTailwindMerge({
  extend: { theme: { radius: ['window', 'pane', 'nested', 'control'] } }
})

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    return false
  }
}

export function resolveValue<T>(value: SetStateAction<T>, current: T): T {
  return typeof value === 'function' ? (value as (current: T) => T)(current) : value
}
