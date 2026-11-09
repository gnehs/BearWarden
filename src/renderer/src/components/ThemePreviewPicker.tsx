import { Radio } from '@base-ui/react/radio'
import { RadioGroup } from '@base-ui/react/radio-group'
import { Check } from 'lucide-react'
import type { JSX } from 'react'
import type { AppSettings } from '../../../shared/vault-contract'
import { cn } from '@renderer/lib/utils'

type ThemePreference = AppSettings['theme']

interface ThemePreviewPickerProps {
  items: ReadonlyArray<{ label: string; value: ThemePreference }>
  value: ThemePreference
  disabled?: boolean
  labelledBy: string
  onValueChange: (value: ThemePreference) => void
}

// Each preview is a miniature window: canvas, sidebar lines, and a content card.
const palettes = {
  light: {
    canvas: '#eceef2',
    sidebar: '#dfe2e8',
    card: '#ffffff',
    line: '#d6d9df',
    tile: '#f1f2f5'
  },
  dark: { canvas: '#1c1c1c', sidebar: '#262626', card: '#2e2e2e', line: '#454545', tile: '#3a3a3a' }
} as const

function WindowSketch({
  palette
}: {
  palette: (typeof palettes)[keyof typeof palettes]
}): JSX.Element {
  return (
    <svg viewBox="0 0 120 76" className="block size-full" aria-hidden="true">
      <rect width="120" height="76" fill={palette.canvas} />
      <rect x="10" y="14" width="110" height="62" rx="7" fill={palette.sidebar} />
      <circle cx="17" cy="21" r="1.6" fill={palette.line} />
      <circle cx="22" cy="21" r="1.6" fill={palette.line} />
      <circle cx="27" cy="21" r="1.6" fill={palette.line} />
      <rect x="15" y="30" width="16" height="3" rx="1.5" fill={palette.line} />
      <rect x="15" y="37" width="20" height="3" rx="1.5" fill={palette.line} />
      <rect x="15" y="44" width="12" height="3" rx="1.5" fill={palette.line} />
      <rect x="40" y="20" width="80" height="56" rx="6" fill={palette.card} />
      <rect x="47" y="28" width="22" height="3" rx="1.5" fill={palette.line} />
      <rect x="47" y="35" width="34" height="3" rx="1.5" fill={palette.tile} />
      <rect x="47" y="45" width="20" height="14" rx="3" fill={palette.tile} />
      <rect x="71" y="45" width="20" height="14" rx="3" fill={palette.tile} />
      <rect x="95" y="45" width="20" height="14" rx="3" fill={palette.tile} />
    </svg>
  )
}

function ThemeSketch({ theme }: { theme: ThemePreference }): JSX.Element {
  if (theme === 'system') {
    return (
      <span className="relative block size-full">
        <WindowSketch palette={palettes.light} />
        <span className="absolute inset-0 [clip-path:polygon(100%_0,100%_100%,0_100%)]">
          <WindowSketch palette={palettes.dark} />
        </span>
      </span>
    )
  }
  return <WindowSketch palette={palettes[theme]} />
}

export function ThemePreviewPicker({
  items,
  value,
  disabled,
  labelledBy,
  onValueChange
}: ThemePreviewPickerProps): JSX.Element {
  return (
    <RadioGroup
      aria-labelledby={labelledBy}
      value={value}
      disabled={disabled}
      onValueChange={(next) => onValueChange(next as ThemePreference)}
      className="grid max-w-[480px] grid-cols-3 gap-3 max-[430px]:gap-2"
    >
      {items.map((item) => (
        <label key={item.value} className="group/theme grid cursor-pointer gap-2 text-center">
          <Radio.Root
            value={item.value}
            className={cn(
              'relative block aspect-[120/76] overflow-hidden rounded-2xl shadow-(--keycap-shadow) outline-none',
              'transition-[box-shadow,scale] duration-150 ease-out active:scale-[0.98]',
              'focus-visible:ring-ring/60 focus-visible:ring-3',
              'data-checked:shadow-[0_0_0_2px_var(--card),0_0_0_4px_var(--foreground)]',
              'data-disabled:cursor-not-allowed data-disabled:opacity-50'
            )}
          >
            <ThemeSketch theme={item.value} />
            <Radio.Indicator className="bg-foreground text-background absolute bottom-1.5 left-1.5 grid size-5 place-items-center rounded-full">
              <Check className="size-3" strokeWidth={3} aria-hidden="true" />
            </Radio.Indicator>
          </Radio.Root>
          <span className="text-muted-foreground group-has-data-checked/theme:text-foreground text-xs font-medium">
            {item.label}
          </span>
        </label>
      ))}
    </RadioGroup>
  )
}
