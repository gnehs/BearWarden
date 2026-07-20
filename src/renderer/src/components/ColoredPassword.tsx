import { cn } from '@renderer/lib/utils'

function passwordCharClassName(char: string): string {
  if (char >= '0' && char <= '9') return 'text-sky-600 dark:text-sky-400'
  if ((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')) {
    return 'text-foreground'
  }
  return 'text-amber-600 dark:text-amber-400'
}

export function ColoredPassword({
  value,
  className
}: {
  value: string
  className?: string
}): React.JSX.Element {
  return (
    <span className={cn('font-mono break-all', className)}>
      {Array.from(value).map((char, index) => (
        <span key={`${index}:${char}`} className={passwordCharClassName(char)}>
          {char}
        </span>
      ))}
    </span>
  )
}
