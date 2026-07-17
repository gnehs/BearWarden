const dateTimeFormatter = new Intl.DateTimeFormat('zh-TW', {
  dateStyle: 'medium',
  timeStyle: 'short'
})

export function formatVaultDate(value: string | null): string {
  if (!value) return '尚未使用'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '未知'
  return dateTimeFormatter.format(date)
}
