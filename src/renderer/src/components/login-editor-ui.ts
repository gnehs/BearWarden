export function editorHeaderContent(
  typeLabel: string,
  itemName: string | null
): { eyebrow: string; heading: string; typeBadge: string | null } {
  return itemName === null
    ? { eyebrow: '新增項目', heading: typeLabel, typeBadge: null }
    : { eyebrow: `編輯${typeLabel}`, heading: itemName, typeBadge: typeLabel }
}

export const uriMatchOptions = [
  {
    value: 'default',
    label: '帳號預設'
  },
  {
    value: '0',
    label: '基礎網域'
  },
  {
    value: '1',
    label: '主機'
  },
  {
    value: '2',
    label: '開頭符合'
  },
  {
    value: '3',
    label: '完全符合'
  },
  {
    value: '4',
    label: '正規表示式'
  },
  {
    value: '5',
    label: '永不符合'
  }
] as const

export type UriMatchOptionValue = (typeof uriMatchOptions)[number]['value']

export function uriMatchExample(value: UriMatchOptionValue, rawUri: string): string {
  const uri = rawUri.trim()
  if (!uri) return '輸入網址後顯示匹配範例'

  switch (value) {
    case 'default':
      return `${uri} → 依帳號設定判斷 ○網址△`
    case '0':
      return `${uri} ≈ 相同基礎網域的 ○網址△`
    case '1':
      return `${uri} ≈ 相同主機的 ○路徑△`
    case '2':
      return `${uri} ≈ ${uri}○△`
    case '3':
      return `${uri} = ${uri}；○△ 不符合`
    case '4':
      return `${uri} → 匹配符合規則的 ○網址△`
    case '5':
      return `${uri} ≠ 所有 ○網址△`
  }
}
