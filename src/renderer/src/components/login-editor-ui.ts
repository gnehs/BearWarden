export function editorHeaderContent(
  typeLabel: string,
  itemName: string | null
): { eyebrow: string; heading: string; typeBadge: string | null } {
  return itemName === null
    ? { eyebrow: '新增項目', heading: typeLabel, typeBadge: null }
    : { eyebrow: `編輯${typeLabel}`, heading: itemName, typeBadge: typeLabel }
}
