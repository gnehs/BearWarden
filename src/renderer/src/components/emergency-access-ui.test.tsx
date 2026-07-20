import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { EmergencyAccessStatus, EmergencyAccessView } from '../../../shared/vault-contract'
import { EmergencyAccessContent } from './EmergencyAccessPage'
import {
  emergencyAccessCreationLabel,
  emergencyAccessDisplayName,
  emergencyAccessStatusLabel,
  safeEmergencyAccessAvatarColor
} from './emergency-access-ui'

const entry: EmergencyAccessView = {
  id: '60000000-0000-4000-8000-000000000001',
  role: 'trusted',
  subjectId: '60000000-0000-4000-8000-000000000002',
  name: null,
  email: 'trusted@example.invalid',
  type: 0,
  status: 3,
  waitTimeDays: 7,
  creationDate: null,
  avatarColor: null
}

describe('Emergency Access UI', () => {
  it('uses the email when the remote display name is null, empty, or whitespace', () => {
    expect(emergencyAccessDisplayName(entry)).toBe('trusted@example.invalid')
    expect(emergencyAccessDisplayName({ ...entry, name: '' })).toBe('trusted@example.invalid')
    expect(emergencyAccessDisplayName({ ...entry, name: '   ' })).toBe('trusted@example.invalid')
  })

  it('uses the official status labels and only accepts safe avatar colors', () => {
    expect(
      [0, 1, 2, 3, 4].map((status) => emergencyAccessStatusLabel(status as EmergencyAccessStatus))
    ).toEqual(['已邀請', '已接受邀請', '已確認', '已提出存取要求', '已核准存取'])
    expect(safeEmergencyAccessAvatarColor('#12abEF')).toBe('#12abEF')
    expect(safeEmergencyAccessAvatarColor('url(example.invalid)')).toBeUndefined()
    expect(emergencyAccessCreationLabel(null)).toBeNull()
  })

  it('renders a visible error state with retry instead of an empty result', () => {
    const markup = renderToStaticMarkup(
      <EmergencyAccessContent entries={[]} loading={false} failed onRetry={vi.fn()} />
    )

    expect(markup).toContain('無法載入 Emergency Access')
    expect(markup).toContain('重試')
    expect(markup).not.toContain('尚未設定 Emergency Access')
  })

  it('renders available access metadata and tolerates missing optional metadata', () => {
    const markup = renderToStaticMarkup(
      <EmergencyAccessContent entries={[entry]} loading={false} failed={false} onRetry={vi.fn()} />
    )

    expect(markup).toContain('trusted@example.invalid')
    expect(markup).toContain('權限：檢視')
    expect(markup).toContain('狀態：已提出存取要求')
    expect(markup).toContain('等待 7 天')
    expect(markup).not.toContain('建立於')
  })
})
