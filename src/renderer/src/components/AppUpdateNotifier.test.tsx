import { beforeEach, describe, expect, it, vi } from 'vitest'
import { toast } from 'sonner'
import type { AppUpdateState } from '../../../shared/vault-contract'
import { presentAppUpdateState } from '../lib/app-update-ui'

vi.mock('sonner', () => ({
  toast: {
    dismiss: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    loading: vi.fn(),
    success: vi.fn()
  }
}))

function updateState(overrides: Partial<AppUpdateState> = {}): AppUpdateState {
  return {
    status: 'idle',
    currentVersion: '1.0.0',
    availableVersion: null,
    progress: null,
    canAutoInstall: true,
    ...overrides
  }
}

describe('app update notifications', () => {
  beforeEach(() => vi.clearAllMocks())

  it('offers an in-app download on supported platforms', () => {
    presentAppUpdateState(
      updateState({ status: 'available', availableVersion: '1.1.0', canAutoInstall: true })
    )

    expect(toast.info).toHaveBeenCalledWith(
      'BearWarden 1.1.0 可供更新',
      expect.objectContaining({ action: expect.objectContaining({ label: '下載更新' }) })
    )
  })

  it('sends unsigned macOS builds to the fixed release page flow', () => {
    presentAppUpdateState(
      updateState({ status: 'available', availableVersion: '1.1.0', canAutoInstall: false })
    )

    expect(toast.info).toHaveBeenCalledWith(
      'BearWarden 1.1.0 可供更新',
      expect.objectContaining({ action: expect.objectContaining({ label: '前往下載' }) })
    )
  })

  it('shows bounded download progress and an explicit restart action', () => {
    presentAppUpdateState(
      updateState({ status: 'downloading', availableVersion: '1.1.0', progress: 49.6 })
    )
    expect(toast.loading).toHaveBeenCalledWith(
      '正在下載 BearWarden 1.1.0',
      expect.objectContaining({ description: '50%' })
    )

    presentAppUpdateState(
      updateState({ status: 'downloaded', availableVersion: '1.1.0', progress: 100 })
    )
    expect(toast.success).toHaveBeenCalledWith(
      'BearWarden 1.1.0 已準備好',
      expect.objectContaining({
        action: expect.objectContaining({ label: '重新啟動並安裝' })
      })
    )
  })

  it('keeps background check failures quiet but reports download failures', () => {
    const error = updateState({ status: 'error' })
    presentAppUpdateState(error)
    expect(toast.error).not.toHaveBeenCalled()

    presentAppUpdateState(error, true)
    expect(toast.error).toHaveBeenCalledWith('無法下載更新', expect.any(Object))
  })
})
