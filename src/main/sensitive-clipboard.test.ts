import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SensitiveClipboard } from './sensitive-clipboard'

describe('SensitiveClipboard', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  function harness(): { clipboard: SensitiveClipboard; state: { value: string } } {
    const state = { value: '' }
    return {
      state,
      clipboard: new SensitiveClipboard({
        writeText: (value) => {
          state.value = value
        },
        readText: () => state.value,
        clear: () => {
          state.value = ''
        }
      })
    }
  }

  it('enforces a per-write maximum even when normal clearing is disabled', () => {
    const { clipboard, state } = harness()
    clipboard.setClearDelay(0)
    clipboard.write('api-secret', 30)
    vi.advanceTimersByTime(29_999)
    expect(state.value).toBe('api-secret')
    clipboard.setClearDelay(0)
    vi.advanceTimersByTime(1)
    expect(state.value).toBe('')
  })

  it('keeps the shorter user timeout and never clears replacement content', () => {
    const { clipboard, state } = harness()
    clipboard.setClearDelay(15)
    clipboard.write('api-secret', 30)
    state.value = 'user replacement'
    vi.advanceTimersByTime(15_000)
    expect(state.value).toBe('user replacement')
  })
})
