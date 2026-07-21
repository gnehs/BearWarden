import { beforeEach, describe, expect, it } from 'vitest'
import { useVaultRuntimeStore } from './vault-runtime-store'

describe('vault runtime store', () => {
  beforeEach(() => {
    useVaultRuntimeStore.setState({ vaultState: 'loading', statusAttempt: 0 })
  })

  it('projects authoritative vault lifecycle updates', () => {
    useVaultRuntimeStore.getState().applyVaultState('unlocked')
    expect(useVaultRuntimeStore.getState().vaultState).toBe('unlocked')

    useVaultRuntimeStore.getState().applyVaultState('locked')
    expect(useVaultRuntimeStore.getState().vaultState).toBe('locked')
  })

  it('starts a fresh status attempt without retaining the previous result', () => {
    useVaultRuntimeStore.getState().applyVaultState('unavailable')
    useVaultRuntimeStore.getState().retryVaultStatus()

    expect(useVaultRuntimeStore.getState()).toMatchObject({
      vaultState: 'loading',
      statusAttempt: 1
    })
  })
})
