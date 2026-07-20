import { describe, expect, it, vi } from 'vitest'
import type { AutofillDiscoveryResult } from './autofill'
import { AutofillCoordinator } from './autofill-coordinator'
import { MacOSAutofillError, type MacOSBrowserContext } from './macos-autofill-adapter'
import { VaultError } from './vault-errors'

const context: MacOSBrowserContext = {
  pid: 42,
  bundleIdentifier: 'com.apple.Safari',
  browser: 'safari',
  url: 'https://login.example.test/path',
  focus: {
    role: 'AXTextField',
    subrole: null,
    editable: true,
    secure: false,
    x: 100,
    y: 200,
    width: 240,
    height: 32
  }
}

function discovery(count = 2, reprompt: 0 | 1 = 0): AutofillDiscoveryResult {
  return {
    generation: 7,
    targetUrl: context.url,
    candidates: Array.from({ length: count }, (_, index) => ({
      id: `00000000-0000-4000-8000-00000000000${index + 1}`,
      name: `Login ${index + 1}`,
      username: reprompt ? '' : `user-${index + 1}`,
      hostname: 'login.example.test',
      reprompt,
      updatedAt: '2026-07-20T00:00:00.000Z'
    }))
  }
}

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function harness(result = discovery()) {
  const publish = vi.fn()
  const showPicker = vi.fn()
  const hidePicker = vi.fn()
  const fill = vi.fn(async () => undefined)
  const captureContext = vi.fn(async () => context)
  const performAutofill = vi.fn(async (_request, validate, consume) => {
    if (!validate([], { generation: 7 })) {
      // Ordinary items do not require the validator. The fake mirrors that distinction.
    }
    await consume({ username: 'secret-user', password: 'secret-password' })
  })
  const coordinator = new AutofillCoordinator({
    vault: {
      discoverAutofillCandidates: vi.fn(async () => result),
      performAutofill
    },
    platform: {
      context: captureContext,
      fill
    },
    publish,
    showPicker,
    hidePicker,
    openMain: vi.fn(),
    createRequestId: () => 'request-1'
  })
  return {
    coordinator,
    publish,
    showPicker,
    hidePicker,
    fill,
    performAutofill,
    captureContext
  }
}

describe('AutofillCoordinator', () => {
  it('publishes only metadata and waits for an explicit choice when multiple logins match', async () => {
    const { coordinator, publish, showPicker, fill } = harness()

    await coordinator.trigger()

    expect(showPicker).toHaveBeenCalledOnce()
    expect(fill).not.toHaveBeenCalled()
    expect(coordinator.current()).toMatchObject({
      requestId: 'request-1',
      hostname: 'login.example.test',
      status: 'ready',
      choices: [{ name: 'Login 1' }, { name: 'Login 2' }]
    })
    expect(JSON.stringify(publish.mock.calls)).not.toContain('secret-password')
  })

  it('fills the only unprotected match without exposing secrets to the picker', async () => {
    const { coordinator, fill, hidePicker, performAutofill, publish } = harness(discovery(1))

    await coordinator.trigger()

    expect(performAutofill).toHaveBeenCalledOnce()
    expect(fill).toHaveBeenCalledWith(
      context,
      { username: 'secret-user', password: 'secret-password' },
      expect.any(AbortSignal)
    )
    expect(hidePicker).toHaveBeenCalled()
    expect(coordinator.current()).toBeNull()
    expect(JSON.stringify(publish.mock.calls)).not.toContain('secret-password')
  })

  it('rejects stale or unknown picker selections', async () => {
    const { coordinator, performAutofill } = harness()
    await coordinator.trigger()

    await coordinator.select({ requestId: 'stale', itemId: discovery().candidates[0]!.id })
    await coordinator.select({ requestId: 'request-1', itemId: 'unknown' })

    expect(performAutofill).not.toHaveBeenCalled()
  })

  it('keeps protected matches in the picker and fails closed on reprompt', async () => {
    const protectedDiscovery = discovery(1, 1)
    const { coordinator, performAutofill, publish } = harness(protectedDiscovery)
    performAutofill.mockRejectedValueOnce(new VaultError('REPROMPT_REQUIRED'))
    await coordinator.trigger()

    await coordinator.select({
      requestId: 'request-1',
      itemId: protectedDiscovery.candidates[0]!.id
    })

    expect(coordinator.current()).toMatchObject({
      status: 'error',
      error: 'REPROMPT_REQUIRED'
    })
    expect(JSON.stringify(publish.mock.calls)).not.toContain('secret-password')
  })

  it('reports denied Accessibility without repeatedly prompting from the shortcut', async () => {
    const { coordinator, publish, captureContext } = harness()
    captureContext.mockRejectedValueOnce(new MacOSAutofillError('ACCESSIBILITY_PERMISSION_DENIED'))

    await coordinator.trigger()

    expect(publish).toHaveBeenLastCalledWith(
      expect.objectContaining({ error: 'ACCESSIBILITY_PERMISSION_DENIED' })
    )
  })

  it('invalidates an in-flight context read when lock or account switch cancels it', async () => {
    const { coordinator, captureContext, showPicker } = harness()
    let resolveContext!: (value: MacOSBrowserContext) => void
    captureContext.mockImplementationOnce(
      () => new Promise<MacOSBrowserContext>((resolve) => (resolveContext = resolve))
    )

    const trigger = coordinator.trigger()
    coordinator.cancel()
    resolveContext(context)
    await trigger

    expect(showPicker).not.toHaveBeenCalled()
    expect(coordinator.current()).toBeNull()
  })
})
