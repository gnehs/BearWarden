import {
  ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL,
  ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL,
  type AccountWebAuthnWrapperConfiguration,
  type AccountWebAuthnWrapperIdentity
} from '../main/account-webauthn-window-protocol'

const MAX_CONNECTOR_URL_LENGTH = 128 * 1_024
const MAX_MESSAGE_LENGTH = 128 * 1_024
const CONNECTOR_PATH = '/webauthn-connector.html'
const CHILD_FRAME_NAME = 'bearwarden-account-webauthn-connector'
const CHILD_FEATURES = 'popup,width=520,height=680,resizable=yes'

interface WrapperIpc {
  invoke(channel: string, input: unknown): Promise<unknown>
  send(channel: string, input: unknown): void
}

interface WrapperWindow {
  readonly location: { readonly href: string }
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  open(url: string, target: string, features: string): Window | null
}

function strictRecord(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  try {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) return null
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const ownKeys = Reflect.ownKeys(descriptors)
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some(
        (key) => typeof key !== 'string' || !keys.includes(key) || !('value' in descriptors[key]!)
      )
    ) {
      return null
    }
    const snapshot = Object.create(null) as Record<string, unknown>
    for (const key of keys) snapshot[key] = descriptors[key]!.value
    return snapshot
  } catch {
    return null
  }
}

function parseConfiguration(
  value: unknown,
  expected: AccountWebAuthnWrapperIdentity,
  actualWrapperUrl: string
): AccountWebAuthnWrapperConfiguration | null {
  const record = strictRecord(value, [
    'epoch',
    'capability',
    'wrapperUrl',
    'connectorUrl',
    'connectorOrigin'
  ])
  if (
    record === null ||
    record.epoch !== expected.epoch ||
    record.capability !== expected.capability ||
    record.wrapperUrl !== actualWrapperUrl ||
    typeof record.connectorUrl !== 'string' ||
    record.connectorUrl.length === 0 ||
    record.connectorUrl.length > MAX_CONNECTOR_URL_LENGTH ||
    typeof record.connectorOrigin !== 'string'
  ) {
    return null
  }

  try {
    const connector = new URL(record.connectorUrl)
    if (
      connector.protocol !== 'https:' ||
      connector.username !== '' ||
      connector.password !== '' ||
      connector.pathname !== CONNECTOR_PATH ||
      connector.origin !== record.connectorOrigin ||
      connector.searchParams.get('parent') !== actualWrapperUrl ||
      connector.searchParams.get('v') !== '1' ||
      [...connector.searchParams.keys()].sort().join(',') !== 'data,parent,v'
    ) {
      return null
    }
  } catch {
    return null
  }

  return {
    epoch: expected.epoch,
    capability: expected.capability,
    wrapperUrl: actualWrapperUrl,
    connectorUrl: record.connectorUrl,
    connectorOrigin: record.connectorOrigin
  }
}

/**
 * Runs only in the wrapper preload's isolated world. The retained child WindowProxy never crosses
 * IPC; it is compared directly with MessageEvent.source in the same JavaScript world.
 */
export async function startAccountWebAuthnWrapper(
  ipc: WrapperIpc,
  wrapperWindow: WrapperWindow,
  identity: AccountWebAuthnWrapperIdentity
): Promise<() => void> {
  let active = true
  let child: Window | null = null
  let readyReceived = false

  const safeSend = (input: unknown): void => {
    try {
      ipc.send(ACCOUNT_WEBAUTHN_WRAPPER_EVENT_CHANNEL, input)
    } catch {
      active = false
    }
  }

  const cancel = (): void => {
    if (!active) return
    active = false
    safeSend({ ...identity, type: 'cancel' })
  }

  let configurationValue: unknown = null
  try {
    configurationValue = await ipc.invoke(ACCOUNT_WEBAUTHN_WRAPPER_INIT_CHANNEL, identity)
  } catch {
    // The authenticated cancel below terminates the main-side one-shot when IPC remains usable.
  }
  const configuration = parseConfiguration(
    configurationValue,
    identity,
    wrapperWindow.location.href
  )
  if (configuration === null) {
    cancel()
    return () => undefined
  }

  const handleMessage = (event: MessageEvent): void => {
    if (
      !active ||
      child === null ||
      event.source !== child ||
      event.origin !== configuration.connectorOrigin ||
      typeof event.data !== 'string' ||
      event.data.length === 0 ||
      event.data.length > MAX_MESSAGE_LENGTH
    ) {
      return
    }
    if (event.data === 'info|ready') {
      if (readyReceived) return
      readyReceived = true
    } else {
      active = false
    }
    safeSend({
      ...identity,
      type: 'message',
      data: event.data
    })
  }

  wrapperWindow.addEventListener('message', handleMessage)
  try {
    child = wrapperWindow.open(configuration.connectorUrl, CHILD_FRAME_NAME, CHILD_FEATURES)
  } catch {
    child = null
  }
  if (child === null) cancel()

  return () => {
    active = false
    child = null
    wrapperWindow.removeEventListener('message', handleMessage)
  }
}
