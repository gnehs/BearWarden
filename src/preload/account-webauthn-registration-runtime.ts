import type {
  AccountWebAuthnAttestation,
  AccountWebAuthnRegistrationChallenge
} from '../main/account-webauthn-registration-codec'
import {
  ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL,
  ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL,
  type AccountWebAuthnRegistrationFailureReason,
  type AccountWebAuthnRegistrationWindowConfiguration,
  type AccountWebAuthnRegistrationWindowIdentity
} from '../main/account-webauthn-registration-window-protocol'

const CONNECTOR_PATH = '/webauthn-connector.html'

export interface AccountWebAuthnRegistrationIpc {
  invoke(channel: string, input: unknown): Promise<unknown>
  send(channel: string, input: unknown): void
}

export interface AccountWebAuthnRegistrationWindow {
  readonly location: { readonly href: string }
  readonly navigator: Pick<Navigator, 'credentials'>
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
  expected: AccountWebAuthnRegistrationWindowIdentity,
  actualUrl: string
): AccountWebAuthnRegistrationWindowConfiguration | null {
  const record = strictRecord(value, ['epoch', 'capability', 'connectorUrl', 'challenge'])
  if (
    record === null ||
    record.epoch !== expected.epoch ||
    record.capability !== expected.capability ||
    record.connectorUrl !== actualUrl
  ) {
    return null
  }
  try {
    const connector = new URL(actualUrl)
    if (
      connector.protocol !== 'https:' ||
      connector.username !== '' ||
      connector.password !== '' ||
      connector.pathname !== CONNECTOR_PATH ||
      connector.search !== '' ||
      connector.hash !== '' ||
      connector.href !== actualUrl
    ) {
      return null
    }
  } catch {
    return null
  }
  return {
    epoch: expected.epoch,
    capability: expected.capability,
    connectorUrl: actualUrl,
    challenge: record.challenge as AccountWebAuthnRegistrationChallenge
  }
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value)
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function decodeBase64Url(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) {
    throw new TypeError('Invalid binary input')
  }
  const standard = value.replaceAll('-', '+').replaceAll('_', '/')
  const binary = atob(standard.padEnd(Math.ceil(standard.length / 4) * 4, '='))
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  if (encodeBase64Url(bytes.buffer) !== value) throw new TypeError('Invalid binary input')
  return bytes.buffer
}

/** Kept inside the isolated preload bundle; no conversion helper is exposed to page JavaScript. */
export function registrationChallengeToPublicKeyOptions(
  challenge: AccountWebAuthnRegistrationChallenge
): PublicKeyCredentialCreationOptions {
  const extensions: Record<string, unknown> = { ...challenge.extensions }
  if (challenge.extensions.credBlob !== undefined) {
    extensions.credBlob = decodeBase64Url(challenge.extensions.credBlob)
  }
  if (challenge.extensions.prf?.eval !== undefined) {
    extensions.prf = {
      eval: {
        first: decodeBase64Url(challenge.extensions.prf.eval.first),
        ...(challenge.extensions.prf.eval.second === undefined
          ? {}
          : { second: decodeBase64Url(challenge.extensions.prf.eval.second) })
      }
    }
  }

  return {
    rp: { ...challenge.rp },
    user: {
      id: decodeBase64Url(challenge.user.id),
      name: challenge.user.name,
      displayName: challenge.user.displayName
    },
    challenge: decodeBase64Url(challenge.challenge),
    pubKeyCredParams: challenge.pubKeyCredParams.map((parameter) => ({ ...parameter })),
    ...(challenge.timeout === undefined ? {} : { timeout: challenge.timeout }),
    excludeCredentials: challenge.excludeCredentials.map((credential) => ({
      type: credential.type,
      id: decodeBase64Url(credential.id),
      ...(credential.transports === undefined
        ? {}
        : { transports: [...credential.transports] as AuthenticatorTransport[] })
    })),
    authenticatorSelection: { ...challenge.authenticatorSelection },
    attestation: challenge.attestation,
    extensions: extensions as AuthenticationExtensionsClientInputs
  }
}

function binary(value: unknown): ArrayBuffer {
  if (!(value instanceof ArrayBuffer) || value.byteLength === 0) {
    throw new TypeError('Invalid credential result')
  }
  return value
}

function booleanExtension(
  value: unknown,
  key: string
): Readonly<Record<string, boolean>> | undefined {
  if (value === undefined) return undefined
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Invalid credential result')
  }
  const result = (value as Record<string, unknown>)[key]
  if (result === undefined) return Object.freeze({})
  if (typeof result !== 'boolean') throw new TypeError('Invalid credential result')
  return Object.freeze({ [key]: result })
}

function extensionResults(value: unknown): AccountWebAuthnAttestation['clientExtensionResults'] {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Invalid credential result')
  }
  const source = value as Record<string, unknown>
  const credProps = booleanExtension(source.credProps, 'rk')
  const largeBlob = booleanExtension(source.largeBlob, 'supported')
  const prf = booleanExtension(source.prf, 'enabled')
  let uvm: readonly (readonly number[])[] | undefined
  if (source.uvm !== undefined) {
    if (!Array.isArray(source.uvm) || source.uvm.length > 16) {
      throw new TypeError('Invalid credential result')
    }
    uvm = Object.freeze(
      source.uvm.map((row) => {
        if (
          !Array.isArray(row) ||
          row.length !== 3 ||
          row.some(
            (entry) =>
              typeof entry !== 'number' ||
              !Number.isSafeInteger(entry) ||
              entry < 0 ||
              entry > 0xffff_ffff
          )
        ) {
          throw new TypeError('Invalid credential result')
        }
        return Object.freeze([...row] as number[])
      })
    )
  }
  return Object.freeze({
    ...(credProps === undefined ? {} : { credProps }),
    ...(largeBlob === undefined ? {} : { largeBlob }),
    ...(prf === undefined ? {} : { prf }),
    ...(uvm === undefined ? {} : { uvm })
  })
}

/** Serializes only the WebAuthn fields accepted by the main-side strict codec. */
export function credentialToAccountWebAuthnAttestation(
  value: Credential | null
): AccountWebAuthnAttestation {
  if (value === null || value.type !== 'public-key')
    throw new TypeError('Invalid credential result')
  const credential = value as PublicKeyCredential
  const response = credential.response as AuthenticatorAttestationResponse
  const rawId = encodeBase64Url(binary(credential.rawId))
  if (credential.id !== rawId) throw new TypeError('Invalid credential result')
  const attachment = credential.authenticatorAttachment
  if (attachment !== null && attachment !== 'platform' && attachment !== 'cross-platform') {
    throw new TypeError('Invalid credential result')
  }
  return Object.freeze({
    id: rawId,
    rawId,
    type: 'public-key',
    response: Object.freeze({
      clientDataJSON: encodeBase64Url(binary(response.clientDataJSON)),
      attestationObject: encodeBase64Url(binary(response.attestationObject))
    }),
    clientExtensionResults: extensionResults(credential.getClientExtensionResults()),
    authenticatorAttachment: attachment
  })
}

function failureReason(error: unknown): AccountWebAuthnRegistrationFailureReason {
  let name = ''
  try {
    if (
      error !== null &&
      typeof error === 'object' &&
      typeof (error as { name?: unknown }).name === 'string'
    ) {
      name = (error as { name: string }).name
    }
  } catch {
    return 'unknown'
  }
  switch (name) {
    case 'AbortError':
      return 'aborted'
    case 'InvalidStateError':
      return 'invalid-state'
    case 'NotAllowedError':
      return 'not-allowed'
    case 'NotSupportedError':
      return 'not-supported'
    case 'SecurityError':
      return 'security'
    default:
      return 'unknown'
  }
}

/**
 * Starts the native creation ceremony from the isolated world. The loaded page receives no API,
 * data, or callback and cannot suppress this work by throwing from its own scripts.
 */
export function startAccountWebAuthnRegistration(
  ipc: AccountWebAuthnRegistrationIpc,
  registrationWindow: AccountWebAuthnRegistrationWindow,
  identity: AccountWebAuthnRegistrationWindowIdentity
): () => void {
  let active = true
  const abortController = new AbortController()

  const sendTerminal = (payload: Record<string, unknown>): void => {
    if (!active) return
    active = false
    try {
      ipc.send(ACCOUNT_WEBAUTHN_REGISTRATION_EVENT_CHANNEL, { ...identity, ...payload })
    } catch {
      // The main process owns timeout and window-loss termination.
    }
  }

  void (async () => {
    try {
      const configuration = parseConfiguration(
        await ipc.invoke(ACCOUNT_WEBAUTHN_REGISTRATION_INIT_CHANNEL, identity),
        identity,
        registrationWindow.location.href
      )
      if (configuration === null) throw new TypeError('Invalid registration configuration')
      const publicKey = registrationChallengeToPublicKeyOptions(configuration.challenge)
      const credential = await registrationWindow.navigator.credentials.create({
        publicKey,
        signal: abortController.signal
      })
      sendTerminal({
        type: 'success',
        attestation: credentialToAccountWebAuthnAttestation(credential)
      })
    } catch (error) {
      sendTerminal({ type: 'failure', reason: failureReason(error) })
    }
  })()

  return () => {
    active = false
    abortController.abort()
  }
}
