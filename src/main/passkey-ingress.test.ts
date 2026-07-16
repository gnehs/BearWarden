import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  bindPasskeyIngressRequest,
  PasskeyIngressError,
  type PasskeyIngressErrorCode,
  type PasskeyIngressTransportContext
} from './passkey-ingress'

const CHALLENGE = Uint8Array.from({ length: 32 }, (_, index) => index + 1)
const OTHER_CHALLENGE = Uint8Array.from({ length: 32 }, (_, index) => 255 - index)

function b64(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url')
}

function clientData(
  kind: 'create' | 'get',
  challenge = CHALLENGE,
  origin = 'https://login.example.test',
  extra: Record<string, unknown> = {}
): string {
  return b64(
    Buffer.from(
      JSON.stringify({
        type: kind === 'create' ? 'webauthn.create' : 'webauthn.get',
        challenge: b64(challenge),
        origin,
        crossOrigin: false,
        ...extra
      })
    )
  )
}

function createPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    kind: 'create',
    clientDataJSON: clientData('create'),
    options: {
      challenge: b64(CHALLENGE),
      rp: { id: 'example.test', name: 'Example Test' },
      user: {
        id: b64(Uint8Array.from([1, 2, 3, 4])),
        name: 'example-user',
        displayName: 'Example User'
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60_000,
      excludeCredentials: [
        { type: 'public-key', id: b64(Uint8Array.from([5, 6, 7])), transports: ['internal'] }
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required'
      },
      attestation: 'none',
      extensions: {}
    },
    ...overrides
  }
}

function getPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    kind: 'get',
    clientDataJSON: clientData('get'),
    options: {
      challenge: b64(CHALLENGE),
      rpId: 'example.test',
      timeout: 60_000,
      allowCredentials: [
        {
          type: 'public-key',
          id: b64(Uint8Array.from([9, 8, 7])),
          transports: ['internal', 'hybrid']
        }
      ],
      userVerification: 'preferred',
      mediation: 'required',
      extensions: {}
    },
    ...overrides
  }
}

function transport(controller = new AbortController()): PasskeyIngressTransportContext {
  return {
    provider: 'native-provider',
    binding: 'browser-profile:a',
    epoch: 7,
    signal: controller.signal
  }
}

function expectIngressError(
  payload: unknown,
  code: PasskeyIngressErrorCode,
  context: PasskeyIngressTransportContext = transport()
): void {
  try {
    bindPasskeyIngressRequest(payload, context)
    throw new Error(`Expected ${code}`)
  } catch (error) {
    expect(error).toBeInstanceOf(PasskeyIngressError)
    expect((error as PasskeyIngressError).code).toBe(code)
    expect((error as Error).message).toBe(code)
  }
}

function optionsOf(payload: Record<string, unknown>): Record<string, unknown> {
  return payload.options as Record<string, unknown>
}

describe('passkey trusted ingress', () => {
  it('binds a create request to its authenticated peer and preserves exact frozen client bytes', () => {
    const raw = createPayload()
    const encodedClientData = raw.clientDataJSON as string
    const expectedBytes = Buffer.from(encodedClientData, 'base64url')
    const expectedHash = createHash('sha256').update(expectedBytes).digest()
    const snapshot = bindPasskeyIngressRequest(raw, transport())

    expect(snapshot).toMatchObject({
      version: 1,
      kind: 'create',
      peer: { provider: 'native-provider', binding: 'browser-profile:a', epoch: 7 },
      origin: 'https://login.example.test',
      rpId: 'example.test',
      challenge: [...CHALLENGE],
      clientDataJSON: [...expectedBytes],
      clientDataHash: [...expectedHash],
      discoverable: true
    })
    expect(snapshot.requestDigest).toHaveLength(32)
    expect(snapshot.options).toMatchObject({
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      attestation: 'none',
      authenticatorSelection: { userVerification: 'required' }
    })
    expect(Object.isFrozen(snapshot)).toBe(true)
    expect(Object.isFrozen(snapshot.peer)).toBe(true)
    expect(Object.isFrozen(snapshot.clientDataJSON)).toBe(true)
    expect(Object.isFrozen(snapshot.clientDataHash)).toBe(true)
    expect(Object.isFrozen(snapshot.options)).toBe(true)
    expect(snapshot.kind).toBe('create')
    if (snapshot.kind !== 'create') throw new Error('Expected create snapshot')
    expect(Object.isFrozen(snapshot.options.excludeCredentials)).toBe(true)
    expect(Object.isFrozen(snapshot.options.excludeCredentials[0]?.id)).toBe(true)
  })

  it('parses get bounds and defaults without turning ceremony material into renderer data', () => {
    const raw = getPayload()
    raw.options = {
      challenge: b64(CHALLENGE),
      rpId: 'example.test'
    }
    const snapshot = bindPasskeyIngressRequest(raw, transport())

    expect(snapshot).toMatchObject({
      kind: 'get',
      origin: 'https://login.example.test',
      rpId: 'example.test',
      options: {
        userVerification: 'preferred',
        mediation: 'optional',
        allowCredentials: [],
        extensions: {}
      }
    })
    expect(snapshot.signal).toBeInstanceOf(AbortSignal)
    expect(snapshot.kind).toBe('get')
    if (snapshot.kind !== 'get') throw new Error('Expected get snapshot')
    expect(Object.isFrozen(snapshot.options.allowCredentials)).toBe(true)
  })

  it('uses the origin validator canonical RP ID everywhere in the trusted snapshot', () => {
    const raw = createPayload()
    ;(optionsOf(raw).rp as Record<string, unknown>).id = 'EXAMPLE.TEST'
    const snapshot = bindPasskeyIngressRequest(raw, transport())

    expect(snapshot.rpId).toBe('example.test')
    expect(snapshot.kind).toBe('create')
    if (snapshot.kind !== 'create') throw new Error('Expected create snapshot')
    expect(snapshot.options.rp.id).toBe('example.test')
  })

  it('defaults omitted create/get RP IDs to the canonical client origin hostname', () => {
    const create = createPayload()
    delete (optionsOf(create).rp as Record<string, unknown>).id
    const createSnapshot = bindPasskeyIngressRequest(create, transport())
    expect(createSnapshot.rpId).toBe('login.example.test')
    expect(createSnapshot.kind).toBe('create')
    if (createSnapshot.kind !== 'create') throw new Error('Expected create snapshot')
    expect(createSnapshot.options.rp.id).toBe('login.example.test')
    const explicitCreate = createPayload()
    ;(optionsOf(explicitCreate).rp as Record<string, unknown>).id = 'login.example.test'
    expect(bindPasskeyIngressRequest(explicitCreate, transport()).requestDigest).toEqual(
      createSnapshot.requestDigest
    )

    const get = getPayload()
    delete optionsOf(get).rpId
    const getSnapshot = bindPasskeyIngressRequest(get, transport())
    expect(getSnapshot.rpId).toBe('login.example.test')
    expect(getSnapshot.kind).toBe('get')
    if (getSnapshot.kind !== 'get') throw new Error('Expected get snapshot')
    expect(getSnapshot.options.rpId).toBe('login.example.test')
    const explicitGet = getPayload()
    optionsOf(explicitGet).rpId = 'login.example.test'
    expect(bindPasskeyIngressRequest(explicitGet, transport()).requestDigest).toEqual(
      getSnapshot.requestDigest
    )
  })

  it('fails closed on an invalid client origin when the effective RP ID is omitted', () => {
    const create = createPayload({
      clientDataJSON: clientData('create', CHALLENGE, 'not an origin')
    })
    delete (optionsOf(create).rp as Record<string, unknown>).id
    expectIngressError(create, 'ORIGIN_REJECTED')

    const get = getPayload({
      clientDataJSON: clientData('get', CHALLENGE, 'https://127.0.0.1')
    })
    delete optionsOf(get).rpId
    expectIngressError(get, 'ORIGIN_REJECTED')
  })

  it('snapshots all mutable payload and transport identity fields', () => {
    const raw = createPayload()
    const options = optionsOf(raw)
    const rp = options.rp as Record<string, unknown>
    const user = options.user as Record<string, unknown>
    const controller = new AbortController()
    const context = transport(controller) as {
      provider: string
      binding: string
      epoch: number
      signal: AbortSignal
    }
    const snapshot = bindPasskeyIngressRequest(raw, context)
    const digest = [...snapshot.requestDigest]

    raw.clientDataJSON = clientData('create', OTHER_CHALLENGE)
    options.challenge = b64(OTHER_CHALLENGE)
    rp.id = 'evil.test'
    user.name = 'mutated'
    context.provider = 'spoofed-provider'
    context.binding = 'spoofed-binding'
    context.epoch = 99

    expect(snapshot.peer).toEqual({
      provider: 'native-provider',
      binding: 'browser-profile:a',
      epoch: 7
    })
    expect(snapshot.challenge).toEqual([...CHALLENGE])
    expect(snapshot.rpId).toBe('example.test')
    expect(snapshot.kind === 'create' ? snapshot.options.user.name : '').toBe('example-user')
    expect(snapshot.requestDigest).toEqual(digest)
  })

  it('computes a deterministic digest over peer, exact ceremony data, and normalized options', () => {
    const first = bindPasskeyIngressRequest(getPayload(), transport())
    const reordered = getPayload()
    const originalOptions = optionsOf(reordered)
    reordered.options = {
      extensions: originalOptions.extensions,
      mediation: originalOptions.mediation,
      userVerification: originalOptions.userVerification,
      allowCredentials: originalOptions.allowCredentials,
      timeout: originalOptions.timeout,
      rpId: originalOptions.rpId,
      challenge: originalOptions.challenge
    }
    const second = bindPasskeyIngressRequest(reordered, transport())
    expect(second.requestDigest).toEqual(first.requestDigest)

    const otherPeer = bindPasskeyIngressRequest(getPayload(), {
      ...transport(),
      binding: 'browser-profile:b'
    })
    expect(otherPeer.requestDigest).not.toEqual(first.requestDigest)

    const differentExactJson = getPayload({
      clientDataJSON: b64(
        Buffer.from(
          ` { "type":"webauthn.get", "challenge":"${b64(CHALLENGE)}", "origin":"https://login.example.test", "crossOrigin":false } `
        )
      )
    })
    expect(bindPasskeyIngressRequest(differentExactJson, transport()).requestDigest).not.toEqual(
      first.requestDigest
    )
  })

  it('strictly verifies ceremony type and challenge for both create and get', () => {
    expectIngressError(createPayload({ clientDataJSON: clientData('get') }), 'CEREMONY_MISMATCH')
    expectIngressError(
      getPayload({ clientDataJSON: clientData('get', OTHER_CHALLENGE) }),
      'CEREMONY_MISMATCH'
    )

    const mismatchedOption = getPayload()
    optionsOf(mismatchedOption).challenge = b64(OTHER_CHALLENGE)
    expectIngressError(mismatchedOption, 'CEREMONY_MISMATCH')
  })

  it('rejects wrong RP/origin relationships, non-canonical origins, and cross-origin data', () => {
    const wrongRp = getPayload()
    optionsOf(wrongRp).rpId = 'other.test'
    expectIngressError(wrongRp, 'ORIGIN_REJECTED')

    expectIngressError(
      getPayload({ clientDataJSON: clientData('get', CHALLENGE, 'https://evil.test') }),
      'ORIGIN_REJECTED'
    )
    expectIngressError(
      getPayload({
        clientDataJSON: clientData('get', CHALLENGE, 'HTTPS://LOGIN.EXAMPLE.TEST:443')
      }),
      'ORIGIN_REJECTED'
    )
    expectIngressError(
      getPayload({
        clientDataJSON: clientData('get', CHALLENGE, undefined, { crossOrigin: true })
      }),
      'CROSS_ORIGIN_UNSUPPORTED'
    )
    expectIngressError(
      getPayload({
        clientDataJSON: clientData('get', CHALLENGE, undefined, {
          topOrigin: 'https://top.example.test'
        })
      }),
      'CROSS_ORIGIN_UNSUPPORTED'
    )
  })

  it('rejects unknown fields and duplicate client data keys instead of accepting overlays', () => {
    expectIngressError({ ...getPayload(), peer: { binding: 'spoof' } }, 'INVALID_PAYLOAD')

    const unknownOptions = getPayload()
    optionsOf(unknownOptions).unexpected = true
    expectIngressError(unknownOptions, 'INVALID_PAYLOAD')

    const symbolOptions = getPayload()
    ;(optionsOf(symbolOptions) as Record<PropertyKey, unknown>)[Symbol('overlay')] = true
    expectIngressError(symbolOptions, 'INVALID_PAYLOAD')

    expectIngressError(
      getPayload({ clientDataJSON: clientData('get', CHALLENGE, undefined, { unexpected: true }) }),
      'INVALID_CLIENT_DATA'
    )
    const duplicateType = `{"type":"webauthn.get","type":"webauthn.create","challenge":"${b64(CHALLENGE)}","origin":"https://login.example.test"}`
    expectIngressError(
      getPayload({ clientDataJSON: b64(Buffer.from(duplicateType)) }),
      'INVALID_CLIENT_DATA'
    )

    const throwingProxy = new Proxy(getPayload(), {
      ownKeys: () => {
        throw new Error('provider-controlled secret')
      }
    })
    expectIngressError(throwingProxy, 'INVALID_PAYLOAD')
  })

  it('rejects non-canonical base64url and bounded binary/text collections', () => {
    const paddedClientData = getPayload()
    paddedClientData.clientDataJSON = `${paddedClientData.clientDataJSON as string}=`
    expectIngressError(paddedClientData, 'INVALID_CLIENT_DATA')

    const paddedChallenge = getPayload()
    optionsOf(paddedChallenge).challenge = `${b64(CHALLENGE)}=`
    expectIngressError(paddedChallenge, 'INVALID_PAYLOAD')

    const shortChallenge = getPayload()
    optionsOf(shortChallenge).challenge = b64(Uint8Array.from([1]))
    expectIngressError(shortChallenge, 'INVALID_PAYLOAD')

    const oversizedChallenge = getPayload()
    optionsOf(oversizedChallenge).challenge = b64(new Uint8Array(1_025))
    expectIngressError(oversizedChallenge, 'INVALID_PAYLOAD')

    const oversizedClientData = getPayload()
    oversizedClientData.clientDataJSON = b64(new Uint8Array(8_193))
    expectIngressError(oversizedClientData, 'INVALID_CLIENT_DATA')

    const oversizedUser = createPayload()
    ;(optionsOf(oversizedUser).user as Record<string, unknown>).id = b64(new Uint8Array(65))
    expectIngressError(oversizedUser, 'INVALID_PAYLOAD')

    const tooManyDescriptors = getPayload()
    optionsOf(tooManyDescriptors).allowCredentials = Array.from({ length: 129 }, (_, index) => ({
      type: 'public-key',
      id: b64(Uint8Array.from([index >> 8, index & 0xff]))
    }))
    expectIngressError(tooManyDescriptors, 'INVALID_PAYLOAD')
  })

  it('keeps all known transports including smart-card and ignores bounded unknown values', () => {
    const payload = getPayload()
    optionsOf(payload).allowCredentials = [
      {
        type: 'public-key',
        id: b64(Uint8Array.from([1, 2, 3])),
        transports: [
          'usb',
          'nfc',
          'ble',
          'smart-card',
          'hybrid',
          'internal',
          'future-transport',
          'smart-card'
        ]
      }
    ]
    const snapshot = bindPasskeyIngressRequest(payload, transport())
    expect(snapshot.kind).toBe('get')
    if (snapshot.kind !== 'get') throw new Error('Expected get snapshot')
    expect(snapshot.options.allowCredentials[0]?.transports).toEqual([
      'usb',
      'nfc',
      'ble',
      'smart-card',
      'hybrid',
      'internal'
    ])

    const unknownOnly = getPayload()
    optionsOf(unknownOnly).allowCredentials = [
      {
        type: 'public-key',
        id: b64(Uint8Array.from([4, 5, 6])),
        transports: ['future-transport']
      }
    ]
    const unknownSnapshot = bindPasskeyIngressRequest(unknownOnly, transport())
    expect(
      unknownSnapshot.kind === 'get'
        ? unknownSnapshot.options.allowCredentials[0]?.transports
        : undefined
    ).toEqual([])
  })

  it('rejects malformed, oversized, or control-containing transport hints', () => {
    for (const transportHint of [42, 'x'.repeat(65), 'future\ntransport']) {
      const payload = getPayload()
      optionsOf(payload).allowCredentials = [
        {
          type: 'public-key',
          id: b64(Uint8Array.from([1])),
          transports: [transportHint]
        }
      ]
      expectIngressError(payload, 'INVALID_PAYLOAD')
    }
  })

  it('fails closed for unsupported algorithms, attestation, extensions, and conditional UI', () => {
    const algorithm = createPayload()
    optionsOf(algorithm).pubKeyCredParams = [{ type: 'public-key', alg: -257 }]
    expectIngressError(algorithm, 'UNSUPPORTED_OPTION')

    const algorithmFallback = createPayload()
    optionsOf(algorithmFallback).pubKeyCredParams = [
      { type: 'public-key', alg: -257 },
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -8 }
    ]
    const algorithmSnapshot = bindPasskeyIngressRequest(algorithmFallback, transport())
    expect(algorithmSnapshot.kind).toBe('create')
    if (algorithmSnapshot.kind !== 'create') throw new Error('Expected create snapshot')
    expect(algorithmSnapshot.options.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }])

    const malformedAlgorithm = createPayload()
    optionsOf(malformedAlgorithm).pubKeyCredParams = [{ type: 'public-key', alg: '-7' }]
    expectIngressError(malformedAlgorithm, 'INVALID_PAYLOAD')

    const attestation = createPayload()
    optionsOf(attestation).attestation = 'direct'
    expectIngressError(attestation, 'UNSUPPORTED_OPTION')

    for (const payload of [createPayload(), getPayload()]) {
      optionsOf(payload).extensions = { prf: {} }
      expectIngressError(payload, 'UNSUPPORTED_OPTION')
    }

    const conditional = getPayload()
    optionsOf(conditional).mediation = 'conditional'
    expectIngressError(conditional, 'UNSUPPORTED_OPTION')

    const crossPlatform = createPayload()
    optionsOf(crossPlatform).authenticatorSelection = {
      authenticatorAttachment: 'cross-platform'
    }
    expectIngressError(crossPlatform, 'UNSUPPORTED_OPTION')
  })

  it('accepts only v1 and validates create/get scalar bounds', () => {
    expectIngressError({ ...getPayload(), version: 2 }, 'UNSUPPORTED_VERSION')

    const badTimeout = getPayload()
    optionsOf(badTimeout).timeout = 600_001
    expectIngressError(badTimeout, 'INVALID_PAYLOAD')

    const badSelection = createPayload()
    optionsOf(badSelection).authenticatorSelection = {
      residentKey: 'required',
      requireResidentKey: false
    }
    expectIngressError(badSelection, 'INVALID_PAYLOAD')

    const duplicateCredential = getPayload()
    const descriptor = { type: 'public-key', id: b64(Uint8Array.from([1])) }
    optionsOf(duplicateCredential).allowCredentials = [descriptor, { ...descriptor }]
    expectIngressError(duplicateCredential, 'INVALID_PAYLOAD')

    const sparseAlgorithms = createPayload()
    optionsOf(sparseAlgorithms).pubKeyCredParams = new Array(1)
    expectIngressError(sparseAlgorithms, 'INVALID_PAYLOAD')

    const accessor = getPayload()
    Object.defineProperty(optionsOf(accessor), 'challenge', {
      enumerable: true,
      get: () => {
        throw new Error('provider-controlled secret')
      }
    })
    expectIngressError(accessor, 'INVALID_PAYLOAD')
  })

  it('does not admit an aborted peer and preserves later disconnects for downstream cancellation', () => {
    const disconnected = new AbortController()
    disconnected.abort('transport closed')
    expectIngressError(getPayload(), 'PEER_DISCONNECTED', transport(disconnected))

    const connected = new AbortController()
    const snapshot = bindPasskeyIngressRequest(getPayload(), transport(connected))
    expect(snapshot.signal.aborted).toBe(false)
    connected.abort('transport closed')
    expect(snapshot.signal.aborted).toBe(true)
    expect(snapshot.signal.reason).toBe('transport closed')
  })

  it('rejects peer spoofing and malformed authenticated transport contexts with safe errors', () => {
    const spoof = getPayload({
      provider: 'spoofed-provider',
      binding: 'spoofed-binding',
      epoch: 99
    })
    expectIngressError(spoof, 'INVALID_PAYLOAD')

    expectIngressError(getPayload(), 'INVALID_TRANSPORT_CONTEXT', {
      ...transport(),
      epoch: -1
    })
    expectIngressError(getPayload(), 'INVALID_TRANSPORT_CONTEXT', {
      ...transport(),
      binding: 'secret\nvalue'
    })
    expectIngressError(getPayload(), 'INVALID_TRANSPORT_CONTEXT', {
      ...transport(),
      signal: {} as AbortSignal
    })
  })
})
