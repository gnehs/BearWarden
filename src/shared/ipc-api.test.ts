import { describe, expect, expectTypeOf, it } from 'vitest'
import { IPC_API, PRELOAD_IPC, type BearWardenAPI as DerivedApi } from './ipc-api'
import { IPC_CHANNELS, IPC_EVENTS, type BearWardenAPI as HandWrittenApi } from './vault-contract'

const endpoints = [
  ...Object.values(IPC_API).flatMap((namespace) => Object.values(namespace)),
  ...Object.values(PRELOAD_IPC)
]

describe('IPC API table', () => {
  it('derives exactly the hand-written renderer API', () => {
    expectTypeOf<DerivedApi>().toEqualTypeOf<HandWrittenApi>()
    expectTypeOf<DerivedApi['vault']>().toEqualTypeOf<HandWrittenApi['vault']>()
    expectTypeOf<DerivedApi['logins']>().toEqualTypeOf<HandWrittenApi['logins']>()
    expectTypeOf<DerivedApi['accounts']>().toEqualTypeOf<HandWrittenApi['accounts']>()
    expectTypeOf<DerivedApi['accountSecurity']>().toEqualTypeOf<HandWrittenApi['accountSecurity']>()
  })

  it('uses exactly the existing channel and event names', () => {
    const channels = endpoints
      .filter((endpoint) => endpoint.kind === 'invoke' || endpoint.kind === 'send')
      .map((endpoint) => endpoint.channel)
    const events = endpoints
      .filter((endpoint) => endpoint.kind === 'event' || endpoint.kind === 'signal')
      .map((endpoint) => endpoint.channel)

    expect(channels.sort()).toEqual(Object.values(IPC_CHANNELS).sort())
    expect(events.sort()).toEqual(Object.values(IPC_EVENTS).sort())
  })
})
