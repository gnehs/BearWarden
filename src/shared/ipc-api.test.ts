import { describe, expect, expectTypeOf, it } from 'vitest'
import { IPC_API, PRELOAD_IPC, type BearWardenAPI, type IpcEventChannel } from './ipc-api'
import {
  IPC_EVENTS,
  type AccountMutationResult,
  type AttachmentProgressEvent
} from './vault-contract'

const endpoints = [
  ...Object.values(IPC_API).flatMap((namespace) => Object.values(namespace)),
  ...Object.values(PRELOAD_IPC)
]

describe('IPC API table', () => {
  it('gives every channel and event exactly one definition', () => {
    const channels = endpoints.map((endpoint) => endpoint.channel)

    expect(new Set(channels).size).toBe(channels.length)
  })

  it('keeps the legacy event constants pointing at defined events', () => {
    const events = new Set<string>(
      endpoints
        .filter((endpoint) => endpoint.kind === 'event' || endpoint.kind === 'signal')
        .map((endpoint) => endpoint.channel)
    )

    expectTypeOf(IPC_EVENTS).toExtend<Record<string, IpcEventChannel>>()
    for (const channel of Object.values(IPC_EVENTS)) expect(events.has(channel)).toBe(true)
  })

  it('derives renderer methods from the argument mappers and payload types', () => {
    expectTypeOf<BearWardenAPI['accounts']['rename']>().toEqualTypeOf<
      (
        accountId: string,
        displayName: string,
        expectedRevision: number
      ) => Promise<AccountMutationResult>
    >()
    expectTypeOf<BearWardenAPI['vault']['setLockRequestReady']>().toEqualTypeOf<
      (ready: boolean) => void
    >()
    expectTypeOf<BearWardenAPI['vault']['onLocked']>().toEqualTypeOf<
      (listener: () => void) => () => void
    >()
    expectTypeOf<BearWardenAPI['logins']['onAttachmentProgress']>().toEqualTypeOf<
      (listener: (progress: AttachmentProgressEvent) => void) => () => void
    >()
  })
})
