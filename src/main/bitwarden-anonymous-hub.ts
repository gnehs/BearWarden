import { HttpTransportType, HubConnectionBuilder, LogLevel } from '@microsoft/signalr'
import { MessagePackHubProtocol } from '@microsoft/signalr-protocol-msgpack'

/**
 * Wakes a Login with device poll when the server pushes `AuthRequestResponseRecieved` (spelled as
 * upstream spells it) on the anonymous hub. It carries no authority: the poll still reads the
 * answer, so a missing or failed hub only delays the poll to its next interval.
 */
export interface AuthRequestResponseNudge {
  /** Resolves on the next push, or at once if one arrived since the last call. */
  next: () => Promise<void>
  close: () => void
}

export type AuthRequestResponseNudgeFactory = (
  notificationsUrl: string,
  requestId: string
) => AuthRequestResponseNudge

export interface AnonymousHubConnection {
  start: () => Promise<void>
  stop: () => Promise<void>
  on: (methodName: string, handler: () => void) => void
}

function createAnonymousHubConnection(url: string): AnonymousHubConnection {
  return (
    new HubConnectionBuilder()
      .withUrl(url, { skipNegotiation: true, transport: HttpTransportType.WebSockets })
      .withHubProtocol(new MessagePackHubProtocol())
      // Connection errors can echo the hub URL; servers with WebSockets disabled are expected.
      .configureLogging(LogLevel.None)
      .build()
  )
}

export function createAuthRequestResponseNudgeFactory(
  connect: (url: string) => AnonymousHubConnection = createAnonymousHubConnection
): AuthRequestResponseNudgeFactory {
  return (notificationsUrl, requestId) => {
    // bitwarden/clients AnonymousHubService: the request id is the hub token.
    const connection = connect(
      `${notificationsUrl}/anonymous-hub?Token=${encodeURIComponent(requestId)}`
    )
    let waiter: (() => void) | null = null
    let pending = false
    let closed = false
    connection.on('AuthRequestResponseRecieved', () => {
      if (waiter) {
        waiter()
        waiter = null
      } else {
        pending = true
      }
    })
    void connection.start().catch(() => undefined)
    return {
      next: () => {
        if (pending || closed) {
          pending = false
          return Promise.resolve()
        }
        return new Promise<void>((resolve) => {
          waiter = resolve
        })
      },
      close: () => {
        closed = true
        waiter?.()
        waiter = null
        void connection.stop().catch(() => undefined)
      }
    }
  }
}
