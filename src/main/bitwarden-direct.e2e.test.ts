import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { type AddressInfo } from 'node:net'
import { describe, expect, it } from 'vitest'
import {
  deriveMasterKey,
  encryptBitwardenBytes,
  encryptBitwardenString,
  stretchMasterKey
} from './bitwarden-crypto'
import { BitwardenDirectClient } from './bitwarden-direct'
import { type JsonObject } from './bitwarden-http'

const EMAIL = 'loopback-user@example.invalid'
const PASSWORD = 'loopback master password'
const PROFILE_ID = '10000000-0000-4000-8000-000000000001'
const FOLDER_ID = '20000000-0000-4000-8000-000000000001'
const LOGIN_ID = '30000000-0000-4000-8000-000000000001'
const CREATED_FOLDER_ID = '40000000-0000-4000-8000-000000000001'
const CREATED_CIPHER_ID = '50000000-0000-4000-8000-000000000001'

type SyncMode = 'valid' | 'empty' | 'malformed'

interface RequestLog {
  method: string
  path: string
  authorization: string | undefined
  clientVersion: string | undefined
  body: string
}

interface LoopbackVault {
  origin: string
  requests: RequestLog[]
  setSyncMode(mode: SyncMode): void
  close(): Promise<void>
}

async function encryptedV1Sync(): Promise<JsonObject> {
  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, { type: 'pbkdf2', iterations: 5_000 })
  const stretched = stretchMasterKey(masterKey)
  const userKey = Buffer.alloc(64, 7)
  const itemKey = Buffer.alloc(64, 9)
  try {
    return {
      profile: {
        id: PROFILE_ID,
        securityStamp: 'loopback-security-stamp',
        key: encryptBitwardenBytes(userKey, stretched.combinedKey)
      },
      // Bitwarden's current V1 sync shape supplies this alongside the legacy profile key.
      userDecryption: {
        masterPasswordUnlock: {
          masterKeyEncryptedUserKey: encryptBitwardenBytes(userKey, stretched.combinedKey)
        }
      },
      folders: [
        {
          id: FOLDER_ID,
          name: encryptBitwardenString('Existing folder', userKey),
          revisionDate: '2026-07-14T00:00:00.000Z'
        }
      ],
      ciphers: [
        {
          id: LOGIN_ID,
          type: 1,
          organizationId: null,
          folderId: FOLDER_ID,
          name: encryptBitwardenString('Existing login', itemKey),
          notes: encryptBitwardenString('Existing note', itemKey),
          favorite: true,
          key: encryptBitwardenBytes(itemKey, userKey),
          login: {
            username: encryptBitwardenString(EMAIL, itemKey),
            password: encryptBitwardenString('existing-secret', itemKey),
            uris: [
              { uri: encryptBitwardenString('https://existing.invalid', itemKey), match: null }
            ]
          },
          creationDate: '2026-07-13T00:00:00.000Z',
          revisionDate: '2026-07-14T00:00:00.000Z',
          deletedDate: null
        }
      ]
    }
  } finally {
    masterKey.fill(0)
    stretched.encKey.fill(0)
    stretched.macKey.fill(0)
    stretched.combinedKey.fill(0)
    userKey.fill(0)
    itemKey.fill(0)
  }
}

function writeJson(response: ServerResponse, value: unknown, status = 200): void {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8'
  })
  response.end(JSON.stringify(value))
}

function writeEmpty(response: ServerResponse, status = 204): void {
  response.writeHead(status, { 'cache-control': 'no-store' })
  response.end()
}

async function requestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  let length = 0
  for await (const chunk of request) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    length += value.length
    if (length > 1024 * 1024) throw new Error('test request body is unexpectedly large')
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function jsonObject(value: string): JsonObject {
  const parsed: unknown = JSON.parse(value)
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('expected JSON object from direct client')
  }
  return parsed as JsonObject
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      resolve()
    })
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('loopback server has no TCP address')
  return (address as AddressInfo).port
}

async function close(server: Server): Promise<void> {
  server.closeIdleConnections()
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

async function startLoopbackVault(initialSyncMode: SyncMode = 'valid'): Promise<LoopbackVault> {
  const sync = await encryptedV1Sync()
  const requests: RequestLog[] = []
  let syncMode = initialSyncMode
  let accessToken = 'access-token-1'
  let refreshToken = 'refresh-token-1'
  let rejectFirstSync = true
  let latestCreatedCipher: JsonObject | null = null

  const server = createServer((request, response) => {
    void (async () => {
      const method = request.method ?? 'GET'
      const url = new URL(request.url ?? '/', 'http://127.0.0.1')
      const body = await requestBody(request)
      requests.push({
        method,
        path: `${url.pathname}${url.search}`,
        authorization: request.headers.authorization,
        clientVersion:
          typeof request.headers['bitwarden-client-version'] === 'string'
            ? request.headers['bitwarden-client-version']
            : undefined,
        body
      })

      if (method === 'POST' && url.pathname === '/identity/accounts/prelogin/password') {
        writeJson(response, {
          kdf: { type: 0, iterations: 5_000, salt: EMAIL }
        })
        return
      }

      if (method === 'POST' && url.pathname === '/identity/connect/token') {
        const form = new URLSearchParams(body)
        if (form.get('grant_type') === 'password') {
          writeJson(response, {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: 3600
          })
          return
        }
        if (
          form.get('grant_type') === 'refresh_token' &&
          form.get('refresh_token') === refreshToken
        ) {
          accessToken = 'access-token-2'
          refreshToken = 'refresh-token-2'
          writeJson(response, {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: 3600
          })
          return
        }
        writeJson(response, { error: 'invalid_grant' }, 400)
        return
      }

      if (request.headers.authorization !== `Bearer ${accessToken}`) {
        writeJson(response, { error: 'invalid_token' }, 401)
        return
      }

      if (method === 'GET' && url.pathname === '/api/sync') {
        if (rejectFirstSync) {
          rejectFirstSync = false
          writeJson(response, { error: 'invalid_token' }, 401)
          return
        }
        if (syncMode === 'empty') {
          writeEmpty(response, 200)
          return
        }
        if (syncMode === 'malformed') {
          writeJson(response, { profile: sync.profile, folders: {}, ciphers: [] })
          return
        }
        writeJson(response, sync)
        return
      }

      if (method === 'POST' && url.pathname === '/api/folders') {
        const folder = jsonObject(body)
        writeJson(response, {
          folder: {
            id: CREATED_FOLDER_ID,
            name: folder.name,
            revisionDate: '2026-07-14T00:00:01.000Z'
          }
        })
        return
      }
      if (method === 'PUT' && url.pathname === `/api/folders/${CREATED_FOLDER_ID}`) {
        const folder = jsonObject(body)
        writeJson(response, {
          folder: {
            id: CREATED_FOLDER_ID,
            name: folder.name,
            revisionDate: '2026-07-14T00:00:02.000Z'
          }
        })
        return
      }
      if (method === 'DELETE' && url.pathname === `/api/folders/${CREATED_FOLDER_ID}`) {
        writeEmpty(response)
        return
      }

      if (method === 'POST' && url.pathname === '/api/ciphers') {
        const cipher = jsonObject(body)
        latestCreatedCipher = {
          ...cipher,
          id: CREATED_CIPHER_ID,
          creationDate: '2026-07-14T00:00:03.000Z',
          revisionDate: '2026-07-14T00:00:03.000Z',
          deletedDate: null
        }
        writeJson(response, { cipher: latestCreatedCipher })
        return
      }
      if (method === 'PUT' && url.pathname === `/api/ciphers/${CREATED_CIPHER_ID}`) {
        const cipher = jsonObject(body)
        latestCreatedCipher = {
          ...cipher,
          id: CREATED_CIPHER_ID,
          creationDate: '2026-07-14T00:00:03.000Z',
          revisionDate: '2026-07-14T00:00:04.000Z',
          deletedDate: null
        }
        writeJson(response, { cipher: latestCreatedCipher })
        return
      }
      if (method === 'PUT' && url.pathname === `/api/ciphers/${CREATED_CIPHER_ID}/delete`) {
        writeEmpty(response)
        return
      }
      if (
        method === 'PUT' &&
        url.pathname === `/api/ciphers/${CREATED_CIPHER_ID}/restore` &&
        latestCreatedCipher
      ) {
        latestCreatedCipher = {
          ...latestCreatedCipher,
          revisionDate: '2026-07-14T00:00:05.000Z',
          deletedDate: null
        }
        writeJson(response, { cipher: latestCreatedCipher })
        return
      }
      if (method === 'DELETE' && url.pathname === `/api/ciphers/${CREATED_CIPHER_ID}`) {
        writeEmpty(response)
        return
      }

      writeJson(response, { message: 'not found' }, 404)
    })().catch(() => {
      if (!response.headersSent) writeJson(response, { message: 'test server failure' }, 500)
      else response.destroy()
    })
  })

  const port = await listen(server)
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    setSyncMode(mode) {
      syncMode = mode
    },
    close: () => close(server)
  }
}

describe('BitwardenDirectClient loopback V1 protocol', () => {
  it('uses modern prelogin, rotates a rejected token, syncs V1 data, and performs encrypted CRUD', async () => {
    const vault = await startLoopbackVault()
    const stateChanges: Array<ReturnType<BitwardenDirectClient['exportState']>> = []
    const client = new BitwardenDirectClient({
      serverUrl: vault.origin,
      email: EMAIL,
      clientVersion: '1.0.0',
      onStateChanged: (state) => {
        stateChanges.push(state)
      }
    })

    try {
      await client.login({ email: EMAIL, password: PASSWORD })
      await client.sync()

      expect(await client.listFolders()).toEqual([{ id: FOLDER_ID, name: 'Existing folder' }])
      expect(await client.listPersonalLogins()).toEqual([
        expect.objectContaining({
          id: LOGIN_ID,
          name: 'Existing login',
          username: EMAIL,
          password: 'existing-secret',
          notes: 'Existing note',
          folderId: FOLDER_ID,
          favorite: true
        })
      ])

      await expect(client.createFolder('Created folder')).resolves.toEqual({
        id: CREATED_FOLDER_ID,
        name: 'Created folder'
      })
      await expect(client.editFolder(CREATED_FOLDER_ID, 'Renamed folder')).resolves.toEqual({
        id: CREATED_FOLDER_ID,
        name: 'Renamed folder'
      })
      await expect(client.deleteFolder(CREATED_FOLDER_ID)).resolves.toBeUndefined()

      const created = await client.createLogin({
        type: 'card',
        name: 'Created card',
        cardholderName: 'Test Holder',
        brand: 'Visa',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2030',
        code: '123',
        notes: 'Created card note',
        folderId: FOLDER_ID,
        favorite: true
      })
      expect(created).toMatchObject({
        id: CREATED_CIPHER_ID,
        type: 'card',
        name: 'Created card',
        cardholderName: 'Test Holder'
      })

      await expect(
        client.editLogin(CREATED_CIPHER_ID, {
          type: 'card',
          name: 'Renamed card',
          cardholderName: 'Updated Holder',
          number: '5555555555554444',
          notes: 'Updated card note',
          folderId: FOLDER_ID,
          favorite: false
        })
      ).resolves.toMatchObject({
        id: CREATED_CIPHER_ID,
        type: 'card',
        name: 'Renamed card',
        cardholderName: 'Updated Holder'
      })
      await expect(client.softDeleteLogin(CREATED_CIPHER_ID)).resolves.toBeUndefined()
      expect(
        (await client.listPersonalLogins()).find(({ id }) => id === CREATED_CIPHER_ID)?.deletedAt
      ).toEqual(expect.any(String))
      await expect(client.restoreLogin(CREATED_CIPHER_ID)).resolves.toBeUndefined()
      expect(
        (await client.listPersonalLogins()).find(({ id }) => id === CREATED_CIPHER_ID)?.deletedAt
      ).toBeNull()
      await expect(client.hardDeleteLogin(CREATED_CIPHER_ID)).resolves.toBeUndefined()

      const prelogin = vault.requests.find(
        (request) => request.path === '/identity/accounts/prelogin/password'
      )
      expect(prelogin?.method).toBe('POST')
      expect(prelogin?.authorization).toBeUndefined()

      const tokenRequests = vault.requests.filter(
        (request) => request.path === '/identity/connect/token'
      )
      expect(tokenRequests).toHaveLength(2)
      expect(new URLSearchParams(tokenRequests[0]?.body).get('grant_type')).toBe('password')
      expect(new URLSearchParams(tokenRequests[1]?.body).get('grant_type')).toBe('refresh_token')
      expect(new URLSearchParams(tokenRequests[1]?.body).get('refresh_token')).toBe(
        'refresh-token-1'
      )

      const syncRequests = vault.requests.filter((request) => request.path === '/api/sync')
      expect(syncRequests.map((request) => request.authorization)).toEqual([
        'Bearer access-token-1',
        'Bearer access-token-2'
      ])
      expect(syncRequests.every((request) => request.clientVersion === '2025.5.0')).toBe(true)
      expect(client.exportState().session).toMatchObject({
        accessToken: 'access-token-2',
        refreshToken: 'refresh-token-2'
      })
      expect(stateChanges.at(-1)?.session?.refreshToken).toBe('refresh-token-2')

      const apiWrites = vault.requests.filter(
        (request) => request.method !== 'GET' && request.path.startsWith('/api/')
      )
      expect(apiWrites.map((request) => `${request.method} ${request.path}`)).toEqual([
        'POST /api/folders',
        `PUT /api/folders/${CREATED_FOLDER_ID}`,
        `DELETE /api/folders/${CREATED_FOLDER_ID}`,
        'POST /api/ciphers',
        `PUT /api/ciphers/${CREATED_CIPHER_ID}`,
        `PUT /api/ciphers/${CREATED_CIPHER_ID}/delete`,
        `PUT /api/ciphers/${CREATED_CIPHER_ID}/restore`,
        `DELETE /api/ciphers/${CREATED_CIPHER_ID}`
      ])

      const uploadText = apiWrites.map((request) => request.body).join('\n')
      for (const plaintext of [
        'Created folder',
        'Renamed folder',
        'Created card',
        'Renamed card',
        'Test Holder',
        'Updated Holder',
        '4111111111111111',
        '5555555555554444',
        'Created card note',
        'Updated card note'
      ]) {
        expect(uploadText).not.toContain(plaintext)
      }
      expect(
        apiWrites
          .filter((request) => request.body.length > 0)
          .every((request) => request.body.includes('2.'))
      ).toBe(true)
    } finally {
      await vault.close()
    }
  })

  it('rejects empty and malformed sync payloads without replacing a verified local vault', async () => {
    const vault = await startLoopbackVault()
    const client = new BitwardenDirectClient({ serverUrl: vault.origin, email: EMAIL })

    try {
      await client.login({ email: EMAIL, password: PASSWORD })
      await client.sync()
      const foldersBeforeFailure = await client.listFolders()
      const loginsBeforeFailure = await client.listPersonalLogins()

      vault.setSyncMode('empty')
      await expect(client.sync()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
      expect(await client.listFolders()).toEqual(foldersBeforeFailure)
      expect(await client.listPersonalLogins()).toEqual(loginsBeforeFailure)

      vault.setSyncMode('malformed')
      await expect(client.sync()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
      expect(await client.listFolders()).toEqual(foldersBeforeFailure)
      expect(await client.listPersonalLogins()).toEqual(loginsBeforeFailure)
    } finally {
      await vault.close()
    }
  })
})
