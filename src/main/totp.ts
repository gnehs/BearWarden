import { createHmac } from 'node:crypto'
import { VaultError } from './vault-errors'
import type { TotpCodeView } from '../shared/vault-contract'

const DEFAULT_PERIOD = 30
const DEFAULT_DIGITS = 6
const MAX_SECRET_BYTES = 1024

interface TotpParameters {
  secret: Buffer
  algorithm: 'sha1' | 'sha256' | 'sha512'
  digits: number
  period: number
}

function decodeBase32(value: string): Buffer {
  const normalized = value.replace(/[\s=-]/g, '').toUpperCase()
  if (!normalized || !/^[A-Z2-7]+$/.test(normalized)) throw new VaultError('INVALID_INPUT')

  let bits = 0
  let accumulator = 0
  const bytes: number[] = []
  for (const character of normalized) {
    const code = character.charCodeAt(0)
    const digit = code >= 65 && code <= 90 ? code - 65 : code - 24
    accumulator = (accumulator << 5) | digit
    bits += 5
    while (bits >= 8) {
      bits -= 8
      bytes.push((accumulator >>> bits) & 0xff)
      accumulator &= (1 << bits) - 1
      if (bytes.length > MAX_SECRET_BYTES) throw new VaultError('INVALID_INPUT')
    }
  }
  if (bytes.length === 0) throw new VaultError('INVALID_INPUT')
  return Buffer.from(bytes)
}

function positiveInteger(
  value: string | null,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  if (value === null || value === '') return fallback
  if (!/^\d+$/.test(value)) throw new VaultError('INVALID_INPUT')
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new VaultError('INVALID_INPUT')
  }
  return parsed
}

function parseTotp(value: string): TotpParameters {
  const trimmed = value.trim()
  let secretValue = trimmed
  let algorithm: TotpParameters['algorithm'] = 'sha1'
  let digits = DEFAULT_DIGITS
  let period = DEFAULT_PERIOD

  if (/^otpauth:\/\//i.test(trimmed)) {
    let uri: URL
    try {
      uri = new URL(trimmed)
    } catch {
      throw new VaultError('INVALID_INPUT')
    }
    if (uri.protocol !== 'otpauth:' || uri.hostname.toLowerCase() !== 'totp') {
      throw new VaultError('INVALID_INPUT')
    }
    secretValue = uri.searchParams.get('secret') ?? ''
    const requestedAlgorithm = (uri.searchParams.get('algorithm') ?? 'SHA1').toUpperCase()
    if (
      requestedAlgorithm !== 'SHA1' &&
      requestedAlgorithm !== 'SHA256' &&
      requestedAlgorithm !== 'SHA512'
    ) {
      throw new VaultError('INVALID_INPUT')
    }
    algorithm = requestedAlgorithm.toLowerCase() as TotpParameters['algorithm']
    digits = positiveInteger(uri.searchParams.get('digits'), DEFAULT_DIGITS, 6, 10)
    period = positiveInteger(uri.searchParams.get('period'), DEFAULT_PERIOD, 1, 300)
  }

  return { secret: decodeBase32(secretValue), algorithm, digits, period }
}

export function generateTotp(value: string, now = new Date()): TotpCodeView {
  const parameters = parseTotp(value)
  const unixSeconds = Math.floor(now.getTime() / 1000)
  if (!Number.isFinite(unixSeconds) || unixSeconds < 0) throw new VaultError('INVALID_INPUT')
  const counter = BigInt(Math.floor(unixSeconds / parameters.period))
  const counterBytes = Buffer.alloc(8)
  counterBytes.writeBigUInt64BE(counter)
  const digest = createHmac(parameters.algorithm, parameters.secret).update(counterBytes).digest()
  parameters.secret.fill(0)
  const offset = digest[digest.length - 1]! & 0x0f
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff)
  const code = String(binary % 10 ** parameters.digits).padStart(parameters.digits, '0')
  const elapsed = unixSeconds % parameters.period
  return {
    code,
    period: parameters.period,
    remainingSeconds: parameters.period - elapsed
  }
}
