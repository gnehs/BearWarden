import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import { EFF_LONG_WORDLIST_GZIP_BASE64, EFF_LONG_WORDLIST_SHA256 } from './eff-wordlist-asset'
import { VaultError } from './vault-errors'

const EFF_WORD_COUNT = 7_776
const EFF_LINE = /^([1-6]{5})\t([a-z]+(?:-[a-z]+)*)$/

let cachedWords: readonly string[] | null = null

function expectedDiceCode(index: number): string {
  let value = index
  let code = ''
  for (let digit = 0; digit < 5; digit += 1) {
    code = String((value % 6) + 1) + code
    value = Math.floor(value / 6)
  }
  return code
}

/** Decode and authenticate an embedded EFF list before any word can be selected. */
export function decodeEffLongWordlist(
  gzipBase64: string,
  expectedSha256: string
): readonly string[] {
  try {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(gzipBase64)) throw new Error('invalid base64')
    const bytes = gunzipSync(Buffer.from(gzipBase64, 'base64'))
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (digest !== expectedSha256) throw new Error('wordlist integrity check failed')

    const text = bytes.toString('utf8')
    if (!text.endsWith('\n') || text.includes('\r')) throw new Error('invalid line endings')
    const lines = text.slice(0, -1).split('\n')
    if (lines.length !== EFF_WORD_COUNT) throw new Error('invalid word count')

    const words: string[] = []
    const uniqueWords = new Set<string>()
    lines.forEach((line, index) => {
      const match = EFF_LINE.exec(line)
      if (!match || match[1] !== expectedDiceCode(index) || uniqueWords.has(match[2]!)) {
        throw new Error('invalid wordlist row')
      }
      uniqueWords.add(match[2]!)
      words.push(match[2]!)
    })
    return Object.freeze(words)
  } catch {
    throw new VaultError('INTERNAL_ERROR')
  }
}

/** Load once in main; the cache contains only the verified word array. */
export function loadEffLongWordlist(): readonly string[] {
  cachedWords ??= decodeEffLongWordlist(EFF_LONG_WORDLIST_GZIP_BASE64, EFF_LONG_WORDLIST_SHA256)
  return cachedWords
}
