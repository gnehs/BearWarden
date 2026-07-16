import { isIP } from 'node:net'
import { domainToASCII } from 'node:url'
import { parse } from 'tldts'

export type PasskeyOriginValidationErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_ORIGIN'
  | 'INVALID_RP_ID'
  | 'CROSS_ORIGIN_UNSUPPORTED'
  | 'RP_ID_MISMATCH'

export class PasskeyOriginValidationError extends Error {
  readonly code: PasskeyOriginValidationErrorCode

  constructor(code: PasskeyOriginValidationErrorCode) {
    super(code)
    this.name = 'PasskeyOriginValidationError'
    this.code = code
  }
}

export interface PasskeyOriginValidationInput {
  readonly origin: string
  readonly rpId: string
  readonly crossOrigin?: boolean
}

export interface ValidatedPasskeyOrigin {
  /** A serialized origin. Default ports are omitted. */
  readonly origin: string
  /** A lowercase ASCII domain string suitable for rpIdHash. */
  readonly rpId: string
  /** The caller origin's lowercase ASCII hostname. */
  readonly hostname: string
  /** The canonical non-default port, or null when the default port is used. */
  readonly port: string | null
  /** The PSL-derived eTLD+1, including private suffixes. Localhost has no eTLD+1. */
  readonly registrableDomain: string | null
}

const FORBIDDEN_RP_ID_CHARACTER = new Set(['/', ':', '@', '\\', '%', '?', '#', '[', ']'])
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u

function fail(code: PasskeyOriginValidationErrorCode): never {
  throw new PasskeyOriginValidationError(code)
}

function isCanonicalDomainSyntax(value: string): boolean {
  if (value.length === 0 || value.length > 253 || value.startsWith('.') || value.endsWith('.')) {
    return false
  }

  return value.split('.').every((label) => DOMAIN_LABEL.test(label))
}

function hasForbiddenWhitespace(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!
    if (codePoint <= 0x20 || codePoint === 0x7f || character.trim().length === 0) return true
  }

  return false
}

function canonicalizeRpId(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.trim() ||
    hasForbiddenWhitespace(value) ||
    [...value].some((character) => FORBIDDEN_RP_ID_CHARACTER.has(character))
  ) {
    return fail('INVALID_RP_ID')
  }

  const ascii = domainToASCII(value).toLowerCase()
  if (!isCanonicalDomainSyntax(ascii)) return fail('INVALID_RP_ID')

  try {
    const hostname = new URL(`https://${ascii}`).hostname
    if (hostname !== ascii || isIP(hostname) !== 0) return fail('INVALID_RP_ID')
  } catch {
    return fail('INVALID_RP_ID')
  }

  return ascii
}

function canonicalizeOrigin(value: unknown): URL {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.trim() ||
    hasForbiddenWhitespace(value)
  ) {
    return fail('INVALID_ORIGIN')
  }

  // An RFC 6454 serialized origin contains only scheme and authority. Requiring
  // that shape also rejects paths, queries, fragments and opaque origins before
  // WHATWG URL normalization can hide them.
  const match = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]+)$/iu.exec(value)
  if (!match || match[2]!.includes('@') || match[2]!.includes('\\') || match[2]!.includes('%')) {
    return fail('INVALID_ORIGIN')
  }

  const rawAuthority = match[2]!
  if (rawAuthority.endsWith(':')) return fail('INVALID_ORIGIN')

  let url: URL
  try {
    url = new URL(value)
  } catch {
    return fail('INVALID_ORIGIN')
  }

  if (
    url.origin === 'null' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== '' ||
    !isCanonicalDomainSyntax(url.hostname) ||
    isIP(url.hostname.replace(/^\[|\]$/gu, '')) !== 0
  ) {
    return fail('INVALID_ORIGIN')
  }

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost')) {
    return fail('INVALID_ORIGIN')
  }

  return url
}

/**
 * Validates the classic WebAuthn Level 3 origin/RP-ID relationship.
 *
 * Related Origin Requests and cross-origin iframe ceremonies intentionally fail
 * closed here. Supporting either requires separate trusted top-origin handling
 * and, for related origins, a bounded HTTPS `.well-known/webauthn` fetch.
 *
 * @see https://www.w3.org/TR/webauthn-3/#relying-party-identifier
 * @see https://www.w3.org/TR/webauthn-3/#sctn-related-origins
 */
export function validatePasskeyOrigin(
  input: PasskeyOriginValidationInput
): Readonly<ValidatedPasskeyOrigin> {
  if (input === null || typeof input !== 'object') return fail('INVALID_INPUT')
  if (input.crossOrigin !== undefined && typeof input.crossOrigin !== 'boolean') {
    return fail('INVALID_INPUT')
  }
  if (input.crossOrigin === true) return fail('CROSS_ORIGIN_UNSUPPORTED')

  const url = canonicalizeOrigin(input.origin)
  const rpId = canonicalizeRpId(input.rpId)
  const hostname = url.hostname

  if (hostname === 'localhost' || rpId === 'localhost') {
    if (hostname !== 'localhost' || rpId !== 'localhost') return fail('RP_ID_MISMATCH')

    return Object.freeze({
      origin: url.origin,
      rpId,
      hostname,
      port: url.port || null,
      registrableDomain: null
    })
  }

  const parsedOrigin = parse(hostname, { allowPrivateDomains: true })
  const parsedRpId = parse(rpId, { allowPrivateDomains: true })
  if (parsedOrigin.isIp || parsedOrigin.hostname !== hostname || parsedOrigin.domain === null) {
    return fail('INVALID_ORIGIN')
  }
  if (parsedRpId.isIp || parsedRpId.hostname !== rpId || parsedRpId.domain === null) {
    return fail('INVALID_RP_ID')
  }
  if (parsedOrigin.domain !== parsedRpId.domain) return fail('RP_ID_MISMATCH')

  if (hostname !== rpId && !hostname.endsWith(`.${rpId}`)) return fail('RP_ID_MISMATCH')

  return Object.freeze({
    origin: url.origin,
    rpId,
    hostname,
    port: url.port || null,
    registrableDomain: parsedRpId.domain
  })
}
