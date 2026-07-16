import { createHash, createPublicKey, randomBytes, type KeyObject } from 'node:crypto'
import type { SshKeyMaterial } from '../shared/vault-contract'

const OPENSSH_MAGIC = Buffer.from('openssh-key-v1\0', 'ascii')
const OPENSSH_BLOCK_SIZE = 8
const PEM_LINE_LENGTH = 70

interface EncodedKey {
  publicBlob: Buffer
  privateFields: Buffer[]
}

interface EcdsaCurve {
  keyType: string
  name: string
  coordinateLength: number
}

function uint32(value: number, owned: Buffer[]): Buffer {
  const encoded = Buffer.allocUnsafe(4)
  encoded.writeUInt32BE(value)
  owned.push(encoded)
  return encoded
}

function sshString(value: string | Buffer, owned: Buffer[]): Buffer {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : value
  if (typeof value === 'string') owned.push(bytes)
  const encoded = Buffer.allocUnsafe(4 + bytes.length)
  encoded.writeUInt32BE(bytes.length, 0)
  bytes.copy(encoded, 4)
  owned.push(encoded)
  return encoded
}

function decodeJwkValue(value: string | undefined, owned: Buffer[]): Buffer {
  if (value === undefined || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error('SSH_KEY_FORMAT_FAILED')
  }

  const decoded = Buffer.from(value, 'base64url')
  owned.push(decoded)
  if (decoded.length === 0 || decoded.toString('base64url') !== value) {
    throw new Error('SSH_KEY_FORMAT_FAILED')
  }
  return decoded
}

function mpint(unsigned: Buffer, owned: Buffer[]): Buffer {
  let offset = 0
  while (offset < unsigned.length - 1 && unsigned[offset] === 0) offset += 1
  const significant = unsigned.subarray(offset)
  if (significant.length === 1 && significant[0] === 0) {
    const zero = Buffer.alloc(0)
    owned.push(zero)
    return zero
  }
  if ((significant[0]! & 0x80) === 0) {
    const result = Buffer.from(significant)
    owned.push(result)
    return result
  }

  const positive = Buffer.allocUnsafe(significant.length + 1)
  positive[0] = 0
  significant.copy(positive, 1)
  owned.push(positive)
  return positive
}

function requireLength(value: Buffer, length: number): Buffer {
  if (value.length !== length) throw new Error('SSH_KEY_FORMAT_FAILED')
  return value
}

function encodeEd25519(jwk: JsonWebKey, owned: Buffer[]): EncodedKey {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') throw new Error('SSH_KEY_UNSUPPORTED')

  const publicKey = requireLength(decodeJwkValue(jwk.x, owned), 32)
  const privateSeed = requireLength(decodeJwkValue(jwk.d, owned), 32)
  const privateKeyPair = Buffer.concat([privateSeed, publicKey])
  owned.push(privateKeyPair)
  const publicBlob = Buffer.concat([sshString('ssh-ed25519', owned), sshString(publicKey, owned)])
  owned.push(publicBlob)

  return {
    publicBlob,
    privateFields: [
      sshString('ssh-ed25519', owned),
      sshString(publicKey, owned),
      sshString(privateKeyPair, owned)
    ]
  }
}

function encodeRsa(jwk: JsonWebKey, owned: Buffer[]): EncodedKey {
  if (jwk.kty !== 'RSA') throw new Error('SSH_KEY_UNSUPPORTED')

  const n = mpint(decodeJwkValue(jwk.n, owned), owned)
  const e = mpint(decodeJwkValue(jwk.e, owned), owned)
  const d = mpint(decodeJwkValue(jwk.d, owned), owned)
  const iqmp = mpint(decodeJwkValue(jwk.qi, owned), owned)
  const p = mpint(decodeJwkValue(jwk.p, owned), owned)
  const q = mpint(decodeJwkValue(jwk.q, owned), owned)
  const publicBlob = Buffer.concat([
    sshString('ssh-rsa', owned),
    sshString(e, owned),
    sshString(n, owned)
  ])
  owned.push(publicBlob)

  return {
    publicBlob,
    privateFields: [
      sshString('ssh-rsa', owned),
      sshString(n, owned),
      sshString(e, owned),
      sshString(d, owned),
      sshString(iqmp, owned),
      sshString(p, owned),
      sshString(q, owned)
    ]
  }
}

function getEcdsaCurve(crv: string | undefined): EcdsaCurve {
  switch (crv) {
    case 'P-256':
      return { keyType: 'ecdsa-sha2-nistp256', name: 'nistp256', coordinateLength: 32 }
    case 'P-384':
      return { keyType: 'ecdsa-sha2-nistp384', name: 'nistp384', coordinateLength: 48 }
    case 'P-521':
      return { keyType: 'ecdsa-sha2-nistp521', name: 'nistp521', coordinateLength: 66 }
    default:
      throw new Error('SSH_KEY_UNSUPPORTED')
  }
}

function encodeEcdsa(jwk: JsonWebKey, owned: Buffer[]): EncodedKey {
  if (jwk.kty !== 'EC') throw new Error('SSH_KEY_UNSUPPORTED')

  const curve = getEcdsaCurve(jwk.crv)
  const x = requireLength(decodeJwkValue(jwk.x, owned), curve.coordinateLength)
  const y = requireLength(decodeJwkValue(jwk.y, owned), curve.coordinateLength)
  const d = mpint(requireLength(decodeJwkValue(jwk.d, owned), curve.coordinateLength), owned)
  const uncompressed = Buffer.from([4])
  const publicPoint = Buffer.concat([uncompressed, x, y])
  owned.push(uncompressed, publicPoint)
  const publicBlob = Buffer.concat([
    sshString(curve.keyType, owned),
    sshString(curve.name, owned),
    sshString(publicPoint, owned)
  ])
  owned.push(publicBlob)

  return {
    publicBlob,
    privateFields: [
      sshString(curve.keyType, owned),
      sshString(curve.name, owned),
      sshString(publicPoint, owned),
      sshString(d, owned)
    ]
  }
}

function encodeKey(privateKey: KeyObject, owned: Buffer[]): EncodedKey {
  if (privateKey.type !== 'private') throw new Error('SSH_KEY_FORMAT_FAILED')
  const jwk = privateKey.export({ format: 'jwk' })

  switch (privateKey.asymmetricKeyType) {
    case 'ed25519':
      return encodeEd25519(jwk, owned)
    case 'rsa':
      return encodeRsa(jwk, owned)
    case 'ec':
      return encodeEcdsa(jwk, owned)
    default:
      throw new Error('SSH_KEY_UNSUPPORTED')
  }
}

function wrapOpenSshPrivateKey(binary: Buffer): string {
  const base64 = binary.toString('base64')
  const lines: string[] = []
  for (let offset = 0; offset < base64.length; offset += PEM_LINE_LENGTH) {
    lines.push(base64.slice(offset, offset + PEM_LINE_LENGTH))
  }
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`
}

/** Serialize a supported private KeyObject into Bitwarden-compatible SSH key material. */
export function formatSshKeyMaterial(privateKey: KeyObject): SshKeyMaterial {
  const owned: Buffer[] = []

  try {
    const encodedKey = encodeKey(privateKey, owned)

    const check = randomBytes(4)
    owned.push(check)
    const firstCheck = Buffer.from(check)
    const secondCheck = Buffer.from(check)
    owned.push(firstCheck, secondCheck)
    const privateParts = [
      firstCheck,
      secondCheck,
      ...encodedKey.privateFields,
      sshString('', owned)
    ]

    const privateLength = privateParts.reduce((total, part) => total + part.length, 0)
    const paddingLength =
      (OPENSSH_BLOCK_SIZE - (privateLength % OPENSSH_BLOCK_SIZE)) % OPENSSH_BLOCK_SIZE
    const padding = Buffer.allocUnsafe(paddingLength)
    for (let index = 0; index < padding.length; index += 1) padding[index] = index + 1
    owned.push(padding)

    const privateSection = Buffer.concat([...privateParts, padding])
    owned.push(privateSection)
    const magic = Buffer.from(OPENSSH_MAGIC)
    owned.push(magic)
    const outerParts = [
      magic,
      sshString('none', owned),
      sshString('none', owned),
      sshString('', owned),
      uint32(1, owned),
      sshString(encodedKey.publicBlob, owned),
      sshString(privateSection, owned)
    ]
    const opensshPrivateKey = Buffer.concat(outerParts)
    owned.push(opensshPrivateKey)

    const publicKey = `${readKeyType(encodedKey.publicBlob)} ${encodedKey.publicBlob.toString('base64')}`
    const fingerprint = `SHA256:${createHash('sha256')
      .update(encodedKey.publicBlob)
      .digest('base64')
      .replace(/=+$/u, '')}`

    // Deriving the public key forces OpenSSL to validate that this is a usable private key.
    createPublicKey(privateKey)
    return { privateKey: wrapOpenSshPrivateKey(opensshPrivateKey), publicKey, fingerprint }
  } finally {
    for (const buffer of owned) buffer.fill(0)
  }
}

function readKeyType(publicBlob: Buffer): string {
  if (publicBlob.length < 4) throw new Error('SSH_KEY_FORMAT_FAILED')
  const length = publicBlob.readUInt32BE(0)
  if (length === 0 || length > publicBlob.length - 4) throw new Error('SSH_KEY_FORMAT_FAILED')
  return publicBlob.toString('ascii', 4, 4 + length)
}
