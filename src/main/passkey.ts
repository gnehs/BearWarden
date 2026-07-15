import type { PasskeyView } from '../shared/vault-contract'

/** Complete decrypted FIDO2 credential. This type must never cross the preload bridge. */
export interface StoredPasskeyCredential {
  credentialId: string
  keyType: string
  keyAlgorithm: string
  keyCurve: string
  keyValue: string
  rpId: string
  userHandle: string | null
  userName: string | null
  counter: string
  rpName: string | null
  userDisplayName: string | null
  discoverable: boolean
  creationDate: string
}

export function toPasskeyView(passkey: StoredPasskeyCredential): PasskeyView {
  return {
    credentialId: passkey.credentialId,
    rpId: passkey.rpId,
    rpName: passkey.rpName,
    userHandle: passkey.userHandle,
    userName: passkey.userName,
    userDisplayName: passkey.userDisplayName,
    discoverable: passkey.discoverable,
    creationDate: passkey.creationDate
  }
}
