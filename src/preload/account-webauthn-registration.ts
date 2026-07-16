import { ipcRenderer } from 'electron'
import {
  ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT,
  ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT
} from '../main/account-webauthn-registration-window-protocol'
import { startAccountWebAuthnRegistration } from './account-webauthn-registration-runtime'

function uniqueArgument(prefix: string): string | null {
  const values = process.argv.filter((argument) => argument.startsWith(prefix))
  if (values.length !== 1) return null
  const value = values[0]!.slice(prefix.length)
  return value.length > 0 ? value : null
}

const epochValue = uniqueArgument(ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT)
const capability = uniqueArgument(ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT)
const epoch = epochValue === null ? Number.NaN : Number(epochValue)

if (
  capability !== null &&
  /^[A-Za-z0-9_-]{32,128}$/u.test(capability) &&
  Number.isSafeInteger(epoch) &&
  epoch >= 0
) {
  startAccountWebAuthnRegistration(
    ipcRenderer,
    { location: window.location, navigator },
    {
      epoch,
      capability
    }
  )
}
