import { ipcRenderer } from 'electron'
import {
  ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT,
  ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT
} from '../main/account-webauthn-registration-window-protocol'
import {
  ACCOUNT_WEBAUTHN_CAPABILITY_PATTERN,
  uniqueArgument
} from '../main/account-webauthn-window-primitives'
import { startAccountWebAuthnRegistration } from './account-webauthn-registration-runtime'

const epochValue = uniqueArgument(ACCOUNT_WEBAUTHN_REGISTRATION_EPOCH_ARGUMENT)
const capability = uniqueArgument(ACCOUNT_WEBAUTHN_REGISTRATION_CAPABILITY_ARGUMENT)
const epoch = epochValue === null ? Number.NaN : Number(epochValue)

if (
  capability !== null &&
  ACCOUNT_WEBAUTHN_CAPABILITY_PATTERN.test(capability) &&
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
