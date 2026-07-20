import { CheckCircle2, Palette, Pencil, UserRound } from 'lucide-react'
import { useRef, useState } from 'react'
import type { AccountSecurityProfile } from '../../../shared/vault-contract'
import { Trans, useLingui } from '@lingui/react/macro'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import { Button } from '@renderer/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@renderer/components/ui/dialog'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@renderer/components/ui/field'
import { Input } from '@renderer/components/ui/input'
import { Spinner } from '@renderer/components/ui/spinner'
import { isAvatarColor, profileNameValidationError } from './account-profile-validation'

const DEFAULT_AVATAR_COLOR = '#175DDC'

interface AccountProfileCardProps {
  profile: AccountSecurityProfile
  onProfileChange: (profile: AccountSecurityProfile) => void
}

function AccountProfileCard({
  profile,
  onProfileChange
}: AccountProfileCardProps): React.JSX.Element {
  const { t } = useLingui()
  const [current, setCurrent] = useState(profile)
  const [name, setName] = useState(profile.name)
  const [avatarColor, setAvatarColor] = useState(profile.avatarColor ?? DEFAULT_AVATAR_COLOR)
  const [nameBusy, setNameBusy] = useState(false)
  const [avatarBusy, setAvatarBusy] = useState(false)
  const [nameError, setNameError] = useState('')
  const [avatarError, setAvatarError] = useState('')
  const [nameSuccess, setNameSuccess] = useState('')
  const [avatarSuccess, setAvatarSuccess] = useState('')
  const mutationInFlight = useRef(false)
  const profileBusy = nameBusy || avatarBusy

  async function refreshAfterFailure(field: 'name' | 'avatar'): Promise<boolean> {
    try {
      const refreshed = await window.bearwarden.accountSecurity.profile()
      setCurrent(refreshed)
      onProfileChange(refreshed)
      if (field === 'name') setName(refreshed.name)
      else setAvatarColor(refreshed.avatarColor ?? DEFAULT_AVATAR_COLOR)
      return true
    } catch {
      // Keep the submitted values visible so the user can retry after reconnecting.
      return false
    }
  }

  async function saveName(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (mutationInFlight.current) return
    const validationError = profileNameValidationError(name)
    if (validationError) {
      setNameError(validationError)
      setNameSuccess('')
      return
    }

    mutationInFlight.current = true
    setNameBusy(true)
    setNameError('')
    setNameSuccess('')
    try {
      const updated = await window.bearwarden.accountSecurity.updateName({
        name,
        expectedName: current.name
      })
      setCurrent(updated)
      onProfileChange(updated)
      setName(updated.name)
      setNameSuccess(t`Display name saved.`)
    } catch {
      const refreshed = await refreshAfterFailure('name')
      setNameError(
        refreshed
          ? t`Unable to save the display name; the current server value has been reloaded.`
          : t`Unable to save the display name, and the current server value could not be reloaded. Please try again later.`
      )
    } finally {
      mutationInFlight.current = false
      setNameBusy(false)
    }
  }

  async function saveAvatar(nextColor: string | null = avatarColor): Promise<void> {
    if (mutationInFlight.current) return
    if (nextColor !== null && !isAvatarColor(nextColor)) {
      setAvatarError(t`Please choose a valid six-digit hexadecimal color.`)
      setAvatarSuccess('')
      return
    }

    mutationInFlight.current = true
    setAvatarBusy(true)
    setAvatarError('')
    setAvatarSuccess('')
    try {
      const updated = await window.bearwarden.accountSecurity.updateAvatar({
        avatarColor: nextColor,
        expectedAvatarColor: current.avatarColor
      })
      setCurrent(updated)
      onProfileChange(updated)
      setAvatarColor(updated.avatarColor ?? DEFAULT_AVATAR_COLOR)
      setAvatarSuccess(
        nextColor === null ? t`Custom avatar color cleared.` : t`Avatar color saved.`
      )
    } catch {
      const refreshed = await refreshAfterFailure('avatar')
      setAvatarError(
        refreshed
          ? t`Unable to save the avatar color; the current server value has been reloaded.`
          : t`Unable to save the avatar color, and the current server value could not be reloaded. Please try again later.`
      )
    } finally {
      mutationInFlight.current = false
      setAvatarBusy(false)
    }
  }

  return (
    <Dialog>
      <section className="flex items-center gap-3 p-4" aria-labelledby="account-profile-title">
        <span
          className="flex size-10 shrink-0 items-center justify-center rounded-full text-white"
          style={{ backgroundColor: current.avatarColor ?? DEFAULT_AVATAR_COLOR }}
          aria-hidden="true"
        >
          <UserRound className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <h3 id="account-profile-title" className="font-medium">
            <Trans>Profile</Trans>
          </h3>
          <p className="text-muted-foreground truncate text-sm">{current.name || current.email}</p>
        </div>
        <DialogTrigger
          render={<Button type="button" variant="outline" size="sm" aria-label={t`Edit profile`} />}
        >
          <Pencil data-icon="inline-start" aria-hidden="true" />
          <Trans>Edit</Trans>
        </DialogTrigger>
      </section>

      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-md" forceOverlay>
        <DialogHeader>
          <DialogTitle>
            <Trans>Edit profile</Trans>
          </DialogTitle>
          <DialogDescription>
            <Trans>Manage your display name and avatar color.</Trans>
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="account-profile-email">
              <Trans>Email</Trans>
            </FieldLabel>
            <Input id="account-profile-email" type="email" value={current.email} readOnly />
            <FieldDescription>
              <Trans>Email cannot be changed here.</Trans>
            </FieldDescription>
          </Field>

          <form onSubmit={(event) => void saveName(event)}>
            <Field>
              <FieldLabel htmlFor="account-profile-name">
                <Trans>Display name</Trans>
              </FieldLabel>
              <Input
                id="account-profile-name"
                value={name}
                onChange={(event) => {
                  setName(event.target.value)
                  setNameError('')
                  setNameSuccess('')
                }}
                disabled={profileBusy}
                aria-describedby="account-profile-name-help"
              />
              <FieldDescription id="account-profile-name-help">
                <Trans>Optional; maximum 50 UTF-8 bytes.</Trans>
              </FieldDescription>
              {nameError && (
                <Alert variant="destructive">
                  <AlertDescription>{nameError}</AlertDescription>
                </Alert>
              )}
              {nameSuccess && (
                <Alert role="status">
                  <CheckCircle2 aria-hidden="true" />
                  <AlertDescription>{nameSuccess}</AlertDescription>
                </Alert>
              )}
              <Button type="submit" size="sm" disabled={profileBusy || name === current.name}>
                {nameBusy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                <Trans>Save display name</Trans>
              </Button>
            </Field>
          </form>

          <form
            onSubmit={(event) => {
              event.preventDefault()
              void saveAvatar()
            }}
          >
            <Field>
              <FieldLabel htmlFor="account-profile-avatar">
                <Trans>Avatar color</Trans>
              </FieldLabel>
              <div className="flex items-center gap-3">
                <Input
                  id="account-profile-avatar"
                  className="h-10 w-16 p-1"
                  type="color"
                  value={avatarColor}
                  onChange={(event) => {
                    setAvatarColor(event.target.value.toUpperCase())
                    setAvatarError('')
                    setAvatarSuccess('')
                  }}
                  disabled={profileBusy}
                  aria-label={t`Select avatar color`}
                />
                <code className="text-sm">{avatarColor.toUpperCase()}</code>
              </div>
              <FieldDescription>
                {current.avatarColor
                  ? t`Current color: ${current.avatarColor}`
                  : t`The server default color is currently being used.`}
              </FieldDescription>
              {avatarError && (
                <Alert variant="destructive">
                  <AlertDescription>{avatarError}</AlertDescription>
                </Alert>
              )}
              {avatarSuccess && (
                <Alert role="status">
                  <CheckCircle2 aria-hidden="true" />
                  <AlertDescription>{avatarSuccess}</AlertDescription>
                </Alert>
              )}
              <div className="flex flex-wrap gap-2">
                <Button
                  type="submit"
                  size="sm"
                  disabled={
                    profileBusy || avatarColor.toUpperCase() === current.avatarColor?.toUpperCase()
                  }
                >
                  {avatarBusy && <Spinner data-icon="inline-start" aria-hidden="true" />}
                  <Palette data-icon="inline-start" aria-hidden="true" />
                  <Trans>Save avatar color</Trans>
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={profileBusy || current.avatarColor === null}
                  onClick={() => void saveAvatar(null)}
                >
                  <Trans>Clear custom color</Trans>
                </Button>
              </div>
            </Field>
          </form>
        </FieldGroup>
      </DialogContent>
    </Dialog>
  )
}

export default AccountProfileCard
