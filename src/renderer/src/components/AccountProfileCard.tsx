import { CheckCircle2, Palette, Pencil, UserRound } from 'lucide-react'
import { useRef, useState } from 'react'
import type { AccountSecurityProfile } from '../../../shared/vault-contract'
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
      setNameSuccess('顯示名稱已儲存。')
    } catch {
      const refreshed = await refreshAfterFailure('name')
      setNameError(
        refreshed
          ? '無法儲存顯示名稱；已重新載入伺服器上的目前值。'
          : '無法儲存顯示名稱，也無法重新載入伺服器上的目前值。請稍後再試。'
      )
    } finally {
      mutationInFlight.current = false
      setNameBusy(false)
    }
  }

  async function saveAvatar(nextColor: string | null = avatarColor): Promise<void> {
    if (mutationInFlight.current) return
    if (nextColor !== null && !isAvatarColor(nextColor)) {
      setAvatarError('請選擇有效的六位十六進位顏色。')
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
      setAvatarSuccess(nextColor === null ? '自訂頭像顏色已清除。' : '頭像顏色已儲存。')
    } catch {
      const refreshed = await refreshAfterFailure('avatar')
      setAvatarError(
        refreshed
          ? '無法儲存頭像顏色；已重新載入伺服器上的目前值。'
          : '無法儲存頭像顏色，也無法重新載入伺服器上的目前值。請稍後再試。'
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
            個人資料
          </h3>
          <p className="text-muted-foreground truncate text-sm">{current.name || current.email}</p>
        </div>
        <DialogTrigger
          render={<Button type="button" variant="outline" size="sm" aria-label="編輯個人資料" />}
        >
          <Pencil data-icon="inline-start" aria-hidden="true" />
          編輯
        </DialogTrigger>
      </section>

      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-md" forceOverlay>
        <DialogHeader>
          <DialogTitle>編輯個人資料</DialogTitle>
          <DialogDescription>管理顯示名稱與頭像顏色。</DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="account-profile-email">電子郵件</FieldLabel>
            <Input id="account-profile-email" type="email" value={current.email} readOnly />
            <FieldDescription>電子郵件無法在此變更。</FieldDescription>
          </Field>

          <form onSubmit={(event) => void saveName(event)}>
            <Field>
              <FieldLabel htmlFor="account-profile-name">顯示名稱</FieldLabel>
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
                可留空，最多 50 個 UTF-8 位元組。
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
                儲存顯示名稱
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
              <FieldLabel htmlFor="account-profile-avatar">頭像顏色</FieldLabel>
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
                  aria-label="選擇頭像顏色"
                />
                <code className="text-sm">{avatarColor.toUpperCase()}</code>
              </div>
              <FieldDescription>
                {current.avatarColor
                  ? `目前顏色：${current.avatarColor}`
                  : '目前使用伺服器預設顏色。'}
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
                  儲存頭像顏色
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={profileBusy || current.avatarColor === null}
                  onClick={() => void saveAvatar(null)}
                >
                  清除自訂顏色
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
