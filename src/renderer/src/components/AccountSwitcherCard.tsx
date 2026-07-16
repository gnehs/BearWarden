import { useState } from 'react'
import type { AccountStatus } from '../../../shared/vault-contract'
import { Alert, AlertDescription } from '@renderer/components/ui/alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle
} from '@renderer/components/ui/alert-dialog'
import { Badge } from '@renderer/components/ui/badge'
import { Button } from '@renderer/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from '@renderer/components/ui/card'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldTitle
} from '@renderer/components/ui/field'
import { Spinner } from '@renderer/components/ui/spinner'
import { AlertTriangle, Plus, RefreshCw } from 'lucide-react'
import {
  accountConfirmationContent,
  accountSwitchButtonDisabled,
  localAccountPresentation,
  MAX_LOCAL_ACCOUNTS,
  type AccountConfirmationAction
} from './account-switcher-ui'

interface AccountSwitcherCardProps {
  accountStatus: AccountStatus | null
  busy: boolean
  error: string
  onRequestAdd: (proceed: () => void) => void
  onRequestSwitch: (proceed: () => void) => void
  onAdd: () => Promise<void>
  onSwitch: (accountId: string) => Promise<void>
}

function AccountSwitcherCard({
  accountStatus,
  busy,
  error,
  onRequestAdd,
  onRequestSwitch,
  onAdd,
  onSwitch
}: AccountSwitcherCardProps): React.JSX.Element {
  const [confirmationAction, setConfirmationAction] = useState<AccountConfirmationAction | null>(
    null
  )
  const accounts = accountStatus?.accounts ?? []
  const confirmation = confirmationAction ? accountConfirmationContent(confirmationAction) : null

  async function confirm(): Promise<void> {
    if (!confirmationAction) return
    try {
      if (confirmationAction.kind === 'add') await onAdd()
      else await onSwitch(confirmationAction.accountId)
    } catch {
      // VaultShell maps mutation failures to safe, visible renderer feedback.
    } finally {
      setConfirmationAction(null)
    }
  }

  return (
    <>
      <Card className="settings-card" aria-labelledby="local-accounts-settings-title">
        <CardHeader>
          <CardTitle id="local-accounts-settings-title" role="heading" aria-level={2}>
            本機帳號
          </CardTitle>
          <CardDescription>在這台裝置上新增或切換保管庫帳號。</CardDescription>
          <CardAction>
            <Badge variant="secondary">
              {accounts.length} / {MAX_LOCAL_ACCOUNTS}
            </Badge>
          </CardAction>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            {accountStatus === null ? (
              <Field>
                <FieldContent>
                  <FieldTitle>正在讀取本機帳號</FieldTitle>
                  <FieldDescription aria-live="polite">請稍候。</FieldDescription>
                </FieldContent>
              </Field>
            ) : (
              accounts.map((account) => (
                <AccountRow
                  key={account.id}
                  account={account}
                  busy={busy}
                  onRequestSwitch={onRequestSwitch}
                  onConfirm={(action) => setConfirmationAction(action)}
                />
              ))
            )}
            {busy && (
              <Field>
                <FieldContent>
                  <FieldDescription role="status" aria-live="polite">
                    <Spinner data-icon="inline-start" aria-hidden="true" />
                    正在安全切換並重新啟動
                  </FieldDescription>
                </FieldContent>
              </Field>
            )}
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </FieldGroup>
        </CardContent>
        <CardFooter>
          <Button
            size="sm"
            type="button"
            disabled={busy || accountStatus === null || accounts.length >= MAX_LOCAL_ACCOUNTS}
            onClick={() => onRequestAdd(() => setConfirmationAction({ kind: 'add' }))}
          >
            <Plus data-icon="inline-start" aria-hidden="true" />
            新增本機帳號
          </Button>
        </CardFooter>
      </Card>

      <AlertDialog
        open={confirmationAction !== null}
        onOpenChange={(open) => {
          if (!open && !busy) setConfirmationAction(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogMedia>
              <AlertTriangle aria-hidden="true" />
            </AlertDialogMedia>
            <AlertDialogTitle>{confirmation?.title}</AlertDialogTitle>
            <AlertDialogDescription>{confirmation?.description}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
            <AlertDialogAction type="button" disabled={busy} onClick={() => void confirm()}>
              {busy ? (
                <Spinner data-icon="inline-start" aria-hidden="true" />
              ) : (
                <RefreshCw data-icon="inline-start" aria-hidden="true" />
              )}
              鎖定並重新啟動
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

interface AccountRowProps {
  account: AccountStatus['accounts'][number]
  busy: boolean
  onRequestSwitch: (proceed: () => void) => void
  onConfirm: (action: AccountConfirmationAction) => void
}

function AccountRow({
  account,
  busy,
  onRequestSwitch,
  onConfirm
}: AccountRowProps): React.JSX.Element {
  const presentation = localAccountPresentation(account)
  return (
    <Field orientation="responsive" data-disabled={busy || undefined}>
      <FieldContent>
        <FieldTitle>{presentation.label}</FieldTitle>
        <FieldDescription>{presentation.description}</FieldDescription>
      </FieldContent>
      {presentation.active && <Badge>使用中</Badge>}
      <Button
        variant="outline"
        size="sm"
        type="button"
        disabled={accountSwitchButtonDisabled(account, busy)}
        onClick={() =>
          onRequestSwitch(() =>
            onConfirm({ kind: 'switch', accountId: account.id, slot: account.slot })
          )
        }
      >
        切換
      </Button>
    </Field>
  )
}

export default AccountSwitcherCard
