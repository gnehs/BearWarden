import { useRef, useState } from 'react'
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
import { AlertTriangle, ArrowDown, ArrowUp, Plus, RefreshCw, Trash2 } from 'lucide-react'
import {
  accountConfirmationContent,
  accountMoveButtonDisabled,
  accountRemoveButtonDisabled,
  accountSwitchButtonDisabled,
  localAccountPresentation,
  MAX_LOCAL_ACCOUNTS,
  moveAccountIds,
  type AccountConfirmationAction
} from './account-switcher-ui'

interface AccountSwitcherCardProps {
  accountStatus: AccountStatus | null
  busy: boolean
  busyLabel: string
  error: string
  onRequestAdd: (proceed: () => void) => void
  onRequestSwitch: (proceed: () => void) => void
  onRequestRemove: (proceed: () => void) => void
  onAdd: () => Promise<void>
  onSwitch: (accountId: string) => Promise<void>
  onReorder: (accountIds: readonly string[], expectedRevision: number) => Promise<void>
  onRemove: (accountId: string) => Promise<void>
}

function AccountSwitcherCard({
  accountStatus,
  busy,
  busyLabel,
  error,
  onRequestAdd,
  onRequestSwitch,
  onRequestRemove,
  onAdd,
  onSwitch,
  onReorder,
  onRemove
}: AccountSwitcherCardProps): React.JSX.Element {
  const [confirmationAction, setConfirmationAction] = useState<AccountConfirmationAction | null>(
    null
  )
  const addAccountButtonRef = useRef<HTMLButtonElement>(null)
  const accounts = accountStatus?.accounts ?? []
  const confirmation = confirmationAction ? accountConfirmationContent(confirmationAction) : null

  async function confirm(): Promise<void> {
    if (!confirmationAction) return
    const action = confirmationAction
    try {
      if (action.kind === 'add') await onAdd()
      else if (action.kind === 'switch') await onSwitch(action.accountId)
      else await onRemove(action.accountId)
    } catch {
      // VaultShell maps mutation failures to safe, visible renderer feedback.
    } finally {
      setConfirmationAction(null)
      if (action.kind === 'remove') {
        queueMicrotask(() => addAccountButtonRef.current?.focus())
      }
    }
  }

  return (
    <>
      <Card className="settings-card" aria-labelledby="local-accounts-settings-title">
        <CardHeader>
          <CardTitle id="local-accounts-settings-title" role="heading" aria-level={2}>
            本機帳號
          </CardTitle>
          <CardDescription>新增、排序、切換或移除這台裝置上的密碼庫帳號。</CardDescription>
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
              accounts.map((account, index) => (
                <AccountRow
                  key={account.id}
                  account={account}
                  accounts={accounts}
                  index={index}
                  revision={accountStatus.revision}
                  busy={busy}
                  onRequestSwitch={onRequestSwitch}
                  onRequestRemove={onRequestRemove}
                  onReorder={onReorder}
                  onConfirm={(action) => setConfirmationAction(action)}
                />
              ))
            )}
            {busy && (
              <Field>
                <FieldContent>
                  <FieldDescription role="status" aria-live="polite">
                    <Spinner data-icon="inline-start" aria-hidden="true" />
                    {busyLabel || '正在處理本機帳號'}
                  </FieldDescription>
                </FieldContent>
              </Field>
            )}
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {accountStatus?.cleanupPending && (
              <Alert>
                <AlertDescription>
                  上次移除的本機資料尚未完成安全清理。BearWarden
                  會在下次啟動再次嘗試；在完成前不會刪除或覆寫未知資料。
                </AlertDescription>
              </Alert>
            )}
          </FieldGroup>
        </CardContent>
        <CardFooter>
          <Button
            ref={addAccountButtonRef}
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
              {confirmation?.destructive ? (
                <Trash2 aria-hidden="true" />
              ) : (
                <AlertTriangle aria-hidden="true" />
              )}
            </AlertDialogMedia>
            <AlertDialogTitle>{confirmation?.title}</AlertDialogTitle>
            <AlertDialogDescription>{confirmation?.description}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
            <AlertDialogAction
              type="button"
              variant={confirmation?.destructive ? 'destructive' : 'default'}
              disabled={busy}
              onClick={() => void confirm()}
            >
              {busy ? (
                <Spinner data-icon="inline-start" aria-hidden="true" />
              ) : confirmation?.destructive ? (
                <Trash2 data-icon="inline-start" aria-hidden="true" />
              ) : (
                <RefreshCw data-icon="inline-start" aria-hidden="true" />
              )}
              {confirmation?.actionLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

interface AccountRowProps {
  account: AccountStatus['accounts'][number]
  accounts: AccountStatus['accounts']
  index: number
  revision: number
  busy: boolean
  onRequestSwitch: (proceed: () => void) => void
  onRequestRemove: (proceed: () => void) => void
  onReorder: (accountIds: readonly string[], expectedRevision: number) => Promise<void>
  onConfirm: (action: AccountConfirmationAction) => void
}

function AccountRow({
  account,
  accounts,
  index,
  revision,
  busy,
  onRequestSwitch,
  onRequestRemove,
  onReorder,
  onConfirm
}: AccountRowProps): React.JSX.Element {
  const presentation = localAccountPresentation(account)
  async function move(direction: 'up' | 'down'): Promise<void> {
    const accountIds = moveAccountIds(accounts, account.id, direction)
    if (!accountIds) return
    try {
      await onReorder(accountIds, revision)
    } catch {
      // VaultShell maps mutation failures to safe, visible renderer feedback.
    }
  }
  return (
    <Field orientation="responsive" data-disabled={busy || undefined}>
      <FieldContent>
        <FieldTitle>{presentation.label}</FieldTitle>
        <FieldDescription>{presentation.description}</FieldDescription>
      </FieldContent>
      {presentation.active && <Badge>使用中</Badge>}
      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="icon-sm"
          type="button"
          aria-label={`將${presentation.label}上移`}
          disabled={accountMoveButtonDisabled(index, accounts.length, 'up', busy)}
          onClick={() => void move('up')}
        >
          <ArrowUp aria-hidden="true" />
        </Button>
        <Button
          variant="ghost"
          size="icon-sm"
          type="button"
          aria-label={`將${presentation.label}下移`}
          disabled={accountMoveButtonDisabled(index, accounts.length, 'down', busy)}
          onClick={() => void move('down')}
        >
          <ArrowDown aria-hidden="true" />
        </Button>
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
        {!account.active && (
          <Button
            variant="destructive"
            size="icon-sm"
            type="button"
            aria-label={`移除${presentation.label}`}
            disabled={accountRemoveButtonDisabled(account, accounts.length, busy)}
            onClick={() =>
              onRequestRemove(() =>
                onConfirm({ kind: 'remove', accountId: account.id, slot: account.slot })
              )
            }
          >
            <Trash2 aria-hidden="true" />
          </Button>
        )}
      </div>
    </Field>
  )
}

export default AccountSwitcherCard
