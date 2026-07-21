import { useRef, useState } from 'react'
import {
  closestCenter,
  DndContext,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent
} from '@dnd-kit/core'
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import type { AccountStatus } from '../../../shared/vault-contract'
import { Trans, useLingui } from '@lingui/react/macro'
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
  CardAction,
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
import { cn } from '@renderer/lib/utils'
import { AlertTriangle, GripVertical, Plus, RefreshCw, Trash2 } from 'lucide-react'
import {
  accountConfirmationContent,
  accountRemoveButtonDisabled,
  accountSwitchButtonDisabled,
  localAccountPresentation,
  MAX_LOCAL_ACCOUNTS,
  moveAccountIds,
  type AccountConfirmationAction
} from './account-switcher-ui'
import { SettingsCard, SettingsCardContent } from './SettingsPrimitives'

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
  const { i18n, t } = useLingui()
  const [confirmationAction, setConfirmationAction] = useState<AccountConfirmationAction | null>(
    null
  )
  const addAccountButtonRef = useRef<HTMLButtonElement>(null)
  const accounts = accountStatus?.accounts ?? []
  const confirmation = confirmationAction ? accountConfirmationContent(confirmationAction) : null
  const numberFormatter = new Intl.NumberFormat(i18n.locale)
  const formattedAccountCount = numberFormatter.format(accounts.length)
  const formattedMaxLocalAccounts = numberFormatter.format(MAX_LOCAL_ACCOUNTS)
  const sortableSensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )

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

  async function reorderAccounts(event: DragEndEvent): Promise<void> {
    const overId = event.over ? String(event.over.id) : null
    if (!accountStatus || !overId) return
    const accountIds = moveAccountIds(accounts, String(event.active.id), overId)
    if (!accountIds) return
    try {
      await onReorder(accountIds, accountStatus.revision)
    } catch {
      // VaultShell maps mutation failures to safe, visible renderer feedback.
    }
  }

  return (
    <>
      <SettingsCard aria-labelledby="local-accounts-settings-title">
        <CardHeader>
          <CardTitle id="local-accounts-settings-title" role="heading" aria-level={2}>
            <Trans>Local accounts</Trans>
          </CardTitle>
          <CardDescription>
            <Trans>Add, reorder, switch, or remove vault accounts on this device.</Trans>
          </CardDescription>
          <CardAction>
            <Badge variant="secondary">
              <Trans>
                {formattedAccountCount} / {formattedMaxLocalAccounts}
              </Trans>
            </Badge>
          </CardAction>
        </CardHeader>
        <SettingsCardContent>
          <FieldGroup>
            {accountStatus === null ? (
              !error && (
                <Field>
                  <FieldContent>
                    <FieldTitle>
                      <Trans>Loading local accounts</Trans>
                    </FieldTitle>
                    <FieldDescription aria-live="polite">
                      <Trans>Please wait.</Trans>
                    </FieldDescription>
                  </FieldContent>
                </Field>
              )
            ) : (
              <DndContext
                sensors={sortableSensors}
                collisionDetection={closestCenter}
                accessibility={{
                  screenReaderInstructions: {
                    draggable: t`To reorder a local account, press space or enter. Use the arrow keys to move it, then press space or enter again to drop it.`
                  },
                  announcements: {
                    onDragStart: ({ active }) => {
                      const position = accounts.findIndex(
                        (account) => account.id === String(active.id)
                      )
                      return t`Picked up local account ${position + 1} of ${accounts.length}.`
                    },
                    onDragOver: ({ over }) => {
                      if (!over) return
                      const position = accounts.findIndex(
                        (account) => account.id === String(over.id)
                      )
                      return t`Local account moved to position ${position + 1} of ${accounts.length}.`
                    },
                    onDragEnd: ({ over }) => {
                      if (!over) return t`Local account was not moved.`
                      const position = accounts.findIndex(
                        (account) => account.id === String(over.id)
                      )
                      return t`Local account dropped at position ${position + 1} of ${accounts.length}.`
                    },
                    onDragCancel: () => t`Local account reordering cancelled.`
                  }
                }}
                onDragEnd={(event) => void reorderAccounts(event)}
              >
                <SortableContext
                  items={accounts.map((account) => account.id)}
                  strategy={verticalListSortingStrategy}
                >
                  {accounts.map((account) => (
                    <AccountRow
                      key={account.id}
                      account={account}
                      accounts={accounts}
                      busy={busy}
                      onRequestSwitch={onRequestSwitch}
                      onRequestRemove={onRequestRemove}
                      onConfirm={(action) => setConfirmationAction(action)}
                    />
                  ))}
                </SortableContext>
              </DndContext>
            )}
            {busy && (
              <Field>
                <FieldContent>
                  <FieldDescription role="status" aria-live="polite">
                    <Spinner data-icon="inline-start" aria-hidden="true" />
                    {busyLabel || t`Processing local accounts`}
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
                  <Trans>
                    The local data from the last removal has not completed secure cleanup.
                    BearWarden will try again the next time it starts; it will not delete or
                    overwrite unknown data until cleanup is complete.
                  </Trans>
                </AlertDescription>
              </Alert>
            )}
          </FieldGroup>
        </SettingsCardContent>
        <CardFooter>
          <Button
            ref={addAccountButtonRef}
            size="sm"
            type="button"
            disabled={busy || accountStatus === null || accounts.length >= MAX_LOCAL_ACCOUNTS}
            onClick={() => onRequestAdd(() => setConfirmationAction({ kind: 'add' }))}
          >
            <Plus data-icon="inline-start" aria-hidden="true" />
            <Trans>Add local account</Trans>
          </Button>
        </CardFooter>
      </SettingsCard>

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
            <AlertDialogCancel disabled={busy}>
              <Trans>Cancel</Trans>
            </AlertDialogCancel>
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
  busy: boolean
  onRequestSwitch: (proceed: () => void) => void
  onRequestRemove: (proceed: () => void) => void
  onConfirm: (action: AccountConfirmationAction) => void
}

function AccountRow({
  account,
  accounts,
  busy,
  onRequestSwitch,
  onRequestRemove,
  onConfirm
}: AccountRowProps): React.JSX.Element {
  const { t } = useLingui()
  const presentation = localAccountPresentation(account)
  const {
    attributes,
    listeners,
    setNodeRef,
    setActivatorNodeRef,
    transform,
    transition,
    isDragging
  } = useSortable({ id: account.id, disabled: busy || accounts.length < 2 })
  return (
    <div
      ref={setNodeRef}
      className={cn(
        'grid grid-cols-[auto_minmax(0,1fr)] items-center gap-1',
        isDragging && 'opacity-60'
      )}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      data-account-sortable-row=""
      data-dragging={isDragging ? 'true' : undefined}
    >
      <Button
        ref={setActivatorNodeRef}
        variant="ghost"
        size="icon-sm"
        type="button"
        className="h-7 w-5 min-w-5 cursor-grab touch-none px-0 active:cursor-grabbing"
        aria-label={t`Reorder ${`${presentation.label}`}`}
        disabled={busy || accounts.length < 2}
        {...attributes}
        {...listeners}
      >
        <GripVertical aria-hidden="true" />
      </Button>
      <Field orientation="responsive" data-disabled={busy || undefined}>
        <FieldContent>
          <FieldTitle>{presentation.label}</FieldTitle>
          <FieldDescription>{presentation.description}</FieldDescription>
        </FieldContent>
        {presentation.active && (
          <Badge>
            <Trans>Active</Trans>
          </Badge>
        )}
        <div className="flex items-center gap-1">
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
            <Trans>Switch</Trans>
          </Button>
          {!account.active && (
            <Button
              variant="destructive"
              size="icon-sm"
              type="button"
              aria-label={t`Remove ${presentation.label}`}
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
    </div>
  )
}

export default AccountSwitcherCard
