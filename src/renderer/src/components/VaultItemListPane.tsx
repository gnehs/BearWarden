import { Trans, useLingui } from '@lingui/react/macro'
import {
  Archive,
  ArchiveRestore,
  FolderOpen,
  KeyRound,
  ListFilter,
  Plus,
  RotateCcw,
  Search,
  Trash2
} from 'lucide-react'
import type { LoginSummary, TotpCodeView } from '../../../shared/vault-contract'
import type { VaultSortMode } from '@renderer/lib/vault-sort'
import { cn } from '@renderer/lib/utils'
import { Button } from '@renderer/components/ui/button'
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle
} from '@renderer/components/ui/empty'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@renderer/components/ui/select'
import type { ItemSelectionModifiers } from './DndRows'
import { useShallow } from 'zustand/react/shallow'
import { useVaultSessionStore } from '@renderer/stores/vault-session-store'
import TotpCountdownIndicator from './TotpCountdownIndicator'
import VirtualizedItemList, { type VirtualizedItemGroup } from './VirtualizedItemList'
import {
  totpListCountdownPeriodSeconds,
  type BulkActionKind,
  type BulkActionSnapshot
} from './VaultShell-model'

interface VaultItemListPaneList {
  scopeTitle: string
  itemCount: number
  groups: readonly VirtualizedItemGroup[]
  sortOptions: ReadonlyArray<{ label: string; value: VaultSortMode }>
  showWebsiteIcons: boolean
  totpCodes: ReadonlyMap<string, TotpCodeView | null>
  totpCountdown: TotpCodeView | null
  trashItemCount: number
}

interface VaultItemListPaneSelection {
  selectedItemCount: number
}

interface VaultItemListPaneActions {
  onPrefetch: (id: string) => void
  onSelect: (id: string, modifiers: ItemSelectionModifiers) => void
  onToggleFavorite: (item: LoginSummary) => void
  onContextMenu: (id: string, position: { x: number; y: number }) => void
  onOpenCreate: () => void
  snapshotBulkAction: (action: BulkActionKind) => BulkActionSnapshot
  onPerformBulkAction: (snapshot: BulkActionSnapshot) => Promise<boolean>
  onSetPendingBulkAction: (snapshot: BulkActionSnapshot) => void
  onOpenMove: () => void
  onEmptyTrash: () => void
}

interface VaultItemListPaneProps {
  list: VaultItemListPaneList
  selection: VaultItemListPaneSelection
  actions: VaultItemListPaneActions
}

export function VaultItemListPane({
  list,
  selection,
  actions
}: VaultItemListPaneProps): React.JSX.Element {
  const { t } = useLingui()
  const { scope, query, sortMode, typeFilter, activeId, selectedIds, busy, setSortMode, setQuery } =
    useVaultSessionStore(
      useShallow((state) => ({
        scope: state.scope,
        query: state.query,
        sortMode: state.sortMode,
        typeFilter: state.typeFilter,
        activeId: state.editorMode ? null : state.selectedId,
        selectedIds: state.selectedIds,
        busy: state.busy,
        setSortMode: state.setSortMode,
        setQuery: state.setQuery
      }))
    )

  return (
    <>
      <header className="flex min-h-[82px] items-center justify-between gap-3 px-[18px] pt-[15px] pb-[11px] max-[430px]:px-[11px]">
        <div className="grid gap-0.5">
          <h1
            className="m-0 text-[21px] leading-[1.2] font-[760] tracking-[-0.025em]"
            id="list-title"
          >
            {list.scopeTitle}
          </h1>
          <small className="text-muted-foreground text-[11px]">
            {selectedIds.size > 1
              ? t`${selectedIds.size} selected · ${list.itemCount} items total`
              : t`${list.itemCount} items`}
          </small>
        </div>
        <div className="border-border flex items-center gap-[7px] rounded-[14px] border bg-[color-mix(in_oklch,var(--card)_78%,transparent)] p-1 shadow-none dark:bg-[color-mix(in_oklch,var(--card)_70%,transparent)]">
          <div className="text-muted-foreground flex h-8 items-center gap-1 border-0 bg-transparent py-0 pr-1 pl-1.5 shadow-none">
            <ListFilter size={16} aria-hidden="true" />
            <Select
              items={list.sortOptions}
              value={sortMode}
              disabled={scope.kind === 'recent'}
              onValueChange={(value) => setSortMode(value as VaultSortMode)}
            >
              <SelectTrigger size="sm" variant="embedded" aria-label={t`Sort order`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {list.sortOptions.map((item) => (
                    <SelectItem key={item.value} value={item.value}>
                      {item.label}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
        </div>
      </header>
      {query && (
        <div
          className="text-muted-foreground flex min-h-7 items-center justify-between gap-2.5 px-[19px] pt-0 pb-[7px] text-[10px]"
          role="status"
        >
          <span>
            <Trans>Search “{query}”</Trans>
          </span>
          <span>
            <Trans>{list.itemCount} results</Trans>
          </span>
        </div>
      )}

      {list.itemCount ? (
        <VirtualizedItemList
          groups={list.groups}
          scopeTitle={list.scopeTitle}
          activeId={activeId}
          selectedIds={selectedIds}
          onPrefetch={scope.kind === 'trash' ? undefined : actions.onPrefetch}
          onSelect={actions.onSelect}
          onFavorite={actions.onToggleFavorite}
          onContextMenu={actions.onContextMenu}
          showWebsiteIcons={scope.kind !== 'trash' && list.showWebsiteIcons}
          showTotpCodes={typeFilter === 'totp'}
          totpCodes={list.totpCodes}
          readOnly={scope.kind === 'trash'}
          className={cn(typeFilter === 'totp' && 'pb-20')}
        />
      ) : (
        <Empty className="min-h-0 flex-1 gap-0 p-7">
          <EmptyHeader>
            <EmptyMedia
              variant="icon"
              className="text-primary mb-[13px] size-[52px] rounded-2xl bg-(--accent-soft)"
            >
              {query ? (
                <Search className="size-8" />
              ) : scope.kind === 'trash' ? (
                <Trash2 className="size-8" />
              ) : (
                <KeyRound className="size-8" />
              )}
            </EmptyMedia>
            <EmptyTitle className="m-0">
              {query
                ? t`No matching items`
                : scope.kind === 'trash'
                  ? t`Trash is empty`
                  : t`There are no vault items here yet`}
            </EmptyTitle>
            <EmptyDescription className="text-muted-foreground mb-4 max-w-[290px] leading-[1.55]">
              {query
                ? t`Try a shorter search term or switch to All items.`
                : scope.kind === 'trash'
                  ? t`Deleted items remain here until you restore or permanently delete them, or the server removes them according to its retention policy.`
                  : t`Add your first item and BearWarden will keep it safe.`}
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            {query ? (
              <Button variant="outline" type="button" onClick={() => setQuery('')}>
                <Trans>Clear search</Trans>
              </Button>
            ) : scope.kind !== 'trash' && scope.kind !== 'archive' ? (
              <Button
                className="before:ring-primary-foreground/20 relative h-[38px] gap-2 rounded-[9px] border-0 px-3.5 font-[680] shadow-[var(--subtle-primary-action-shadow)] before:pointer-events-none before:absolute before:inset-0 before:rounded-[inherit] before:ring-1 before:ring-inset has-data-[icon=inline-start]:pl-3.5"
                type="button"
                onClick={actions.onOpenCreate}
              >
                <Plus data-icon="inline-start" />
                <Trans>Add item</Trans>
              </Button>
            ) : null}
          </EmptyContent>
        </Empty>
      )}
      {typeFilter === 'totp' && list.itemCount > 0 && (
        <div
          className={cn(
            'pointer-events-none absolute right-4 bottom-4',
            selection.selectedItemCount >= 2 && 'bottom-20'
          )}
        >
          <TotpCountdownIndicator
            key={list.totpCountdown?.code ?? 'loading'}
            remainingSeconds={list.totpCountdown?.remainingSeconds ?? null}
            period={totpListCountdownPeriodSeconds}
          />
        </div>
      )}
      {(selection.selectedItemCount >= 2 ||
        (scope.kind === 'trash' && list.trashItemCount > 0)) && (
        <footer
          className="border-border bg-muted flex min-h-16 flex-none flex-wrap items-center justify-end gap-2 border-t px-5 py-1"
          aria-label={t`List actions`}
        >
          {selection.selectedItemCount >= 2 && (
            <div
              className={cn(
                'flex flex-wrap items-center gap-2',
                scope.kind !== 'trash' && 'flex-1'
              )}
              role="toolbar"
              aria-label={t`Bulk actions for selected items`}
              aria-busy={busy}
            >
              <span className="sr-only" aria-live="polite">
                <Trans>{selection.selectedItemCount} items selected</Trans>
              </span>
              {scope.kind === 'trash' ? (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      void actions.onPerformBulkAction(actions.snapshotBulkAction('restore'))
                    }
                  >
                    <RotateCcw data-icon="inline-start" />
                    <Trans>Restore</Trans>
                  </Button>
                  <Button
                    variant="destructive"
                    size="sm"
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      actions.onSetPendingBulkAction(
                        actions.snapshotBulkAction('deletePermanently')
                      )
                    }
                  >
                    <Trash2 data-icon="inline-start" />
                    <Trans>Delete permanently</Trans>
                  </Button>
                </>
              ) : (
                <>
                  <Button
                    variant="destructive"
                    size="sm"
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      actions.onSetPendingBulkAction(actions.snapshotBulkAction('delete'))
                    }
                  >
                    <Trash2 data-icon="inline-start" />
                    <Trans>Delete</Trans>
                  </Button>
                  <div className="ml-auto flex flex-wrap items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      type="button"
                      disabled={busy}
                      onClick={actions.onOpenMove}
                    >
                      <FolderOpen data-icon="inline-start" />
                      <Trans>Move</Trans>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void actions.onPerformBulkAction(
                          actions.snapshotBulkAction(
                            scope.kind === 'archive' ? 'unarchive' : 'archive'
                          )
                        )
                      }
                    >
                      {scope.kind === 'archive' ? (
                        <ArchiveRestore data-icon="inline-start" />
                      ) : (
                        <Archive data-icon="inline-start" />
                      )}
                      {scope.kind === 'archive' ? t`Unarchive` : t`Archive`}
                    </Button>
                  </div>
                </>
              )}
            </div>
          )}
          {scope.kind === 'trash' && list.trashItemCount > 0 && (
            <Button
              variant="outline"
              size="sm"
              type="button"
              disabled={busy}
              onClick={actions.onEmptyTrash}
            >
              <Trash2 data-icon="inline-start" />
              <Trans>Empty Trash</Trans>
            </Button>
          )}
        </footer>
      )}
    </>
  )
}
