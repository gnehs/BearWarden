import { useDndContext, useDroppable } from '@dnd-kit/core'
import { SortableContext, verticalListSortingStrategy } from '@dnd-kit/sortable'
import { Trans, useLingui } from '@lingui/react/macro'
import { useShallow } from 'zustand/react/shallow'
import {
  Archive,
  ChevronUp,
  LockKeyhole,
  Plus,
  Send as SendIcon,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Star,
  Trash2,
  UserRound,
  type LucideIcon
} from 'lucide-react'
import { useMemo, useState, type ComponentProps, type JSX, type RefObject } from 'react'
import type {
  CollectionView,
  FolderView,
  OrganizationView,
  SharedLoginSummary,
  SyncStatus
} from '../../../shared/vault-contract'
import type { VaultCategoryFilter } from '../lib/vault-category'
import { useVaultSessionStore } from '../stores/vault-session-store'
import type { Scope } from './VaultShell-model'
import { folderRootDropId, quickAccessDropIds } from './VaultShell-dnd'
import { SidebarLink, UnfiledRow, type SidebarTone } from './VaultShell-primitives'
import { FolderRow } from './DndRows'
import { VaultOrganizationSidebarSection } from './VaultOrganizationSidebarSection'
import { Button } from '@renderer/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger
} from '@renderer/components/ui/dropdown-menu'
import { Kbd } from '@renderer/components/ui/kbd'
import { Tooltip, TooltipContent, TooltipTrigger } from '@renderer/components/ui/tooltip'
import { cn } from '@renderer/lib/utils'
import {
  vaultFolderAggregateCounts,
  vaultFolderHierarchyRows,
  vaultFolderVisibleItemCount,
  visibleVaultFolderHierarchyRows
} from '@renderer/lib/vault-folder-tree'

interface VaultSidebarAppearance {
  isMac: boolean
  isWindows: boolean
  open: boolean
}

interface VaultSidebarCategory {
  id: VaultCategoryFilter
  icon: LucideIcon
  label: string
  tone: SidebarTone
}

interface VaultSidebarNavigation {
  categories: readonly VaultSidebarCategory[]
  categoryCounts: ReadonlyMap<VaultCategoryFilter, number>
  specialFolderCounts: {
    favorites: number
    archive: number
    trash: number
  }
  folderCounts: ReadonlyMap<string | null, number>
  organizations: OrganizationView[]
  collections: CollectionView[]
  sharedItems: SharedLoginSummary[]
}

interface VaultSidebarAccount {
  name: string
  syncState: SyncStatus['state']
  syncLabel: string
  syncIcon: LucideIcon
  commandLabel: string
}

interface VaultSidebarActions {
  onSelectType: (type: VaultCategoryFilter) => void
  onSelectScope: (scope: Scope) => void
  onAddFolder: () => void
  onEditFolder: (folder: FolderView) => void
  onOpenGenerator: () => void
  onOpenEmergencyAccess: () => void
  onOpenSends: () => void
  onOpenHealth: () => void
  onOpenSettings: () => void
  onLockVault: () => void | Promise<void>
  onOpenSync: () => void
}

interface VaultShellSidebarProps {
  appearance: VaultSidebarAppearance
  navigation: VaultSidebarNavigation
  account: VaultSidebarAccount
  actions: VaultSidebarActions
  accountMenuTriggerRef: RefObject<HTMLButtonElement | null>
}

interface SidebarTooltipIconButtonProps extends ComponentProps<typeof Button> {
  label: string
}

const folderSectionClassName =
  'flex flex-none flex-col [&>header]:flex [&>header]:items-center [&>header]:justify-between [&>header]:pt-0 [&>header]:pr-1.5 [&>header]:pb-1 [&>header]:pl-[9px] [&_h2]:m-0 [&_h2]:text-[10px] [&_h2]:font-[760] [&_h2]:tracking-[0.11em] [&_h2]:text-muted-foreground [&_h2]:uppercase'

function SidebarTooltipIconButton({
  label,
  children,
  className,
  ...props
}: SidebarTooltipIconButtonProps): JSX.Element {
  const { active } = useDndContext()

  return (
    <Tooltip disabled={active != null}>
      <TooltipTrigger
        render={
          <Button
            aria-label={label}
            className={cn(
              'border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground dark:bg-card dark:hover:bg-muted size-[34px] min-w-[34px] rounded-md shadow-(--control-highlight) transition-[background,color,border-color,transform] duration-[130ms] [-webkit-app-region:no-drag]',
              className
            )}
            {...props}
          />
        }
      >
        {children}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  )
}

export function VaultShellSidebar({
  appearance,
  navigation,
  account,
  actions,
  accountMenuTriggerRef
}: VaultShellSidebarProps): JSX.Element {
  const { t } = useLingui()
  const { folders, scope, typeFilter } = useVaultSessionStore(
    useShallow((state) => ({
      folders: state.folders,
      scope: state.scope,
      typeFilter: state.typeFilter
    }))
  )
  const SyncSidebarIcon = account.syncIcon
  const sidebarAccountName = account.name
  const canDropIntoSpecialFolder = scope.kind !== 'archive' && scope.kind !== 'trash'
  const [collapsedFolderIds, setCollapsedFolderIds] = useState<ReadonlySet<string>>(() => new Set())
  const folderRows = useMemo(() => vaultFolderHierarchyRows(folders), [folders])
  const { active, over } = useDndContext()
  const activeFolderDrag = active
    ? folders.some((folder) => folder.id === String(active.id))
    : false
  const temporarilyExpandedFolderId =
    activeFolderDrag && over && folders.some((folder) => folder.id === String(over.id))
      ? String(over.id)
      : null
  const effectiveCollapsedFolderIds = useMemo(() => {
    if (!temporarilyExpandedFolderId || !collapsedFolderIds.has(temporarilyExpandedFolderId)) {
      return collapsedFolderIds
    }
    const next = new Set(collapsedFolderIds)
    next.delete(temporarilyExpandedFolderId)
    return next
  }, [collapsedFolderIds, temporarilyExpandedFolderId])
  const visibleFolderRows = useMemo(
    () => visibleVaultFolderHierarchyRows(folderRows, effectiveCollapsedFolderIds),
    [effectiveCollapsedFolderIds, folderRows]
  )
  const aggregateFolderCounts = useMemo(
    () => vaultFolderAggregateCounts(folderRows, navigation.folderCounts),
    [folderRows, navigation.folderCounts]
  )
  const { setNodeRef: setFolderRootRef, isOver: isOverFolderRoot } = useDroppable({
    id: folderRootDropId
  })

  return (
    <aside
      className={cn(
        'border-sidebar-border bg-sidebar text-foreground z-11 flex min-h-0 min-w-0 flex-col overflow-hidden border-r bg-[linear-gradient(color-mix(in_oklch,var(--sidebar-foreground)_3%,transparent),transparent)] [backdrop-filter:saturate(165%)_blur(28px)] [-webkit-backdrop-filter:saturate(165%)_blur(28px)] max-[880px]:absolute max-[880px]:inset-y-0 max-[880px]:left-0 max-[880px]:z-31 max-[880px]:w-[248px] max-[880px]:-translate-x-full max-[880px]:transition-transform max-[880px]:duration-180 max-[880px]:ease-out',
        (appearance.isMac || appearance.isWindows) &&
          'max-[880px]:bg-sidebar mb-[-8px] border-0 bg-transparent bg-none shadow-none [backdrop-filter:none] [-webkit-backdrop-filter:none] max-[880px]:[inset:0_auto_8px_8px] max-[880px]:mb-0 max-[880px]:translate-x-[calc(-100%-8px)] max-[880px]:rounded-2xl max-[880px]:border max-[880px]:border-(--native-material-border) max-[880px]:shadow-(--native-material-shadow) max-[880px]:[backdrop-filter:saturate(165%)_blur(28px)] max-[880px]:[-webkit-backdrop-filter:saturate(165%)_blur(28px)] [@media(max-width:880px)_and_(prefers-reduced-transparency:reduce)]:[backdrop-filter:none] [@media(max-width:880px)_and_(prefers-reduced-transparency:reduce)]:[-webkit-backdrop-filter:none]',
        appearance.open &&
          'max-[880px]:translate-x-0 max-[880px]:shadow-[14px_0_40px_color-mix(in_oklch,var(--shadow-color)_30%,transparent)]',
        appearance.open &&
          (appearance.isMac || appearance.isWindows) &&
          'max-[880px]:shadow-(--native-material-shadow)'
      )}
      data-vault-sidebar=""
      aria-label={t`Vault navigation`}
    >
      <div className="scroll-fade-y forced-colors:scroll-fade-none min-h-0 flex-1 [scrollbar-color:color-mix(in_oklch,var(--muted-foreground)_25%,transparent)_transparent] overflow-y-auto overscroll-contain max-[880px]:pt-2">
        <section
          className={cn(folderSectionClassName, 'px-[11px] pb-1')}
          aria-labelledby="categories-title"
        >
          <h2 className="hidden" id="categories-title">
            <Trans>Categories</Trans>
          </h2>
          <nav className="grid grid-cols-2 gap-2 p-0 pt-px" aria-label={t`Vault categories`}>
            {navigation.categories.map((category) => {
              const Icon = category.icon
              return (
                <SidebarLink
                  key={category.id}
                  icon={<Icon size={17} />}
                  label={category.label}
                  count={navigation.categoryCounts.get(category.id) ?? 0}
                  active={scope.kind === 'all' && typeFilter === category.id}
                  variant="tile"
                  tone={category.tone}
                  onClick={() => actions.onSelectType(category.id)}
                />
              )
            })}
          </nav>
        </section>

        <section
          className={cn(folderSectionClassName, 'px-[9px] py-1')}
          aria-labelledby="folders-title"
        >
          <header
            ref={setFolderRootRef}
            className={cn(
              'rounded-lg transition-shadow',
              activeFolderDrag &&
                isOverFolderRoot &&
                'bg-sidebar-overlay-active ring-sidebar-ring ring-2'
            )}
          >
            <h2 id="folders-title">
              <Trans>Folders</Trans>
            </h2>
            <SidebarTooltipIconButton
              variant="sidebar"
              size="icon"
              className="hover:bg-sidebar-overlay-hover hover:text-foreground border-transparent bg-transparent shadow-none hover:shadow-(--control-highlight) dark:bg-transparent"
              type="button"
              label={t`Add folder`}
              onClick={actions.onAddFolder}
            >
              <Plus aria-hidden="true" />
            </SidebarTooltipIconButton>
          </header>
          <ul className="m-0 [scrollbar-color:var(--sidebar-ring)_transparent] list-none overflow-visible p-0">
            <li className="grid">
              <SidebarLink
                icon={<Star size={16} />}
                label={t`Favorites`}
                count={navigation.specialFolderCounts.favorites}
                active={scope.kind === 'favorites'}
                dropTargetId={canDropIntoSpecialFolder ? quickAccessDropIds.favorites : undefined}
                onClick={() => actions.onSelectScope({ kind: 'favorites' })}
              />
            </li>
            <li className="grid">
              <SidebarLink
                icon={<Archive size={16} />}
                label={t`Archive`}
                count={navigation.specialFolderCounts.archive}
                active={scope.kind === 'archive'}
                dropTargetId={canDropIntoSpecialFolder ? quickAccessDropIds.archive : undefined}
                onClick={() => actions.onSelectScope({ kind: 'archive' })}
              />
            </li>
            <li className="grid">
              <SidebarLink
                icon={<Trash2 size={16} />}
                label={t`Trash`}
                count={navigation.specialFolderCounts.trash}
                active={scope.kind === 'trash'}
                dropTargetId={scope.kind === 'trash' ? undefined : quickAccessDropIds.trash}
                onClick={() => actions.onSelectScope({ kind: 'trash' })}
              />
            </li>
            <UnfiledRow
              selected={scope.kind === 'unfiled'}
              count={navigation.folderCounts.get(null) ?? 0}
              onSelect={() => actions.onSelectScope({ kind: 'unfiled' })}
            />
            <SortableContext
              items={visibleFolderRows.map((row) => row.folder.id)}
              strategy={verticalListSortingStrategy}
            >
              {visibleFolderRows.map((row) => {
                const { folder, label, depth, hasChildren } = row
                const expanded = !effectiveCollapsedFolderIds.has(folder.id)
                const count = vaultFolderVisibleItemCount(
                  row,
                  expanded,
                  navigation.folderCounts,
                  aggregateFolderCounts
                )

                return (
                  <FolderRow
                    key={folder.id}
                    folder={folder}
                    label={label}
                    depth={depth}
                    count={count}
                    hasChildren={hasChildren}
                    expanded={expanded}
                    toggleDisabled={activeFolderDrag}
                    selected={scope.kind === 'folder' && scope.folderId === folder.id}
                    onToggle={() =>
                      setCollapsedFolderIds((current) => {
                        const next = new Set(current)
                        if (next.has(folder.id)) next.delete(folder.id)
                        else next.add(folder.id)
                        return next
                      })
                    }
                    onSelect={() => actions.onSelectScope({ kind: 'folder', folderId: folder.id })}
                    onEdit={() => actions.onEditFolder(folder)}
                  />
                )
              })}
            </SortableContext>
          </ul>
        </section>

        {navigation.organizations.length > 0 && (
          <VaultOrganizationSidebarSection
            organizations={navigation.organizations}
            collections={navigation.collections}
            sharedItems={navigation.sharedItems}
            scope={scope}
            onSelectAllShared={() => actions.onSelectScope({ kind: 'shared' })}
            onSelectOrganization={(organizationId) =>
              actions.onSelectScope({ kind: 'organization', organizationId })
            }
            onSelectCollection={(organizationId, collectionId) =>
              actions.onSelectScope({ kind: 'collection', organizationId, collectionId })
            }
          />
        )}
      </div>

      <footer className="text-muted-foreground grid grid-cols-[minmax(0,1fr)_auto] items-center gap-1 border-t-0 bg-transparent px-[9px] pt-[7px] pb-[9px] text-[10px]">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                ref={accountMenuTriggerRef}
                variant="sidebar"
                className="text-sidebar-foreground hover:bg-sidebar-overlay-hover data-popup-open:bg-sidebar-overlay-active h-auto min-h-9 w-full justify-start gap-[7px] rounded-[9px] px-1.5 py-1"
                type="button"
                aria-label={t`Open ${sidebarAccountName} menu`}
              />
            }
          >
            <span
              className="text-muted-foreground grid size-5 flex-none place-items-center [&>svg]:size-[18px]"
              aria-hidden="true"
            >
              <UserRound />
            </span>
            <span className="block min-w-0 flex-1 text-left">
              <strong className="text-sidebar-foreground block truncate text-xs font-bold">
                {account.name}
              </strong>
            </span>
            <ChevronUp className="text-muted-foreground ml-auto" aria-hidden="true" />
          </DropdownMenuTrigger>
          <DropdownMenuContent
            side="top"
            align="start"
            sideOffset={8}
            className="min-w-[220px] p-[5px] [&_[data-slot=dropdown-menu-item]]:min-h-[34px] [&_[data-slot=dropdown-menu-item]]:gap-2 [&_[data-slot=dropdown-menu-item]]:px-[9px]"
          >
            <DropdownMenuGroup>
              <DropdownMenuLabel className="flex items-center gap-[7px] p-[7px]">
                <span
                  className="text-muted-foreground grid size-5 flex-none place-items-center [&>svg]:size-[18px]"
                  aria-hidden="true"
                >
                  <UserRound />
                </span>
                <span className="grid min-w-0 gap-px">
                  <strong className="text-sidebar-foreground block truncate text-xs font-bold">
                    {account.name}
                  </strong>
                  <small className="text-muted-foreground block truncate text-[10px] font-medium">
                    {account.syncLabel}
                  </small>
                </span>
              </DropdownMenuLabel>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem onClick={actions.onOpenGenerator}>
                <Sparkles data-icon="inline-start" />
                <Trans>Generator</Trans>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={actions.onOpenEmergencyAccess}>
                <ShieldAlert data-icon="inline-start" />
                <Trans>Emergency Access</Trans>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={actions.onOpenSends}>
                <SendIcon data-icon="inline-start" />
                <Trans>Sends</Trans>
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem onClick={actions.onOpenHealth}>
                <ShieldCheck data-icon="inline-start" />
                <Trans>Health report</Trans>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={actions.onOpenSettings}>
                <Settings2 data-icon="inline-start" />
                <Trans>Settings</Trans>
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuItem onClick={() => void actions.onLockVault()}>
                <LockKeyhole data-icon="inline-start" />
                <Trans>Lock vault</Trans>
                <DropdownMenuShortcut>
                  <Kbd>{account.commandLabel} L</Kbd>
                </DropdownMenuShortcut>
              </DropdownMenuItem>
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
        <SidebarTooltipIconButton
          variant="sidebar"
          size="icon"
          className="hover:bg-sidebar-overlay-hover hover:text-foreground size-[34px] rounded-[9px] border-transparent bg-transparent shadow-none hover:shadow-(--control-highlight) dark:bg-transparent"
          type="button"
          label={t`Cloud sync: ${account.syncLabel}`}
          onClick={actions.onOpenSync}
        >
          <SyncSidebarIcon
            className={cn(
              'text-muted-foreground',
              account.syncState === 'ready' && 'text-sidebar-status-success',
              (account.syncState === 'locked' || account.syncState === 'unconfigured') &&
                'text-chart-4',
              account.syncState === 'error' && 'text-destructive',
              account.syncState === 'syncing' &&
                'text-ring animate-[sync-pulse_1.1s_ease-in-out_infinite]'
            )}
            aria-hidden="true"
          />
        </SidebarTooltipIconButton>
      </footer>
    </aside>
  )
}
