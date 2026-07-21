import { Trans, useLingui } from '@lingui/react/macro'
import { ArrowLeft, Menu, Plus, Search, X, type LucideIcon } from 'lucide-react'
import type { RefObject } from 'react'
import type { LoginSummary, VaultItemType } from '../../../shared/vault-contract'
import { MAX_VAULT_SEARCH_QUERY_LENGTH, normalizedVaultSearchQuery } from '../lib/vault-search-ui'
import { normalizeBitwardenCardBrand } from '../lib/payment-card'
import { cn } from '../lib/utils'
import ApplicationTitlebarMenu from './ApplicationTitlebarMenu'
import BrandMark from './BrandMark'
import PaymentCardBrandMark from './PaymentCardBrandMark'
import { TooltipIconButton } from './VaultShell-primitives'
import WebsiteIcon from './WebsiteIcon'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList
} from './ui/command'
import { InputGroup, InputGroupAddon, InputGroupButton } from './ui/input-group'
import { Kbd } from './ui/kbd'
import { Spinner } from './ui/spinner'

interface ItemTypePresentation {
  label: string
  icon: LucideIcon
}

const titlebarClassName = cn(
  // Base titlebar layout and appearance.
  'border-border relative z-20 flex h-[54px] min-h-[54px] items-center gap-3 border-b bg-[color-mix(in_oklch,var(--card)_86%,transparent)] py-0 pr-3.5 pl-[78px] shadow-[inset_0_1px_color-mix(in_oklch,var(--shadow-color)_5%,transparent)] backdrop-blur-xl backdrop-saturate-180 select-none [-webkit-app-region:drag]',
  // Compact layouts.
  'max-[1050px]:pl-[70px] max-[880px]:pl-3.5 max-[680px]:h-[52px] max-[680px]:min-h-[52px] max-[430px]:gap-2 max-[430px]:px-[9px]',
  // Leave space for the macOS traffic-light controls.
  '[.platform-macos_&]:border-b-transparent [.platform-macos_&]:bg-transparent [.platform-macos_&]:pl-[94px] [.platform-macos_&]:shadow-none [.platform-macos_&]:backdrop-filter-none max-[880px]:[.platform-macos_&]:pl-[82px] max-[430px]:[.platform-macos_&]:py-0 max-[430px]:[.platform-macos_&]:pr-[9px] max-[430px]:[.platform-macos_&]:pl-[82px]',
  // Windows draws its native controls outside the titlebar content.
  '[.platform-windows_&]:border-b-transparent [.platform-windows_&]:bg-transparent [.platform-windows_&]:pl-3.5 [.platform-windows_&]:shadow-none [.platform-windows_&]:backdrop-filter-none max-[430px]:[.platform-windows_&]:px-[9px]',
  // Respect the browser-provided safe area when Window Controls Overlay is active.
  '[.platform-window-controls-overlay_&]:h-[env(titlebar-area-height,54px)] [.platform-window-controls-overlay_&]:min-h-[env(titlebar-area-height,54px)] [.platform-window-controls-overlay_&]:pr-[calc(14px+100vw-env(titlebar-area-x,0px)-env(titlebar-area-width,100vw))] [.platform-window-controls-overlay_&]:pl-[calc(14px+env(titlebar-area-x,0px))] max-[430px]:[.platform-window-controls-overlay_&]:pr-[calc(9px+100vw-env(titlebar-area-x,0px)-env(titlebar-area-width,100vw))] max-[430px]:[.platform-window-controls-overlay_&]:pl-[calc(9px+env(titlebar-area-x,0px))]'
)

interface VaultShellLoadingProps {
  appearance: {
    isMac: boolean
    usesWindowControlsOverlay: boolean
  }
}

export function VaultShellLoading({ appearance }: VaultShellLoadingProps): React.JSX.Element {
  if (appearance.isMac) {
    return (
      <main
        className="bg-background text-muted-foreground flex size-full items-center justify-center gap-3.5"
        role="status"
      >
        <BrandMark className="absolute bottom-[25px] left-1/2 -translate-x-1/2" stacked />
        <Spinner className="size-6" aria-hidden="true" />
        <p>
          <Trans>Decrypting your items…</Trans>
        </p>
      </main>
    )
  }

  return (
    <main
      className={cn(
        'bg-background flex size-full min-w-0 flex-col',
        appearance.usesWindowControlsOverlay && 'platform-window-controls-overlay'
      )}
    >
      <header className={titlebarClassName}>
        <ApplicationTitlebarMenu />
        <div className="flex-1 self-stretch" aria-hidden="true" />
      </header>
      <div
        className="bg-background text-muted-foreground flex size-full items-center justify-center gap-3.5"
        role="status"
      >
        <Spinner className="size-6" aria-hidden="true" />
        <p>
          <Trans>Decrypting your items…</Trans>
        </p>
      </div>
    </main>
  )
}

interface VaultShellTitlebarProps {
  appearance: {
    isMac: boolean
  }
  navigation: {
    auxiliaryPageOpen: boolean
    closeAuxiliaryPage: (() => void) | null
    sidebarOpen: boolean
    onToggleSidebar: () => void
  }
  search: {
    query: string
    open: boolean
    shortcutLabel: string
    onOpen: () => void
    onClear: () => void
  }
  itemCreation: {
    visible: boolean
    onCreate: () => void
  }
  onLockVault: () => void | Promise<void>
}

export function VaultShellTitlebar({
  appearance,
  navigation,
  search,
  itemCreation,
  onLockVault
}: VaultShellTitlebarProps): React.JSX.Element {
  const { t } = useLingui()
  const query = search.query

  return (
    <header className={titlebarClassName}>
      <ApplicationTitlebarMenu onLockVault={onLockVault} />
      {!navigation.auxiliaryPageOpen && (
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="hidden max-[880px]:grid"
          type="button"
          label={navigation.sidebarOpen ? t`Close sidebar` : t`Open sidebar`}
          aria-expanded={navigation.sidebarOpen}
          onClick={navigation.onToggleSidebar}
        >
          <span
            className="group/icon-swap relative inline-grid"
            data-state={navigation.sidebarOpen ? 'b' : 'a'}
            aria-hidden="true"
          >
            <Menu
              className="col-start-1 row-start-1 scale-(--icon-swap-start-scale) opacity-0 blur-(--icon-swap-blur) transition-[opacity,filter,transform] duration-(--icon-swap-dur) ease-(--icon-swap-ease) will-change-[opacity,filter,transform] group-data-[state=a]/icon-swap:scale-100 group-data-[state=a]/icon-swap:opacity-100 group-data-[state=a]/icon-swap:blur-none motion-reduce:transition-none"
              data-icon="a"
            />
            <X
              className="col-start-1 row-start-1 scale-(--icon-swap-start-scale) opacity-0 blur-(--icon-swap-blur) transition-[opacity,filter,transform] duration-(--icon-swap-dur) ease-(--icon-swap-ease) will-change-[opacity,filter,transform] group-data-[state=b]/icon-swap:scale-100 group-data-[state=b]/icon-swap:opacity-100 group-data-[state=b]/icon-swap:blur-none motion-reduce:transition-none"
              data-icon="b"
            />
          </span>
        </TooltipIconButton>
      )}
      {navigation.closeAuxiliaryPage && (
        <Button variant="outline" size="sm" type="button" onClick={navigation.closeAuxiliaryPage}>
          <ArrowLeft data-icon="inline-start" />
          <Trans>Vault</Trans>
        </Button>
      )}
      {appearance.isMac && (
        <div className="inline-flex items-center gap-2 max-[680px]:hidden">
          <BrandMark hideMark />
          <Badge variant="secondary" className="bg-black/5 shadow-(--control-highlight)">
            <Trans>Beta</Trans>
          </Badge>
        </div>
      )}
      {!navigation.auxiliaryPageOpen && (
        <InputGroup
          className={cn(
            'text-muted-foreground [@media(prefers-reduced-transparency:reduce)]:bg-card bg-card/50 hover:bg-muted hover:text-foreground absolute left-1/2 h-[38px] w-[clamp(300px,44vw,560px)] min-w-0 -translate-x-1/2 gap-[7px] rounded-[11px] border-0 py-0 pr-2 pl-2.5 focus-within:border-(--focus) max-[880px]:static max-[880px]:max-w-none max-[880px]:flex-1 max-[880px]:translate-x-0 max-[680px]:[&_kbd]:hidden',
            'shadow-(--control-highlight) hover:shadow-(--control-highlight)',
            '[-webkit-app-region:no-drag] **:[-webkit-app-region:no-drag]'
          )}
        >
          <Button
            variant="ghost"
            className="text-foreground hover:text-foreground h-full min-w-0 flex-1 justify-start bg-transparent p-0 text-xs font-normal shadow-none hover:bg-transparent hover:shadow-none focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none aria-expanded:bg-transparent [&>span]:w-full [&>span]:min-w-0 [&>span]:text-left"
            type="button"
            aria-label={query ? t`Search vault items, currently ${query}` : t`Search vault items`}
            aria-haspopup="dialog"
            aria-expanded={search.open}
            onClick={search.onOpen}
          >
            <span className={cn('truncate', !search.query && 'text-muted-foreground')}>
              {search.query || t`Search vault`}
            </span>
          </Button>
          <InputGroupAddon align="inline-start">
            <Search aria-hidden="true" />
          </InputGroupAddon>
          {search.query && (
            <InputGroupAddon align="inline-end">
              <InputGroupButton
                size="icon-xs"
                type="button"
                aria-label={t`Clear search`}
                onClick={search.onClear}
              >
                <X />
              </InputGroupButton>
            </InputGroupAddon>
          )}
          <InputGroupAddon align="inline-end">
            <Kbd>{search.shortcutLabel} F</Kbd>
          </InputGroupAddon>
        </InputGroup>
      )}
      <div
        className={cn('flex-1 self-stretch', !navigation.auxiliaryPageOpen && 'max-[880px]:hidden')}
        aria-hidden="true"
      />
      {itemCreation.visible && (
        <TooltipIconButton
          variant="outline"
          size="icon"
          className="border-border text-foreground rounded-[10px] bg-[color-mix(in_oklch,var(--card)_32%,transparent)] shadow-[var(--control-highlight),0_1px_2px_color-mix(in_oklch,var(--shadow-color)_12%,transparent)]"
          type="button"
          label={t`Add item`}
          onClick={itemCreation.onCreate}
        >
          <Plus aria-hidden="true" />
        </TooltipIconButton>
      )}
    </header>
  )
}

interface VaultSearchDialogProps {
  state: {
    open: boolean
    query: string
    items: LoginSummary[]
    scopeTitle: string
  }
  inputRef: RefObject<HTMLInputElement | null>
  presentation: {
    itemTypes: Record<VaultItemType, ItemTypePresentation>
    showWebsiteIcons: boolean
    isTrash: boolean
  }
  actions: {
    onOpenChange: (open: boolean) => void
    onQueryChange: (query: string) => void
    onSelectItem: (id: string) => void
  }
}

export function VaultSearchDialog({
  state,
  inputRef,
  presentation,
  actions
}: VaultSearchDialogProps): React.JSX.Element {
  const { t } = useLingui()
  const scopeTitle = state.scopeTitle

  return (
    <CommandDialog
      open={state.open}
      onOpenChange={actions.onOpenChange}
      title={t`Search vault`}
      description={t`Search names, summaries, websites, and content. Start with > for advanced field-specific search.`}
    >
      <Command
        className="max-h-[min(480px,70vh)] [&_[data-slot=command-input-wrapper]]:px-2 [&_[data-slot=command-input-wrapper]]:pt-2 [&_[data-slot=command-input-wrapper]]:pb-0"
        label={t`Search vault items`}
        loop
        shouldFilter={false}
      >
        <CommandInput
          ref={inputRef}
          placeholder={t`Search vault; for example, >name:github`}
          maxLength={MAX_VAULT_SEARCH_QUERY_LENGTH}
          value={state.query}
          onValueChange={actions.onQueryChange}
          endAdornment={
            state.query ? (
              <InputGroupAddon align="inline-end">
                <InputGroupButton
                  size="icon-xs"
                  type="button"
                  aria-label={t`Clear search`}
                  onClick={() => {
                    actions.onQueryChange('')
                    window.requestAnimationFrame(() => inputRef.current?.focus())
                  }}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') event.stopPropagation()
                  }}
                >
                  <X />
                </InputGroupButton>
              </InputGroupAddon>
            ) : undefined
          }
        />
        <CommandList className="scroll-fade-y forced-colors:scroll-fade-none max-h-[min(420px,calc(70vh-54px))] p-1.5">
          <CommandEmpty>
            <Trans>No matching vault items</Trans>
          </CommandEmpty>
          {state.items.length > 0 && (
            <CommandGroup
              heading={
                normalizedVaultSearchQuery(state.query)
                  ? t`Search results · ${state.items.length} items`
                  : t`${scopeTitle} · ${state.items.length} items`
              }
            >
              {state.items.map((item) => {
                const ItemIcon = presentation.itemTypes[item.type].icon
                return (
                  <CommandItem
                    key={item.id}
                    value={item.id}
                    onSelect={() => actions.onSelectItem(item.id)}
                  >
                    <span
                      className={cn(
                        'bg-foreground/5 text-muted-foreground grid size-[30px] flex-none place-items-center rounded',
                        item.type === 'login' && !presentation.isTrash && 'overflow-hidden'
                      )}
                      aria-hidden="true"
                    >
                      {item.type === 'card' ? (
                        <PaymentCardBrandMark
                          brand={normalizeBitwardenCardBrand(item.cardBrand)}
                          compact
                        />
                      ) : item.type === 'login' && !presentation.isTrash ? (
                        <WebsiteIcon
                          id={item.id}
                          uri={item.uri}
                          enabled={presentation.showWebsiteIcons}
                        />
                      ) : (
                        <ItemIcon />
                      )}
                    </span>
                    <span className="min-w-0 flex-1">
                      <strong className="block truncate">{item.name}</strong>
                      <small className="text-muted-foreground block truncate text-[10px]">
                        {item.subtitle || item.username || item.uri || t`No summary`}
                      </small>
                    </span>
                    <span className="text-muted-foreground flex-none text-[10px]">
                      {presentation.itemTypes[item.type].label}
                    </span>
                  </CommandItem>
                )
              })}
            </CommandGroup>
          )}
        </CommandList>
      </Command>
    </CommandDialog>
  )
}
