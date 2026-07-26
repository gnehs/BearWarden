import { useCallback } from 'react'
import { useLingui } from '@lingui/react/macro'
import type { ApplicationMenuCommand } from '../../../shared/vault-contract'
import { SELECTED_ITEM_COPY_SHORTCUTS } from '../../../shared/selected-item-shortcuts'
import { shouldUseApplicationTitlebarMenu } from '../lib/application-titlebar-menu'
import {
  Menubar,
  MenubarContent,
  MenubarGroup,
  MenubarItem,
  MenubarMenu,
  MenubarSeparator,
  MenubarShortcut,
  MenubarTrigger
} from './ui/menubar'

interface ApplicationTitlebarMenuProps {
  onLockVault?: () => void | Promise<void>
}

const shortcutPrefix = 'Ctrl'

const usesWindowControlsOverlay = shouldUseApplicationTitlebarMenu(navigator.userAgent)

export default function ApplicationTitlebarMenu({
  onLockVault
}: ApplicationTitlebarMenuProps): React.JSX.Element | null {
  const { t } = useLingui()
  const execute = useCallback((command: ApplicationMenuCommand): void => {
    void window.bearwarden.applicationMenu.execute(command).catch(() => undefined)
  }, [])

  const requestLock = useCallback((): void => {
    void onLockVault?.()
  }, [onLockVault])

  if (!usesWindowControlsOverlay) return null

  const fileItems = (
    <MenubarGroup>
      <MenubarItem onClick={() => execute('close-window')}>
        {t`Close window`}
        <MenubarShortcut>{shortcutPrefix}+W</MenubarShortcut>
      </MenubarItem>
    </MenubarGroup>
  )
  const vaultItems = (
    <MenubarGroup>
      <MenubarItem disabled={!onLockVault} onClick={requestLock}>
        {t`Lock vault`}
        <MenubarShortcut>{shortcutPrefix}+L</MenubarShortcut>
      </MenubarItem>
    </MenubarGroup>
  )
  const itemItems = (
    <MenubarGroup>
      <MenubarItem onClick={() => execute('copy-selected-username')}>
        {t`Copy username`}
        <MenubarShortcut>{SELECTED_ITEM_COPY_SHORTCUTS.username.display}</MenubarShortcut>
      </MenubarItem>
      <MenubarItem onClick={() => execute('copy-selected-password')}>
        {t`Copy password`}
        <MenubarShortcut>{SELECTED_ITEM_COPY_SHORTCUTS.password.display}</MenubarShortcut>
      </MenubarItem>
      <MenubarItem onClick={() => execute('copy-selected-totp')}>
        {t`Copy verification code`}
        <MenubarShortcut>{SELECTED_ITEM_COPY_SHORTCUTS.totp.display}</MenubarShortcut>
      </MenubarItem>
      <MenubarItem onClick={() => execute('copy-selected-website')}>
        {t`Copy website`}
        <MenubarShortcut>{SELECTED_ITEM_COPY_SHORTCUTS.website.display}</MenubarShortcut>
      </MenubarItem>
    </MenubarGroup>
  )
  const editItems = (
    <>
      <MenubarGroup>
        <MenubarItem onClick={() => execute('undo')}>
          {t`Undo`}
          <MenubarShortcut>{shortcutPrefix}+Z</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('redo')}>
          {t`Redo`}
          <MenubarShortcut>{shortcutPrefix}+Shift+Z</MenubarShortcut>
        </MenubarItem>
      </MenubarGroup>
      <MenubarSeparator />
      <MenubarGroup>
        <MenubarItem onClick={() => execute('cut')}>
          {t`Cut`}
          <MenubarShortcut>{shortcutPrefix}+X</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('copy')}>
          {t`Copy`}
          <MenubarShortcut>{shortcutPrefix}+C</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('paste')}>
          {t`Paste`}
          <MenubarShortcut>{shortcutPrefix}+V</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('delete')}>{t`Delete`}</MenubarItem>
      </MenubarGroup>
      <MenubarSeparator />
      <MenubarGroup>
        <MenubarItem onClick={() => execute('select-all')}>
          {t`Select all`}
          <MenubarShortcut>{shortcutPrefix}+A</MenubarShortcut>
        </MenubarItem>
      </MenubarGroup>
    </>
  )
  const viewItems = (
    <MenubarGroup>
      <MenubarItem onClick={() => execute('toggle-full-screen')}>
        {t`Toggle full screen`}
        <MenubarShortcut>F11</MenubarShortcut>
      </MenubarItem>
      <MenubarItem onClick={() => execute('toggle-developer-tools')}>
        {t`Developer tools`}
      </MenubarItem>
    </MenubarGroup>
  )
  const windowItems = (
    <MenubarGroup>
      <MenubarItem onClick={() => execute('minimize-window')}>{t`Minimize`}</MenubarItem>
      <MenubarItem
        onClick={() => execute('toggle-maximize-window')}
      >{t`Maximize / Restore`}</MenubarItem>
      <MenubarItem onClick={() => execute('close-window')}>{t`Close`}</MenubarItem>
    </MenubarGroup>
  )

  return (
    <>
      <Menubar
        className="hidden h-auto border-0 bg-transparent p-0 shadow-none [-webkit-app-region:no-drag] min-[1051px]:flex"
        aria-label={t`Application menu`}
      >
        <MenubarMenu>
          <MenubarTrigger>{t`File`}</MenubarTrigger>
          <MenubarContent>{fileItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>{t`Vault`}</MenubarTrigger>
          <MenubarContent>{vaultItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>{t`Edit`}</MenubarTrigger>
          <MenubarContent>{editItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>{t`Item`}</MenubarTrigger>
          <MenubarContent>{itemItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>{t`View`}</MenubarTrigger>
          <MenubarContent>{viewItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>{t`Window`}</MenubarTrigger>
          <MenubarContent>{windowItems}</MenubarContent>
        </MenubarMenu>
      </Menubar>

      <Menubar
        className="h-auto border-0 bg-transparent p-0 shadow-none [-webkit-app-region:no-drag] min-[1051px]:hidden"
        aria-label={t`Application menu`}
      >
        <MenubarMenu>
          <MenubarTrigger>{t`Menu`}</MenubarTrigger>
          <MenubarContent>
            {fileItems}
            <MenubarSeparator />
            {vaultItems}
            <MenubarSeparator />
            {editItems}
            <MenubarSeparator />
            {itemItems}
            <MenubarSeparator />
            {viewItems}
            <MenubarSeparator />
            {windowItems}
          </MenubarContent>
        </MenubarMenu>
      </Menubar>
    </>
  )
}
