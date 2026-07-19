import { useCallback } from 'react'
import type { ApplicationMenuCommand } from '../../../shared/vault-contract'
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
        關閉視窗
        <MenubarShortcut>{shortcutPrefix}+W</MenubarShortcut>
      </MenubarItem>
    </MenubarGroup>
  )
  const vaultItems = (
    <MenubarGroup>
      <MenubarItem disabled={!onLockVault} onClick={requestLock}>
        鎖定密碼庫
        <MenubarShortcut>{shortcutPrefix}+L</MenubarShortcut>
      </MenubarItem>
    </MenubarGroup>
  )
  const editItems = (
    <>
      <MenubarGroup>
        <MenubarItem onClick={() => execute('undo')}>
          復原
          <MenubarShortcut>{shortcutPrefix}+Z</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('redo')}>
          重做
          <MenubarShortcut>{shortcutPrefix}+Shift+Z</MenubarShortcut>
        </MenubarItem>
      </MenubarGroup>
      <MenubarSeparator />
      <MenubarGroup>
        <MenubarItem onClick={() => execute('cut')}>
          剪下
          <MenubarShortcut>{shortcutPrefix}+X</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('copy')}>
          複製
          <MenubarShortcut>{shortcutPrefix}+C</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('paste')}>
          貼上
          <MenubarShortcut>{shortcutPrefix}+V</MenubarShortcut>
        </MenubarItem>
        <MenubarItem onClick={() => execute('delete')}>刪除</MenubarItem>
      </MenubarGroup>
      <MenubarSeparator />
      <MenubarGroup>
        <MenubarItem onClick={() => execute('select-all')}>
          全選
          <MenubarShortcut>{shortcutPrefix}+A</MenubarShortcut>
        </MenubarItem>
      </MenubarGroup>
    </>
  )
  const viewItems = (
    <MenubarGroup>
      <MenubarItem onClick={() => execute('toggle-full-screen')}>
        切換全螢幕
        <MenubarShortcut>F11</MenubarShortcut>
      </MenubarItem>
    </MenubarGroup>
  )
  const windowItems = (
    <MenubarGroup>
      <MenubarItem onClick={() => execute('minimize-window')}>最小化</MenubarItem>
      <MenubarItem onClick={() => execute('toggle-maximize-window')}>最大化／還原</MenubarItem>
      <MenubarItem onClick={() => execute('close-window')}>關閉</MenubarItem>
    </MenubarGroup>
  )

  return (
    <>
      <Menubar
        className="hidden h-auto border-0 bg-transparent p-0 shadow-none [-webkit-app-region:no-drag] min-[1051px]:flex"
        aria-label="應用程式選單"
      >
        <MenubarMenu>
          <MenubarTrigger>檔案</MenubarTrigger>
          <MenubarContent>{fileItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>密碼庫</MenubarTrigger>
          <MenubarContent>{vaultItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>編輯</MenubarTrigger>
          <MenubarContent>{editItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>顯示方式</MenubarTrigger>
          <MenubarContent>{viewItems}</MenubarContent>
        </MenubarMenu>
        <MenubarMenu>
          <MenubarTrigger>視窗</MenubarTrigger>
          <MenubarContent>{windowItems}</MenubarContent>
        </MenubarMenu>
      </Menubar>

      <Menubar
        className="h-auto border-0 bg-transparent p-0 shadow-none [-webkit-app-region:no-drag] min-[1051px]:hidden"
        aria-label="應用程式選單"
      >
        <MenubarMenu>
          <MenubarTrigger>選單</MenubarTrigger>
          <MenubarContent>
            {fileItems}
            <MenubarSeparator />
            {vaultItems}
            <MenubarSeparator />
            {editItems}
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
