import { useEffect, useEffectEvent } from 'react'
import {
  SELECTED_ITEM_COPY_SHORTCUTS,
  type SelectedItemCopyCommand
} from '../../../shared/selected-item-shortcuts'
import type { LoginSummary, VaultCopyField } from '../../../shared/vault-contract'
import type { SelectedVaultLogin, VaultEditorMode } from '@renderer/stores/vault-session-store'

export interface VaultShortcutsOptions {
  auxiliaryPageOpen: boolean
  editorMode: VaultEditorMode
  searchOpen: boolean
  busy: boolean
  canCreate: boolean
  selectedLogin: SelectedVaultLogin | null
  selectedSummary: LoginSummary | null
  copyField: (field: VaultCopyField, uriIndex?: number) => Promise<void>
  copyTotp: () => Promise<void>
  selectAll: () => void
  openSearch: () => void
  openEditor: (mode: 'create' | 'edit') => void
  openMoveDialog: () => void
}

function isEditableShortcutTarget(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLElement &&
    target.matches('input, textarea, select, [contenteditable="true"]')
  )
}

/**
 * Keyboard shortcuts for the vault list and detail, plus the application menu's copy
 * commands. Both read the latest options, so the listeners are registered once per mount.
 */
export function useVaultShortcuts({
  auxiliaryPageOpen,
  editorMode,
  searchOpen,
  busy,
  canCreate,
  selectedLogin,
  selectedSummary,
  copyField,
  copyTotp,
  selectAll,
  openSearch,
  openEditor,
  openMoveDialog
}: VaultShortcutsOptions): void {
  const copySelectedItem = useEffectEvent((command: SelectedItemCopyCommand): boolean => {
    if (
      editorMode ||
      searchOpen ||
      auxiliaryPageOpen ||
      !selectedLogin ||
      selectedLogin.deletedAt
    ) {
      return false
    }
    if (command === 'username' && selectedLogin.type === 'login' && selectedLogin.username) {
      void copyField('username')
      return true
    }
    if (command === 'password' && selectedLogin.type === 'login') {
      void copyField('password')
      return true
    }
    if (command === 'totp' && selectedLogin.type === 'login' && selectedLogin.hasTotp) {
      void copyTotp()
      return true
    }
    if (command === 'website' && selectedLogin.uris.length > 0) {
      void copyField('uri', 0)
      return true
    }
    return false
  })

  const handleShortcut = useEffectEvent((event: KeyboardEvent): void => {
    const command = event.metaKey || event.ctrlKey
    if (!command) return
    const key = event.key.toLocaleLowerCase()

    if (!isEditableShortcutTarget(event.target)) {
      const copyCommand = Object.entries(SELECTED_ITEM_COPY_SHORTCUTS).find(
        ([, shortcut]) => shortcut.key === key && shortcut.shiftKey === event.shiftKey
      )?.[0] as SelectedItemCopyCommand | undefined
      if (copyCommand && copySelectedItem(copyCommand)) {
        event.preventDefault()
        return
      }
    }

    if (auxiliaryPageOpen) return
    if (key === 'a' && !editorMode && !searchOpen && !isEditableShortcutTarget(event.target)) {
      event.preventDefault()
      selectAll()
    }
    if (key === 'f') {
      event.preventDefault()
      openSearch()
    }
    if (key === 'n' && !editorMode && canCreate) {
      event.preventDefault()
      openEditor('create')
    }
    if (key === 'e' && selectedLogin && !selectedLogin.deletedAt && !editorMode) {
      event.preventDefault()
      openEditor('edit')
    }
    if (key === 's' && editorMode && !busy) {
      event.preventDefault()
      document.querySelector<HTMLFormElement>('form[data-vault-editor]')?.requestSubmit()
    }
    if (key === 'm' && event.shiftKey && selectedSummary && !selectedSummary.deletedAt) {
      event.preventDefault()
      openMoveDialog()
    }
  })

  useEffect(() => {
    const unsubscribeCopySelectedItem = window.bearwarden.applicationMenu.onCopySelectedItem(
      (command) => copySelectedItem(command)
    )
    const onKeyDown = (event: KeyboardEvent): void => handleShortcut(event)
    window.addEventListener('keydown', onKeyDown)
    return () => {
      unsubscribeCopySelectedItem()
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [])
}
