export type SelectedItemCopyCommand = 'username' | 'password' | 'totp' | 'website'

export interface SelectedItemCopyShortcut {
  accelerator: string
  display: string
  key: string
  shiftKey: boolean
}

export const SELECTED_ITEM_COPY_SHORTCUTS = {
  username: {
    accelerator: 'CommandOrControl+U',
    display: 'Ctrl+U',
    key: 'u',
    shiftKey: false
  },
  password: {
    accelerator: 'CommandOrControl+P',
    display: 'Ctrl+P',
    key: 'p',
    shiftKey: false
  },
  totp: {
    accelerator: 'CommandOrControl+T',
    display: 'Ctrl+T',
    key: 't',
    shiftKey: false
  },
  // CommandOrControl+W is the close-window shortcut, so website keeps Shift.
  website: {
    accelerator: 'CommandOrControl+Shift+W',
    display: 'Ctrl+Shift+W',
    key: 'w',
    shiftKey: true
  }
} as const satisfies Record<SelectedItemCopyCommand, SelectedItemCopyShortcut>
