import { useLingui } from '@lingui/react/macro'
import type { KeyRound } from 'lucide-react'
import { useMemo } from 'react'
import type { VaultItemType } from '../../../shared/vault-contract'
import { itemTypeIcons } from '../components/vault-item-type-icons'

export interface ItemTypeMeta {
  label: string
  icon: typeof KeyRound
}

/** Translated label and icon for each vault item type. */
export function useItemTypeMeta(): Record<VaultItemType, ItemTypeMeta> {
  const { t } = useLingui()
  return useMemo<Record<VaultItemType, ItemTypeMeta>>(
    () => ({
      login: { label: t`Login`, icon: itemTypeIcons.login },
      card: {
        label: t({
          message: 'Card',
          comment: 'Vault item category label for payment card records.'
        }),
        icon: itemTypeIcons.card
      },
      identity: { label: t`Identity`, icon: itemTypeIcons.identity },
      secureNote: { label: t`Secure note`, icon: itemTypeIcons.secureNote },
      sshKey: { label: t`SSH key`, icon: itemTypeIcons.sshKey }
    }),
    [t]
  )
}
