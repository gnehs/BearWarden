import { ContactRound, CreditCard, FileKey2, Globe2, KeyRound, NotebookPen } from 'lucide-react'
import type { VaultItemType } from '../../../shared/vault-contract'

export const itemTypeIcons: Record<VaultItemType, typeof KeyRound> = {
  login: KeyRound,
  card: CreditCard,
  identity: ContactRound,
  secureNote: NotebookPen,
  sshKey: FileKey2
}

export const itemListIcons: Record<VaultItemType, typeof KeyRound> = {
  ...itemTypeIcons,
  login: Globe2
}
