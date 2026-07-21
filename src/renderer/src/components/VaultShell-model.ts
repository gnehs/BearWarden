import type {
  LoginAuthorization,
  SyncStatus,
  TotpCodeView,
  VaultCustomFieldSource,
  VaultSecretField
} from '../../../shared/vault-contract'
import type { VaultCategoryFilter } from '../lib/vault-category'

export type Scope =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'recent' }
  | { kind: 'folder'; folderId: string }
  | { kind: 'unfiled' }
  | { kind: 'archive' }
  | { kind: 'trash' }

export type TypeFilter = VaultCategoryFilter

export const initialSyncStatus: SyncStatus = { configured: false, state: 'unconfigured' }
export const totpListCountdownPeriodSeconds = 30

export interface RevealedSecretsState {
  itemId: string | null
  values: Partial<Record<VaultSecretField, string>>
}

export const emptyRevealedSecrets: RevealedSecretsState = { itemId: null, values: {} }

export interface TotpGenerationErrorState {
  itemId: string
  kind: 'unsupported'
}

export type TotpListEntry = { code: TotpCodeView; expiresAt: number } | null

export interface RevealedCustomFieldsState {
  itemId: string | null
  values: Record<
    number,
    { value: string; source: VaultCustomFieldSource; expectedUpdatedAt: string }
  >
}

export const emptyRevealedCustomFields: RevealedCustomFieldsState = { itemId: null, values: {} }

export interface RepromptPromptState {
  itemName: string
}

export interface PendingReprompt {
  key: string
  ids: string[]
  promise: Promise<LoginAuthorization>
  resolve: (authorization: LoginAuthorization) => void
  reject: (error: Error) => void
}

export type BulkSelectionState = 'active' | 'archive' | 'trash'
export type BulkActionKind = 'archive' | 'unarchive' | 'delete' | 'restore' | 'deletePermanently'

export interface BulkActionSnapshot {
  action: BulkActionKind
  ids: string[]
  state: BulkSelectionState
}

export interface MoveSnapshot {
  ids: string[]
  state: Exclude<BulkSelectionState, 'trash'>
}
