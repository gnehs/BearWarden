import type { VaultEditorSecretField, VaultItemType } from '../../../shared/vault-contract'

export type SshKeyGenerationState = 'idle' | 'generating' | 'ready' | 'error'
export type SshKeyMaterialState = 'blank' | 'complete' | 'partial'
export type SshKeyGenerationAction = 'wait' | 'generate' | 'ready' | 'error'

interface SshKeyMaterial {
  privateKey: string
  publicKey: string
  fingerprint: string
}

export function sshKeyMaterialState(material: SshKeyMaterial): SshKeyMaterialState {
  const values = [material.privateKey, material.publicKey, material.fingerprint]
  if (values.every((value) => !value.trim())) return 'blank'
  return values.every((value) => value.trim()) ? 'complete' : 'partial'
}

export function sshKeyGenerationAction(
  secretsReady: boolean,
  type: VaultItemType,
  state: SshKeyGenerationState,
  material: SshKeyMaterial
): SshKeyGenerationAction {
  if (!secretsReady || type !== 'sshKey' || state !== 'idle') return 'wait'

  const materialState = sshKeyMaterialState(material)
  if (materialState === 'blank') return 'generate'
  return materialState === 'complete' ? 'ready' : 'error'
}

export function clearSshKeyMaterial<
  T extends SshKeyMaterial & { changedSecrets: VaultEditorSecretField[] }
>(draft: T): T {
  return {
    ...draft,
    privateKey: '',
    publicKey: '',
    fingerprint: '',
    changedSecrets: draft.changedSecrets.filter((field) => field !== 'privateKey')
  }
}

export function canApplyGeneratedSshKey(
  requestId: number,
  currentRequestId: number,
  draft: SshKeyMaterial & { type: VaultItemType }
): boolean {
  return (
    requestId === currentRequestId &&
    draft.type === 'sshKey' &&
    sshKeyMaterialState(draft) === 'blank'
  )
}

export function canFinalizeGeneratedSshKey(
  requestId: number,
  currentRequestId: number,
  draft: SshKeyMaterial & { type: VaultItemType }
): boolean {
  return (
    requestId === currentRequestId &&
    draft.type === 'sshKey' &&
    sshKeyMaterialState(draft) === 'complete'
  )
}

export function applyGeneratedSshKey<
  T extends SshKeyMaterial & {
    type: VaultItemType
    changedSecrets: VaultEditorSecretField[]
  }
>(requestId: number, currentRequestId: number, draft: T, generated: SshKeyMaterial): T {
  if (!canApplyGeneratedSshKey(requestId, currentRequestId, draft)) return draft

  return {
    ...draft,
    ...generated,
    changedSecrets: draft.changedSecrets.includes('privateKey')
      ? draft.changedSecrets
      : [...draft.changedSecrets, 'privateKey']
  }
}

export function isSshKeyGenerationBlockingSave(
  type: VaultItemType,
  state: SshKeyGenerationState
): boolean {
  return type === 'sshKey' && state !== 'ready'
}
