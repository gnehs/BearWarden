import { i18n } from '@lingui/core'
import { msg } from '@lingui/core/macro'
import type {
  LoginCreateRequest,
  LoginUpdateRequest,
  LoginView,
  SshKeyCreateImportedRequest,
  SshKeyGenerationResult,
  SshKeyImportResult,
  SshKeyUpdateImportedRequest,
  VaultEditorSecretField,
  VaultItemType
} from '../../../shared/vault-contract'

export type SshKeyGenerationState = 'idle' | 'generating' | 'ready' | 'error'
export type SshKeyMaterialState = 'blank' | 'complete' | 'partial'
export type SshKeyGenerationAction = 'wait' | 'generate' | 'ready' | 'error'
export type SshKeyImportState =
  'idle' | 'reading' | 'awaitingPassphrase' | 'submittingPassphrase' | 'ready'
export type SshKeyImportResultAction = 'awaitPassphrase' | 'ready' | 'retryPassphrase' | 'fail'

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

export function applyImportedSshKey<
  T extends SshKeyMaterial & {
    type: VaultItemType
    changedSecrets: VaultEditorSecretField[]
    sshImportToken?: string
  }
>(
  requestId: number,
  currentRequestId: number,
  draft: T,
  result: Extract<SshKeyImportResult, { status: 'ready' }>
): T {
  if (requestId !== currentRequestId || draft.type !== 'sshKey') return draft

  return {
    ...draft,
    privateKey: '',
    publicKey: result.publicKey,
    fingerprint: result.fingerprint,
    sshImportToken: result.token,
    changedSecrets: draft.changedSecrets.filter((field) => field !== 'privateKey')
  }
}

export function invalidateFailedSshImport<
  T extends SshKeyMaterial & {
    changedSecrets: VaultEditorSecretField[]
    sshImportToken?: string
  }
>(draft: T, failedToken: string): T {
  if (draft.sshImportToken !== failedToken) return draft
  return { ...clearSshKeyMaterial(draft), sshImportToken: undefined }
}

export function sshKeyImportErrorMessage(
  code: Extract<SshKeyImportResult, { status: 'error' }>['code']
): string {
  const messages = {
    EmptyClipboard: msg`The clipboard is empty. Copy an SSH private key and try again.`,
    ClipboardTooLarge: msg`The clipboard contents are too large to safely import as an SSH private key.`,
    ParsingError: msg`The SSH private key in the clipboard could not be parsed. Verify that its contents are complete.`,
    UnsupportedKeyType: msg`This SSH private key type is not supported. Use a supported key format.`,
    WrongPassword: msg`The private key passphrase is incorrect. Enter it again.`,
    InvalidPassphrase: msg`Enter a valid private key passphrase.`,
    SessionUnavailable: msg`The SSH private key import session has expired. Import it from the clipboard again.`,
    SessionLimitReached: msg`Too many SSH private key import sessions are in progress. Try again later.`
  } satisfies Record<
    Extract<SshKeyImportResult, { status: 'error' }>['code'],
    ReturnType<typeof msg>
  >

  return i18n._(messages[code])
}

export function sshKeyImportResultAction(result: SshKeyImportResult): SshKeyImportResultAction {
  if (result.status === 'awaitingPassphrase') return 'awaitPassphrase'
  if (result.status === 'ready') return 'ready'
  return result.code === 'WrongPassword' || result.code === 'InvalidPassphrase'
    ? 'retryPassphrase'
    : 'fail'
}

export function isValidSshImportPassphrase(passphrase: string): boolean {
  if (!passphrase) return false
  const encoded = new TextEncoder().encode(passphrase)
  const valid = encoded.byteLength <= 1_024
  encoded.fill(0)
  return valid
}

interface LoginCreateOperations {
  create: (request: LoginCreateRequest) => Promise<LoginView>
  createImported: (request: SshKeyCreateImportedRequest) => Promise<LoginView>
}

interface LoginUpdateOperations {
  update: (request: LoginUpdateRequest) => Promise<LoginView>
  updateImported: (request: SshKeyUpdateImportedRequest) => Promise<LoginView>
}

export function createLoginWithOptionalSshImport(
  request: LoginCreateRequest,
  importToken: string | undefined,
  operations: LoginCreateOperations
): Promise<LoginView> {
  if (!importToken) return operations.create(request)

  const rendererSafeRequest = { ...request }
  delete rendererSafeRequest.privateKey
  return operations.createImported({ ...rendererSafeRequest, importToken })
}

export function updateLoginWithOptionalSshImport(
  request: LoginUpdateRequest,
  importToken: string | undefined,
  operations: LoginUpdateOperations
): Promise<LoginView> {
  if (!importToken) return operations.update(request)

  const rendererSafeRequest = { ...request }
  delete rendererSafeRequest.privateKey
  return operations.updateImported({ ...rendererSafeRequest, importToken })
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

export function applyGeneratedSshKey<
  T extends SshKeyMaterial & {
    type: VaultItemType
    changedSecrets: VaultEditorSecretField[]
    sshImportToken?: string
  }
>(
  requestId: number,
  currentRequestId: number,
  draft: T,
  generated: Extract<SshKeyGenerationResult, { status: 'ready' }>
): T {
  if (!canApplyGeneratedSshKey(requestId, currentRequestId, draft)) return draft

  return {
    ...draft,
    privateKey: '',
    publicKey: generated.publicKey,
    fingerprint: generated.fingerprint,
    sshImportToken: generated.token,
    changedSecrets: draft.changedSecrets.filter((field) => field !== 'privateKey')
  }
}

export function isSshKeyGenerationBlockingSave(
  type: VaultItemType,
  state: SshKeyGenerationState,
  importToken?: string
): boolean {
  return type === 'sshKey' && !importToken && state !== 'ready'
}
