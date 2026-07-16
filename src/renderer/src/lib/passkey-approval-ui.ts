import type {
  PasskeyApprovalPrompt,
  PasskeyVerificationMethod
} from '../../../shared/vault-contract'

export type PasskeyApprovalUiVerificationMethod = Exclude<PasskeyVerificationMethod, 'none'>

const MAX_MASTER_PASSWORD_LENGTH = 1_024

export interface PasskeyApprovalUiSelection {
  selectedChoiceId?: string
  verificationMethod?: PasskeyApprovalUiVerificationMethod
  masterPassword: string
}

export function isPasskeyApprovalExpired(
  request: Pick<PasskeyApprovalPrompt, 'expiresAt'>,
  now = Date.now()
): boolean {
  return request.expiresAt <= now
}

export function initialPasskeyApprovalChoice(
  request: Pick<PasskeyApprovalPrompt, 'choices'>
): string | undefined {
  return request.choices.length === 1 ? request.choices[0]?.id : undefined
}

/** Prefer the platform verifier when it is available; it keeps passwords out of the renderer. */
export function initialPasskeyApprovalVerificationMethod(
  request: Pick<PasskeyApprovalPrompt, 'userVerification' | 'verificationMethods'>
): PasskeyApprovalUiVerificationMethod | undefined {
  if (request.userVerification === 'discouraged') return undefined
  if (request.verificationMethods.includes('touch-id')) return 'touch-id'
  if (request.verificationMethods.includes('master-password')) return 'master-password'
  return undefined
}

export function hasPasskeyApprovalChoice(
  request: Pick<PasskeyApprovalPrompt, 'choices'>,
  selectedChoiceId: string | undefined
): boolean {
  return (
    selectedChoiceId !== undefined &&
    request.choices.some((choice) => choice.id === selectedChoiceId)
  )
}

export function selectedPasskeyApprovalChoiceRequiresReprompt(
  request: Pick<PasskeyApprovalPrompt, 'choices'>,
  selectedChoiceId: string | undefined
): boolean {
  return request.choices.some((choice) => choice.id === selectedChoiceId && choice.requiresReprompt)
}

/**
 * A reprompt is a vault policy check, not WebAuthn user verification. They can both apply to
 * the same request, including when WebAuthn user verification is discouraged.
 */
export function requiresPasskeyApprovalPasswordVerification(
  request: Pick<PasskeyApprovalPrompt, 'choices' | 'userVerification'>,
  selectedChoiceId: string | undefined,
  verificationMethod: PasskeyApprovalUiVerificationMethod | undefined
): boolean {
  return (
    selectedPasskeyApprovalChoiceRequiresReprompt(request, selectedChoiceId) ||
    (request.userVerification !== 'discouraged' && verificationMethod === 'master-password')
  )
}

/** The response must never represent discouraged user verification as a successful UV proof. */
export function passkeyApprovalResponseVerificationMethod(
  request: Pick<PasskeyApprovalPrompt, 'userVerification'>,
  verificationMethod: PasskeyApprovalUiVerificationMethod | undefined
): PasskeyVerificationMethod | undefined {
  return request.userVerification === 'discouraged' ? 'none' : verificationMethod
}

export function canApprovePasskeyApproval(
  request: Pick<
    PasskeyApprovalPrompt,
    'choices' | 'expiresAt' | 'userVerification' | 'verificationMethods'
  >,
  selection: PasskeyApprovalUiSelection,
  now = Date.now()
): boolean {
  if (isPasskeyApprovalExpired(request, now)) return false
  if (!hasPasskeyApprovalChoice(request, selection.selectedChoiceId)) return false

  if (
    request.userVerification !== 'discouraged' &&
    (selection.verificationMethod === undefined ||
      !request.verificationMethods.includes(selection.verificationMethod))
  ) {
    return false
  }

  return (
    !requiresPasskeyApprovalPasswordVerification(
      request,
      selection.selectedChoiceId,
      selection.verificationMethod
    ) ||
    (selection.masterPassword.length > 0 &&
      selection.masterPassword.length <= MAX_MASTER_PASSWORD_LENGTH)
  )
}

export function formatPasskeyApprovalExpiry(expiresAt: number, now = Date.now()): string {
  const remainingSeconds = Math.max(0, Math.ceil((expiresAt - now) / 1_000))
  return remainingSeconds > 0 ? `此要求將在約 ${remainingSeconds} 秒後過期。` : '此要求已過期。'
}
