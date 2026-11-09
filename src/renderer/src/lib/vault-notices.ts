import { toast } from 'sonner'

export const vaultErrorToastId = 'vault-error'

export function announce(message: string): void {
  toast.success(message)
}

/** Vault errors share one toast id, so a newer error replaces the previous one. */
export function announceError(message: string): void {
  toast.error(message, {
    id: vaultErrorToastId,
    duration: 7_000
  })
}
