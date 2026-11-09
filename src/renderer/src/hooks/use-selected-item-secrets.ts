import { useLingui } from '@lingui/react/macro'
import { useCallback, useEffect, useRef, useState, type RefObject } from 'react'
import { useShallow } from 'zustand/react/shallow'
import type {
  VaultPasswordHistoryView,
  PasswordHistoryEntryRequest,
  VaultCopyField,
  VaultCustomFieldSource,
  VaultCustomFieldView,
  VaultSecretField
} from '../../../shared/vault-contract'
import { isSharedLoginSummary } from '../components/organizations-ui'
import { canRevealSecretsOnHover } from '../components/VaultDetailFieldRows-model'
import { authorizationTokenField } from '../components/vault-detail-cache'
import {
  customFieldCopyFeedbackKey,
  detailFieldCopyFeedbackKey,
  matchesCustomFieldSource
} from '../components/vault-detail-view-model'
import { tracksItemUsage, type VaultItemAccess } from '../components/vault-item-access'
import {
  emptyRevealedCustomFields,
  emptyRevealedSecrets,
  type RevealedCustomFieldsState,
  type RevealedSecretsState
} from '../components/VaultShell-model'
import { useCopyFeedback } from './use-copy-feedback'
import { useDescribeVaultError } from './use-describe-vault-error'
import { announce, announceError } from '@renderer/lib/vault-notices'
import type { VaultAuthorization } from '@renderer/stores/vault-authorization-store'
import type { VaultDataSync } from '@renderer/stores/vault-data-sync'
import {
  findVaultItem,
  useVaultSessionStore,
  useVaultSessionStoreApi
} from '@renderer/stores/vault-session-store'

type PasswordHistoryLocator = Omit<PasswordHistoryEntryRequest, 'id' | 'authorizationToken'>

export interface SelectedItemSecrets {
  copiedKey: string | null
  revealedSecrets: RevealedSecretsState
  revealedCustomFields: RevealedCustomFieldsState
  resetReveals: () => void
  resetRevealedCustomFields: () => void
  hoveringSecretFieldsRef: RefObject<Set<VaultSecretField>>
  hoverRevealedSecretFieldsRef: RefObject<Set<VaultSecretField>>
  passwordZoomOpenRef: RefObject<boolean>
  passwordZoomValue: string | null
  revealSecret: (
    field: VaultSecretField,
    options?: { quiet?: boolean; forceShow?: boolean }
  ) => Promise<string | undefined>
  hideRevealedSecret: (field: VaultSecretField) => void
  openPasswordZoom: () => Promise<void>
  closePasswordZoom: () => void
  copyField: (field: VaultCopyField, uriIndex?: number) => Promise<void>
  revealCustomField: (index: number, field: VaultCustomFieldView) => Promise<void>
  copyCustomField: (index: number, field: VaultCustomFieldView) => Promise<void>
  copyTotp: () => Promise<void>
  openWebsite: (uriIndex?: number) => Promise<void>
  showLoginContextMenu: (id: string, position: { x: number; y: number }) => void
  loadPasswordHistory: () => Promise<VaultPasswordHistoryView>
  revealPasswordHistory: (locator: PasswordHistoryLocator) => Promise<string>
  copyPasswordHistory: (locator: PasswordHistoryLocator) => Promise<void>
}

/**
 * Revealing, copying and opening the selected item's secrets. Revealed values hide again
 * after 30 seconds, and each action goes through the item's owning IPC namespace.
 */
export function useSelectedItemSecrets(
  authorization: VaultAuthorization,
  itemAccess: VaultItemAccess,
  vaultData: Pick<VaultDataSync, 'refreshItems'>
): SelectedItemSecrets {
  const { t } = useLingui()
  const describeVaultError = useDescribeVaultError()
  const session = useVaultSessionStoreApi()
  const logins = window.bearwarden.logins
  const { copiedKey, clearCopied, showCopied } = useCopyFeedback()
  const { selectedSummary, selectedLogin } = useVaultSessionStore(
    useShallow((state) => ({
      selectedSummary: state.selectedId ? (findVaultItem(state, state.selectedId) ?? null) : null,
      selectedLogin: state.selectedLogin
    }))
  )
  const selectedSharedSummary =
    selectedSummary && isSharedLoginSummary(selectedSummary) ? selectedSummary : null
  const [revealedSecrets, setRevealedSecrets] = useState<RevealedSecretsState>(emptyRevealedSecrets)
  const [revealedCustomFields, setRevealedCustomFields] =
    useState<RevealedCustomFieldsState>(emptyRevealedCustomFields)
  const [passwordZoom, setPasswordZoom] = useState<{ itemId: string; value: string } | null>(null)
  if (passwordZoom !== null && passwordZoom.itemId !== selectedLogin?.id) {
    setPasswordZoom(null)
  }
  const passwordZoomValue =
    passwordZoom !== null && passwordZoom.itemId === selectedLogin?.id ? passwordZoom.value : null
  const hoveringSecretFieldsRef = useRef(new Set<VaultSecretField>())
  const hoverRevealedSecretFieldsRef = useRef(new Set<VaultSecretField>())
  const passwordZoomOpenRef = useRef(false)

  const showLoginContextMenu = useCallback(
    (id: string, position: { x: number; y: number }): void => {
      void authorization
        .withReprompt([id], (tokenFor) =>
          logins.showContextMenu({
            id,
            ...position,
            hasTotp: session.getState().items.find((item) => item.id === id)?.hasTotp ?? false,
            ...authorizationTokenField(tokenFor(id))
          })
        )
        .catch((menuError) => announceError(describeVaultError(menuError)))
    },
    [authorization, describeVaultError, logins, session]
  )

  const loadPasswordHistory = useCallback(async () => {
    const summary = selectedSummary
    if (!summary || summary.passwordHistoryCount === 0) throw new Error('INVALID_INPUT')
    const itemId = summary.id
    return authorization.withReprompt(
      [itemId],
      (tokenFor) =>
        logins.getPasswordHistory({
          id: itemId,
          ...authorizationTokenField(tokenFor(itemId))
        }),
      true
    )
  }, [authorization, logins, selectedSummary])

  const revealPasswordHistory = useCallback(
    async (
      locator: Omit<PasswordHistoryEntryRequest, 'id' | 'authorizationToken'>
    ): Promise<string> => {
      const summary = selectedSummary
      if (!summary) throw new Error('INVALID_INPUT')
      const itemId = summary.id
      return authorization.withReprompt(
        [itemId],
        (tokenFor) =>
          logins.revealPasswordHistory({
            id: itemId,
            ...locator,
            ...authorizationTokenField(tokenFor(itemId))
          }),
        true
      )
    },
    [authorization, logins, selectedSummary]
  )

  const copyPasswordHistory = useCallback(
    async (
      locator: Omit<PasswordHistoryEntryRequest, 'id' | 'authorizationToken'>
    ): Promise<void> => {
      const summary = selectedSummary
      if (!summary) throw new Error('INVALID_INPUT')
      const itemId = summary.id
      await authorization.withReprompt(
        [itemId],
        (tokenFor) =>
          logins.copyPasswordHistory({
            id: itemId,
            ...locator,
            ...authorizationTokenField(tokenFor(itemId))
          }),
        true
      )
    },
    [authorization, logins, selectedSummary]
  )

  useEffect(() => {
    if (Object.keys(revealedSecrets.values).length === 0) return
    const timeout = window.setTimeout(() => setRevealedSecrets(emptyRevealedSecrets), 30_000)
    return () => window.clearTimeout(timeout)
  }, [revealedSecrets])

  useEffect(() => {
    hoveringSecretFieldsRef.current.clear()
    hoverRevealedSecretFieldsRef.current.clear()
    passwordZoomOpenRef.current = false
  }, [selectedLogin?.id])

  useEffect(() => {
    if (Object.keys(revealedCustomFields.values).length === 0) return
    const timeout = window.setTimeout(
      () => setRevealedCustomFields(emptyRevealedCustomFields),
      30_000
    )
    return () => window.clearTimeout(timeout)
  }, [revealedCustomFields])

  async function revealSecret(
    field: VaultSecretField,
    options: { quiet?: boolean; forceShow?: boolean } = {}
  ): Promise<string | undefined> {
    if (!selectedSummary) return undefined
    if (selectedSharedSummary && !canRevealSecretsOnHover(selectedSharedSummary)) return undefined
    const itemId = selectedSummary.id
    const revealedValue =
      revealedSecrets.itemId === itemId ? revealedSecrets.values[field] : undefined
    if (revealedValue !== undefined) {
      if (options.forceShow) return revealedValue
      setRevealedSecrets((current) => {
        if (current.itemId !== itemId) return current
        const next = { ...current.values }
        delete next[field]
        return Object.keys(next).length ? { itemId, values: next } : emptyRevealedSecrets
      })
      return undefined
    }
    try {
      const value = await itemAccess.revealSecret(selectedSummary, field)
      if (session.getState().selectedId !== itemId) return undefined
      if (
        options.quiet &&
        !hoveringSecretFieldsRef.current.has(field) &&
        !(field === 'password' && passwordZoomOpenRef.current)
      ) {
        return value
      }
      setRevealedSecrets((current) => ({
        itemId,
        values: {
          ...(current.itemId === itemId ? current.values : {}),
          [field]: value
        }
      }))
      if (!options.quiet) {
        const revealedLabel = field === 'privateKey' ? t`Private key` : t`Sensitive data`
        announce(t`${revealedLabel} is visible and will be hidden automatically in 30 seconds.`)
      }
      return value
    } catch (revealError) {
      announceError(describeVaultError(revealError))
      return undefined
    }
  }

  function hideRevealedSecret(field: VaultSecretField): void {
    if (!selectedSummary) return
    const itemId = selectedSummary.id
    setRevealedSecrets((current) => {
      if (current.itemId !== itemId || current.values[field] === undefined) return current
      const next = { ...current.values }
      delete next[field]
      return Object.keys(next).length ? { itemId, values: next } : emptyRevealedSecrets
    })
  }

  async function openPasswordZoom(): Promise<void> {
    if (!selectedSummary) return
    const itemId = selectedSummary.id
    passwordZoomOpenRef.current = true
    const value = await revealSecret('password', { quiet: true, forceShow: true })
    if (value === undefined) {
      passwordZoomOpenRef.current = false
      return
    }
    setPasswordZoom({ itemId, value })
  }

  function closePasswordZoom(): void {
    passwordZoomOpenRef.current = false
    setPasswordZoom(null)
    if (!hoveringSecretFieldsRef.current.has('password')) {
      hoverRevealedSecretFieldsRef.current.delete('password')
      hideRevealedSecret('password')
    }
  }

  async function copyField(field: VaultCopyField, uriIndex?: number): Promise<void> {
    if (!selectedSummary) return
    clearCopied()
    try {
      await itemAccess.copyField(selectedSummary, field, uriIndex)
      showCopied(detailFieldCopyFeedbackKey(selectedSummary.id, field, uriIndex))
      if (tracksItemUsage(selectedSummary)) await vaultData.refreshItems()
    } catch (copyError) {
      announceError(describeVaultError(copyError))
    }
  }

  async function revealCustomField(index: number, field: VaultCustomFieldView): Promise<void> {
    if (!selectedLogin || !selectedSummary) return
    const itemId = selectedLogin.id
    const revealedEntry =
      revealedCustomFields.itemId === itemId ? revealedCustomFields.values[index] : undefined
    if (
      revealedEntry &&
      revealedEntry.expectedUpdatedAt === selectedLogin.updatedAt &&
      matchesCustomFieldSource(field, index, revealedEntry.source)
    ) {
      setRevealedCustomFields((current) => {
        if (current.itemId !== itemId) return current
        const next = { ...current.values }
        delete next[index]
        return Object.keys(next).length ? { itemId, values: next } : emptyRevealedCustomFields
      })
      return
    }
    try {
      const expectedUpdatedAt = selectedLogin.updatedAt
      const source: VaultCustomFieldSource = {
        index,
        name: field.name,
        type: field.type,
        linkedId: field.linkedId
      }
      const value = await itemAccess.revealCustomField(selectedSummary, {
        expectedUpdatedAt,
        source
      })
      if (session.getState().selectedId !== itemId) return
      setRevealedCustomFields((current) => ({
        itemId,
        values: {
          ...(current.itemId === itemId ? current.values : {}),
          [index]: { value, source, expectedUpdatedAt }
        }
      }))
      announce(t`The hidden field is visible and will be hidden automatically in 30 seconds.`)
    } catch (revealError) {
      announceError(describeVaultError(revealError))
    }
  }

  async function copyCustomField(index: number, field: VaultCustomFieldView): Promise<void> {
    if (!selectedLogin || !selectedSummary) return
    clearCopied()
    try {
      await itemAccess.copyCustomField(selectedSummary, {
        expectedUpdatedAt: selectedLogin.updatedAt,
        source: { index, name: field.name, type: field.type, linkedId: field.linkedId }
      })
      showCopied(customFieldCopyFeedbackKey(selectedLogin.id, index, field))
      if (tracksItemUsage(selectedSummary)) await vaultData.refreshItems()
    } catch (copyError) {
      announceError(describeVaultError(copyError))
    }
  }

  async function copyTotp(): Promise<void> {
    if (!selectedLogin?.hasTotp || !selectedSummary) return
    clearCopied()
    try {
      await itemAccess.copyTotp(selectedSummary)
      showCopied(`totp:${selectedLogin.id}`)
      if (tracksItemUsage(selectedSummary)) await vaultData.refreshItems()
    } catch (copyError) {
      announceError(describeVaultError(copyError))
    }
  }

  async function openWebsite(uriIndex = 0): Promise<void> {
    if (!selectedSummary?.uris[uriIndex]?.uri) return
    try {
      await itemAccess.openUri(selectedSummary, uriIndex)
      announce(t`Website opened.`)
      if (tracksItemUsage(selectedSummary)) await vaultData.refreshItems()
    } catch (openError) {
      announceError(describeVaultError(openError))
    }
  }

  const resetReveals = useCallback((): void => {
    setRevealedSecrets(emptyRevealedSecrets)
    setRevealedCustomFields(emptyRevealedCustomFields)
  }, [])
  const resetRevealedCustomFields = useCallback(
    (): void => setRevealedCustomFields(emptyRevealedCustomFields),
    []
  )

  return {
    copiedKey,
    revealedSecrets,
    revealedCustomFields,
    resetReveals,
    resetRevealedCustomFields,
    hoveringSecretFieldsRef,
    hoverRevealedSecretFieldsRef,
    passwordZoomOpenRef,
    passwordZoomValue,
    revealSecret,
    hideRevealedSecret,
    openPasswordZoom,
    closePasswordZoom,
    copyField,
    revealCustomField,
    copyCustomField,
    copyTotp,
    openWebsite,
    showLoginContextMenu,
    loadPasswordHistory,
    revealPasswordHistory,
    copyPasswordHistory
  }
}
