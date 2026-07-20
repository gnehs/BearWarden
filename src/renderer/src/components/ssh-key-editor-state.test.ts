import { describe, expect, it, vi } from 'vitest'
import type {
  LoginView,
  SshKeyCreateImportedRequest,
  SshKeyUpdateImportedRequest,
  VaultEditorSecretField
} from '../../../shared/vault-contract'
import {
  applyImportedSshKey,
  applyGeneratedSshKey,
  canApplyGeneratedSshKey,
  clearSshKeyMaterial,
  createLoginWithOptionalSshImport,
  invalidateFailedSshImport,
  isValidSshImportPassphrase,
  isSshKeyGenerationBlockingSave,
  sshKeyGenerationAction,
  sshKeyImportErrorMessage,
  sshKeyImportResultAction,
  sshKeyMaterialState,
  updateLoginWithOptionalSshImport
} from './ssh-key-editor-state'

describe('SSH key editor state', () => {
  it('classifies blank, complete, and partial material before automatic generation', () => {
    expect(sshKeyMaterialState({ privateKey: '', publicKey: '', fingerprint: '' })).toBe('blank')
    expect(
      sshKeyMaterialState({
        privateKey: 'private',
        publicKey: 'public',
        fingerprint: 'fingerprint'
      })
    ).toBe('complete')
    expect(sshKeyMaterialState({ privateKey: 'private', publicKey: '', fingerprint: '' })).toBe(
      'partial'
    )
    expect(isSshKeyGenerationBlockingSave('sshKey', 'idle')).toBe(true)
  })

  it('waits for existing secrets before deciding whether to generate', () => {
    const blank = { privateKey: '', publicKey: '', fingerprint: '' }
    const complete = {
      privateKey: 'private',
      publicKey: 'public',
      fingerprint: 'fingerprint'
    }

    expect(sshKeyGenerationAction(false, 'sshKey', 'idle', blank)).toBe('wait')
    expect(sshKeyGenerationAction(true, 'login', 'idle', blank)).toBe('wait')
    expect(sshKeyGenerationAction(true, 'sshKey', 'idle', blank)).toBe('generate')
    expect(sshKeyGenerationAction(true, 'sshKey', 'idle', complete)).toBe('ready')
    expect(sshKeyGenerationAction(true, 'sshKey', 'idle', { ...complete, privateKey: '' })).toBe(
      'error'
    )
  })

  it('clears partial material and private-key tracking before a retry', () => {
    const reset = clearSshKeyMaterial({
      type: 'sshKey' as const,
      name: 'deploy key',
      privateKey: 'partial-private',
      publicKey: 'partial-public',
      fingerprint: '',
      changedSecrets: ['password', 'privateKey']
    })

    expect(reset).toEqual({
      type: 'sshKey',
      name: 'deploy key',
      privateKey: '',
      publicKey: '',
      fingerprint: '',
      changedSecrets: ['password']
    })
    expect(sshKeyMaterialState(reset)).toBe('blank')
  })

  it('rejects a stale response after leaving SSH or starting a newer request', () => {
    const blankSsh = {
      type: 'sshKey' as const,
      privateKey: '',
      publicKey: '',
      fingerprint: ''
    }

    expect(canApplyGeneratedSshKey(4, 5, blankSsh)).toBe(false)
    expect(canApplyGeneratedSshKey(5, 5, { ...blankSsh, type: 'login' })).toBe(false)
    expect(canApplyGeneratedSshKey(5, 5, { ...blankSsh, publicKey: 'occupied' })).toBe(false)
    expect(canApplyGeneratedSshKey(5, 5, blankSsh)).toBe(true)
  })

  it('applies only generated public metadata without losing queued draft edits', () => {
    const current = {
      type: 'sshKey' as const,
      name: 'queued name change',
      notes: 'preserved notes',
      privateKey: '',
      publicKey: '',
      fingerprint: '',
      changedSecrets: ['password'] as VaultEditorSecretField[]
    }
    const generated = {
      status: 'ready' as const,
      token: 'generated-token',
      expiresAt: Date.now() + 60_000,
      publicKey: 'generated-public',
      fingerprint: 'generated-fingerprint'
    }

    const applied = applyGeneratedSshKey(5, 5, current, generated)
    expect(applied).toEqual({
      type: 'sshKey',
      name: 'queued name change',
      notes: 'preserved notes',
      privateKey: '',
      publicKey: 'generated-public',
      fingerprint: 'generated-fingerprint',
      sshImportToken: 'generated-token',
      changedSecrets: ['password']
    })
    expect(JSON.stringify(generated)).not.toContain('generated-private')
    expect(applyGeneratedSshKey(4, 5, current, generated)).toBe(current)
  })

  it('keeps save disabled while generation is pending or failed', () => {
    expect(isSshKeyGenerationBlockingSave('sshKey', 'idle')).toBe(true)
    expect(isSshKeyGenerationBlockingSave('sshKey', 'generating')).toBe(true)
    expect(isSshKeyGenerationBlockingSave('sshKey', 'error')).toBe(true)
    expect(isSshKeyGenerationBlockingSave('sshKey', 'ready')).toBe(false)
    expect(isSshKeyGenerationBlockingSave('sshKey', 'error', 'main-only-token')).toBe(false)
    expect(isSshKeyGenerationBlockingSave('login', 'generating')).toBe(false)
  })

  it('applies only public import metadata for the current SSH request', () => {
    const draft = {
      type: 'sshKey' as const,
      privateKey: 'generated-private',
      publicKey: 'generated-public',
      fingerprint: 'generated-fingerprint',
      changedSecrets: ['privateKey'] as VaultEditorSecretField[]
    }
    const rendererSafeResult = {
      status: 'ready' as const,
      token: 'import-token',
      expiresAt: Date.now() + 60_000,
      publicKey: 'imported-public',
      fingerprint: 'imported-fingerprint'
    }

    expect(Object.keys(rendererSafeResult)).not.toContain('privateKey')
    expect(applyImportedSshKey(8, 8, draft, rendererSafeResult)).toEqual({
      type: 'sshKey',
      privateKey: '',
      publicKey: 'imported-public',
      fingerprint: 'imported-fingerprint',
      sshImportToken: 'import-token',
      changedSecrets: []
    })
    expect(applyImportedSshKey(7, 8, draft, rendererSafeResult)).toBe(draft)
    expect(applyImportedSshKey(8, 8, { ...draft, type: 'login' }, rendererSafeResult)).toEqual({
      ...draft,
      type: 'login'
    })
  })

  it('keeps a wrong-password import in the same retryable session', () => {
    const wrongPassword = { status: 'error' as const, code: 'WrongPassword' as const }
    expect(sshKeyImportResultAction(wrongPassword)).toBe('retryPassphrase')
    expect(sshKeyImportErrorMessage(wrongPassword.code)).toBe(
      '私密金鑰密碼片語不正確。請再次輸入。'
    )
    expect(sshKeyImportResultAction({ status: 'error', code: 'SessionUnavailable' })).toBe('fail')
  })

  it('validates passphrase limits by UTF-8 bytes before IPC', () => {
    expect(isValidSshImportPassphrase('')).toBe(false)
    expect(isValidSshImportPassphrase('a'.repeat(1_024))).toBe(true)
    expect(isValidSshImportPassphrase('é'.repeat(512))).toBe(true)
    expect(isValidSshImportPassphrase('é'.repeat(513))).toBe(false)
  })

  it('invalidates only the consumed import token after a failed save', () => {
    const draft = {
      type: 'sshKey' as const,
      privateKey: '',
      publicKey: 'imported-public',
      fingerprint: 'imported-fingerprint',
      sshImportToken: 'consumed-token',
      changedSecrets: ['password'] as VaultEditorSecretField[]
    }

    expect(invalidateFailedSshImport(draft, 'stale-token')).toBe(draft)
    expect(invalidateFailedSshImport(draft, 'consumed-token')).toEqual({
      type: 'sshKey',
      privateKey: '',
      publicKey: '',
      fingerprint: '',
      sshImportToken: undefined,
      changedSecrets: ['password']
    })
  })

  it('routes create saves through imported IPC without renderer private material', async () => {
    const created = {} as LoginView
    const create = vi.fn(async () => created)
    const createImported = vi
      .fn<(request: SshKeyCreateImportedRequest) => Promise<LoginView>>()
      .mockResolvedValue(created)

    await createLoginWithOptionalSshImport(
      { name: 'Imported key', type: 'sshKey', privateKey: 'must-not-cross-renderer-ipc' },
      'import-token',
      { create, createImported }
    )

    expect(create).not.toHaveBeenCalled()
    expect(createImported).toHaveBeenCalledOnce()
    expect(createImported.mock.calls[0]?.[0]).toEqual({
      name: 'Imported key',
      type: 'sshKey',
      importToken: 'import-token'
    })
  })

  it('keeps normal create and imported update save paths distinct', async () => {
    const saved = {} as LoginView
    const create = vi.fn(async () => saved)
    const createImported = vi.fn(async () => saved)
    const update = vi.fn(async () => saved)
    const updateImported = vi
      .fn<(request: SshKeyUpdateImportedRequest) => Promise<LoginView>>()
      .mockResolvedValue(saved)

    await createLoginWithOptionalSshImport({ name: 'Generated key', type: 'sshKey' }, undefined, {
      create,
      createImported
    })
    await updateLoginWithOptionalSshImport(
      { id: 'item-id', name: 'Imported replacement', privateKey: 'must-not-cross-renderer-ipc' },
      'import-token',
      { update, updateImported }
    )

    expect(create).toHaveBeenCalledOnce()
    expect(createImported).not.toHaveBeenCalled()
    expect(update).not.toHaveBeenCalled()
    expect(updateImported.mock.calls[0]?.[0]).toEqual({
      id: 'item-id',
      name: 'Imported replacement',
      importToken: 'import-token'
    })
  })
})
