import { describe, expect, it } from 'vitest'
import type { VaultEditorSecretField } from '../../../shared/vault-contract'
import {
  applyGeneratedSshKey,
  canApplyGeneratedSshKey,
  canFinalizeGeneratedSshKey,
  clearSshKeyMaterial,
  isSshKeyGenerationBlockingSave,
  sshKeyGenerationAction,
  sshKeyMaterialState
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

  it('finalizes only committed complete material from the current request', () => {
    const completeSsh = {
      type: 'sshKey' as const,
      privateKey: 'private',
      publicKey: 'public',
      fingerprint: 'fingerprint'
    }

    expect(canFinalizeGeneratedSshKey(5, 5, completeSsh)).toBe(true)
    expect(canFinalizeGeneratedSshKey(4, 5, completeSsh)).toBe(false)
    expect(canFinalizeGeneratedSshKey(5, 5, { ...completeSsh, type: 'login' })).toBe(false)
    expect(canFinalizeGeneratedSshKey(5, 5, { ...completeSsh, fingerprint: '' })).toBe(false)
  })

  it('applies generated material without losing queued draft edits', () => {
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
      privateKey: 'generated-private',
      publicKey: 'generated-public',
      fingerprint: 'generated-fingerprint'
    }

    const applied = applyGeneratedSshKey(5, 5, current, generated)
    expect(applied).toMatchObject({
      name: 'queued name change',
      notes: 'preserved notes',
      ...generated,
      changedSecrets: ['password', 'privateKey']
    })
    expect(applyGeneratedSshKey(4, 5, current, generated)).toBe(current)
  })

  it('keeps save disabled while generation is pending or failed', () => {
    expect(isSshKeyGenerationBlockingSave('sshKey', 'idle')).toBe(true)
    expect(isSshKeyGenerationBlockingSave('sshKey', 'generating')).toBe(true)
    expect(isSshKeyGenerationBlockingSave('sshKey', 'error')).toBe(true)
    expect(isSshKeyGenerationBlockingSave('sshKey', 'ready')).toBe(false)
    expect(isSshKeyGenerationBlockingSave('login', 'generating')).toBe(false)
  })
})
