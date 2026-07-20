import { randomUUID } from 'node:crypto'
import type {
  AutofillPrompt,
  AutofillPromptErrorCode,
  AutofillSelectionRequest
} from '../shared/vault-contract'
import type {
  AutofillAuthorizationValidator,
  AutofillCredentialConsumer,
  AutofillCredentials,
  AutofillDiscoveryResult,
  AutofillExecutionRequest
} from './autofill'
import { MacOSAutofillError, type MacOSBrowserContext } from './macos-autofill-adapter'
import { VaultError } from './vault-errors'

interface AutofillVault {
  discoverAutofillCandidates(targetUrl: string): Promise<AutofillDiscoveryResult>
  performAutofill(
    request: AutofillExecutionRequest,
    validateAuthorization: AutofillAuthorizationValidator,
    consume: AutofillCredentialConsumer
  ): Promise<void>
}

interface AutofillPlatform {
  permission(prompt?: boolean): Promise<boolean>
  context(): Promise<MacOSBrowserContext>
  fill(
    context: MacOSBrowserContext,
    credentials: AutofillCredentials,
    signal: AbortSignal
  ): Promise<void>
}

export interface AutofillCoordinatorOptions {
  readonly vault: AutofillVault
  readonly platform: AutofillPlatform
  readonly publish: (prompt: AutofillPrompt | null) => void
  readonly showPicker: () => void
  readonly hidePicker: () => void
  readonly openMain: (itemId?: string) => void
  readonly createRequestId?: () => string
}

interface ActiveRequest {
  readonly prompt: AutofillPrompt
  readonly context: MacOSBrowserContext
  readonly discovery: AutofillDiscoveryResult
  readonly abort: AbortController
  filling: boolean
}

function safeHostname(value: string): string {
  try {
    return new URL(value).hostname
  } catch {
    return ''
  }
}

function errorCode(error: unknown): AutofillPromptErrorCode {
  if (error instanceof MacOSAutofillError) {
    switch (error.code) {
      case 'ACCESSIBILITY_PERMISSION_DENIED':
      case 'UNSUPPORTED_APPLICATION':
      case 'URL_UNAVAILABLE':
      case 'FOCUSED_WINDOW_UNAVAILABLE':
      case 'FOCUSED_ELEMENT_UNAVAILABLE':
      case 'FOCUSED_FIELD_NOT_EDITABLE':
      case 'FOCUSED_FIELD_OUTSIDE_WEB_CONTENT':
      case 'ADDRESS_FIELD_FOCUSED':
      case 'TARGET_NOT_FOUND':
      case 'CONTEXT_CHANGED':
      case 'FILL_FAILED':
        return error.code
      case 'TARGET_ACTIVATION_FAILED':
        return 'TARGET_NOT_FOUND'
      case 'INVALID_HELPER_RESPONSE':
      case 'UNAVAILABLE':
        return 'UNAVAILABLE'
    }
  }
  if (error instanceof VaultError) {
    if (error.code === 'LOCKED') return 'LOCKED'
    if (error.code === 'REPROMPT_REQUIRED') return 'REPROMPT_REQUIRED'
  }
  return 'UNAVAILABLE'
}

export class AutofillCoordinator {
  private active: ActiveRequest | null = null
  private prompt: AutofillPrompt | null = null
  private triggerEpoch = 0

  constructor(private readonly options: AutofillCoordinatorOptions) {}

  current(): AutofillPrompt | null {
    return this.prompt
  }

  async trigger(): Promise<void> {
    this.cancel()
    const epoch = ++this.triggerEpoch
    let context: MacOSBrowserContext
    try {
      context = await this.options.platform.context()
    } catch (error) {
      if (error instanceof MacOSAutofillError && error.code === 'ACCESSIBILITY_PERMISSION_DENIED') {
        // The shortcut is an explicit user gesture, so this is the only place allowed to prompt.
        await this.options.platform.permission(true).catch(() => false)
      }
      if (epoch === this.triggerEpoch) this.publishError(error)
      return
    }
    if (epoch !== this.triggerEpoch) return

    try {
      const discovery = await this.options.vault.discoverAutofillCandidates(context.url)
      if (epoch !== this.triggerEpoch) return
      const requestId = this.options.createRequestId?.() ?? randomUUID()
      const prompt: AutofillPrompt = {
        requestId,
        browser: context.browser,
        hostname: safeHostname(discovery.targetUrl),
        status: discovery.candidates.length === 0 ? 'error' : 'ready',
        choices: discovery.candidates.map((candidate) => ({
          id: candidate.id,
          name: candidate.name,
          username: candidate.username,
          hostname: candidate.hostname,
          reprompt: candidate.reprompt
        })),
        ...(discovery.candidates.length === 0 ? { error: 'NO_MATCHES' as const } : {})
      }
      this.active = { prompt, context, discovery, abort: new AbortController(), filling: false }
      this.prompt = prompt
      if (discovery.candidates.length === 1 && discovery.candidates[0]!.reprompt === 0) {
        await this.select({ requestId, itemId: discovery.candidates[0]!.id })
        return
      }
      this.options.publish(prompt)
      this.options.showPicker()
    } catch (error) {
      if (epoch === this.triggerEpoch) this.publishError(error, context)
    }
  }

  async select(request: AutofillSelectionRequest): Promise<void> {
    const active = this.active
    if (
      !active ||
      active.filling ||
      request.requestId !== active.prompt.requestId ||
      typeof request.itemId !== 'string'
    ) {
      return
    }
    const candidate = active.discovery.candidates.find(({ id }) => id === request.itemId)
    if (!candidate) return
    active.filling = true
    const fillingPrompt: AutofillPrompt = { ...active.prompt, status: 'filling' }
    this.active = { ...active, prompt: fillingPrompt, filling: true }
    this.prompt = fillingPrompt
    this.options.publish(fillingPrompt)
    try {
      await this.options.vault.performAutofill(
        {
          itemId: candidate.id,
          targetUrl: active.discovery.targetUrl,
          expectedGeneration: active.discovery.generation,
          expectedUpdatedAt: candidate.updatedAt
        },
        // The quick picker never collects a master password. Protected items fail closed and are
        // handed to the full main window instead of weakening the existing reprompt boundary.
        () => false,
        (credentials) =>
          this.options.platform.fill(active.context, credentials, active.abort.signal)
      )
      if (this.active?.prompt.requestId === request.requestId) this.cancel()
    } catch (error) {
      if (this.active?.prompt.requestId !== request.requestId) return
      const failed: AutofillPrompt = {
        ...active.prompt,
        status: 'error',
        error: errorCode(error)
      }
      this.active = { ...active, prompt: failed, filling: false }
      this.prompt = failed
      this.options.publish(failed)
      this.options.showPicker()
    }
  }

  cancel(requestId?: string): void {
    if (requestId && this.prompt?.requestId !== requestId) return
    this.triggerEpoch += 1
    this.active?.abort.abort()
    this.active = null
    this.prompt = null
    this.options.publish(null)
    this.options.hidePicker()
  }

  openMain(requestId: string): void {
    const active = this.active
    if (this.prompt?.requestId !== requestId) return
    const protectedChoice = active?.discovery.candidates.find(({ reprompt }) => reprompt === 1)
    this.options.openMain(active ? protectedChoice?.id : undefined)
    this.cancel(requestId)
  }

  dispose(): void {
    this.triggerEpoch += 1
    this.cancel()
  }

  private publishError(error: unknown, context?: MacOSBrowserContext): void {
    const prompt: AutofillPrompt = {
      requestId: this.options.createRequestId?.() ?? randomUUID(),
      browser: context?.browser ?? '',
      hostname: context ? safeHostname(context.url) : '',
      status: 'error',
      choices: [],
      error: errorCode(error)
    }
    if (context) {
      this.active = {
        prompt,
        context,
        discovery: { generation: -1, targetUrl: context.url, candidates: [] },
        abort: new AbortController(),
        filling: false
      }
    } else {
      this.active = null
    }
    this.prompt = prompt
    this.options.publish(prompt)
    this.options.showPicker()
  }
}
