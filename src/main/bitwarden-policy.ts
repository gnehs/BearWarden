/**
 * Bitwarden organization policy wire values.
 *
 * Keep these numbers aligned with the official PolicyType wire enum. Unknown future values are
 * deliberately accepted by the parser and retained only as a bounded numeric identifier.
 */
export const BITWARDEN_POLICY_TYPE = {
  TwoFactorAuthentication: 0,
  MasterPassword: 1,
  PasswordGenerator: 2,
  SingleOrg: 3,
  RequireSso: 4,
  OrganizationDataOwnership: 5,
  DisableSend: 6,
  SendOptions: 7,
  ResetPassword: 8,
  MaximumVaultTimeout: 9,
  DisablePersonalVaultExport: 10,
  ActivateAutofill: 11,
  AutomaticAppLogIn: 12,
  FreeFamiliesSponsorship: 13,
  RemoveUnlockWithPin: 14,
  RestrictedItemTypes: 15,
  UriMatchDefaults: 16,
  AutotypeDefaultSetting: 17,
  AutomaticUserConfirmation: 18,
  BlockClaimedDomainAccountCreation: 19,
  OrganizationUserNotification: 20,
  SendControls: 21
} as const

export type KnownBitwardenPolicyType =
  (typeof BITWARDEN_POLICY_TYPE)[keyof typeof BITWARDEN_POLICY_TYPE]

/**
 * `actionable` means this parser retained all data needed to enforce the policy. The caller must
 * still wire the corresponding product behavior and resolve official membership exemptions.
 */
export type BitwardenPolicyExecution = 'actionable' | 'unsupported' | 'unknown' | 'malformed'

export interface PasswordGeneratorPolicyMetadata {
  kind: 'passwordGenerator'
  overridePasswordType: '' | 'password' | 'passphrase'
  minLength: number
  useUppercase: boolean
  useLowercase: boolean
  useNumbers: boolean
  numberCount: number
  useSpecial: boolean
  specialCount: number
  minNumberWords: number
  capitalize: boolean
  includeNumber: boolean
}

export interface MaximumVaultTimeoutPolicyMetadata {
  kind: 'maximumVaultTimeout'
  minutes: number
  timeoutType: 'never' | 'onAppRestart' | 'onSystemLock' | 'immediately' | 'custom' | null
  action: 'lock' | 'logOut' | null
}

export interface RestrictedItemTypesPolicyMetadata {
  kind: 'restrictedItemTypes'
  cipherTypes: number[]
}

export interface BooleanPolicyMetadata {
  kind:
    | 'organizationDataOwnership'
    | 'disableSend'
    | 'disablePersonalVaultExport'
    | 'removeUnlockWithPin'
}

export type ActionablePolicyMetadata =
  | PasswordGeneratorPolicyMetadata
  | MaximumVaultTimeoutPolicyMetadata
  | RestrictedItemTypesPolicyMetadata
  | BooleanPolicyMetadata

/** Safe to persist: it contains no server policy payload, banner text, domains, or secrets. */
export interface BitwardenPolicyMetadata {
  id: string
  organizationId: string
  type: number
  typeName: keyof typeof BITWARDEN_POLICY_TYPE | null
  enabled: boolean
  canToggleState: boolean
  revisionDate: string | null
  execution: BitwardenPolicyExecution
  data: ActionablePolicyMetadata | null
}

export interface BitwardenPolicySet {
  source: 'policiesNew' | 'policies' | 'none'
  policies: BitwardenPolicyMetadata[]
  /** Organization ids whose profile membership explicitly reports `usePolicies: true`. */
  applicableOrganizationIds?: string[]
  /**
   * Safe, value-free marker used when a sync returned policy data that could not be normalized.
   * Read-only vault synchronization may still commit, but every policy-sensitive operation must
   * fail closed until a later valid policy snapshot replaces this marker.
   */
  parseFailure?: 'invalid-response' | 'limit-exceeded'
}

export type PolicyEnforcementDecision =
  | { state: 'not-applicable'; policies: [] }
  | { state: 'enforce'; policies: BitwardenPolicyMetadata[] }
  | {
      state: 'fail-closed'
      reason: 'malformed-policy' | 'unsupported-policy' | 'unknown-policy'
      policies: BitwardenPolicyMetadata[]
    }

export class BitwardenPolicyParseError extends Error {
  constructor(readonly code: 'INVALID_POLICY_RESPONSE' | 'POLICY_LIMIT_EXCEEDED') {
    super(code)
    this.name = 'BitwardenPolicyParseError'
  }
}

const MAX_POLICIES = 256
const MAX_POLICY_TYPE = 65_535
const MAX_TIMEOUT_MINUTES = 366 * 24 * 60
const MAX_GENERATOR_LENGTH = 4_096
const MAX_GENERATOR_COUNT = 1_024
const MAX_RESTRICTED_TYPES = 16
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u

const POLICY_NAMES = new Map<number, keyof typeof BITWARDEN_POLICY_TYPE>(
  Object.entries(BITWARDEN_POLICY_TYPE).map(([name, type]) => [
    type,
    name as keyof typeof BITWARDEN_POLICY_TYPE
  ])
)

function invalidResponse(): never {
  throw new BitwardenPolicyParseError('INVALID_POLICY_RESPONSE')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function readAliased(
  record: Record<string, unknown>,
  camelName: string,
  pascalName: string
): unknown {
  const hasCamel = Object.hasOwn(record, camelName)
  const hasPascal = Object.hasOwn(record, pascalName)
  if (hasCamel && hasPascal) invalidResponse()
  if (hasCamel) return record[camelName]
  if (hasPascal) return record[pascalName]
  return undefined
}

function requiredUuid(value: unknown): string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) invalidResponse()
  return value.toLowerCase()
}

function requiredBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') invalidResponse()
  return value
}

function optionalBoolean(value: unknown, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'boolean') invalidResponse()
  return value
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : null
}

function optionalDate(value: unknown): string | null {
  if (value === undefined || value === null) return null
  if (
    typeof value !== 'string' ||
    value.length > 40 ||
    !ISO_DATE_PATTERN.test(value) ||
    !Number.isFinite(Date.parse(value))
  ) {
    invalidResponse()
  }
  // Date.parse normalizes impossible dates such as February 30. The second-precision prefix must
  // survive parsing unchanged; sub-millisecond server precision remains safe to persist verbatim.
  if (new Date(value).toISOString().slice(0, 19) !== value.slice(0, 19)) invalidResponse()
  return value
}

function dataValue(data: Record<string, unknown>, name: string): unknown {
  return readAliased(data, name, `${name[0]?.toUpperCase() ?? ''}${name.slice(1)}`)
}

function dataBoolean(data: Record<string, unknown>, name: string): boolean | null {
  const value = dataValue(data, name)
  if (value === undefined || value === null) return false
  return typeof value === 'boolean' ? value : null
}

function dataInteger(data: Record<string, unknown>, name: string, maximum: number): number | null {
  const value = dataValue(data, name)
  if (value === undefined || value === null) return 0
  return boundedInteger(value, 0, maximum)
}

function parsePasswordGenerator(data: unknown): PasswordGeneratorPolicyMetadata | null {
  if (!isRecord(data)) return null
  const override = dataValue(data, 'overridePasswordType')
  const overridePasswordType = override === undefined || override === null ? '' : override
  if (
    overridePasswordType !== '' &&
    overridePasswordType !== 'password' &&
    overridePasswordType !== 'passphrase'
  ) {
    return null
  }
  const minLength = dataInteger(data, 'minLength', MAX_GENERATOR_LENGTH)
  const numberCount = dataInteger(data, 'minNumbers', MAX_GENERATOR_COUNT)
  const specialCount = dataInteger(data, 'minSpecial', MAX_GENERATOR_COUNT)
  const minNumberWords = dataInteger(data, 'minNumberWords', MAX_GENERATOR_COUNT)
  const useUppercase = dataBoolean(data, 'useUpper')
  const useLowercase = dataBoolean(data, 'useLower')
  const useNumbers = dataBoolean(data, 'useNumbers')
  const useSpecial = dataBoolean(data, 'useSpecial')
  const capitalize = dataBoolean(data, 'capitalize')
  const includeNumber = dataBoolean(data, 'includeNumber')
  if (
    minLength === null ||
    numberCount === null ||
    specialCount === null ||
    minNumberWords === null ||
    useUppercase === null ||
    useLowercase === null ||
    useNumbers === null ||
    useSpecial === null ||
    capitalize === null ||
    includeNumber === null
  ) {
    return null
  }
  return {
    kind: 'passwordGenerator',
    overridePasswordType,
    minLength,
    useUppercase,
    useLowercase,
    useNumbers,
    numberCount,
    useSpecial,
    specialCount,
    minNumberWords,
    capitalize,
    includeNumber
  }
}

function parseMaximumVaultTimeout(data: unknown): MaximumVaultTimeoutPolicyMetadata | null {
  if (!isRecord(data)) return null
  const minutes = boundedInteger(dataValue(data, 'minutes'), 1, MAX_TIMEOUT_MINUTES)
  if (minutes === null) return null
  const rawType = dataValue(data, 'type')
  const rawAction = dataValue(data, 'action')
  const timeoutType = rawType === undefined ? null : rawType
  const action = rawAction === undefined ? null : rawAction
  if (
    timeoutType !== null &&
    timeoutType !== 'never' &&
    timeoutType !== 'onAppRestart' &&
    timeoutType !== 'onSystemLock' &&
    timeoutType !== 'immediately' &&
    timeoutType !== 'custom'
  ) {
    return null
  }
  if (action !== null && action !== 'lock' && action !== 'logOut') return null
  return { kind: 'maximumVaultTimeout', minutes, timeoutType, action }
}

function parseRestrictedItemTypes(data: unknown): RestrictedItemTypesPolicyMetadata | null {
  // The official client treats absent policy data as the legacy Card-only restriction.
  if (data === undefined || data === null) {
    return { kind: 'restrictedItemTypes', cipherTypes: [3] }
  }
  if (!Array.isArray(data) || data.length === 0 || data.length > MAX_RESTRICTED_TYPES) return null
  const cipherTypes = new Set<number>()
  for (const value of data) {
    const type = boundedInteger(value, 1, 8)
    if (type === null) return null
    cipherTypes.add(type)
  }
  return { kind: 'restrictedItemTypes', cipherTypes: [...cipherTypes].sort((a, b) => a - b) }
}

function actionableData(type: number, data: unknown): ActionablePolicyMetadata | null | undefined {
  switch (type) {
    case BITWARDEN_POLICY_TYPE.PasswordGenerator:
      return parsePasswordGenerator(data)
    case BITWARDEN_POLICY_TYPE.OrganizationDataOwnership:
      return { kind: 'organizationDataOwnership' }
    case BITWARDEN_POLICY_TYPE.DisableSend:
      return { kind: 'disableSend' }
    case BITWARDEN_POLICY_TYPE.MaximumVaultTimeout:
      return parseMaximumVaultTimeout(data)
    case BITWARDEN_POLICY_TYPE.DisablePersonalVaultExport:
      return { kind: 'disablePersonalVaultExport' }
    case BITWARDEN_POLICY_TYPE.RemoveUnlockWithPin:
      return { kind: 'removeUnlockWithPin' }
    case BITWARDEN_POLICY_TYPE.RestrictedItemTypes:
      return parseRestrictedItemTypes(data)
    default:
      return undefined
  }
}

function parsePolicy(value: unknown): BitwardenPolicyMetadata {
  if (!isRecord(value)) invalidResponse()
  const id = requiredUuid(readAliased(value, 'id', 'Id'))
  const organizationId = requiredUuid(readAliased(value, 'organizationId', 'OrganizationId'))
  const type = boundedInteger(readAliased(value, 'type', 'Type'), 0, MAX_POLICY_TYPE)
  if (type === null) invalidResponse()
  const enabled = requiredBoolean(readAliased(value, 'enabled', 'Enabled'))
  const canToggleState = optionalBoolean(
    readAliased(value, 'canToggleState', 'CanToggleState'),
    true
  )
  const revisionDate = optionalDate(readAliased(value, 'revisionDate', 'RevisionDate'))
  const typeName = POLICY_NAMES.get(type) ?? null
  const normalizedData = actionableData(type, readAliased(value, 'data', 'Data'))
  const execution: BitwardenPolicyExecution =
    typeName === null
      ? 'unknown'
      : normalizedData === undefined
        ? 'unsupported'
        : normalizedData === null
          ? 'malformed'
          : 'actionable'
  return {
    id,
    organizationId,
    type,
    typeName,
    enabled,
    canToggleState,
    revisionDate,
    execution,
    data: normalizedData ?? null
  }
}

function parsePolicyArray(value: unknown): BitwardenPolicyMetadata[] {
  if (!Array.isArray(value)) invalidResponse()
  if (value.length > MAX_POLICIES) {
    throw new BitwardenPolicyParseError('POLICY_LIMIT_EXCEEDED')
  }
  return value.map(parsePolicy)
}

/**
 * Parses a complete sync response. A non-empty PoliciesNew array is authoritative; an empty one
 * intentionally falls back to the legacy Policies array, matching the official client rollout.
 */
export function parseBitwardenPolicySync(response: unknown): BitwardenPolicySet {
  if (!isRecord(response)) invalidResponse()
  const policiesNew = readAliased(response, 'policiesNew', 'PoliciesNew')
  if (policiesNew !== undefined && policiesNew !== null) {
    if (!Array.isArray(policiesNew)) invalidResponse()
    if (policiesNew.length > 0) {
      return { source: 'policiesNew', policies: parsePolicyArray(policiesNew) }
    }
  }
  const policies = readAliased(response, 'policies', 'Policies')
  if (policies === undefined || policies === null) return { source: 'none', policies: [] }
  return { source: 'policies', policies: parsePolicyArray(policies) }
}

/** Returns enabled policies that need an explicit compatibility decision before use. */
export function unenforcedEnabledPolicies(
  policySet: BitwardenPolicySet
): BitwardenPolicyMetadata[] {
  return policySet.policies.filter((policy) => policy.enabled && policy.execution !== 'actionable')
}

/**
 * Provides a conservative operation gate after the caller has determined policy applicability.
 * Organization filtering is optional because owner/admin exemption rules must be resolved by the
 * caller from its trusted organization membership context.
 */
export function policyEnforcementDecision(
  policySet: BitwardenPolicySet,
  type: number,
  applicableOrganizationIds?: ReadonlySet<string>
): PolicyEnforcementDecision {
  const policies = policySet.policies.filter(
    (policy) =>
      policy.enabled &&
      policy.type === type &&
      (applicableOrganizationIds === undefined ||
        applicableOrganizationIds.has(policy.organizationId))
  )
  if (policies.length === 0) return { state: 'not-applicable', policies: [] }
  if (policies.some((policy) => policy.execution === 'malformed')) {
    return { state: 'fail-closed', reason: 'malformed-policy', policies }
  }
  if (policies.some((policy) => policy.execution === 'unknown')) {
    return { state: 'fail-closed', reason: 'unknown-policy', policies }
  }
  if (policies.some((policy) => policy.execution === 'unsupported')) {
    return { state: 'fail-closed', reason: 'unsupported-policy', policies }
  }
  return { state: 'enforce', policies }
}
