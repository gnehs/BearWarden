import * as sax from 'sax'
import type { VaultCustomField, VaultItemFields } from '../shared/vault-contract'
import type {
  PortableVaultFolder,
  PortableVaultItem,
  PortableVaultSnapshot
} from './vault-portability-codec'
import { VaultError } from './vault-errors'

export const KEEPASS_XML_LIMITS = {
  maximumDocumentBytes: 64 * 1024 * 1024,
  maximumDepth: 64,
  maximumEvents: 2_000_000,
  /** The KeePass root Group plus at most 2,000 folders. */
  maximumGroups: 2_001,
  maximumEntries: 100_000,
  maximumStrings: 1_000_000,
  maximumFieldBytes: 1024 * 1024
} as const

const MAX_NAME_BYTES = 256
const MAX_USERNAME_BYTES = 512
const MAX_PASSWORD_BYTES = 16_384
const MAX_URI_BYTES = 4_096
const MAX_NOTES_BYTES = 65_536
const MAX_CUSTOM_FIELD_BYTES = 5_000
const MAX_STRINGS_PER_ENTRY = 1_000
const MAX_BINARIES_PER_ENTRY = 1_000
const MAX_HISTORY_ENTRIES_PER_ENTRY = 1_000
const UUID_FIELD_NAMES = new Set([
  'UUID',
  'RecycleBinUUID',
  'EntryTemplatesGroup',
  'LastSelectedGroup',
  'LastTopVisibleGroup',
  'CustomIconUUID',
  'LastTopVisibleEntry',
  'PreviousParentGroup'
])
const TIME_OTP_SECRET_KEYS = [
  'TimeOtp-Secret',
  'TimeOtp-Secret-Hex',
  'TimeOtp-Secret-Base32',
  'TimeOtp-Secret-Base64'
] as const
const TIME_OTP_PARAMETER_KEYS = ['TimeOtp-Length', 'TimeOtp-Period', 'TimeOtp-Algorithm'] as const
const TIME_OTP_KEYS = new Set<string>([...TIME_OTP_SECRET_KEYS, ...TIME_OTP_PARAMETER_KEYS])
const XML_DECLARATION_BODY =
  /^version=(['"])1\.0\1(?:\s+encoding=(['"])utf-8\2)?(?:\s+standalone=(['"])(?:yes|no)\3)?$/iu

const CHILDREN = {
  KeePassFile: ['Meta', 'Root'],
  Meta: [
    'Generator',
    'HeaderHash',
    'SettingsChanged',
    'DatabaseName',
    'DatabaseNameChanged',
    'DatabaseDescription',
    'DatabaseDescriptionChanged',
    'DefaultUserName',
    'DefaultUserNameChanged',
    'MaintenanceHistoryDays',
    'Color',
    'MasterKeyChanged',
    'MasterKeyChangeRec',
    'MasterKeyChangeForce',
    'MasterKeyChangeForceOnce',
    'MemoryProtection',
    'CustomIcons',
    'RecycleBinEnabled',
    'RecycleBinUUID',
    'RecycleBinChanged',
    'EntryTemplatesGroup',
    'EntryTemplatesGroupChanged',
    'HistoryMaxItems',
    'HistoryMaxSize',
    'LastSelectedGroup',
    'LastTopVisibleGroup',
    'Binaries',
    'CustomData'
  ],
  MemoryProtection: [
    'ProtectTitle',
    'ProtectUserName',
    'ProtectPassword',
    'ProtectURL',
    'ProtectNotes'
  ],
  CustomIcons: ['Icon'],
  Icon: ['UUID', 'Data', 'Name', 'LastModificationTime'],
  Binaries: ['Binary'],
  CustomData: ['Item'],
  Item: ['Key', 'Value', 'LastModificationTime'],
  Root: ['Group', 'DeletedObjects'],
  Group: [
    'UUID',
    'Name',
    'Notes',
    'IconID',
    'CustomIconUUID',
    'Times',
    'IsExpanded',
    'DefaultAutoTypeSequence',
    'EnableAutoType',
    'EnableSearching',
    'LastTopVisibleEntry',
    'Group',
    'Entry',
    'CustomData',
    'Tags',
    'PreviousParentGroup'
  ],
  Times: [
    'CreationTime',
    'LastModificationTime',
    'LastAccessTime',
    'ExpiryTime',
    'Expires',
    'UsageCount',
    'LocationChanged'
  ],
  Entry: [
    'UUID',
    'IconID',
    'CustomIconUUID',
    'ForegroundColor',
    'BackgroundColor',
    'OverrideURL',
    'QualityCheck',
    'Tags',
    'Times',
    'String',
    'Binary',
    'AutoType',
    'History',
    'CustomData',
    'PreviousParentGroup'
  ],
  String: ['Key', 'Value'],
  Binary: ['Key', 'Value'],
  AutoType: ['Enabled', 'DataTransferObfuscation', 'DefaultSequence', 'Association'],
  Association: ['Window', 'KeystrokeSequence'],
  History: ['Entry'],
  DeletedObjects: ['DeletedObject'],
  DeletedObject: ['UUID', 'DeletionTime']
} as const satisfies Record<string, readonly string[]>

const CONTAINERS = new Set(Object.keys(CHILDREN))
const REPEATABLE_CHILDREN = new Set([
  'Group/Group',
  'Group/Entry',
  'Entry/String',
  'Entry/Binary',
  'History/Entry',
  'CustomIcons/Icon',
  'Binaries/Binary',
  'CustomData/Item',
  'AutoType/Association',
  'DeletedObjects/DeletedObject'
])

type SkipReason = 'recycle-bin' | 'templates' | null

interface Frame {
  name: string
  text: string
  textBytes: number
  childCounts: Map<string, number>
  childTexts: Map<string, string>
  attributes: Record<string, string>
}

interface GroupContext {
  root: boolean
  uuid: string | null
  name: string | null
  path: string | null
  folderId: string | null
  skipReason: SkipReason
  times: ParsedTimes | null
  folder: PortableVaultFolder | null
}

interface ParsedTimes {
  creationTime?: string
  lastModificationTime?: string
}

interface EntryContext {
  historical: boolean
  values: Map<string, { value: string; protectedInMemory: boolean }>
  times: ParsedTimes | null
  binaryMetadata: number
}

interface StringContext {
  key: string | null
  value: string | null
  protectedInMemory: boolean
}

export interface KeePassXmlImport {
  snapshot: PortableVaultSnapshot
  skippedTrashItems: number
  skippedTemplateEntries: number
  skippedAttachments: number
  skippedHistoryEntries: number
}

export interface KeePassXmlParseOptions {
  /** Used once for any optional KeePass timestamps that are absent. */
  now?: Date
}

function invalidInput(): never {
  throw new VaultError('INVALID_INPUT')
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8')
}

function bounded(value: string, maximumBytes: number, allowEmpty = true): string {
  if (
    byteLength(value) > maximumBytes ||
    (!allowEmpty && value.length === 0) ||
    value.includes('\0')
  ) {
    invalidInput()
  }
  return value
}

function strictBoolean(value: string): boolean {
  if (value === 'True') return true
  if (value === 'False') return false
  return invalidInput()
}

function strictKeePassTime(value: string): string {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-])(\d{2}):(\d{2}))?$/u.exec(
      value
    )
  if (!match) invalidInput()
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const fraction = match[7] ?? ''
  const offsetHour = match[9] === undefined ? 0 : Number(match[9])
  const offsetMinute = match[10] === undefined ? 0 : Number(match[10])
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  if (
    year === 0 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth[month - 1]! ||
    minute > 59 ||
    second > 59 ||
    hour > 24 ||
    (hour === 24 && (minute !== 0 || second !== 0 || /[1-9]/u.test(fraction))) ||
    offsetHour > 14 ||
    offsetMinute > 59 ||
    (offsetHour === 14 && offsetMinute !== 0)
  ) {
    invalidInput()
  }
  const milliseconds = Number(`${fraction}000`.slice(0, 3))
  const base = new Date(0)
  base.setUTCFullYear(year, month - 1, day)
  base.setUTCHours(hour, minute, second, milliseconds)
  const offset = (offsetHour * 60 + offsetMinute) * 60_000
  // KeePass exports timezone-less xs:dateTime values as wall-clock UTC; never consult host TZ.
  const epoch = base.getTime() + (match[8] === '+' ? -offset : match[8] === '-' ? offset : 0)
  const date = new Date(epoch)
  if (!Number.isFinite(epoch) || date.getUTCFullYear() < 0 || date.getUTCFullYear() > 9_999) {
    invalidInput()
  }
  return date.toISOString()
}

function canonicalKeePassUuid(value: string): string {
  const collapsed = value.replace(/[\t\n\r ]+/gu, '')
  if (!/^(?:[A-Za-z0-9+/]{4}){5}[A-Za-z0-9+/]{2}==$/u.test(collapsed)) invalidInput()
  const decoded = Buffer.from(collapsed, 'base64')
  if (decoded.length !== 16 || decoded.toString('base64') !== collapsed) invalidInput()
  return collapsed
}

function encodeBase32(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  let output = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
    value &= (1 << bits) - 1
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31]
  return output
}

function decodeBase32(value: string): Buffer {
  const normalizedInput = value.replace(/[\s-]+/gu, '')
  if (!/^[A-Za-z2-7]+={0,6}$/u.test(normalizedInput)) invalidInput()
  const unpadded = normalizedInput.replace(/=+$/u, '').toUpperCase()
  if (![0, 2, 4, 5, 7].includes(unpadded.length % 8)) invalidInput()
  let bits = 0
  let accumulator = 0
  const bytes: number[] = []
  for (const character of unpadded) {
    const digit = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(character)
    if (digit < 0) invalidInput()
    accumulator = (accumulator << 5) | digit
    bits += 5
    if (bits >= 8) {
      bytes.push((accumulator >>> (bits - 8)) & 0xff)
      bits -= 8
      accumulator &= (1 << bits) - 1
    }
  }
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) invalidInput()
  const decoded = Buffer.from(bytes)
  const canonical = encodeBase32(decoded)
  const normalized = normalizedInput.toUpperCase()
  if (
    normalized !== canonical &&
    normalized !== canonical.padEnd(Math.ceil(canonical.length / 8) * 8, '=')
  ) {
    invalidInput()
  }
  return decoded
}

function decodeTimeOtpSecret(key: string, value: string): Buffer {
  bounded(value, MAX_PASSWORD_BYTES, false)
  if (key === 'TimeOtp-Secret') return Buffer.from(value, 'utf8')
  if (key === 'TimeOtp-Secret-Hex') {
    if (!/^(?:[0-9A-Fa-f]{2})+$/u.test(value)) invalidInput()
    return Buffer.from(value, 'hex')
  }
  if (key === 'TimeOtp-Secret-Base32') return decodeBase32(value)
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    invalidInput()
  }
  const decoded = Buffer.from(value, 'base64')
  if (decoded.length === 0 || decoded.toString('base64') !== value) invalidInput()
  return decoded
}

function strictInteger(value: string, minimum: number, maximum: number): number {
  if (!/^\d+$/u.test(value)) invalidInput()
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) invalidInput()
  return parsed
}

function keepassTotp(
  values: ReadonlyMap<string, { value: string }>,
  title: string
): { value: string; consumed: ReadonlySet<string> } {
  const legacy = values.get('otp')?.value ?? ''
  const modernKeys = [...TIME_OTP_KEYS].filter((key) => values.has(key))
  if (modernKeys.length === 0) {
    return {
      value: legacy.startsWith('key=') ? legacy.slice(4) : legacy,
      consumed: new Set(['otp'])
    }
  }
  if (legacy !== '') invalidInput()
  const secretKeys = TIME_OTP_SECRET_KEYS.filter((key) => values.has(key))
  if (secretKeys.length !== 1) invalidInput()
  const secretKey = secretKeys[0]!
  const secret = decodeTimeOtpSecret(secretKey, values.get(secretKey)!.value)
  let base32: string
  try {
    if (secret.length === 0 || secret.length > 1_024) invalidInput()
    base32 = bounded(encodeBase32(secret), MAX_PASSWORD_BYTES, false)
  } finally {
    secret.fill(0)
  }
  const digits = values.has('TimeOtp-Length')
    ? strictInteger(values.get('TimeOtp-Length')!.value, 1, 8)
    : 6
  const period = values.has('TimeOtp-Period')
    ? strictInteger(values.get('TimeOtp-Period')!.value, 1, 0xffff_ffff)
    : 30
  const rawAlgorithm = values.get('TimeOtp-Algorithm')?.value ?? 'HMAC-SHA-1'
  const algorithms = {
    'HMAC-SHA-1': 'SHA1',
    'HMAC-SHA-256': 'SHA256',
    'HMAC-SHA-512': 'SHA512'
  } as const
  if (!Object.prototype.hasOwnProperty.call(algorithms, rawAlgorithm)) invalidInput()
  const algorithm = algorithms[rawAlgorithm as keyof typeof algorithms]
  const result =
    digits === 6 && period === 30 && algorithm === 'SHA1'
      ? base32
      : `otpauth://totp/${encodeURIComponent(title.trim() || 'KeePass Import')}?secret=${base32}&algorithm=${algorithm}&digits=${digits}&period=${period}`
  return { value: result, consumed: new Set(['otp', ...modernKeys]) }
}

function emptyItemFields(): VaultItemFields {
  return {
    username: '',
    password: '',
    totp: '',
    uri: null,
    cardholderName: '',
    brand: '',
    number: '',
    expMonth: '',
    expYear: '',
    code: '',
    title: '',
    firstName: '',
    middleName: '',
    lastName: '',
    address1: '',
    address2: '',
    address3: '',
    city: '',
    state: '',
    postalCode: '',
    country: '',
    company: '',
    email: '',
    phone: '',
    ssn: '',
    identityUsername: '',
    passportNumber: '',
    licenseNumber: '',
    privateKey: '',
    publicKey: '',
    fingerprint: ''
  }
}

function preScanXml(input: string): void {
  if (byteLength(input) > KEEPASS_XML_LIMITS.maximumDocumentBytes) invalidInput()
  let index = 0
  while (index < input.length && /\s/u.test(input[index]!)) index += 1
  if (input.startsWith('<?xml', index)) {
    const end = input.indexOf('?>', index + 5)
    if (
      end < 0 ||
      end - index > 512 ||
      !XML_DECLARATION_BODY.test(input.slice(index + 5, end).trim())
    ) {
      invalidInput()
    }
    index = end + 2
  }
  // KeePass exports do not require declarations beyond the XML declaration. Rejecting these
  // tokens before sax is constructed prevents it from buffering large comments or declarations.
  if (input.indexOf('<?', index) !== -1 || input.indexOf('<!', index) !== -1) invalidInput()
}

function attributesOf(tag: sax.Tag | sax.QualifiedTag): Record<string, string> {
  const result: Record<string, string> = {}
  for (const [name, rawValue] of Object.entries(tag.attributes)) {
    if (name.includes(':') || name.toLowerCase() === 'xmlns') invalidInput()
    if (typeof rawValue !== 'string') invalidInput()
    result[name] = rawValue
  }
  return result
}

function validateAttributes(
  parent: string | undefined,
  name: string,
  attributes: Record<string, string>
): void {
  const names = Object.keys(attributes)
  let allowed: readonly string[] = []
  if (parent === 'String' && name === 'Value') allowed = ['ProtectInMemory']
  else if (parent === 'Binary' && name === 'Value') allowed = ['Ref', 'Protected']
  else if (parent === 'Binaries' && name === 'Binary') allowed = ['ID', 'Compressed']
  else if (parent === 'Item' && name === 'Value') allowed = ['ProtectInMemory']
  if (names.some((attribute) => !allowed.includes(attribute))) invalidInput()
  if (attributes.ProtectInMemory !== undefined) strictBoolean(attributes.ProtectInMemory)
  if (attributes.Protected !== undefined) strictBoolean(attributes.Protected)
  if (attributes.Compressed !== undefined) strictBoolean(attributes.Compressed)
  if (attributes.ID !== undefined && !/^\d+$/u.test(attributes.ID)) invalidInput()
  if (attributes.Ref !== undefined && !/^\d+$/u.test(attributes.Ref)) invalidInput()
}

/**
 * Parses the plaintext XML produced by KeePass 2 exports without creating a DOM.
 * Binary contents and history values are validated structurally but never retained or decoded.
 */
export function parseKeePass2Xml(
  xml: string,
  options: KeePassXmlParseOptions = {}
): KeePassXmlImport {
  if (typeof xml !== 'string' || xml.length === 0) invalidInput()
  const now = options.now ?? new Date()
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) invalidInput()
  const fallbackTime = now.toISOString()
  const input = xml.charCodeAt(0) === 0xfeff ? xml.slice(1) : xml
  if (input.length === 0) invalidInput()
  preScanXml(input)

  const frames: Frame[] = []
  const groups: GroupContext[] = []
  const entries: EntryContext[] = []
  const strings: StringContext[] = []
  const folders: PortableVaultFolder[] = []
  const items: PortableVaultItem[] = []
  let recycleBinUuid = ''
  let templatesUuid = ''
  let eventCount = 0
  let groupCount = 0
  let entryCount = 0
  let stringCount = 0
  let skippedTrashItems = 0
  let skippedTemplateEntries = 0
  let skippedAttachments = 0
  let skippedHistoryEntries = 0
  let rootSeen = false
  let rootClosed = false
  let xmlDeclarationSeen = false

  const finalizeGroup = (group: GroupContext): void => {
    if (group.path !== null) return
    if (group.uuid === null) invalidInput()
    if (group.name === null || group.name === '') group.name = '-'
    bounded(group.name, MAX_NAME_BYTES, false)
    const parentGroup = groups.at(-2)
    group.path = group.root
      ? ''
      : parentGroup?.root
        ? group.name
        : `${parentGroup?.path ?? ''}/${group.name}`
    if (!group.root) bounded(group.path, MAX_NAME_BYTES, false)
    if (!group.root && group.skipReason === null) {
      group.folder = { id: group.folderId!, name: group.path }
      folders.push(group.folder)
    }
  }

  const countEvent = (): void => {
    eventCount += 1
    if (eventCount > KEEPASS_XML_LIMITS.maximumEvents) invalidInput()
  }

  const parser = sax.parser(true, {
    strictEntities: true,
    trim: false,
    normalize: false,
    lowercase: false,
    xmlns: false,
    position: true
  } as sax.SAXOptions & { strictEntities: true })

  parser.onprocessinginstruction = (instruction) => {
    countEvent()
    if (
      instruction.name !== 'xml' ||
      xmlDeclarationSeen ||
      rootSeen ||
      !XML_DECLARATION_BODY.test(instruction.body.trim())
    ) {
      invalidInput()
    }
    xmlDeclarationSeen = true
  }
  parser.ondoctype = invalidInput
  parser.onsgmldeclaration = invalidInput
  parser.oncdata = invalidInput
  parser.oncomment = invalidInput
  parser.onerror = invalidInput

  parser.onopentag = (tag) => {
    countEvent()
    if (rootClosed || frames.length >= KEEPASS_XML_LIMITS.maximumDepth || tag.name.includes(':')) {
      invalidInput()
    }
    const parent = frames.at(-1)
    if (!parent) {
      if (rootSeen || tag.name !== 'KeePassFile') invalidInput()
      rootSeen = true
    } else {
      const allowed = CHILDREN[parent.name as keyof typeof CHILDREN]
      if (!allowed || !(allowed as readonly string[]).includes(tag.name)) invalidInput()
      const count = (parent.childCounts.get(tag.name) ?? 0) + 1
      parent.childCounts.set(tag.name, count)
      if (count > 1 && !REPEATABLE_CHILDREN.has(`${parent.name}/${tag.name}`)) invalidInput()
      if (
        (parent.name === 'Entry' && tag.name === 'String' && count > MAX_STRINGS_PER_ENTRY) ||
        (parent.name === 'Entry' && tag.name === 'Binary' && count > MAX_BINARIES_PER_ENTRY) ||
        (parent.name === 'History' && tag.name === 'Entry' && count > MAX_HISTORY_ENTRIES_PER_ENTRY)
      ) {
        invalidInput()
      }
      if (
        parent.name === 'KeePassFile' &&
        tag.name === 'Root' &&
        parent.childCounts.get('Meta') !== 1
      ) {
        invalidInput()
      }
      if (
        parent.name === 'Root' &&
        tag.name === 'DeletedObjects' &&
        parent.childCounts.get('Group') !== 1
      ) {
        invalidInput()
      }
    }
    const attributes = attributesOf(tag)
    validateAttributes(parent?.name, tag.name, attributes)
    frames.push({
      name: tag.name,
      text: '',
      textBytes: 0,
      childCounts: new Map(),
      childTexts: new Map(),
      attributes
    })

    if (tag.name === 'Group') {
      groupCount += 1
      if (groupCount > KEEPASS_XML_LIMITS.maximumGroups) invalidInput()
      const parentGroup = groups.at(-1)
      if (parentGroup) finalizeGroup(parentGroup)
      groups.push({
        root: groups.length === 0,
        uuid: null,
        name: null,
        path: null,
        folderId: groups.length === 0 ? null : `keepass-folder-${groupCount - 1}`,
        skipReason: parentGroup?.skipReason ?? null,
        times: null,
        folder: null
      })
    } else if (tag.name === 'Entry') {
      const group = groups.at(-1)
      if (!group) invalidInput()
      finalizeGroup(group)
      entryCount += 1
      if (entryCount > KEEPASS_XML_LIMITS.maximumEntries) invalidInput()
      entries.push({
        historical: frames.at(-2)?.name === 'History',
        values: new Map(),
        times: null,
        binaryMetadata: 0
      })
    } else if (tag.name === 'String') {
      stringCount += 1
      if (stringCount > KEEPASS_XML_LIMITS.maximumStrings) invalidInput()
      strings.push({ key: null, value: null, protectedInMemory: false })
    }
  }

  parser.ontext = (text) => {
    countEvent()
    const frame = frames.at(-1)
    if (!frame) {
      if (text.trim() !== '') invalidInput()
      return
    }
    const parentName = frames.at(-2)?.name
    const isContainer =
      CONTAINERS.has(frame.name) && !(frame.name === 'Binary' && parentName === 'Binaries')
    if (isContainer) {
      if (text.trim() !== '') invalidInput()
      return
    }
    const discardBinary =
      (frame.name === 'Data' && parentName === 'Icon') ||
      (frame.name === 'Binary' && parentName === 'Binaries') ||
      (frame.name === 'Value' && parentName === 'Binary')
    if (discardBinary) return
    frame.textBytes += byteLength(text)
    if (frame.textBytes > KEEPASS_XML_LIMITS.maximumFieldBytes) invalidInput()
    frame.text += text
  }

  parser.onclosetag = (name) => {
    countEvent()
    const frame = frames.pop()
    if (!frame || frame.name !== name) invalidInput()
    const parentFrame = frames.at(-1)
    const parentName = parentFrame?.name
    const text = frame.text
    if (parentFrame && !CONTAINERS.has(name)) parentFrame.childTexts.set(name, text)

    let canonicalUuid: string | undefined
    if (UUID_FIELD_NAMES.has(name)) canonicalUuid = canonicalKeePassUuid(text)

    if (name === 'CreationTime' || name === 'LastModificationTime') {
      if (parentName === 'Times') strictKeePassTime(text)
      else if (text !== '') strictKeePassTime(text)
    } else if (
      parentName === 'Times' &&
      (name === 'LastAccessTime' || name === 'ExpiryTime' || name === 'LocationChanged')
    ) {
      strictKeePassTime(text)
    } else if (parentName === 'Times' && name === 'Expires') {
      strictBoolean(text)
    } else if (parentName === 'Times' && name === 'UsageCount' && !/^\d+$/u.test(text)) {
      invalidInput()
    }

    if (name === 'RecycleBinUUID' && parentName === 'Meta') {
      recycleBinUuid = canonicalUuid!
    } else if (name === 'EntryTemplatesGroup' && parentName === 'Meta') {
      templatesUuid = canonicalUuid!
    } else if (parentName === 'Group' && name === 'UUID') {
      const group = groups.at(-1)
      if (!group) invalidInput()
      group.uuid = canonicalUuid!
      if (group.skipReason === null && group.uuid === recycleBinUuid)
        group.skipReason = 'recycle-bin'
      if (group.skipReason === null && group.uuid === templatesUuid) group.skipReason = 'templates'
    } else if (parentName === 'Group' && name === 'Name') {
      const group = groups.at(-1)
      if (!group || group.uuid === null || group.path !== null) invalidInput()
      group.name = bounded(text, MAX_NAME_BYTES)
    } else if (parentName === 'String' && name === 'Key') {
      const current = strings.at(-1)
      if (!current) invalidInput()
      current.key = bounded(text, MAX_CUSTOM_FIELD_BYTES)
    } else if (parentName === 'String' && name === 'Value') {
      const current = strings.at(-1)
      if (!current) invalidInput()
      current.value = text
      current.protectedInMemory = frame.attributes.ProtectInMemory === 'True'
    } else if (name === 'String') {
      const current = strings.pop()
      const entry = entries.at(-1)
      if (!current || !entry || current.key === null || current.value === null) invalidInput()
      if (entry.values.has(current.key)) invalidInput()
      entry.values.set(current.key, {
        value: current.value,
        protectedInMemory: current.protectedInMemory
      })
    } else if (name === 'Binary' && parentName === 'Entry') {
      const entry = entries.at(-1)
      if (!entry || frame.childCounts.get('Key') !== 1 || frame.childCounts.get('Value') !== 1) {
        invalidInput()
      }
      entry.binaryMetadata += 1
    } else if (name === 'Entry') {
      const entry = entries.pop()
      if (!entry) invalidInput()
      if (frame.childCounts.get('UUID') !== 1) invalidInput()
      if (entry.historical) {
        if (groups.at(-1)?.skipReason === null) skippedHistoryEntries += 1
      } else {
        const group = groups.at(-1)
        if (!group || group.name === null || group.uuid === null) invalidInput()
        if (group.skipReason === 'recycle-bin') {
          skippedTrashItems += 1
        } else if (group.skipReason === 'templates') {
          skippedTemplateEntries += 1
        } else {
          const title = entry.values.get('Title')?.value ?? ''
          const username = entry.values.get('UserName')?.value ?? ''
          const password = entry.values.get('Password')?.value ?? ''
          const uri = entry.values.get('URL')?.value ?? ''
          const notes = entry.values.get('Notes')?.value ?? ''
          const totp = keepassTotp(entry.values, title)
          bounded(title, MAX_NAME_BYTES)
          bounded(username, MAX_USERNAME_BYTES)
          bounded(password, MAX_PASSWORD_BYTES)
          bounded(uri, MAX_URI_BYTES)
          bounded(notes, MAX_NOTES_BYTES)
          bounded(totp.value, MAX_PASSWORD_BYTES)
          const reserved = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes', 'otp'])
          const customFields: VaultCustomField[] = []
          for (const [key, field] of entry.values) {
            if (reserved.has(key) || totp.consumed.has(key)) continue
            customFields.push({
              name: bounded(key, MAX_CUSTOM_FIELD_BYTES),
              value: bounded(field.value, MAX_CUSTOM_FIELD_BYTES),
              type: field.protectedInMemory ? 'hidden' : 'text',
              linkedId: null
            })
          }
          const fields = emptyItemFields()
          fields.username = username
          fields.password = password
          fields.totp = totp.value
          fields.uri = uri === '' ? null : uri
          const createdAt =
            entry.times?.creationTime ?? entry.times?.lastModificationTime ?? fallbackTime
          const updatedAt =
            entry.times?.lastModificationTime ?? entry.times?.creationTime ?? fallbackTime
          const item: PortableVaultItem = {
            ...fields,
            id: `keepass-item-${items.length + 1}`,
            type: 'login',
            name: title.trim() === '' ? '--' : title,
            notes: notes === '' ? null : notes,
            folderId: group.folderId,
            favorite: false,
            createdAt,
            updatedAt,
            deletedAt: null,
            archivedAt: null,
            reprompt: 0,
            uris: uri === '' ? [] : [{ uri, match: null }],
            passkeys: [],
            customFields,
            passwordHistory: [],
            passwordRevisionDate: null,
            autofillOnPageLoad: null
          }
          items.push(item)
          skippedAttachments += entry.binaryMetadata
        }
      }
    } else if (name === 'Group') {
      const group = groups.at(-1)
      if (!group) invalidInput()
      finalizeGroup(group)
      if (group.folder) {
        group.folder.updatedAt =
          group.times?.lastModificationTime ?? group.times?.creationTime ?? fallbackTime
      }
      groups.pop()
    } else if (name === 'Root') {
      if (frame.childCounts.get('Group') !== 1) invalidInput()
    } else if (name === 'KeePassFile') {
      if (
        frames.length !== 0 ||
        frame.childCounts.get('Meta') !== 1 ||
        frame.childCounts.get('Root') !== 1
      ) {
        invalidInput()
      }
      rootClosed = true
    }

    if (name === 'Times') {
      const ownerGroup = parentName === 'Group' ? groups.at(-1) : undefined
      const ownerEntry = parentName === 'Entry' ? entries.at(-1) : undefined
      const times: ParsedTimes = {}
      const creationTime = frame.childTexts.get('CreationTime')
      const lastModificationTime = frame.childTexts.get('LastModificationTime')
      if (creationTime !== undefined) times.creationTime = strictKeePassTime(creationTime)
      if (lastModificationTime !== undefined) {
        times.lastModificationTime = strictKeePassTime(lastModificationTime)
      }
      if (ownerGroup) ownerGroup.times = times
      else if (ownerEntry) ownerEntry.times = times
      else invalidInput()
    }
  }

  try {
    parser.write(input).close()
  } catch (error) {
    if (error instanceof VaultError) throw error
    invalidInput()
  }
  if (
    !rootSeen ||
    !rootClosed ||
    frames.length !== 0 ||
    groups.length !== 0 ||
    entries.length !== 0 ||
    strings.length !== 0
  ) {
    invalidInput()
  }
  return {
    snapshot: { folders, items },
    skippedTrashItems,
    skippedTemplateEntries,
    skippedAttachments,
    skippedHistoryEntries
  }
}
