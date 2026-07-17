import { describe, expect, it } from 'vitest'
import { generateTotp } from './totp'
import { KEEPASS_XML_LIMITS, parseKeePass2Xml } from './vault-portability-keepass-xml'

const TIME = '2026-07-17T01:02:03Z'

function uuid(seed: number): string {
  const bytes = Buffer.alloc(16)
  bytes.writeUInt32BE(seed >>> 0, 12)
  return bytes.toString('base64')
}

function spaced(value: string): string {
  return value.match(/.{1,4}/gu)!.join(' \n')
}

function times(overrides = ''): string {
  return `<Times><CreationTime>${TIME}</CreationTime><LastModificationTime>${TIME}</LastModificationTime><LastAccessTime>${TIME}</LastAccessTime><ExpiryTime>${TIME}</ExpiryTime><Expires>False</Expires><UsageCount>0</UsageCount><LocationChanged>${TIME}</LocationChanged>${overrides}</Times>`
}

function minimalTimes(): string {
  return `<Times><CreationTime>${TIME}</CreationTime><LastModificationTime>${TIME}</LastModificationTime></Times>`
}

function entry(body: string, extra = ''): string {
  return `<Entry><UUID>${uuid(100)}</UUID>${times()}${body}${extra}<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><Association><Window>Example</Window><KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</KeystrokeSequence></Association></AutoType></Entry>`
}

function string(key: string, value: string, attributes = ''): string {
  return `<String><Key>${key}</Key><Value${attributes}>${value}</Value></String>`
}

function document(rootContents: string, meta = ''): string {
  return `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile><Meta><Generator>KeePass</Generator>${meta}</Meta><Root>${rootContents}<DeletedObjects /></Root></KeePassFile>`
}

function rootGroup(contents: string, uuidValue = uuid(1)): string {
  return `<Group><UUID>${uuidValue}</UUID><Name>Database</Name>${times()}${contents}</Group>`
}

function expectInvalid(xml: string): void {
  expect(() => parseKeePass2Xml(xml)).toThrowError(
    expect.objectContaining({ code: 'INVALID_INPUT' })
  )
}

describe('KeePass 2 plaintext XML import', () => {
  it('maps the official shape, entities, nested paths, protected custom fields, otp, and times', () => {
    const xml = document(
      rootGroup(
        `${entry(
          string('Title', 'Root &amp; Login') +
            string('UserName', 'alice') +
            string('Password', 'secret') +
            string('URL', 'https://example.test') +
            string('Notes', 'line &lt; two') +
            string('otp', 'key=otpauth://totp/example') +
            string('Account Number', '1234', ' ProtectInMemory="True"')
        )}<Group><UUID>${uuid(2)}</UUID><Name>Work</Name>${times()}<Group><UUID>${uuid(3)}</UUID><Name>Admin</Name>${times()}${entry(
          string('Title', '')
        )}</Group></Group>`
      )
    )

    const parsed = parseKeePass2Xml(xml)

    expect(parsed.snapshot.folders).toEqual([
      expect.objectContaining({ name: 'Work' }),
      expect.objectContaining({ name: 'Work/Admin' })
    ])
    expect(parsed.snapshot.items).toEqual([
      expect.objectContaining({
        type: 'login',
        name: 'Root & Login',
        username: 'alice',
        password: 'secret',
        uri: 'https://example.test',
        notes: 'line < two',
        totp: 'otpauth://totp/example',
        folderId: null,
        createdAt: '2026-07-17T01:02:03.000Z',
        updatedAt: '2026-07-17T01:02:03.000Z',
        customFields: [{ name: 'Account Number', value: '1234', type: 'hidden', linkedId: null }]
      }),
      expect.objectContaining({
        name: '--',
        folderId: parsed.snapshot.folders[1]!.id
      })
    ])
  })

  it('skips recycle-bin and template subtrees and counts attachment metadata and history entries', () => {
    const recycleUuid = uuid(10)
    const templatesUuid = uuid(11)
    const live = entry(
      string('Title', 'Live'),
      '<Binary><Key>document.txt</Key><Value Ref="0" /></Binary><History>' +
        entry(string('Title', 'Old 1')) +
        entry(string('Title', 'Old 2')) +
        '</History>'
    )
    const omittedData =
      '<Binary><Key>ignored.txt</Key><Value Ref="0" /></Binary><History>' +
      entry(string('Title', 'Ignored history')) +
      '</History>'
    const xml = document(
      rootGroup(
        `${live}<Group><UUID>${spaced(recycleUuid)}</UUID><Name>Recycle Bin</Name>${times()}${entry(
          string('Title', 'Deleted'),
          omittedData
        )}<Group><UUID>${uuid(12)}</UUID><Name>Child</Name>${times()}${entry(
          string('Title', 'Deleted child')
        )}</Group></Group><Group><UUID>${templatesUuid}</UUID><Name>Templates</Name>${times()}${entry(
          string('Title', 'Template'),
          omittedData
        )}</Group>`
      ),
      `<RecycleBinEnabled>False</RecycleBinEnabled><RecycleBinUUID>${spaced(recycleUuid)}</RecycleBinUUID><EntryTemplatesGroup>${spaced(templatesUuid)}</EntryTemplatesGroup><Binaries><Binary ID="0" Compressed="True">bm90LWRlY29kZWQ=</Binary></Binaries>`
    )

    const parsed = parseKeePass2Xml(xml)

    expect(parsed.snapshot.items.map((item) => item.name)).toEqual(['Live'])
    expect(parsed.snapshot.folders).toEqual([])
    expect(parsed).toMatchObject({
      skippedTrashItems: 2,
      skippedTemplateEntries: 1,
      skippedAttachments: 1,
      skippedHistoryEntries: 2
    })
  })

  it('rejects comments, CDATA, DTD/XXE, expansion entities, namespaces, and other PIs', () => {
    const valid = document(rootGroup(entry(string('Title', 'Okay'))))
    expect(parseKeePass2Xml(valid).snapshot.items).toHaveLength(1)

    for (const invalid of [
      valid.replace('<Entry>', '<!-- comment --><Entry>'),
      valid.replace('<Entry>', `<!--${'x'.repeat(2 * 1024 * 1024)}--><Entry>`),
      valid.replace('Okay', '<![CDATA[Okay]]>'),
      valid.replace(
        '<KeePassFile>',
        '<!DOCTYPE KeePassFile [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><KeePassFile>'
      ),
      valid.replace(
        '<KeePassFile>',
        '<!DOCTYPE KeePassFile [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><KeePassFile>'
      ),
      valid.replace('<KeePassFile>', '<KeePassFile xmlns="urn:keepass">'),
      valid.replace('<KeePassFile>', '<kp:KeePassFile>'),
      valid.replace('</KeePassFile>', '</kp:KeePassFile>'),
      valid.replace('<KeePassFile>', '<?target data?><KeePassFile>'),
      valid.replace('Okay', '&unknown;')
    ]) {
      expectInvalid(invalid)
    }
  })

  it('uses one fallback time for optional names/times and normalizes legal offsets to UTC', () => {
    const fallback = new Date('2030-01-02T03:04:05.000Z')
    const xml = document(
      `<Group><UUID>${uuid(300)}</UUID><Group><UUID>${uuid(301)}</UUID><Times><LastModificationTime>2026-07-17T05:02:03-04:00</LastModificationTime></Times><Entry><UUID>${uuid(302)}</UUID><Times><CreationTime>2026-07-17T09:02:03+08:00</CreationTime></Times>${string('Title', 'Optional')}</Entry><Entry><UUID>${uuid(303)}</UUID>${string('Title', 'Fallback')}</Entry><Entry><UUID>${uuid(304)}</UUID><Times><CreationTime>2026-07-17T01:02:03</CreationTime></Times>${string('Title', 'No timezone')}</Entry></Group></Group>`
    )

    const parsed = parseKeePass2Xml(xml, { now: fallback })

    expect(parsed.snapshot.folders).toEqual([
      {
        id: expect.any(String),
        name: '-',
        updatedAt: '2026-07-17T09:02:03.000Z'
      }
    ])
    expect(parsed.snapshot.items[0]).toMatchObject({
      name: 'Optional',
      createdAt: '2026-07-17T01:02:03.000Z',
      updatedAt: '2026-07-17T01:02:03.000Z'
    })
    expect(parsed.snapshot.items[1]).toMatchObject({
      name: 'Fallback',
      createdAt: fallback.toISOString(),
      updatedAt: fallback.toISOString()
    })
    expect(parsed.snapshot.items[2]).toMatchObject({
      name: 'No timezone',
      createdAt: '2026-07-17T01:02:03.000Z',
      updatedAt: '2026-07-17T01:02:03.000Z'
    })
  })

  it('rejects malformed documents, invalid UUIDs/dates/offsets, and unknown structure', () => {
    const valid = document(rootGroup(entry(string('Title', 'Okay'))))
    for (const invalid of [
      valid.slice(0, -10),
      valid.replace(TIME, '2026-02-30T01:02:03Z'),
      valid.replace(TIME, '2026-07-17T01:02:03+14:01'),
      valid.replace(TIME, '2026-07-17T01:02:03+15:00'),
      valid.replace(TIME, '2026-07-17T24:00:01Z'),
      valid.replace(uuid(1), 'AQ=='),
      valid.replace(uuid(1), 'AAAAAAAAAAAAAAAAAAAAAB=='),
      valid.replace(uuid(100), 'not-an-entry-uuid'),
      valid.replace('<Entry>', '<Entry><Unknown />'),
      valid.replace('<Value>Okay</Value>', '<Value unexpected="True">Okay</Value>'),
      valid.replace('<Root>', `<Root><Group><UUID>${uuid(20)}</UUID><Name>duplicate</Name>`)
    ]) {
      expectInvalid(invalid)
    }
  })

  it('converts modern KeePass TOTP secret encodings and consumes only related fields', () => {
    const cases = [
      ['TimeOtp-Secret', 'hello'],
      ['TimeOtp-Secret-Hex', '68656c6c6f'],
      ['TimeOtp-Secret-Base32', 'jbsw-y3dp \n eb3w64tmmq======'],
      ['TimeOtp-Secret-Base64', 'aGVsbG8=']
    ] as const

    for (const [key, value] of cases) {
      const parsed = parseKeePass2Xml(
        document(
          rootGroup(
            entry(
              string('Title', 'Modern OTP') + string(key, value) + string('Unrelated', 'preserved')
            )
          )
        )
      )
      const item = parsed.snapshot.items[0]!
      expect(item.totp).toBe(key === 'TimeOtp-Secret-Base32' ? 'JBSWY3DPEB3W64TMMQ' : 'NBSWY3DP')
      expect(item.customFields).toEqual([
        { name: 'Unrelated', value: 'preserved', type: 'text', linkedId: null }
      ])
      expect(generateTotp(item.totp, new Date('2026-07-17T01:02:03Z')).code).toHaveLength(6)
    }
  })

  it('emits a usable otpauth URI for non-default modern KeePass TOTP parameters', () => {
    const parsed = parseKeePass2Xml(
      document(
        rootGroup(
          entry(
            string('Title', 'Admin Portal') +
              string('TimeOtp-Secret-Hex', '3132333435363738393031323334353637383930') +
              string('TimeOtp-Length', '8') +
              string('TimeOtp-Period', '60') +
              string('TimeOtp-Algorithm', 'HMAC-SHA-256')
          )
        )
      )
    )
    const totp = parsed.snapshot.items[0]!.totp

    expect(totp).toBe(
      'otpauth://totp/Admin%20Portal?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60'
    )
    expect(generateTotp(totp, new Date('2026-07-17T01:02:03Z'))).toMatchObject({
      period: 60,
      code: expect.stringMatching(/^\d{8}$/u)
    })
    expect(parsed.snapshot.items[0]!.customFields).toEqual([])

    const rfcSha512Secret = '1234567890123456789012345678901234567890123456789012345678901234'
    const sha512 = parseKeePass2Xml(
      document(
        rootGroup(
          entry(
            string('Title', 'RFC SHA-512') +
              string('TimeOtp-Secret', rfcSha512Secret) +
              string('TimeOtp-Length', '8') +
              string('TimeOtp-Algorithm', 'HMAC-SHA-512')
          )
        )
      )
    ).snapshot.items[0]!.totp
    expect(generateTotp(sha512, new Date(59_000)).code).toBe('90693936')
  })

  it('fails closed for conflicting, incomplete, invalid, or unusable modern KeePass TOTP data', () => {
    const invalidFields = [
      string('TimeOtp-Secret', 'one') + string('TimeOtp-Secret-Hex', '6f6e65'),
      string('otp', 'JBSWY3DP') + string('TimeOtp-Secret', 'one'),
      string('TimeOtp-Period', '30'),
      string('TimeOtp-Secret-Hex', 'abc'),
      string('TimeOtp-Secret-Base32', 'MZ'),
      string('TimeOtp-Secret-Base64', 'not-base64'),
      string('TimeOtp-Secret', 'one') + string('TimeOtp-Length', '9'),
      string('TimeOtp-Secret', 'one') + string('TimeOtp-Period', '0'),
      string('TimeOtp-Secret', 'one') + string('TimeOtp-Algorithm', 'HMAC-SHA-3'),
      string('TimeOtp-Secret', 'x'.repeat(1_025))
    ]

    for (const fields of invalidFields) {
      expectInvalid(document(rootGroup(entry(string('Title', 'Invalid OTP') + fields))))
    }
  })

  it('enforces depth, group, event, entry, string, and field byte bounds', () => {
    const deepGroups = Array.from(
      { length: KEEPASS_XML_LIMITS.maximumDepth },
      (_, index) => `<Group><UUID>${uuid(index + 30)}</UUID><Name>g</Name>${times()}`
    ).join('')
    expectInvalid(document(`${deepGroups}${'</Group>'.repeat(KEEPASS_XML_LIMITS.maximumDepth)}`))

    expectInvalid(
      document(
        rootGroup(
          `<Group><UUID>${uuid(200)}</UUID><Name>${'x'.repeat(257)}</Name>${times()}</Group>`
        )
      )
    )
    expectInvalid(
      document(rootGroup(entry(string('Title', 'Okay') + string('oversized', 'x'.repeat(5_001)))))
    )

    const repeatedKey = string('same', 'one') + string('same', 'two')
    expectInvalid(document(rootGroup(entry(string('Title', 'Okay') + repeatedKey))))
  })

  it('allows 2,000 folders besides the root and rejects the next group node', () => {
    const groups = Array.from(
      { length: KEEPASS_XML_LIMITS.maximumGroups - 1 },
      (_, index) =>
        `<Group><UUID>${uuid(index + 1_000)}</UUID><Name>g${index}</Name>${times()}</Group>`
    )
    const atLimit = parseKeePass2Xml(document(rootGroup(groups.join(''))))
    expect(atLimit.snapshot.folders).toHaveLength(2_000)

    groups.push(`<Group><UUID>${uuid(4_000)}</UUID><Name>too-many</Name>${times()}</Group>`)
    expectInvalid(document(rootGroup(groups.join(''))))
  })

  it('bounds String, Binary, and History nodes within each Entry', () => {
    const strings = Array.from({ length: 1_001 }, (_, index) =>
      string(`custom-${index}`, 'value')
    ).join('')
    expectInvalid(document(rootGroup(entry(strings))))

    const binaries = Array.from(
      { length: 1_001 },
      (_, index) => `<Binary><Key>file-${index}</Key><Value Ref="0" /></Binary>`
    ).join('')
    expectInvalid(document(rootGroup(entry(string('Title', 'Binary bound'), binaries))))

    const history = Array.from(
      { length: 1_001 },
      (_, index) =>
        `<Entry><UUID>${uuid(index + 5_000)}</UUID>${times()}${string('Title', `old-${index}`)}</Entry>`
    ).join('')
    expectInvalid(
      document(rootGroup(entry(string('Title', 'History bound'), `<History>${history}</History>`)))
    )
  })

  it('enforces the global Entry node bound without retaining historical entries', () => {
    const historicalEntry = `<Entry><UUID>${uuid(7_000)}</UUID>${minimalTimes()}</Entry>`
    const liveEntries = Array.from({ length: 100 }, (_, index) => {
      const history = historicalEntry.repeat(999)
      return `<Entry><UUID>${uuid(index + 8_000)}</UUID>${minimalTimes()}<History>${history}</History></Entry>`
    }).join('')
    const oneTooMany = `<Entry><UUID>${uuid(9_000)}</UUID>${minimalTimes()}</Entry>`

    expectInvalid(document(rootGroup(liveEntries + oneTooMany)))
  }, 30_000)

  it('spreads the global String quota across Entries instead of treating it as per-vault 100k', () => {
    const fields = Array.from({ length: 1_000 }, (_, index) =>
      string(`field-${index}`, 'value')
    ).join('')
    const historicalEntries = Array.from(
      { length: 100 },
      (_, index) => `<Entry><UUID>${uuid(index + 10_000)}</UUID>${minimalTimes()}${fields}</Entry>`
    ).join('')
    const oneTooMany = `<Entry><UUID>${uuid(11_000)}</UUID>${minimalTimes()}${string('overflow', 'value')}</Entry>`
    const live = `<Entry><UUID>${uuid(11_001)}</UUID>${minimalTimes()}<History>${historicalEntries}${oneTooMany}</History></Entry>`

    expect(parseKeePass2Xml(document(rootGroup(live)))).toMatchObject({
      skippedHistoryEntries: 101,
      snapshot: { items: [expect.objectContaining({ name: '--' })] }
    })
  }, 30_000)

  it('enforces the global parser event bound for otherwise small ignored nodes', () => {
    const deletedObject = `<DeletedObject><UUID>${uuid(12_000)}</UUID><DeletionTime /></DeletedObject>`
    const count = Math.ceil(KEEPASS_XML_LIMITS.maximumEvents / 6) + 1
    const xml = document(rootGroup('')).replace(
      '<DeletedObjects />',
      `<DeletedObjects>${deletedObject.repeat(count)}</DeletedObjects>`
    )

    expectInvalid(xml)
  }, 30_000)
})
