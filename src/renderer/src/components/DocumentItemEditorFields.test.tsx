import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { VaultItemFields, VaultSecretField } from '../../../shared/vault-contract'
import { DocumentItemEditorFields } from './DocumentItemEditorFields'
import { emptyDocumentViewFields } from './vault-detail-test-fixtures'

const fields = {
  ...emptyDocumentViewFields,
  accountNumber: '',
  pin: '',
  swiftCode: '',
  iban: '',
  nationalIdentificationNumber: '',
  firstName: '',
  middleName: '',
  lastName: '',
  licenseNumber: '',
  passportNumber: ''
} as unknown as VaultItemFields

function render(
  type: 'bankAccount' | 'driversLicense' | 'passport',
  draft: Partial<VaultItemFields> = {},
  invalidDateField: 'dateOfBirth' | 'issueDate' | 'expirationDate' | null = null
): { html: string; secrets: VaultSecretField[] } {
  const secrets: VaultSecretField[] = []
  const html = renderToStaticMarkup(
    <DocumentItemEditorFields
      type={type}
      draft={{ ...fields, ...draft }}
      disabled={false}
      invalidDateField={invalidDateField}
      onChange={() => {}}
      renderSecret={(field) => {
        secrets.push(field)
        return <span key={field} data-secret={field} />
      }}
    />
  )
  return { html, secrets }
}

describe('DocumentItemEditorFields', () => {
  it('routes every official secret through the masked secret input', () => {
    expect(render('bankAccount').secrets).toEqual(['accountNumber', 'pin', 'swiftCode', 'iban'])
    expect(render('driversLicense').secrets).toEqual(['licenseNumber'])
    expect(render('passport').secrets).toEqual(['passportNumber', 'nationalIdentificationNumber'])
  })

  it('uses native date inputs and flags the invalid date for assistive technology', () => {
    const { html } = render('passport', { issueDate: '2021-03-04' }, 'expirationDate')
    expect(html).toMatch(/id="editor-issueDate" type="date"[^>]*value="2021-03-04"/u)
    expect(html).toMatch(/id="editor-expirationDate" type="date"[^>]*aria-invalid="true"/u)
  })

  it('keeps a non-ISO date from another client editable as text', () => {
    expect(render('driversLicense', { dateOfBirth: '31/01/1990' }).html).toMatch(
      /id="editor-dateOfBirth" type="text"[^>]*value="31\/01\/1990"/u
    )
  })
})
