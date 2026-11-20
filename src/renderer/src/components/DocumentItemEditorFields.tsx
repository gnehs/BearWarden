import { useLingui } from '@lingui/react/macro'
import type { VaultItemFields, VaultSecretField } from '../../../shared/vault-contract'
import {
  BANK_ACCOUNT_TYPES,
  isBankAccountType,
  type BankAccountType,
  type DocumentDateField
} from '../lib/document-item-fields'
import { useBankAccountTypeLabels } from '../hooks/use-bank-account-type-labels'
import { Field, FieldGroup, FieldLabel } from './ui/field'
import { Input } from './ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue
} from './ui/select'

const fieldGridClassName = 'grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-3'
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/u

type DocumentItemType = 'bankAccount' | 'driversLicense' | 'passport'
type TextFieldName = Exclude<keyof VaultItemFields, VaultSecretField | 'uri' | 'totp'>

interface DocumentItemEditorFieldsProps {
  type: DocumentItemType
  draft: VaultItemFields
  disabled: boolean
  invalidDateField: DocumentDateField | null
  onChange: (field: TextFieldName, value: string) => void
  renderSecret: (field: VaultSecretField, label: string) => React.JSX.Element
}

/** Editor fields for Bitwarden's bank account, driver's license, and passport item types. */
export function DocumentItemEditorFields({
  type,
  draft,
  disabled,
  invalidDateField,
  onChange,
  renderSecret
}: DocumentItemEditorFieldsProps): React.JSX.Element {
  const { t } = useLingui()
  const text = (field: TextFieldName, label: string, inputType = 'text'): React.JSX.Element => (
    <Field key={field}>
      <FieldLabel htmlFor={`editor-${field}`}>{label}</FieldLabel>
      <Input
        id={`editor-${field}`}
        type={inputType}
        value={draft[field]}
        onChange={(event) => onChange(field, event.target.value)}
        disabled={disabled}
      />
    </Field>
  )
  const date = (field: DocumentDateField, label: string): React.JSX.Element => {
    const invalid = invalidDateField === field
    // A date another client stored in a different format stays editable as plain text.
    const nativeDate = draft[field] === '' || ISO_DATE_PATTERN.test(draft[field])
    return (
      <Field key={field} data-invalid={invalid || undefined}>
        <FieldLabel htmlFor={`editor-${field}`}>{label}</FieldLabel>
        <Input
          id={`editor-${field}`}
          type={nativeDate ? 'date' : 'text'}
          value={draft[field]}
          onChange={(event) => onChange(field, event.target.value)}
          disabled={disabled}
          aria-invalid={invalid || undefined}
          aria-describedby={invalid ? 'editor-error' : undefined}
        />
      </Field>
    )
  }
  const issuingCountry = t({
    message: 'Issuing country',
    comment: "Field label for the country that issued a driver's license or passport."
  })
  const issuingAuthority = t({
    message: 'Issuing authority',
    comment: "Field label for the agency that issued a driver's license or passport."
  })
  const dateOfBirth = t({
    message: 'Date of birth',
    comment: "Date field for the holder's birth date on a driver's license or passport."
  })
  const issueDate = t({
    message: 'Issue date',
    comment: "Date field for when a driver's license or passport was issued."
  })
  const expirationDate = t`Expiration date`

  if (type === 'bankAccount') {
    return (
      <>
        <FieldGroup className={fieldGridClassName}>
          {text(
            'bankName',
            t({ message: 'Bank name', comment: 'Field label for the bank of a bank account item.' })
          )}
          {text(
            'nameOnAccount',
            t({
              message: 'Name on account',
              comment: 'Field label for the account holder name of a bank account item.'
            })
          )}
        </FieldGroup>
        <BankAccountTypeSelect
          value={draft.accountType}
          disabled={disabled}
          onChange={(value) => onChange('accountType', value)}
        />
        {renderSecret(
          'accountNumber',
          t({
            message: 'Account number',
            comment: 'Masked field label for the bank account number.'
          })
        )}
        <FieldGroup className={fieldGridClassName}>
          {text(
            'routingNumber',
            t({
              message: 'Routing number',
              comment: 'Field label for the bank routing or sort code of a bank account item.'
            })
          )}
          {text(
            'branchNumber',
            t({
              message: 'Branch number',
              comment: 'Field label for the bank branch number of a bank account item.'
            })
          )}
        </FieldGroup>
        {renderSecret(
          'pin',
          t({
            message: 'PIN',
            context: 'bank-account-pin',
            comment:
              'Masked field label for the PIN of a bank account or its card, not the app unlock PIN.'
          })
        )}
        {renderSecret(
          'swiftCode',
          t({
            message: 'SWIFT code',
            comment: 'Masked field label for the SWIFT/BIC code of a bank account item.'
          })
        )}
        {renderSecret(
          'iban',
          t({
            message: 'IBAN',
            comment: 'Masked field label for the International Bank Account Number.'
          })
        )}
        {text(
          'bankContactPhone',
          t({
            message: 'Bank contact phone',
            comment: 'Field label for the phone number of the bank in a bank account item.'
          }),
          'tel'
        )}
      </>
    )
  }

  if (type === 'driversLicense') {
    return (
      <>
        <FieldGroup className={fieldGridClassName}>
          {text('firstName', t`First name`)}
          {text('middleName', t`Middle name`)}
          {text('lastName', t`Last name`)}
        </FieldGroup>
        {renderSecret(
          'licenseNumber',
          t({
            message: 'License number',
            context: 'drivers-license-number',
            comment: "Masked field label for the number printed on a driver's license item."
          })
        )}
        <FieldGroup className={fieldGridClassName}>
          {date('dateOfBirth', dateOfBirth)}
          {text(
            'licenseClass',
            t({
              message: 'License class',
              comment: "Field label for the vehicle class on a driver's license, such as C or B."
            })
          )}
        </FieldGroup>
        <FieldGroup className={fieldGridClassName}>
          {text('issuingCountry', issuingCountry)}
          {text(
            'issuingState',
            t({
              message: 'Issuing state / province',
              comment: "Field label for the state or province that issued a driver's license."
            })
          )}
        </FieldGroup>
        {text('issuingAuthority', issuingAuthority)}
        <FieldGroup className={fieldGridClassName}>
          {date('issueDate', issueDate)}
          {date('expirationDate', expirationDate)}
        </FieldGroup>
      </>
    )
  }

  return (
    <>
      <FieldGroup className={fieldGridClassName}>
        {text(
          'givenName',
          t({
            message: 'Given name',
            comment: 'Field label for the given names printed on a passport.'
          })
        )}
        {text(
          'surname',
          t({ message: 'Surname', comment: 'Field label for the surname printed on a passport.' })
        )}
      </FieldGroup>
      <FieldGroup className={fieldGridClassName}>
        {date('dateOfBirth', dateOfBirth)}
        {text(
          'sex',
          t({
            message: 'Sex',
            comment: 'Field label for the sex marker printed on a passport, such as F, M, or X.'
          })
        )}
      </FieldGroup>
      <FieldGroup className={fieldGridClassName}>
        {text(
          'birthPlace',
          t({
            message: 'Place of birth',
            comment: 'Field label for the place of birth printed on a passport.'
          })
        )}
        {text(
          'nationality',
          t({
            message: 'Nationality',
            comment: 'Field label for the nationality printed on a passport.'
          })
        )}
      </FieldGroup>
      {renderSecret('passportNumber', t`Passport number`)}
      {text(
        'passportType',
        t({
          message: 'Passport type',
          comment: 'Field label for the passport type code, such as P for an ordinary passport.'
        })
      )}
      {renderSecret(
        'nationalIdentificationNumber',
        t({
          message: 'National ID number',
          comment: 'Masked field label for the national identification number on a passport.'
        })
      )}
      <FieldGroup className={fieldGridClassName}>
        {text('issuingCountry', issuingCountry)}
        {text('issuingAuthority', issuingAuthority)}
      </FieldGroup>
      <FieldGroup className={fieldGridClassName}>
        {date('issueDate', issueDate)}
        {date('expirationDate', expirationDate)}
      </FieldGroup>
    </>
  )
}

function BankAccountTypeSelect({
  value,
  disabled,
  onChange
}: {
  value: string
  disabled: boolean
  onChange: (value: string) => void
}): React.JSX.Element {
  const { t } = useLingui()
  const labels = useBankAccountTypeLabels()
  const items: Array<{ value: string; label: string }> = [
    { value: '', label: t`Not set` },
    ...BANK_ACCOUNT_TYPES.map((type: BankAccountType) => ({ value: type, label: labels[type] })),
    // Keep a value written by another client selectable instead of silently replacing it.
    ...(value && !isBankAccountType(value) ? [{ value, label: value }] : [])
  ]
  return (
    <Field>
      <FieldLabel htmlFor="editor-accountType">
        {t({
          message: 'Account type',
          comment: 'Field label for choosing a bank account kind, such as checking or savings.'
        })}
      </FieldLabel>
      <Select
        items={items}
        value={value}
        disabled={disabled}
        onValueChange={(next) => onChange(next ?? '')}
      >
        <SelectTrigger id="editor-accountType" className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {items.map((item) => (
              <SelectItem key={item.value || 'unset'} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </Field>
  )
}
