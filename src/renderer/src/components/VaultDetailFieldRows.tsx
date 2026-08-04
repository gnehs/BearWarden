import { useLingui } from '@lingui/react/macro'
import { ArrowUpRight, Eye, EyeOff, ZoomIn } from 'lucide-react'
import type { RefObject } from 'react'
import type {
  VaultCopyField,
  VaultCustomFieldView,
  VaultSecretField
} from '../../../shared/vault-contract'
import { formatPaymentCardNumber } from '../lib/payment-card'
import { cn } from '../lib/utils'
import { ColoredPassword } from './ColoredPassword'
import { CopyFeedbackIcon } from './CopyFeedbackIcon'
import { Button } from './ui/button'
import { detailFieldClassName, TooltipIconButton } from './VaultShell-primitives'
import type { RevealedCustomFieldsState, RevealedSecretsState } from './VaultShell-model'
import {
  customFieldCopyFeedbackKey,
  customFieldDisplayValue,
  matchesCustomFieldSource,
  type DetailField
} from './vault-detail-view-model'

interface DetailFieldCopyControls {
  copiedKey: string | null
  itemId: string | undefined
  copyField: (field: VaultCopyField, uriIndex?: number) => void | Promise<void>
}

interface DetailFieldRevealControls {
  state: RevealedSecretsState
  selectedItemId: string
  hoveringFieldsRef: RefObject<Set<VaultSecretField>>
  hoverRevealedFieldsRef: RefObject<Set<VaultSecretField>>
  passwordZoomOpenRef: RefObject<boolean>
  reveal: (
    field: VaultSecretField,
    options?: { quiet?: boolean; forceShow?: boolean }
  ) => Promise<string | undefined>
  hide: (field: VaultSecretField) => void
  openPasswordZoom: () => void | Promise<void>
  revealOnHover?: boolean
}

interface DetailFieldWebsiteControls {
  openWebsite: (uriIndex?: number) => void | Promise<void>
}

interface VaultDetailFieldRowsProps {
  fields: DetailField[]
  copy: DetailFieldCopyControls
  reveal: DetailFieldRevealControls
  website: DetailFieldWebsiteControls
}

interface VaultDetailFieldRowProps {
  field: DetailField
  copy: DetailFieldCopyControls
  reveal: DetailFieldRevealControls
  website: DetailFieldWebsiteControls
}

function VaultDetailFieldRow({
  field,
  copy,
  reveal,
  website
}: VaultDetailFieldRowProps): React.JSX.Element {
  const { t } = useLingui()
  const secretField = field.field as VaultSecretField
  const isPasswordField = field.field === 'password'
  const revealedValue =
    field.secret && reveal.state.itemId === reveal.selectedItemId
      ? reveal.state.values[secretField]
      : undefined
  const hasExtraAction = Boolean(field.copyable) && Boolean(field.openUri)
  const canCopyFromValue = Boolean(field.secret || field.copyable)
  const copyKey = `field:${copy.itemId}:${field.field}:${field.uriIndex ?? ''}`
  const valueClassName = field.secret
    ? revealedValue === undefined
      ? 'tracking-widest'
      : isPasswordField
        ? 'min-w-0 select-text'
        : 'font-mono select-text'
    : undefined
  const displayValue =
    field.secret && revealedValue !== undefined && isPasswordField ? (
      revealedValue ? (
        <ColoredPassword value={revealedValue} className="text-xs font-medium" />
      ) : (
        t`Not set`
      )
    ) : field.secret ? (
      revealedValue === undefined ? (
        field.field === 'code' ? (
          '•••'
        ) : (
          '••••••••••••'
        )
      ) : field.field === 'number' ? (
        formatPaymentCardNumber(revealedValue) || t`Not set`
      ) : (
        revealedValue || t`Not set`
      )
    ) : (
      field.value || t`Not set`
    )
  const secretHoverHandlers =
    field.secret && reveal.revealOnHover !== false
      ? {
          onMouseEnter: () => {
            reveal.hoveringFieldsRef.current.add(secretField)
            if (revealedValue !== undefined) return
            reveal.hoverRevealedFieldsRef.current.add(secretField)
            void reveal.reveal(secretField, { quiet: true, forceShow: true })
          },
          onMouseLeave: () => {
            reveal.hoveringFieldsRef.current.delete(secretField)
            if (secretField === 'password' && reveal.passwordZoomOpenRef.current) return
            if (!reveal.hoverRevealedFieldsRef.current.delete(secretField)) return
            reveal.hide(secretField)
          }
        }
      : undefined
  const value = (
    <strong className={valueClassName} {...(canCopyFromValue ? undefined : secretHoverHandlers)}>
      {displayValue}
    </strong>
  )

  return (
    <div
      className={cn(
        detailFieldClassName,
        !field.secret && !hasExtraAction && 'max-[430px]:grid-cols-[1fr_auto]'
      )}
    >
      <span>{field.label}</span>
      {canCopyFromValue ? (
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2 w-[calc(100%+8px)] min-w-0 justify-start overflow-hidden px-2 [&>strong]:min-w-0 [&>strong]:truncate [&>strong]:text-xs [&>strong]:font-medium"
          data-field-copy-value=""
          type="button"
          aria-label={
            copy.copiedKey === copyKey ? t`${field.label} copied` : t`Copy ${field.label}`
          }
          disabled={!field.secret && !field.value}
          onClick={() => void copy.copyField(field.field, field.uriIndex)}
          {...secretHoverHandlers}
        >
          {value}
        </Button>
      ) : (
        value
      )}
      {field.secret ? (
        <>
          {isPasswordField ? (
            <TooltipIconButton
              variant="outline"
              size="icon"
              type="button"
              label={t`Show password in large type`}
              onClick={() => void reveal.openPasswordZoom()}
            >
              <ZoomIn />
            </TooltipIconButton>
          ) : (
            <TooltipIconButton
              variant="outline"
              size="icon"
              type="button"
              label={revealedValue === undefined ? t`Show ${field.label}` : t`Hide ${field.label}`}
              aria-pressed={revealedValue !== undefined}
              onClick={() => void reveal.reveal(secretField)}
            >
              {revealedValue === undefined ? <Eye /> : <EyeOff />}
            </TooltipIconButton>
          )}
          <TooltipIconButton
            variant="outline"
            size="icon"
            type="button"
            label={copy.copiedKey === copyKey ? t`${field.label} copied` : t`Copy ${field.label}`}
            onClick={() => void copy.copyField(field.field)}
          >
            <CopyFeedbackIcon copied={copy.copiedKey === copyKey} />
          </TooltipIconButton>
        </>
      ) : (
        <>
          {field.copyable && (
            <TooltipIconButton
              variant="outline"
              size="icon"
              type="button"
              label={copy.copiedKey === copyKey ? t`${field.label} copied` : t`Copy ${field.label}`}
              disabled={!field.value}
              onClick={() => void copy.copyField(field.field, field.uriIndex)}
            >
              <CopyFeedbackIcon copied={copy.copiedKey === copyKey} />
            </TooltipIconButton>
          )}
          {field.openUri && (
            <TooltipIconButton
              variant="outline"
              size="icon"
              type="button"
              label={t`Open website`}
              disabled={!field.value}
              onClick={() => void website.openWebsite(field.uriIndex)}
            >
              <ArrowUpRight />
            </TooltipIconButton>
          )}
        </>
      )}
    </div>
  )
}

export function VaultDetailFieldRows({
  fields,
  copy,
  reveal,
  website
}: VaultDetailFieldRowsProps): React.JSX.Element {
  return (
    <>
      {fields.map((field) => (
        <VaultDetailFieldRow
          key={`${field.label}:${field.field}:${field.uriIndex ?? ''}`}
          field={field}
          copy={copy}
          reveal={reveal}
          website={website}
        />
      ))}
    </>
  )
}

type CustomFieldLabels = Parameters<typeof customFieldDisplayValue>[1]

interface CustomFieldCopyControls {
  copiedKey: string | null
  copyField: (index: number, field: VaultCustomFieldView) => void | Promise<void>
}

interface CustomFieldRevealControls {
  state: RevealedCustomFieldsState
  reveal: (index: number, field: VaultCustomFieldView) => void | Promise<void>
}

interface VaultCustomFieldRowsProps {
  fields: VaultCustomFieldView[]
  item: {
    id: string
    updatedAt: string
  }
  labels: CustomFieldLabels
  copy: CustomFieldCopyControls
  reveal: CustomFieldRevealControls
}

interface VaultCustomFieldRowProps extends Omit<VaultCustomFieldRowsProps, 'fields'> {
  field: VaultCustomFieldView
  index: number
}

function VaultCustomFieldRow({
  field,
  index,
  item,
  labels,
  copy,
  reveal
}: VaultCustomFieldRowProps): React.JSX.Element {
  const { t } = useLingui()
  const revealedEntry = reveal.state.itemId === item.id ? reveal.state.values[index] : undefined
  const revealedValue =
    revealedEntry &&
    revealedEntry.expectedUpdatedAt === item.updatedAt &&
    matchesCustomFieldSource(field, index, revealedEntry.source)
      ? revealedEntry.value
      : undefined
  const hidden = field.type === 'hidden'
  const label = field.name || t`Unnamed field`
  const copyFeedbackKey = customFieldCopyFeedbackKey(item.id, index, field)
  const copyDisabled = field.type !== 'linked' && !field.value && !hidden
  const value = (
    <strong
      className={cn(
        hidden && (revealedValue === undefined ? 'tracking-widest' : 'font-mono select-text')
      )}
    >
      {hidden
        ? revealedValue === undefined
          ? '••••••••••••'
          : revealedValue || t`Not set`
        : customFieldDisplayValue(field, labels)}
    </strong>
  )

  return (
    <div className={cn(detailFieldClassName, !hidden && 'max-[430px]:grid-cols-[1fr_auto]')}>
      <span>{label}</span>
      <Button
        variant="ghost"
        size="sm"
        className="-ml-2 w-[calc(100%+8px)] min-w-0 justify-start overflow-hidden px-2 [&>strong]:min-w-0 [&>strong]:truncate [&>strong]:text-xs [&>strong]:font-medium"
        data-field-copy-value=""
        type="button"
        aria-label={copy.copiedKey === copyFeedbackKey ? t`${label} copied` : t`Copy ${label}`}
        disabled={copyDisabled}
        onClick={() => void copy.copyField(index, field)}
      >
        {value}
      </Button>
      {hidden && (
        <TooltipIconButton
          variant="outline"
          size="icon"
          type="button"
          label={revealedValue === undefined ? t`Show ${label}` : t`Hide ${label}`}
          aria-pressed={revealedValue !== undefined}
          onClick={() => void reveal.reveal(index, field)}
        >
          {revealedValue === undefined ? <Eye /> : <EyeOff />}
        </TooltipIconButton>
      )}
      <TooltipIconButton
        variant="outline"
        size="icon"
        type="button"
        label={copy.copiedKey === copyFeedbackKey ? t`${label} copied` : t`Copy ${label}`}
        disabled={copyDisabled}
        onClick={() => void copy.copyField(index, field)}
      >
        <CopyFeedbackIcon copied={copy.copiedKey === copyFeedbackKey} />
      </TooltipIconButton>
    </div>
  )
}

export function VaultCustomFieldRows({
  fields,
  item,
  labels,
  copy,
  reveal
}: VaultCustomFieldRowsProps): React.JSX.Element {
  return (
    <>
      {fields.map((field, index) => (
        <VaultCustomFieldRow
          key={`${index}:${field.name}:${field.type}`}
          field={field}
          index={index}
          item={item}
          labels={labels}
          copy={copy}
          reveal={reveal}
        />
      ))}
    </>
  )
}
