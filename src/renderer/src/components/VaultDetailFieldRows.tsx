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
import {
  DetailRow,
  DetailRowPair,
  detailActionClassName,
  detailValueButtonClassName,
  detailValueClassName
} from './VaultDetailLayout'
import { TooltipIconButton } from './VaultShell-primitives'
import type { RevealedCustomFieldsState, RevealedSecretsState } from './VaultShell-model'
import {
  arrangeDetailFields,
  customFieldCopyFeedbackKey,
  customFieldDisplayValue,
  detailFieldCopyFeedbackKey,
  matchesCustomFieldSource,
  type DetailField,
  type DetailFieldRowModel
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
  tag?: string
  copy: DetailFieldCopyControls
  reveal: DetailFieldRevealControls
  website: DetailFieldWebsiteControls
}

function VaultDetailFieldRow({
  field,
  tag,
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
  const canCopyFromValue = Boolean(field.secret || field.copyable)
  const copyKey = detailFieldCopyFeedbackKey(copy.itemId, field.field, field.uriIndex)
  const valueClassName = field.secret
    ? revealedValue === undefined
      ? 'tracking-widest'
      : isPasswordField
        ? 'min-w-0 select-text'
        : 'font-mono select-text'
    : undefined
  const plainValue = !canCopyFromValue
  const displayValue =
    field.secret && revealedValue !== undefined && isPasswordField ? (
      revealedValue ? (
        <ColoredPassword value={revealedValue} className="text-sm font-medium" />
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
    <strong
      className={cn(
        plainValue ? 'block text-sm font-medium break-words' : detailValueClassName,
        valueClassName
      )}
    >
      {displayValue}
    </strong>
  )

  const copyLabel = copy.copiedKey === copyKey ? t`${field.label} copied` : t`Copy ${field.label}`
  const copyAction = (
    <TooltipIconButton
      className={detailActionClassName}
      variant="ghost"
      size="icon-sm"
      type="button"
      label={copyLabel}
      disabled={!field.secret && !field.value}
      onClick={() => void copy.copyField(field.field, field.uriIndex)}
    >
      <CopyFeedbackIcon copied={copy.copiedKey === copyKey} />
    </TooltipIconButton>
  )

  return (
    <DetailRow
      label={field.label}
      actions={
        field.secret ? (
          <>
            <TooltipIconButton
              className={detailActionClassName}
              variant="ghost"
              size="icon-sm"
              type="button"
              label={revealedValue === undefined ? t`Show ${field.label}` : t`Hide ${field.label}`}
              aria-pressed={revealedValue !== undefined}
              onClick={() => void reveal.reveal(secretField)}
            >
              {revealedValue === undefined ? <Eye /> : <EyeOff />}
            </TooltipIconButton>
            {isPasswordField && (
              <TooltipIconButton
                className={detailActionClassName}
                variant="ghost"
                size="icon-sm"
                type="button"
                label={t`Show password in large type`}
                onClick={() => void reveal.openPasswordZoom()}
              >
                <ZoomIn />
              </TooltipIconButton>
            )}
            {copyAction}
          </>
        ) : (
          <>
            {field.copyable && copyAction}
            {field.openUri && (
              <TooltipIconButton
                className={detailActionClassName}
                variant="ghost"
                size="icon-sm"
                type="button"
                label={t`Open website`}
                disabled={!field.value}
                onClick={() => void website.openWebsite(field.uriIndex)}
              >
                <ArrowUpRight />
              </TooltipIconButton>
            )}
          </>
        )
      }
    >
      <div className="flex min-w-0 items-center">
        {canCopyFromValue ? (
          <Button
            variant="ghost"
            size="sm"
            className={cn(detailValueButtonClassName, tag && 'flex-initial')}
            data-field-copy-value=""
            type="button"
            aria-label={copyLabel}
            disabled={!field.secret && !field.value}
            onClick={() => void copy.copyField(field.field, field.uriIndex)}
            {...secretHoverHandlers}
          >
            {value}
          </Button>
        ) : (
          value
        )}
        {tag && (
          <span className="bg-muted text-muted-foreground rounded-control ml-2 flex-none px-1.5 py-0.5 text-[11px] leading-4 font-semibold">
            {tag}
          </span>
        )}
      </div>
    </DetailRow>
  )
}

export function VaultDetailFieldRows({
  fields,
  copy,
  reveal,
  website
}: VaultDetailFieldRowsProps): React.JSX.Element {
  const renderRow = (row: DetailFieldRowModel): React.JSX.Element => {
    const cells = row.fields.map((field) => (
      <VaultDetailFieldRow
        key={`${field.label}:${field.field}:${field.uriIndex ?? ''}`}
        field={field}
        tag={row.tag}
        copy={copy}
        reveal={reveal}
        website={website}
      />
    ))
    return row.fields.length === 2 ? (
      <DetailRowPair key={cells.map((cell) => cell.key).join('|')}>{cells}</DetailRowPair>
    ) : (
      cells[0]!
    )
  }
  return <>{arrangeDetailFields(fields).map(renderRow)}</>
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
  const copyLabel = copy.copiedKey === copyFeedbackKey ? t`${label} copied` : t`Copy ${label}`
  const value = (
    <strong
      className={cn(
        detailValueClassName,
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
    <DetailRow
      label={<span title={label}>{label}</span>}
      actions={
        <>
          {hidden && (
            <TooltipIconButton
              className={detailActionClassName}
              variant="ghost"
              size="icon-sm"
              type="button"
              label={revealedValue === undefined ? t`Show ${label}` : t`Hide ${label}`}
              aria-pressed={revealedValue !== undefined}
              onClick={() => void reveal.reveal(index, field)}
            >
              {revealedValue === undefined ? <Eye /> : <EyeOff />}
            </TooltipIconButton>
          )}
          <TooltipIconButton
            className={detailActionClassName}
            variant="ghost"
            size="icon-sm"
            type="button"
            label={copyLabel}
            disabled={copyDisabled}
            onClick={() => void copy.copyField(index, field)}
          >
            <CopyFeedbackIcon copied={copy.copiedKey === copyFeedbackKey} />
          </TooltipIconButton>
        </>
      }
    >
      <Button
        variant="ghost"
        size="sm"
        className={detailValueButtonClassName}
        data-field-copy-value=""
        type="button"
        aria-label={copyLabel}
        disabled={copyDisabled}
        onClick={() => void copy.copyField(index, field)}
      >
        {value}
      </Button>
    </DetailRow>
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
