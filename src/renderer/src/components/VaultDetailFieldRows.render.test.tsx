import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'
import type { VaultCustomFieldView } from '../../../shared/vault-contract'
import { VaultCustomFieldRows, VaultDetailFieldRows } from './VaultDetailFieldRows'

vi.mock('./PaymentCardBrandMark', () => ({ default: () => <span /> }))
vi.mock('./WebsiteIcon', () => ({ default: () => <span /> }))

const labels = {
  yes: 'Yes',
  no: 'No',
  linkedTo: (label: string) => `Linked to ${label}`,
  itemField: 'Item field',
  linkedFields: { 100: 'Username' },
  unset: 'Not set'
}

describe('VaultDetailFieldRows copy targets', () => {
  it('renders every copy-enabled detail value as a copy button', () => {
    const markup = renderToStaticMarkup(
      <VaultDetailFieldRows
        fields={[
          { field: 'number', label: 'Card number', secret: true },
          { field: 'code', label: 'Security code', secret: true },
          {
            field: 'uri',
            label: 'Website',
            value: 'https://example.invalid',
            copyable: true,
            openUri: true
          },
          { field: 'username', label: 'Display-only name', value: 'Sample Person' }
        ]}
        copy={{ copiedKey: null, itemId: 'card-id', copyField: vi.fn() }}
        reveal={{
          state: { itemId: null, values: {} },
          selectedItemId: 'card-id',
          hoveringFieldsRef: { current: new Set() },
          hoverRevealedFieldsRef: { current: new Set() },
          passwordZoomOpenRef: { current: false },
          reveal: vi.fn(),
          hide: vi.fn(),
          openPasswordZoom: vi.fn()
        }}
        website={{ openWebsite: vi.fn() }}
      />
    )

    expect(markup.match(/data-field-copy-value=""/g)).toHaveLength(3)
    expect(markup).toMatch(/<button[^>]*data-field-copy-value=""[^>]*>.*•••/s)
    expect(markup).toMatch(
      /<button[^>]*data-field-copy-value=""[^>]*>.*https:\/\/example\.invalid.*<\/button>/s
    )
    expect(markup).not.toMatch(
      /<button[^>]*data-field-copy-value=""[^>]*>.*Sample Person.*<\/button>/s
    )
  })

  it('renders every custom field type as a value copy button', () => {
    const fields: VaultCustomFieldView[] = [
      { name: 'Email', value: 'user@example.invalid', type: 'text', linkedId: null },
      { name: 'Secret', value: null, type: 'hidden', linkedId: null },
      { name: 'Enabled', value: 'true', type: 'boolean', linkedId: null },
      { name: 'Account', value: null, type: 'linked', linkedId: 100 }
    ]
    const markup = renderToStaticMarkup(
      <VaultCustomFieldRows
        fields={fields}
        item={{ id: 'login-id', updatedAt: '2026-08-04T00:00:00.000Z' }}
        labels={labels}
        copy={{ copiedKey: null, copyField: vi.fn() }}
        reveal={{ state: { itemId: null, values: {} }, reveal: vi.fn() }}
      />
    )

    expect(markup.match(/data-field-copy-value=""/g)).toHaveLength(4)
    expect(markup).toMatch(
      /<button[^>]*data-field-copy-value=""[^>]*>.*user@example\.invalid.*<\/button>/s
    )
    expect(markup).toMatch(/<button[^>]*data-field-copy-value=""[^>]*>.*•••.*<\/button>/s)
    expect(markup).toMatch(/<button[^>]*data-field-copy-value=""[^>]*>.*Yes.*<\/button>/s)
    expect(markup).toMatch(/<button[^>]*data-field-copy-value=""[^>]*>.*Username.*<\/button>/s)
  })
})
