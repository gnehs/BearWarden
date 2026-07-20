import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import EmergencyAccessPage from './EmergencyAccessPage'
import FeatureUnderConstructionNotice from './FeatureUnderConstructionNotice'
import OrganizationsPage from './OrganizationsPage'
import SendsPage from './SendsPage'

describe('FeatureUnderConstructionNotice', () => {
  it('renders an accessible construction notice with feature-specific details', () => {
    const markup = renderToStaticMarkup(
      <FeatureUnderConstructionNotice>目前僅提供唯讀功能。</FeatureUnderConstructionNotice>
    )

    expect(markup).toContain('role="alert"')
    expect(markup).toContain('施工中')
    expect(markup).toContain('目前僅提供唯讀功能。')
    expect(markup).toContain('aria-hidden="true"')
  })

  it.each([
    {
      name: '組織',
      Page: OrganizationsPage,
      details: '目前可唯讀瀏覽已同步的組織與共享項目',
      removedHeadline: 'Bitwarden Organizations'
    },
    {
      name: 'Emergency Access',
      Page: EmergencyAccessPage,
      details: '目前僅可檢視 Emergency Access',
      removedHeadline: 'Bitwarden Emergency Access'
    },
    {
      name: 'Sends',
      Page: SendsPage,
      details: '文字與檔案 Send 的主要流程已可使用',
      removedHeadline: 'Bitwarden Send'
    }
  ])(
    'marks the $name page as under construction without a headline',
    ({ Page, details, removedHeadline }) => {
      const markup = renderToStaticMarkup(<Page />)

      expect(markup).toContain('施工中')
      expect(markup).toContain(details)
      expect(markup).not.toContain(removedHeadline)
    }
  )
})
