import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { Pencil } from 'lucide-react'

import { Card, CardContent, CardHeader, CardTitle } from './card'
import { Input } from './input'

describe('Card folder variant', () => {
  it('marks the folder variant and its tone without changing the default variant', () => {
    const folderMarkup = renderToStaticMarkup(
      <Card variant="folder" tone="amber">
        <CardHeader>
          <CardTitle>
            <Pencil aria-hidden="true" />
            Title
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Input aria-label="Title" />
        </CardContent>
      </Card>
    )
    const defaultMarkup = renderToStaticMarkup(<Card tone="amber" />)

    expect(folderMarkup).toContain('data-variant="folder"')
    expect(folderMarkup).toContain('data-tone="amber"')
    expect(folderMarkup).toContain('data-slot="card-title"')
    expect(folderMarkup).toContain('data-slot="input"')
    expect(defaultMarkup).toContain('data-variant="default"')
    expect(defaultMarkup).not.toContain('data-tone')
  })

  it('defaults folder cards to the neutral tone', () => {
    expect(renderToStaticMarkup(<Card variant="folder" />)).toContain('data-tone="neutral"')
  })
})
