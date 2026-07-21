import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { Pencil } from 'lucide-react'

import { Card, CardContent, CardHeader, CardTitle } from './card'
import { Input } from './input'

describe('Card item variant', () => {
  it('scopes the item surface treatment without changing the default variant', () => {
    const itemMarkup = renderToStaticMarkup(
      <Card variant="item">
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
    const defaultMarkup = renderToStaticMarkup(<Card />)

    expect(itemMarkup).toContain('data-variant="item"')
    expect(itemMarkup).toContain('rounded-[14px]')
    expect(itemMarkup).not.toContain('overflow-hidden rounded-xl')
    expect(itemMarkup).toContain('ring-border/70')
    expect(itemMarkup).toContain('[--card-spacing:--spacing(3)]')
    expect(itemMarkup).toContain('[&amp;_[data-slot=input]]:h-9')
    expect(itemMarkup).toContain('group-data-[variant=item]/card:text-sm')
    expect(itemMarkup).toContain('group-data-[variant=item]/card:[&amp;_svg:not(')
    expect(itemMarkup).toContain(')]:size-4')
    expect(itemMarkup).toContain('data-slot="card-title"')
    expect(itemMarkup).toContain('data-slot="input"')
    expect(defaultMarkup).toContain('data-variant="default"')
    expect(defaultMarkup).toContain('rounded-xl')
    expect(defaultMarkup).not.toContain('data-variant="item"')
  })
})
