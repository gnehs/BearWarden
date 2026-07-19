import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import { Checkbox } from './checkbox'
import { Switch } from './switch'
import { Tabs, TabsList, TabsTrigger } from './tabs'

describe('motion-enabled UI primitives', () => {
  it('keeps the checkbox check path mounted for draw transitions', () => {
    const markup = renderToStaticMarkup(<Checkbox aria-label="測試勾選" checked={false} />)

    expect(markup).toContain('t-check')
    expect(markup).toContain('--check-len:23')
    expect(markup).toContain('<svg')
  })

  it('renders a distinct mark for an indeterminate checkbox', () => {
    const markup = renderToStaticMarkup(
      <Checkbox aria-label="部分勾選" checked={false} indeterminate />
    )

    expect(markup).toContain('aria-checked="mixed"')
    expect(markup).toContain('data-indeterminate')
    expect(markup).toContain('lucide-minus')
  })

  it('maps switch state onto the transitions.dev hooks', () => {
    const markup = renderToStaticMarkup(
      <Switch aria-label="測試開關" checked onCheckedChange={vi.fn()} />
    )

    expect(markup).toContain('t-toggle')
    expect(markup).toContain('data-on="true"')
    expect(markup).toContain('t-toggle-thumb')
    expect(markup).not.toContain('is-init')
  })

  it('enables sliding hooks only for opted-in horizontal tabs', () => {
    const horizontal = renderToStaticMarkup(
      <Tabs value="first">
        <TabsList sliding>
          <TabsTrigger value="first">第一個</TabsTrigger>
          <TabsTrigger value="second">第二個</TabsTrigger>
        </TabsList>
      </Tabs>
    )
    const vertical = renderToStaticMarkup(
      <Tabs value="first" orientation="vertical">
        <TabsList sliding>
          <TabsTrigger value="first">第一個</TabsTrigger>
          <TabsTrigger value="second">第二個</TabsTrigger>
        </TabsList>
      </Tabs>
    )

    expect(horizontal).toContain('t-tabs')
    expect(horizontal).toContain('t-tab')
    expect(vertical).not.toContain('t-tabs')
    expect(vertical).not.toContain('t-tab')
  })
})
