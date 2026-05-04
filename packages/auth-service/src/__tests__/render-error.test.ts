import { describe, it, expect } from 'vitest'

import { renderError } from '../lib/render-error.js'

describe('renderError', () => {
  it('produces an HTML document with default title', () => {
    const html = renderError('Something went wrong')
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true)
    expect(html).toContain('<title>Error</title>')
    expect(html).toContain('<h1>Error</h1>')
    expect(html).toContain('Something went wrong')
  })

  it('uses the provided title', () => {
    const html = renderError('Nope', 'Access Denied')
    expect(html).toContain('<title>Access Denied</title>')
    expect(html).toContain('<h1>Access Denied</h1>')
  })

  it('escapes HTML in the message', () => {
    const html = renderError('<script>alert(1)</script>')
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('escapes HTML in the title', () => {
    const html = renderError('msg', '<img src=x onerror=alert(1)>')
    expect(html).not.toContain('<img src=x onerror=alert(1)>')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })

  it('includes inline styles', () => {
    const html = renderError('x')
    expect(html).toMatch(/<style>[\s\S]*\.container[\s\S]*<\/style>/)
  })
})
