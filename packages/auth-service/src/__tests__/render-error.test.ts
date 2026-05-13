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

  describe('options object form', () => {
    // The function accepts either a title string (legacy) or an options
    // object with title / startOverHref / startOverLabel. Both paths are
    // production callers — exercise them explicitly so a future signature
    // change can't silently drop one.

    it('accepts an options object with title', () => {
      const html = renderError('msg', { title: 'Custom' })
      expect(html).toContain('<title>Custom</title>')
      expect(html).toContain('<h1>Custom</h1>')
    })

    it('falls back to "Error" when options has no title', () => {
      const html = renderError('msg', {})
      expect(html).toContain('<title>Error</title>')
    })

    it('renders a Start Over button when startOverHref is set', () => {
      const html = renderError('msg', {
        startOverHref: 'https://demo.example/sign-in',
      })
      expect(html).toContain('class="start-over"')
      expect(html).toContain('href="https://demo.example/sign-in"')
      expect(html).toContain('rel="noopener noreferrer"')
      // Default label
      expect(html).toContain('>Start over</a>')
    })

    it('uses the provided startOverLabel', () => {
      const html = renderError('msg', {
        startOverHref: 'https://demo.example/',
        startOverLabel: 'Return to sign in',
      })
      expect(html).toContain('>Return to sign in</a>')
    })

    it('omits the Start Over button when no href is given', () => {
      const html = renderError('msg', { title: 'X' })
      expect(html).not.toContain('class="start-over"')
    })

    it('rejects a startOverHref with javascript: scheme', () => {
      // Defence-in-depth: escapeHtml does NOT neutralise javascript:
      // URLs (no escape-sensitive chars), so the shared renderer must
      // refuse to inline them. Auth-service inherits that protection
      // by passing options straight through.
      const html = renderError('msg', { startOverHref: 'javascript:alert(1)' })
      expect(html).not.toContain('class="start-over"')
      expect(html).not.toContain('javascript:')
    })

    it('rejects a startOverHref with file: scheme', () => {
      const html = renderError('msg', { startOverHref: 'file:///etc/passwd' })
      expect(html).not.toContain('class="start-over"')
      expect(html).not.toContain('file:')
    })

    it('rejects a malformed startOverHref', () => {
      const html = renderError('msg', { startOverHref: 'not a url' })
      expect(html).not.toContain('class="start-over"')
    })

    it('still escapes HTML in startOverLabel even though the scheme has been validated', () => {
      const html = renderError('msg', {
        startOverHref: 'https://demo.example/',
        startOverLabel: '<script>alert(1)</script>',
      })
      expect(html).toContain('class="start-over"')
      expect(html).not.toContain('<script>alert(1)</script>')
      expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
    })
  })
})
