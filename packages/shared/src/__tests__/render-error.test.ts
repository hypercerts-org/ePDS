/**
 * Tests for the shared `renderError` template. Exercised here from
 * the source path (`../render-error.js` resolves to
 * `packages/shared/src/render-error.ts` under vitest's source-tree
 * coverage instrumentation) — the auth-service / pds-core tests go
 * through the package's compiled `dist/` and therefore don't count
 * for shared's coverage. This file is the source of truth for the
 * template's behaviour.
 */
import { describe, it, expect } from 'vitest'
import { renderError, ERROR_CSS } from '../render-error.js'

describe('renderError — basic shape', () => {
  it('produces an HTML document with default title', () => {
    const html = renderError('Something went wrong')
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true)
    expect(html).toContain('<title>Error</title>')
    expect(html).toContain('<h1>Error</h1>')
    expect(html).toContain('Something went wrong')
  })

  it('uses the provided title', () => {
    const html = renderError('Nope', { title: 'Access Denied' })
    expect(html).toContain('<title>Access Denied</title>')
    expect(html).toContain('<h1>Access Denied</h1>')
  })

  it('escapes HTML in the message', () => {
    const html = renderError('<script>alert(1)</script>')
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('escapes HTML in the title', () => {
    const html = renderError('msg', { title: '<img src=x onerror=alert(1)>' })
    expect(html).not.toContain('<img src=x onerror=alert(1)>')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })

  it('includes the inline ERROR_CSS', () => {
    const html = renderError('x')
    expect(html).toContain(ERROR_CSS)
  })

  it('appends extraCss after ERROR_CSS', () => {
    const html = renderError('x', { extraCss: '.custom { color: red }' })
    expect(html).toContain('.custom { color: red }')
    expect(html.indexOf(ERROR_CSS)).toBeLessThan(
      html.indexOf('.custom { color: red }'),
    )
  })

  it('inserts bodyExtra after the .container', () => {
    const html = renderError('x', { bodyExtra: '<footer>powered by</footer>' })
    expect(html).toContain('<footer>powered by</footer>')
    // Not inside the .container — comes AFTER it.
    expect(html.indexOf('</div>')).toBeLessThan(
      html.indexOf('<footer>powered by</footer>'),
    )
  })
})

describe('renderError — Start Over button', () => {
  it('renders the button when startOverHref is set', () => {
    const html = renderError('msg', {
      startOverHref: 'https://demo.example/sign-in',
    })
    expect(html).toContain('class="start-over"')
    expect(html).toContain('href="https://demo.example/sign-in"')
    expect(html).toContain('rel="noopener noreferrer"')
    expect(html).toContain('>Start over</a>')
  })

  it('uses the provided startOverLabel', () => {
    const html = renderError('msg', {
      startOverHref: 'https://demo.example/',
      startOverLabel: 'Return to sign in',
    })
    expect(html).toContain('>Return to sign in</a>')
  })

  it('omits the button when no href is given', () => {
    const html = renderError('msg', {})
    expect(html).not.toContain('class="start-over"')
  })

  it('omits the button when startOverHref is undefined', () => {
    const html = renderError('msg', { startOverHref: undefined })
    expect(html).not.toContain('class="start-over"')
  })

  it('rejects javascript: scheme', () => {
    // The whole point of normaliseStartOverHref — escapeHtml does
    // NOT neutralise `javascript:` URLs because they contain no
    // escape-sensitive characters, so the renderer must refuse to
    // inline them at parse time.
    const html = renderError('msg', { startOverHref: 'javascript:alert(1)' })
    expect(html).not.toContain('class="start-over"')
    expect(html).not.toContain('javascript:')
  })

  it('rejects data: scheme', () => {
    const html = renderError('msg', {
      startOverHref: 'data:text/html,<script>alert(1)</script>',
    })
    expect(html).not.toContain('class="start-over"')
  })

  it('rejects file: scheme', () => {
    const html = renderError('msg', { startOverHref: 'file:///etc/passwd' })
    expect(html).not.toContain('class="start-over"')
  })

  it('rejects unparseable URLs', () => {
    const html = renderError('msg', { startOverHref: 'not a url' })
    expect(html).not.toContain('class="start-over"')
  })

  it('accepts http://', () => {
    const html = renderError('msg', {
      startOverHref: 'http://localhost:3002/',
    })
    expect(html).toContain('href="http://localhost:3002/"')
  })

  it('escapes HTML in startOverLabel', () => {
    const html = renderError('msg', {
      startOverHref: 'https://demo.example/',
      startOverLabel: '<script>alert(1)</script>',
    })
    expect(html).toContain('class="start-over"')
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('escapes HTML in startOverHref before inlining (defence in depth)', () => {
    // A URL like `https://demo.example/?x="><script>alert(1)</script>` is
    // technically valid (URL constructor accepts it) but the rendered
    // attribute must not break out into HTML. escapeHtml runs after
    // normalisation, so the attribute value stays quoted.
    const html = renderError('msg', {
      startOverHref: 'https://demo.example/?x=%22%3E%3Cscript%3E',
    })
    expect(html).toContain('class="start-over"')
    expect(html).not.toContain('"><script>')
  })
})
