import { describe, it, expect } from 'vitest'

import {
  renderFaviconTag,
  renderOptionalStyleTag,
} from '../lib/page-helpers.js'

describe('renderOptionalStyleTag', () => {
  it('returns empty string when css is undefined', () => {
    expect(renderOptionalStyleTag(undefined)).toBe('')
  })

  it('returns empty string when css is null', () => {
    expect(renderOptionalStyleTag(null)).toBe('')
  })

  it('returns empty string when css is empty', () => {
    expect(renderOptionalStyleTag('')).toBe('')
  })

  it('returns style tag when css is provided', () => {
    expect(renderOptionalStyleTag('body { color: red; }')).toBe(
      '\n  <style>body { color: red; }</style>',
    )
  })

  it('preserves css content verbatim', () => {
    const css = 'h1{font-size:20px} .x{content:"</style>"}'
    expect(renderOptionalStyleTag(css)).toBe(`\n  <style>${css}</style>`)
  })
})

describe('renderFaviconTag', () => {
  const LIGHT =
    '<link rel="icon" href="/static/favicon.svg" media="(prefers-color-scheme: light)" type="image/svg+xml">'
  const DARK =
    '<link rel="icon" href="/static/favicon-dark.svg" media="(prefers-color-scheme: dark)" type="image/svg+xml">'

  it('emits both light and dark <link> tags when no custom URL', () => {
    const out = renderFaviconTag(undefined)
    expect(out).toContain(LIGHT)
    expect(out).toContain(DARK)
  })

  it('emits both light and dark <link> tags when custom URL is null', () => {
    const out = renderFaviconTag(null)
    expect(out).toContain(LIGHT)
    expect(out).toContain(DARK)
  })

  it('emits both light and dark <link> tags when custom URL is empty', () => {
    const out = renderFaviconTag('')
    expect(out).toContain(LIGHT)
    expect(out).toContain(DARK)
  })

  it('emits a single bare <link> when only the light URL is set (no dark variant)', () => {
    expect(renderFaviconTag('https://cdn.example.com/favicon.svg')).toBe(
      '<link rel="icon" href="https://cdn.example.com/favicon.svg">',
    )
  })

  it('emits a single bare <link> when dark URL is null/undefined/empty', () => {
    const expected =
      '<link rel="icon" href="https://cdn.example.com/favicon.svg">'
    expect(renderFaviconTag('https://cdn.example.com/favicon.svg', null)).toBe(
      expected,
    )
    expect(
      renderFaviconTag('https://cdn.example.com/favicon.svg', undefined),
    ).toBe(expected)
    expect(renderFaviconTag('https://cdn.example.com/favicon.svg', '')).toBe(
      expected,
    )
  })

  it('emits two media-gated <link> tags when both light and dark URLs are set', () => {
    const out = renderFaviconTag(
      'https://app.example/favicon.svg',
      'https://app.example/favicon-dark.svg',
    )
    expect(out).toContain(
      '<link rel="icon" href="https://app.example/favicon.svg" media="(prefers-color-scheme: light)">',
    )
    expect(out).toContain(
      '<link rel="icon" href="https://app.example/favicon-dark.svg" media="(prefers-color-scheme: dark)">',
    )
  })

  it('falls back to default light+dark when light URL is missing, even if dark is set', () => {
    // Dark-only is meaningless: the light variant is the default/required
    // case, so we ignore a stray dark URL and emit the ePDS defaults.
    const out = renderFaviconTag(null, 'https://app.example/favicon-dark.svg')
    expect(out).toContain(LIGHT)
    expect(out).toContain(DARK)
    expect(out).not.toContain('https://app.example/favicon-dark.svg')
  })

  it('escapes the custom URL to prevent attribute-context injection', () => {
    const malicious = 'https://evil.example.com/"><script>alert(1)</script>'
    const out = renderFaviconTag(malicious)
    expect(out).not.toContain('<script>')
    expect(out).toContain('&quot;')
    expect(out).toContain('&gt;')
  })

  it('escapes both light and dark URLs in the dual-tag form', () => {
    const out = renderFaviconTag(
      'https://app.example/"><script>alert(1)</script>',
      'https://app.example/dark"><script>alert(2)</script>',
    )
    expect(out).not.toContain('<script>')
    expect((out.match(/&quot;/g) ?? []).length).toBeGreaterThanOrEqual(2)
  })
})
