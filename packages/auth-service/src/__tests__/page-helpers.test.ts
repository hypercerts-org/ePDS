import { describe, it, expect } from 'vitest'

import { renderOptionalStyleTag } from '../lib/page-helpers.js'

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
