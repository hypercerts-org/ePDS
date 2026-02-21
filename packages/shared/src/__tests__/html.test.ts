import { describe, it, expect } from 'vitest'
import { escapeHtml, maskEmail } from '../html.js'

describe('escapeHtml', () => {
  it('escapes ampersands', () => {
    expect(escapeHtml('a & b')).toBe('a &amp; b')
  })

  it('escapes angle brackets', () => {
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;')
  })

  it('escapes double quotes', () => {
    expect(escapeHtml('say "hello"')).toBe('say &quot;hello&quot;')
  })

  it('escapes all special chars in one string', () => {
    expect(escapeHtml('<a href="x">a & b</a>')).toBe(
      '&lt;a href=&quot;x&quot;&gt;a &amp; b&lt;/a&gt;',
    )
  })

  it('returns plain strings unchanged', () => {
    expect(escapeHtml('hello world')).toBe('hello world')
  })

  it('handles empty string', () => {
    expect(escapeHtml('')).toBe('')
  })
})

describe('maskEmail', () => {
  it('masks a normal email', () => {
    expect(maskEmail('john@example.com')).toBe('j***n@example.com')
  })

  it('masks a short local part (2 chars)', () => {
    expect(maskEmail('ab@example.com')).toBe('a***@example.com')
  })

  it('masks a single char local part', () => {
    expect(maskEmail('a@example.com')).toBe('a***@example.com')
  })

  it('returns invalid email unchanged', () => {
    expect(maskEmail('not-an-email')).toBe('not-an-email')
  })

  it('handles long local parts', () => {
    expect(maskEmail('longusername@test.com')).toBe('l***e@test.com')
  })
})
