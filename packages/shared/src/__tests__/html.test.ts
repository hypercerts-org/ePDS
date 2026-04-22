import { describe, it, expect } from 'vitest'
import {
  escapeHtml,
  maskEmail,
  formatOtpPlain,
  formatOtpHtmlGrouped,
} from '../html.js'

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
  it.each([
    [
      'masks every segment including the TLD',
      'john@example.com',
      '***n@***e.***m',
    ],
    [
      'masks each dot-separated segment of the local part independently',
      'persons.address@gmail.com',
      '***s.***s@***l.***m',
    ],
    ['masks a short local part (2 chars)', 'ab@example.com', '***b@***e.***m'],
    ['masks a single char local part', 'a@example.com', '***@***e.***m'],
    ['masks a single char domain segment', 'user@a.co', '***r@***.***o'],
    [
      'handles long local parts without leaking length',
      'longusername@test.com',
      '***e@***t.***m',
    ],
    ['handles multi-level TLDs', 'alice@example.co.uk', '***e@***e.***o.***k'],
    ['returns invalid email unchanged (no @)', 'not-an-email', 'not-an-email'],
    [
      'returns invalid email unchanged (empty local)',
      '@example.com',
      '@example.com',
    ],
    ['returns invalid email unchanged (empty domain)', 'user@', 'user@'],
  ])('%s', (_desc, input, expected) => {
    expect(maskEmail(input)).toBe(expected)
  })
})

describe('formatOtpPlain', () => {
  it('returns codes shorter than 8 chars as-is', () => {
    expect(formatOtpPlain('1234')).toBe('1234')
  })

  it('returns a 7-char code as-is (just under the threshold)', () => {
    expect(formatOtpPlain('1234567')).toBe('1234567')
  })

  it('groups an 8-char code into two groups of 4', () => {
    expect(formatOtpPlain('12345678')).toBe('1234 5678')
  })

  it('groups a 9-char code into three groups of 3', () => {
    expect(formatOtpPlain('123456789')).toBe('123 456 789')
  })

  it('groups a 12-char code into three groups of 4', () => {
    expect(formatOtpPlain('123456789012')).toBe('1234 5678 9012')
  })

  it('returns a length-10 code as-is (does not divide evenly by 4 or 3)', () => {
    expect(formatOtpPlain('1234567890')).toBe('1234567890')
  })

  it('returns a length-11 code as-is (does not divide evenly by 4 or 3)', () => {
    expect(formatOtpPlain('12345678901')).toBe('12345678901')
  })
})

describe('formatOtpHtmlGrouped', () => {
  it('returns codes shorter than 8 chars as an escaped flat string', () => {
    expect(formatOtpHtmlGrouped('1234')).toBe('1234')
  })

  it('wraps an 8-char code in two spans, second with padding-left', () => {
    expect(formatOtpHtmlGrouped('12345678')).toBe(
      '<span>1234</span><span style="padding-left:0.35em">5678</span>',
    )
  })

  it('wraps a 9-char code in three spans, second and third with padding-left', () => {
    expect(formatOtpHtmlGrouped('123456789')).toBe(
      '<span>123</span>' +
        '<span style="padding-left:0.35em">456</span>' +
        '<span style="padding-left:0.35em">789</span>',
    )
  })

  it('wraps a 12-char code in three groups of 4', () => {
    expect(formatOtpHtmlGrouped('123456789012')).toBe(
      '<span>1234</span>' +
        '<span style="padding-left:0.35em">5678</span>' +
        '<span style="padding-left:0.35em">9012</span>',
    )
  })

  it('returns a length-10 code as a flat escaped string (no grouping)', () => {
    expect(formatOtpHtmlGrouped('1234567890')).toBe('1234567890')
  })

  it('escapes < in a short code (XSS, no grouping path)', () => {
    expect(formatOtpHtmlGrouped('<script')).toBe('&lt;script')
  })

  it('escapes & in a short code (XSS, no grouping path)', () => {
    expect(formatOtpHtmlGrouped('a&b')).toBe('a&amp;b')
  })

  it('escapes < inside grouped spans (XSS, grouping path)', () => {
    // 8 chars containing '<' — grouping applies, chunks must be escaped
    expect(formatOtpHtmlGrouped('1234<678')).toBe(
      '<span>1234</span><span style="padding-left:0.35em">&lt;678</span>',
    )
  })

  it('escapes & inside grouped spans (XSS, grouping path)', () => {
    expect(formatOtpHtmlGrouped('1234&678')).toBe(
      '<span>1234</span><span style="padding-left:0.35em">&amp;678</span>',
    )
  })
})
