import { describe, it, expect } from 'vitest'
import { maskEmail } from '../lib/mask-email.js'

describe('maskEmail', () => {
  it.each([
    ['a@example.com', '***@example.com'],
    ['ab@example.com', '***@example.com'],
    ['abc@example.com', 'a***@example.com'],
    ['abcd@example.com', 'a***@example.com'],
    ['abcde@example.com', 'ab***@example.com'],
    ['alice.private@example.com', 'al***@example.com'],
  ])('%s → %s', (email, expected) => {
    expect(maskEmail(email)).toBe(expected)
  })

  it('never reveals more than about half of the local part', () => {
    for (let length = 1; length <= 12; length++) {
      const label = maskEmail(`${'x'.repeat(length)}@example.com`)
      const visible = label.indexOf('***')
      expect(visible * 2).toBeLessThanOrEqual(length)
    }
  })

  it('gives short local parts the same label whatever their characters', () => {
    // With the domain visible, a label that varies with a 1-2 character
    // local part would let anyone read the address straight off the page.
    expect(maskEmail('ab@example.com')).toBe(maskEmail('zq@example.com'))
    expect(maskEmail('a@example.com')).toBe(maskEmail('z@example.com'))
  })

  it('treats everything after the last @ as the domain', () => {
    // A quoted local part may contain '@'; none of it may show as "domain".
    const label = maskEmail('"a@bc"@example.com')
    expect(label).toBe('"a***@example.com')
    expect(label).not.toContain('bc')
  })

  it('counts characters, not UTF-16 units, so it never splits a pair', () => {
    expect(maskEmail('😀😀😀😀😀@example.com')).toBe('😀😀***@example.com')
  })

  it('reveals nothing when there is no usable local part', () => {
    expect(maskEmail('not-an-email')).toBe('***')
    expect(maskEmail('@example.com')).toBe('***')
  })
})
