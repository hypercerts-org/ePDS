import { describe, expect, it } from 'vitest'
import { suggestEmailAddress } from '../lib/email-typo-guard.js'

describe('suggestEmailAddress', () => {
  it.each([
    ['person@gnail.com', 'person@gmail.com'],
    ['person@gmial.com', 'person@gmail.com'],
    ['person@gmail.coml', 'person@gmail.com'],
    ['person@hotmal.com', 'person@hotmail.com'],
    ['person@outlok.com', 'person@outlook.com'],
    ['person@yaho.com', 'person@yahoo.com'],
    ['person@iclod.com', 'person@icloud.com'],
  ])('suggests %s as %s', (email, expected) => {
    expect(suggestEmailAddress(email)).toBe(expected)
  })

  it('preserves the local part while normalising the suggested domain', () => {
    expect(suggestEmailAddress(' First.Last+tag@GMIAL.COM ')).toBe(
      'First.Last+tag@gmail.com',
    )
  })

  it.each([
    'person@gmail.com',
    'person@GMAIL.COM',
    'person@example.com',
    'person@proton.me',
    'person@gmx.com',
    'not-an-email',
    '@gmial.com',
    'person@',
    'person@@gmial.com',
  ])('does not guess a correction for %s', (email) => {
    expect(suggestEmailAddress(email)).toBeNull()
  })
})
