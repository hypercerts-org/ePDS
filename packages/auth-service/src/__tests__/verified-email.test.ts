import { describe, expect, it } from 'vitest'
import { hasVerifiedEmail } from '../lib/verified-email.js'

describe('hasVerifiedEmail', () => {
  it('is true for a boolean true', () => {
    expect(hasVerifiedEmail({ emailVerified: true })).toBe(true)
  })

  it.each([false, 'true', 'false', 1, 0, null, undefined, {}])(
    'is false for %j',
    (emailVerified) => {
      expect(hasVerifiedEmail({ emailVerified })).toBe(false)
    },
  )

  it('is false for no user', () => {
    expect(hasVerifiedEmail(null)).toBe(false)
    expect(hasVerifiedEmail(undefined)).toBe(false)
  })
})
