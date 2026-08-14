import { describe, it, expect } from 'vitest'
import { pickOtpVerifyErrorMessage } from '../lib/otp-verify-error.js'

// Expected user-facing messages for each error class. Lifted to
// constants so the tests don't repeat the exact copy at every call
// site (Sonar flags >3% line duplication on new code).
const RESEND_MSG =
  'That code can no longer be used. Click "Resend code" below to get a fresh one.'
const TYPO_MSG = 'Invalid code. Please try again.'
const FALLBACK_MSG = 'Verification failed. Please try again.'

describe('pickOtpVerifyErrorMessage', () => {
  // The OTP verify flows (account-login, recovery) surface three
  // distinct error states through their server-rendered OTP forms.
  // The user-facing copy must distinguish them — typing more in
  // an unrecoverable state just rolls up failed attempts that
  // could never succeed.

  it.each([
    ['Too many attempts', RESEND_MSG],
    ['OTP expired', RESEND_MSG],
    ['Too many attempts on this code', RESEND_MSG],
    ['TOO MANY ATTEMPTS', RESEND_MSG], // case-insensitive
  ])(
    'points the user at Resend on lockout/aged-out: %s',
    (errMessage, expected) => {
      expect(pickOtpVerifyErrorMessage(new Error(errMessage))).toBe(expected)
    },
  )

  it('asks the user to re-type on a typo', () => {
    expect(pickOtpVerifyErrorMessage(new Error('Invalid OTP'))).toBe(TYPO_MSG)
  })

  it('falls back to generic verification-failed on unknown errors', () => {
    expect(
      pickOtpVerifyErrorMessage(new Error('Internal database problem')),
    ).toBe(FALLBACK_MSG)
  })

  it.each([['string-thrown'], [null], [undefined]])(
    'falls back to generic verification-failed on non-Error rejections (%p)',
    (err) => {
      expect(pickOtpVerifyErrorMessage(err)).toBe(FALLBACK_MSG)
    },
  )
})
