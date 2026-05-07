import { describe, it, expect } from 'vitest'
import { pickOtpVerifyErrorMessage } from '../lib/otp-verify-error.js'

describe('pickOtpVerifyErrorMessage', () => {
  // The standalone /account/login flow surfaces three distinct
  // error states through its server-rendered OTP form. The user-
  // facing copy must distinguish them, otherwise typing more in
  // an unrecoverable state just rolls up failed attempts that
  // could never succeed.

  it('points the user at Resend when the row was locked out', () => {
    const err = new Error('Too many attempts')
    expect(pickOtpVerifyErrorMessage(err)).toBe(
      'That code can no longer be used. Click "Resend code" below to get a fresh one.',
    )
  })

  it('points the user at Resend when the OTP has expired', () => {
    const err = new Error('OTP expired')
    expect(pickOtpVerifyErrorMessage(err)).toBe(
      'That code can no longer be used. Click "Resend code" below to get a fresh one.',
    )
  })

  it('asks the user to re-type on a typo', () => {
    const err = new Error('Invalid OTP')
    expect(pickOtpVerifyErrorMessage(err)).toBe(
      'Invalid code. Please try again.',
    )
  })

  it('falls back to a generic verification-failed message on unknown errors', () => {
    const err = new Error('Internal database problem')
    expect(pickOtpVerifyErrorMessage(err)).toBe(
      'Verification failed. Please try again.',
    )
  })

  it('handles non-Error rejections gracefully', () => {
    expect(pickOtpVerifyErrorMessage('string-thrown')).toBe(
      'Verification failed. Please try again.',
    )
    expect(pickOtpVerifyErrorMessage(null)).toBe(
      'Verification failed. Please try again.',
    )
    expect(pickOtpVerifyErrorMessage(undefined)).toBe(
      'Verification failed. Please try again.',
    )
  })

  it('matches the lockout pattern case-insensitively', () => {
    // better-auth's INVALID_OTP / OTP_EXPIRED / TOO_MANY_ATTEMPTS
    // strings come through as English fixed text — the function
    // lowercases the message before matching, so capitalisation
    // shouldn't matter.
    expect(pickOtpVerifyErrorMessage(new Error('TOO MANY ATTEMPTS'))).toBe(
      'That code can no longer be used. Click "Resend code" below to get a fresh one.',
    )
  })
})
