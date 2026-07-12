/**
 * Tests for logOtpVerificationFailure — the bridge that surfaces better-auth's
 * 4xx OTP verification errors ("OTP expired" vs "Invalid OTP" vs "Too many
 * attempts") in our pino logs, with the user's email attached.
 *
 * These are exactly the errors better-auth throws from its email-otp verify
 * endpoint (better-auth 1.4.18 dist/plugins/email-otp/routes.mjs), which the
 * browser posts to directly and which were previously logged nowhere.
 */
import { describe, it, expect, vi } from 'vitest'
import { APIError } from 'better-auth/api'
import { isOtpVerifyPath, logOtpVerificationFailure } from '../better-auth.js'

const PATH = '/sign-in/email-otp'

/** Minimal stand-in for the pino logger — only `info` and `warn` are used. */
function makeLogger() {
  return { info: vi.fn(), warn: vi.fn() } as unknown as Parameters<
    typeof logOtpVerificationFailure
  >[3]
}

describe('logOtpVerificationFailure', () => {
  it('maps an expired-OTP error to a self-contained message with the email', () => {
    const log = makeLogger()
    const error = new APIError('BAD_REQUEST', { message: 'OTP expired' })
    logOtpVerificationFailure(error, 'alice@example.com', PATH, log)

    expect(log.info).toHaveBeenCalledOnce()
    expect(log.info).toHaveBeenCalledWith(
      { email: 'alice@example.com', statusCode: 400, path: PATH },
      'OTP verification failed: code expired',
    )
    expect(log.warn).not.toHaveBeenCalled()
  })

  it('maps an invalid-OTP error, distinct from expiry', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new APIError('BAD_REQUEST', { message: 'Invalid OTP' }),
      'bob@example.com',
      PATH,
      log,
    )

    expect(log.info).toHaveBeenCalledWith(
      { email: 'bob@example.com', statusCode: 400, path: PATH },
      'OTP verification failed: invalid or unrecognized code',
    )
  })

  it('logs a 403 too-many-attempts error at warn (possible abuse signal)', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new APIError('FORBIDDEN', { message: 'Too many attempts' }),
      'carol@example.com',
      PATH,
      log,
    )

    expect(log.warn).toHaveBeenCalledWith(
      { email: 'carol@example.com', statusCode: 403, path: PATH },
      'OTP verification failed: too many attempts, code invalidated',
    )
    expect(log.info).not.toHaveBeenCalled()
  })

  it('logs the broad-scope path verbatim in the path field', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new APIError('BAD_REQUEST', { message: 'Invalid OTP' }),
      'dave@example.com',
      '/email-otp/reset-password',
      log,
    )

    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({ path: '/email-otp/reset-password' }),
      'OTP verification failed: invalid or unrecognized code',
    )
  })

  it('falls back to the prefixed reason for an unmapped 4xx reason', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new APIError('BAD_REQUEST', { message: 'Some other reason' }),
      'eve@example.com',
      PATH,
      log,
    )

    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'eve@example.com', statusCode: 400 }),
      'OTP verification failed: Some other reason',
    )
  })

  it('logs email as undefined when the body had no email', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new APIError('BAD_REQUEST', { message: 'Invalid OTP' }),
      undefined,
      PATH,
      log,
    )

    expect(log.info).toHaveBeenCalledWith(
      { email: undefined, statusCode: 400, path: PATH },
      'OTP verification failed: invalid or unrecognized code',
    )
  })

  it('ignores 5xx errors (already logged by better-auth itself)', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new APIError('INTERNAL_SERVER_ERROR', { message: 'boom' }),
      'alice@example.com',
      PATH,
      log,
    )

    expect(log.warn).not.toHaveBeenCalled()
    expect(log.info).not.toHaveBeenCalled()
  })

  it('ignores 3xx redirects', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new APIError('FOUND'),
      'alice@example.com',
      PATH,
      log,
    )

    expect(log.warn).not.toHaveBeenCalled()
    expect(log.info).not.toHaveBeenCalled()
  })

  it('ignores non-APIError values (e.g. a successful response)', () => {
    const log = makeLogger()
    logOtpVerificationFailure(
      new Error('some other failure'),
      'a@x.com',
      PATH,
      log,
    )
    logOtpVerificationFailure({ token: 'ok' }, 'a@x.com', PATH, log)
    logOtpVerificationFailure(undefined, 'a@x.com', PATH, log)

    expect(log.warn).not.toHaveBeenCalled()
    expect(log.info).not.toHaveBeenCalled()
  })
})

describe('isOtpVerifyPath', () => {
  it('matches the OTP verification endpoints', () => {
    expect(isOtpVerifyPath('/sign-in/email-otp')).toBe(true)
    expect(isOtpVerifyPath('/email-otp/check-verification-otp')).toBe(true)
    expect(isOtpVerifyPath('/email-otp/verify-email')).toBe(true)
    expect(isOtpVerifyPath('/email-otp/reset-password')).toBe(true)
  })

  it('excludes the OTP send endpoints (a send failure is not a verification failure)', () => {
    expect(isOtpVerifyPath('/email-otp/send-verification-otp')).toBe(false)
    expect(isOtpVerifyPath('/email-otp/request-password-reset')).toBe(false)
  })

  it('excludes unrelated endpoints', () => {
    expect(isOtpVerifyPath('/sign-in/social')).toBe(false)
    expect(isOtpVerifyPath('/callback/google')).toBe(false)
  })
})
