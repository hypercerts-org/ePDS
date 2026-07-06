/**
 * Tests for logBetterAuthApiError — the bridge that surfaces better-auth's
 * 4xx client errors (notably "OTP expired" vs "Invalid OTP") in our pino logs.
 *
 * These are exactly the errors better-auth throws from its email-otp verify
 * endpoint (better-auth 1.4.18 dist/plugins/email-otp/routes.mjs), which the
 * browser posts to directly and which were previously logged nowhere.
 */
import { describe, it, expect, vi } from 'vitest'
import { APIError } from 'better-auth/api'
import { logBetterAuthApiError } from '../better-auth.js'

/** Minimal stand-in for the pino logger — only `warn` is exercised. */
function makeLogger() {
  return { warn: vi.fn() } as unknown as Parameters<
    typeof logBetterAuthApiError
  >[1]
}

describe('logBetterAuthApiError', () => {
  it('logs an expired-OTP error at warn with the reason', () => {
    const log = makeLogger()
    logBetterAuthApiError(
      new APIError('BAD_REQUEST', { message: 'OTP expired' }),
      log,
    )

    expect(log.warn).toHaveBeenCalledOnce()
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'BAD_REQUEST',
        statusCode: 400,
        message: 'OTP expired',
      }),
      'better-auth API error',
    )
  })

  it('logs an invalid-OTP error at warn, distinct from expiry', () => {
    const log = makeLogger()
    logBetterAuthApiError(
      new APIError('BAD_REQUEST', { message: 'Invalid OTP' }),
      log,
    )

    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 400, message: 'Invalid OTP' }),
      'better-auth API error',
    )
  })

  it('logs a 403 too-many-attempts error at warn', () => {
    const log = makeLogger()
    logBetterAuthApiError(
      new APIError('FORBIDDEN', { message: 'Too many attempts' }),
      log,
    )

    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'FORBIDDEN',
        statusCode: 403,
        message: 'Too many attempts',
      }),
      'better-auth API error',
    )
  })

  it('falls back to error.message when the body has no message', () => {
    const log = makeLogger()
    const err = new APIError('BAD_REQUEST')
    err.message = 'bare message'
    logBetterAuthApiError(err, log)

    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'bare message' }),
      'better-auth API error',
    )
  })

  it('ignores 5xx errors (already logged by better-auth itself)', () => {
    const log = makeLogger()
    logBetterAuthApiError(
      new APIError('INTERNAL_SERVER_ERROR', { message: 'boom' }),
      log,
    )

    expect(log.warn).not.toHaveBeenCalled()
  })

  it('ignores 3xx redirects', () => {
    const log = makeLogger()
    logBetterAuthApiError(new APIError('FOUND'), log)

    expect(log.warn).not.toHaveBeenCalled()
  })

  it('ignores non-APIError values', () => {
    const log = makeLogger()
    logBetterAuthApiError(new Error('some other failure'), log)
    logBetterAuthApiError('a string', log)
    logBetterAuthApiError(undefined, log)

    expect(log.warn).not.toHaveBeenCalled()
  })
})
