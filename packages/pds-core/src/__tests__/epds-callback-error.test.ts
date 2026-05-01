import { describe, expect, it, vi } from 'vitest'
import type { Response } from 'express'
import {
  EXPIRED_PAR_MESSAGE_PATTERN,
  classifyCallbackError,
  handleCallbackError,
} from '../lib/epds-callback-error.js'

const PDS_URL = 'https://pds.example'
const REDIRECT_URI = 'https://demo.example/api/oauth/callback'
const STATE = 'XNMi-ebr4JAUAEWa-52HEA'

const TIMEOUT_DESCRIPTION =
  'Your sign-in took too long to complete and timed out. Please start sign-in again.'
const SERVER_DESCRIPTION = 'Authentication failed.'

/** Build a minimal Response double that records the calls
 *  handleCallbackError makes on it. Untouched by middleware, so reset
 *  per test. */
function makeResStub() {
  let headersSent = false
  const headers: Record<string, string> = {}
  let statusCode: number | undefined
  let contentType: string | undefined
  let body: string | undefined
  let redirectStatus: number | undefined
  let redirectLocation: string | undefined

  const res = {
    get headersSent() {
      return headersSent
    },
    setHeader(name: string, value: string) {
      headers[name.toLowerCase()] = value
      return res
    },
    status(code: number) {
      statusCode = code
      return res
    },
    type(t: string) {
      contentType = t
      return res
    },
    send(s: string) {
      body = s
      headersSent = true
      return res
    },
    redirect(status: number, location: string) {
      redirectStatus = status
      redirectLocation = location
      headersSent = true
    },
    /** Pretend an earlier middleware already sent something — drives
     *  the no-op branch. */
    forceHeadersSent() {
      headersSent = true
    },
  } as unknown as Response & { forceHeadersSent: () => void }

  return {
    res,
    inspect: () => ({
      headers,
      statusCode,
      contentType,
      body,
      redirectStatus,
      redirectLocation,
    }),
  }
}

describe('EXPIRED_PAR_MESSAGE_PATTERN', () => {
  it.each([
    'This request has expired',
    'Unknown request_uri',
    'invalid_grant',
    'something has expired',
    // Case-insensitive
    'INVALID_GRANT',
  ])('matches dead-PAR message: %s', (msg) => {
    expect(EXPIRED_PAR_MESSAGE_PATTERN.test(msg)).toBe(true)
  })

  it.each([
    'Database connection refused',
    'Account not found',
    'Internal server error',
    '',
  ])('does not match unrelated message: %s', (msg) => {
    expect(EXPIRED_PAR_MESSAGE_PATTERN.test(msg)).toBe(false)
  })
})

describe('classifyCallbackError', () => {
  it.each([
    {
      label: 'AccessDeniedError("This request has expired")',
      message: 'This request has expired',
    },
    {
      label: 'InvalidRequestError("Unknown request_uri")',
      message: 'Unknown request_uri',
    },
    { label: 'invalid_grant', message: 'invalid_grant' },
  ])('classifies $label as expired', ({ message }) => {
    expect(classifyCallbackError(new Error(message))).toEqual({
      code: 'access_denied',
      description: TIMEOUT_DESCRIPTION,
      isExpired: true,
    })
  })

  it('classifies a generic failure as server_error', () => {
    const err = new Error('Database connection refused')
    expect(classifyCallbackError(err)).toEqual({
      code: 'server_error',
      description: SERVER_DESCRIPTION,
      isExpired: false,
    })
  })

  it('handles non-Error thrown values by stringifying them', () => {
    expect(classifyCallbackError('something has expired')).toEqual({
      code: 'access_denied',
      description: TIMEOUT_DESCRIPTION,
      isExpired: true,
    })
    expect(classifyCallbackError({ code: 'oops' })).toEqual({
      code: 'server_error',
      description: SERVER_DESCRIPTION,
      isExpired: false,
    })
  })
})

/** Shared driver for handleCallbackError tests. Lifts the response
 *  stub + spies + the seven-field options object into a single call so
 *  individual tests only have to spell out what's varying (the error,
 *  the captured redirect_uri/state, optionally a forceHeadersSent
 *  override). Returns the inspect snapshot plus the spies, so tests
 *  can assert on response state, the renderError contract, and the
 *  logger contract from one call site. */
function invoke(opts: {
  err: unknown
  capturedRedirectUri?: string
  capturedState?: string
  forceHeadersSent?: boolean
}) {
  const { res, inspect } = makeResStub()
  if (opts.forceHeadersSent) {
    ;(res as Response & { forceHeadersSent: () => void }).forceHeadersSent()
  }
  const renderError = vi.fn((m: string) => `<html>${m}</html>`)
  const logger = { error: vi.fn(), warn: vi.fn() }
  handleCallbackError({
    res,
    err: opts.err,
    capturedRedirectUri: opts.capturedRedirectUri,
    capturedState: opts.capturedState,
    pdsUrl: PDS_URL,
    logger,
    renderError,
  })
  return { ...inspect(), renderError, logger }
}

describe('handleCallbackError — redirect path', () => {
  it('redirects with error=access_denied + timeout description on expired PAR', () => {
    const got = invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
    })
    expect(got.renderError).not.toHaveBeenCalled()
    const url = new URL(got.redirectLocation!)
    expect(url.origin + url.pathname).toBe(REDIRECT_URI)
    expect(url.searchParams.get('error')).toBe('access_denied')
    expect(url.searchParams.get('error_description')).toBe(TIMEOUT_DESCRIPTION)
    expect(url.searchParams.get('iss')).toBe(PDS_URL)
    expect(url.searchParams.get('state')).toBe(STATE)
  })

  it('redirects with error=server_error on unrelated failures', () => {
    const got = invoke({
      err: new Error('Database connection refused'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
    })
    const url = new URL(got.redirectLocation!)
    expect(url.searchParams.get('error')).toBe('server_error')
    expect(url.searchParams.get('error_description')).toBe(SERVER_DESCRIPTION)
    expect(url.searchParams.get('iss')).toBe(PDS_URL)
    expect(url.searchParams.get('state')).toBe(STATE)
  })

  it('omits state when none was captured', () => {
    const got = invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
    })
    const url = new URL(got.redirectLocation!)
    expect(url.searchParams.has('state')).toBe(false)
  })

  it('issues a 303 See Other so OAuth clients re-fetch with GET', () => {
    const got = invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
    })
    expect(got.redirectStatus).toBe(303)
  })

  it('marks the redirect non-cacheable so per-request state cannot be replayed', () => {
    const got = invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
    })
    expect(got.headers['cache-control']).toBe('no-store')
  })
})

describe('handleCallbackError — malformed captured redirect_uri', () => {
  // The redirect_uri is captured from an upstream-validated PAR row,
  // so this branch is defensive — but the catch block exists to spare
  // the user a 500, and a `new URL()` throw inside it would defeat
  // that purpose. Verify the malformed-URL path falls through to the
  // styled HTML page and logs the URL parse failure.
  it.each([
    'not a url at all',
    '://broken',
    '/relative/only',
    'https://[malformed-bracket',
  ])('falls back to HTML when capturedRedirectUri is %s', (badUri) => {
    const got = invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: badUri,
      capturedState: STATE,
    })
    // No redirect emitted.
    expect(got.redirectLocation).toBeUndefined()
    // HTML page served instead.
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
    expect(got.renderError).toHaveBeenCalledWith(TIMEOUT_DESCRIPTION)
    // The URL parse failure must be visible in operational logs.
    expect(got.logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ capturedRedirectUri: badUri }),
      expect.stringContaining('not a valid URL'),
    )
  })
})

describe('handleCallbackError — HTML fallback path', () => {
  it('renders a styled HTML page when no redirect_uri was captured (expired)', () => {
    const got = invoke({ err: new Error('This request has expired') })
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
    expect(got.renderError).toHaveBeenCalledWith(TIMEOUT_DESCRIPTION)
    expect(got.body).toContain(TIMEOUT_DESCRIPTION)
    expect(got.redirectLocation).toBeUndefined()
  })

  it('marks the HTML response non-cacheable', () => {
    const got = invoke({ err: new Error('This request has expired') })
    expect(got.headers['cache-control']).toBe('no-store')
  })

  it('renders a 500 HTML page on generic server failure with no redirect_uri', () => {
    const got = invoke({ err: new Error('Database connection refused') })
    expect(got.statusCode).toBe(500)
    expect(got.renderError).toHaveBeenCalledWith(SERVER_DESCRIPTION)
  })

  it('does NOT leak raw JSON {"error":"Authentication failed"}', () => {
    // Regression guard against the pre-fix behaviour. The body must
    // not parse as the legacy JSON error shape on either status path.
    for (const err of [
      new Error('This request has expired'),
      new Error('Database connection refused'),
    ]) {
      const got = invoke({ err })
      const body = got.body ?? ''
      expect(body.startsWith('{')).toBe(false)
      expect(body).not.toMatch(/^\s*\{\s*"error"/)
    }
  })
})

describe('handleCallbackError — already-responded short-circuit', () => {
  it('does nothing when headers were already sent', () => {
    const got = invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
      forceHeadersSent: true,
    })
    expect(got.redirectLocation).toBeUndefined()
    expect(got.body).toBeUndefined()
    expect(got.renderError).not.toHaveBeenCalled()
  })
})

describe('handleCallbackError — log levels', () => {
  // Expired PARs are an expected user-paced timeout, not a server
  // fault. They should land at warn so they stay in operational logs
  // but don't trigger error-level alerting once expiry becomes
  // routine in production.
  it('logs an expired-PAR failure at warn (not error)', () => {
    const got = invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
    })
    expect(got.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ err: expect.any(Error) }),
      expect.stringContaining('timed out'),
    )
    expect(got.logger.error).not.toHaveBeenCalled()
  })

  it('logs a generic server failure at error (not warn)', () => {
    const got = invoke({
      err: new Error('Database connection refused'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
    })
    expect(got.logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ err: expect.any(Error) }),
      'ePDS callback error',
    )
    expect(got.logger.warn).not.toHaveBeenCalled()
  })
})
