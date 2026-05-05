import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { Response } from 'express'

// Mock `resolveClientMetadata` so the new signedClientId fallback path
// can drive happy/sad branches without standing up a real client
// metadata HTTP fetch. The mock is hoisted (vi.mock is statically
// applied at module-graph time) so it is in effect before the
// epds-callback-error module is imported below.
const resolveClientMetadataMock = vi.hoisted(() => vi.fn())
const resolveStartOverHrefMock = vi.hoisted(() => vi.fn())
vi.mock('@certified-app/shared', async (importActual) => {
  const actual = await importActual<Record<string, unknown>>()
  return {
    ...actual,
    resolveClientMetadata: resolveClientMetadataMock,
    resolveStartOverHref: resolveStartOverHrefMock,
  }
})

import {
  EXPIRED_PAR_MESSAGE_PATTERN,
  classifyCallbackError,
  handleCallbackError,
} from '../lib/epds-callback-error.js'

const PDS_URL = 'https://pds.example'
const REDIRECT_URI = 'https://demo.example/api/oauth/callback'
const STATE = 'XNMi-ebr4JAUAEWa-52HEA'
const CLIENT_ID = 'https://demo.example/client-metadata.json'

beforeEach(() => {
  resolveClientMetadataMock.mockReset()
  resolveStartOverHrefMock.mockReset()
})

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
async function invoke(opts: {
  err: unknown
  capturedRedirectUri?: string
  capturedState?: string
  signedClientId?: string
  forceHeadersSent?: boolean
}) {
  const { res, inspect } = makeResStub()
  if (opts.forceHeadersSent) {
    ;(res as Response & { forceHeadersSent: () => void }).forceHeadersSent()
  }
  const renderError = vi.fn((m: string) => `<html>${m}</html>`)
  const logger = { error: vi.fn(), warn: vi.fn() }
  await handleCallbackError({
    res,
    err: opts.err,
    capturedRedirectUri: opts.capturedRedirectUri,
    capturedState: opts.capturedState,
    signedClientId: opts.signedClientId,
    pdsUrl: PDS_URL,
    logger,
    renderError,
  })
  return { ...inspect(), renderError, logger }
}

describe('handleCallbackError — redirect path', () => {
  it('redirects with error=access_denied + timeout description on expired PAR', async () => {
    const got = await invoke({
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

  it('redirects with error=server_error on unrelated failures', async () => {
    const got = await invoke({
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

  it('omits state when none was captured', async () => {
    const got = await invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
    })
    const url = new URL(got.redirectLocation!)
    expect(url.searchParams.has('state')).toBe(false)
  })

  it('issues a 303 See Other so OAuth clients re-fetch with GET', async () => {
    const got = await invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
    })
    expect(got.redirectStatus).toBe(303)
  })

  it('marks the redirect non-cacheable so per-request state cannot be replayed', async () => {
    const got = await invoke({
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
  ])('falls back to HTML when capturedRedirectUri is %s', async (badUri) => {
    const got = await invoke({
      err: new Error('This request has expired'),
      capturedRedirectUri: badUri,
      capturedState: STATE,
    })
    // No redirect emitted.
    expect(got.redirectLocation).toBeUndefined()
    // HTML page served instead.
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
    expect(got.renderError).toHaveBeenCalledWith(
      TIMEOUT_DESCRIPTION,
      expect.any(Object),
    )
    // The URL parse failure must be visible in operational logs.
    expect(got.logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ capturedRedirectUri: badUri }),
      expect.stringContaining('not a valid URL'),
    )
  })
})

describe('handleCallbackError — HTML fallback path', () => {
  it('renders a styled HTML page when no redirect_uri was captured (expired)', async () => {
    const got = await invoke({ err: new Error('This request has expired') })
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
    expect(got.renderError).toHaveBeenCalledWith(
      TIMEOUT_DESCRIPTION,
      expect.any(Object),
    )
    expect(got.body).toContain(TIMEOUT_DESCRIPTION)
    expect(got.redirectLocation).toBeUndefined()
  })

  it('marks the HTML response non-cacheable', async () => {
    const got = await invoke({ err: new Error('This request has expired') })
    expect(got.headers['cache-control']).toBe('no-store')
  })

  it('renders a 500 HTML page on generic server failure with no redirect_uri', async () => {
    const got = await invoke({ err: new Error('Database connection refused') })
    expect(got.statusCode).toBe(500)
    expect(got.renderError).toHaveBeenCalledWith(
      SERVER_DESCRIPTION,
      expect.any(Object),
    )
  })

  it('does NOT leak raw JSON {"error":"Authentication failed"}', async () => {
    // Regression guard against the pre-fix behaviour. The body must
    // not parse as the legacy JSON error shape on either status path.
    for (const err of [
      new Error('This request has expired'),
      new Error('Database connection refused'),
    ]) {
      const got = await invoke({ err })
      const body = got.body ?? ''
      expect(body.startsWith('{')).toBe(false)
      expect(body).not.toMatch(/^\s*\{\s*"error"/)
    }
  })
})

describe('handleCallbackError — signedClientId fallback', () => {
  // When Step 2 inside /oauth/epds-callback throws, no
  // capturedRedirectUri / capturedState can be stashed (the PAR row
  // is gone in the same call that threw). The signed callback URL
  // carries `client_id` so this branch can resolve the client's
  // published metadata and recover redirect_uris[0]. State is
  // unrecoverable and the OAuth spec permits its absence on error.

  it('redirects to redirect_uris[0] when capturedRedirectUri is missing but signedClientId resolves', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: [REDIRECT_URI],
    })
    const got = await invoke({
      err: new Error('This request has expired'),
      signedClientId: CLIENT_ID,
    })
    expect(resolveClientMetadataMock).toHaveBeenCalledWith(CLIENT_ID)
    expect(got.renderError).not.toHaveBeenCalled()
    const url = new URL(got.redirectLocation!)
    expect(url.origin + url.pathname).toBe(REDIRECT_URI)
    expect(url.searchParams.get('error')).toBe('access_denied')
    expect(url.searchParams.get('error_description')).toBe(TIMEOUT_DESCRIPTION)
    expect(url.searchParams.get('iss')).toBe(PDS_URL)
    // No state — the original lived in the dead PAR.
    expect(url.searchParams.has('state')).toBe(false)
  })

  it('issues 303 + Cache-Control:no-store on the fallback redirect', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: [REDIRECT_URI],
    })
    const got = await invoke({
      err: new Error('This request has expired'),
      signedClientId: CLIENT_ID,
    })
    expect(got.redirectStatus).toBe(303)
    expect(got.headers['cache-control']).toBe('no-store')
  })

  it('falls back to HTML when signedClientId resolves but metadata has no redirect_uris', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({})
    const got = await invoke({
      err: new Error('This request has expired'),
      signedClientId: CLIENT_ID,
    })
    expect(got.redirectLocation).toBeUndefined()
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
    expect(got.renderError).toHaveBeenCalledWith(
      TIMEOUT_DESCRIPTION,
      expect.any(Object),
    )
    expect(got.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ signedClientId: CLIENT_ID }),
      expect.stringContaining('no usable redirect_uris'),
    )
  })

  it('falls back to HTML when client metadata lookup throws', async () => {
    resolveClientMetadataMock.mockRejectedValueOnce(new Error('network blip'))
    const got = await invoke({
      err: new Error('This request has expired'),
      signedClientId: CLIENT_ID,
    })
    expect(got.redirectLocation).toBeUndefined()
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
    expect(got.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ signedClientId: CLIENT_ID }),
      expect.stringContaining('client metadata lookup failed'),
    )
  })

  it('falls back to HTML when redirect_uris[0] is not a valid URL', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({
      redirect_uris: ['not a url at all'],
    })
    const got = await invoke({
      err: new Error('This request has expired'),
      signedClientId: CLIENT_ID,
    })
    expect(got.redirectLocation).toBeUndefined()
    expect(got.statusCode).toBe(400)
    expect(got.logger.error).toHaveBeenCalledWith(
      expect.objectContaining({
        signedClientId: CLIENT_ID,
        fallbackRedirect: 'not a url at all',
      }),
      expect.stringContaining('not a valid URL'),
    )
  })

  it('prefers capturedRedirectUri over signedClientId when both are present', async () => {
    // Belt-and-braces: when Step 2 succeeded we have a real
    // redirect_uri AND state. Don't override that with the
    // metadata-resolved fallback (no state, possibly different URI).
    const got = await invoke({
      err: new Error('account creation failed'),
      capturedRedirectUri: REDIRECT_URI,
      capturedState: STATE,
      signedClientId: CLIENT_ID,
    })
    expect(resolveClientMetadataMock).not.toHaveBeenCalled()
    const url = new URL(got.redirectLocation!)
    expect(url.searchParams.get('state')).toBe(STATE)
  })

  it('does not call resolveClientMetadata when no signedClientId is present', async () => {
    const got = await invoke({ err: new Error('This request has expired') })
    expect(resolveClientMetadataMock).not.toHaveBeenCalled()
    // Falls through to the existing static HTML page.
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
  })
})

describe('handleCallbackError — HTML fallback Start Over CTA', () => {
  // When neither tier produces a redirect, the HTML fallback should
  // still surface a "Return to sign in" button when the shared
  // resolveStartOverHref resolves to a sign-in entry URL. The
  // resolver's own behaviour (client_uri / origin / scheme
  // sanitisation) is owned and tested by
  // packages/shared/src/__tests__/start-over-href.test.ts;
  // these tests just verify handleCallbackError trusts the resolver
  // and threads its result onto the renderError options.

  it('renders a Start Over button when signedClientId resolves to a Start Over href', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({}) // Tier 1b: no redirect_uris → falls through
    resolveStartOverHrefMock.mockResolvedValueOnce('https://demo.example/')
    const got = await invoke({
      err: new Error('This request has expired'),
      signedClientId: CLIENT_ID,
    })
    expect(got.statusCode).toBe(400)
    expect(got.contentType).toBe('html')
    expect(got.renderError).toHaveBeenCalledWith(
      TIMEOUT_DESCRIPTION,
      expect.objectContaining({
        startOverHref: 'https://demo.example/',
        startOverLabel: 'Return to sign in',
      }),
    )
    expect(resolveStartOverHrefMock).toHaveBeenCalledWith(
      CLIENT_ID,
      expect.any(Object),
    )
  })

  it('omits the Start Over button when no signedClientId is in scope', async () => {
    const got = await invoke({ err: new Error('This request has expired') })
    expect(resolveStartOverHrefMock).not.toHaveBeenCalled()
    expect(got.renderError).toHaveBeenCalledWith(
      TIMEOUT_DESCRIPTION,
      expect.objectContaining({ startOverHref: undefined }),
    )
  })

  it('omits the Start Over button when the resolver returns null', async () => {
    resolveClientMetadataMock.mockResolvedValueOnce({}) // Tier 1b
    resolveStartOverHrefMock.mockResolvedValueOnce(null)
    const got = await invoke({
      err: new Error('This request has expired'),
      signedClientId: CLIENT_ID,
    })
    expect(got.renderError).toHaveBeenCalledWith(
      TIMEOUT_DESCRIPTION,
      expect.objectContaining({ startOverHref: undefined }),
    )
  })
})

describe('handleCallbackError — already-responded short-circuit', () => {
  it('does nothing when headers were already sent', async () => {
    const got = await invoke({
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
  it('logs an expired-PAR failure at warn (not error)', async () => {
    const got = await invoke({
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

  it('logs a generic server failure at error (not warn)', async () => {
    const got = await invoke({
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
