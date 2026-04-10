import { describe, expect, it } from 'vitest'
import {
  buildPdsAuthorizeRedirect,
  hasDeviceSessionCookie,
  isForceLoginPrompt,
  shouldReuseSession,
  type SessionReuseRequest,
} from '../lib/session-reuse.js'

function makeReq(
  opts: {
    cookies?: Record<string, string>
    cookieHeader?: string
    query?: Record<string, unknown>
  } = {},
): SessionReuseRequest {
  return {
    cookies: opts.cookies,
    headers: { cookie: opts.cookieHeader },
    query: opts.query ?? {},
  }
}

describe('hasDeviceSessionCookie (HYPER-268)', () => {
  it('returns true when req.cookies has a dev-id entry', () => {
    expect(
      hasDeviceSessionCookie(makeReq({ cookies: { 'dev-id': 'abc' } })),
    ).toBe(true)
  })

  it('returns true when the raw Cookie header contains dev-id', () => {
    expect(
      hasDeviceSessionCookie(makeReq({ cookieHeader: 'dev-id=xyz' })),
    ).toBe(true)
  })

  it('returns true when dev-id is not the first cookie in the header', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({ cookieHeader: 'foo=1; dev-id=xyz; bar=2' }),
      ),
    ).toBe(true)
  })

  it('returns false when no cookies are present', () => {
    expect(hasDeviceSessionCookie(makeReq())).toBe(false)
  })

  it('returns false when the cookie header only has unrelated cookies', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({ cookieHeader: 'csrf=1; epds_auth_flow=2' }),
      ),
    ).toBe(false)
  })

  it('is not fooled by a cookie whose name contains dev-id as a substring', () => {
    // "not-dev-id=" should NOT match — only a real dev-id cookie should.
    expect(
      hasDeviceSessionCookie(makeReq({ cookieHeader: 'not-dev-id=abc' })),
    ).toBe(false)
  })

  it('prefers the parsed cookie bag over the raw header', () => {
    expect(
      hasDeviceSessionCookie(
        makeReq({
          cookies: { 'dev-id': 'abc' },
          cookieHeader: 'nothing-here=1',
        }),
      ),
    ).toBe(true)
  })
})

describe('isForceLoginPrompt (HYPER-268)', () => {
  it('returns true when prompt=login', () => {
    expect(isForceLoginPrompt(makeReq({ query: { prompt: 'login' } }))).toBe(
      true,
    )
  })

  it('returns false for other prompt values', () => {
    expect(isForceLoginPrompt(makeReq({ query: { prompt: 'none' } }))).toBe(
      false,
    )
    expect(isForceLoginPrompt(makeReq({ query: { prompt: 'consent' } }))).toBe(
      false,
    )
  })

  it('returns false when prompt is absent', () => {
    expect(isForceLoginPrompt(makeReq())).toBe(false)
  })

  it('returns false when prompt is an array', () => {
    // Express parses repeated query params as arrays; we only honour
    // plain string prompt=login, not the edge case.
    expect(isForceLoginPrompt(makeReq({ query: { prompt: ['login'] } }))).toBe(
      false,
    )
  })
})

describe('shouldReuseSession (HYPER-268)', () => {
  it('returns true when dev-id is set and prompt is absent', () => {
    expect(shouldReuseSession(makeReq({ cookies: { 'dev-id': 'abc' } }))).toBe(
      true,
    )
  })

  it('returns false when dev-id is set but prompt=login', () => {
    expect(
      shouldReuseSession(
        makeReq({ cookies: { 'dev-id': 'abc' }, query: { prompt: 'login' } }),
      ),
    ).toBe(false)
  })

  it('returns false when dev-id is absent', () => {
    expect(shouldReuseSession(makeReq())).toBe(false)
  })
})

describe('buildPdsAuthorizeRedirect (HYPER-268)', () => {
  const pds = 'https://pds.example'

  it('preserves a simple query string', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      request_uri: 'urn:x:1',
      client_id: 'https://trusted.example/client',
    })
    const parsed = new URL(url)
    expect(parsed.origin + parsed.pathname).toBe(
      'https://pds.example/oauth/authorize',
    )
    expect(parsed.searchParams.get('request_uri')).toBe('urn:x:1')
    expect(parsed.searchParams.get('client_id')).toBe(
      'https://trusted.example/client',
    )
  })

  it('preserves repeated query parameters via array values', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      scope: ['atproto', 'transition:generic'],
    })
    const parsed = new URL(url)
    expect(parsed.searchParams.getAll('scope')).toEqual([
      'atproto',
      'transition:generic',
    ])
  })

  it('skips non-string query values', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      request_uri: 'urn:x:1',
      bogus: undefined,
      numeric: 42,
    })
    const parsed = new URL(url)
    expect(parsed.searchParams.has('bogus')).toBe(false)
    expect(parsed.searchParams.has('numeric')).toBe(false)
    expect(parsed.searchParams.get('request_uri')).toBe('urn:x:1')
  })

  it('url-encodes special characters in values', () => {
    const url = buildPdsAuthorizeRedirect(pds, {
      redirect_uri: 'https://app.example/cb?foo=bar&baz=1',
    })
    expect(url).toContain('redirect_uri=https%3A%2F%2Fapp.example%2Fcb')
  })
})
