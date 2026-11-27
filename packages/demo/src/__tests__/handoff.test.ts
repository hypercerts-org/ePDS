/**
 * Checks for the Atmosphere hand-off (lib/handoff.ts) and the
 * /api/oauth/handoff route that applies them.
 *
 * The route test plays the browser's part with a small cookie jar, so the
 * sequential replay protection (the accepted hand-off clears the sign-in cookie,
 * a replay then finds none; concurrent replays are not covered, see the route) is exercised end to end rather than asserted
 * piecemeal.
 */
import { describe, it, expect, vi } from 'vitest'
import { NextRequest } from 'next/server'

// lib/auth reads PDS_URL when it is first imported.
vi.hoisted(() => {
  process.env.PDS_URL = 'https://pds.example'
  process.env.PUBLIC_URL = 'http://localhost:3002'
})

import { verifyHandoff } from '../lib/handoff'
import {
  createOAuthSessionCookie,
  OAUTH_COOKIE,
  type OAuthSession,
} from '../lib/session'
import { GET } from '../app/api/oauth/handoff/route'

const ISSUER = 'https://pds.example'
const STATE = 'state-from-our-par'

function sessionFor(overrides: Partial<OAuthSession> = {}): OAuthSession {
  return {
    state: STATE,
    codeVerifier: 'verifier',
    dpopPrivateJwk: {},
    tokenEndpoint: `${ISSUER}/oauth/token`,
    issuer: ISSUER,
    ...overrides,
  }
}

function params(overrides: Record<string, string | null> = {}) {
  const base: Record<string, string | null> = {
    handle: 'alice.bsky.social',
    iss: ISSUER,
    state: STATE,
    ...overrides,
  }
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(base)) {
    if (value !== null) search.set(key, value)
  }
  return search
}

function verify(
  overrides: Record<string, string | null> = {},
  session: OAuthSession | null = sessionFor(),
) {
  return verifyHandoff({
    params: params(overrides),
    session,
    expectedIssuer: ISSUER,
  })
}

describe('verifyHandoff', () => {
  it('accepts a hand-off that continues this browser’s sign-in', () => {
    expect(verify()).toEqual({ ok: true, handle: 'alice.bsky.social' })
  })

  it('accepts a handle typed with a leading @ and returns it normalised', () => {
    expect(verify({ handle: ' @alice.bsky.social ' })).toEqual({
      ok: true,
      handle: 'alice.bsky.social',
    })
  })

  it('refuses a state that is not the one in this browser’s cookie', () => {
    expect(verify({ state: 'someone-elses-state' })).toEqual({
      ok: false,
      reason: 'state_mismatch',
    })
  })

  it('refuses a missing state', () => {
    expect(verify({ state: null })).toEqual({
      ok: false,
      reason: 'missing_params',
    })
    expect(verify({ state: '' })).toEqual({
      ok: false,
      reason: 'missing_params',
    })
  })

  it('refuses a wrong iss, including near-misses', () => {
    for (const iss of [
      'https://evil.example',
      `${ISSUER}/`,
      'https://PDS.example',
    ]) {
      expect(verify({ iss })).toEqual({ ok: false, reason: 'wrong_issuer' })
    }
  })

  it('refuses a missing iss or handle', () => {
    expect(verify({ iss: null })).toEqual({
      ok: false,
      reason: 'missing_params',
    })
    expect(verify({ handle: null })).toEqual({
      ok: false,
      reason: 'missing_params',
    })
  })

  it('refuses when this browser has no sign-in under way', () => {
    expect(verify({}, null)).toEqual({
      ok: false,
      reason: 'no_sign_in_in_this_browser',
    })
  })

  it('refuses a sign-in that was started against another server', () => {
    const elsewhere = sessionFor({ issuer: 'https://bsky.social' })
    expect(verify({}, elsewhere)).toEqual({
      ok: false,
      reason: 'sign_in_started_elsewhere',
    })
  })

  it('checks the handle only after the browser binding has passed', () => {
    expect(verify({ handle: 'not a handle' })).toEqual({
      ok: false,
      reason: 'invalid_handle',
    })
    expect(verify({ handle: 'not a handle', state: 'wrong' })).toEqual({
      ok: false,
      reason: 'state_mismatch',
    })
  })
})

describe('GET /api/oauth/handoff', () => {
  const BASE = 'http://localhost:3002'

  /** A browser: sends its cookies, applies Set-Cookie from the response. */
  function browser(initial: Record<string, string> = {}) {
    const jar = new Map(Object.entries(initial))
    return {
      has: (name: string) => jar.has(name),
      set: (name: string, value: string) => jar.set(name, value),
      get(query: URLSearchParams) {
        const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ')
        const request = new NextRequest(
          `${BASE}/api/oauth/handoff?${query.toString()}`,
          { headers: cookie ? { cookie } : {} },
        )
        const response = GET(request)
        for (const set of response.cookies.getAll()) {
          if (set.value === '') jar.delete(set.name)
          else jar.set(set.name, set.value)
        }
        return response
      },
    }
  }

  const signedCookie = () => {
    const { name, value } = createOAuthSessionCookie(sessionFor())
    return { [name]: value }
  }

  it('continues the sign-in for the handle and deletes the cookie', () => {
    const b = browser(signedCookie())

    const res = b.get(params())

    const location = new URL(res.headers.get('location') ?? '')
    expect(location.origin + location.pathname).toBe(`${BASE}/api/oauth/login`)
    expect(location.searchParams.get('handle')).toBe('alice.bsky.social')
    // Neither the state nor the issuer is passed on to the login route.
    expect(location.searchParams.has('state')).toBe(false)
    expect(b.has(OAUTH_COOKIE)).toBe(false)
  })

  it('refuses a replay of the same hand-off URL', () => {
    const b = browser(signedCookie())
    const first = b.get(params())
    expect(first.headers.get('location')).toContain('/api/oauth/login')

    const replay = b.get(params())

    expect(replay.headers.get('location')).toBe(
      `${BASE}/?error=handoff_refused`,
    )
  })

  it('refuses a replay after the login route has set a cookie for the new flow', () => {
    const b = browser(signedCookie())
    b.get(params())
    const next = createOAuthSessionCookie(sessionFor({ state: 'new-flow' }))
    b.set(next.name, next.value)

    const replay = b.get(params())

    expect(replay.headers.get('location')).toBe(
      `${BASE}/?error=handoff_refused`,
    )
    expect(b.has(OAUTH_COOKIE)).toBe(true)
  })

  it.each([
    ['a tampered state', { state: 'tampered' }, signedCookie()],
    ['a tampered iss', { iss: 'https://evil.example' }, signedCookie()],
    ['no state', { state: null }, signedCookie()],
    ['no cookie', {}, {}],
    ['a cookie with a bad signature', {}, { [OAUTH_COOKIE]: 'e30.forged' }],
  ])('refuses %s and leaves the cookie alone', (_name, query, cookies) => {
    const b = browser(cookies)

    const res = b.get(params(query))

    expect(res.headers.get('location')).toBe(`${BASE}/?error=handoff_refused`)
    expect(b.has(OAUTH_COOKIE)).toBe(OAUTH_COOKIE in cookies)
  })

  it('reports a malformed handle without consuming the sign-in', () => {
    const b = browser(signedCookie())

    const res = b.get(params({ handle: 'not a handle' }))

    expect(res.headers.get('location')).toBe(`${BASE}/?error=invalid_handle`)
    expect(b.has(OAUTH_COOKIE)).toBe(true)
  })
})
