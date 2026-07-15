import { describe, it, expect } from 'vitest'
import {
  createOAuthSessionCookie,
  getOAuthSessionFromCookie,
  readOAuthSessionCookie,
  createUserSessionCookie,
  getUserSessionFromCookie,
  getSessionFromCookie,
  resolveCallbackErrorCode,
  OAUTH_COOKIE,
  OAUTH_COOKIE_MAX_AGE_SECONDS,
  SESSION_COOKIE,
} from '../lib/session'
import type { OAuthSession, UserSession } from '../lib/session'
import * as crypto from 'crypto'

// Helper: build a minimal cookie store from a name/value pair
function cookieStore(name: string, value: string) {
  return {
    get(n: string) {
      return n === name ? { value } : undefined
    },
  }
}

function emptyCookieStore() {
  return { get: () => undefined }
}

const sampleOAuthSession: OAuthSession = {
  state: 'test-state',
  codeVerifier: 'test-verifier',
  dpopPrivateJwk: { kty: 'EC', crv: 'P-256' },
  tokenEndpoint: 'https://pds.example/oauth/token',
  email: 'alice@example.com',
}

const sampleUserSession: UserSession = {
  userDid: 'did:plc:abc123',
  userHandle: 'alice.bsky.social',
  createdAt: Date.now(),
}

describe('OAuth session cookie', () => {
  it('round-trips: create → read', () => {
    const cookie = createOAuthSessionCookie(sampleOAuthSession)
    expect(cookie.name).toBe(OAUTH_COOKIE)

    const store = cookieStore(cookie.name, cookie.value)
    const restored = getOAuthSessionFromCookie(store)
    expect(restored).toEqual(sampleOAuthSession)
  })

  it('returns null for tampered cookie', () => {
    const cookie = createOAuthSessionCookie(sampleOAuthSession)
    const tampered = cookie.value.slice(0, -4) + 'XXXX'
    const store = cookieStore(cookie.name, tampered)
    expect(getOAuthSessionFromCookie(store)).toBeNull()
  })

  it('returns null when cookie is missing', () => {
    expect(getOAuthSessionFromCookie(emptyCookieStore())).toBeNull()
  })
})

describe('User session cookie', () => {
  it('round-trips: create → read', () => {
    const cookie = createUserSessionCookie(sampleUserSession)
    expect(cookie.name).toBe(SESSION_COOKIE)

    const store = cookieStore(cookie.name, cookie.value)
    const restored = getUserSessionFromCookie(store)
    expect(restored).toEqual(sampleUserSession)
  })

  it('returns null for tampered cookie', () => {
    const cookie = createUserSessionCookie(sampleUserSession)
    // Flip a character in the HMAC portion
    const parts = cookie.value.split('.')
    parts[parts.length - 1] = crypto.randomBytes(16).toString('base64url')
    const tampered = parts.join('.')
    const store = cookieStore(cookie.name, tampered)
    expect(getUserSessionFromCookie(store)).toBeNull()
  })

  it('returns null when cookie is missing', () => {
    expect(getUserSessionFromCookie(emptyCookieStore())).toBeNull()
  })
})

describe('getSessionFromCookie', () => {
  it('delegates to getUserSessionFromCookie', () => {
    const cookie = createUserSessionCookie(sampleUserSession)
    const store = cookieStore(cookie.name, cookie.value)
    expect(getSessionFromCookie(store)).toEqual(sampleUserSession)
  })
})

describe('OAUTH_COOKIE_MAX_AGE_SECONDS', () => {
  it('is one hour, long enough to outlast a realistic email-code wait', () => {
    expect(OAUTH_COOKIE_MAX_AGE_SECONDS).toBe(60 * 60)
  })

  it('outlasts the previous 10-minute value that could expire mid-flow', () => {
    expect(OAUTH_COOKIE_MAX_AGE_SECONDS).toBeGreaterThan(600)
  })
})

describe('resolveCallbackErrorCode', () => {
  it('maps a missing oauth_state cookie to session_expired', () => {
    expect(resolveCallbackErrorCode({ oauthCookiePresent: false })).toBe(
      'session_expired',
    )
  })

  it('maps a present cookie (any other failure) to auth_failed', () => {
    expect(resolveCallbackErrorCode({ oauthCookiePresent: true })).toBe(
      'auth_failed',
    )
  })
})

describe('readOAuthSessionCookie', () => {
  it('returns a valid signed session', () => {
    const cookie = createOAuthSessionCookie(sampleOAuthSession)
    expect(
      readOAuthSessionCookie(cookieStore(cookie.name, cookie.value)),
    ).toEqual({ session: sampleOAuthSession })
  })

  it('classifies a missing cookie as an expired session', () => {
    expect(readOAuthSessionCookie(emptyCookieStore())).toEqual({
      session: null,
      errorCode: 'session_expired',
      logMessage: '[oauth/callback] Missing oauth_state cookie',
    })
  })

  it('classifies a present but invalid cookie as an auth failure', () => {
    expect(
      readOAuthSessionCookie(cookieStore(OAUTH_COOKIE, 'tampered')),
    ).toEqual({
      session: null,
      errorCode: 'auth_failed',
      logMessage: '[oauth/callback] Invalid oauth_state cookie',
    })
  })
})
