/**
 * HMAC-signed cookie sessions for OAuth state and user sessions.
 *
 * Adapted from maearth-demo. Stripped: 2FA verified field.
 */

import * as crypto from 'crypto'

const DEV_SECRET = 'dev-session-secret-change-in-production'

function getSessionSecret(): string {
  const secret = process.env.SESSION_SECRET || DEV_SECRET
  if (process.env.NODE_ENV === 'production' && secret === DEV_SECRET) {
    throw new Error(
      'SESSION_SECRET must be set in production. Generate one with: openssl rand -base64 32',
    )
  }
  return secret
}

// --- Types ---

export interface OAuthSession {
  state: string
  codeVerifier: string
  dpopPrivateJwk: crypto.JsonWebKey
  tokenEndpoint: string
  /**
   * Authorization server issuer identifier, used as the `aud` claim
   * when signing client_assertion JWTs for confidential clients. Per
   * RFC 7523 §3 item 3, the assertion's audience must be the AS
   * identifier, not the specific token/PAR endpoint URL.
   */
  issuer: string
  email?: string
  expectedDid?: string
  expectedPdsUrl?: string
}

export interface UserSession {
  userDid: string
  userHandle: string
  createdAt: number
}

// --- HMAC Signing (sign arbitrary JSON payloads into cookie values) ---

function signPayload(payload: string): string {
  const hmac = crypto
    .createHmac('sha256', getSessionSecret())
    .update(payload)
    .digest('base64url')
  return `${payload}.${hmac}`
}

function verifyPayload(signed: string): string | null {
  const dotIndex = signed.lastIndexOf('.')
  if (dotIndex === -1) return null
  const payload = signed.substring(0, dotIndex)
  const providedHmac = signed.substring(dotIndex + 1)
  const expectedHmac = crypto
    .createHmac('sha256', getSessionSecret())
    .update(payload)
    .digest('base64url')
  const a = Buffer.from(providedHmac)
  const b = Buffer.from(expectedHmac)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null
  return payload
}

// --- OAuth Sessions (stored in cookie as signed JSON) ---

const OAUTH_COOKIE = 'oauth_state'

/**
 * Lifetime of the `oauth_state` cookie, in seconds.
 *
 * The cookie carries everything the callback needs to finish the
 * token exchange (state, code verifier, token endpoint, issuer). It
 * must outlive a realistic sign-in: the user requests an email code,
 * fetches it from their inbox, and only then submits — a wait that
 * can run to several minutes. The old 600s (10 min) timer started
 * when the OAuth flow began, before the OTP was issued, while the
 * OTP's own 600s validity started only when it was sent. The cookie
 * could therefore disappear while a late-issued code was still
 * valid. One hour matches the auth service's `auth_flow` row TTL:
 * as long as the auth service can still recover the flow, the demo
 * can too.
 */
export const OAUTH_COOKIE_MAX_AGE_SECONDS = 60 * 60

/**
 * Error code the OAuth callback landing page should show when the
 * flow can't be completed. Split out as a pure function so the
 * mapping is unit-testable without standing up a Next request.
 *
 * `session_expired` is reserved for the case where the sign-in
 * itself succeeded but *our* `oauth_state` cookie has gone away
 * (expired, cleared, or a wait longer than its lifetime) — there is
 * nothing to exchange the code against, but the user did nothing
 * wrong, so an honest "took too long" beats a generic "auth failed".
 * Every other failure maps to `auth_failed`.
 */
export function resolveCallbackErrorCode(reason: {
  oauthCookiePresent: boolean
}): 'session_expired' | 'auth_failed' {
  return reason.oauthCookiePresent ? 'auth_failed' : 'session_expired'
}

export function createOAuthSessionCookie(data: OAuthSession): {
  name: string
  value: string
} {
  const json = Buffer.from(JSON.stringify(data)).toString('base64url')
  return { name: OAUTH_COOKIE, value: signPayload(json) }
}

export function getOAuthSessionFromCookie(cookieStore: {
  get(name: string): { value: string } | undefined
}): OAuthSession | null {
  const cookie = cookieStore.get(OAUTH_COOKIE)
  if (!cookie) return null
  const json = verifyPayload(cookie.value)
  if (!json) return null
  try {
    return JSON.parse(Buffer.from(json, 'base64url').toString())
  } catch {
    return null
  }
}

/**
 * Read and classify the callback's OAuth session cookie.
 *
 * Missing cookies represent an expired browser session, while cookies that
 * are present but fail signature or JSON validation represent an auth failure.
 * Keeping the classification here ensures the callback's log and user-facing
 * error stay consistent.
 */
export function readOAuthSessionCookie(cookieStore: {
  get(name: string): { value: string } | undefined
}):
  | { session: OAuthSession }
  | {
      session: null
      errorCode: 'session_expired' | 'auth_failed'
      logMessage: string
    } {
  const oauthCookiePresent = cookieStore.get(OAUTH_COOKIE) !== undefined
  const session = getOAuthSessionFromCookie(cookieStore)
  if (session) return { session }

  return {
    session: null,
    errorCode: resolveCallbackErrorCode({ oauthCookiePresent }),
    logMessage: oauthCookiePresent
      ? '[oauth/callback] Invalid oauth_state cookie'
      : '[oauth/callback] Missing oauth_state cookie',
  }
}

// --- User Sessions (stored in cookie as signed JSON) ---

const SESSION_COOKIE = 'session_id'

export function createUserSessionCookie(data: UserSession): {
  name: string
  value: string
} {
  const json = Buffer.from(JSON.stringify(data)).toString('base64url')
  return { name: SESSION_COOKIE, value: signPayload(json) }
}

export function getUserSessionFromCookie(cookieStore: {
  get(name: string): { value: string } | undefined
}): UserSession | null {
  const cookie = cookieStore.get(SESSION_COOKIE)
  if (!cookie) return null
  const json = verifyPayload(cookie.value)
  if (!json) return null
  try {
    return JSON.parse(Buffer.from(json, 'base64url').toString())
  } catch {
    return null
  }
}

export function getSessionFromCookie(cookieStore: {
  get(name: string): { value: string } | undefined
}): UserSession | null {
  return getUserSessionFromCookie(cookieStore)
}

export { SESSION_COOKIE, OAUTH_COOKIE }
