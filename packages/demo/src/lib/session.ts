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
