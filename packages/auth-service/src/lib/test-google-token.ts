/**
 * E2E test-only stand-in for Google's token endpoint.
 *
 * The e2e stack has no internet, and a real Google sign-in needs a real
 * Google account. The e2e suite therefore intercepts the browser's trip to
 * accounts.google.com and sends it straight back to better-auth's callback
 * with `code=<base64url JSON of the ID token claims the scenario wants>`.
 * This module answers better-auth's server-side exchange of that code at
 * https://oauth2.googleapis.com/token with an ID token carrying those
 * claims, so everything after it (ePDS's Google claim check, user creation
 * and linking, /auth/complete) runs as in production.
 *
 * Installed by index.ts only when EPDS_TEST_HOOKS=1 and
 * EPDS_TEST_FAKE_GOOGLE=1; refuses to install when NODE_ENV=production.
 * Anyone who can reach such an instance can sign in as any address.
 */
import { createLogger } from '@certified-app/shared'

const logger = createLogger('auth:test-google-token')

export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}

/** The form fields of a token request body (a URLSearchParams or a string). */
function requestForm(body: RequestInit['body']): URLSearchParams {
  if (body instanceof URLSearchParams) return body
  return new URLSearchParams(typeof body === 'string' ? body : '')
}

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

/** The token response for an authorization `code` minted by the e2e suite. */
export function fakeGoogleTokenResponse(
  code: string,
  clientId: string,
): Response {
  let claims: unknown
  try {
    claims = JSON.parse(Buffer.from(code, 'base64url').toString('utf8'))
  } catch {
    claims = null
  }
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    return Response.json({ error: 'invalid_grant' }, { status: 400 })
  }
  const now = Math.floor(Date.now() / 1000)
  // better-auth's Google provider decodes the redirect flow's ID token
  // without verifying it (TLS to Google is the trust), so it is unsigned.
  const idToken = [
    base64url({ alg: 'RS256', kid: 'e2e', typ: 'JWT' }),
    base64url({
      iss: 'https://accounts.google.com',
      aud: clientId,
      iat: now,
      exp: now + 3600,
      ...claims,
    }),
    'e2e',
  ].join('.')
  return Response.json({
    access_token: 'e2e-access-token',
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: 3600,
  })
}

/** Answer Google token requests made by this process with fake tokens. */
export function installTestGoogleTokenEndpoint(clientId: string): void {
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'EPDS_TEST_FAKE_GOOGLE=1 is set but NODE_ENV=production — refusing to fake Google sign-in',
    )
  }
  logger.warn(
    'Fake Google token endpoint ENABLED — any address can sign in (EPDS_TEST_FAKE_GOOGLE=1)',
  )
  const realFetch = globalThis.fetch.bind(globalThis)
  globalThis.fetch = (input, init) => {
    if (requestUrl(input) !== GOOGLE_TOKEN_URL) return realFetch(input, init)
    // better-auth posts the code as a URLSearchParams form body.
    const form = requestForm(init?.body)
    return Promise.resolve(
      fakeGoogleTokenResponse(form.get('code') ?? '', clientId),
    )
  }
}
