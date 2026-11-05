/**
 * Drive a Google sign-in through a real better-auth instance, as the login
 * page's Google button does: POST /sign-in/social, then GET
 * /callback/google with Google's token endpoint stubbed. Shared by the
 * tests that run ePDS's provider config (better-auth-social-sign-in) and
 * the production instance (create-better-auth).
 */
import { expect, vi } from 'vitest'

/** The part of a better-auth instance these helpers use. */
interface AuthHandler {
  handler: (request: Request) => Promise<Response>
}

/** An unsigned JWT carrying `claims`; better-auth's decodeJwt only parses. */
export function idToken(claims: Record<string, unknown>): string {
  const part = (v: unknown) =>
    Buffer.from(JSON.stringify(v)).toString('base64url')
  return `${part({ alg: 'RS256', kid: 'test' })}.${part({
    iss: 'https://accounts.google.com',
    aud: 'google-client-id',
    sub: 'google-sub-1',
    name: 'Alice',
    picture: 'https://example.com/a.png',
    iat: 0,
    exp: 9999999999,
    ...claims,
  })}.sig`
}

/**
 * Start a sign-in exactly as the login page's Google button does and
 * return the state and cookies the callback needs.
 */
export async function startGoogleSignIn(auth: AuthHandler) {
  const res = await auth.handler(
    new Request('https://auth.example/api/auth/sign-in/social', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://auth.example',
      },
      body: JSON.stringify({
        provider: 'google',
        callbackURL: '/auth/complete',
        errorCallbackURL: '/auth/complete',
      }),
    }),
  )
  expect(res.status).toBe(200)
  const { url } = (await res.json()) as { url: string }
  const state = new URL(url).searchParams.get('state') ?? ''
  const cookie = res.headers
    .getSetCookie()
    .map((c) => c.split(';')[0])
    .join('; ')
  return { state, cookie }
}

/**
 * Answer Google's token endpoint with an ID token carrying `claims`. Undo
 * with `vi.unstubAllGlobals()`.
 */
export function stubGoogleToken(claims: Record<string, unknown>): void {
  const realFetch = globalThis.fetch.bind(globalThis)
  vi.stubGlobal(
    'fetch',
    vi.fn((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url =
        input instanceof URL
          ? input.href
          : typeof input === 'string'
            ? input
            : input.url
      if (url.startsWith('https://oauth2.googleapis.com/token')) {
        return Promise.resolve(
          Response.json({
            access_token: 'access-token',
            id_token: idToken(claims),
            token_type: 'Bearer',
            expires_in: 3600,
          }),
        )
      }
      return realFetch(input, init)
    }),
  )
}

/** GET /callback/google with `query`; resolves to the redirect target. */
export async function googleCallback(
  auth: AuthHandler,
  query: string,
  cookie: string,
): Promise<string | null> {
  const res = await auth.handler(
    new Request(`https://auth.example/api/auth/callback/google?${query}`, {
      headers: { cookie },
    }),
  )
  expect(res.status).toBe(302)
  return res.headers.get('location')
}

/**
 * A whole Google sign-in whose ID token carries `claims`; resolves to
 * where better-auth sends the browser afterwards.
 */
export async function signInWithGoogleRedirect(
  auth: AuthHandler,
  claims: Record<string, unknown>,
): Promise<string | null> {
  const { state, cookie } = await startGoogleSignIn(auth)
  stubGoogleToken(claims)
  try {
    return await googleCallback(auth, `code=c&state=${state}`, cookie)
  } finally {
    vi.unstubAllGlobals()
  }
}
