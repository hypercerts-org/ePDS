/**
 * Drive an OpenStreetMap sign-in or link through a real better-auth
 * instance with OpenStreetMap's OIDC endpoints stubbed: discovery, JWKS,
 * token and userinfo. Unlike the Google helper, the ID token is really
 * signed (RS256 with a throwaway key), because the generic OAuth plugin
 * verifies it against the discovered JWKS and checks its nonce.
 */
import { generateKeyPairSync, sign } from 'node:crypto'
import { expect, vi } from 'vitest'

export const OSM_TEST_ISSUER = 'https://osm.example'
/** A second OSM instance, whose user ids overlap the first's. */
export const OSM_OTHER_TEST_ISSUER = 'https://other-osm.example'
export const OSM_TEST_CLIENT_ID = 'osm-client-id'
export const OSM_TEST_ENV = {
  OSM_CLIENT_ID: OSM_TEST_CLIENT_ID,
  OSM_CLIENT_SECRET: 'osm-client-secret',
  OSM_ISSUER: OSM_TEST_ISSUER,
}

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
})
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256' }

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

function signIdToken(claims: Record<string, unknown>): string {
  const input = `${b64url({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${b64url(claims)}`
  const signature = sign('sha256', Buffer.from(input), privateKey)
  return `${input}.${signature.toString('base64url')}`
}

/** The OSM user the stubbed token endpoint answers for next. */
const next = { sub: '1001', username: 'alice', nonce: '' }

/**
 * Stub the endpoints of OpenStreetMap instances at {@link OSM_TEST_ISSUER}
 * and {@link OSM_OTHER_TEST_ISSUER} for the whole test. Token endpoints
 * answer for {@link next}; undo with `vi.unstubAllGlobals()`.
 */
export function stubOpenStreetMap(): void {
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
      const issuer = [OSM_TEST_ISSUER, OSM_OTHER_TEST_ISSUER].find((i) =>
        url.startsWith(`${i}/`),
      )
      if (!issuer) return realFetch(input, init)
      if (url === `${issuer}/.well-known/openid-configuration`) {
        return Promise.resolve(
          Response.json({
            issuer,
            authorization_endpoint: `${issuer}/oauth2/authorize`,
            token_endpoint: `${issuer}/oauth2/token`,
            userinfo_endpoint: `${issuer}/oauth2/userinfo`,
            jwks_uri: `${issuer}/oauth2/discovery/keys`,
            id_token_signing_alg_values_supported: ['RS256'],
            claims_supported: ['sub', 'preferred_username', 'email'],
          }),
        )
      }
      if (url === `${issuer}/oauth2/discovery/keys`) {
        return Promise.resolve(Response.json({ keys: [jwk] }))
      }
      if (url === `${issuer}/oauth2/token`) {
        const now = Math.floor(Date.now() / 1000)
        return Promise.resolve(
          Response.json({
            access_token: 'osm-access-token',
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'openid',
            id_token: signIdToken({
              iss: issuer,
              aud: OSM_TEST_CLIENT_ID,
              sub: next.sub,
              nonce: next.nonce,
              iat: now,
              exp: now + 600,
            }),
          }),
        )
      }
      if (url === `${issuer}/oauth2/userinfo`) {
        return Promise.resolve(
          Response.json({ sub: next.sub, preferred_username: next.username }),
        )
      }
      return realFetch(input, init)
    }),
  )
}

/** The part of a better-auth instance these helpers use. */
interface AuthHandler {
  handler: (request: Request) => Promise<Response>
}

function cookiePairs(res: Response): string[] {
  return res.headers.getSetCookie().map((c) => c.split(';')[0])
}

/**
 * Start an OpenStreetMap sign-in (`/sign-in/social`) or, with a session
 * `cookie`, a link (`/link-social`), as the login page and account
 * settings do. The next token-endpoint answer is for OSM user `sub`.
 */
export async function startOpenStreetMap(
  auth: AuthHandler,
  opts: { sub: string; sessionCookie?: string; idTokenNonce?: string },
): Promise<{ state: string; cookie: string; authorizationUrl: URL }> {
  const linking = opts.sessionCookie !== undefined
  const res = await auth.handler(
    new Request(
      `https://auth.example/api/auth/${linking ? 'link-social' : 'sign-in/social'}`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'https://auth.example',
          ...(linking ? { cookie: opts.sessionCookie } : {}),
        },
        body: JSON.stringify({
          provider: 'openstreetmap',
          callbackURL: linking ? '/account?osm=connected' : '/auth/complete',
          errorCallbackURL: linking
            ? '/account?osm=connect_failed'
            : '/auth/complete',
        }),
      },
    ),
  )
  expect(res.status).toBe(200)
  const { url } = (await res.json()) as { url: string }
  const authorizationUrl = new URL(url)
  next.sub = opts.sub
  next.nonce =
    opts.idTokenNonce ?? authorizationUrl.searchParams.get('nonce') ?? ''
  const cookie = [
    ...(opts.sessionCookie ? [opts.sessionCookie] : []),
    ...cookiePairs(res),
  ].join('; ')
  return {
    state: authorizationUrl.searchParams.get('state') ?? '',
    cookie,
    authorizationUrl,
  }
}

/**
 * GET /callback/openstreetmap for a started sign-in or link; resolves to
 * the redirect target and the cookies better-auth set.
 */
export async function openStreetMapCallback(
  auth: AuthHandler,
  started: { state: string; cookie: string },
): Promise<{ location: string | null; cookie: string }> {
  const res = await auth.handler(
    new Request(
      `https://auth.example/api/auth/callback/openstreetmap?code=c&state=${started.state}`,
      { headers: { cookie: started.cookie } },
    ),
  )
  expect(res.status).toBe(302)
  return {
    location: res.headers.get('location'),
    cookie: cookiePairs(res).join('; '),
  }
}
