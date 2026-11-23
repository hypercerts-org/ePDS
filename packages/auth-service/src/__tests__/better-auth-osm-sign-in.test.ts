/**
 * OpenStreetMap sign-in and linking through a real better-auth instance
 * with ePDS's provider config, linking options, link guard and database
 * hooks, and OpenStreetMap's OIDC endpoints stubbed (see
 * __helpers__/osm-sign-in.ts).
 *
 * Pins the property the design rests on: an OpenStreetMap identity only
 * ever signs in to an account it was explicitly connected to from a live
 * session, and is matched by its `sub`, never by email.
 */
import Database from 'better-sqlite3'
import { betterAuth } from 'better-auth'
import { createAuthMiddleware } from 'better-auth/api'
import { getMigrations } from 'better-auth/db/migration'
import { genericOAuth, testUtils } from 'better-auth/plugins'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  buildSocialProviders,
  databaseHooks,
  LINK_PROVIDER_NOT_ALLOWED,
  openStreetMapAccountLinking,
  refuseNonOsmLink,
} from '../better-auth.js'
import {
  buildOpenStreetMapConfig,
  OSM_PLACEHOLDER_EMAIL_DOMAIN,
} from '../lib/openstreetmap.js'
import {
  OSM_OTHER_TEST_ISSUER,
  OSM_TEST_ENV,
  OSM_TEST_ISSUER,
  openStreetMapCallback,
  startOpenStreetMap,
  stubOpenStreetMap,
} from './__helpers__/osm-sign-in.js'

/**
 * ePDS's better-auth setup against OSM at `issuer`. Pass the `database`
 * of an earlier instance to model a deployment whose `OSM_ISSUER` changed.
 */
async function makeAuth(
  issuer = OSM_TEST_ISSUER,
  database = new Database(':memory:'),
) {
  const osm = buildOpenStreetMapConfig({ ...OSM_TEST_ENV, OSM_ISSUER: issuer })
  if (!osm) throw new Error('OpenStreetMap provider not configured')
  const auth = betterAuth({
    secret: 'test-secret-test-secret-test-secret',
    baseURL: 'https://auth.example',
    basePath: '/api/auth',
    database,
    databaseHooks,
    account: { accountLinking: openStreetMapAccountLinking(true) },
    hooks: {
      before: createAuthMiddleware((ctx) => {
        refuseNonOsmLink(true, ctx.path, ctx.body)
        return Promise.resolve()
      }),
    },
    socialProviders: buildSocialProviders({
      GOOGLE_CLIENT_ID: 'google-client-id',
      GOOGLE_CLIENT_SECRET: 'google-client-secret',
    }),
    plugins: [genericOAuth({ config: [osm] }), testUtils()],
  })
  const { runMigrations } = await getMigrations(auth.options)
  await runMigrations()
  return Object.assign(auth, { database })
}

type Auth = Awaited<ReturnType<typeof makeAuth>>

/** A user who proved `email` with an email code, and their session cookie. */
async function signedInUser(auth: Auth, email: string) {
  const { test } = await auth.$context
  const user = await test.saveUser(
    test.createUser({ email, emailVerified: true }),
  )
  const { headers } = await test.login({ userId: user.id })
  return { user, cookie: headers.get('cookie') ?? '' }
}

async function sessionEmail(auth: Auth, cookie: string) {
  const session = await auth.api.getSession({ headers: { cookie } })
  return session?.user.email ?? null
}

async function userCount(auth: Auth) {
  const { internalAdapter } = await auth.$context
  return (await internalAdapter.listUsers()).length
}

beforeEach(() => {
  stubOpenStreetMap()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('OpenStreetMap authorization URL (real better-auth)', () => {
  it('goes to the issuer with openid only, PKCE and a nonce', async () => {
    const auth = await makeAuth()
    const { authorizationUrl } = await startOpenStreetMap(auth, { sub: '1' })
    expect(authorizationUrl.origin).toBe(OSM_TEST_ISSUER)
    expect(authorizationUrl.searchParams.get('scope')).toBe('openid')
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe(
      'S256',
    )
    expect(authorizationUrl.searchParams.get('nonce')).toBeTruthy()
  })
})

describe('OpenStreetMap ID token checks', () => {
  it('refuses an ID token minted for another sign-in (nonce)', async () => {
    const auth = await makeAuth()
    const alice = await signedInUser(auth, 'alice@example.com')
    await openStreetMapCallback(
      auth,
      await startOpenStreetMap(auth, {
        sub: '1001',
        sessionCookie: alice.cookie,
      }),
    )
    const started = await startOpenStreetMap(auth, {
      sub: '1001',
      idTokenNonce: 'some-other-nonce',
    })
    const { location, cookie } = await openStreetMapCallback(auth, started)
    expect(location).toMatch(/^\/auth\/complete\?error=/)
    expect(await sessionEmail(auth, cookie)).toBeNull()
  })
})

describe('OpenStreetMap sign-in without a connected account', () => {
  it('is refused with signup_disabled and creates no user', async () => {
    const auth = await makeAuth()
    const started = await startOpenStreetMap(auth, { sub: '1001' })
    const { location, cookie } = await openStreetMapCallback(auth, started)
    expect(location).toBe('/auth/complete?error=signup_disabled')
    expect(await userCount(auth)).toBe(0)
    expect(await sessionEmail(auth, cookie)).toBeNull()
  })

  it('never joins an existing user, even one holding a placeholder-domain address', async () => {
    // OSM is a trusted provider, so better-auth would implicitly link a
    // sign-in whose mapped email equals a verified user's. A placeholder
    // derived from the sub (as `1001@…` once was) would be guessable; the
    // random one cannot be matched.
    const auth = await makeAuth()
    await signedInUser(auth, 'alice@example.com')
    await signedInUser(auth, `1001@${OSM_PLACEHOLDER_EMAIL_DOMAIN}`)
    const started = await startOpenStreetMap(auth, { sub: '1001' })
    const { location, cookie } = await openStreetMapCallback(auth, started)
    expect(location).toBe('/auth/complete?error=signup_disabled')
    expect(await sessionEmail(auth, cookie)).toBeNull()
    expect(await userCount(auth)).toBe(2)
  })
})

describe('Connecting OpenStreetMap from a signed-in session', () => {
  it('links the identity, which then signs in to that user by sub', async () => {
    const auth = await makeAuth()
    const alice = await signedInUser(auth, 'alice@example.com')

    const link = await startOpenStreetMap(auth, {
      sub: '1001',
      sessionCookie: alice.cookie,
    })
    expect((await openStreetMapCallback(auth, link)).location).toBe(
      '/account?osm=connected',
    )

    const signIn = await startOpenStreetMap(auth, { sub: '1001' })
    const { location, cookie } = await openStreetMapCallback(auth, signIn)
    expect(location).toBe('/auth/complete')
    expect(await sessionEmail(auth, cookie)).toBe('alice@example.com')

    // The sign-in left the user's own email and verification alone.
    const { internalAdapter } = await auth.$context
    const stored = await internalAdapter.findUserById(alice.user.id)
    expect(stored?.email).toBe('alice@example.com')
    expect(stored?.emailVerified).toBe(true)
    expect(await userCount(auth)).toBe(1)
  })

  it('does not move an identity already connected to another user', async () => {
    const auth = await makeAuth()
    const alice = await signedInUser(auth, 'alice@example.com')
    const bob = await signedInUser(auth, 'bob@example.com')
    await openStreetMapCallback(
      auth,
      await startOpenStreetMap(auth, {
        sub: '1001',
        sessionCookie: alice.cookie,
      }),
    )

    const { location } = await openStreetMapCallback(
      auth,
      await startOpenStreetMap(auth, {
        sub: '1001',
        sessionCookie: bob.cookie,
      }),
    )
    expect(location).toMatch(/^\/account\?osm=connect_failed&error=/)

    const signIn = await startOpenStreetMap(auth, { sub: '1001' })
    const { cookie } = await openStreetMapCallback(auth, signIn)
    expect(await sessionEmail(auth, cookie)).toBe('alice@example.com')
  })

  it('signs in only from the OSM instance it was connected on', async () => {
    const auth = await makeAuth(OSM_TEST_ISSUER)
    const alice = await signedInUser(auth, 'alice@example.com')
    await openStreetMapCallback(
      auth,
      await startOpenStreetMap(auth, {
        sub: '1001',
        sessionCookie: alice.cookie,
      }),
    )

    // Same database, OSM_ISSUER switched: user 1001 there is someone else.
    const other = await makeAuth(OSM_OTHER_TEST_ISSUER, auth.database)
    const elsewhere = await openStreetMapCallback(
      other,
      await startOpenStreetMap(other, { sub: '1001' }),
    )
    expect(elsewhere.location).toBe('/auth/complete?error=signup_disabled')
    expect(await sessionEmail(other, elsewhere.cookie)).toBeNull()

    const home = await openStreetMapCallback(
      auth,
      await startOpenStreetMap(auth, { sub: '1001' }),
    )
    expect(await sessionEmail(auth, home.cookie)).toBe('alice@example.com')
  })

  it('refuses explicit linking of any other provider', async () => {
    const auth = await makeAuth()
    const alice = await signedInUser(auth, 'alice@example.com')
    const res = await auth.handler(
      new Request('https://auth.example/api/auth/link-social', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'https://auth.example',
          cookie: alice.cookie,
        },
        body: JSON.stringify({ provider: 'google', callbackURL: '/account' }),
      }),
    )
    expect(res.status).toBe(403)
    expect(((await res.json()) as { code?: string }).code).toBe(
      LINK_PROVIDER_NOT_ALLOWED,
    )
  })
})
