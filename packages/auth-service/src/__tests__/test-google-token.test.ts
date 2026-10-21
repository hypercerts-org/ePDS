/**
 * The e2e suite's stand-in for Google's token endpoint, driven through a
 * real better-auth instance the way the e2e browser drives it: the
 * authorization code carries the ID token claims.
 */
import Database from 'better-sqlite3'
import { betterAuth } from 'better-auth'
import { getMigrations } from 'better-auth/db'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { buildSocialProviders, databaseHooks } from '../better-auth.js'
import {
  fakeGoogleTokenResponse,
  installTestGoogleTokenEndpoint,
} from '../lib/test-google-token.js'
import {
  googleCallback,
  startGoogleSignIn,
} from './__helpers__/google-sign-in.js'

const realFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = realFetch
  vi.unstubAllEnvs()
})

function code(claims: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(claims)).toString('base64url')
}

async function makeAuth() {
  const auth = betterAuth({
    secret: 'test-secret-test-secret-test-secret',
    baseURL: 'https://auth.example',
    basePath: '/api/auth',
    database: new Database(':memory:'),
    databaseHooks,
    socialProviders: buildSocialProviders({
      GOOGLE_CLIENT_ID: 'google-client-id',
      GOOGLE_CLIENT_SECRET: 'google-client-secret',
    }),
  })
  const { runMigrations } = await getMigrations(auth.options)
  await runMigrations()
  return auth
}

describe('installTestGoogleTokenEndpoint', () => {
  it('signs in the identity the authorization code names', async () => {
    installTestGoogleTokenEndpoint('google-client-id')
    const auth = await makeAuth()
    const { state, cookie } = await startGoogleSignIn(auth)

    const claims = {
      sub: 'e2e-sub',
      email: 'alice@gmail.com',
      email_verified: true,
    }
    expect(
      await googleCallback(auth, `code=${code(claims)}&state=${state}`, cookie),
    ).toBe('/auth/complete')

    const ctx = await auth.$context
    const user = await ctx.internalAdapter.findUserByEmail('alice@gmail.com', {
      includeAccounts: true,
    })
    expect(user?.accounts.map((a) => [a.providerId, a.accountId])).toEqual([
      ['google', 'e2e-sub'],
    ])
  })

  it('still applies the Google claim check', async () => {
    installTestGoogleTokenEndpoint('google-client-id')
    const auth = await makeAuth()
    const { state, cookie } = await startGoogleSignIn(auth)

    const claims = {
      sub: 'e2e-sub',
      email: 'alice@example.com',
      email_verified: true,
      hd: 'other.example',
    }
    expect(
      await googleCallback(auth, `code=${code(claims)}&state=${state}`, cookie),
    ).toBe('/auth/complete?error=email_not_verified')
  })

  it('leaves every other request alone', async () => {
    const passthrough = vi.fn(() => Promise.resolve(new Response('ok')))
    globalThis.fetch = passthrough
    installTestGoogleTokenEndpoint('google-client-id')

    await globalThis.fetch('https://example.com/')

    expect(passthrough).toHaveBeenCalledWith('https://example.com/', undefined)
  })

  it('refuses to install in production', () => {
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => {
      installTestGoogleTokenEndpoint('google-client-id')
    }).toThrow(/NODE_ENV=production/)
    expect(globalThis.fetch).toBe(realFetch)
  })
})

describe('fakeGoogleTokenResponse', () => {
  it.each([
    '',
    'not-base64-json',
    code([] as unknown as Record<string, never>),
  ])('rejects a code that carries no claims (%j)', async (badCode) => {
    const res = fakeGoogleTokenResponse(badCode, 'google-client-id')
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_grant' })
  })
})
