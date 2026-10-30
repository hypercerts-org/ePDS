/**
 * The better-auth instance exactly as index.ts builds it (createBetterAuth),
 * not one assembled in the test: the user-creation guard and the strict
 * Google claim only protect anyone if they are wired into it.
 *
 * Runs on in-memory SQLite with Google configured, Google's token endpoint
 * stubbed (see __helpers__/google-sign-in), PDS lookups mocked, and the
 * email codes captured from a stub EmailSender, so both kinds of sign-in
 * run through stock better-auth.
 */
import { getMigrations } from 'better-auth/db'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { EpdsDb } from '@certified-app/shared'
import { createBetterAuth, refuseUnverifiedUser } from '../better-auth.js'
import type { EmailSender } from '../email/sender.js'
import { mapGoogleProfileToUser } from '../lib/google-email-verified.js'
import { signInWithGoogleRedirect } from './__helpers__/google-sign-in.js'

vi.mock('../lib/get-did-by-email.js', () => ({
  getDidByEmail: vi.fn(() => Promise.resolve(null)),
}))

/** The last email code sent to each address. */
const codes = new Map<string, string>()

const emailSender = {
  sendOtpCode: vi.fn((opts: { to: string; code: string }) => {
    codes.set(opts.to, opts.code)
    return Promise.resolve()
  }),
} as unknown as EmailSender

const epdsDb = {
  getAuthFlow: vi.fn(() => undefined),
} as unknown as EpdsDb

beforeEach(() => {
  vi.stubEnv('DB_LOCATION', ':memory:')
  vi.stubEnv('AUTH_HOSTNAME', 'auth.example')
  vi.stubEnv('AUTH_SESSION_SECRET', 'test-secret-test-secret-test-secret')
  vi.stubEnv('GOOGLE_CLIENT_ID', 'google-client-id')
  vi.stubEnv('GOOGLE_CLIENT_SECRET', 'google-client-secret')
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  codes.clear()
})

async function makeAuth() {
  const auth = createBetterAuth(emailSender, epdsDb, 6)
  const { runMigrations } = await getMigrations(auth.options)
  await runMigrations()
  return auth
}

type Auth = Awaited<ReturnType<typeof makeAuth>>

/** Sign in with an emailed code, as the login page's email form does. */
async function signInWithEmailCode(auth: Auth, email: string) {
  await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } })
  const otp = codes.get(email)
  if (!otp) throw new Error(`no code was sent to ${email}`)
  return auth.api.signInEmailOTP({ body: { email, otp } })
}

async function storedUser(auth: Auth, email: string) {
  const ctx = await auth.$context
  return ctx.internalAdapter.findUserByEmail(email, { includeAccounts: true })
}

describe('createBetterAuth wiring', () => {
  it('passes ePDS’s user-creation guard and Google claim mapper to better-auth', async () => {
    const auth = await makeAuth()
    const userHooks = auth.options.databaseHooks.user
    expect(userHooks.create.before).toBe(refuseUnverifiedUser)
    expect(userHooks).not.toHaveProperty('update')
    expect(auth.options.socialProviders.google?.mapProfileToUser).toBe(
      mapGoogleProfileToUser,
    )
  })

  it('refuses a Google address Google is not authoritative for, leaving no user', async () => {
    const auth = await makeAuth()
    expect(
      await signInWithGoogleRedirect(auth, {
        email: 'alice@example.com',
        email_verified: true,
      }),
    ).toBe('/auth/complete?error=email_not_verified')
    expect(await storedUser(auth, 'alice@example.com')).toBeNull()
  })

  it('signs a verified Gmail address in', async () => {
    const auth = await makeAuth()
    expect(
      await signInWithGoogleRedirect(auth, {
        email: 'alice@gmail.com',
        email_verified: true,
      }),
    ).toBe('/auth/complete')
    const user = await storedUser(auth, 'alice@gmail.com')
    expect(user?.user.emailVerified).toBe(true)
    expect(user?.accounts.map((a) => a.providerId)).toEqual(['google'])
  })
})

describe('a Google user who also uses email codes (createBetterAuth)', () => {
  const gmail = { email: 'alice@gmail.com', email_verified: true }

  it('signs in by email code as the same user, keeping the Google link', async () => {
    const auth = await makeAuth()
    await signInWithGoogleRedirect(auth, gmail)
    const before = await storedUser(auth, 'alice@gmail.com')

    const res = await signInWithEmailCode(auth, 'alice@gmail.com')

    expect(res.user.id).toBe(before?.user.id)
    const after = await storedUser(auth, 'alice@gmail.com')
    expect(after?.accounts.map((a) => a.providerId)).toEqual(['google'])
  })

  it('keeps the Google session when the address is verified again', async () => {
    // /email-otp/verify-email writes emailVerified: true even for a user
    // who is already verified; that must not end or replace the session
    // the user already has.
    const auth = await makeAuth()
    const ctx = await auth.$context
    await signInWithGoogleRedirect(auth, gmail)
    const userId = (await storedUser(auth, 'alice@gmail.com'))?.user.id ?? ''
    const [session] = await ctx.internalAdapter.listSessions(userId)

    await auth.api.sendVerificationOTP({
      body: { email: 'alice@gmail.com', type: 'email-verification' },
    })
    const otp = codes.get('alice@gmail.com') ?? ''
    await auth.api.verifyEmailOTP({ body: { email: 'alice@gmail.com', otp } })

    expect(await ctx.internalAdapter.findSession(session.token)).not.toBeNull()
    expect(
      (await ctx.internalAdapter.listSessions(userId)).map((s) => s.token),
    ).toEqual([session.token])
    const user = await storedUser(auth, 'alice@gmail.com')
    expect(user?.accounts.map((a) => a.providerId)).toEqual(['google'])
  })
})
