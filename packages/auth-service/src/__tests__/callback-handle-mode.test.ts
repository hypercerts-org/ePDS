import { randomBytes } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import express from 'express'
import cookieParser from 'cookie-parser'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  verifyCallback,
  type CallbackParams,
  type HandleMode,
} from '@certified-app/shared'
import type { AuthServiceContext } from '../context.js'
import { createChooseHandleRouter } from '../routes/choose-handle.js'
import { createCompleteRouter } from '../routes/complete.js'

const mocks = vi.hoisted(() => ({
  getDidByEmail: vi.fn(),
  pingParRequest: vi.fn(),
  resolveRecoveryEmail: vi.fn(),
  resolveClientBranding: vi.fn(),
}))

vi.mock('../lib/get-did-by-email.js', () => ({
  getDidByEmail: mocks.getDidByEmail,
}))

vi.mock('../lib/ping-par-request.js', () => ({
  pingParRequest: mocks.pingParRequest,
}))

vi.mock('../lib/resolve-recovery-email.js', () => ({
  resolveRecoveryEmail: mocks.resolveRecoveryEmail,
}))

vi.mock('../lib/client-metadata.js', () => ({
  resolveClientBranding: mocks.resolveClientBranding,
}))

const AUTH_FLOW_COOKIE = 'epds_auth_flow'
const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:req-123'
const CLIENT_ID = 'https://app.example/client.json'
const realFetch = globalThis.fetch.bind(globalThis)

function makeCtx(handleMode: HandleMode | null): AuthServiceContext {
  return {
    config: {
      pdsPublicUrl: 'https://pds.example',
      pdsHostname: 'pds.example',
      epdsCallbackSecret: 'test-callback-secret',
      trustedClients: [],
    },
    db: {
      getAuthFlow: vi.fn(() => ({
        flowId: 'flow-1',
        requestUri: REQUEST_URI,
        clientId: CLIENT_ID,
        handleMode,
      })),
      deleteAuthFlow: vi.fn(),
    },
  } as unknown as AuthServiceContext
}

/**
 * A better-auth stand-in whose session belongs to `user` (null: no
 * session). The default is what an email-OTP sign-in leaves, which always
 * verifies the address.
 */
function makeAuth(
  user: Record<string, unknown> | null = {
    email: 'Alice@example.com',
    emailVerified: true,
  },
) {
  return {
    api: {
      getSession: vi.fn(() => Promise.resolve(user ? { user } : null)),
    },
  }
}

async function startApp(
  ctx: AuthServiceContext,
  auth: ReturnType<typeof makeAuth>,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const app = express()
  app.disable('x-powered-by')
  app.use(cookieParser())
  app.use(express.urlencoded({ extended: false }))
  app.use(createCompleteRouter(ctx, auth))
  app.use(createChooseHandleRouter(ctx, auth))

  const server = app.listen(0)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.once('listening', () => {
      resolve()
    })
  })
  server.unref()
  const port = (server.address() as AddressInfo).port
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          resolve()
        })
      }),
  }
}

function parseRedirect(res: globalThis.Response): URL {
  const location = res.headers.get('location')
  if (!location) throw new Error('Missing redirect location')
  return new URL(location)
}

function normalizeFetchUrl(input: Parameters<typeof fetch>[0]): URL {
  if (input instanceof URL) return input
  if (typeof input === 'string') return new URL(input)
  return new URL(input.url)
}

function verifySignedCallbackUrl(url: URL): boolean {
  const callbackParams: CallbackParams = {
    request_uri: url.searchParams.get('request_uri') ?? '',
    email: url.searchParams.get('email') ?? '',
    approved: url.searchParams.get('approved') ?? '',
    new_account: url.searchParams.get('new_account') ?? '',
    // Required, not spread conditionally: a callback that omitted it
    // must fail verification rather than be read as unverified.
    email_verified: url.searchParams.get('email_verified') ?? '',
    ...(url.searchParams.has('handle')
      ? { handle: url.searchParams.get('handle') ?? '' }
      : {}),
    // /auth/complete signs client_id too (so a dead-PAR clean exit can still
    // reach the right client); omitting it here would fail verification.
    ...(url.searchParams.has('client_id')
      ? { client_id: url.searchParams.get('client_id') ?? '' }
      : {}),
    ...(url.searchParams.has('epds_handle_mode')
      ? { epds_handle_mode: url.searchParams.get('epds_handle_mode') ?? '' }
      : {}),
  }

  return verifyCallback(
    callbackParams,
    url.searchParams.get('ts') ?? '',
    url.searchParams.get('sig') ?? '',
    'test-callback-secret',
  )
}

async function fetchCompleteRedirect(handleMode: HandleMode | null) {
  const app = await startApp(makeCtx(handleMode), makeAuth())
  try {
    const res = await fetch(`${app.baseUrl}/auth/complete`, {
      redirect: 'manual',
      headers: { cookie: `${AUTH_FLOW_COOKIE}=flow-1` },
    })

    expect(res.status).toBe(303)
    const url = parseRedirect(res)
    expect(url.pathname).toBe('/oauth/epds-callback')
    return url
  } finally {
    await app.close()
  }
}

let priorEnv: { pdsInternalUrl?: string; internalSecret?: string }

beforeEach(() => {
  priorEnv = {
    pdsInternalUrl: process.env.PDS_INTERNAL_URL,
    internalSecret: process.env.EPDS_INTERNAL_SECRET,
  }
  process.env.PDS_INTERNAL_URL = 'http://pds.internal' // NOSONAR test-only internal mocked URL
  process.env.EPDS_INTERNAL_SECRET = 'test-internal-secret'
  mocks.getDidByEmail.mockReset()
  mocks.pingParRequest.mockReset()
  mocks.resolveRecoveryEmail.mockReset()
  mocks.resolveClientBranding.mockReset()
  mocks.pingParRequest.mockResolvedValue({ ok: true })
  mocks.resolveRecoveryEmail.mockResolvedValue(null)
  mocks.resolveClientBranding.mockResolvedValue({
    customCss: null,
    customFaviconUrl: null,
    customFaviconUrlDark: null,
  })
  vi.stubGlobal(
    'fetch',
    vi.fn((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = normalizeFetchUrl(input)
      if (url.hostname === '127.0.0.1') return realFetch(input, init)
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ exists: false }),
      })
    }),
  )
})

afterEach(() => {
  if (priorEnv.pdsInternalUrl === undefined) delete process.env.PDS_INTERNAL_URL
  else process.env.PDS_INTERNAL_URL = priorEnv.pdsInternalUrl
  if (priorEnv.internalSecret === undefined)
    delete process.env.EPDS_INTERNAL_SECRET
  else process.env.EPDS_INTERNAL_SECRET = priorEnv.internalSecret
  vi.unstubAllGlobals()
})

describe('auth-service epds-callback handle mode threading', () => {
  it('includes the stored canonical handle mode for random-mode new users', async () => {
    mocks.getDidByEmail.mockResolvedValue(null)
    const url = await fetchCompleteRedirect('random')
    expect(url.searchParams.get('epds_handle_mode')).toBe('random')
    expect(url.searchParams.has('handle')).toBe(false)
    expect(verifySignedCallbackUrl(url)).toBe(true)
  })

  it('includes the stored canonical handle mode for existing users', async () => {
    mocks.getDidByEmail.mockResolvedValue(randomBytes(16).toString('hex'))
    const url = await fetchCompleteRedirect('picker-with-random')
    expect(url.searchParams.get('epds_handle_mode')).toBe('picker-with-random')
  })

  it('includes the stored canonical handle mode for chosen-handle callbacks', async () => {
    mocks.getDidByEmail.mockResolvedValue(null)
    const app = await startApp(makeCtx('picker'), makeAuth())
    try {
      const res = await fetch(`${app.baseUrl}/auth/choose-handle`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          cookie: `${AUTH_FLOW_COOKIE}=flow-1`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ handle: 'Alice1' }),
      })

      expect(res.status).toBe(303)
      const url = parseRedirect(res)
      expect(url.pathname).toBe('/oauth/epds-callback')
      expect(url.searchParams.get('epds_handle_mode')).toBe('picker')
      expect(url.searchParams.get('handle')).toBe('alice1')
    } finally {
      await app.close()
    }
  })
})

/**
 * Request `path` with the flow cookie (as a form POST when `form` is
 * given); returns the 303 redirect target.
 */
async function redirectFrom(
  auth: ReturnType<typeof makeAuth>,
  path: string,
  {
    handleMode = 'random',
    form,
  }: { handleMode?: HandleMode; form?: string } = {},
): Promise<URL> {
  const app = await startApp(makeCtx(handleMode), auth)
  try {
    const res = await fetch(`${app.baseUrl}${path}`, {
      redirect: 'manual',
      headers: {
        cookie: `${AUTH_FLOW_COOKIE}=flow-1`,
        ...(form
          ? { 'content-type': 'application/x-www-form-urlencoded' }
          : {}),
      },
      ...(form ? { method: 'POST', body: form } : {}),
    })
    expect(res.status).toBe(303)
    const location = res.headers.get('location')
    if (!location) throw new Error('Missing redirect location')
    return new URL(location, app.baseUrl)
  } finally {
    await app.close()
  }
}

// A social sign-in comes back to /auth/complete too: the login page's
// social buttons pass it as better-auth's errorCallbackURL, so a cancel at
// the provider or a refusal by better-auth arrives as ?error=<code>. The
// route must send the user back to the login page for the same flow with a
// fixed error code, and must not fall through to whatever better-auth
// session the browser already holds.
describe('/auth/complete after a social sign-in that did not complete', () => {
  it.each([
    ['access_denied', 'cancelled'],
    ['account_not_linked', 'email_unverified'],
    ['email_not_found', 'no_email'],
    ['invalid_code', 'failed'],
  ])('?error=%s returns to the login page with %s', async (error, expected) => {
    const url = await redirectFrom(
      makeAuth(null),
      `/auth/complete?error=${error}`,
    )
    expect(url.pathname).toBe('/oauth/authorize')
    expect(url.searchParams.get('request_uri')).toBe(REQUEST_URI)
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID)
    expect(url.searchParams.get('epds_social_error')).toBe(expected)
  })

  it('carries the provider back so the message can name it', async () => {
    const url = await redirectFrom(
      makeAuth(null),
      '/auth/complete?epds_social_provider=google&error=email_not_verified',
    )
    expect(url.searchParams.get('epds_social_error')).toBe('email_unverified')
    expect(url.searchParams.get('epds_social_provider')).toBe('google')
  })

  it('does not use a session the browser already holds', async () => {
    // An earlier, valid sign-in in the same browser must not be resumed
    // when this one was cancelled.
    const auth = makeAuth()
    mocks.getDidByEmail.mockResolvedValue('did:plc:alice')

    const url = await redirectFrom(auth, '/auth/complete?error=access_denied')

    expect(url.pathname).toBe('/oauth/authorize')
    expect(auth.api.getSession).not.toHaveBeenCalled()
    expect(mocks.getDidByEmail).not.toHaveBeenCalled()
  })
})

// A session whose email is not verified must neither create a PDS account
// nor sign into an existing one: it goes back to the login page.
describe('a session whose email is not verified', () => {
  const unverified = { email: 'alice@example.com', emailVerified: false }

  it.each([
    ['a new account', null],
    ['an existing account', 'did:plc:alice'],
  ])('/auth/complete refuses it for %s', async (_l, did) => {
    mocks.getDidByEmail.mockResolvedValue(did)

    const url = await redirectFrom(makeAuth(unverified), '/auth/complete')

    expect(url.pathname).toBe('/oauth/authorize')
    expect(url.searchParams.get('request_uri')).toBe(REQUEST_URI)
    expect(url.searchParams.get('epds_social_error')).toBe('email_unverified')
    expect(mocks.pingParRequest).not.toHaveBeenCalled()
  })

  it('a missing emailVerified counts as unverified', async () => {
    const url = await redirectFrom(
      makeAuth({ email: 'alice@example.com' }),
      '/auth/complete',
    )
    expect(url.searchParams.get('epds_social_error')).toBe('email_unverified')
  })

  it.each([
    ['GET', undefined],
    ['POST', 'handle=alice1'],
  ])(
    '%s /auth/choose-handle bounces it to /auth/complete',
    async (_m, form) => {
      mocks.getDidByEmail.mockResolvedValue(null)

      const url = await redirectFrom(
        makeAuth(unverified),
        '/auth/choose-handle',
        { handleMode: 'picker', form },
      )

      expect(url.pathname).toBe('/auth/complete')
      expect(mocks.pingParRequest).not.toHaveBeenCalled()
    },
  )
})
